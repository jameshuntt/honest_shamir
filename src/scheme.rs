use alloc::vec;
use alloc::vec::Vec;

use honest::poly::{lagrange_at_zero, PolyError};
use honest::{evaluate, Gf256};
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::{ShamirError, Share, Threshold};

/// Split `secret` into `threshold.total()` shares using `rng` for the
/// polynomial coefficients.
///
/// Every byte gets its own polynomial: the byte as the constant term,
/// `required − 1` random coefficients above it. The coefficients live in a
/// zeroizing buffer and are scrubbed when the split finishes. A generator
/// that fails to produce bytes aborts the split with
/// [`ShamirError::Randomness`]; no partial shares are returned.
pub fn split_with<R: TryCryptoRng + ?Sized>(
    secret: &[u8],
    threshold: Threshold,
    rng: &mut R,
) -> Result<Vec<Share>, ShamirError> {
    if secret.is_empty() {
        return Err(ShamirError::EmptySecret);
    }
    let required = usize::from(threshold.required());
    let total = usize::from(threshold.total());

    let mut shares: Vec<Vec<u8>> = (0..total).map(|_| vec![0u8; secret.len()]).collect();
    let mut coeffs: Zeroizing<Vec<Gf256>> = Zeroizing::new(vec![Gf256::ZERO; required]);
    let mut random: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; required - 1]);

    for (position, &byte) in secret.iter().enumerate() {
        rng.try_fill_bytes(&mut random).map_err(|_| ShamirError::Randomness)?;
        coeffs[0] = Gf256(byte);
        for (coefficient, &r) in coeffs[1..].iter_mut().zip(random.iter()) {
            *coefficient = Gf256(r);
        }
        for (i, share) in shares.iter_mut().enumerate() {
            share[position] = evaluate(&coeffs, x_of(i)).0;
        }
    }

    Ok(shares.into_iter().enumerate().map(|(i, bytes)| Share::from_parts(x_of(i).0, bytes)).collect())
}

/// [`split_with`] using the operating system's generator.
#[cfg(feature = "os-rng")]
pub fn split(secret: &[u8], threshold: Threshold) -> Result<Vec<Share>, ShamirError> {
    split_with(secret, threshold, &mut rand_core::OsRng)
}

/// Rebuild the secret from the first `threshold.required()` of `shares`.
///
/// Those shares must carry distinct non-zero indexes and equal lengths.
/// Extra shares beyond the threshold are ignored. Nothing checks that the
/// shares are genuine: a wrong or tampered share produces a wrong secret,
/// so verify the result (a digest kept beside the shares, an AEAD tag on
/// what the secret unlocks) before trusting it.
pub fn reconstruct(shares: &[Share], threshold: Threshold) -> Result<Vec<u8>, ShamirError> {
    let required = usize::from(threshold.required());
    if shares.len() < required {
        return Err(ShamirError::TooFewShares { required: threshold.required(), provided: shares.len() });
    }
    let selected = &shares[..required];
    validate_set(selected)?;

    let xs: Vec<Gf256> = selected.iter().map(|s| Gf256(s.index())).collect();
    let mut basis = vec![Gf256::ZERO; required];
    lagrange_at_zero(&xs, &mut basis).map_err(basis_error)?;

    let len = selected[0].len();
    let mut secret = vec![0u8; len];
    for (position, out) in secret.iter_mut().enumerate() {
        let acc = selected
            .iter()
            .zip(&basis)
            .fold(Gf256::ZERO, |acc, (share, &b)| acc.add(b.mul(Gf256(share.bytes()[position]))));
        *out = acc.0;
    }
    Ok(secret)
}

/// Re-randomize `shares` in place so that they still rebuild the same
/// secret but no longer combine with the shares they replace.
///
/// A random polynomial with a zero constant term is added to every byte's
/// polynomial, which leaves the secret alone and changes every share. All
/// shares that are meant to keep working must be refreshed together: any
/// share left out stops combining with the refreshed ones. `threshold` is
/// the policy the shares were split with.
pub fn refresh_with<R: TryCryptoRng + ?Sized>(
    shares: &mut [Share],
    threshold: Threshold,
    rng: &mut R,
) -> Result<(), ShamirError> {
    validate_set(shares)?;
    let required = usize::from(threshold.required());
    let len = shares[0].len();

    let mut coeffs: Zeroizing<Vec<Gf256>> = Zeroizing::new(vec![Gf256::ZERO; required]);
    let mut random: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; required - 1]);

    for position in 0..len {
        rng.try_fill_bytes(&mut random).map_err(|_| ShamirError::Randomness)?;
        for (coefficient, &r) in coeffs[1..].iter_mut().zip(random.iter()) {
            *coefficient = Gf256(r);
        }
        for share in shares.iter_mut() {
            let x = Gf256(share.index());
            let delta = evaluate(&coeffs, x);
            let byte = &mut share.bytes_mut()[position];
            *byte = Gf256(*byte).add(delta).0;
        }
    }
    Ok(())
}

/// [`refresh_with`] using the operating system's generator.
#[cfg(feature = "os-rng")]
pub fn refresh(shares: &mut [Share], threshold: Threshold) -> Result<(), ShamirError> {
    refresh_with(shares, threshold, &mut rand_core::OsRng)
}

fn x_of(share_position: usize) -> Gf256 {
    // share positions are 0-based, x coordinates start at 1
    Gf256((share_position + 1) as u8)
}

fn validate_set(shares: &[Share]) -> Result<(), ShamirError> {
    let Some(first) = shares.first() else {
        return Err(ShamirError::TooFewShares { required: 2, provided: 0 });
    };
    let expected = first.len();
    if expected == 0 {
        return Err(ShamirError::EmptyShare);
    }
    let mut seen = [false; 256];
    for share in shares {
        let x = share.index();
        if x == 0 {
            return Err(ShamirError::ZeroIndex);
        }
        if seen[usize::from(x)] {
            return Err(ShamirError::DuplicateIndex(x));
        }
        seen[usize::from(x)] = true;
        if share.len() != expected {
            return Err(ShamirError::LengthMismatch { expected, found: share.len() });
        }
    }
    Ok(())
}

// `validate_set` runs first, so these cannot happen; map them anyway rather than panic.
fn basis_error(e: PolyError) -> ShamirError {
    match e {
        PolyError::Empty => ShamirError::TooFewShares { required: 2, provided: 0 },
        PolyError::DuplicatePoint => ShamirError::DuplicateIndex(0),
        PolyError::LengthMismatch => ShamirError::LengthMismatch { expected: 0, found: 0 },
    }
}
