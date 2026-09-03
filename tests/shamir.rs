//! Split, reconstruct and refresh: round trips, every subset, refusals,
//! and what a short set of shares does not tell you.

use std::collections::HashSet;

use honest_shamir::rand_core::{CryptoRng, RngCore, SeedableRng, TryCryptoRng, TryRngCore};
use honest_shamir::{reconstruct, refresh_with, split_with, ShamirError, Share, Threshold};
use rand_chacha::ChaCha20Rng;

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn t(k: u8, n: u8) -> Threshold {
    Threshold::new(k, n).unwrap()
}

/// Every k-subset of `shares`, as owned vectors.
fn subsets(shares: &[Share], k: usize) -> Vec<Vec<Share>> {
    let n = shares.len();
    let mut out = Vec::new();
    for mask in 0u32..(1 << n) {
        if mask.count_ones() as usize == k {
            out.push((0..n).filter(|i| mask & (1 << i) != 0).map(|i| shares[i].clone()).collect());
        }
    }
    out
}

#[test]
fn every_three_of_five_rebuilds_the_secret() {
    let secret: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(37) ^ 0xA5).collect();
    let shares = split_with(&secret, t(3, 5), &mut rng(1)).unwrap();
    assert_eq!(shares.len(), 5);
    assert_eq!(shares.iter().map(Share::index).collect::<Vec<_>>(), [1, 2, 3, 4, 5]);
    assert!(shares.iter().all(|s| s.len() == 32));

    let all = subsets(&shares, 3);
    assert_eq!(all.len(), 10);
    for subset in &all {
        assert_eq!(reconstruct(subset, t(3, 5)).unwrap(), secret);
    }
    // more than three is fine too: the first three are used
    assert_eq!(reconstruct(&shares, t(3, 5)).unwrap(), secret);
}

#[test]
fn thresholds_across_the_range() {
    let secret = b"sixty-four bytes of secret material, give or take a few chars.".to_vec();
    for (k, n) in [(2, 2), (2, 3), (5, 5), (7, 10), (3, 255), (255, 255)] {
        let shares = split_with(&secret, t(k, n), &mut rng(u64::from(k) * 1000 + u64::from(n))).unwrap();
        assert_eq!(shares.len(), usize::from(n), "{k}-of-{n}");
        // the last k shares, reversed, so the order and the indexes vary
        let mut chosen: Vec<Share> = shares[shares.len() - usize::from(k)..].to_vec();
        chosen.reverse();
        assert_eq!(reconstruct(&chosen, t(k, n)).unwrap(), secret, "{k}-of-{n}");
    }
}

#[test]
fn secrets_of_any_length() {
    for len in [1usize, 2, 3, 17, 1000] {
        let secret: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let shares = split_with(&secret, t(2, 3), &mut rng(len as u64)).unwrap();
        assert_eq!(reconstruct(&shares[1..], t(2, 3)).unwrap(), secret, "len {len}");
    }
}

#[test]
fn fewer_shares_than_the_threshold_is_refused() {
    let shares = split_with(b"secret", t(3, 4), &mut rng(2)).unwrap();
    assert_eq!(
        reconstruct(&shares[..2], t(3, 4)).unwrap_err(),
        ShamirError::TooFewShares { required: 3, provided: 2 }
    );
    assert_eq!(reconstruct(&[], t(2, 2)).unwrap_err(), ShamirError::TooFewShares { required: 2, provided: 0 });
}

#[test]
fn a_single_share_of_a_two_of_three_split_looks_random() {
    // the same one-byte secret split 512 times: share 1's byte should range widely
    let mut seen = HashSet::new();
    for seed in 0..512u64 {
        let shares = split_with(&[0x42], t(2, 3), &mut rng(seed)).unwrap();
        seen.insert(shares[0].bytes()[0]);
    }
    assert!(seen.len() > 200, "only {} distinct values", seen.len());
}

#[test]
fn a_wrong_share_gives_a_wrong_secret_without_complaint() {
    let secret = b"trust but verify".to_vec();
    let shares = split_with(&secret, t(2, 3), &mut rng(3)).unwrap();
    let mut bytes = shares[1].bytes().to_vec();
    bytes[0] ^= 1;
    let forged = Share::new(2, bytes).unwrap();
    let rebuilt = reconstruct(&[shares[0].clone(), forged], t(2, 3)).unwrap();
    assert_ne!(rebuilt, secret);
    assert_eq!(rebuilt[1..], secret[1..], "only the tampered byte position is affected");
}

#[test]
fn share_sets_are_validated() {
    let shares = split_with(b"abc", t(2, 3), &mut rng(4)).unwrap();
    let dup = [shares[0].clone(), shares[0].clone()];
    assert_eq!(reconstruct(&dup, t(2, 3)).unwrap_err(), ShamirError::DuplicateIndex(1));

    let short = Share::new(2, vec![1, 2]).unwrap();
    let mixed = [shares[0].clone(), short];
    assert_eq!(reconstruct(&mixed, t(2, 3)).unwrap_err(), ShamirError::LengthMismatch { expected: 3, found: 2 });

    assert_eq!(Share::new(0, vec![1]).unwrap_err(), ShamirError::ZeroIndex);
    assert_eq!(Share::new(1, vec![]).unwrap_err(), ShamirError::EmptyShare);
    assert_eq!(split_with(&[], t(2, 3), &mut rng(0)).unwrap_err(), ShamirError::EmptySecret);
    assert_eq!(Threshold::new(0, 0).unwrap_err(), ShamirError::InvalidThreshold { required: 0, total: 0 });
    assert_eq!(ShamirError::DuplicateIndex(7).to_string(), "two shares carry index 7");
}

#[test]
fn shares_redact_clone_and_compare() {
    let shares = split_with(b"hello", t(2, 2), &mut rng(5)).unwrap();
    assert_eq!(format!("{:?}", shares[0]), "Share { index: 1, len: 5 }");
    let copy = shares[0].clone();
    assert_eq!(copy, shares[0]);
    assert_ne!(shares[0], shares[1]);
    let other_index = Share::new(9, shares[0].bytes().to_vec()).unwrap();
    assert_ne!(other_index, shares[0]);
    assert_eq!(copy.into_bytes(), shares[0].bytes());
}

#[test]
fn refreshed_shares_rebuild_the_secret_but_do_not_mix_with_old_ones() {
    let secret = b"rotate me".to_vec();
    let old = split_with(&secret, t(3, 5), &mut rng(6)).unwrap();
    let mut new = old.clone();
    refresh_with(&mut new, t(3, 5), &mut rng(7)).unwrap();

    assert!(new.iter().zip(&old).all(|(a, b)| a != b), "every share changed");
    assert!(new.iter().zip(&old).all(|(a, b)| a.index() == b.index()), "indexes did not");
    for subset in subsets(&new, 3) {
        assert_eq!(reconstruct(&subset, t(3, 5)).unwrap(), secret);
    }
    let mixed = [old[0].clone(), old[1].clone(), new[2].clone()];
    assert_ne!(reconstruct(&mixed, t(3, 5)).unwrap(), secret);
}

#[test]
fn the_same_seed_gives_the_same_shares() {
    let a = split_with(b"determinism", t(2, 4), &mut rng(8)).unwrap();
    let b = split_with(b"determinism", t(2, 4), &mut rng(8)).unwrap();
    let c = split_with(b"determinism", t(2, 4), &mut rng(9)).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
}

/// A generator that always fails, to prove the failure is surfaced.
struct Broken;

impl TryRngCore for Broken {
    type Error = core::fmt::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(core::fmt::Error)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(core::fmt::Error)
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        Err(core::fmt::Error)
    }
}
impl TryCryptoRng for Broken {}

#[test]
fn a_failing_generator_aborts_the_split_and_the_refresh() {
    assert_eq!(split_with(b"x", t(2, 3), &mut Broken).unwrap_err(), ShamirError::Randomness);
    let mut shares = split_with(b"x", t(2, 3), &mut rng(10)).unwrap();
    assert_eq!(refresh_with(&mut shares, t(2, 3), &mut Broken).unwrap_err(), ShamirError::Randomness);
}

/// An infallible generator is accepted through the blanket `TryCryptoRng` impl.
struct Counter(u8);

impl RngCore for Counter {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for d in dst {
            self.0 = self.0.wrapping_add(1);
            *d = self.0;
        }
    }
}
impl CryptoRng for Counter {}

#[test]
fn any_crypto_rng_works() {
    let shares = split_with(b"counter", t(2, 3), &mut Counter(0)).unwrap();
    assert_eq!(reconstruct(&shares[1..], t(2, 3)).unwrap(), b"counter");
}

#[cfg(feature = "os-rng")]
#[test]
fn the_os_generator_round_trips() {
    let threshold = t(4, 6);
    let mut shares = honest_shamir::split(b"from the operating system", threshold).unwrap();
    assert_eq!(reconstruct(&shares[2..], threshold).unwrap(), b"from the operating system");
    honest_shamir::refresh(&mut shares, threshold).unwrap();
    assert_eq!(reconstruct(&shares[..4], threshold).unwrap(), b"from the operating system");
}
