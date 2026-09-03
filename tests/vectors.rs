//! Known answers, computed by hand in GF(2^8) with the AES polynomial.
//!
//! With a generator that always returns 0x02, every random coefficient is
//! 0x02, so the polynomials are known and the shares can be checked byte by
//! byte.

use honest_shamir::rand_core::{CryptoRng, RngCore};
use honest_shamir::{reconstruct, split_with, Share, Threshold};

struct Always(u8);

impl RngCore for Always {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([self.0; 4])
    }
    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([self.0; 8])
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        dst.fill(self.0);
    }
}
impl CryptoRng for Always {}

#[test]
fn two_of_three_over_one_byte() {
    // p(x) = 0x53 + 0x02·x
    // p(1) = 0x53 ^ 0x02 = 0x51, p(2) = 0x53 ^ 0x04 = 0x57, p(3) = 0x53 ^ 0x06 = 0x55
    let t = Threshold::new(2, 3).unwrap();
    let shares = split_with(&[0x53], t, &mut Always(0x02)).unwrap();
    let bytes: Vec<u8> = shares.iter().map(|s| s.bytes()[0]).collect();
    assert_eq!(bytes, [0x51, 0x57, 0x55]);

    // Lagrange at zero for x = {2, 3}: L_2 = 3/(2−3) = 3, L_3 = 2/(3−2) = 2
    // 3·0x57 = 0xF9, 2·0x55 = 0xAA, sum = 0x53
    assert_eq!(reconstruct(&shares[1..], t).unwrap(), [0x53]);
}

#[test]
fn three_of_three_over_one_byte() {
    // p(x) = 0x53 + 0x02·x + 0x02·x²
    // p(1) = 0x53 ^ 0x02 ^ 0x02 = 0x53
    // p(2) = 0x53 ^ 0x04 ^ 0x08 = 0x5F        (2² = 4)
    // p(3) = 0x53 ^ 0x06 ^ 0x0A = 0x5F        (3² = x²+1 = 0x05, 2·0x05 = 0x0A)
    let t = Threshold::new(3, 3).unwrap();
    let shares = split_with(&[0x53], t, &mut Always(0x02)).unwrap();
    let bytes: Vec<u8> = shares.iter().map(|s| s.bytes()[0]).collect();
    assert_eq!(bytes, [0x53, 0x5F, 0x5F]);
    assert_eq!(reconstruct(&shares, t).unwrap(), [0x53]);
}

#[test]
fn zero_coefficients_make_every_share_the_secret() {
    // with all random coefficients zero, p(x) = secret for every x
    let t = Threshold::new(2, 4).unwrap();
    let shares = split_with(b"\x10\x20", t, &mut Always(0x00)).unwrap();
    for s in &shares {
        assert_eq!(s.bytes(), b"\x10\x20");
    }
    assert_eq!(reconstruct(&shares[2..], t).unwrap(), b"\x10\x20");
}

#[test]
fn a_share_built_from_received_bytes_reconstructs_like_the_original() {
    let t = Threshold::new(2, 3).unwrap();
    let received = [Share::new(2, vec![0x57]).unwrap(), Share::new(3, vec![0x55]).unwrap()];
    assert_eq!(reconstruct(&received, t).unwrap(), [0x53]);
}
