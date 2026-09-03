//! Shamir secret sharing over GF(2^8).
//!
//! A secret of any length is split into `n` shares so that any `k` of them
//! rebuild it and any `k − 1` say nothing about it. Each byte of the secret
//! is the constant term of its own random polynomial of degree `k − 1` over
//! the AES field ([`honest::Gf256`]); share `i` holds every polynomial
//! evaluated at `x = i`. Shares are therefore the same length as the secret,
//! and `n` is at most 255.
//!
//! ```
//! use honest_shamir::{split_with, reconstruct, Threshold};
//! use rand_chacha::ChaCha20Rng;
//! use rand_core::SeedableRng;
//!
//! let mut rng = ChaCha20Rng::seed_from_u64(7);
//! let threshold = Threshold::new(3, 5).unwrap();
//! let shares = split_with(b"the key to the archive", threshold, &mut rng).unwrap();
//!
//! // any three shares rebuild the secret
//! let some = [shares[4].clone(), shares[0].clone(), shares[2].clone()];
//! assert_eq!(reconstruct(&some, threshold).unwrap(), b"the key to the archive");
//! ```
//!
//! This crate is the arithmetic and nothing else: bytes in, bytes out. It
//! does not authenticate shares (a corrupted share rebuilds a wrong secret
//! without complaint), does not wrap the secret in a zeroizing container
//! for you, and does not decide who holds which share. `classified_shamir`
//! layers the containers on top; the policy is yours.
//!
//! Randomness comes from any [`rand_core::TryCryptoRng`], so a host that
//! has no OS generator can pass its own; with the `os-rng` feature (on by
//! default) [`split`] and [`refresh`] use the operating system's.
//!
//! `no_std` with `alloc` when the `std` feature is off.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod error;
mod scheme;
mod share;
mod threshold;

pub use error::ShamirError;
pub use scheme::{reconstruct, refresh_with, split_with};
#[cfg(feature = "os-rng")]
pub use scheme::{refresh, split};
pub use share::Share;
pub use threshold::Threshold;

pub use rand_core;

#[cfg(all(doctest, feature = "os-rng"))]
#[doc = include_str!("../README.md")]
mod readme_doctests {}
