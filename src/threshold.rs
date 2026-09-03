use core::fmt;

use crate::ShamirError;

/// A `k`-of-`n` policy: `total` shares are made and any `required` rebuild
/// the secret.
///
/// `required` is at least 2, because a 1-of-`n` split hands the secret
/// itself to every holder, and at most `total`. `total` is at most 255,
/// the number of non-zero points in the field.
///
/// ```
/// use honest_shamir::{Threshold, ShamirError};
///
/// let t = Threshold::new(3, 5).unwrap();
/// assert_eq!((t.required(), t.total()), (3, 5));
/// assert_eq!(t.to_string(), "3-of-5");
/// assert_eq!(Threshold::new(1, 5).unwrap_err(), ShamirError::InvalidThreshold { required: 1, total: 5 });
/// assert_eq!(Threshold::new(6, 5).unwrap_err(), ShamirError::InvalidThreshold { required: 6, total: 5 });
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Threshold {
    required: u8,
    total: u8,
}

impl Threshold {
    /// A `required`-of-`total` policy.
    pub const fn new(required: u8, total: u8) -> Result<Self, ShamirError> {
        if required < 2 || required > total {
            return Err(ShamirError::InvalidThreshold { required, total });
        }
        Ok(Self { required, total })
    }

    /// How many shares rebuild the secret, `k`.
    pub const fn required(self) -> u8 {
        self.required
    }

    /// How many shares are made, `n`.
    pub const fn total(self) -> u8 {
        self.total
    }
}

impl fmt::Display for Threshold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-of-{}", self.required, self.total)
    }
}
