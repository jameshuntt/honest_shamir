use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroize;

use crate::ShamirError;

/// One share: the x coordinate it was evaluated at and one byte per byte
/// of the secret.
///
/// The bytes are zeroized when the share is dropped, `Debug` shows only
/// the index and length, and equality is checked without an early exit.
/// A share is a secret in its own right: any `k` of them are the secret.
pub struct Share {
    index: u8,
    bytes: Vec<u8>,
}

impl Share {
    /// A share received from elsewhere. The index must be non-zero and the
    /// bytes non-empty; rejected bytes are zeroized before the error returns.
    pub fn new(index: u8, mut bytes: Vec<u8>) -> Result<Self, ShamirError> {
        if index == 0 {
            bytes.zeroize();
            return Err(ShamirError::ZeroIndex);
        }
        if bytes.is_empty() {
            return Err(ShamirError::EmptyShare);
        }
        Ok(Self { index, bytes })
    }

    pub(crate) fn from_parts(index: u8, bytes: Vec<u8>) -> Self {
        debug_assert!(index != 0 && !bytes.is_empty());
        Self { index, bytes }
    }

    /// The x coordinate, `1..=255`.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The share's bytes, one per byte of the secret.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// How many bytes the share holds, which is the length of the secret.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always false: a share is never built empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Take the bytes out. The caller owns them and their zeroization now.
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl Clone for Share {
    fn clone(&self) -> Self {
        Self { index: self.index, bytes: self.bytes.clone() }
    }
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share").field("index", &self.index).field("len", &self.bytes.len()).finish()
    }
}

impl PartialEq for Share {
    fn eq(&self, other: &Self) -> bool {
        if self.index != other.index || self.bytes.len() != other.bytes.len() {
            return false;
        }
        self.bytes.iter().zip(&other.bytes).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    }
}

impl Eq for Share {}

impl Zeroize for Share {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
