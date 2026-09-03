use core::fmt;

/// Why a split, reconstruction or refresh was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShamirError {
    /// `required` must be at least 2 and at most `total`.
    InvalidThreshold {
        /// The `k` that was asked for.
        required: u8,
        /// The `n` that was asked for.
        total: u8,
    },
    /// The secret has no bytes.
    EmptySecret,
    /// A share has no bytes.
    EmptyShare,
    /// A share index of zero would hold the secret itself.
    ZeroIndex,
    /// Two shares in one set carry the same index.
    DuplicateIndex(u8),
    /// Fewer shares than the threshold requires.
    TooFewShares {
        /// The `k` of the threshold.
        required: u8,
        /// How many shares were given.
        provided: usize,
    },
    /// Shares in one set are not all the same length.
    LengthMismatch {
        /// The length of the first share.
        expected: usize,
        /// A length that differed.
        found: usize,
    },
    /// The random generator failed to produce bytes.
    Randomness,
}

impl fmt::Display for ShamirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidThreshold { required, total } => {
                write!(f, "invalid threshold {required}-of-{total}: need 2 <= required <= total")
            }
            Self::EmptySecret => write!(f, "secret must not be empty"),
            Self::EmptyShare => write!(f, "share must not be empty"),
            Self::ZeroIndex => write!(f, "share index must not be zero"),
            Self::DuplicateIndex(x) => write!(f, "two shares carry index {x}"),
            Self::TooFewShares { required, provided } => {
                write!(f, "too few shares: {provided} provided, {required} required")
            }
            Self::LengthMismatch { expected, found } => {
                write!(f, "share lengths differ: expected {expected}, found {found}")
            }
            Self::Randomness => write!(f, "random generator failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ShamirError {}
