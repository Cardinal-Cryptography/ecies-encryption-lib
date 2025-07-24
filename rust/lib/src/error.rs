use hex::FromHexError;
use thiserror::Error;

/// Result type with the `ecies-encryption-lib` crate's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// ECIES encryption lib errors
#[derive(Error, Debug)]
pub enum Error {
    #[error("Eliptic Curve Error: {0}")]
    ElipticCurve(#[from] k256::elliptic_curve::Error),
    #[error("Decryption failed")]
    Decryption,
    #[error("Failed to decode hex: {0}")]
    Decoding(#[from] FromHexError),
    #[error("Invalid message length (found {found:?} bytes, expected at most {expected:?} bytes)")]
    InvalidMessageLength { found: usize, expected: usize },
    #[error("Invalid padded length (found {found:?} bytes, expected at least {expected:?} bytes)")]
    InvalidPaddedLength { found: usize, expected: usize },
}
