use hex::FromHexError;
use sha2::digest::crypto_common;
use thiserror::Error;

/// Result type with the `ecies-encryption-lib` crate's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// ECIES encryption lib errors
#[derive(Error, Debug)]
pub enum Error {
    #[error("Eliptic Curve Error: {0}")]
    ElipticCurve(#[from] k256::elliptic_curve::Error),
    #[error("Invalid Length Error : {0}")]
    CryptoInvalidLength(String),
    #[error("AES Error : {0}")]
    AES(#[from] aes_gcm::Error),
    #[error("Failed to decode: {0}")]
    Decoding(String),
    #[error("Invalid message length (found {found:?} bytes, expected at most {expected:?} bytes)")]
    InvalidMessageLength { found: usize, expected: usize },
    #[error("Invalid padded length (found {found:?} bytes, expected at least {expected:?} bytes)")]
    InvalidPaddedLength { found: usize, expected: usize },
}

impl From<FromHexError> for Error {
    fn from(error: FromHexError) -> Self {
        Error::Decoding(error.to_string())
    }
}

impl From<hkdf::InvalidLength> for Error {
    fn from(error: hkdf::InvalidLength) -> Self {
        Error::CryptoInvalidLength(error.to_string())
    }
}

impl From<crypto_common::InvalidLength> for Error {
    fn from(error: crypto_common::InvalidLength) -> Self {
        Error::CryptoInvalidLength(error.to_string())
    }
}
