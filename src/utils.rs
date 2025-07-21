use crate::error::{Error, Result};

pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

pub fn from_hex(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str).map_err(Error::Decoding)
}
