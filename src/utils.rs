pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

pub fn from_hex(hex_str: &str) -> anyhow::Result<Vec<u8>> {
    hex::decode(hex_str).map_err(|e| anyhow::anyhow!("Failed to decode hex: {}", e))
}
