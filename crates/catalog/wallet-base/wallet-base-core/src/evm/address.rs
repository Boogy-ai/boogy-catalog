use crate::types::AdapterError;
use alloy_primitives::keccak256;
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};

/// EVM address = last 20 bytes of keccak256(uncompressed_pubkey[1..]) (drop 0x04 tag),
/// EIP-55 checksummed.
pub fn address_from_pubkey(pubkey_sec1: &[u8]) -> Result<String, AdapterError> {
    let pk = PublicKey::from_sec1_bytes(pubkey_sec1)
        .map_err(|e| AdapterError::Encoding(format!("pubkey: {e}")))?;
    let point = pk.to_encoded_point(false); // 0x04 || X || Y
    let bytes = point.as_bytes();
    let hash = keccak256(&bytes[1..]); // skip 0x04
    Ok(to_checksum(&hash[12..]))
}

/// Test-only accessor for the EIP-55 checksum routine.
pub fn checksum_for_test(addr20: &[u8]) -> String { to_checksum(addr20) }

/// EIP-55 mixed-case checksum of 20 address bytes → `0x…`.
fn to_checksum(addr20: &[u8]) -> String {
    let hexed = hex::encode(addr20); // lowercase, 40 chars
    let hash = keccak256(hexed.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hexed.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            // nibble i of the hash (high nibble for even i, low for odd)
            let byte = hash[i / 2];
            let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
            if nibble >= 8 { out.push(c.to_ascii_uppercase()); } else { out.push(c); }
        }
    }
    out
}
