//! Cosmos bech32 address derivation.
//!
//! Implemented directly against the Cosmos spec —
//! `bech32(hrp, ripemd160(sha256(compressed_pubkey)))` — so the address layer
//! does NOT depend on cosmrs. `tests/cosmos_vectors.rs` cross-checks this output
//! against cosmrs's `PublicKey::account_id`, guarding the two against drift.

use crate::types::AdapterError;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Derive a `<hrp>1…` bech32 address from a SEC1 secp256k1 pubkey.
///
/// Accepts either compressed (33-byte) or uncompressed (65-byte) SEC1 input;
/// k256 normalizes to the compressed form before hashing, so the derivation is
/// independent of the on-the-wire pubkey encoding. Empty/garbage input → `Err`
/// (no panic). A malformed `hrp` is surfaced by the bech32 library as `Err`.
pub fn address_from_pubkey(
    pubkey_sec1_compressed: &[u8],
    hrp: &str,
) -> Result<String, AdapterError> {
    // Parse + normalize to compressed SEC1. `from_sec1_bytes` accepts both
    // compressed and uncompressed points and rejects anything off-curve or
    // malformed (empty/garbage) — fail closed.
    let pk = k256::PublicKey::from_sec1_bytes(pubkey_sec1_compressed)
        .map_err(|e| AdapterError::BadIntent(format!("invalid secp256k1 pubkey: {e}")))?;
    let compressed = pk.to_encoded_point(true);

    let sha = Sha256::digest(compressed.as_bytes());
    let rip = Ripemd160::digest(sha);

    let hrp = bech32::Hrp::parse(hrp)
        .map_err(|e| AdapterError::BadIntent(format!("invalid bech32 hrp: {e}")))?;
    bech32::encode::<bech32::Bech32>(hrp, &rip)
        .map_err(|e| AdapterError::Encoding(format!("bech32 encode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compressed pubkey from the canonical test key 0x4646..4646.
    fn test_pk() -> Vec<u8> {
        use k256::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(
            &hex::decode("4646464646464646464646464646464646464646464646464646464646464646")
                .unwrap(),
        )
        .unwrap();
        sk.verifying_key().to_encoded_point(true).as_bytes().to_vec()
    }

    #[test]
    fn derives_cosmos1_address() {
        let addr = address_from_pubkey(&test_pk(), "cosmos").unwrap();
        assert!(addr.starts_with("cosmos1"), "got {addr}");
    }

    #[test]
    fn hrp_changes_prefix() {
        let addr = address_from_pubkey(&test_pk(), "osmo").unwrap();
        assert!(addr.starts_with("osmo1"), "got {addr}");
    }

    #[test]
    fn uncompressed_pubkey_normalizes_to_same_address() {
        use k256::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(
            &hex::decode("4646464646464646464646464646464646464646464646464646464646464646")
                .unwrap(),
        )
        .unwrap();
        let uncompressed = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        assert_eq!(uncompressed.len(), 65);
        let from_uncompressed = address_from_pubkey(&uncompressed, "cosmos").unwrap();
        let from_compressed = address_from_pubkey(&test_pk(), "cosmos").unwrap();
        assert_eq!(from_uncompressed, from_compressed);
    }

    #[test]
    fn empty_pubkey_errs() {
        assert!(address_from_pubkey(&[], "cosmos").is_err());
    }

    #[test]
    fn garbage_pubkey_errs() {
        assert!(address_from_pubkey(&[0xFF; 33], "cosmos").is_err());
    }
}
