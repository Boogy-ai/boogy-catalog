//! Solana address derivation.
//!
//! A Solana address IS the 32-byte Ed25519 public key encoded in base58 — there
//! is NO hashing step (unlike EVM keccak or Cosmos ripemd160(sha256)). We encode
//! via `solana_pubkey::Pubkey::to_string()`, which is the canonical base58 form
//! and byte-identical to `bs58::encode(pubkey32).into_string()`.

use crate::types::AdapterError;

/// Derive a base58 Solana address from a 32-byte Ed25519 public key.
///
/// Requires EXACTLY 32 bytes; any other length → `Err` (no panic) — fail closed.
pub fn address_from_pubkey(ed25519_pubkey: &[u8]) -> Result<String, AdapterError> {
    let arr: [u8; 32] = ed25519_pubkey.try_into().map_err(|_| {
        AdapterError::BadIntent(format!(
            "ed25519 pubkey must be 32 bytes, got {}",
            ed25519_pubkey.len()
        ))
    })?;
    // Canonical base58 — no hashing. Pubkey::from is infallible for a [u8; 32].
    Ok(solana_pubkey::Pubkey::from(arr).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_zero_pubkey_is_canonical_base58() {
        let addr = address_from_pubkey(&[0u8; 32]).unwrap();
        assert_eq!(addr, "11111111111111111111111111111111");
    }

    #[test]
    fn matches_bs58_encode_directly() {
        let pk = [0x42u8; 32];
        let addr = address_from_pubkey(&pk).unwrap();
        assert_eq!(addr, bs58::encode(pk).into_string());
    }

    #[test]
    fn wrong_length_errs() {
        for len in [0usize, 31, 33, 64] {
            let bytes = vec![0u8; len];
            assert!(
                address_from_pubkey(&bytes).is_err(),
                "len {len} must Err"
            );
        }
    }
}
