//! P2WPKH (native SegWit v0) address derivation.
//!
//! `bc1q…` (mainnet) / `tb1q…` (testnet) = bech32 over `hash160(pubkey)` with a
//! v0 witness program. We REQUIRE a 33-byte **compressed** secp256k1 pubkey:
//! `CompressedPublicKey::from_slice` rejects uncompressed (65-byte), garbage, and
//! empty inputs — P2WPKH is undefined for uncompressed keys, so this is a
//! fail-closed correctness gate, not a stylistic one.

use super::BtcNetwork;
use crate::types::AdapterError;

/// Derive the P2WPKH address string for `compressed_pubkey` on `network`.
///
/// Input must be a valid 33-byte compressed secp256k1 pubkey; anything else
/// (uncompressed, wrong length, off-curve, empty) → [`AdapterError::BadIntent`]
/// with NO panic.
pub fn address_from_pubkey(
    compressed_pubkey: &[u8],
    network: BtcNetwork,
) -> Result<String, AdapterError> {
    let pk = bitcoin::key::CompressedPublicKey::from_slice(compressed_pubkey)
        .map_err(|e| AdapterError::BadIntent(format!("invalid compressed pubkey: {e}")))?;
    let addr = bitcoin::Address::p2wpkh(&pk, network.known_hrp());
    Ok(addr.to_string())
}
