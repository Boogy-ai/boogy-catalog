//! Cosmos (cosmrs) chain adapter — external-signer mode.
//!
//! cosmrs is used ONLY for proto encoding (Body / AuthInfo / SignDoc / TxRaw);
//! the private key never enters this crate. `build_unsigned` produces a 32-byte
//! SHA-256 digest of the SignDoc (SIGN_MODE_DIRECT) for credops to sign;
//! `assemble_signed` splices the returned 64-byte compact `r||s` signature into a
//! `TxRaw` — no recovery id is needed (the pubkey is carried in `auth_info`).
//!
//! This phase supports a single bank `MsgSend` (the common case). Arbitrary
//! `Any` messages are deferred (YAGNI).

mod address;
pub mod rpc;
mod tx;

pub use address::address_from_pubkey;

/// Normalized intent for a single-`MsgSend` Cosmos transfer.
#[derive(Debug, Clone)]
pub struct CosmosIntent {
    pub chain_id: String,              // "cosmoshub-4"
    pub hrp: String,                   // "cosmos"
    pub account_number: u64,
    pub sequence: u64,
    pub from_address: String,          // bech32
    pub to_address: String,            // bech32
    pub amount: String,                // decimal, base denom
    pub denom: String,                 // "uatom"
    pub fee_amount: String,            // decimal
    pub fee_denom: String,
    pub gas_limit: u64,
    pub memo: String,
    pub pubkey_compressed_hex: String, // 33-byte compressed pubkey, hex
}

/// Cosmos chain adapter (Cosmos SDK chains; SIGN_MODE_DIRECT bank send).
pub struct CosmosAdapter;

impl CosmosAdapter {
    /// `bech32(hrp, ripemd160(sha256(pubkey)))`. See [`address_from_pubkey`].
    pub fn address_from_pubkey(
        pubkey_sec1_compressed: &[u8],
        hrp: &str,
    ) -> Result<String, crate::types::AdapterError> {
        address::address_from_pubkey(pubkey_sec1_compressed, hrp)
    }

    pub fn build_unsigned(
        intent: &CosmosIntent,
    ) -> Result<crate::types::Unsigned, crate::types::AdapterError> {
        tx::build_unsigned(intent)
    }

    pub fn assemble_signed(
        unsigned: &crate::types::Unsigned,
        sigs: &[crate::types::Secp256k1Signature],
    ) -> Result<crate::types::RawTx, crate::types::AdapterError> {
        tx::assemble_signed(unsigned, sigs)
    }
}
