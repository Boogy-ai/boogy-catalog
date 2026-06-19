//! Solana chain adapter — external-signer mode.
//!
//! Solana is the first non-secp256k1 chain in this crate: the signing curve is
//! **Ed25519**, not secp256k1. Two consequences shape this adapter:
//!
//!  1. The address IS the 32-byte Ed25519 public key, base58-encoded — NO
//!     hashing (unlike EVM keccak / Cosmos ripemd160(sha256)). See [`address`].
//!  2. Ed25519 signs the **whole serialized message**, and the signature is a
//!     **raw 64-byte** sig — there is no recovery id and no r/s split. So
//!     `build_unsigned` emits a [`SignRequest::Message`](crate::types::SignRequest)
//!     carrying the exact serialized `Message`, and `assemble_signed` takes a raw
//!     `&[u8]` 64-byte signature (NOT the secp256k1 `Secp256k1Signature` r/s type
//!     the EVM/Cosmos adapters use).
//!
//! The private key never enters this crate. The Solana libs are used ONLY for
//! address encoding + message/transaction serialization; we never call any
//! local keypair-signing convenience. This phase supports a single SystemProgram
//! `transfer` (the common case); arbitrary instructions are deferred (YAGNI).

mod address;
pub mod rpc;
mod tx;

pub use address::address_from_pubkey;
pub use tx::SolanaIntent;

/// Solana chain adapter (Ed25519; SystemProgram transfer, external-signer).
pub struct SolanaAdapter;

impl SolanaAdapter {
    /// `base58(ed25519_pubkey)` — the address IS the 32-byte pubkey, no hashing.
    /// See [`address_from_pubkey`].
    pub fn address_from_pubkey(
        ed25519_pubkey: &[u8],
    ) -> Result<String, crate::types::AdapterError> {
        address::address_from_pubkey(ed25519_pubkey)
    }

    pub fn build_unsigned(
        intent: &SolanaIntent,
    ) -> Result<crate::types::Unsigned, crate::types::AdapterError> {
        tx::build_unsigned(intent)
    }

    /// Splice a raw 64-byte Ed25519 signature into the assembled transaction.
    /// NOTE: unlike the EVM/Cosmos adapters (which take `&[Secp256k1Signature]`),
    /// Solana takes the raw 64-byte sig directly — Ed25519 has no r/s split.
    pub fn assemble_signed(
        unsigned: &crate::types::Unsigned,
        sig64: &[u8],
    ) -> Result<crate::types::RawTx, crate::types::AdapterError> {
        tx::assemble_signed(unsigned, sig64)
    }
}
