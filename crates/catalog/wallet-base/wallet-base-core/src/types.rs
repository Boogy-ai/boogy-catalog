//! Chain-agnostic transaction types + the `ChainAdapter` contract.

use serde::{Deserialize, Serialize};

/// Supported chains (this plan implements `Evm`; others land in later plans).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain { Evm, Btc, Cosmos, Solana }

/// secp256k1 signature, externally produced by credops. `recovery_id` is the
/// EVM `v` parity (0/1). DER/64-byte encodings are derived by adapters as needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secp256k1Signature { pub r: [u8; 32], pub s: [u8; 32], pub recovery_id: u8 }

/// What an adapter needs signed. EVM/BTC/Cosmos use `Digest`; Solana uses `Message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignRequest { Digest([u8; 32]), Message(Vec<u8>) }

/// Normalized EVM transaction intent (chain-specific intents are added per chain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmIntent {
    pub to: Option<String>,        // 0x-hex address; None = contract creation
    /// The signer's 0x address (host-derived from the wallet key). Used ONLY to
    /// self-verify that the assembled signature recovers to it (#15). Empty =
    /// skip the recover-and-compare (lower-level encoding paths / unit fixtures);
    /// the production send path always sets it from the wallet row.
    #[serde(default)]
    pub from_address: String,
    pub value_wei: String,         // decimal string (u256-safe)
    pub data_hex: String,          // 0x-prefixed calldata ("" or "0x" = empty)
    pub chain_id: u64,
    pub nonce: Option<u64>,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub gas_limit: Option<u64>,
    pub legacy: bool,
    pub gas_price: Option<String>,
}

/// Fetched on-chain state needed to finalize a tx (EVM: nonce + fee context).
#[derive(Debug, Clone, Default)]
pub struct ChainState {
    pub nonce: Option<u64>,
    pub base_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub gas_price: Option<u128>,
    pub gas_limit: Option<u64>,
}

/// An unsigned tx: the canonical preimage plus what must be signed.
#[derive(Debug, Clone)]
pub struct Unsigned { pub preimage: Vec<u8>, pub sign_requests: Vec<SignRequest> }

/// Broadcast-ready raw transaction bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTx(pub Vec<u8>);
impl RawTx { pub fn to_hex(&self) -> String { format!("0x{}", hex::encode(&self.0)) } }

#[derive(Debug, Clone, Default)]
pub struct FeeEstimate {
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub gas_price: Option<u128>,
    pub gas_limit: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Simulation { pub success: bool, pub gas_used: Option<u64>, pub error: Option<String> }

/// A JSON-RPC request the handler will send via `outbound_http`.
#[derive(Debug, Clone)]
pub struct RpcRequest { pub method: String, pub params: serde_json::Value }

/// The raw JSON-RPC response body the handler hands back for parsing.
pub type RpcResponse = serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    BadIntent(String),
    Encoding(String),
    Rpc(String),
}
impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterError::BadIntent(m) => write!(f, "bad intent: {m}"),
            AdapterError::Encoding(m) => write!(f, "encoding: {m}"),
            AdapterError::Rpc(m) => write!(f, "rpc: {m}"),
        }
    }
}
impl std::error::Error for AdapterError {}

/// Convert a credops secp256k1 signature (compact `r||s` + recovery id) to the
/// adapter's [`Secp256k1Signature`]. The host signer (`boogy-sign::local`)
/// returns `serialize_compact()` — a 64-byte `r||s` buffer plus a recovery id —
/// so `r = bytes[0..32]`, `s = bytes[32..64]`. EVM requires the recovery id;
/// reject if absent or if the byte length is wrong (defensive against a
/// malformed signer response).
pub fn secp_sig_from_compact(
    bytes: &[u8],
    recovery_id: Option<u8>,
) -> Result<Secp256k1Signature, AdapterError> {
    if bytes.len() != 64 {
        return Err(AdapterError::Encoding(format!(
            "expected 64-byte compact sig, got {}",
            bytes.len()
        )));
    }
    let rec = recovery_id
        .ok_or_else(|| AdapterError::Encoding("missing recovery id (required for EVM)".into()))?;
    let mut r = [0u8; 32];
    r.copy_from_slice(&bytes[0..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&bytes[32..64]);
    Ok(Secp256k1Signature { r, s, recovery_id: rec })
}

/// The per-chain contract. EVM implements it here; later plans add the others.
pub trait ChainAdapter {
    fn derive_address(&self, pubkey_sec1: &[u8]) -> Result<String, AdapterError>;
    fn build_unsigned(&self, intent: &EvmIntent, state: &ChainState) -> Result<Unsigned, AdapterError>;
    fn assemble_signed(&self, unsigned: &Unsigned, sigs: &[Secp256k1Signature]) -> Result<RawTx, AdapterError>;
    fn parse_fees(&self, resp: &RpcResponse) -> Result<FeeEstimate, AdapterError>;
    fn parse_simulation(&self, resp: &RpcResponse) -> Result<Simulation, AdapterError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secp_signature_roundtrips_rsv() {
        let sig = Secp256k1Signature { r: [0x11; 32], s: [0x22; 32], recovery_id: 1 };
        assert_eq!(sig.recovery_id, 1);
        assert_eq!(sig.r[0], 0x11);
    }

    #[test]
    fn secp_sig_from_compact_valid_splits_r_and_s() {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&[0xAA; 32]);
        bytes[32..64].copy_from_slice(&[0xBB; 32]);
        let sig = secp_sig_from_compact(&bytes, Some(1)).expect("valid");
        assert_eq!(sig.r, [0xAA; 32]);
        assert_eq!(sig.s, [0xBB; 32]);
        assert_eq!(sig.recovery_id, 1);
    }

    #[test]
    fn secp_sig_from_compact_rejects_wrong_length() {
        for len in [0usize, 63, 65] {
            let bytes = vec![0u8; len];
            let err = secp_sig_from_compact(&bytes, Some(0)).unwrap_err();
            assert!(matches!(err, AdapterError::Encoding(_)), "len {len} must Err");
        }
    }

    #[test]
    fn secp_sig_from_compact_rejects_missing_recovery_id() {
        let bytes = [0u8; 64];
        let err = secp_sig_from_compact(&bytes, None).unwrap_err();
        match err {
            AdapterError::Encoding(m) => assert!(m.contains("recovery id"), "msg: {m}"),
            other => panic!("expected Encoding, got {other:?}"),
        }
    }
}
