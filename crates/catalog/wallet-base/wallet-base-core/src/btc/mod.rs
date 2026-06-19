//! Bitcoin chain adapter — P2WPKH (native SegWit), host-signed mode.
//!
//! Bitcoin is the first UTXO chain in this crate, which shapes the adapter
//! differently from the account-based chains (EVM/Cosmos/Solana):
//!
//!  1. A transfer spends **N inputs** (the selected UTXOs) and produces 1–2
//!     outputs (recipient + optional change back to the sender's own address).
//!     So `build_unsigned` emits **N** [`SignRequest::Digest`] — one BIP143
//!     sighash per input, in input order — and `assemble_signed` takes **N**
//!     signatures (one per input).
//!  2. The signing curve is secp256k1 (same as EVM/Cosmos): P2WPKH signs ECDSA
//!     over the per-input BIP143 sighash, so we reuse the crate's
//!     [`Secp256k1Signature`](crate::types::Secp256k1Signature) `r||s` type. The
//!     recovery id is unused for P2WPKH (the pubkey rides in the witness).
//!  3. The signature lives in the **witness** (`[der||0x01, compressed_pubkey]`),
//!     not the legacy `script_sig`.
//!
//! The private key never enters this crate. The `bitcoin` crate is used ONLY for
//! address encoding + transaction/sighash construction + witness assembly; we
//! never call any local key-gen/signing convenience (`rand` /
//! `global-context` / `secp-recovery` features are OFF). This phase supports a
//! single recipient with implicit change back to the sender's own P2WPKH (the
//! common case); arbitrary script types / multi-recipient are deferred (YAGNI).

mod address;
pub mod coinselect;
pub mod rpc;
mod tx;

pub use coinselect::{select_coins, Selection};
pub use tx::{BtcIntent, Utxo};

/// Bitcoin network — selects the bech32 HRP (`bc1q…` vs `tb1q…`) and gates
/// `to_address` parsing in `build_unsigned`. Defaults to [`BtcNetwork::Mainnet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtcNetwork {
    Mainnet,
    Testnet,
}

impl Default for BtcNetwork {
    fn default() -> Self {
        BtcNetwork::Mainnet
    }
}

impl BtcNetwork {
    /// Map to the bech32 human-readable prefix used by `Address::p2wpkh`.
    pub(crate) fn known_hrp(self) -> bitcoin::address::KnownHrp {
        match self {
            BtcNetwork::Mainnet => bitcoin::address::KnownHrp::Mainnet,
            BtcNetwork::Testnet => bitcoin::address::KnownHrp::Testnets,
        }
    }

    /// Map to the `bitcoin::Network` used by `require_network` when validating a
    /// destination address. `Testnet` is the canonical representative of the
    /// `tb1q…`/`Testnets` HRP family.
    pub(crate) fn network(self) -> bitcoin::Network {
        match self {
            BtcNetwork::Mainnet => bitcoin::Network::Bitcoin,
            BtcNetwork::Testnet => bitcoin::Network::Testnet,
        }
    }
}

/// Bitcoin chain adapter (P2WPKH native SegWit; single-recipient transfer with
/// implicit change, host-signed).
pub struct BtcAdapter;

impl BtcAdapter {
    /// `bech32(P2WPKH(hash160(compressed_pubkey)))`. Requires a 33-byte
    /// compressed secp256k1 pubkey. See [`address_from_pubkey`].
    pub fn address_from_pubkey(
        compressed_pubkey: &[u8],
        network: BtcNetwork,
    ) -> Result<String, crate::types::AdapterError> {
        address::address_from_pubkey(compressed_pubkey, network)
    }

    /// Coin-select, build the unsigned tx, and emit one BIP143 sighash per
    /// selected input (in input order). See [`tx::build_unsigned`].
    pub fn build_unsigned(
        intent: &BtcIntent,
    ) -> Result<crate::types::Unsigned, crate::types::AdapterError> {
        tx::build_unsigned(intent)
    }

    /// Splice N secp256k1 signatures (one per input, in input order) into the
    /// P2WPKH witnesses. `sigs.len()` MUST equal the number of inputs. See
    /// [`tx::assemble_signed`].
    pub fn assemble_signed(
        unsigned: &crate::types::Unsigned,
        sigs: &[crate::types::Secp256k1Signature],
    ) -> Result<crate::types::RawTx, crate::types::AdapterError> {
        tx::assemble_signed(unsigned, sigs)
    }
}

pub use address::address_from_pubkey;

/// Compress a SEC1 secp256k1 public key to its 33-byte compressed form.
///
/// `signing_create_key` may return either the compressed (33-byte) or the
/// uncompressed (65-byte) SEC1 encoding depending on the host signer, but P2WPKH
/// is defined ONLY over the compressed key (`address_from_pubkey` requires it,
/// and the witness must carry the SAME compressed key the address commits to).
/// This normalizes either encoding to 33 compressed bytes; garbage / off-curve /
/// wrong-length input → [`AdapterError::BadIntent`] with NO panic.
///
/// Additive helper consumed by the service's `do_ensure_wallet` for the `btc`
/// arm; the existing btc address/tx logic is unchanged.
pub fn compress_pubkey(sec1: &[u8]) -> Result<Vec<u8>, crate::types::AdapterError> {
    let pk = bitcoin::secp256k1::PublicKey::from_slice(sec1)
        .map_err(|e| crate::types::AdapterError::BadIntent(format!("invalid secp256k1 pubkey: {e}")))?;
    Ok(pk.serialize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed valid secp256k1 pubkey: the generator point G in both SEC1
    // encodings (compressed 33-byte / uncompressed 65-byte). Compressing either
    // must yield the canonical 33-byte compressed form, and the result must be a
    // valid P2WPKH input (round-trips through `address_from_pubkey`).
    const G_COMPRESSED: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G_UNCOMPRESSED: &str =
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
         483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    #[test]
    fn compress_pubkey_idempotent_on_compressed() {
        let c = hex::decode(G_COMPRESSED).expect("hex");
        let out = compress_pubkey(&c).expect("ok");
        assert_eq!(out.len(), 33);
        assert_eq!(out, c);
    }

    #[test]
    fn compress_pubkey_compresses_uncompressed() {
        let u = hex::decode(G_UNCOMPRESSED.replace(['\n', ' '], "")).expect("hex");
        assert_eq!(u.len(), 65);
        let out = compress_pubkey(&u).expect("ok");
        assert_eq!(out.len(), 33);
        // Compressing the uncompressed encoding yields the canonical compressed
        // key, and that key is a valid P2WPKH input.
        assert_eq!(out, hex::decode(G_COMPRESSED).expect("hex"));
        assert!(address_from_pubkey(&out, BtcNetwork::Mainnet).is_ok());
    }

    #[test]
    fn compress_pubkey_rejects_garbage() {
        assert!(compress_pubkey(&[]).is_err());
        assert!(compress_pubkey(&[0u8; 33]).is_err()); // all-zero is off-curve
        assert!(compress_pubkey(b"not a pubkey").is_err());
    }
}
