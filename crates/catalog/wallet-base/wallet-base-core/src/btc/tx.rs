//! P2WPKH UTXO transaction build + per-input BIP143 sighash + witness assemble
//! (host-signed mode).
//!
//! Pinned `bitcoin` 0.32 API actually used here:
//!   - Address: `CompressedPublicKey::from_slice` → `Address::p2wpkh(&pk, hrp)`
//!     → `addr.script_pubkey()`.
//!   - Destination validation: `Address::from_str` (NetworkUnchecked) +
//!     `require_network(net)` — gates wrong-network sends.
//!   - Unsigned tx: struct literals (`Transaction`/`TxIn`/`TxOut`/`OutPoint`).
//!   - Per-input sighash: `SighashCache::p2wpkh_signature_hash(i, &spk, value,
//!     EcdsaSighashType::All)` → `to_byte_array()` (the 32-byte digest to sign).
//!     The per-input prevout VALUE is load-bearing in BIP143.
//!   - Assemble: `secp256k1::ecdsa::Signature::from_compact(r||s)` →
//!     `normalize_s()` (BIP62 low-S, ALWAYS) → `ecdsa::Signature::sighash_all` →
//!     `Witness::p2wpkh(&sig, &pubkey)` → `input[i].witness = …` → `consensus::serialize`.

use super::coinselect::select_coins;
use super::BtcNetwork;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use bitcoin::hashes::Hash;

/// One unspent output the sender controls (a P2WPKH UTXO on its own address).
/// `value_sat` is the prevout amount — load-bearing for the BIP143 sighash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value_sat: u64,
}

/// Normalized intent for a single-recipient P2WPKH transfer with implicit change
/// back to the sender's own P2WPKH address.
#[derive(Debug, Clone)]
pub struct BtcIntent {
    /// 33-byte compressed secp256k1 pubkey, hex. The sender's key — its P2WPKH
    /// is both what every input spends and where change returns.
    pub from_pubkey_hex: String,
    pub network: BtcNetwork,
    /// Destination bech32 address; validated for `network`.
    pub to_address: String,
    pub amount_sat: u64,
    pub fee_rate_sat_vb: u64,
    /// The sender's spendable UTXOs (all on the sender's own P2WPKH).
    pub utxos: Vec<Utxo>,
}

/// Carried in `Unsigned.preimage` so `assemble_signed` rebuilds the tx + every
/// witness deterministically without re-running coin selection. We persist the
/// consensus-serialized unsigned tx (input order fixed) + the compressed pubkey
/// hex (the witness's second element); the per-input prevout values were only
/// needed to compute the sighashes (already consumed in `build_unsigned`).
#[derive(Serialize, Deserialize)]
struct ResolvedBtcTx {
    /// Consensus-serialized unsigned `Transaction` (witnesses empty).
    unsigned_tx: Vec<u8>,
    /// Sender's 33-byte compressed pubkey, hex (the witness pubkey for EVERY
    /// input — all inputs are the sender's own P2WPKH).
    pubkey_compressed_hex: String,
}

fn parse_compressed_pubkey(
    hex_str: &str,
) -> Result<bitcoin::key::CompressedPublicKey, AdapterError> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| AdapterError::BadIntent(format!("invalid pubkey hex: {e}")))?;
    bitcoin::key::CompressedPublicKey::from_slice(&bytes)
        .map_err(|e| AdapterError::BadIntent(format!("invalid compressed pubkey: {e}")))
}

pub fn build_unsigned(intent: &BtcIntent) -> Result<Unsigned, AdapterError> {
    // Reject a zero / sub-dust recipient amount up front (#11), BEFORE the key is
    // touched. Such a send can only ever build a non-standard (dust) output the
    // network refuses to relay — fail closed rather than waste a key-touch and a
    // daily-spend slot on a tx that can never confirm.
    if intent.amount_sat < super::coinselect::DUST_THRESHOLD_SAT {
        return Err(AdapterError::BadIntent(format!(
            "recipient amount {} sat is below the dust threshold ({} sat)",
            intent.amount_sat,
            super::coinselect::DUST_THRESHOLD_SAT
        )));
    }

    // Sender's compressed pubkey → its own P2WPKH script_pubkey. Each input
    // spends one of these; change (if any) returns to it.
    let pk = parse_compressed_pubkey(&intent.from_pubkey_hex)?;
    let sender_addr = bitcoin::Address::p2wpkh(&pk, intent.network.known_hrp());
    let sender_spk = sender_addr.script_pubkey();

    // Validate the destination address FOR THIS NETWORK (a mainnet send to a
    // tb1q… testnet address — or vice versa — fails closed here).
    let to_addr = bitcoin::Address::from_str(intent.to_address.trim())
        .map_err(|e| AdapterError::BadIntent(format!("invalid to_address: {e}")))?
        .require_network(intent.network.network())
        .map_err(|e| AdapterError::BadIntent(format!("to_address wrong network: {e}")))?;
    let to_spk = to_addr.script_pubkey();

    // Coin-select against amount + estimated fee (fail-closed on insufficient).
    let selection = select_coins(&intent.utxos, intent.amount_sat, intent.fee_rate_sat_vb)?;

    // Build inputs from the selected UTXOs (input order == selection order).
    let mut inputs: Vec<bitcoin::TxIn> = Vec::with_capacity(selection.selected.len());
    for u in &selection.selected {
        let txid = u
            .txid
            .trim()
            .parse::<bitcoin::Txid>()
            .map_err(|e| AdapterError::BadIntent(format!("invalid utxo txid {}: {e}", u.txid)))?;
        inputs.push(bitcoin::TxIn {
            previous_output: bitcoin::OutPoint { txid, vout: u.vout },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        });
    }

    // Outputs: recipient first, then optional change back to the sender.
    let mut outputs: Vec<bitcoin::TxOut> = vec![bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(intent.amount_sat),
        script_pubkey: to_spk,
    }];
    if selection.change_sat > 0 {
        outputs.push(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(selection.change_sat),
            script_pubkey: sender_spk.clone(),
        });
    }

    let unsigned_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    // One BIP143 sighash per input (input order). Each input spends the
    // sender's own P2WPKH, so the prevout script is `sender_spk` and the prevout
    // value is the selected UTXO's amount (load-bearing in BIP143).
    let mut cache = bitcoin::sighash::SighashCache::new(&unsigned_tx);
    let mut sign_requests: Vec<SignRequest> = Vec::with_capacity(selection.selected.len());
    for (i, u) in selection.selected.iter().enumerate() {
        let sighash = cache
            .p2wpkh_signature_hash(
                i,
                &sender_spk,
                bitcoin::Amount::from_sat(u.value_sat),
                bitcoin::EcdsaSighashType::All,
            )
            .map_err(|e| AdapterError::Encoding(format!("p2wpkh sighash input {i}: {e}")))?;
        let digest: [u8; 32] = sighash.to_byte_array();
        sign_requests.push(SignRequest::Digest(digest));
    }

    let resolved = ResolvedBtcTx {
        unsigned_tx: bitcoin::consensus::serialize(&unsigned_tx),
        pubkey_compressed_hex: hex::encode(pk.to_bytes()),
    };
    let preimage = serde_json::to_vec(&resolved)
        .map_err(|e| AdapterError::Encoding(format!("serialize resolved btc tx: {e}")))?;

    Ok(Unsigned {
        preimage,
        sign_requests,
    })
}

pub fn assemble_signed(
    unsigned: &Unsigned,
    sigs: &[Secp256k1Signature],
) -> Result<RawTx, AdapterError> {
    let resolved: ResolvedBtcTx = serde_json::from_slice(&unsigned.preimage)
        .map_err(|e| AdapterError::Encoding(format!("deserialize resolved btc tx: {e}")))?;

    let mut tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&resolved.unsigned_tx)
        .map_err(|e| AdapterError::Encoding(format!("deserialize unsigned tx: {e}")))?;

    // N inputs → N signatures, exactly. A wrong count (the host returned too few
    // or too many) is a hard error — fail closed rather than emit a tx with a
    // missing or stray witness.
    if sigs.len() != tx.input.len() {
        return Err(AdapterError::BadIntent(format!(
            "BTC requires exactly {} signature(s) (one per input), got {}",
            tx.input.len(),
            sigs.len()
        )));
    }

    // The witness pubkey is the sender's compressed key (every input is the
    // sender's own P2WPKH). Parse it once.
    let pk_bytes = hex::decode(resolved.pubkey_compressed_hex.trim())
        .map_err(|e| AdapterError::Encoding(format!("invalid stored pubkey hex: {e}")))?;
    let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&pk_bytes)
        .map_err(|e| AdapterError::Encoding(format!("invalid stored pubkey: {e}")))?;

    // The per-input BIP143 sighashes (input order) come straight from
    // build_unsigned via `unsigned.sign_requests` — the exact digests each
    // signature must commit to. Used to self-verify every signature below.
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();

    for (i, sig) in sigs.iter().enumerate() {
        // Rebuild the 64-byte compact r||s from the crate's signature type.
        let mut compact = [0u8; 64];
        compact[0..32].copy_from_slice(&sig.r);
        compact[32..64].copy_from_slice(&sig.s);

        let mut secp_sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(&compact)
            .map_err(|e| AdapterError::Encoding(format!("invalid compact sig input {i}: {e}")))?;
        // BIP62 low-S: enforce in place, always (network policy rejects high-S).
        secp_sig.normalize_s();

        // SELF-VERIFY (#7): the signature MUST validate against this input's
        // BIP143 sighash under the sender's pubkey before we splice it. A
        // misordered, wrong, or corrupt signature is rejected here (fail loud)
        // rather than producing a tx the network silently rejects at broadcast.
        let digest = match unsigned.sign_requests.get(i) {
            Some(SignRequest::Digest(d)) => *d,
            _ => {
                return Err(AdapterError::Encoding(format!(
                    "missing BIP143 sighash for input {i}"
                )))
            }
        };
        let msg = bitcoin::secp256k1::Message::from_digest(digest);
        secp.verify_ecdsa(&msg, &secp_sig, &pubkey).map_err(|_| {
            AdapterError::BadIntent(format!(
                "signature {i} does not verify against its BIP143 sighash"
            ))
        })?;

        let btc_sig = bitcoin::ecdsa::Signature::sighash_all(secp_sig);
        // Witness for P2WPKH = [der_sig||sighash_type, compressed_pubkey].
        tx.input[i].witness = bitcoin::Witness::p2wpkh(&btc_sig, &pubkey);
    }

    let wire = bitcoin::consensus::serialize(&tx);
    Ok(RawTx(wire))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc::BtcAdapter;

    // Authoritative spike vector: this compressed pubkey → bc1qvzvkjn4… (KAT in
    // tests/btc_vectors.rs). Reused here for the build/assemble flow.
    const PUBKEY_HEX: &str =
        "033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc";

    fn utxo(value: u64) -> Utxo {
        Utxo {
            txid: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            vout: 0,
            value_sat: value,
        }
    }

    fn fixture_intent() -> BtcIntent {
        BtcIntent {
            from_pubkey_hex: PUBKEY_HEX.into(),
            network: BtcNetwork::Mainnet,
            // A real mainnet P2WPKH address (the sender's own, for simplicity).
            to_address: "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw".into(),
            amount_sat: 50_000,
            fee_rate_sat_vb: 1,
            utxos: vec![utxo(100_000)],
        }
    }

    #[test]
    fn build_unsigned_emits_one_digest_per_input() {
        let u = build_unsigned(&fixture_intent()).unwrap();
        assert_eq!(u.sign_requests.len(), 1);
        match &u.sign_requests[0] {
            SignRequest::Digest(d) => assert_eq!(d.len(), 32),
            other => panic!("expected Digest, got {other:?}"),
        }
    }

    #[test]
    fn bad_pubkey_hex_errs() {
        let mut i = fixture_intent();
        i.from_pubkey_hex = "zzzz".into();
        assert!(build_unsigned(&i).is_err());
    }

    #[test]
    fn assemble_requires_one_sig_per_input() {
        let u = build_unsigned(&fixture_intent()).unwrap();
        let sig = Secp256k1Signature { r: [0x11; 32], s: [0x22; 32], recovery_id: 0 };
        assert!(assemble_signed(&u, &[]).is_err(), "0 sigs (1 input) → Err");
        assert!(
            assemble_signed(&u, &[sig.clone(), sig.clone()]).is_err(),
            "2 sigs (1 input) → Err"
        );
        // A structurally-valid-but-wrong signature (correct count) is now REJECTED
        // by the sighash self-verify (#7) — see assemble_rejects_wrong_signature.
        let _ = BtcAdapter::assemble_signed(&u, &[sig]);
    }

    /// A deterministic test keypair + its compressed-pubkey hex.
    fn test_keypair() -> (bitcoin::secp256k1::SecretKey, String) {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        (sk, hex::encode(pk.serialize()))
    }

    /// Sign every per-input sighash of `u` with `sk` — produces real, low-S,
    /// verifiable secp256k1 signatures (RFC6979).
    fn sign_all(u: &Unsigned, sk: &bitcoin::secp256k1::SecretKey) -> Vec<Secp256k1Signature> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        u.sign_requests
            .iter()
            .map(|sr| {
                let d = match sr {
                    SignRequest::Digest(d) => *d,
                    other => panic!("expected Digest, got {other:?}"),
                };
                let msg = bitcoin::secp256k1::Message::from_digest(d);
                let c = secp.sign_ecdsa(&msg, sk).serialize_compact();
                let mut r = [0u8; 32];
                r.copy_from_slice(&c[0..32]);
                let mut s = [0u8; 32];
                s.copy_from_slice(&c[32..64]);
                Secp256k1Signature { r, s, recovery_id: 0 }
            })
            .collect()
    }

    #[test]
    fn assemble_accepts_valid_signatures() {
        let (sk, pk_hex) = test_keypair();
        let intent = BtcIntent { from_pubkey_hex: pk_hex, ..fixture_intent() };
        let u = build_unsigned(&intent).unwrap();
        let sigs = sign_all(&u, &sk);
        assert!(
            BtcAdapter::assemble_signed(&u, &sigs).is_ok(),
            "a correctly-signed tx assembles"
        );
    }

    #[test]
    fn assemble_rejects_wrong_signature() {
        // Right count, but the signature does not verify against the input's
        // BIP143 sighash → rejected (no broadcast-of-garbage; #7).
        let (_sk, pk_hex) = test_keypair();
        let intent = BtcIntent { from_pubkey_hex: pk_hex, ..fixture_intent() };
        let u = build_unsigned(&intent).unwrap();
        let bad = Secp256k1Signature { r: [0x11; 32], s: [0x22; 32], recovery_id: 0 };
        assert!(
            BtcAdapter::assemble_signed(&u, &[bad]).is_err(),
            "a signature that doesn't match its sighash is rejected"
        );
    }

    #[test]
    fn assemble_rejects_misordered_signatures() {
        // Two inputs share one pubkey but have DISTINCT sighashes; swapping the
        // two valid signatures must fail verification (#7 — the misordering case).
        let (sk, pk_hex) = test_keypair();
        let intent = BtcIntent {
            from_pubkey_hex: pk_hex,
            amount_sat: 50_000,
            utxos: vec![
                Utxo { txid: utxo(40_000).txid, vout: 0, value_sat: 40_000 },
                Utxo {
                    txid: "0000000000000000000000000000000000000000000000000000000000000002"
                        .into(),
                    vout: 1,
                    value_sat: 40_000,
                },
            ],
            ..fixture_intent()
        };
        let u = build_unsigned(&intent).unwrap();
        assert_eq!(u.sign_requests.len(), 2);
        let mut sigs = sign_all(&u, &sk);
        sigs.swap(0, 1);
        assert!(
            BtcAdapter::assemble_signed(&u, &sigs).is_err(),
            "misordered signatures are rejected"
        );
    }
}
