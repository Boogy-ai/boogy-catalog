//! Bitcoin P2WPKH adapter — address KAT + build_unsigned/assemble_signed
//! round-trip + adversarial coverage. External-signer mode throughout: no
//! private key, no local signing — sighashes go out, signatures come back in.

use wallet_base_core::btc::{BtcAdapter, BtcIntent, BtcNetwork, Utxo};
use wallet_base_core::types::{RawTx, Secp256k1Signature, SignRequest};

// ---------------------------------------------------------------------------
// Task 1 — P2WPKH address KAT + adversarial
// ---------------------------------------------------------------------------

/// Authoritative spike vector: this compressed pubkey derives this mainnet
/// P2WPKH address (`bc1q…`). Exact, pinned.
const PUBKEY_HEX: &str = "033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc";
const ADDR_MAINNET: &str = "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw";

fn pubkey_bytes() -> Vec<u8> {
    hex::decode(PUBKEY_HEX).unwrap()
}

#[test]
fn btc_address_kat_mainnet() {
    let addr = BtcAdapter::address_from_pubkey(&pubkey_bytes(), BtcNetwork::Mainnet).unwrap();
    assert_eq!(addr, ADDR_MAINNET, "P2WPKH mainnet address KAT");
}

#[test]
fn btc_address_testnet_uses_tb1q_hrp() {
    let addr = BtcAdapter::address_from_pubkey(&pubkey_bytes(), BtcNetwork::Testnet).unwrap();
    assert!(addr.starts_with("tb1q"), "testnet HRP, got {addr}");
    // Same witness program, different HRP → different string from mainnet.
    assert_ne!(addr, ADDR_MAINNET);
}

#[test]
fn btc_address_rejects_uncompressed_pubkey() {
    // 65-byte uncompressed (0x04 || X || Y) — P2WPKH is undefined for these.
    let uncompressed = [0x04u8; 65];
    assert!(BtcAdapter::address_from_pubkey(&uncompressed, BtcNetwork::Mainnet).is_err());
}

#[test]
fn btc_address_rejects_short_pubkey() {
    let thirty_two = [0x02u8; 32];
    assert!(BtcAdapter::address_from_pubkey(&thirty_two, BtcNetwork::Mainnet).is_err());
}

#[test]
fn btc_address_rejects_empty_pubkey() {
    assert!(BtcAdapter::address_from_pubkey(&[], BtcNetwork::Mainnet).is_err());
}

// ---------------------------------------------------------------------------
// Task 2 — build_unsigned + coin-select + assemble_signed + round-trip
// ---------------------------------------------------------------------------

fn utxo(txid_last_byte: u8, value: u64) -> Utxo {
    let mut t = String::from("00000000000000000000000000000000000000000000000000000000000000");
    t.push_str(&format!("{txid_last_byte:02x}"));
    Utxo { txid: t, vout: 0, value_sat: value }
}

/// Fixed single-input fixture (1 UTXO of 100_000 sat, send 50_000 @ 1 sat/vB).
/// build_unsigned must reproduce the pinned BIP143 sighash snapshot exactly.
fn fixture_intent() -> BtcIntent {
    BtcIntent {
        from_pubkey_hex: PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 50_000,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 100_000)],
    }
}

/// Pinned BIP143 sighash for `fixture_intent()`'s single input — a stability
/// snapshot (deterministic given the fixed tx + prevout value). Captured on the
/// first green run; locks the BIP143 preimage construction across `bitcoin` revs.
const SIGHASH_SNAPSHOT: &str =
    "8a581d7d027276b61d5e7c265e92228be5f42938ed3f03b97ff208ace46ccb68";

#[test]
fn btc_build_unsigned_matches_sighash_snapshot() {
    let u = BtcAdapter::build_unsigned(&fixture_intent()).unwrap();
    assert_eq!(u.sign_requests.len(), 1, "one input → one sighash");
    let hex_digest = match &u.sign_requests[0] {
        SignRequest::Digest(d) => hex::encode(d),
        other => panic!("expected Digest, got {other:?}"),
    };
    assert_eq!(
        hex_digest, SIGHASH_SNAPSHOT,
        "BIP143 sighash changed (or snapshot not yet captured)"
    );
}

/// A valid compact secp256k1 signature for structural round-trip tests.
/// `Signature::from_compact` validates r and s are in-range scalars; r=1, s=1
/// are valid, so this exercises the full assemble path without a real signer.
fn valid_dummy_sig() -> Secp256k1Signature {
    let mut r = [0u8; 32];
    r[31] = 1;
    let mut s = [0u8; 32];
    s[31] = 1;
    Secp256k1Signature { r, s, recovery_id: 0 }
}

#[test]
fn btc_single_input_roundtrips() {
    let u = BtcAdapter::build_unsigned(&fixture_intent()).unwrap();
    assert_eq!(u.sign_requests.len(), 1);
    let raw: RawTx = BtcAdapter::assemble_signed(&u, &[valid_dummy_sig()]).unwrap();

    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw.0).unwrap();
    assert_eq!(tx.input.len(), 1, "one input survives");
    // Witness is [der_sig||sighash_type, compressed_pubkey].
    let w = &tx.input[0].witness;
    assert_eq!(w.len(), 2, "P2WPKH witness = [sig, pubkey]");
    // Outputs: recipient + change (100_000 > 50_000 + small fee).
    assert_eq!(tx.output.len(), 2, "recipient + change");
}

#[test]
fn btc_multi_input_roundtrips() {
    // Two UTXOs of 40_000 each (80_000 total); send 50_000 → both inputs needed.
    let intent = BtcIntent {
        from_pubkey_hex: PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 50_000,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 40_000), utxo(0x02, 40_000)],
    };
    let u = BtcAdapter::build_unsigned(&intent).unwrap();
    assert_eq!(u.sign_requests.len(), 2, "two inputs → two sighashes");
    // The two sighashes differ (different prevout outpoint + value position).
    if let (SignRequest::Digest(a), SignRequest::Digest(b)) =
        (&u.sign_requests[0], &u.sign_requests[1])
    {
        assert_ne!(a, b, "per-input sighashes are distinct");
    } else {
        panic!("expected two Digest sign_requests");
    }

    let sigs = vec![valid_dummy_sig(), valid_dummy_sig()];
    let raw = BtcAdapter::assemble_signed(&u, &sigs).unwrap();

    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw.0).unwrap();
    assert_eq!(tx.input.len(), 2, "two inputs survive");
    for (i, txin) in tx.input.iter().enumerate() {
        assert_eq!(txin.witness.len(), 2, "input {i} witness = [sig, pubkey]");
    }
}

#[test]
fn btc_coinselect_picks_enough_and_computes_change() {
    // Send 10_000 from a 100_000 UTXO → 1 input, non-dust change → 2 outputs.
    let intent = BtcIntent {
        from_pubkey_hex: PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 10_000,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 100_000)],
    };
    let u = BtcAdapter::build_unsigned(&intent).unwrap();
    let raw = BtcAdapter::assemble_signed(&u, &[valid_dummy_sig()]).unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw.0).unwrap();
    assert_eq!(tx.output.len(), 2, "recipient + non-dust change");
    // Recipient output value is exactly the requested amount.
    assert_eq!(tx.output[0].value.to_sat(), 10_000);
    // Change output is non-dust.
    assert!(tx.output[1].value.to_sat() >= 294, "non-dust change");
}

#[test]
fn btc_dust_change_folded_into_fee_no_change_output() {
    // amount + fee leaves only dust as residue → no change output (1 output).
    // 1 input, 1 output vsize = 11 + 68 + 31 = 110; fee@1 = 110.
    // total = 10_000 + 110 + 293 (dust-1) = 10_403.
    let intent = BtcIntent {
        from_pubkey_hex: PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 10_000,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 10_403)],
    };
    let u = BtcAdapter::build_unsigned(&intent).unwrap();
    let raw = BtcAdapter::assemble_signed(&u, &[valid_dummy_sig()]).unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw.0).unwrap();
    assert_eq!(tx.output.len(), 1, "dust change folded into fee → no change output");
    assert_eq!(tx.output[0].value.to_sat(), 10_000, "recipient only");
}

// --- Adversarial ---

#[test]
fn btc_insufficient_funds_errs() {
    let intent = BtcIntent {
        from_pubkey_hex: PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 50_000,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 5_000)],
    };
    assert!(BtcAdapter::build_unsigned(&intent).is_err());
}

#[test]
fn btc_empty_utxos_errs() {
    let intent = BtcIntent {
        from_pubkey_hex: PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 50_000,
        fee_rate_sat_vb: 1,
        utxos: vec![],
    };
    assert!(BtcAdapter::build_unsigned(&intent).is_err());
}

#[test]
fn btc_wrong_sig_count_errs() {
    // 1 input → assembling with 0 or 2 sigs must fail closed.
    let u = BtcAdapter::build_unsigned(&fixture_intent()).unwrap();
    assert_eq!(u.sign_requests.len(), 1);
    assert!(BtcAdapter::assemble_signed(&u, &[]).is_err(), "N-1 sigs");
    assert!(
        BtcAdapter::assemble_signed(&u, &[valid_dummy_sig(), valid_dummy_sig()]).is_err(),
        "N+1 sigs"
    );
}

#[test]
fn btc_wrong_network_to_address_errs() {
    // Mainnet intent, but a testnet (tb1q…) destination → reject.
    let testnet_addr =
        BtcAdapter::address_from_pubkey(&pubkey_bytes(), BtcNetwork::Testnet).unwrap();
    let intent = BtcIntent {
        from_pubkey_hex: PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: testnet_addr,
        amount_sat: 50_000,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 100_000)],
    };
    assert!(BtcAdapter::build_unsigned(&intent).is_err(), "wrong-network to_address");
}

#[test]
fn btc_garbage_to_address_errs() {
    let mut intent = fixture_intent();
    intent.to_address = "not-an-address".into();
    assert!(BtcAdapter::build_unsigned(&intent).is_err());
}

#[test]
fn btc_zero_amount_handling() {
    // Zero-amount send: a 0-sat recipient output is below dust and economically
    // meaningless, but coin selection still resolves (fee-only). We define the
    // behavior as: it builds (no panic) — the recipient output carries 0 sat.
    // Higher layers (guardrails) reject zero-value sends; the adapter is
    // mechanical. Assert it does not panic and produces a well-formed tx.
    let intent = BtcIntent {
        from_pubkey_hex: PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 0,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 100_000)],
    };
    let u = BtcAdapter::build_unsigned(&intent).expect("zero-amount builds mechanically");
    assert_eq!(u.sign_requests.len(), 1);
    let raw = BtcAdapter::assemble_signed(&u, &[valid_dummy_sig()]).unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw.0).unwrap();
    assert_eq!(tx.output[0].value.to_sat(), 0, "zero-sat recipient output");
}
