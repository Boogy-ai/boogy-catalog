//! Adversarial / negative coverage for the EVM chain adapter.
//!
//! Crypto wallets are frequent attack targets. Every hostile input below MUST
//! yield an `Err(AdapterError::…)` — never a panic, unwrap-failure, or silent
//! wrong result. A panic in a signing/encoding path is a DoS/safety bug.

use wallet_base_core::evm::{rpc, EvmAdapter};
use wallet_base_core::types::*;

/// A baseline valid 1559 intent we mutate per-case.
fn base_intent() -> EvmIntent {
    EvmIntent {
        to: Some("0x3535353535353535353535353535353535353535".into()),
        from_address: String::new(),
        value_wei: "1000".into(),
        data_hex: "".into(),
        chain_id: 1,
        nonce: Some(1),
        max_fee_per_gas: Some("30000000000".into()),
        max_priority_fee_per_gas: Some("1000000000".into()),
        gas_limit: Some(21000),
        legacy: false,
        gas_price: None,
    }
}

fn build(intent: &EvmIntent, state: &ChainState) -> Result<Unsigned, AdapterError> {
    ChainAdapter::build_unsigned(&EvmAdapter, intent, state)
}

// ===========================================================================
// A. build_unsigned rejects malformed intents (BadIntent/Encoding, no panic)
// ===========================================================================

#[test]
fn a_missing_nonce_is_err() {
    let mut intent = base_intent();
    intent.nonce = None;
    let state = ChainState { nonce: None, ..Default::default() };
    let err = build(&intent, &state).unwrap_err();
    assert!(matches!(err, AdapterError::BadIntent(_)), "got {err:?}");
}

#[test]
fn a_missing_gas_limit_is_err() {
    let mut intent = base_intent();
    intent.gas_limit = None;
    let state = ChainState { nonce: Some(1), gas_limit: None, ..Default::default() };
    let err = build(&intent, &state).unwrap_err();
    assert!(matches!(err, AdapterError::BadIntent(_)), "got {err:?}");
}

#[test]
fn a_value_wei_non_decimal_is_err() {
    let mut intent = base_intent();
    intent.value_wei = "abc".into();
    assert!(matches!(
        build(&intent, &ChainState::default()).unwrap_err(),
        AdapterError::BadIntent(_)
    ));
}

#[test]
fn a_value_wei_empty_is_err() {
    let mut intent = base_intent();
    intent.value_wei = "".into();
    assert!(build(&intent, &ChainState::default()).is_err());
}

#[test]
fn a_value_wei_overflows_u256_is_err() {
    let mut intent = base_intent();
    // 80 nines: well past 2^256 - 1 (which has 78 decimal digits).
    intent.value_wei = "9".repeat(80);
    let err = build(&intent, &ChainState::default()).unwrap_err();
    assert!(matches!(err, AdapterError::BadIntent(_)), "got {err:?}");
}

#[test]
fn a_to_not_hex_is_err() {
    let mut intent = base_intent();
    intent.to = Some("0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".into());
    assert!(matches!(
        build(&intent, &ChainState::default()).unwrap_err(),
        AdapterError::BadIntent(_)
    ));
}

#[test]
fn a_to_wrong_length_is_err() {
    let mut intent = base_intent();
    intent.to = Some("0x1234".into());
    assert!(matches!(
        build(&intent, &ChainState::default()).unwrap_err(),
        AdapterError::BadIntent(_)
    ));
}

#[test]
fn a_to_garbage_non_hex_no_prefix_is_err() {
    // alloy's Address parser ACCEPTS a bare 40-hex string (no 0x required), so
    // that is not a defect. What must still be rejected is garbage that is not a
    // valid 20-byte address regardless of prefix.
    let mut intent = base_intent();
    intent.to = Some("ZZ35353535353535353535353535353535353535".into()); // non-hex, no prefix
    assert!(matches!(
        build(&intent, &ChainState::default()).unwrap_err(),
        AdapterError::BadIntent(_)
    ));
}

#[test]
fn a_data_hex_odd_length_is_err() {
    let mut intent = base_intent();
    intent.data_hex = "0xabc".into();
    assert!(matches!(
        build(&intent, &ChainState::default()).unwrap_err(),
        AdapterError::BadIntent(_)
    ));
}

#[test]
fn a_data_hex_non_hex_is_err() {
    let mut intent = base_intent();
    intent.data_hex = "0xzz".into();
    assert!(matches!(
        build(&intent, &ChainState::default()).unwrap_err(),
        AdapterError::BadIntent(_)
    ));
}

#[test]
fn a_legacy_without_gas_price_is_err() {
    let mut intent = base_intent();
    intent.legacy = true;
    intent.gas_price = None;
    let state = ChainState { nonce: Some(1), gas_limit: Some(21000), gas_price: None, ..Default::default() };
    let err = build(&intent, &state).unwrap_err();
    assert!(matches!(err, AdapterError::BadIntent(_)), "got {err:?}");
}

#[test]
fn a_max_fee_non_decimal_is_err() {
    let mut intent = base_intent();
    intent.max_fee_per_gas = Some("xyz".into());
    assert!(matches!(
        build(&intent, &ChainState::default()).unwrap_err(),
        AdapterError::BadIntent(_)
    ));
}

// ===========================================================================
// B. assemble_signed rejects bad signature sets
// ===========================================================================

fn valid_unsigned() -> Unsigned {
    build(&base_intent(), &ChainState::default()).unwrap()
}

#[test]
fn b_empty_sigs_is_err() {
    let unsigned = valid_unsigned();
    let err = ChainAdapter::assemble_signed(&EvmAdapter, &unsigned, &[]).unwrap_err();
    assert!(matches!(err, AdapterError::BadIntent(_)), "got {err:?}");
}

#[test]
fn b_two_sigs_is_err() {
    let unsigned = valid_unsigned();
    let sig = Secp256k1Signature { r: [0x11; 32], s: [0x22; 32], recovery_id: 0 };
    let err =
        ChainAdapter::assemble_signed(&EvmAdapter, &unsigned, &[sig.clone(), sig]).unwrap_err();
    assert!(matches!(err, AdapterError::BadIntent(_)), "got {err:?}");
}

#[test]
fn b_corrupt_preimage_is_err_not_panic() {
    // A hostile/garbage preimage must deserialize-fail cleanly, not panic.
    let unsigned = Unsigned { preimage: vec![0xff, 0x00, 0x13, 0x37], sign_requests: vec![] };
    let sig = Secp256k1Signature { r: [0x11; 32], s: [0x22; 32], recovery_id: 0 };
    let err = ChainAdapter::assemble_signed(&EvmAdapter, &unsigned, &[sig]).unwrap_err();
    assert!(matches!(err, AdapterError::Encoding(_)), "got {err:?}");
}

// ===========================================================================
// C. derive_address rejects garbage pubkeys (Encoding, no panic)
// ===========================================================================

fn derive(pk: &[u8]) -> Result<String, AdapterError> {
    ChainAdapter::derive_address(&EvmAdapter, pk)
}

#[test]
fn c_empty_pubkey_is_err() {
    assert!(matches!(derive(&[]).unwrap_err(), AdapterError::Encoding(_)));
}

#[test]
fn c_too_short_pubkey_is_err() {
    assert!(matches!(derive(&[0x04, 0x01]).unwrap_err(), AdapterError::Encoding(_)));
}

#[test]
fn c_wrong_length_0x04_prefixed_is_err() {
    // 0x04 tag but only 33 bytes (looks like a truncated uncompressed key).
    let mut pk = vec![0x04u8];
    pk.extend(std::iter::repeat(0x01).take(32));
    assert!(matches!(derive(&pk).unwrap_err(), AdapterError::Encoding(_)));
}

#[test]
fn c_65_byte_not_on_curve_is_err() {
    // 65 bytes, 0x04 prefix, all-ones X/Y — not a valid curve point.
    let mut pk = vec![0x04u8];
    pk.extend(std::iter::repeat(0x01).take(64));
    assert_eq!(pk.len(), 65);
    assert!(matches!(derive(&pk).unwrap_err(), AdapterError::Encoding(_)));
}

// ===========================================================================
// D. RPC parsers tolerate hostile / garbage JSON (Err, no panic)
// ===========================================================================

use serde_json::json;

#[test]
fn d_parse_nonce_hostile() {
    assert!(rpc::parse_nonce(&json!({})).is_err());
    assert!(rpc::parse_nonce(&json!({"result": "0xZZ"})).is_err());
    assert!(rpc::parse_nonce(&json!({"result": 123})).is_err());
    assert!(rpc::parse_nonce(&json!({"error": {"message": "x"}})).is_err());
}

#[test]
fn d_parse_max_priority_fee_hostile() {
    assert!(rpc::parse_max_priority_fee(&json!({})).is_err());
    assert!(rpc::parse_max_priority_fee(&json!({"result": "0xZZ"})).is_err());
    assert!(rpc::parse_max_priority_fee(&json!({"result": 123})).is_err());
    assert!(rpc::parse_max_priority_fee(&json!({"error": {"message": "x"}})).is_err());
}

#[test]
fn d_parse_base_fee_hostile() {
    assert!(rpc::parse_base_fee(&json!({})).is_err());
    // result present but baseFeePerGas bad hex
    assert!(rpc::parse_base_fee(&json!({"result": {"baseFeePerGas": "0xZZ"}})).is_err());
    // result present but baseFeePerGas wrong type
    assert!(rpc::parse_base_fee(&json!({"result": {"baseFeePerGas": 123}})).is_err());
    assert!(rpc::parse_base_fee(&json!({"error": {"message": "x"}})).is_err());
}

#[test]
fn d_parse_send_result_hostile() {
    assert!(rpc::parse_send_result(&json!({})).is_err());
    assert!(rpc::parse_send_result(&json!({"error": {"message": "nonce too low"}})).is_err());
    assert!(rpc::parse_send_result(&json!({"result": 123})).is_err());
}

#[test]
fn d_parse_simulation_graceful_on_garbage() {
    // No result, no error → Err (never panic).
    assert!(rpc::parse_simulation(&json!({})).is_err());
    // Error object → graceful success:false.
    let sim = rpc::parse_simulation(&json!({"error": {"message": "reverted"}})).unwrap();
    assert!(!sim.success);
    // Garbage non-string result with no error → Err.
    assert!(rpc::parse_simulation(&json!({"result": 42})).is_err());
}

#[test]
fn d_parse_estimate_gas_graceful_on_garbage() {
    // No result, no error → Err (never panic).
    assert!(rpc::parse_estimate_gas(&json!({})).is_err());
    // Error object → graceful success:false.
    let sim = rpc::parse_estimate_gas(&json!({"error": {"message": "out of gas"}})).unwrap();
    assert!(!sim.success);
    // Bad-hex result → Err.
    assert!(rpc::parse_estimate_gas(&json!({"result": "0xZZ"})).is_err());
}

#[test]
fn d_parse_receipt_null_is_none() {
    assert_eq!(rpc::parse_receipt(&json!({"result": null})).unwrap(), None);
    // Entirely missing result is also treated as not-yet-mined null.
    assert_eq!(rpc::parse_receipt(&json!({})).unwrap(), None);
}

#[test]
fn d_parse_receipt_malformed_is_err_not_panic() {
    // Receipt object missing `status` → Err, no panic.
    assert!(rpc::parse_receipt(&json!({"result": {"blockNumber": "0x1"}})).is_err());
    // Missing blockNumber → Err.
    assert!(rpc::parse_receipt(&json!({"result": {"status": "0x1"}})).is_err());
    // status present but bad-hex blockNumber → Err.
    assert!(rpc::parse_receipt(&json!({"result": {"status": "0x1", "blockNumber": "0xZZ"}})).is_err());
    // error object → Err.
    assert!(rpc::parse_receipt(&json!({"error": {"message": "x"}})).is_err());
}

// ===========================================================================
// E. Decode robustness — attacker bytes must Err, not panic.
// ===========================================================================

#[test]
fn e_decode_2718_garbage_is_err_not_panic() {
    use alloy_consensus::TxEnvelope;
    use alloy_eips::eip2718::Decodable2718;

    for garbage in [
        &[0xffu8, 0x00, 0x13, 0x37][..],
        &[0x02, 0x00][..],            // typed marker then truncated
        &[][..],                      // empty
        &[0xc0][..],                  // empty RLP list
        &[0x80][..],                  // empty RLP string
    ] {
        let mut slice = garbage;
        let res = TxEnvelope::decode_2718(&mut slice);
        assert!(res.is_err(), "expected Err for garbage {garbage:?}");
    }
}
