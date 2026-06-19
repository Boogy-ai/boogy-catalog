// Source of truth: EIP-155 specification, "Example" section.
const EIP155_SIGNING_HASH: &str =
    "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";

#[test]
fn address_derivation_matches_eip155_key() {
    // The pubkey is derived (test-only) from the canonical EIP-155 example
    // private key 0x4646..4646 via k256; the resulting address is well-known.
    use k256::ecdsa::SigningKey;
    let sk_bytes = hex::decode(
        "4646464646464646464646464646464646464646464646464646464646464646").unwrap();
    let sk = SigningKey::from_slice(&sk_bytes).unwrap();
    let vk = sk.verifying_key();
    let pubkey = vk.to_encoded_point(false); // uncompressed 0x04||X||Y, 65 bytes
    let adapter = wallet_base_core::evm::EvmAdapter;
    let addr = <wallet_base_core::evm::EvmAdapter as wallet_base_core::types::ChainAdapter>
        ::derive_address(&adapter, pubkey.as_bytes()).unwrap();
    // Address bytes are fixed; compare case-insensitively (checksum casing tested separately).
    assert_eq!(addr.to_lowercase(), "0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f");
}

#[test]
fn eip55_checksum_matches_spec_example() {
    // Canonical EIP-55 spec example address. The derive function must produce
    // exactly this mixed-case checksum from the lowercase 20 bytes.
    let bytes = hex::decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
    let out = wallet_base_core::evm::address::checksum_for_test(&bytes);
    assert_eq!(out, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
}

/// Build the canonical EIP-155 example as a legacy `EvmIntent`.
fn eip155_legacy_intent() -> wallet_base_core::types::EvmIntent {
    use wallet_base_core::types::EvmIntent;
    EvmIntent {
        to: Some("0x3535353535353535353535353535353535353535".into()),
        from_address: String::new(),
        value_wei: "1000000000000000000".into(),
        data_hex: "".into(),
        chain_id: 1,
        nonce: Some(9),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        gas_limit: Some(21000),
        legacy: true,
        gas_price: Some("20000000000".into()),
    }
}

#[test]
fn eip155_signing_hash_matches_spec() {
    use wallet_base_core::evm::EvmAdapter;
    use wallet_base_core::types::*;

    let intent = eip155_legacy_intent();
    let adapter = EvmAdapter;
    let unsigned =
        ChainAdapter::build_unsigned(&adapter, &intent, &ChainState::default()).unwrap();

    assert_eq!(unsigned.sign_requests.len(), 1);
    match &unsigned.sign_requests[0] {
        SignRequest::Digest(d) => assert_eq!(hex::encode(d), EIP155_SIGNING_HASH),
        other => panic!("expected Digest, got {other:?}"),
    }
}

#[test]
fn eip155_signed_raw_tx_matches_spec() {
    use wallet_base_core::evm::EvmAdapter;
    use wallet_base_core::types::*;

    let intent = eip155_legacy_intent();
    let adapter = EvmAdapter;
    let unsigned =
        ChainAdapter::build_unsigned(&adapter, &intent, &ChainState::default()).unwrap();

    // Canonical EIP-155 example signature (recovery_id 0 -> v=37 for chain_id 1).
    let r: [u8; 32] = hex::decode(
        "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276",
    )
    .unwrap()
    .try_into()
    .unwrap();
    let s: [u8; 32] = hex::decode(
        "67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
    )
    .unwrap()
    .try_into()
    .unwrap();
    let sig = Secp256k1Signature { r, s, recovery_id: 0 };

    let raw = ChainAdapter::assemble_signed(&adapter, &unsigned, &[sig]).unwrap();
    assert_eq!(
        raw.to_hex(),
        "0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
    );
}

#[test]
fn eip1559_build_unsigned_is_typed() {
    use wallet_base_core::evm::EvmAdapter;
    use wallet_base_core::types::*;

    let intent = EvmIntent {
        to: Some("0x3535353535353535353535353535353535353535".into()),
        from_address: String::new(),
        value_wei: "1000".into(),
        data_hex: "".into(),
        chain_id: 1,
        nonce: Some(5),
        max_fee_per_gas: Some("30000000000".into()),
        max_priority_fee_per_gas: Some("1000000000".into()),
        gas_limit: Some(21000),
        legacy: false,
        gas_price: None,
    };
    let adapter = EvmAdapter;
    let unsigned =
        ChainAdapter::build_unsigned(&adapter, &intent, &ChainState::default()).unwrap();
    assert_eq!(unsigned.sign_requests.len(), 1);
    assert!(matches!(unsigned.sign_requests[0], SignRequest::Digest(_)));

    let sig = Secp256k1Signature { r: [1; 32], s: [1; 32], recovery_id: 0 };
    let raw = ChainAdapter::assemble_signed(&adapter, &unsigned, &[sig]).unwrap();
    assert_eq!(raw.0[0], 0x02, "EIP-1559 typed-envelope marker");
}

#[test]
fn eip1559_rejects_out_of_range_recovery_id() {
    // #14: recovery_id ∉ {0,1} must be rejected, not silently collapsed to
    // y_parity=false (which would recover a DIFFERENT address → a tx that can't
    // land). The host signer effectively never emits 2/3, but fail closed anyway.
    use wallet_base_core::evm::EvmAdapter;
    use wallet_base_core::types::*;

    let intent = EvmIntent {
        to: Some("0x3535353535353535353535353535353535353535".into()),
        from_address: String::new(),
        value_wei: "1000".into(),
        data_hex: "".into(),
        chain_id: 1,
        nonce: Some(5),
        max_fee_per_gas: Some("30000000000".into()),
        max_priority_fee_per_gas: Some("1000000000".into()),
        gas_limit: Some(21000),
        legacy: false,
        gas_price: None,
    };
    let adapter = EvmAdapter;
    let unsigned =
        ChainAdapter::build_unsigned(&adapter, &intent, &ChainState::default()).unwrap();
    let sig = Secp256k1Signature { r: [1; 32], s: [1; 32], recovery_id: 2 };
    assert!(
        ChainAdapter::assemble_signed(&adapter, &unsigned, &[sig]).is_err(),
        "recovery_id outside {{0,1}} is rejected"
    );
}

#[test]
fn eip1559_roundtrip_decodes_to_same_fields() {
    use wallet_base_core::types::*;
    use wallet_base_core::evm::EvmAdapter;
    use alloy_consensus::TxEnvelope;
    use alloy_eips::eip2718::Decodable2718;

    let intent = EvmIntent {
        to: Some("0x3535353535353535353535353535353535353535".into()),
        from_address: String::new(),
        value_wei: "1000000000000000000".into(),
        data_hex: "0xabcdef".into(),
        chain_id: 1,
        nonce: Some(7),
        max_fee_per_gas: Some("30000000000".into()),
        max_priority_fee_per_gas: Some("1000000000".into()),
        gas_limit: Some(50000),
        legacy: false,
        gas_price: None,
    };
    let adapter = EvmAdapter;
    let unsigned = ChainAdapter::build_unsigned(&adapter, &intent, &ChainState::default()).unwrap();
    let sig = Secp256k1Signature { r: [0x11; 32], s: [0x22; 32], recovery_id: 0 };
    let raw = ChainAdapter::assemble_signed(&adapter, &unsigned, &[sig]).unwrap();

    // Decode the EIP-2718 typed envelope back and assert the fields survived.
    let bytes = raw.0.clone();
    let env = TxEnvelope::decode_2718(&mut bytes.as_slice()).unwrap();
    match env {
        TxEnvelope::Eip1559(signed) => {
            let tx = signed.tx();
            assert_eq!(tx.chain_id, 1);
            assert_eq!(tx.nonce, 7);
            assert_eq!(tx.max_fee_per_gas, 30_000_000_000u128);
            assert_eq!(tx.max_priority_fee_per_gas, 1_000_000_000u128);
            assert_eq!(tx.gas_limit, 50_000u64);
            assert_eq!(tx.value, alloy_primitives::U256::from(1_000_000_000_000_000_000u128));
            assert_eq!(tx.input.as_ref(), &[0xab, 0xcd, 0xef]);
        }
        other => panic!("expected Eip1559 envelope, got {other:?}"),
    }
}

/// Canonical EIP-155 example r||s (recovery_id 0) for the 0x4646… key signing
/// `eip155_legacy_intent()` — reused by the #15 self-verify tests below.
fn eip155_example_sig() -> wallet_base_core::types::Secp256k1Signature {
    use wallet_base_core::types::Secp256k1Signature;
    let r: [u8; 32] =
        hex::decode("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276")
            .unwrap()
            .try_into()
            .unwrap();
    let s: [u8; 32] =
        hex::decode("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83")
            .unwrap()
            .try_into()
            .unwrap();
    Secp256k1Signature { r, s, recovery_id: 0 }
}

#[test]
fn eip155_self_verify_accepts_correct_signer() {
    use k256::ecdsa::SigningKey;
    use wallet_base_core::evm::EvmAdapter;
    use wallet_base_core::types::*;

    // The 0x4646… key's address — the account the canonical signature recovers to.
    let sk = SigningKey::from_slice(
        &hex::decode("4646464646464646464646464646464646464646464646464646464646464646").unwrap(),
    )
    .unwrap();
    let from = EvmAdapter
        .derive_address(sk.verifying_key().to_encoded_point(false).as_bytes())
        .unwrap();

    let mut intent = eip155_legacy_intent();
    intent.from_address = from;
    let unsigned =
        ChainAdapter::build_unsigned(&EvmAdapter, &intent, &ChainState::default()).unwrap();
    assert!(
        ChainAdapter::assemble_signed(&EvmAdapter, &unsigned, &[eip155_example_sig()]).is_ok(),
        "#15: a signature that recovers to the wallet address assembles"
    );
}

#[test]
fn eip155_self_verify_rejects_wrong_signer() {
    use wallet_base_core::evm::EvmAdapter;
    use wallet_base_core::types::*;

    // Same valid signature, but the host-set wallet address is a DIFFERENT
    // account → the recovered signer mismatches → rejected before broadcast.
    let mut intent = eip155_legacy_intent();
    intent.from_address = "0x000000000000000000000000000000000000dEaD".into();
    let unsigned =
        ChainAdapter::build_unsigned(&EvmAdapter, &intent, &ChainState::default()).unwrap();
    assert!(
        ChainAdapter::assemble_signed(&EvmAdapter, &unsigned, &[eip155_example_sig()]).is_err(),
        "#15: a signature recovering to a different account is rejected"
    );
}
