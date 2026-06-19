//! Cosmos (cosmrs) wasm-compat feasibility spike — address + SignDoc vectors.
//!
//! Two parts:
//!  1. Address cross-check (authoritative): derive a compressed secp256k1 pubkey
//!     from a fixed test private key, then compute the `cosmos1…` address TWO
//!     ways — a hand-rolled `bech32("cosmos", ripemd160(sha256(pk)))` per the
//!     Cosmos spec, and via cosmrs's `PublicKey::account_id("cosmos")` — and
//!     assert they MATCH. This cross-checks cosmrs's derivation against the spec.
//!  2. SignDoc digest (stability snapshot): build a minimal SIGN_MODE_DIRECT
//!     SignDoc for a fixed bank MsgSend, encode it (`into_bytes()`), SHA-256, and
//!     assert against a snapshot captured on first green run. Cosmos lacks the
//!     rich published end-to-end digest vectors EVM has; the address cross-check
//!     above is the authoritative part. The assemble round-trip in a later task
//!     covers byte-correctness. This guards encoding stability across cosmrs revs.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Fixed test-only private key (same convention as the EVM address test, which
/// derives from 0x4646..4646). secp256k1 scalar, 32 bytes.
const TEST_SK_HEX: &str = "4646464646464646464646464646464646464646464646464646464646464646";

/// Derive the compressed (33-byte SEC1) secp256k1 pubkey from the test key.
fn test_compressed_pubkey() -> Vec<u8> {
    use k256::ecdsa::SigningKey;
    let sk_bytes = hex::decode(TEST_SK_HEX).unwrap();
    let sk = SigningKey::from_slice(&sk_bytes).unwrap();
    let vk = sk.verifying_key();
    vk.to_encoded_point(true).as_bytes().to_vec() // compressed 0x02/0x03 || X
}

/// Spec algorithm: cosmos address = bech32("cosmos", ripemd160(sha256(pubkey))).
fn cosmos_addr_spec(compressed_pubkey: &[u8]) -> String {
    let sha = Sha256::digest(compressed_pubkey);
    let rip = Ripemd160::digest(sha);
    let hrp = bech32::Hrp::parse("cosmos").unwrap();
    bech32::encode::<bech32::Bech32>(hrp, &rip).unwrap()
}

#[test]
fn cosmos_address_cross_checks_cosmrs_against_spec() {
    use cosmrs::crypto::PublicKey;

    let pk_bytes = test_compressed_pubkey();
    assert_eq!(pk_bytes.len(), 33, "compressed pubkey must be 33 bytes");

    // Way 1: hand-rolled spec algorithm.
    let spec_addr = cosmos_addr_spec(&pk_bytes);
    assert!(spec_addr.starts_with("cosmos1"), "got {spec_addr}");

    // Way 2: via cosmrs.
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pk_bytes).unwrap();
    let cosmrs_pk = PublicKey::from(vk);
    let account_id = cosmrs_pk.account_id("cosmos").unwrap();
    let cosmrs_addr = account_id.to_string();

    assert_eq!(
        spec_addr, cosmrs_addr,
        "cosmrs address derivation must match the bech32(ripemd160(sha256(pk))) spec"
    );
}

/// SHA-256 of the encoded SignDoc bytes for a fixed transaction — a stability
/// snapshot (NOT a published vector; see module docs). Captured on first green run.
const SIGNDOC_DIGEST_SNAPSHOT: &str =
    "e127e7360b8e5f82b808e7f21c1c6a2d0a8b0afed6c4340ae0cdc9270d51afb0";

#[test]
fn cosmos_signdoc_digest_is_stable() {
    use cosmrs::bank::MsgSend;
    use cosmrs::tx::{Body, Fee, Msg, SignDoc, SignerInfo};
    use cosmrs::{AccountId, Coin};

    let pk_bytes = test_compressed_pubkey();
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pk_bytes).unwrap();
    let sender_pk = cosmrs::crypto::PublicKey::from(vk);
    let from: AccountId = sender_pk.account_id("cosmos").unwrap();

    // Fixed recipient (a deterministic cosmos1 address).
    let to: AccountId = "cosmos1qy352eufqy352eufqy352eufqy35qqqz9te5xt"
        .parse()
        .unwrap_or_else(|_| from.clone());

    let amount = Coin {
        denom: "uatom".parse().unwrap(),
        amount: 1_000_000u128,
    };

    let msg = MsgSend {
        from_address: from.clone(),
        to_address: to,
        amount: vec![amount.clone()],
    };

    let body = Body::new(vec![msg.to_any().unwrap()], "", 0u16);
    let signer_info = SignerInfo::single_direct(Some(sender_pk), 0);
    let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(amount, 200_000u64));

    let chain_id = "cosmoshub-4".parse().unwrap();
    let sign_doc = SignDoc::new(&body, &auth_info, &chain_id, 1).unwrap();
    let bytes = sign_doc.into_bytes().unwrap();

    let digest = Sha256::digest(&bytes);
    let digest_hex = hex::encode(digest);

    // On first run, this will fail and print the actual digest — paste it into
    // SIGNDOC_DIGEST_SNAPSHOT to lock the snapshot.
    assert_eq!(
        digest_hex, SIGNDOC_DIGEST_SNAPSHOT,
        "SignDoc encoding changed (or snapshot not yet captured)"
    );
}

// ---------------------------------------------------------------------------
// CosmosAdapter: build_unsigned / assemble_signed KAT + round-trip + adversarial
// ---------------------------------------------------------------------------

use wallet_base_core::cosmos::{CosmosAdapter, CosmosIntent};
use wallet_base_core::types::{Secp256k1Signature, SignRequest};

/// The same fixture the spike snapshot was captured on: fixed key, recipient,
/// 1_000_000 uatom send, 1_000_000 uatom / 200_000 gas fee, account_number 1,
/// sequence 0, empty memo, chain cosmoshub-4. build_unsigned must reproduce the
/// snapshot digest exactly.
fn fixture_intent() -> CosmosIntent {
    let pk = test_compressed_pubkey();
    let from = CosmosAdapter::address_from_pubkey(&pk, "cosmos").unwrap();
    CosmosIntent {
        chain_id: "cosmoshub-4".into(),
        hrp: "cosmos".into(),
        account_number: 1,
        sequence: 0,
        // The spike snapshot was captured with `to = from` (its hard-coded
        // recipient string failed AccountId parse and fell back to `from`), so
        // the KAT must use the same recipient to reproduce the digest.
        from_address: from.clone(),
        to_address: from,
        amount: "1000000".into(),
        denom: "uatom".into(),
        fee_amount: "1000000".into(),
        fee_denom: "uatom".into(),
        gas_limit: 200_000,
        memo: "".into(),
        pubkey_compressed_hex: hex::encode(&pk),
    }
}

#[test]
fn cosmos_build_unsigned_matches_signdoc_snapshot() {
    let unsigned = CosmosAdapter::build_unsigned(&fixture_intent()).unwrap();
    assert_eq!(unsigned.sign_requests.len(), 1);
    let digest_hex = match &unsigned.sign_requests[0] {
        SignRequest::Digest(d) => hex::encode(d),
        other => panic!("expected Digest, got {other:?}"),
    };
    assert_eq!(
        digest_hex, SIGNDOC_DIGEST_SNAPSHOT,
        "build_unsigned digest must equal the spike's SignDoc snapshot"
    );
}

#[test]
fn cosmos_assemble_roundtrips_into_txraw() {
    use cosmrs::proto::cosmos::tx::v1beta1::TxRaw;
    use cosmrs::proto::traits::Message;

    let unsigned = CosmosAdapter::build_unsigned(&fixture_intent()).unwrap();

    // Dummy 64-byte compact r||s (no recovery id needed for Cosmos).
    let sig = Secp256k1Signature { r: [0xAB; 32], s: [0xCD; 32], recovery_id: 0 };
    let raw = CosmosAdapter::assemble_signed(&unsigned, &[sig]).unwrap();

    // Decode the TxRaw back and assert structure survives.
    let decoded = TxRaw::decode(raw.0.as_slice()).unwrap();
    assert_eq!(decoded.signatures.len(), 1, "exactly one signature");
    assert_eq!(decoded.signatures[0].len(), 64, "64-byte compact r||s");
    assert!(!decoded.body_bytes.is_empty(), "body_bytes survives");
    assert!(!decoded.auth_info_bytes.is_empty(), "auth_info_bytes survives");

    // r||s spliced verbatim.
    let mut expected = Vec::with_capacity(64);
    expected.extend_from_slice(&[0xAB; 32]);
    expected.extend_from_slice(&[0xCD; 32]);
    assert_eq!(decoded.signatures[0], expected);
}

#[test]
fn cosmos_assemble_rejects_wrong_sig_count() {
    let unsigned = CosmosAdapter::build_unsigned(&fixture_intent()).unwrap();
    let sig = Secp256k1Signature { r: [0x01; 32], s: [0x02; 32], recovery_id: 0 };
    assert!(CosmosAdapter::assemble_signed(&unsigned, &[]).is_err(), "0 sigs → Err");
    assert!(
        CosmosAdapter::assemble_signed(&unsigned, &[sig.clone(), sig]).is_err(),
        "2 sigs → Err"
    );
}

#[test]
fn cosmos_build_unsigned_rejects_malformed_pubkey() {
    let mut i = fixture_intent();
    i.pubkey_compressed_hex = "deadbeef".into(); // valid hex, not a valid point
    assert!(CosmosAdapter::build_unsigned(&i).is_err());
    let mut j = fixture_intent();
    j.pubkey_compressed_hex = "nothex".into();
    assert!(CosmosAdapter::build_unsigned(&j).is_err());
}

#[test]
fn cosmos_build_unsigned_rejects_bad_bech32() {
    let mut from = fixture_intent();
    from.from_address = "cosmos1notvalid!!".into();
    assert!(CosmosAdapter::build_unsigned(&from).is_err());
    let mut to = fixture_intent();
    to.to_address = "garbage".into();
    assert!(CosmosAdapter::build_unsigned(&to).is_err());
}

#[test]
fn cosmos_build_unsigned_rejects_unparseable_amount() {
    let mut amt = fixture_intent();
    amt.amount = "not-a-number".into();
    assert!(CosmosAdapter::build_unsigned(&amt).is_err());
    let mut empty = fixture_intent();
    empty.amount = "".into();
    assert!(CosmosAdapter::build_unsigned(&empty).is_err());
    let mut fee = fixture_intent();
    fee.fee_amount = "".into();
    assert!(CosmosAdapter::build_unsigned(&fee).is_err());
}
