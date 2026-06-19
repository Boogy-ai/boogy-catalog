//! Cross-chain digest-isolation: the EVM and Cosmos signing digests are
//! domain-separated, so a digest minted as one chain's signing input can never
//! be a valid signing input for the other. This is the core anti-cross-chain-
//! replay property the custodial signer relies on (one key per `(principal,
//! chain)`, one digest format per chain).
//!
//! The substantive assertion is the digest INEQUALITY for an analogous transfer
//! (EVM keccak-256 signature hash vs Cosmos SHA-256 over the SignDoc). The
//! `assemble_signed` checks are lightweight confirmation that the two chains'
//! `Unsigned`s carry distinct, non-interchangeable encodings (EVM RLP envelope
//! vs Cosmos protobuf `TxRaw`) — the type system already separates them.
//!
//! Solana is isolated by a stronger structural property: it signs a
//! `SignRequest::Message` (the whole variable-length serialized message, signed
//! with Ed25519), NOT a `SignRequest::Digest` (the fixed 32-byte secp256k1
//! digest that EVM and Cosmos sign). A secp256k1 digest is therefore never a
//! structurally-valid Solana sign input, and a Solana message is never a valid
//! secp256k1 digest — they are different variants of different lengths.
//!
//! Bitcoin is isolated by yet another structural property: a multi-input send
//! emits **N `SignRequest::Digest`s** — one BIP143 sighash per UTXO — vs the
//! single-digest account chains (EVM/Cosmos) and the single-message Solana
//! chain. Even though BTC shares the secp256k1 curve with EVM/Cosmos, each
//! BIP143 sighash is its own preimage domain: for an analogous transfer the BTC
//! per-input sighash differs from both the EVM keccak sig-hash and the Cosmos
//! SHA-256 SignDoc digest, so a digest minted for one chain can never be a valid
//! signing input for another.

use sha2::{Digest, Sha256};

use wallet_base_core::btc::{BtcAdapter, BtcIntent, BtcNetwork, Utxo};
use wallet_base_core::cosmos::{CosmosAdapter, CosmosIntent};
use wallet_base_core::evm::EvmAdapter;
use wallet_base_core::solana::{SolanaAdapter, SolanaIntent};
use wallet_base_core::types::{
    ChainAdapter, ChainState, EvmIntent, Secp256k1Signature, SignRequest,
};

/// Same fixed test-only key the address/SignDoc vectors use (0x4646…4646).
const TEST_SK_HEX: &str = "4646464646464646464646464646464646464646464646464646464646464646";

/// Compressed (33-byte SEC1) secp256k1 pubkey from the test key.
fn test_compressed_pubkey() -> Vec<u8> {
    use k256::ecdsa::SigningKey;
    let sk_bytes = hex::decode(TEST_SK_HEX).unwrap();
    let sk = SigningKey::from_slice(&sk_bytes).unwrap();
    sk.verifying_key().to_encoded_point(true).as_bytes().to_vec()
}

/// A fully-specified EIP-1559 EVM transfer (nonce + fees + gas all provided so
/// `build_unsigned` is a pure function of the intent — no `ChainState` fill-in).
/// Mirrors the ready fixture in `evm/tx.rs`'s test module.
fn evm_intent() -> EvmIntent {
    EvmIntent {
        to: Some("0x000000000000000000000000000000000000dEaD".into()),
        value_wei: "1000000".into(),
        data_hex: "".into(),
        chain_id: 1,
        nonce: Some(0),
        max_fee_per_gas: Some("2000000000".into()),
        max_priority_fee_per_gas: Some("1000000000".into()),
        gas_limit: Some(21_000),
        legacy: false,
        gas_price: None,
    }
}

/// An analogous Cosmos transfer (the canonical SignDoc fixture: 1_000_000 uatom
/// from the test key to itself, fixed fee/gas/account/sequence/chain).
fn cosmos_intent() -> CosmosIntent {
    let pk = test_compressed_pubkey();
    let from = CosmosAdapter::address_from_pubkey(&pk, "cosmos").unwrap();
    CosmosIntent {
        chain_id: "cosmoshub-4".into(),
        hrp: "cosmos".into(),
        account_number: 1,
        sequence: 0,
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

/// The canonical Solana transfer fixture (byte-identical to the values in
/// `tests/solana_vectors.rs`): from = 0x42…, to = base58(0x24…), 1_000_000
/// lamports, blockhash = base58(0x11…). Kept self-consistent with that vector
/// file so the cross-chain assertions reuse the same known transfer.
fn solana_intent() -> SolanaIntent {
    SolanaIntent {
        from_pubkey_hex: hex::encode([0x42u8; 32]),
        to_address: bs58::encode([0x24u8; 32]).into_string(),
        lamports: 1_000_000,
        recent_blockhash: bs58::encode([0x11u8; 32]).into_string(),
    }
}

/// The authoritative BTC P2WPKH vector (byte-identical to the pinned values in
/// `tests/btc_vectors.rs`): this compressed pubkey derives this mainnet `bc1q…`
/// address. Kept self-consistent with that vector file so the cross-chain
/// assertions reuse the same known key/address.
const BTC_PUBKEY_HEX: &str =
    "033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc";
const BTC_ADDR_MAINNET: &str = "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw";

/// A `Utxo` with a deterministic txid (only the last byte varies) and value.
/// Mirrors the fixture shape in `tests/btc_vectors.rs`.
fn btc_utxo(txid_last_byte: u8, value: u64) -> Utxo {
    let mut t = String::from("00000000000000000000000000000000000000000000000000000000000000");
    t.push_str(&format!("{txid_last_byte:02x}"));
    Utxo { txid: t, vout: 0, value_sat: value }
}

/// A BTC transfer with TWO UTXOs (40_000 each; send 50_000 → both inputs
/// required), so `build_unsigned` must emit exactly 2 per-input BIP143 sighashes.
/// This is the distinguishing BTC property: N inputs → N `SignRequest::Digest`s,
/// vs the single-digest account chains. Reuses the authoritative pubkey/address.
fn btc_intent_two_utxos() -> BtcIntent {
    BtcIntent {
        from_pubkey_hex: BTC_PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: BTC_ADDR_MAINNET.into(),
        amount_sat: 50_000,
        fee_rate_sat_vb: 1,
        utxos: vec![btc_utxo(0x01, 40_000), btc_utxo(0x02, 40_000)],
    }
}

/// Pull ALL the per-input digests out of a BTC `Unsigned`, asserting every
/// sign-request is a 32-byte `SignRequest::Digest` (never a `Message`).
fn btc_digests(unsigned: &wallet_base_core::types::Unsigned) -> Vec<[u8; 32]> {
    unsigned
        .sign_requests
        .iter()
        .map(|sr| match sr {
            SignRequest::Digest(d) => {
                assert_eq!(d.len(), 32, "each BTC sighash must be 32 bytes");
                *d
            }
            other => panic!("BTC must sign Digests, got {other:?}"),
        })
        .collect()
}

/// Pull the single message-bytes blob out of a Solana `Unsigned`, asserting
/// there is exactly one `SignRequest::Message` — and explicitly that it is NOT a
/// `SignRequest::Digest`. This is the structural anti-cross-chain property: a
/// secp256k1 digest can never appear here, and this message can never appear in
/// `sole_digest`.
fn sole_message(unsigned: &wallet_base_core::types::Unsigned) -> Vec<u8> {
    assert_eq!(unsigned.sign_requests.len(), 1, "exactly one sign request");
    match &unsigned.sign_requests[0] {
        SignRequest::Message(m) => m.clone(),
        other @ SignRequest::Digest(_) => {
            panic!("Solana must sign a Message, never a Digest, got {other:?}")
        }
    }
}

/// Pull the single 32-byte digest out of an `Unsigned`, asserting there is
/// exactly one `SignRequest::Digest`.
fn sole_digest(unsigned: &wallet_base_core::types::Unsigned) -> [u8; 32] {
    assert_eq!(unsigned.sign_requests.len(), 1, "exactly one sign request");
    match &unsigned.sign_requests[0] {
        SignRequest::Digest(d) => {
            assert_eq!(d.len(), 32, "digest must be 32 bytes");
            *d
        }
        other => panic!("expected a Digest sign request, got {other:?}"),
    }
}

#[test]
fn evm_and_cosmos_digests_are_domain_separated() {
    let evm_unsigned =
        ChainAdapter::build_unsigned(&EvmAdapter, &evm_intent(), &ChainState::default()).unwrap();
    let cosmos_unsigned = CosmosAdapter::build_unsigned(&cosmos_intent()).unwrap();

    let evm_digest = sole_digest(&evm_unsigned);
    let cosmos_digest = sole_digest(&cosmos_unsigned);

    // The core anti-cross-chain-replay property: an analogous transfer produces
    // a different signing digest on each chain (keccak-256 sig-hash vs SHA-256
    // SignDoc). A signature over one is meaningless as a signature over the other.
    assert_ne!(
        evm_digest, cosmos_digest,
        "EVM and Cosmos signing digests for an analogous transfer must differ \
         (keccak vs SHA-256 domain separation)"
    );
}

#[test]
fn each_chain_digest_is_deterministic() {
    // Rebuilding from the same intent yields the same digest — the digest is a
    // pure function of that chain's preimage, so there is no nondeterminism an
    // attacker could exploit to slip a different preimage past a cached digest.
    let evm_a =
        ChainAdapter::build_unsigned(&EvmAdapter, &evm_intent(), &ChainState::default()).unwrap();
    let evm_b =
        ChainAdapter::build_unsigned(&EvmAdapter, &evm_intent(), &ChainState::default()).unwrap();
    assert_eq!(sole_digest(&evm_a), sole_digest(&evm_b), "EVM digest deterministic");

    let cosmos_a = CosmosAdapter::build_unsigned(&cosmos_intent()).unwrap();
    let cosmos_b = CosmosAdapter::build_unsigned(&cosmos_intent()).unwrap();
    assert_eq!(
        sole_digest(&cosmos_a),
        sole_digest(&cosmos_b),
        "Cosmos digest deterministic"
    );
}

#[test]
fn assemble_signed_is_bound_to_its_own_chain_encoding() {
    use cosmrs::proto::cosmos::tx::v1beta1::TxRaw;
    use cosmrs::proto::traits::Message;

    // Cosmos: assembling the Cosmos `Unsigned` with a single sig yields a decodable
    // protobuf `TxRaw` (64-byte compact r||s, no recovery id).
    let cosmos_unsigned = CosmosAdapter::build_unsigned(&cosmos_intent()).unwrap();
    let cosmos_sig = Secp256k1Signature { r: [0xAB; 32], s: [0xCD; 32], recovery_id: 0 };
    let cosmos_raw = CosmosAdapter::assemble_signed(&cosmos_unsigned, &[cosmos_sig]).unwrap();
    let txraw = TxRaw::decode(cosmos_raw.0.as_slice())
        .expect("Cosmos assemble_signed must produce a decodable protobuf TxRaw");
    assert_eq!(txraw.signatures.len(), 1);

    // EVM: assembling the EVM `Unsigned` yields an EIP-2718 RLP envelope (NOT a
    // protobuf TxRaw). It is a different byte format entirely, and the EVM path
    // requires a recovery id.
    let evm_unsigned =
        ChainAdapter::build_unsigned(&EvmAdapter, &evm_intent(), &ChainState::default()).unwrap();
    let evm_sig = Secp256k1Signature { r: [0x11; 32], s: [0x22; 32], recovery_id: 1 };
    let evm_raw = ChainAdapter::assemble_signed(&EvmAdapter, &evm_unsigned, &[evm_sig]).unwrap();

    // 1559 typed envelope leads with the 0x02 type marker — a protobuf TxRaw never
    // does — and the two encodings are not interchangeable.
    assert_eq!(evm_raw.0.first().copied(), Some(0x02u8), "1559 typed-envelope marker");
    assert!(
        TxRaw::decode(evm_raw.0.as_slice())
            .map(|tx| tx.signatures.len() == 1 && !tx.body_bytes.is_empty())
            .unwrap_or(false)
            == false,
        "EVM RLP envelope must NOT decode as a well-formed Cosmos TxRaw"
    );
    assert_ne!(evm_raw.0, cosmos_raw.0, "EVM and Cosmos raw txs are distinct encodings");

    // Sanity: the Cosmos raw really is SHA-256-preimage-shaped (non-empty body).
    assert!(!txraw.body_bytes.is_empty());
    let _ = Sha256::digest(&txraw.body_bytes); // SHA-256 is the Cosmos digest hash
}

#[test]
fn solana_signs_a_message_never_a_digest() {
    // Solana's distinguishing structural property: it emits exactly one
    // `SignRequest::Message(bytes)` — the whole serialized message, signed with
    // Ed25519 — and NEVER a `SignRequest::Digest`. `sole_message` asserts the
    // variant explicitly (and panics on a Digest), so a 32-byte secp256k1 digest
    // is structurally never a Solana sign input, and vice versa.
    let solana_unsigned = SolanaAdapter::build_unsigned(&solana_intent()).unwrap();
    let msg = sole_message(&solana_unsigned);

    // The message is the variable-length serialized transfer message — NOT a
    // fixed 32-byte digest. (A SystemProgram transfer message is well over 32 B.)
    assert_ne!(
        msg.len(),
        32,
        "a Solana message is variable-length, never a 32-byte secp256k1 digest"
    );
}

#[test]
fn solana_message_differs_from_evm_and_cosmos_digests() {
    // Anti-cross-chain-replay across all three chains for an analogous transfer:
    // the Solana sign input (message bytes) can never equal either the EVM or the
    // Cosmos secp256k1 digest. This is trivially true (different variant, and a
    // variable-length message vs a fixed 32-byte digest) but asserted as the
    // explicit isolation property: a digest minted for EVM/Cosmos can never be
    // replayed as a Solana sign input.
    let evm_unsigned =
        ChainAdapter::build_unsigned(&EvmAdapter, &evm_intent(), &ChainState::default()).unwrap();
    let cosmos_unsigned = CosmosAdapter::build_unsigned(&cosmos_intent()).unwrap();
    let solana_unsigned = SolanaAdapter::build_unsigned(&solana_intent()).unwrap();

    let evm_digest = sole_digest(&evm_unsigned);
    let cosmos_digest = sole_digest(&cosmos_unsigned);
    let solana_msg = sole_message(&solana_unsigned);

    // A 32-byte secp256k1 digest can never equal the variable-length Solana
    // message: compared as byte slices, the length alone separates them.
    assert_ne!(
        solana_msg.as_slice(),
        evm_digest.as_slice(),
        "Solana message must never equal the EVM secp256k1 digest"
    );
    assert_ne!(
        solana_msg.as_slice(),
        cosmos_digest.as_slice(),
        "Solana message must never equal the Cosmos secp256k1 digest"
    );
}

#[test]
fn solana_message_is_deterministic() {
    // Rebuilding the Solana `Unsigned` from the same intent yields byte-identical
    // message bytes — the sign input is a pure function of the intent, so there is
    // no nondeterminism an attacker could exploit to slip a different message past
    // a cached/approved one.
    let a = SolanaAdapter::build_unsigned(&solana_intent()).unwrap();
    let b = SolanaAdapter::build_unsigned(&solana_intent()).unwrap();
    assert_eq!(sole_message(&a), sole_message(&b), "Solana message deterministic");
}

#[test]
fn btc_multi_input_emits_one_digest_per_utxo() {
    // BTC's distinguishing structural property: a multi-input send emits exactly
    // ONE `SignRequest::Digest` per UTXO (one BIP143 sighash per input), unlike the
    // single-digest account chains (EVM/Cosmos) and the single-message Solana
    // chain. With 2 UTXOs both required to fund the send, there must be exactly 2
    // sign requests — the count equals the input count.
    let intent = btc_intent_two_utxos();
    let unsigned = BtcAdapter::build_unsigned(&intent).unwrap();
    let digests = btc_digests(&unsigned);

    assert_eq!(
        digests.len(),
        intent.utxos.len(),
        "BTC emits exactly one BIP143 sighash per input (N inputs → N digests)"
    );
    assert_eq!(digests.len(), 2, "the 2-UTXO fixture needs both inputs → 2 sighashes");
    // The two per-input sighashes differ (distinct prevout outpoint + value
    // position in the BIP143 preimage).
    assert_ne!(digests[0], digests[1], "per-input BTC sighashes are distinct");
}

#[test]
fn btc_sighash_differs_from_evm_and_cosmos_digests() {
    // Even though BTC shares the secp256k1 curve with EVM and Cosmos, each BIP143
    // sighash is its own preimage domain. For an analogous transfer, neither BTC
    // per-input sighash equals the EVM keccak sig-hash or the Cosmos SHA-256
    // SignDoc digest — so a digest minted for one chain can never be replayed as a
    // valid signing input for another.
    let evm_unsigned =
        ChainAdapter::build_unsigned(&EvmAdapter, &evm_intent(), &ChainState::default()).unwrap();
    let cosmos_unsigned = CosmosAdapter::build_unsigned(&cosmos_intent()).unwrap();
    let btc_unsigned = BtcAdapter::build_unsigned(&btc_intent_two_utxos()).unwrap();

    let evm_digest = sole_digest(&evm_unsigned);
    let cosmos_digest = sole_digest(&cosmos_unsigned);
    let btc = btc_digests(&btc_unsigned);

    // Each BTC sighash is 32 bytes (asserted in `btc_digests`) yet differs from
    // both the EVM and Cosmos single secp256k1 digests.
    for (i, d) in btc.iter().enumerate() {
        assert_ne!(
            d, &evm_digest,
            "BTC input {i} sighash must differ from the EVM keccak digest (distinct preimage domain)"
        );
        assert_ne!(
            d, &cosmos_digest,
            "BTC input {i} sighash must differ from the Cosmos SHA-256 SignDoc digest (distinct preimage domain)"
        );
    }
}

#[test]
fn btc_per_input_digests_are_deterministic() {
    // Rebuilding the BTC `Unsigned` from the same intent yields byte-identical
    // per-input digests — the sighashes are a pure function of the intent (fixed
    // tx + prevout values), so there is no nondeterminism an attacker could
    // exploit to slip a different preimage past a cached/approved one.
    let a = BtcAdapter::build_unsigned(&btc_intent_two_utxos()).unwrap();
    let b = BtcAdapter::build_unsigned(&btc_intent_two_utxos()).unwrap();
    assert_eq!(
        btc_digests(&a),
        btc_digests(&b),
        "BTC per-input sighashes are deterministic"
    );
}
