//! Solana (Ed25519, external-signer) adapter vectors.
//!
//! Three parts mirroring the Cosmos vector file:
//!  1. Address KAT (authoritative): all-zero 32-byte pubkey → the canonical
//!     base58 system-program id `"11111111111111111111111111111111"`. The
//!     address IS the pubkey, base58-encoded — no hashing.
//!  2. Message-serialize stability snapshot: `build_unsigned` for a fixed
//!     transfer must reproduce a captured serialized-Message hex blob. Solana
//!     lacks rich published end-to-end vectors; this guards encoding stability
//!     across crate revs. The assemble round-trip below covers byte-correctness.
//!  3. Assemble round-trip + adversarial: splice a raw 64-byte Ed25519 sig,
//!     bincode-decode the Transaction back, assert signature + message survive;
//!     reject wrong sig length / bad base58 / non-hex / wrong-length pubkey.

use wallet_base_core::solana::{SolanaAdapter, SolanaIntent};
use wallet_base_core::types::{RawTx, SignRequest};

// ---------------------------------------------------------------------------
// 1. Address KAT
// ---------------------------------------------------------------------------

#[test]
fn solana_address_all_zero_pubkey_kat() {
    let addr = SolanaAdapter::address_from_pubkey(&[0u8; 32]).unwrap();
    assert_eq!(addr, "11111111111111111111111111111111");
}

#[test]
fn solana_address_rejects_wrong_length() {
    for len in [0usize, 31, 33, 64] {
        let bytes = vec![0u8; len];
        assert!(
            SolanaAdapter::address_from_pubkey(&bytes).is_err(),
            "len {len} must Err"
        );
    }
}

// ---------------------------------------------------------------------------
// Shared fixture: from = 0x42…, to = 0x24…, 1_000_000 lamports, blockhash 0x11…
// ---------------------------------------------------------------------------

fn fixture_intent() -> SolanaIntent {
    SolanaIntent {
        from_pubkey_hex: hex::encode([0x42u8; 32]),
        to_address: bs58::encode([0x24u8; 32]).into_string(),
        lamports: 1_000_000,
        recent_blockhash: bs58::encode([0x11u8; 32]).into_string(),
    }
}

// ---------------------------------------------------------------------------
// 2. Message-serialize stability snapshot
// ---------------------------------------------------------------------------

/// Hex of the serialized transfer Message for `fixture_intent()`. Captured on
/// first green run — a stability snapshot (NOT a published vector). On the first
/// run this fails and prints the actual hex; paste it here to lock the snapshot.
const MESSAGE_SNAPSHOT_HEX: &str = "01000103424242424242424242424242424242424242424242424242424242424242424224242424242424242424242424242424242424242424242424242424242424240000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111101020200010c0200000040420f0000000000";

#[test]
fn solana_build_unsigned_matches_message_snapshot() {
    let unsigned = SolanaAdapter::build_unsigned(&fixture_intent()).unwrap();
    assert_eq!(unsigned.sign_requests.len(), 1);
    let msg_hex = match &unsigned.sign_requests[0] {
        SignRequest::Message(m) => hex::encode(m),
        other => panic!("expected Message, got {other:?}"),
    };
    // The preimage is byte-identical to the sign input.
    assert_eq!(hex::encode(&unsigned.preimage), msg_hex);
    assert_eq!(
        msg_hex, MESSAGE_SNAPSHOT_HEX,
        "serialized Message changed (or snapshot not yet captured)"
    );
}

// ---------------------------------------------------------------------------
// 3. Assemble round-trip + adversarial
// ---------------------------------------------------------------------------

#[test]
fn solana_assemble_roundtrips_into_transaction() {
    use solana_transaction::Transaction;

    use ed25519_dalek::{Signer, SigningKey};

    // A REAL Ed25519 keypair; the intent's `from` is its pubkey so the signature
    // verifies. The post-assembly self-verify (#15) now rejects a dummy sig.
    let sk = SigningKey::from_bytes(&[0x33u8; 32]);
    let intent = SolanaIntent {
        from_pubkey_hex: hex::encode(sk.verifying_key().to_bytes()),
        ..fixture_intent()
    };
    let unsigned = SolanaAdapter::build_unsigned(&intent).unwrap();

    // Sign the exact message bytes (== preimage) the Ed25519 path commits to.
    let sig = sk.sign(&unsigned.preimage).to_bytes();
    let raw: RawTx = SolanaAdapter::assemble_signed(&unsigned, &sig).unwrap();

    // Decode the Transaction back and assert structure survives.
    let decoded: Transaction = bincode::deserialize(&raw.0).unwrap();
    assert_eq!(decoded.signatures.len(), 1, "exactly one signature slot");
    assert_eq!(
        decoded.signatures[0].as_ref(),
        &sig[..],
        "raw 64-byte sig spliced verbatim into slot 0"
    );
    // The signed message matches the preimage we built from.
    assert_eq!(
        decoded.message.serialize(),
        unsigned.preimage,
        "message preserved through assemble"
    );
}

#[test]
fn solana_assemble_rejects_wrong_sig_length() {
    let unsigned = SolanaAdapter::build_unsigned(&fixture_intent()).unwrap();
    for len in [0usize, 63, 65] {
        let sig = vec![0u8; len];
        assert!(
            SolanaAdapter::assemble_signed(&unsigned, &sig).is_err(),
            "len {len} must Err"
        );
    }
}

#[test]
fn solana_build_unsigned_rejects_bad_base58() {
    let mut bad_to = fixture_intent();
    bad_to.to_address = "0OIl".into(); // chars outside the base58 alphabet
    assert!(SolanaAdapter::build_unsigned(&bad_to).is_err());

    let mut bad_bh = fixture_intent();
    bad_bh.recent_blockhash = "not valid base58!!".into();
    assert!(SolanaAdapter::build_unsigned(&bad_bh).is_err());

    // Valid base58 but wrong decoded length.
    let mut short_to = fixture_intent();
    short_to.to_address = bs58::encode([0x24u8; 16]).into_string();
    assert!(SolanaAdapter::build_unsigned(&short_to).is_err());
}

#[test]
fn solana_build_unsigned_rejects_bad_from_pubkey() {
    let mut nothex = fixture_intent();
    nothex.from_pubkey_hex = "nothex".into();
    assert!(SolanaAdapter::build_unsigned(&nothex).is_err());

    let mut short = fixture_intent();
    short.from_pubkey_hex = hex::encode([0x42u8; 31]);
    assert!(SolanaAdapter::build_unsigned(&short).is_err());

    let mut long = fixture_intent();
    long.from_pubkey_hex = hex::encode([0x42u8; 33]);
    assert!(SolanaAdapter::build_unsigned(&long).is_err());
}
