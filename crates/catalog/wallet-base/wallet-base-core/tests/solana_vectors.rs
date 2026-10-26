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
//!     check the wire layout and decode the message back, assert signature +
//!     message survive;
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

    // The wire layout: one signature (compact-u16 1), the raw 64-byte sig,
    // then the message exactly as signed, which decodes back to itself.
    assert_eq!(raw.0[0], 1, "exactly one signature slot");
    assert_eq!(&raw.0[1..65], &sig[..], "raw 64-byte sig spliced verbatim into slot 0");
    assert_eq!(&raw.0[65..], &unsigned.preimage[..], "message preserved through assemble");
    let decoded: solana_message::Message = wincode::deserialize(&raw.0[65..]).unwrap();
    assert_eq!(decoded.serialize(), unsigned.preimage);
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

// ---------------------------------------------------------------------------
// 4. Known-answer test from an independent implementation
// ---------------------------------------------------------------------------

/// solana-web3.js (maintenance/v1.x), `test/transaction.test.ts`, "serialize
/// unsigned transaction" and "parse wire format and serialize": a
/// `SystemProgram.transfer` of 49 lamports from `Keypair.fromSeed([8; 32])` to
/// `J3dxNj7nDRRqRRXuEMynDG57DkZK4jYRuv3Garmb1i99`, recent blockhash
/// `EETubP5AKHgjPAhzPAFcb8BAY1hMH639CWCFTqi3hq1k`, fee payer the sender. The
/// two base64 strings are web3.js's expected wire bytes, verbatim: unsigned (a
/// zeroed signature slot) and signed by web3.js.
const WEB3JS_UNSIGNED_B64: &str = concat!(
    "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAABAAEDE5j2LG0aRXxRumpLXz29L2n8qTIWIY3ImX5Ba9F9k8r9",
    "Q5/Mtmcn8onFxt47xKj+XdXXd3C8j/FcPu7csUrz/AAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAxJrndgN4IFTxep3s6kO0ROug7bEsbx0xxuDkqEvwUusBAgIAAQwC",
    "AAAAMQAAAAAAAAA=",
);
const WEB3JS_SIGNED_B64: &str = concat!(
    "AVuErQHaXv0SG0/PchunfxHKt8wMRfMZzqV0tkC5qO6owYxWU2v871AoWywGoFQr4z+q/7mE8lIufNl/",
    "kxj+nQ0BAAEDE5j2LG0aRXxRumpLXz29L2n8qTIWIY3ImX5Ba9F9k8r9Q5/Mtmcn8onFxt47xKj+XdXX",
    "d3C8j/FcPu7csUrz/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxJrndgN4IFTxep3s6kO0",
    "ROug7bEsbx0xxuDkqEvwUusBAgIAAQwCAAAAMQAAAAAAAAA=",
);

fn b64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn web3js_intent() -> SolanaIntent {
    let sender = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    SolanaIntent {
        from_pubkey_hex: hex::encode(sender.verifying_key().to_bytes()),
        to_address: "J3dxNj7nDRRqRRXuEMynDG57DkZK4jYRuv3Garmb1i99".into(),
        lamports: 49,
        recent_blockhash: "EETubP5AKHgjPAhzPAFcb8BAY1hMH639CWCFTqi3hq1k".into(),
    }
}

/// Our serialized Message, the exact Ed25519 sign input, is byte-identical to
/// web3.js's: the wire bytes after the one-entry signature section.
#[test]
fn solana_message_matches_web3js() {
    let unsigned = SolanaAdapter::build_unsigned(&web3js_intent()).unwrap();
    let wire = b64(WEB3JS_UNSIGNED_B64);
    assert_eq!(wire[0], 1, "one signature slot");
    assert_eq!(hex::encode(&unsigned.preimage), hex::encode(&wire[65..]));
    match &unsigned.sign_requests[..] {
        [SignRequest::Message(m)] => assert_eq!(m, &unsigned.preimage),
        other => panic!("expected one Message sign request, got {other:?}"),
    }
}

/// web3.js's signature, spliced by our assembler (which self-verifies it
/// against our message), gives web3.js's signed wire bytes exactly.
#[test]
fn solana_signed_transaction_matches_web3js() {
    let unsigned = SolanaAdapter::build_unsigned(&web3js_intent()).unwrap();
    let signed = b64(WEB3JS_SIGNED_B64);
    let sig: [u8; 64] = signed[1..65].try_into().unwrap();
    let raw: RawTx = SolanaAdapter::assemble_signed(&unsigned, &sig).unwrap();
    assert_eq!(hex::encode(&raw.0), hex::encode(&signed));
}
