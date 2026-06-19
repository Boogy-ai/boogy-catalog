//! Solana message build + transaction assemble (SystemProgram transfer,
//! host-signed, Ed25519).
//!
//! Pinned, spike-verified API used here:
//!   - `solana_system_interface::instruction::transfer(&from, &to, lamports)
//!      -> solana_instruction::Instruction`
//!   - `solana_message::Message::new_with_blockhash(&[ix], Some(&from), &blockhash)
//!      -> Message`; `message.serialize() -> Vec<u8>` is EXACTLY the Ed25519
//!      sign input.
//!   - assemble: `Transaction::new_unsigned(message)` (sizes `.signatures` to
//!      `num_required_signatures` == 1 for a single-signer transfer), then
//!      `tx.signatures[0] = Signature::from(<[u8; 64]>)` and
//!      `bincode::serialize(&tx)` for the broadcast-ready wire bytes.
//!
//! The `Message` is round-tripped from `Unsigned.preimage`, which holds
//! `message.serialize()`. In solana-message 4.x `Message::serialize()` is
//! `wincode::serialize` while `assemble_signed` decodes with `bincode`; the
//! round-trip is byte-correct because wincode's ShortU16 + fixint-LE layout is
//! identical to what serde's `bincode` reads back here for this fixed Message
//! shape (#19 — the two encoders agree on these bytes; do NOT assume they are
//! interchangeable in general). `btc_vectors`-style snapshot + round-trip tests
//! guard against a future divergence.

use crate::types::*;

use solana_hash::Hash;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

/// Normalized intent for a single SystemProgram `transfer`. Fee payer = `from`.
#[derive(Debug, Clone)]
pub struct SolanaIntent {
    /// 32-byte Ed25519 public key (the sender / fee payer), hex-encoded.
    pub from_pubkey_hex: String,
    /// Recipient address (base58 of a 32-byte Ed25519 pubkey).
    pub to_address: String,
    /// Transfer amount in lamports.
    pub lamports: u64,
    /// Recent blockhash (base58 of 32 bytes), fetched from the cluster.
    pub recent_blockhash: String,
}

/// Decode a base58 string to exactly 32 bytes (a Solana pubkey / blockhash).
/// Bad base58 or wrong length → `Err` (fail closed, no panic).
fn decode_base58_32(s: &str, field: &str) -> Result<[u8; 32], AdapterError> {
    let bytes = bs58::decode(s.trim())
        .into_vec()
        .map_err(|e| AdapterError::BadIntent(format!("invalid base58 {field}: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        AdapterError::BadIntent(format!("{field} must be 32 bytes, got {}", v.len()))
    })
}

pub fn build_unsigned(intent: &SolanaIntent) -> Result<Unsigned, AdapterError> {
    // Fee payer / sender: 32-byte Ed25519 pubkey, hex-encoded.
    let from_bytes = hex::decode(intent.from_pubkey_hex.trim())
        .map_err(|e| AdapterError::BadIntent(format!("invalid from_pubkey hex: {e}")))?;
    let from_arr: [u8; 32] = from_bytes.try_into().map_err(|v: Vec<u8>| {
        AdapterError::BadIntent(format!("from_pubkey must be 32 bytes, got {}", v.len()))
    })?;
    let from_pk = Pubkey::from(from_arr);

    // Recipient + recent blockhash: base58 of 32 bytes each.
    let to_pk = Pubkey::from(decode_base58_32(&intent.to_address, "to_address")?);
    let blockhash = Hash::new_from_array(decode_base58_32(
        &intent.recent_blockhash,
        "recent_blockhash",
    )?);

    let ix = solana_system_interface::instruction::transfer(&from_pk, &to_pk, intent.lamports);

    // Fee payer = from. new_with_blockhash builds the canonical SystemProgram
    // transfer Message; `message.serialize()` is the exact Ed25519 sign input.
    let message = Message::new_with_blockhash(&[ix], Some(&from_pk), &blockhash);
    let serialized = message.serialize();

    Ok(Unsigned {
        // The serialized Message is BOTH the preimage we rebuild from in
        // assemble_signed (via bincode round-trip) AND the exact sign input.
        preimage: serialized.clone(),
        sign_requests: vec![SignRequest::Message(serialized)],
    })
}

pub fn assemble_signed(unsigned: &Unsigned, sig64: &[u8]) -> Result<RawTx, AdapterError> {
    // Ed25519 signature is a RAW 64-byte sig — no recovery id, no r/s split.
    let sig_arr: [u8; 64] = sig64.try_into().map_err(|_| {
        AdapterError::Encoding(format!(
            "Solana requires a 64-byte Ed25519 signature, got {}",
            sig64.len()
        ))
    })?;

    // Rebuild the Message from the stored preimage (== message.serialize()).
    let message: Message = bincode::deserialize(&unsigned.preimage)
        .map_err(|e| AdapterError::Encoding(format!("deserialize solana message: {e}")))?;

    // SELF-VERIFY (#15): the Ed25519 signature MUST validate against the signed
    // message bytes (the preimage) under the fee-payer / signer pubkey
    // (`account_keys[0]` — the sole required signer for a single-signer transfer)
    // before we emit the transaction. A wrong/corrupt signature is rejected here
    // (fail loud) rather than broadcasting a tx the cluster rejects.
    let signer = message
        .account_keys
        .first()
        .ok_or_else(|| AdapterError::Encoding("message has no signer account".into()))?;
    if !Signature::from(sig_arr).verify(signer.as_ref(), &unsigned.preimage) {
        return Err(AdapterError::BadIntent(
            "signature does not verify against the message".into(),
        ));
    }

    splice_signature(message, sig_arr)
}

/// Assemble a transaction for the **simulate read-path ONLY**, splicing the
/// signature verbatim WITHOUT the #15 self-verify. The Solana `simulateTransaction`
/// RPC is invoked with `sigVerify: false` and a dummy (all-zero) signature, so a
/// real signature (and the real key) is never involved. NEVER use this on the
/// signing/broadcast path — it does not verify the signature.
pub fn assemble_for_simulation(unsigned: &Unsigned, sig64: &[u8]) -> Result<RawTx, AdapterError> {
    let sig_arr: [u8; 64] = sig64.try_into().map_err(|_| {
        AdapterError::Encoding(format!(
            "Solana requires a 64-byte Ed25519 signature, got {}",
            sig64.len()
        ))
    })?;
    let message: Message = bincode::deserialize(&unsigned.preimage)
        .map_err(|e| AdapterError::Encoding(format!("deserialize solana message: {e}")))?;
    splice_signature(message, sig_arr)
}

/// Splice a raw 64-byte signature into slot 0 of the transaction and serialize.
fn splice_signature(message: Message, sig_arr: [u8; 64]) -> Result<RawTx, AdapterError> {
    // new_unsigned sizes `.signatures` to num_required_signatures (== 1 for a
    // single-signer transfer); splice the raw sig into slot 0.
    let mut tx = Transaction::new_unsigned(message);
    if tx.signatures.is_empty() {
        return Err(AdapterError::Encoding(
            "transaction has no signature slots".into(),
        ));
    }
    tx.signatures[0] = Signature::from(sig_arr);

    let wire = bincode::serialize(&tx)
        .map_err(|e| AdapterError::Encoding(format!("serialize solana transaction: {e}")))?;
    Ok(RawTx(wire))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solana::SolanaAdapter;

    // Deterministic fixture: from = 0x42…, to = 0x24…, 1_000_000 lamports,
    // blockhash 0x11…. Mirrors the spike's Message snapshot fixture.
    fn fixture_intent() -> SolanaIntent {
        SolanaIntent {
            from_pubkey_hex: hex::encode([0x42u8; 32]),
            to_address: bs58::encode([0x24u8; 32]).into_string(),
            lamports: 1_000_000,
            recent_blockhash: bs58::encode([0x11u8; 32]).into_string(),
        }
    }

    #[test]
    fn build_unsigned_emits_one_message_request() {
        let u = build_unsigned(&fixture_intent()).unwrap();
        assert_eq!(u.sign_requests.len(), 1);
        match &u.sign_requests[0] {
            SignRequest::Message(m) => {
                assert!(!m.is_empty());
                assert_eq!(m, &u.preimage, "preimage == message.serialize()");
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[test]
    fn assemble_requires_64_byte_sig() {
        let u = build_unsigned(&fixture_intent()).unwrap();
        for len in [0usize, 63, 65] {
            let sig = vec![0u8; len];
            assert!(
                SolanaAdapter::assemble_signed(&u, &sig).is_err(),
                "len {len} must Err"
            );
        }
        // A 64-byte-but-wrong signature is now REJECTED by the post-assembly
        // self-verify (#15) — see assemble_rejects_wrong_signature / accepts_valid.
    }

    /// A real Ed25519 keypair (test-only) + an intent whose `from` is its pubkey.
    fn signing_fixture() -> (ed25519_dalek::SigningKey, SolanaIntent) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let intent = SolanaIntent {
            from_pubkey_hex: hex::encode(pk),
            ..fixture_intent()
        };
        (sk, intent)
    }

    #[test]
    fn assemble_accepts_valid_signature() {
        use ed25519_dalek::Signer;
        let (sk, intent) = signing_fixture();
        let u = build_unsigned(&intent).unwrap();
        // Sign the exact message bytes (== preimage) the Ed25519 path commits to.
        let sig = sk.sign(&u.preimage).to_bytes();
        assert!(
            SolanaAdapter::assemble_signed(&u, &sig).is_ok(),
            "a signature over the message under the signer key assembles"
        );
    }

    #[test]
    fn assemble_rejects_wrong_signature() {
        // #15: a 64-byte signature that does NOT verify against the message under
        // the signer pubkey is rejected (fail loud), not spliced + broadcast.
        let (_sk, intent) = signing_fixture();
        let u = build_unsigned(&intent).unwrap();
        assert!(SolanaAdapter::assemble_signed(&u, &[0xAB; 64]).is_err());
    }

    #[test]
    fn bad_from_pubkey_errs() {
        let mut nothex = fixture_intent();
        nothex.from_pubkey_hex = "zzzz".into();
        assert!(build_unsigned(&nothex).is_err());

        let mut shortpk = fixture_intent();
        shortpk.from_pubkey_hex = hex::encode([0x42u8; 31]);
        assert!(build_unsigned(&shortpk).is_err());
    }

    #[test]
    fn bad_base58_fields_err() {
        let mut bad_to = fixture_intent();
        bad_to.to_address = "0OIl".into(); // chars outside the base58 alphabet
        assert!(build_unsigned(&bad_to).is_err());

        let mut bad_bh = fixture_intent();
        bad_bh.recent_blockhash = "not valid base58!!".into();
        assert!(build_unsigned(&bad_bh).is_err());
    }
}
