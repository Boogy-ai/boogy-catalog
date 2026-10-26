//! Solana message build + transaction assemble (SystemProgram transfer,
//! host-signed, Ed25519).
//!
//! Pinned API used here:
//!   - [`transfer_instruction`]: the System Program `Transfer` instruction,
//!     built here (its layout is fixed by the chain).
//!   - `solana_message::Message::new_with_blockhash(&[ix], Some(&from), &blockhash)
//!      -> Message`; `message.serialize()` (wincode) is EXACTLY the Ed25519 sign
//!      input.
//!   - assemble: the stored preimage is decoded back into a `Message` with
//!      `wincode` (solana-message's own codec) to find the signer and check the
//!      header, then the single-signer wire format is written directly:
//!      `compact-u16(1) || signature (64) || message`.
//!
//! Pinned byte-for-byte against solana-web3.js's own vectors (message and
//! signed transaction) in `tests/solana_vectors.rs`.

use crate::types::*;

use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;

/// The System Program's `Transfer` instruction, as the chain defines it: data
/// is the instruction's index in the System Program (2) as a little-endian
/// u32, then the lamports as a little-endian u64; accounts are the funding
/// account (signer, writable) and the recipient (writable).
pub fn transfer_instruction(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction::new_with_bytes(
        solana_sdk_ids::system_program::ID,
        &data,
        vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
    )
}

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

    let ix = transfer_instruction(&from_pk, &to_pk, intent.lamports);

    // Fee payer = from. new_with_blockhash builds the canonical SystemProgram
    // transfer Message; `message.serialize()` is the exact Ed25519 sign input.
    let message = Message::new_with_blockhash(&[ix], Some(&from_pk), &blockhash);
    let serialized = message.serialize();

    Ok(Unsigned {
        // The serialized Message is BOTH the preimage we rebuild from in
        // assemble_signed AND the exact sign input.
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
    let message = decode_message(&unsigned.preimage)?;

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

    wire_with_signature(&message, &unsigned.preimage, sig_arr)
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
    let message = decode_message(&unsigned.preimage)?;
    wire_with_signature(&message, &unsigned.preimage, sig_arr)
}

/// The stored preimage (`message.serialize()`) decoded back into its Message,
/// with solana-message's own codec. Trailing bytes are refused.
fn decode_message(preimage: &[u8]) -> Result<Message, AdapterError> {
    let message: Message = wincode::deserialize(preimage)
        .map_err(|e| AdapterError::Encoding(format!("deserialize solana message: {e}")))?;
    if message.serialize() != preimage {
        return Err(AdapterError::Encoding("solana message does not re-encode to its preimage".into()));
    }
    Ok(message)
}

/// The wire bytes of a single-signer transaction: the signature count as a
/// compact-u16 (1, one byte), the 64-byte signature, then the message bytes
/// exactly as signed. A message that requires any other number of signatures
/// is refused: this adapter builds single-signer transfers only.
fn wire_with_signature(message: &Message, message_bytes: &[u8], sig_arr: [u8; 64]) -> Result<RawTx, AdapterError> {
    if message.header.num_required_signatures != 1 {
        return Err(AdapterError::Encoding(format!(
            "expected a single-signer message, it requires {} signatures",
            message.header.num_required_signatures
        )));
    }
    let mut wire = Vec::with_capacity(1 + 64 + message_bytes.len());
    wire.push(1);
    wire.extend_from_slice(&sig_arr);
    wire.extend_from_slice(message_bytes);
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

    /// The assembler writes single-signer transactions only: a message that
    /// requires two signatures is refused, not given a zeroed second slot.
    #[test]
    fn a_two_signer_message_is_refused() {
        let from = Pubkey::from([0x42; 32]);
        let to = Pubkey::from([0x24; 32]);
        let mut ix = transfer_instruction(&from, &to, 1_000);
        ix.accounts[1].is_signer = true;
        let message = Message::new_with_blockhash(&[ix], Some(&from), &Hash::new_from_array([0x11; 32]));
        assert_eq!(message.header.num_required_signatures, 2);
        let unsigned = Unsigned { preimage: message.serialize(), sign_requests: vec![] };
        assert!(assemble_for_simulation(&unsigned, &[0u8; 64]).is_err());
    }

    /// A preimage that does not re-encode to itself (trailing bytes) is
    /// refused rather than spliced.
    #[test]
    fn a_preimage_with_trailing_bytes_is_refused() {
        let mut unsigned = build_unsigned(&fixture_intent()).unwrap();
        unsigned.preimage.push(0);
        assert!(assemble_for_simulation(&unsigned, &[0u8; 64]).is_err());
    }
}
