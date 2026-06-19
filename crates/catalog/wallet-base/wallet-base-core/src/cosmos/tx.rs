//! Cosmos SignDoc build + TxRaw assemble (SIGN_MODE_DIRECT, host-signed).
//!
//! Pinned cosmrs 0.22 encoding API actually used here:
//!   - `cosmrs::tx::Body::into_bytes(self) -> Result<Vec<u8>>`
//!   - `cosmrs::tx::AuthInfo::into_bytes(self) -> Result<Vec<u8>>`
//!   - `cosmrs::tx::SignDoc::new(&body, &auth_info, &chain_id, account_number)?`
//!     then `.into_bytes() -> Result<Vec<u8>>`
//!   - TxRaw proto: `cosmrs::proto::cosmos::tx::v1beta1::TxRaw`
//!     (re-exported from `cosmos_sdk_proto`)
//!   - prost encode: `cosmrs::proto::traits::Message::encode_to_vec(&txraw)`
//!     (`Message` is `cosmrs::proto::prost::Message`, re-exported via
//!     `cosmrs::proto::traits`)

use super::CosmosIntent;
use crate::types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use cosmrs::bank::MsgSend;
use cosmrs::crypto::PublicKey;
use cosmrs::proto::traits::Message; // brings `encode_to_vec` into scope
use cosmrs::tx::{Body, Fee, Msg, SignDoc, SignerInfo};
use cosmrs::{AccountId, Coin};

/// Resolved proto bytes carried in `Unsigned.preimage`, so `assemble_signed`
/// rebuilds `TxRaw` directly without re-deriving the body/auth_info.
#[derive(Serialize, Deserialize)]
struct ResolvedCosmosTx {
    body_bytes: Vec<u8>,
    auth_info_bytes: Vec<u8>,
    /// The signer's 33-byte compressed secp256k1 pubkey, hex. Carried so
    /// `assemble_signed` can self-verify the signature against the SignDoc
    /// sighash under it (#15) before emitting the TxRaw.
    pubkey_compressed_hex: String,
}

fn parse_u128_decimal(s: &str, field: &str) -> Result<u128, AdapterError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(AdapterError::BadIntent(format!("empty decimal {field}")));
    }
    trimmed
        .parse::<u128>()
        .map_err(|e| AdapterError::BadIntent(format!("invalid decimal {field}: {e}")))
}

fn parse_account_id(s: &str, field: &str) -> Result<AccountId, AdapterError> {
    s.parse::<AccountId>()
        .map_err(|e| AdapterError::BadIntent(format!("invalid {field} address: {e}")))
}

fn parse_coin(amount: &str, denom: &str, field: &str) -> Result<Coin, AdapterError> {
    let amt = parse_u128_decimal(amount, field)?;
    let denom = denom
        .parse()
        .map_err(|e| AdapterError::BadIntent(format!("invalid {field} denom: {e}")))?;
    Ok(Coin { denom, amount: amt })
}

pub fn build_unsigned(intent: &CosmosIntent) -> Result<Unsigned, AdapterError> {
    // Pubkey: 33-byte compressed hex → k256 VerifyingKey → cosmrs PublicKey.
    let pk_bytes = hex::decode(intent.pubkey_compressed_hex.trim())
        .map_err(|e| AdapterError::BadIntent(format!("invalid pubkey hex: {e}")))?;
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pk_bytes)
        .map_err(|e| AdapterError::BadIntent(format!("invalid secp256k1 pubkey: {e}")))?;
    let public_key = PublicKey::from(vk);

    let from = parse_account_id(&intent.from_address, "from")?;
    let to = parse_account_id(&intent.to_address, "to")?;

    let send_coin = parse_coin(&intent.amount, &intent.denom, "amount")?;
    let fee_coin = parse_coin(&intent.fee_amount, &intent.fee_denom, "fee")?;

    let msg = MsgSend {
        from_address: from,
        to_address: to,
        amount: vec![send_coin],
    };
    let any = msg
        .to_any()
        .map_err(|e| AdapterError::Encoding(format!("encode MsgSend: {e}")))?;

    let body = Body::new(vec![any], intent.memo.clone(), 0u16);

    let signer_info = SignerInfo::single_direct(Some(public_key), intent.sequence);
    let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(fee_coin, intent.gas_limit));

    let chain_id = intent
        .chain_id
        .parse()
        .map_err(|e| AdapterError::BadIntent(format!("invalid chain_id: {e}")))?;

    // SignDoc::new borrows body/auth_info; clones below are consumed by
    // into_bytes (which take self) to capture the canonical proto bytes.
    let sign_doc = SignDoc::new(&body, &auth_info, &chain_id, intent.account_number)
        .map_err(|e| AdapterError::Encoding(format!("build SignDoc: {e}")))?;
    let sign_bytes = sign_doc
        .into_bytes()
        .map_err(|e| AdapterError::Encoding(format!("encode SignDoc: {e}")))?;
    let digest: [u8; 32] = Sha256::digest(&sign_bytes).into();

    let body_bytes = body
        .into_bytes()
        .map_err(|e| AdapterError::Encoding(format!("encode body: {e}")))?;
    let auth_info_bytes = auth_info
        .into_bytes()
        .map_err(|e| AdapterError::Encoding(format!("encode auth_info: {e}")))?;

    let resolved = ResolvedCosmosTx {
        body_bytes,
        auth_info_bytes,
        pubkey_compressed_hex: intent.pubkey_compressed_hex.trim().to_string(),
    };
    let preimage = serde_json::to_vec(&resolved)
        .map_err(|e| AdapterError::Encoding(format!("serialize resolved cosmos tx: {e}")))?;

    Ok(Unsigned {
        preimage,
        sign_requests: vec![SignRequest::Digest(digest)],
    })
}

pub fn assemble_signed(
    unsigned: &Unsigned,
    sigs: &[Secp256k1Signature],
) -> Result<RawTx, AdapterError> {
    let resolved: ResolvedCosmosTx = serde_json::from_slice(&unsigned.preimage)
        .map_err(|e| AdapterError::Encoding(format!("deserialize resolved cosmos tx: {e}")))?;

    if sigs.len() != 1 {
        return Err(AdapterError::BadIntent(format!(
            "Cosmos requires exactly 1 signature, got {}",
            sigs.len()
        )));
    }
    // Cosmos uses the 64-byte compact r||s; NO recovery id (the pubkey is in
    // auth_info). r and s are fixed [u8; 32] arrays so a wrong length is
    // structurally impossible.
    let sig = &sigs[0];
    let mut sig64 = Vec::with_capacity(64);
    sig64.extend_from_slice(&sig.r);
    sig64.extend_from_slice(&sig.s);

    // SELF-VERIFY (#15): the signature MUST validate against the SignDoc sighash
    // (the digest emitted by build_unsigned) under the signer's pubkey before we
    // emit the TxRaw. Reuses the same `bitcoin::secp256k1` verifier the BTC path
    // uses. A wrong/corrupt signature is rejected here (fail loud) rather than
    // broadcasting a TxRaw the chain silently rejects as an invalid signature.
    let digest = match unsigned.sign_requests.first() {
        Some(SignRequest::Digest(d)) => *d,
        _ => return Err(AdapterError::Encoding("missing SignDoc sighash".into())),
    };
    let pk_bytes = hex::decode(resolved.pubkey_compressed_hex.trim())
        .map_err(|e| AdapterError::Encoding(format!("invalid stored pubkey hex: {e}")))?;
    let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&pk_bytes)
        .map_err(|e| AdapterError::Encoding(format!("invalid stored pubkey: {e}")))?;
    let mut secp_sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(&sig64)
        .map_err(|e| AdapterError::Encoding(format!("invalid compact sig: {e}")))?;
    // Cosmos requires low-S; normalize before verify (the host signs low-S).
    secp_sig.normalize_s();
    let msg = bitcoin::secp256k1::Message::from_digest(digest);
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    secp.verify_ecdsa(&msg, &secp_sig, &pubkey).map_err(|_| {
        AdapterError::BadIntent("signature does not verify against the SignDoc sighash".into())
    })?;

    // Emit the LOW-S-normalized signature (Cosmos rejects high-S). The host
    // already signs low-S, so this is a no-op in practice, but it keeps the
    // emitted bytes consistent with the signature we verified.
    encode_txraw(&resolved, secp_sig.serialize_compact().to_vec())
}

/// Assemble a TxRaw for the **simulate read-path ONLY**, splicing the signature
/// bytes verbatim WITHOUT the #15 self-verify. The Cosmos `/simulate` endpoint
/// is invoked with a dummy (all-zero) signature and the node runs it with
/// signature verification disabled, so a real signature (and the real key) is
/// never involved. NEVER use this on the signing/broadcast path — it does not
/// verify the signature.
pub fn assemble_for_simulation(
    unsigned: &Unsigned,
    sigs: &[Secp256k1Signature],
) -> Result<RawTx, AdapterError> {
    let resolved: ResolvedCosmosTx = serde_json::from_slice(&unsigned.preimage)
        .map_err(|e| AdapterError::Encoding(format!("deserialize resolved cosmos tx: {e}")))?;
    if sigs.len() != 1 {
        return Err(AdapterError::BadIntent(format!(
            "Cosmos requires exactly 1 signature, got {}",
            sigs.len()
        )));
    }
    let sig = &sigs[0];
    let mut sig64 = Vec::with_capacity(64);
    sig64.extend_from_slice(&sig.r);
    sig64.extend_from_slice(&sig.s);
    encode_txraw(&resolved, sig64)
}

fn encode_txraw(resolved: &ResolvedCosmosTx, signature: Vec<u8>) -> Result<RawTx, AdapterError> {
    let txraw = cosmrs::proto::cosmos::tx::v1beta1::TxRaw {
        body_bytes: resolved.body_bytes.clone(),
        auth_info_bytes: resolved.auth_info_bytes.clone(),
        signatures: vec![signature],
    };
    Ok(RawTx(txraw.encode_to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosmos::CosmosAdapter;

    fn test_pubkey_hex() -> String {
        use k256::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(
            &hex::decode("4646464646464646464646464646464646464646464646464646464646464646")
                .unwrap(),
        )
        .unwrap();
        hex::encode(sk.verifying_key().to_encoded_point(true).as_bytes())
    }

    fn fixture_intent() -> CosmosIntent {
        let from = CosmosAdapter::address_from_pubkey(
            &hex::decode(test_pubkey_hex()).unwrap(),
            "cosmos",
        )
        .unwrap();
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
            pubkey_compressed_hex: test_pubkey_hex(),
        }
    }

    #[test]
    fn build_unsigned_emits_one_digest() {
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
        i.pubkey_compressed_hex = "zzzz".into();
        assert!(build_unsigned(&i).is_err());
    }

    #[test]
    fn bad_from_address_errs() {
        let mut i = fixture_intent();
        i.from_address = "not-a-bech32".into();
        assert!(build_unsigned(&i).is_err());
    }

    #[test]
    fn empty_amount_errs() {
        let mut i = fixture_intent();
        i.amount = "".into();
        assert!(build_unsigned(&i).is_err());
    }

    #[test]
    fn assemble_requires_exactly_one_sig() {
        let u = build_unsigned(&fixture_intent()).unwrap();
        let sig = Secp256k1Signature { r: [0x11; 32], s: [0x22; 32], recovery_id: 0 };
        assert!(assemble_signed(&u, &[]).is_err());
        assert!(assemble_signed(&u, &[sig.clone(), sig.clone()]).is_err());
        // A structurally-valid-but-wrong signature (correct count) is REJECTED by
        // the post-assembly self-verify (#15) — see assemble_rejects_wrong_signature.
    }

    /// Sign the SignDoc sighash with the fixture's secp256k1 key (same 32-byte
    /// seed as `test_pubkey_hex`, so the signature verifies against the embedded
    /// pubkey). Uses the `bitcoin::secp256k1` signer (already a crate dep).
    fn sign_cosmos(u: &Unsigned) -> Secp256k1Signature {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(
            &hex::decode("4646464646464646464646464646464646464646464646464646464646464646")
                .unwrap(),
        )
        .unwrap();
        let d = match &u.sign_requests[0] {
            SignRequest::Digest(d) => *d,
            other => panic!("expected Digest, got {other:?}"),
        };
        let msg = bitcoin::secp256k1::Message::from_digest(d);
        let c = secp.sign_ecdsa(&msg, &sk).serialize_compact();
        let mut r = [0u8; 32];
        r.copy_from_slice(&c[0..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&c[32..64]);
        Secp256k1Signature { r, s, recovery_id: 0 }
    }

    #[test]
    fn assemble_accepts_valid_signature() {
        let u = build_unsigned(&fixture_intent()).unwrap();
        assert!(
            assemble_signed(&u, &[sign_cosmos(&u)]).is_ok(),
            "a signature over the SignDoc sighash under the embedded pubkey assembles"
        );
    }

    #[test]
    fn assemble_rejects_wrong_signature() {
        // #15: a structurally-valid signature that does NOT verify against the
        // SignDoc sighash under the signer's pubkey is rejected (fail loud) rather
        // than emitting a TxRaw the chain silently rejects at broadcast.
        let u = build_unsigned(&fixture_intent()).unwrap();
        let bad = Secp256k1Signature { r: [0x11; 32], s: [0x22; 32], recovery_id: 0 };
        assert!(assemble_signed(&u, &[bad]).is_err());
    }
}
