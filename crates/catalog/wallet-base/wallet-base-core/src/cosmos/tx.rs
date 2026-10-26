//! Cosmos SignDoc build + TxRaw assemble (SIGN_MODE_DIRECT, host-signed).
//!
//! The protobuf messages come from `cosmos-sdk-proto` and are encoded with
//! prost; nothing here signs. The input checks are the ones the chain applies
//! to the same fields:
//!   - an address is BIP-173 bech32 (not bech32m) in one case, with a
//!     lowercase alphanumeric prefix and 1..=255 bytes, zero padding, and is
//!     re-encoded lowercase;
//!   - a denom is 3..=128 of `[A-Za-z0-9/:._-]`;
//!   - a chain id is 1..=50 of `[A-Za-z0-9._-]`;
//!   - the pubkey is a valid secp256k1 point, carried compressed.
//!
//! `tests/cosmos_vectors.rs` pins the output: cosmjs's published
//! SIGN_MODE_DIRECT vector byte for byte, the SignDoc snapshot, and an
//! independent hand-encoding of the SignDoc framing.

use super::CosmosIntent;
use crate::types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use cosmos_sdk_proto::cosmos::bank::v1beta1::MsgSend;
use cosmos_sdk_proto::cosmos::base::v1beta1::Coin;
use cosmos_sdk_proto::cosmos::crypto::secp256k1::PubKey;
use cosmos_sdk_proto::cosmos::tx::signing::v1beta1::SignMode;
use cosmos_sdk_proto::cosmos::tx::v1beta1::{mode_info, AuthInfo, Fee, ModeInfo, SignDoc, SignerInfo, TxBody, TxRaw};
use cosmos_sdk_proto::prost::{Message, Name};
use cosmos_sdk_proto::Any;

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

/// A bech32 account address, re-encoded in lowercase.
fn parse_account_id(s: &str, field: &str) -> Result<String, AdapterError> {
    use bech32::primitives::decode::CheckedHrpstring;
    let bad = |why: String| AdapterError::BadIntent(format!("invalid {field} address: {why}"));
    let checked = CheckedHrpstring::new::<bech32::Bech32>(s).map_err(|e| bad(e.to_string()))?;
    checked.validate_segwit_padding().map_err(|e| bad(e.to_string()))?;
    let prefix = checked.hrp().to_lowercase();
    if !prefix.chars().all(|c| matches!(c, 'a'..='z' | '0'..='9')) {
        return Err(bad("expected prefix to be lowercase alphanumeric characters only".into()));
    }
    let bytes: Vec<u8> = checked.byte_iter().collect();
    if !(1..=255).contains(&bytes.len()) {
        return Err(bad(format!("account ID should be 1 to 255 bytes long, but was {} bytes long", bytes.len())));
    }
    bech32::encode::<bech32::Bech32>(checked.hrp(), &bytes).map_err(|e| bad(e.to_string()))
}

fn parse_coin(amount: &str, denom: &str, field: &str) -> Result<Coin, AdapterError> {
    let amt = parse_u128_decimal(amount, field)?;
    let valid = (3..=128).contains(&denom.len())
        && denom.chars().all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '/' | ':' | '.' | '_' | '-'));
    if !valid {
        return Err(AdapterError::BadIntent(format!("invalid {field} denom: {denom}")));
    }
    Ok(Coin { denom: denom.to_string(), amount: amt.to_string() })
}

fn parse_chain_id(s: &str) -> Result<String, AdapterError> {
    let valid = (1..=50).contains(&s.len())
        && s.bytes().all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.'));
    if !valid {
        return Err(AdapterError::BadIntent(format!("invalid chain_id: {s}")));
    }
    Ok(s.to_string())
}

fn any_of<M: Name>(msg: &M) -> Any {
    Any { type_url: M::type_url(), value: msg.encode_to_vec() }
}

pub fn build_unsigned(intent: &CosmosIntent) -> Result<Unsigned, AdapterError> {
    // Pubkey: 33-byte compressed hex (or a 65-byte uncompressed point),
    // checked on the curve and carried compressed.
    let pk_bytes = hex::decode(intent.pubkey_compressed_hex.trim())
        .map_err(|e| AdapterError::BadIntent(format!("invalid pubkey hex: {e}")))?;
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pk_bytes)
        .map_err(|e| AdapterError::BadIntent(format!("invalid secp256k1 pubkey: {e}")))?;
    let public_key = any_of(&PubKey { key: vk.to_sec1_point(true).as_bytes().to_vec() });

    let from = parse_account_id(&intent.from_address, "from")?;
    let to = parse_account_id(&intent.to_address, "to")?;

    let send_coin = parse_coin(&intent.amount, &intent.denom, "amount")?;
    let fee_coin = parse_coin(&intent.fee_amount, &intent.fee_denom, "fee")?;

    let msg = MsgSend { from_address: from, to_address: to, amount: vec![send_coin] };

    let body = TxBody { messages: vec![any_of(&msg)], memo: intent.memo.clone(), ..Default::default() };

    let signer_info = SignerInfo {
        public_key: Some(public_key),
        mode_info: Some(ModeInfo { sum: Some(mode_info::Sum::Single(mode_info::Single { mode: SignMode::Direct as i32 })) }),
        sequence: intent.sequence,
    };
    let auth_info = AuthInfo {
        signer_infos: vec![signer_info],
        fee: Some(Fee { amount: vec![fee_coin], gas_limit: intent.gas_limit, ..Default::default() }),
        ..Default::default()
    };

    let chain_id = parse_chain_id(&intent.chain_id)?;

    let body_bytes = body.encode_to_vec();
    let auth_info_bytes = auth_info.encode_to_vec();
    let sign_doc = SignDoc {
        body_bytes: body_bytes.clone(),
        auth_info_bytes: auth_info_bytes.clone(),
        chain_id,
        account_number: intent.account_number,
    };
    let digest: [u8; 32] = Sha256::digest(sign_doc.encode_to_vec()).into();

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
    let txraw = TxRaw {
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

    /// The rules cosmrs applied before the proto types replaced it: BIP-173
    /// bech32 in one case, re-encoded lowercase; a lowercase alphanumeric
    /// prefix; 1..=255 bytes.
    #[test]
    fn an_address_is_single_case_bech32_with_an_alphanumeric_prefix() {
        let lower = "cosmos1pkptre7fdkl6gfrzlesjjvhxhlc3r4gmmk8rs6";
        assert_eq!(parse_account_id(lower, "to").unwrap(), lower);
        assert_eq!(parse_account_id(&lower.to_uppercase(), "to").unwrap(), lower);
        let mixed = "Cosmos1pkptre7fdkl6gfrzlesjjvhxhlc3r4gmmk8rs6";
        assert!(parse_account_id(mixed, "to").is_err());
        let hrp = |h: &str| bech32::Hrp::parse(h).unwrap();
        let bech32m = bech32::encode::<bech32::Bech32m>(hrp("cosmos"), &[7u8; 20]).unwrap();
        assert!(parse_account_id(&bech32m, "to").is_err(), "bech32m is not an account address");
        let odd_prefix = bech32::encode::<bech32::Bech32>(hrp("cos-mos"), &[7u8; 20]).unwrap();
        assert!(parse_account_id(&odd_prefix, "to").is_err());
        let empty = bech32::encode::<bech32::Bech32>(hrp("cosmos"), &[]).unwrap();
        assert!(parse_account_id(&empty, "to").is_err());
        let module = bech32::encode::<bech32::Bech32>(hrp("cosmos"), &[7u8; 32]).unwrap();
        assert_eq!(parse_account_id(&module, "to").unwrap(), module);
    }

    #[test]
    fn a_denom_and_a_chain_id_keep_cosmrs_and_tendermints_rules() {
        assert!(parse_coin("1", "uatom", "amount").is_ok());
        assert!(parse_coin("1", "ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2", "amount").is_ok());
        assert!(parse_coin("1", "ua", "amount").is_err());
        assert!(parse_coin("1", "u atom", "amount").is_err());
        assert!(parse_coin("1", &"a".repeat(129), "amount").is_err());
        assert_eq!(parse_coin("1000000", "uatom", "amount").unwrap().amount, "1000000");
        assert!(parse_chain_id("cosmoshub-4").is_ok());
        assert!(parse_chain_id("").is_err());
        assert!(parse_chain_id(&"c".repeat(51)).is_err());
        assert!(parse_chain_id("cosmos hub").is_err());
    }

    fn test_pubkey_hex() -> String {
        use k256::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(
            &hex::decode("4646464646464646464646464646464646464646464646464646464646464646")
                .unwrap(),
        )
        .unwrap();
        hex::encode(sk.verifying_key().to_sec1_point(true).as_bytes())
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
