//! Solana (`/solana/*`) service handlers — external-signer mode.
//!
//! Mirrors the EVM/Cosmos surface (`sign` / `simulate` / `fees` / `send` /
//! `policy`) but over Solana via `wallet_base_core::solana::SolanaAdapter` and
//! the JSON-RPC client `rpc_client::call_solana_rpc`. Solana is the first
//! non-secp256k1 chain: the key is **Ed25519**, signing is over the whole
//! serialized message (`signing_sign_message`), and the signature is a RAW
//! 64-byte sig (no recovery id, no r/s split).
//!
//! Security invariants (identical to EVM/Cosmos):
//!
//! - The signing-key LABEL is derived from the host-attested principal via
//!   `wallet_label_checked(current_principal(), "solana")`, NEVER from the body —
//!   the sign-as-anyone guard.
//! - Guardrails (`guardrails::check_policy`) run BEFORE the key is touched
//!   (reject-before-signing); ambiguous/unparseable amounts REJECT (fail-closed).
//! - A blocked principal cannot sign or send.
//! - `from_pubkey_hex` is read from the caller's stored `Wallet` row, never the
//!   body; `recent_blockhash` comes from the body (sign-only) or is fetched
//!   on-chain (send/simulate) outside the store `tx` (`outbound_http` is denied
//!   inside a `tx`).

use boogy_sdk::jobs::JobSpec;
use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::signing::SigAlg;
use serde::{Deserialize, Serialize};
use wallet_base_core::solana::rpc::{latest_blockhash_request, parse_latest_blockhash};
use wallet_base_core::solana::{SolanaAdapter, SolanaIntent};
use wallet_base_core::types::SignRequest;

use crate::models::{Transaction, Wallet};
use crate::rpc_client::call_solana_rpc;
use crate::{
    auth, db_insert, is_blocked, jobs_enqueue, load_daily_spend, load_policy, now_millis,
    parse_allowlist, put_policy_for, signing_sign_message, tx, upsert_daily_spend, ApiError, Json,
    PolicyReq, Query, Req, SendOut, SignOut, SimOut, SOLANA_CHAIN,
};

// ─── DTOs ──────────────────────────────────────────────────────────────────────

/// Request body for the Solana handlers. Only chain-public fields are caller-
/// supplied; `from_pubkey_hex` is read from the caller's stored wallet row
/// (never the body). `recent_blockhash` is required for the sign-only path and
/// fetched on-chain for `send`/`simulate`/`fees` when absent.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct SolanaIntentReq {
    /// base58 recipient address (a 32-byte Ed25519 pubkey).
    pub to_address: String,
    /// Transfer amount in lamports.
    pub lamports: u64,
    /// Recent blockhash (base58). Required for the sign-only path; fetched
    /// on-chain for `send`/`simulate`/`fees` when absent.
    pub recent_blockhash: Option<String>,
}

/// Result of `POST /solana/fees`: the network fee for a Solana transaction.
#[derive(Serialize, schemars::JsonSchema)]
pub struct SolanaFeesOut {
    /// The fee in lamports for the message at the resolved blockhash. `null`
    /// when the blockhash is unknown/expired — the caller should refresh the
    /// blockhash (re-POST without `recent_blockhash`) and retry.
    pub fee_lamports: Option<u64>,
}

// ─── Wallet lookup ───────────────────────────────────────────────────────────

/// Load the caller's Solana `Wallet` row (the local key cache). A missing row →
/// the key was never created for this principal.
fn require_wallet(principal: &str) -> Result<Wallet, ApiError> {
    let row = Query::on(Wallet::TABLE)
        .where_eq(Wallet::OWNER_PRINCIPAL, principal)
        .where_eq(Wallet::CHAIN, SOLANA_CHAIN)
        .fetch_one()?
        .ok_or_else(|| ApiError::bad_request("no solana wallet; create one first"))?;
    Ok(Wallet::from_row(&row))
}

/// Build a `SolanaIntent` from the request body + the caller's stored wallet,
/// with a resolved `recent_blockhash`. `from_pubkey_hex` is always taken from
/// the wallet row, never the body.
fn build_intent(body: &SolanaIntentReq, wallet: &Wallet, recent_blockhash: String) -> SolanaIntent {
    SolanaIntent {
        from_pubkey_hex: wallet.pubkey_hex.clone(),
        to_address: body.to_address.clone(),
        lamports: body.lamports,
        recent_blockhash,
    }
}

/// Sign the single message of `unsigned` with the host-held Ed25519 key under
/// `label` and assemble the broadcast-ready raw tx. The key is touched ONLY
/// here, after the caller has already cleared guardrails.
///
/// Solana's adapter emits exactly one `SignRequest::Message(bytes)`; Ed25519
/// signs the full message and returns a RAW 64-byte signature (no recovery id),
/// which `assemble_signed` takes directly (NOT the secp256k1 r/s path).
fn sign_and_assemble(
    label: &str,
    unsigned: &wallet_base_core::types::Unsigned,
) -> Result<String, ApiError> {
    let sr = unsigned
        .sign_requests
        .first()
        .ok_or_else(|| ApiError::internal("solana adapter produced no sign request"))?;
    let msg = match sr {
        SignRequest::Message(m) => m,
        SignRequest::Digest(_) => {
            return Err(ApiError::internal(
                "solana adapter produced a non-message sign request",
            ))
        }
    };
    let sdk_sig = signing_sign_message(label, msg, SigAlg::Ed25519)
        .map_err(|e| ApiError::internal(format!("sign message: {e}")))?;
    // Ed25519: the signature bytes ARE the raw 64-byte sig (recovery_id None).
    let raw = SolanaAdapter::assemble_signed(unsigned, &sdk_sig.bytes)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(raw.to_hex())
}

/// Fetch a recent blockhash from the cluster via the JSON-RPC endpoint.
fn fetch_recent_blockhash() -> Result<String, ApiError> {
    let resp = call_solana_rpc(&latest_blockhash_request())?;
    let bh =
        parse_latest_blockhash(&resp).map_err(|e| ApiError::service_unavailable(e.to_string()))?;
    Ok(bh.blockhash)
}

// ─── /solana/sign ────────────────────────────────────────────────────────────

/// `POST /solana/sign` — sign a fully-specified Solana transfer (sign-only).
///
/// `recent_blockhash` is REQUIRED in the body (no on-chain fetch);
/// `from_pubkey_hex` comes from the caller's stored wallet row. The signing
/// label is host-derived. No broadcast.
pub fn solana_sign(Json(body): Json<SolanaIntentReq>) -> Result<Json<SignOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;

    // Label is host-derived; this also validates "solana" as a known chain.
    let label = wallet_base_core::subject::wallet_label_checked(&p, SOLANA_CHAIN)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let wallet = require_wallet(&p)?;

    let recent_blockhash = body
        .recent_blockhash
        .clone()
        .ok_or_else(|| ApiError::bad_request("recent_blockhash required for sign-only"))?;

    let intent = build_intent(&body, &wallet, recent_blockhash);
    let unsigned = SolanaAdapter::build_unsigned(&intent)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let raw = sign_and_assemble(&label, &unsigned)?;

    Ok(Json(SignOut { raw }))
}

// ─── /solana/simulate ──────────────────────────────────────────────────────────

/// Core of `POST /solana/simulate`: dry-run a Solana transfer WITHOUT touching
/// the real key. `simulateTransaction` is called with `sigVerify:false`, so the
/// tx is assembled with a DUMMY 64-byte signature — the signing key is never
/// touched on this read path.
pub fn do_solana_simulate(principal: &str, body: SolanaIntentReq) -> Result<SimOut, ApiError> {
    use wallet_base_core::solana::rpc::{parse_simulate, simulate_request};

    let wallet = require_wallet(principal)?;

    // Resolve the recent blockhash: body wins, else fetch on-chain.
    let recent_blockhash = match &body.recent_blockhash {
        Some(b) => b.clone(),
        None => fetch_recent_blockhash()?,
    };

    let intent = build_intent(&body, &wallet, recent_blockhash);
    let unsigned = SolanaAdapter::build_unsigned(&intent)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    // DUMMY signature: simulate sets sigVerify:false, so the real key is NOT
    // touched on this read path.
    let raw = SolanaAdapter::assemble_signed(&unsigned, &[0u8; 64])
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let resp = call_solana_rpc(&simulate_request(&raw.0))?;
    let sim = parse_simulate(&resp).map_err(|e| ApiError::service_unavailable(e.to_string()))?;

    Ok(SimOut { success: sim.success, gas_used: sim.gas_used, error: sim.error })
}

/// `POST /solana/simulate` — dry-run a Solana transfer via `simulateTransaction`.
/// Does NOT touch the signing key (a dummy signature is used, which simulate
/// does not verify). `recent_blockhash` is read from the body or fetched
/// on-chain when absent. Requires the caller to have a Solana wallet (400
/// otherwise).
pub fn solana_simulate(Json(body): Json<SolanaIntentReq>) -> Result<Json<SimOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    do_solana_simulate(&p, body).map(Json)
}

// ─── /solana/fees ──────────────────────────────────────────────────────────────

/// `POST /solana/fees` — the network fee (lamports) for a posted Solana
/// transfer.
///
/// Solana fees are per-signature and looked up via `getFeeForMessage`, which
/// takes the serialized **message** bytes (not the full tx) at a blockhash. The
/// message is built from the posted intent (`recent_blockhash` fetched when
/// absent). The key is NOT touched. `fee_lamports` is `null` when the blockhash
/// is unknown/expired — the caller should refresh the blockhash and retry.
pub fn solana_fees(Json(body): Json<SolanaIntentReq>) -> Result<Json<SolanaFeesOut>, ApiError> {
    use wallet_base_core::solana::rpc::{fee_for_message_request, parse_fee_for_message};

    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    let wallet = require_wallet(&p)?;

    let recent_blockhash = match &body.recent_blockhash {
        Some(b) => b.clone(),
        None => fetch_recent_blockhash()?,
    };

    let intent = build_intent(&body, &wallet, recent_blockhash);
    let unsigned = SolanaAdapter::build_unsigned(&intent)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    // getFeeForMessage takes the serialized MESSAGE bytes — that is the exact
    // Ed25519 sign input the adapter emits (`unsigned.preimage` ==
    // SignRequest::Message bytes), NOT the full assembled tx.
    let resp = call_solana_rpc(&fee_for_message_request(&unsigned.preimage))?;
    let fee = parse_fee_for_message(&resp)
        .map_err(|e| ApiError::service_unavailable(e.to_string()))?;

    Ok(Json(SolanaFeesOut { fee_lamports: fee }))
}

// ─── /solana/send ──────────────────────────────────────────────────────────────

/// Core of `POST /solana/send`: the full resolve → guardrail → sign → persist →
/// enqueue pipeline for Solana. Mirrors `do_cosmos_send` on the security path.
///
/// Guardrails run BEFORE the key is touched. The signing label is derived from
/// the principal, never the body. The recent blockhash is fetched on-chain
/// (outside the `tx`) when absent. On success the `Transaction` row (status
/// `signed`), the `DailySpend` accumulator, and the `broadcast_tx` job enqueue
/// commit together in one store transaction.
pub fn do_solana_send(principal: &str, body: SolanaIntentReq) -> Result<SendOut, ApiError> {
    // A blocked principal cannot sign or send.
    if is_blocked(principal)? {
        return Err(ApiError::forbidden("this account is blocked"));
    }

    // Label is host-derived; also validates "solana" as a known chain.
    let label = wallet_base_core::subject::wallet_label_checked(principal, SOLANA_CHAIN)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let wallet = require_wallet(principal)?;

    // ── Resolve recent_blockhash (fetch if absent) — pre-tx ──
    // outbound_http is DENIED inside a store `tx`, so do this before the tx.
    let recent_blockhash = match &body.recent_blockhash {
        Some(b) => b.clone(),
        None => fetch_recent_blockhash()?,
    };

    let intent = build_intent(&body, &wallet, recent_blockhash);

    // ── Guardrails — BEFORE signing ──
    // value = the transfer amount in lamports; recipient = the base58 to_address
    // (canonical — do NOT lowercase it; base58 is case-sensitive). A SystemProgram
    // transfer carries no contract calldata, so to_is_contract = false and the
    // contract allowlist is empty. We do not simulate on the send path, so
    // sim_success = true (no revert signal to enforce).
    let policy = load_policy(principal, SOLANA_CHAIN)?;
    let now_secs = now_millis() as i64 / 1000;
    let daily = load_daily_spend(principal, SOLANA_CHAIN, now_secs)?;

    let (max_value_wei, daily_cap_wei, recipient_allow, _contract_allow, refuse_on_revert) =
        match &policy {
            Some(pol) => (
                pol.max_value_wei.clone(),
                pol.daily_cap_wei.clone(),
                parse_allowlist(&pol.recipient_allowlist),
                parse_allowlist(&pol.contract_allowlist),
                pol.refuse_on_revert,
            ),
            None => (String::new(), String::new(), Vec::new(), Vec::new(), true),
        };

    let value_lamports = intent.lamports.to_string();
    let pi = wallet_base_core::guardrails::PolicyInput {
        value_wei: value_lamports.clone(),
        max_value_wei,
        daily_cap_wei,
        daily_spent_wei: daily.as_ref().map(|d| d.spent_wei.clone()).unwrap_or_default(),
        recipient: intent.to_address.clone(),
        recipient_allowlist: recipient_allow,
        to_is_contract: false,
        contract_allowlist: Vec::new(),
        sim_success: true,
        refuse_on_revert,
    };
    wallet_base_core::guardrails::check_policy(&pi)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    // ── Sign (key is touched only after guardrails pass) ──
    let unsigned = SolanaAdapter::build_unsigned(&intent)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let raw_hex = sign_and_assemble(&label, &unsigned)?;

    // Snapshot values needed for persistence.
    let intent_json = serde_json::to_string(&serialize_intent(&intent))
        .map_err(|e| ApiError::internal(format!("encode intent: {e}")))?;
    let to_addr = intent.to_address.clone();
    let now = Timestamp::new(now_millis() as i64);
    let owner = principal.to_string();

    // ── Persist + enqueue atomically ──
    let tx_id = tx::<_, _, ApiError>(|| {
        let tx_id = db_insert(&Transaction {
            id: Id::new(0),
            owner_principal: owner.clone(),
            chain: SOLANA_CHAIN.to_string(),
            status: "signed".to_string(),
            intent_json: intent_json.clone(),
            raw_hex: raw_hex.clone(),
            tx_hash: String::new(),
            to_addr: to_addr.clone(),
            value_wei: value_lamports.clone(),
            // Solana has no account sequence/nonce; the column is unused here.
            nonce: 0,
            // Fee is not resolved on the send path (per-signature, looked up via
            // /solana/fees); left empty.
            fee_wei: String::new(),
            sim_json: String::new(),
            confirmations: 0,
            created_at: now,
            updated_at: now,
        })
        .map_err(ApiError::from)?;

        upsert_daily_spend(&owner, SOLANA_CHAIN, now_secs, &value_lamports, now)?;

        jobs_enqueue(JobSpec {
            handler: "broadcast_tx".into(),
            payload: serde_json::to_vec(&serde_json::json!({ "tx_id": tx_id }))
                .map_err(|e| ApiError::internal(format!("encode broadcast payload: {e}")))?,
            idempotency_key: Some(format!("broadcast:{tx_id}")),
            ..Default::default()
        })
        .map_err(|e| ApiError::internal(format!("enqueue broadcast: {e}")))?;

        Ok(tx_id)
    })?;

    Ok(SendOut { tx_id, status: "signed".to_string() })
}

/// `POST /solana/send` — resolve → guardrail → sign → persist → enqueue.
///
/// Guardrails run BEFORE the key is touched (reject-before-signing). The signing
/// label is derived from the host-attested principal, never the body. On success
/// the signed `Transaction` row (status `signed`), the `DailySpend` accumulator,
/// and the `broadcast_tx` job enqueue commit together in one store transaction;
/// broadcast + confirmation proceed asynchronously and are streamed on the
/// `wallet` WS channel.
pub fn solana_send(Json(body): Json<SolanaIntentReq>) -> Result<Json<SendOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    do_solana_send(&p, body).map(Json)
}

// ─── /solana/policy ────────────────────────────────────────────────────────────

/// `GET /solana/policy` — return the caller's Solana spend policy (defaults if
/// none). The `PolicyReq` "wei" naming is generic decimal — for Solana the caps
/// are lamport amounts.
pub fn solana_get_policy(_req: &mut Req<'_>) -> Result<Json<PolicyReq>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    let policy = load_policy(&p, SOLANA_CHAIN)?;
    Ok(Json(policy.as_ref().map(PolicyReq::from).unwrap_or_default()))
}

/// `PUT /solana/policy` — upsert the caller's Solana spend policy.
pub fn solana_put_policy(Json(body): Json<PolicyReq>) -> Result<Json<PolicyReq>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    put_policy_for(&p, SOLANA_CHAIN, &body).map(Json)
}

// ─── helpers ───────────────────────────────────────────────────────────────────

/// Serialize a resolved `SolanaIntent` for the `Transaction.intent_json` audit
/// column. `SolanaIntent` is not `Serialize`, so project its fields into a JSON
/// object (the same shape the caller posted, plus the resolved blockhash).
fn serialize_intent(i: &SolanaIntent) -> serde_json::Value {
    serde_json::json!({
        "from_pubkey_hex": i.from_pubkey_hex,
        "to_address": i.to_address,
        "lamports": i.lamports,
        "recent_blockhash": i.recent_blockhash,
    })
}
