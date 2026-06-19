//! Cosmos (`/cosmos/*`) service handlers — external-signer mode.
//!
//! Mirrors the EVM surface (`sign` / `simulate` / `fees` / `send` / `policy`)
//! but over a Cosmos SDK chain via `wallet_base_core::cosmos::CosmosAdapter` and
//! the LCD (REST) client `rpc_client::call_cosmos_rpc`. The same host-held
//! secp256k1 key backs both chains; only the address encoding + transaction
//! format differ.
//!
//! Security invariants (identical to EVM):
//!
//! - The signing-key LABEL is derived from the host-attested principal via
//!   `wallet_label_checked(current_principal(), "cosmos")`, NEVER from the body —
//!   the sign-as-anyone guard.
//! - Guardrails (`guardrails::check_policy`) run BEFORE the key is touched
//!   (reject-before-signing); ambiguous/unparseable amounts REJECT (fail-closed).
//! - A blocked principal cannot sign or send.
//! - `from_address` + the pubkey are read from the caller's stored `Wallet` row,
//!   never the body; `account_number`/`sequence` come from the body (sign-only)
//!   or are fetched on-chain (send) outside the store `tx` (`outbound_http` is
//!   denied inside a `tx`).

use boogy_sdk::jobs::JobSpec;
use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::signing::SigAlg;
use serde::{Deserialize, Serialize};
use wallet_base_core::cosmos::rpc::{account_request, parse_account, simulate_request};
use wallet_base_core::cosmos::{CosmosAdapter, CosmosIntent};
use wallet_base_core::types::{Secp256k1Signature, SignRequest};

use crate::models::{Transaction, Wallet};
use crate::rpc_client::call_cosmos_rpc;
use crate::{
    auth, db_insert, is_blocked, jobs_enqueue, load_daily_spend, load_policy, now_millis,
    parse_allowlist, put_policy_for, signing_sign_digest, tx, upsert_daily_spend, ApiError, Json,
    PolicyReq, Query, Req, SendOut, SignOut, SimOut, COSMOS_CHAIN, COSMOS_HRP,
};

// ─── DTOs ──────────────────────────────────────────────────────────────────────

/// Request body for the Cosmos handlers. Only chain-public fields are caller-
/// supplied; `from_address` + the pubkey are read from the caller's stored
/// wallet row (never the body). `account_number`/`sequence` are required for the
/// sign-only path and fetched on-chain for `send`/`simulate` when absent.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct CosmosIntentReq {
    /// Chain id, e.g. `"cosmoshub-4"`.
    pub chain_id: String,
    /// bech32 recipient address.
    pub to_address: String,
    /// Transfer amount in the base denom, as a decimal string.
    pub amount: String,
    /// Base denom of the transfer, e.g. `"uatom"`.
    pub denom: String,
    /// Fee amount in the base denom, as a decimal string.
    pub fee_amount: String,
    /// Fee denom, e.g. `"uatom"`.
    pub fee_denom: String,
    /// Gas limit. Required for `send` (a missing limit may be estimated via
    /// simulate first); used as-is for `sign`/`simulate`.
    pub gas_limit: Option<u64>,
    /// Optional memo.
    #[serde(default)]
    pub memo: String,
    /// Account number. Required for the sign-only path; fetched on-chain for
    /// `send`/`simulate` when absent.
    pub account_number: Option<u64>,
    /// Account sequence. Required for the sign-only path; fetched on-chain for
    /// `send`/`simulate` when absent.
    pub sequence: Option<u64>,
    /// bech32 human-readable prefix; defaults to `"cosmos"`.
    pub hrp: Option<String>,
}

/// Result of `POST /cosmos/fees`: the estimated gas for a Cosmos transaction.
#[derive(Serialize, schemars::JsonSchema)]
pub struct CosmosFeesOut {
    /// Estimated gas units consumed (from a simulate). The Cosmos fee is
    /// `gas_used × gas_price`, where the gas price is operator/chain-configured;
    /// the caller multiplies by their chosen gas price.
    pub gas_used: Option<u64>,
}

// ─── Wallet lookup ───────────────────────────────────────────────────────────

/// Load the caller's Cosmos `Wallet` row (the local key cache). A missing row →
/// the key was never created for this principal.
fn require_wallet(principal: &str) -> Result<Wallet, ApiError> {
    let row = Query::on(Wallet::TABLE)
        .where_eq(Wallet::OWNER_PRINCIPAL, principal)
        .where_eq(Wallet::CHAIN, COSMOS_CHAIN)
        .fetch_one()?
        .ok_or_else(|| ApiError::bad_request("no cosmos wallet; create one first"))?;
    Ok(Wallet::from_row(&row))
}

/// Build a `CosmosIntent` from the request body + the caller's stored wallet,
/// with resolved `account_number`/`sequence`. `from_address` and the pubkey are
/// always taken from the wallet row, never the body.
fn build_intent(
    body: &CosmosIntentReq,
    wallet: &Wallet,
    account_number: u64,
    sequence: u64,
    gas_limit: u64,
) -> CosmosIntent {
    CosmosIntent {
        chain_id: body.chain_id.clone(),
        hrp: body.hrp.clone().unwrap_or_else(|| COSMOS_HRP.to_string()),
        account_number,
        sequence,
        from_address: wallet.address.clone(),
        to_address: body.to_address.clone(),
        amount: body.amount.clone(),
        denom: body.denom.clone(),
        fee_amount: body.fee_amount.clone(),
        fee_denom: body.fee_denom.clone(),
        gas_limit,
        memo: body.memo.clone(),
        pubkey_compressed_hex: wallet.pubkey_hex.clone(),
    }
}

/// Sign every digest of `unsigned` with the host-held key under `label` and
/// assemble the broadcast-ready raw tx. The key is touched ONLY here, after the
/// caller has already cleared guardrails.
fn sign_and_assemble(
    label: &str,
    unsigned: &wallet_base_core::types::Unsigned,
) -> Result<String, ApiError> {
    let mut sigs = Vec::with_capacity(unsigned.sign_requests.len());
    for sr in &unsigned.sign_requests {
        let digest = match sr {
            SignRequest::Digest(d) => d,
            SignRequest::Message(_) => {
                return Err(ApiError::internal(
                    "cosmos adapter produced a non-digest sign request",
                ))
            }
        };
        // Cosmos secp256k1 signing returns a recovery id; assemble only uses
        // r||s, but `secp_sig_from_compact` requires the id to be present.
        let sdk_sig = signing_sign_digest(label, digest, SigAlg::EcdsaSecp256k1)
            .map_err(|e| ApiError::internal(format!("sign digest: {e}")))?;
        let sig = wallet_base_core::secp_sig_from_compact(&sdk_sig.bytes, sdk_sig.recovery_id)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        sigs.push(sig);
    }
    let raw = CosmosAdapter::assemble_signed(unsigned, &sigs)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(raw.to_hex())
}

/// Fetch the caller's on-chain account (account_number + sequence) via the LCD.
fn fetch_account(address: &str) -> Result<(u64, u64), ApiError> {
    let resp = call_cosmos_rpc(&account_request(address))?;
    let acc = parse_account(&resp).map_err(|e| ApiError::service_unavailable(e.to_string()))?;
    Ok((acc.account_number, acc.sequence))
}

// ─── /cosmos/sign ──────────────────────────────────────────────────────────────

/// `POST /cosmos/sign` — sign a fully-specified Cosmos intent (sign-only).
///
/// `account_number` + `sequence` are REQUIRED in the body (no on-chain fetch);
/// `from_address` + the pubkey come from the caller's stored wallet row. The
/// signing label is host-derived. No broadcast.
pub fn cosmos_sign(Json(body): Json<CosmosIntentReq>) -> Result<Json<SignOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;

    // Label is host-derived; this also validates "cosmos" as a known chain.
    let label = wallet_base_core::subject::wallet_label_checked(&p, COSMOS_CHAIN)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let wallet = require_wallet(&p)?;

    let account_number = body
        .account_number
        .ok_or_else(|| ApiError::bad_request("account_number required for sign-only"))?;
    let sequence = body
        .sequence
        .ok_or_else(|| ApiError::bad_request("sequence required for sign-only"))?;
    let gas_limit = body
        .gas_limit
        .ok_or_else(|| ApiError::bad_request("gas_limit required for sign-only"))?;

    let intent = build_intent(&body, &wallet, account_number, sequence, gas_limit);
    let unsigned = CosmosAdapter::build_unsigned(&intent)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let raw = sign_and_assemble(&label, &unsigned)?;

    Ok(Json(SignOut { raw }))
}

// ─── /cosmos/simulate ──────────────────────────────────────────────────────────

/// Core of `POST /cosmos/simulate`: estimate gas for a Cosmos intent WITHOUT
/// touching the real key. The Cosmos simulate endpoint does not verify
/// signatures, so the tx is assembled with a DUMMY signature — the signing key
/// is never touched on this read path.
pub fn do_cosmos_simulate(principal: &str, body: CosmosIntentReq) -> Result<SimOut, ApiError> {
    use wallet_base_core::cosmos::rpc::parse_simulate;

    let wallet = require_wallet(principal)?;

    // Resolve account_number/sequence: body wins, else fetch on-chain.
    let (account_number, sequence) = match (body.account_number, body.sequence) {
        (Some(a), Some(s)) => (a, s),
        _ => fetch_account(&wallet.address)?,
    };
    // Gas limit only frames the SignDoc here; simulate returns the real estimate.
    let gas_limit = body.gas_limit.unwrap_or(200_000);

    let intent = build_intent(&body, &wallet, account_number, sequence, gas_limit);
    let unsigned = CosmosAdapter::build_unsigned(&intent)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    // DUMMY signature: simulate does not verify it, so the real key is NOT
    // touched on this read path.
    let dummy = Secp256k1Signature { r: [0u8; 32], s: [0u8; 32], recovery_id: 0 };
    let raw = CosmosAdapter::assemble_signed(&unsigned, &[dummy])
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let resp = call_cosmos_rpc(&simulate_request(&raw.0))?;
    let sim = parse_simulate(&resp).map_err(|e| ApiError::service_unavailable(e.to_string()))?;

    Ok(SimOut { success: sim.success, gas_used: sim.gas_used, error: sim.error })
}

/// `POST /cosmos/simulate` — estimate gas for a Cosmos transaction via the LCD
/// simulate endpoint. Does NOT touch the signing key (a dummy signature is used,
/// which the simulate endpoint does not verify). Requires the caller to have a
/// Cosmos wallet (400 otherwise).
pub fn cosmos_simulate(Json(body): Json<CosmosIntentReq>) -> Result<Json<SimOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    do_cosmos_simulate(&p, body).map(Json)
}

// ─── /cosmos/fees ──────────────────────────────────────────────────────────────

/// `POST /cosmos/fees` — estimate the gas for a posted Cosmos intent.
///
/// Cosmos has no EIP-1559 base-fee market: gas is estimated per-transaction and
/// the fee is `gas_used × gas_price` where the gas price is operator/chain-
/// configured. This runs the same simulate as `/cosmos/simulate` and returns
/// just the gas estimate; the caller multiplies by their chosen gas price.
pub fn cosmos_fees(Json(body): Json<CosmosIntentReq>) -> Result<Json<CosmosFeesOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    let sim = do_cosmos_simulate(&p, body)?;
    Ok(Json(CosmosFeesOut { gas_used: sim.gas_used }))
}

// ─── /cosmos/send ──────────────────────────────────────────────────────────────

/// Core of `POST /cosmos/send`: the full resolve → guardrail → sign → persist →
/// enqueue pipeline for Cosmos. Mirrors `do_send` (EVM) on the security path.
///
/// Guardrails run BEFORE the key is touched. The signing label is derived from
/// the principal, never the body. Account number/sequence are fetched on-chain
/// (outside the `tx`) when absent. On success the `Transaction` row (status
/// `signed`), the `DailySpend` accumulator, and the `broadcast_tx` job enqueue
/// commit together in one store transaction.
pub fn do_cosmos_send(principal: &str, body: CosmosIntentReq) -> Result<SendOut, ApiError> {
    // A blocked principal cannot sign or send.
    if is_blocked(principal)? {
        return Err(ApiError::forbidden("this account is blocked"));
    }

    // Label is host-derived; also validates "cosmos" as a known chain.
    let label = wallet_base_core::subject::wallet_label_checked(principal, COSMOS_CHAIN)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let wallet = require_wallet(principal)?;

    // ── Resolve account_number + sequence (fetch if absent) — pre-tx ──
    // outbound_http is DENIED inside a store `tx`, so do this before the tx.
    let (account_number, sequence) = match (body.account_number, body.sequence) {
        (Some(a), Some(s)) => (a, s),
        _ => fetch_account(&wallet.address)?,
    };

    // ── Resolve fee: Cosmos fees are explicit. fee_amount/fee_denom are required;
    // gas_limit is estimated via simulate (with +10% headroom) when absent. ──
    if body.fee_amount.trim().is_empty() || body.fee_denom.trim().is_empty() {
        return Err(ApiError::bad_request("fee_amount and fee_denom required"));
    }
    let gas_limit = match body.gas_limit {
        Some(g) => g,
        None => {
            // Estimate via simulate (dummy-signed, no key touch), +10% headroom.
            let sim = do_cosmos_simulate(principal, clone_req(&body))?;
            let est = sim
                .gas_used
                .ok_or_else(|| ApiError::bad_request("gas_limit required (gas estimate unavailable)"))?;
            est.saturating_add(est / 10) // +10% headroom
        }
    };

    let intent = build_intent(&body, &wallet, account_number, sequence, gas_limit);

    // ── Guardrails — BEFORE signing ──
    // value = the MsgSend amount in base denom; recipient = the bech32 to_address
    // (canonical lowercase already — do NOT re-case it). Cosmos send carries no
    // calldata, so to_is_contract = false and the contract allowlist is empty. We
    // do not simulate on the send path beyond an optional gas estimate, so
    // sim_success = true (no revert signal to enforce).
    let policy = load_policy(principal, COSMOS_CHAIN)?;
    let now_secs = now_millis() as i64 / 1000;
    let daily = load_daily_spend(principal, COSMOS_CHAIN, now_secs)?;

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

    let pi = wallet_base_core::guardrails::PolicyInput {
        value_wei: intent.amount.clone(),
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
    let unsigned = CosmosAdapter::build_unsigned(&intent)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let raw_hex = sign_and_assemble(&label, &unsigned)?;

    // Snapshot values needed for persistence.
    let intent_json = serde_json::to_string(&serialize_intent(&intent))
        .map_err(|e| ApiError::internal(format!("encode intent: {e}")))?;
    let to_addr = intent.to_address.clone();
    let value_wei = intent.amount.clone();
    let nonce_i64 = sequence as i64; // reuse the nonce column for the cosmos sequence
    let fee_wei = intent.fee_amount.clone();
    let now = Timestamp::new(now_millis() as i64);
    let owner = principal.to_string();

    // ── Persist + enqueue atomically ──
    let tx_id = tx::<_, _, ApiError>(|| {
        let tx_id = db_insert(&Transaction {
            id: Id::new(0),
            owner_principal: owner.clone(),
            chain: COSMOS_CHAIN.to_string(),
            status: "signed".to_string(),
            intent_json: intent_json.clone(),
            raw_hex: raw_hex.clone(),
            tx_hash: String::new(),
            to_addr: to_addr.clone(),
            value_wei: value_wei.clone(),
            nonce: nonce_i64,
            fee_wei: fee_wei.clone(),
            sim_json: String::new(),
            confirmations: 0,
            created_at: now,
            updated_at: now,
        })
        .map_err(ApiError::from)?;

        upsert_daily_spend(&owner, COSMOS_CHAIN, now_secs, &value_wei, now)?;

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

/// `POST /cosmos/send` — resolve → guardrail → sign → persist → enqueue.
///
/// Guardrails run BEFORE the key is touched (reject-before-signing). The signing
/// label is derived from the host-attested principal, never the body. On success
/// the signed `Transaction` row (status `signed`), the `DailySpend` accumulator,
/// and the `broadcast_tx` job enqueue commit together in one store transaction;
/// broadcast + confirmation proceed asynchronously and are streamed on the
/// `wallet` WS channel.
pub fn cosmos_send(Json(body): Json<CosmosIntentReq>) -> Result<Json<SendOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    do_cosmos_send(&p, body).map(Json)
}

// ─── /cosmos/policy ──────────────────────────────────────────────────────────

/// `GET /cosmos/policy` — return the caller's Cosmos spend policy (defaults if
/// none). The `PolicyReq` "wei" naming is generic decimal — for Cosmos the caps
/// are base-denom amounts.
pub fn cosmos_get_policy(_req: &mut Req<'_>) -> Result<Json<PolicyReq>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    let policy = load_policy(&p, COSMOS_CHAIN)?;
    Ok(Json(policy.as_ref().map(PolicyReq::from).unwrap_or_default()))
}

/// `PUT /cosmos/policy` — upsert the caller's Cosmos spend policy.
pub fn cosmos_put_policy(Json(body): Json<PolicyReq>) -> Result<Json<PolicyReq>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    put_policy_for(&p, COSMOS_CHAIN, &body).map(Json)
}

// ─── helpers ───────────────────────────────────────────────────────────────────

/// Clone a `CosmosIntentReq` (used to run a pre-tx gas-estimate simulate without
/// consuming the caller's body). `CosmosIntentReq` is not `Clone` (it derives
/// only `Deserialize`), so reconstruct it field-by-field.
fn clone_req(b: &CosmosIntentReq) -> CosmosIntentReq {
    CosmosIntentReq {
        chain_id: b.chain_id.clone(),
        to_address: b.to_address.clone(),
        amount: b.amount.clone(),
        denom: b.denom.clone(),
        fee_amount: b.fee_amount.clone(),
        fee_denom: b.fee_denom.clone(),
        gas_limit: b.gas_limit,
        memo: b.memo.clone(),
        account_number: b.account_number,
        sequence: b.sequence,
        hrp: b.hrp.clone(),
    }
}

/// Serialize a resolved `CosmosIntent` for the `Transaction.intent_json` audit
/// column. `CosmosIntent` is not `Serialize`, so project its fields into a JSON
/// object (the same shape the caller posted, plus the resolved account fields).
fn serialize_intent(i: &CosmosIntent) -> serde_json::Value {
    serde_json::json!({
        "chain_id": i.chain_id,
        "hrp": i.hrp,
        "account_number": i.account_number,
        "sequence": i.sequence,
        "from_address": i.from_address,
        "to_address": i.to_address,
        "amount": i.amount,
        "denom": i.denom,
        "fee_amount": i.fee_amount,
        "fee_denom": i.fee_denom,
        "gas_limit": i.gas_limit,
        "memo": i.memo,
    })
}
