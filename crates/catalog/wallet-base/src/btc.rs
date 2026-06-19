//! Bitcoin (`/btc/*`) service handlers.
//!
//! **Trust model: CUSTODIAL.** The host holds the signing key (via the `signing`
//! capability) and signs on the user's behalf; this wasm never holds private key
//! material. "host-signed" here means the key is external to the *wasm* — NOT
//! that the end user signs. The threat surface is the full custodial one: a bug
//! here moves user funds, so every `/send` AND `/sign` path gates identically.
//!
//! Mirrors the EVM/Cosmos/Solana surface (`sign` / `fees` / `send` / `policy`)
//! but over a UTXO chain via `wallet_base_core::btc::BtcAdapter` and the Esplora
//! REST client (`rpc_client::call_btc_rpc_{json,text}`). Bitcoin is the first
//! UTXO chain, which shapes these handlers differently from the account-based
//! chains:
//!
//!  - There is **no simulate** (`/btc/simulate`): a UTXO transaction has no
//!    on-chain VM to dry-run; validity is checked by the network at broadcast.
//!  - A transfer spends **N inputs**, so `build_unsigned` emits N BIP143
//!    sighashes (one per input, in input order) and the send path signs EACH —
//!    `signing_sign_digest(label, digest, EcdsaSecp256k1)` per input, collected
//!    in order — then `assemble_signed` splices the N signatures into the
//!    witnesses.
//!  - The UTXO set is **fetched** on the send path (never from the body); the
//!    sign-only path takes explicit UTXOs in the body for surface parity.
//!
//! P2WPKH signs **ECDSA secp256k1 over the BIP143 sighash** — the SAME signing
//! seam EVM uses (the key is secp256k1; only the address encoding + tx format
//! differ). The recovery id is unused for P2WPKH (the pubkey rides in the
//! witness) but `secp_sig_from_compact` requires it present, so we pass it
//! through.
//!
//! Security invariants (identical to the other chains):
//!
//! - The signing-key LABEL is derived from the host-attested principal via
//!   `wallet_label_checked(current_principal(), "btc")`, NEVER from the body —
//!   the sign-as-anyone guard.
//! - Guardrails (`guardrails::check_policy`) run BEFORE the key is touched
//!   (reject-before-signing); ambiguous/unparseable amounts REJECT (fail-closed).
//! - A blocked principal cannot sign or send.
//! - `from_pubkey_hex` (compressed) + `network` come from the caller's stored
//!   `Wallet` row, never the body; the UTXOs are fetched on-chain on the send
//!   path (outside the store `tx` — `outbound_http` is denied inside a `tx`).

use boogy_sdk::jobs::JobSpec;
use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::signing::SigAlg;
use serde::{Deserialize, Serialize};
use wallet_base_core::btc::rpc::{
    fee_estimates_request, list_utxos_request, parse_fee_estimate, parse_utxos,
};
use wallet_base_core::btc::{BtcAdapter, BtcIntent, Utxo};
use wallet_base_core::types::{Secp256k1Signature, SignRequest};

use crate::models::{Transaction, Wallet};
use crate::rpc_client::call_btc_rpc_json;
use crate::{
    auth, db_insert, enforce_spend_policy, is_blocked, jobs_enqueue, load_policy, now_millis,
    put_policy_for, record_external_sign, signing_sign_digest, tx, upsert_daily_spend, ApiError,
    Json, PolicyReq, Query, Req, SendOut, SignOut, Spend, BTC_CHAIN, BTC_NETWORK,
};

/// Default confirmation target (blocks) for the send-path fee estimate when the
/// caller doesn't pass `fee_rate_sat_vb`. 6 blocks ≈ 1 hour — a conservative,
/// likely-to-confirm rate.
const SEND_FEE_TARGET_BLOCKS: u32 = 6;

// ─── DTOs ──────────────────────────────────────────────────────────────────────

/// Request body for `POST /btc/send`. Only chain-public fields are caller-
/// supplied; `from_pubkey_hex` (compressed) + `network` come from the caller's
/// stored wallet row (never the body), and the UTXO set is FETCHED on-chain
/// (never from the body). `fee_rate_sat_vb` is fetched from `/fee-estimates`
/// when absent.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct BtcSendReq {
    /// Destination bech32 address (`bc1q…` / `tb1q…`), validated for this
    /// deployment's network at build time.
    pub to_address: String,
    /// Transfer amount in satoshis.
    pub amount_sat: u64,
    /// Fee rate in sat/vB. Fetched from `/fee-estimates` (6-block target) when
    /// absent.
    pub fee_rate_sat_vb: Option<u64>,
}

/// Request body for `POST /btc/sign` (sign-only). Unlike `/btc/send`, the UTXO
/// set and the fee rate are caller-supplied (there is no on-chain fetch and no
/// simulate on this path); everything else is read from the stored wallet, as
/// on the send path. No broadcast, no persistence.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct BtcSignReq {
    /// Destination bech32 address.
    pub to_address: String,
    /// Transfer amount in satoshis.
    pub amount_sat: u64,
    /// Fee rate in sat/vB. Required (no on-chain estimate on the sign path).
    pub fee_rate_sat_vb: u64,
    /// The sender's spendable UTXOs (all on the sender's own P2WPKH). Required
    /// (no on-chain fetch on the sign path).
    pub utxos: Vec<UtxoReq>,
}

/// A caller-supplied UTXO for the sign-only path. Mirrors the core `Utxo`; it
/// exists so the OpenAPI spec gets a `JsonSchema` without `wallet-base-core`
/// taking a `schemars` dependency.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct UtxoReq {
    /// The funding transaction id (hex).
    pub txid: String,
    /// The output index within that transaction.
    pub vout: u32,
    /// The prevout value in satoshis (load-bearing for the BIP143 sighash).
    pub value_sat: u64,
}

impl From<UtxoReq> for Utxo {
    fn from(u: UtxoReq) -> Self {
        Utxo { txid: u.txid, vout: u.vout, value_sat: u.value_sat }
    }
}

/// Result of `POST /btc/fees`: sat/vB fee-rate estimates at two confirmation
/// targets. The caller multiplies by the transaction's virtual size.
#[derive(Serialize, schemars::JsonSchema)]
pub struct BtcFeesOut {
    /// sat/vB for a fast (next-block, target 1) confirmation.
    pub sat_per_vb_fast: u64,
    /// sat/vB for a normal (6-block) confirmation.
    pub sat_per_vb_normal: u64,
}

// ─── Wallet lookup ───────────────────────────────────────────────────────────

/// Load the caller's Bitcoin `Wallet` row (the local key cache). A missing row →
/// the key was never created for this principal. The stored `pubkey_hex` is the
/// 33-byte COMPRESSED secp256k1 key and `address` its P2WPKH — both derived from
/// the same compressed key at wallet creation.
fn require_wallet(principal: &str) -> Result<Wallet, ApiError> {
    let row = Query::on(Wallet::TABLE)
        .where_eq(Wallet::OWNER_PRINCIPAL, principal)
        .where_eq(Wallet::CHAIN, BTC_CHAIN)
        .fetch_one()?
        .ok_or_else(|| ApiError::bad_request("no btc wallet; create one first"))?;
    Ok(Wallet::from_row(&row))
}

/// Sign every BIP143 sighash of `unsigned` with the host-held key under `label`
/// (one secp256k1 signature per input, in input order) and assemble the
/// broadcast-ready raw tx. The key is touched ONLY here, after the caller has
/// already cleared guardrails.
fn sign_and_assemble(
    label: &str,
    unsigned: &wallet_base_core::types::Unsigned,
) -> Result<String, ApiError> {
    let mut sigs: Vec<Secp256k1Signature> = Vec::with_capacity(unsigned.sign_requests.len());
    for sr in &unsigned.sign_requests {
        let digest = match sr {
            SignRequest::Digest(d) => d,
            SignRequest::Message(_) => {
                return Err(ApiError::internal(
                    "btc adapter produced a non-digest sign request",
                ))
            }
        };
        // P2WPKH signs ECDSA secp256k1 over the per-input BIP143 sighash — the
        // same seam EVM uses. The recovery id is unused for P2WPKH (the pubkey
        // rides in the witness) but `secp_sig_from_compact` requires it present.
        let sdk_sig = signing_sign_digest(label, digest, SigAlg::EcdsaSecp256k1)
            .map_err(|e| ApiError::internal(format!("sign digest: {e}")))?;
        let sig = wallet_base_core::secp_sig_from_compact(&sdk_sig.bytes, sdk_sig.recovery_id)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        sigs.push(sig);
    }
    let raw = BtcAdapter::assemble_signed(unsigned, &sigs)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(raw.to_hex())
}

// ─── /btc/sign ──────────────────────────────────────────────────────────────

/// `POST /btc/sign` — sign a fully-specified Bitcoin transfer (sign-only).
///
/// The UTXO set + fee rate are REQUIRED in the body (no on-chain fetch); the
/// compressed pubkey + network come from the caller's stored wallet row. The
/// signing label is host-derived. Gated identically to `/btc/send` (block-list +
/// spend policy + mandatory daily-spend debit; #1) — the returned raw tx is a
/// complete, self-broadcastable spend of the custodial key. No broadcast.
pub fn btc_sign(Json(body): Json<BtcSignReq>) -> Result<Json<SignOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;

    // A blocked principal cannot sign.
    if is_blocked(&p)? {
        return Err(ApiError::forbidden("this account is blocked"));
    }

    // Label is host-derived; this also validates "btc" as a known chain.
    let label = wallet_base_core::subject::wallet_label_checked(&p, BTC_CHAIN)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let wallet = require_wallet(&p)?;

    let intent = BtcIntent {
        from_pubkey_hex: wallet.pubkey_hex,
        network: BTC_NETWORK,
        to_address: body.to_address,
        amount_sat: body.amount_sat,
        // Floor at 1 sat/vB (#12): a 0 fee-rate signs an unrelayable zero-fee tx.
        fee_rate_sat_vb: body.fee_rate_sat_vb.max(1),
        utxos: body.utxos.into_iter().map(Utxo::from).collect(),
    };

    // ── Resolve the selected fee (#2 BTC fee bound) ──
    // Same pure, deterministic selection `build_unsigned` re-runs below, so the
    // fee enforced is exactly the fee of the tx that gets signed.
    let fee_sat = wallet_base_core::btc::select_coins(
        &intent.utxos,
        intent.amount_sat,
        intent.fee_rate_sat_vb,
    )
    .map_err(|e| ApiError::bad_request(e.to_string()))?
    .fee_sat
    .to_string();

    // ── Guardrails BEFORE the key is touched (#1). Fee bounded + counted (#2).
    enforce_spend_policy(
        &p,
        BTC_CHAIN,
        &Spend {
            value: intent.amount_sat.to_string(),
            fee: fee_sat.clone(),
            denom: "sat".to_string(),
            recipient: intent.to_address.clone(),
            sim_success: true,
        },
    )?;

    // Coin selection + the N BIP143 sighashes happen inside build_unsigned; a
    // bad intent (insufficient funds, wrong-network destination) is a 400.
    let unsigned = BtcAdapter::build_unsigned(&intent)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let raw = sign_and_assemble(&label, &unsigned)?;

    // Record the signed tx + debit daily-spend (value + fee; no broadcast job).
    let intent_json = serde_json::to_string(&serialize_intent(&intent))
        .map_err(|e| ApiError::internal(format!("encode intent: {e}")))?;
    record_external_sign(
        &p,
        BTC_CHAIN,
        "sat",
        &intent.to_address,
        &intent.amount_sat.to_string(),
        0,
        &fee_sat,
        &raw,
        &intent_json,
    )?;

    Ok(Json(SignOut { raw }))
}

// ─── /btc/fees ────────────────────────────────────────────────────────────────

/// `POST /btc/fees` — fetch the current sat/vB fee-rate estimates.
///
/// Bitcoin fees are a sat/vB rate (multiplied by the transaction's virtual
/// size), estimated per confirmation target. This reads `/fee-estimates` once
/// and returns the fast (target 1) and normal (target 6) rates; the caller picks
/// one and multiplies by the tx vsize. The signing key is not touched. Takes no
/// body, but is mounted as POST for surface parity with the other chains' fee
/// endpoints.
pub fn btc_fees(_req: &mut Req<'_>) -> Result<Json<BtcFeesOut>, ApiError> {
    let resp = call_btc_rpc_json(&fee_estimates_request())?;
    let fast = parse_fee_estimate(&resp, 1)
        .map_err(|e| ApiError::service_unavailable(e.to_string()))?;
    let normal = parse_fee_estimate(&resp, SEND_FEE_TARGET_BLOCKS)
        .map_err(|e| ApiError::service_unavailable(e.to_string()))?;
    Ok(Json(BtcFeesOut { sat_per_vb_fast: fast, sat_per_vb_normal: normal }))
}

// ─── /btc/send ──────────────────────────────────────────────────────────────

/// Core of `POST /btc/send`: the full fetch → guardrail → sign → persist →
/// enqueue pipeline for Bitcoin. Mirrors `do_send` (EVM) / `do_cosmos_send` on
/// the security path.
///
/// Guardrails run BEFORE the key is touched. The signing label is derived from
/// the principal, never the body. The UTXO set + the fee rate are fetched
/// on-chain (outside the `tx`, since `outbound_http` is denied inside a store
/// `tx`). On success the `Transaction` row (status `signed`), the `DailySpend`
/// accumulator, and the `broadcast_tx` job enqueue commit together in one store
/// transaction.
pub fn do_btc_send(principal: &str, body: BtcSendReq) -> Result<SendOut, ApiError> {
    // A blocked principal cannot sign or send.
    if is_blocked(principal)? {
        return Err(ApiError::forbidden("this account is blocked"));
    }

    // Label is host-derived; also validates "btc" as a known chain.
    let label = wallet_base_core::subject::wallet_label_checked(principal, BTC_CHAIN)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let wallet = require_wallet(principal)?;

    // ── Fetch the spendable UTXOs (pre-tx) ──
    // outbound_http is DENIED inside a store `tx`, so do this before the tx.
    // Use only CONFIRMED UTXOs — spending an unconfirmed input risks a tx that
    // can't enter a block until its parent confirms (and is droppable on a
    // reorg). A wallet with no confirmed UTXOs has nothing to spend → 400 via
    // coin selection below.
    let utxo_resp = call_btc_rpc_json(&list_utxos_request(&wallet.address))?;
    let utxos: Vec<Utxo> = parse_utxos(&utxo_resp)
        .map_err(|e| ApiError::service_unavailable(e.to_string()))?
        .into_iter()
        .filter(|e| e.confirmed)
        .map(|e| e.utxo)
        .collect();

    // ── Resolve fee rate: body wins, else fetch the 6-block estimate (pre-tx) ──
    // Floor at 1 sat/vB (#12): a 0 fee-rate yields a zero-fee tx the network
    // rejects ("min relay fee not met") after a wasted key-touch.
    let fee_rate_sat_vb = match body.fee_rate_sat_vb {
        Some(r) => r.max(1),
        None => {
            let resp = call_btc_rpc_json(&fee_estimates_request())?;
            parse_fee_estimate(&resp, SEND_FEE_TARGET_BLOCKS)
                .map_err(|e| ApiError::service_unavailable(e.to_string()))?
        }
    };

    let intent = BtcIntent {
        from_pubkey_hex: wallet.pubkey_hex,
        network: BTC_NETWORK,
        to_address: body.to_address,
        amount_sat: body.amount_sat,
        fee_rate_sat_vb,
        utxos,
    };

    // ── Resolve the selected fee (#2 BTC fee bound) ──
    // Coin-select here to surface the fee this transfer pays, so the per-tx fee
    // cap AND the total-outflow (value + fee) daily cap apply to BTC like the
    // other chains. `select_coins` is pure + deterministic and is the SAME
    // selection `build_unsigned` re-runs internally below, so the fee enforced is
    // exactly the fee of the tx that gets signed. A selection failure (no/dust
    // UTXOs, insufficient funds) is a caller error → 400.
    let fee_sat = wallet_base_core::btc::select_coins(
        &intent.utxos,
        intent.amount_sat,
        intent.fee_rate_sat_vb,
    )
    .map_err(|e| ApiError::bad_request(e.to_string()))?
    .fee_sat
    .to_string();

    // ── Guardrails — BEFORE signing (single enforcement point) ──
    // value = the transfer amount in satoshis; recipient = the bech32 to_address
    // (canonical lowercase already — do NOT re-case it). A Bitcoin transfer
    // carries no contract calldata. No simulate on a UTXO chain, so
    // sim_success = true. `fee` = the coin-selected fee (above), bounded by the
    // policy's per-tx fee cap and counted toward the daily cap.
    let now_secs = now_millis() as i64 / 1000;
    enforce_spend_policy(
        principal,
        BTC_CHAIN,
        &Spend {
            value: intent.amount_sat.to_string(),
            fee: fee_sat.clone(),
            denom: "sat".to_string(),
            recipient: intent.to_address.clone(),
            sim_success: true,
        },
    )?;

    // ── Build the unsigned tx (coin-select + N sighashes happen inside) ──
    // A coin-select failure (insufficient funds, dust, wrong-network address) is
    // a caller error → 400.
    let unsigned = BtcAdapter::build_unsigned(&intent)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    // ── Sign each input (key is touched only after guardrails pass) ──
    let raw_hex = sign_and_assemble(&label, &unsigned)?;

    // Snapshot values needed for persistence.
    let intent_json = serde_json::to_string(&serialize_intent(&intent))
        .map_err(|e| ApiError::internal(format!("encode intent: {e}")))?;
    let to_addr = intent.to_address.clone();
    let value_sat = intent.amount_sat.to_string();
    let now = Timestamp::new(now_millis() as i64);
    let owner = principal.to_string();

    // ── Persist + enqueue atomically ──
    let tx_id = tx::<_, _, ApiError>(|| {
        let tx_id = db_insert(&Transaction {
            id: Id::new(0),
            owner_principal: owner.clone(),
            chain: BTC_CHAIN.to_string(),
            status: "signed".to_string(),
            intent_json: intent_json.clone(),
            raw_hex: raw_hex.clone(),
            tx_hash: String::new(),
            to_addr: to_addr.clone(),
            value_wei: value_sat.clone(),
            // Bitcoin has no per-account nonce/sequence (UTXO chain). The nonce
            // column is unused here; 0 is a placeholder.
            nonce: 0,
            // The coin-selected fee (sat) — same fee enforced by the guardrail.
            fee_wei: fee_sat.clone(),
            sim_json: String::new(),
            confirmations: 0,
            created_at: now,
            updated_at: now,
        })
        .map_err(ApiError::from)?;

        // Debit value + fee (total outflow) against the daily cap, consistent
        // with the guardrail that just allowed it.
        upsert_daily_spend(&owner, BTC_CHAIN, "sat", now_secs, &value_sat, &fee_sat, now)?;

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

/// `POST /btc/send` — fetch → guardrail → sign → persist → enqueue.
///
/// Guardrails run BEFORE the key is touched (reject-before-signing). The signing
/// label is derived from the host-attested principal, never the body. The UTXO
/// set + fee rate are fetched on-chain. On success the signed `Transaction` row
/// (status `signed`), the `DailySpend` accumulator, and the `broadcast_tx` job
/// enqueue commit together in one store transaction; broadcast + confirmation
/// proceed asynchronously and are streamed on the `wallet` WS channel.
pub fn btc_send(Json(body): Json<BtcSendReq>) -> Result<Json<SendOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    do_btc_send(&p, body).map(Json)
}

// ─── /btc/policy ──────────────────────────────────────────────────────────────

/// `GET /btc/policy` — return the caller's Bitcoin spend policy (defaults if
/// none). The `PolicyReq` "wei" naming is generic decimal — for Bitcoin the caps
/// are satoshi amounts.
pub fn btc_get_policy(_req: &mut Req<'_>) -> Result<Json<PolicyReq>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    let policy = load_policy(&p, BTC_CHAIN)?;
    Ok(Json(policy.as_ref().map(PolicyReq::from).unwrap_or_default()))
}

/// `PUT /btc/policy` — upsert the caller's Bitcoin spend policy.
pub fn btc_put_policy(Json(body): Json<PolicyReq>) -> Result<Json<PolicyReq>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    put_policy_for(&p, BTC_CHAIN, &body).map(Json)
}

// ─── helpers ───────────────────────────────────────────────────────────────────

/// Serialize a resolved `BtcIntent` for the `Transaction.intent_json` audit
/// column. `BtcIntent` is not `Serialize`, so project its fields into a JSON
/// object (the resolved fee rate + the selected UTXO set, mirroring the Cosmos
/// approach). `Utxo` IS `Serialize`, so the UTXO list serializes directly.
fn serialize_intent(i: &BtcIntent) -> serde_json::Value {
    serde_json::json!({
        "from_pubkey_hex": i.from_pubkey_hex,
        "network": format!("{:?}", i.network),
        "to_address": i.to_address,
        "amount_sat": i.amount_sat,
        "fee_rate_sat_vb": i.fee_rate_sat_vb,
        "utxos": i.utxos,
    })
}
