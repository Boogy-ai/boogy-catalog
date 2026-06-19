//! Background-job handler bodies for wallet-base.
//!
//! Two durable jobs drive the EVM send pipeline AFTER `POST /evm/send` has
//! signed the transaction and committed the `Transaction` row (status `signed`)
//! in the same store transaction that enqueued `broadcast_tx`:
//!
//! - `broadcast_tx` — submit the signed raw tx to the chain via
//!   `eth_sendRawTransaction`, flip the row to `pending` with its on-chain
//!   hash, and enqueue `poll_confirmation`.
//! - `poll_confirmation` — poll `eth_getTransactionReceipt`; re-enqueue itself
//!   (bounded) until the tx is mined, then flip the row to `confirmed`/`failed`.
//!
//! Both publish a `tx.status` envelope to the owner's `wallet` WS room AFTER
//! the store write (never inside a tx, where outbound side-effects are denied).
//!
//! ## Idempotency / re-delivery
//!
//! Jobs are at-least-once. Each handler reloads the `Transaction` and treats a
//! row already past its expected status as a no-op success — so a re-delivered
//! `broadcast_tx` won't double-submit, and a re-delivered `poll_confirmation`
//! won't re-publish a terminal outcome. The `broadcast_tx` enqueue of
//! `poll_confirmation` carries a per-tx idempotency key so a retried broadcast
//! collapses to one poller.
//!
//! ## Transient vs terminal
//!
//! A transient RPC failure returns [`JobError::Retry`] (the platform backs off
//! per the manifest `[background_jobs.handlers.*]` `max_attempts`/`backoff_ms`);
//! on the TERMINAL attempt (`ctx.attempts >= MAX_ATTEMPTS`) `broadcast_tx`
//! records `failed` and returns [`JobError::Terminal`]. The poller is naturally
//! bounded: after `POLL_MAX_ATTEMPTS` re-enqueues it stops and leaves the row
//! `pending` (a later manual poll / reconciliation resolves it) rather than
//! dead-lettering, since "not yet mined" is not a failure.

use boogy_sdk::jobs::JobSpec;
use boogy_sdk::model::Timestamp;
use boogy_sdk::{job, JobContext, JobError};
use serde_json::json;
use wallet_base_core::btc::rpc as btc_rpc;
use wallet_base_core::cosmos::rpc as cosmos_rpc;
use wallet_base_core::evm::rpc;
use wallet_base_core::solana::rpc as solana_rpc;

use crate::models::Transaction;
use crate::rpc_client::{
    call_btc_rpc_json, call_btc_rpc_text, call_cosmos_rpc, call_evm_rpc, call_solana_rpc,
};
use crate::{db_get, db_update, jobs_enqueue, now_millis, ws_publish_event, Deserialize};

/// Mirrors `boogy.toml` `[background_jobs.handlers.broadcast_tx] max_attempts`.
/// The job compares `ctx.attempts` against this to detect its terminal attempt
/// and flip the row to `failed` (vs an honest transient `Retry`).
const BROADCAST_MAX_ATTEMPTS: u32 = 8;

/// Cap on `poll_confirmation` self-re-enqueues. "Not yet mined" is not a
/// failure, so the poller bounds itself rather than dead-lettering: after this
/// many attempts it stops and leaves the row `pending`.
const POLL_MAX_ATTEMPTS: u32 = 8;

/// Delay (seconds) between confirmation polls.
const POLL_INTERVAL_SECS: u64 = 15;

/// Payload both jobs carry: just the `Transaction` row id. The row is the
/// source of truth (raw hex, hash, status), so the job is self-describing on
/// reload.
#[derive(Deserialize)]
pub struct TxJobPayload {
    pub tx_id: u64,
}

/// Best-effort: publish a `tx.status` envelope to the owner's `wallet` room.
/// NEVER fails the caller and is NEVER called inside a `tx`. A dropped publish
/// is reconciled by the client on reconnect / a `GET` poll.
fn publish_tx_status(t: &Transaction) {
    let data = json!({
        "tx_id": t.id.get(),
        "status": t.status,
        "tx_hash": t.tx_hash,
        "to": t.to_addr,
        "value_wei": t.value_wei,
        "nonce": t.nonce,
        "confirmations": t.confirmations,
    });
    let _ = ws_publish_event("wallet", &t.owner_principal, "tx.status", 1, data);
}

/// Durable broadcast of one signed EVM transaction.
///
/// Reloads the `Transaction`; if it is not `signed` (already broadcast / past
/// the broadcast step) this is an idempotent no-op success. Otherwise submits
/// `eth_sendRawTransaction(raw_hex)`:
/// - success → flip the row to `pending` with the returned tx hash, enqueue
///   `poll_confirmation` (delayed `POLL_INTERVAL_SECS`, per-tx idempotency key),
///   and publish `tx.status`.
/// - RPC failure → on the TERMINAL attempt (`ctx.attempts >= BROADCAST_MAX_ATTEMPTS`)
///   flip the row to `failed`, publish, and return [`JobError::Terminal`];
///   otherwise return [`JobError::Retry`] and let the platform back off.
#[job("broadcast_tx")]
pub fn broadcast_tx(ctx: JobContext, payload: TxJobPayload) -> Result<(), JobError> {
    let tx_id = payload.tx_id;

    let mut t = db_get::<Transaction>(tx_id)
        .map_err(|e| JobError::Retry(format!("reload tx {tx_id}: {e:?}")))?
        .ok_or_else(|| JobError::Terminal(format!("tx {tx_id} not found")))?;

    // Already broadcast / terminal — idempotent no-op (job re-delivery).
    if t.status != "signed" {
        return Ok(());
    }

    // Chain dispatch: the RPC call + result parse are chain-specific; the status
    // transition, the poller enqueue, and the WS publish are shared.
    match t.chain.as_str() {
        "evm" => evm_broadcast(&mut t, tx_id, &ctx),
        "cosmos" => cosmos_broadcast(&mut t, tx_id, &ctx),
        "solana" => solana_broadcast(&mut t, tx_id, &ctx),
        "btc" => btc_broadcast(&mut t, tx_id, &ctx),
        other => Err(JobError::Terminal(format!("unknown chain {other:?}"))),
    }
}

/// Enqueue the confirmation poller for `tx_id` (delayed `POLL_INTERVAL_SECS`).
/// Idempotency key collapses a retried broadcast (e.g. submit succeeded but the
/// status update failed once) to a single poller.
fn enqueue_poll(tx_id: u64) -> Result<(), JobError> {
    let not_before = now_millis() / 1000 + POLL_INTERVAL_SECS;
    let _ = jobs_enqueue(JobSpec {
        handler: "poll_confirmation".into(),
        payload: serde_json::to_vec(&json!({ "tx_id": tx_id }))
            .map_err(|e| JobError::Retry(format!("encode poll payload: {e}")))?,
        not_before_unix_s: Some(not_before),
        idempotency_key: Some(format!("poll:{tx_id}")),
        ..Default::default()
    });
    Ok(())
}

/// Mark `t` submitted: flip to `pending` with the on-chain hash, persist,
/// enqueue the poller, and publish `tx.status`. Shared broadcast tail.
fn mark_submitted(t: &mut Transaction, tx_id: u64, tx_hash: String) -> Result<(), JobError> {
    t.status = "pending".to_string();
    t.tx_hash = tx_hash;
    t.updated_at = Timestamp::new(now_millis() as i64);
    db_update(tx_id, t).map_err(|e| JobError::Retry(format!("update tx {tx_id}: {e:?}")))?;
    enqueue_poll(tx_id)?;
    publish_tx_status(t);
    Ok(())
}

/// EVM broadcast: `eth_sendRawTransaction(raw_hex)` → pending + poller.
fn evm_broadcast(t: &mut Transaction, tx_id: u64, ctx: &JobContext) -> Result<(), JobError> {
    let resp = match call_evm_rpc(&rpc::send_raw_transaction_request(&t.raw_hex)) {
        Ok(r) => r,
        Err(e) => return Err(broadcast_failure(t, tx_id, ctx, format!("{e:?}"))),
    };
    let tx_hash = match rpc::parse_send_result(&resp) {
        Ok(h) => h,
        Err(e) => return Err(broadcast_failure(t, tx_id, ctx, e.to_string())),
    };
    mark_submitted(t, tx_id, tx_hash)
}

/// Cosmos broadcast: decode the hex `TxRaw`, POST it via the LCD
/// `BROADCAST_MODE_SYNC` endpoint, and branch on the chain `code`:
/// - `code == 0` → accepted: flip to `pending` with the txhash + enqueue poller.
/// - `code != 0` → a terminal chain rejection (e.g. sequence mismatch,
///   insufficient funds): flip to `failed`, publish, return `Terminal`.
/// A transport error → transient `Retry` / terminal-on-last-attempt, same as EVM.
fn cosmos_broadcast(t: &mut Transaction, tx_id: u64, ctx: &JobContext) -> Result<(), JobError> {
    // independent-writes: the db_update calls below are mutually-exclusive
    // status writes to the SAME single Transaction row across error branches
    // (decode-fail / chain-reject / submitted) — exactly one runs per call, so
    // there are never two dependent writes to make atomic. Job re-delivery (not
    // a store tx) provides durability, mirroring the EVM broadcast path.
    // raw_hex is `0x`-prefixed hex of the TxRaw bytes.
    let hex_str = t.raw_hex.strip_prefix("0x").unwrap_or(&t.raw_hex);
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        // A malformed raw tx is permanent — this never broadcasts.
        Err(e) => {
            t.status = "failed".to_string();
            t.updated_at = Timestamp::new(now_millis() as i64);
            let _ = db_update(tx_id, t);
            publish_tx_status(t);
            return Err(JobError::Terminal(format!("decode raw tx: {e}")));
        }
    };

    let resp = match call_cosmos_rpc(&cosmos_rpc::broadcast_request(&bytes)) {
        Ok(r) => r,
        Err(e) => return Err(broadcast_failure(t, tx_id, ctx, format!("{e:?}"))),
    };
    let result = match cosmos_rpc::parse_broadcast(&resp) {
        Ok(r) => r,
        Err(e) => return Err(broadcast_failure(t, tx_id, ctx, e.to_string())),
    };

    if result.code == 0 {
        mark_submitted(t, tx_id, result.txhash)
    } else {
        // Nonzero code = a chain rejection (sequence mismatch, insufficient
        // funds, …). Terminal: retrying the same signed tx cannot succeed.
        t.status = "failed".to_string();
        t.updated_at = Timestamp::new(now_millis() as i64);
        let _ = db_update(tx_id, t);
        publish_tx_status(t);
        Err(JobError::Terminal(format!(
            "cosmos broadcast code {}: {}",
            result.code, result.raw_log
        )))
    }
}

/// Solana broadcast: decode the hex tx, POST it via `sendTransaction`, and parse
/// the base58 signature as the tx hash:
/// - Ok(sig) → accepted: flip to `pending` with the signature + enqueue poller.
/// - parse Err → a chain rejection (e.g. blockhash not found): transient
///   `Retry` / terminal-on-last-attempt (the same signed tx may succeed again
///   before its blockhash expires; a permanent reject dead-letters on attempts).
/// A transport error → transient `Retry` / terminal-on-last-attempt, same as EVM.
fn solana_broadcast(t: &mut Transaction, tx_id: u64, ctx: &JobContext) -> Result<(), JobError> {
    // independent-writes: the db_update calls below are mutually-exclusive
    // status writes to the SAME single Transaction row across error branches
    // (decode-fail / submitted / broadcast-failure) — exactly one runs per call,
    // so there are never two dependent writes to make atomic. Job re-delivery
    // (not a store tx) provides durability, mirroring the EVM/Cosmos paths.
    // raw_hex is `0x`-prefixed hex of the serialized signed transaction bytes.
    let hex_str = t.raw_hex.strip_prefix("0x").unwrap_or(&t.raw_hex);
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        // A malformed raw tx is permanent — this never broadcasts.
        Err(e) => {
            t.status = "failed".to_string();
            t.updated_at = Timestamp::new(now_millis() as i64);
            let _ = db_update(tx_id, t);
            publish_tx_status(t);
            return Err(JobError::Terminal(format!("decode raw tx: {e}")));
        }
    };

    let resp = match call_solana_rpc(&solana_rpc::send_transaction_request(&bytes)) {
        Ok(r) => r,
        Err(e) => return Err(broadcast_failure(t, tx_id, ctx, format!("{e:?}"))),
    };
    match solana_rpc::parse_send_result(&resp) {
        // The base58 signature IS the Solana tx hash.
        Ok(sig) => mark_submitted(t, tx_id, sig),
        Err(e) => {
            let msg = e.to_string();
            // A blockhash-expiry rejection can NEVER succeed on retry — the
            // blockhash is permanently outside the ~150-slot (~60-90s) window.
            // Terminate immediately with a distinct `expired` status so the client
            // re-issues /solana/send (fresh blockhash + re-sign), instead of
            // burning the whole retry budget then reporting a misleading generic
            // `failed` (#13). No funds move (an expired tx never executes).
            let low = msg.to_lowercase();
            if low.contains("blockhash not found") || low.contains("block height exceeded") {
                t.status = "expired".to_string();
                t.updated_at = Timestamp::new(now_millis() as i64);
                let _ = db_update(tx_id, t);
                publish_tx_status(t);
                return Err(JobError::Terminal(format!("solana blockhash expired: {msg}")));
            }
            Err(broadcast_failure(t, tx_id, ctx, msg))
        }
    }
}

/// Bitcoin broadcast: `POST /tx` with the raw consensus tx **hex** (Esplora's
/// wire format is the hex itself, NOT the decoded bytes) → the bare txid as
/// plain text.
/// - Ok(txid) → accepted: flip to `pending` with the txid + enqueue poller.
/// - parse Err (a non-txid plain-text body — Esplora's reject reason, e.g.
///   `sendrawtransaction RPC error: …`) → a chain rejection: transient
///   `Retry` / terminal-on-last-attempt (a mempool/fee transient may clear; a
///   permanent reject dead-letters on attempts).
/// A transport error → transient `Retry` / terminal-on-last-attempt, same as EVM.
/// A malformed local hex (the `0x` prefix strips to non-hex) is permanent →
/// `failed` (mirrors the Cosmos/Solana decode-fail terminal path).
fn btc_broadcast(t: &mut Transaction, tx_id: u64, ctx: &JobContext) -> Result<(), JobError> {
    // independent-writes: the db_update calls below are mutually-exclusive
    // status writes to the SAME single Transaction row across error branches
    // (decode-fail / chain-reject / submitted) — exactly one runs per call, so
    // there are never two dependent writes to make atomic. Job re-delivery (not
    // a store tx) provides durability, mirroring the EVM/Cosmos/Solana paths.
    // raw_hex is `0x`-prefixed hex of the consensus-serialized signed tx; Esplora
    // wants the bare hex (no `0x`), so strip the prefix.
    let hex_str = t.raw_hex.strip_prefix("0x").unwrap_or(&t.raw_hex);
    // Validate the local hex before broadcasting — a non-hex body is a permanent
    // local fault (this never broadcasts), distinct from a chain rejection.
    if hex_str.is_empty() || hex::decode(hex_str).is_err() {
        t.status = "failed".to_string();
        t.updated_at = Timestamp::new(now_millis() as i64);
        let _ = db_update(tx_id, t);
        publish_tx_status(t);
        return Err(JobError::Terminal("decode raw tx: not valid hex".to_string()));
    }

    let body = match call_btc_rpc_text(&btc_rpc::broadcast_request(hex_str)) {
        Ok(b) => b,
        Err(e) => return Err(broadcast_failure(t, tx_id, ctx, format!("{e:?}"))),
    };
    match btc_rpc::parse_broadcast_txid(&body) {
        // The 64-char hex txid IS the Bitcoin tx hash.
        Ok(txid) => mark_submitted(t, tx_id, txid),
        // A non-txid body is the chain's reject reason — transient/terminal.
        Err(e) => Err(broadcast_failure(t, tx_id, ctx, e.to_string())),
    }
}

/// Record a broadcast failure: transient → `Retry`; on the terminal attempt
/// flip the row to `failed`, publish, and return `Terminal`.
fn broadcast_failure(
    t: &mut Transaction,
    tx_id: u64,
    ctx: &JobContext,
    msg: String,
) -> JobError {
    if ctx.attempts >= BROADCAST_MAX_ATTEMPTS {
        t.status = "failed".to_string();
        t.updated_at = Timestamp::new(now_millis() as i64);
        // Best-effort: a transient store error here still surfaces as Terminal
        // (the platform is out of attempts anyway).
        let _ = db_update(tx_id, t);
        publish_tx_status(t);
        JobError::Terminal(msg)
    } else {
        JobError::Retry(msg)
    }
}

/// Durable confirmation poll of one broadcast EVM transaction.
///
/// Reloads the `Transaction`; if it is already `confirmed`/`failed` (or never
/// reached `pending`) this is an idempotent no-op. Otherwise polls
/// `eth_getTransactionReceipt(tx_hash)`:
/// - no receipt yet (`None`) → re-enqueue self after `POLL_INTERVAL_SECS`,
///   bounded by `POLL_MAX_ATTEMPTS`; once exhausted, stop and leave the row
///   `pending` (not a dead-letter — "not yet mined" is not a failure).
/// - receipt (`Some`) → flip the row to `confirmed`/`failed` per the on-chain
///   status, set `confirmations = 1`, and publish `tx.status`.
#[job("poll_confirmation")]
pub fn poll_confirmation(ctx: JobContext, payload: TxJobPayload) -> Result<(), JobError> {
    let tx_id = payload.tx_id;

    let mut t = db_get::<Transaction>(tx_id)
        .map_err(|e| JobError::Retry(format!("reload tx {tx_id}: {e:?}")))?
        .ok_or_else(|| JobError::Terminal(format!("tx {tx_id} not found")))?;

    // Already terminal — idempotent no-op (job re-delivery / belt-and-braces).
    if t.status == "confirmed" || t.status == "failed" {
        return Ok(());
    }
    // Never broadcast (no hash) — nothing to poll. Leave as-is (broadcast_tx
    // owns the transition out of `signed`).
    if t.tx_hash.is_empty() {
        return Ok(());
    }

    // Chain dispatch: the receipt fetch + parse differ; the not-yet-mined
    // re-enqueue and the terminal status transition are shared. A parsed receipt
    // yields `Some(success)`; not-yet-mined yields `None`.
    let outcome = match t.chain.as_str() {
        "evm" => evm_poll(&t),
        "cosmos" => cosmos_poll(&t),
        "solana" => solana_poll(&t),
        "btc" => btc_poll(&t),
        other => return Err(JobError::Terminal(format!("unknown chain {other:?}"))),
    }?;

    match outcome {
        None => {
            // Not yet mined. Re-enqueue ourselves, bounded by attempts. Once
            // exhausted, stop and leave the row `pending` (a later manual poll
            // resolves it). Returning Ok keeps this from dead-lettering.
            if ctx.attempts < POLL_MAX_ATTEMPTS {
                let not_before = now_millis() / 1000 + POLL_INTERVAL_SECS;
                let _ = jobs_enqueue(JobSpec {
                    handler: "poll_confirmation".into(),
                    payload: serde_json::to_vec(&json!({ "tx_id": tx_id }))
                        .map_err(|e| JobError::Retry(format!("encode poll payload: {e}")))?,
                    not_before_unix_s: Some(not_before),
                    // Distinct per attempt so each re-poll enqueues afresh.
                    idempotency_key: Some(format!("poll:{tx_id}:{}", ctx.attempts + 1)),
                    ..Default::default()
                });
            }
            Ok(())
        }
        Some(success) => {
            t.status = if success { "confirmed" } else { "failed" }.to_string();
            t.confirmations = 1;
            t.updated_at = Timestamp::new(now_millis() as i64);
            db_update(tx_id, &t)
                .map_err(|e| JobError::Retry(format!("update tx {tx_id}: {e:?}")))?;
            publish_tx_status(&t);
            Ok(())
        }
    }
}

/// EVM poll: `eth_getTransactionReceipt(tx_hash)` → `None` (unmined) /
/// `Some(success)`.
fn evm_poll(t: &Transaction) -> Result<Option<bool>, JobError> {
    let resp = call_evm_rpc(&rpc::receipt_request(&t.tx_hash))
        .map_err(|e| JobError::Retry(format!("receipt rpc: {e:?}")))?;
    Ok(rpc::parse_receipt(&resp)
        .map_err(|e| JobError::Retry(e.to_string()))?
        .map(|rcpt| rcpt.success))
}

/// Cosmos poll: `GET /cosmos/tx/v1beta1/txs/{hash}` → `None` (not yet indexed) /
/// `Some(success)`.
fn cosmos_poll(t: &Transaction) -> Result<Option<bool>, JobError> {
    let resp = call_cosmos_rpc(&cosmos_rpc::tx_status_request(&t.tx_hash))
        .map_err(|e| JobError::Retry(format!("tx status rpc: {e:?}")))?;
    Ok(cosmos_rpc::parse_tx_status(&resp)
        .map_err(|e| JobError::Retry(e.to_string()))?
        .map(|st| st.success))
}

/// Solana poll: `getSignatureStatuses(tx_hash)` → `None` (keep polling) /
/// `Some(success)`.
///
/// `None` means "not yet seen" OR "seen but not yet confirmed" — both keep the
/// poller going (re-enqueue, bounded). `Some` is terminal: confirmed-with-no-err
/// → `Some(true)` (confirmed), confirmed-with-err → `Some(false)` (failed).
fn solana_poll(t: &Transaction) -> Result<Option<bool>, JobError> {
    let resp = call_solana_rpc(&solana_rpc::signature_status_request(&t.tx_hash))
        .map_err(|e| JobError::Retry(format!("signature status rpc: {e:?}")))?;
    let status = solana_rpc::parse_signature_status(&resp)
        .map_err(|e| JobError::Retry(e.to_string()))?;
    Ok(match status {
        // Not yet seen by the cluster — keep polling.
        None => None,
        // Seen but not yet confirmed/finalized — keep polling.
        Some(st) if !st.confirmed => None,
        // Confirmed/finalized — terminal: failed iff the tx erred on-chain.
        Some(st) => Some(!st.err),
    })
}

/// Bitcoin poll: `GET /tx/{txid}/status` → `None` (keep polling) / `Some(true)`
/// (confirmed).
///
/// `parse_tx_status` returns `None` for a not-yet-seen txid (empty object) and
/// `Some(TxConfirmation{confirmed,..})` once Esplora knows it. A UTXO chain has
/// no on-chain "failed" state (an invalid tx is rejected at broadcast, never
/// mined), so this NEVER yields `Some(false)`: an unconfirmed (mempool) tx keeps
/// polling (`None`), and a confirmed tx is terminal-success (`Some(true)`).
fn btc_poll(t: &Transaction) -> Result<Option<bool>, JobError> {
    let resp = call_btc_rpc_json(&btc_rpc::tx_status_request(&t.tx_hash))
        .map_err(|e| JobError::Retry(format!("tx status rpc: {e:?}")))?;
    let status = btc_rpc::parse_tx_status(&resp)
        .map_err(|e| JobError::Retry(e.to_string()))?;
    Ok(match status {
        // Not yet seen by the indexer — keep polling.
        None => None,
        // Seen but still in the mempool (unmined) — keep polling.
        Some(st) if !st.confirmed => None,
        // Mined — terminal success (no on-chain failure state for a UTXO tx).
        Some(_) => Some(true),
    })
}
