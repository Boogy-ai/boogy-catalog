//! The `execute_proposal` job: run a passed proposal's encoded actions in `seq`
//! order, exactly as written (transparent + immutable). Each action is an in-mesh
//! peer call or an outbound call, BOUNDED by the host's manifest envelope
//! (`[outbound] allowed_hosts` + the peer capability). Per-action status +
//! attempts are tracked; partial failure stops at the failing action and is
//! operator-replayable.

use boogy_sdk::model::{Model, Timestamp};
use boogy_sdk::peer::PeerRequest;
use boogy_sdk::store::Val;
use govern_base_core::ProposalStatus;

use crate::bindings::boogy::platform::outbound_http;
use crate::models::{Proposal, ProposalAction};
use crate::{
    db_find_by, db_update, get_row, jobs_enqueue, now_ms, peer_fetch, tx, Deserialize, ApiError,
};
use boogy_sdk::jobs::JobSpec;
use boogy_sdk::{job, JobContext, JobError};

/// Result of atomically claiming a pending action for execution.
enum Claim {
    /// We set the action to `running` (proceed to execute).
    Won,
    /// Action was already `running` — a concurrent or crashed worker; do NOT re-fire.
    Busy,
    /// Action reached a terminal failure state.
    Failed,
    /// Action already completed (`done` or `skipped`).
    Done,
}

/// Atomically claim a `pending` action for execution by flipping it to `running`
/// inside a transaction. Returns `Won` if this worker won the claim, `Busy` if
/// another worker already holds it, or a terminal state if the action already
/// completed. Increments `attempts` on a successful claim so the counter reflects
/// actual execution attempts rather than job retries.
fn claim_running(action_id: u64) -> Result<Claim, ApiError> {
    tx::<_, _, ApiError>(|| {
        let row = get_row(ProposalAction::TABLE, action_id)?.ok_or_else(ApiError::not_found)?;
        let mut a = ProposalAction::from_row(&row);
        match a.exec_status.as_str() {
            "pending" => {
                a.exec_status = "running".to_string();
                a.attempts += 1;
                db_update::<ProposalAction>(action_id, &a)?;
                Ok(Claim::Won)
            }
            "running" => Ok(Claim::Busy),
            "failed" => Ok(Claim::Failed),
            _ => Ok(Claim::Done), // done | skipped
        }
    })
}

/// All actions for a proposal in `seq` order.
pub fn actions_for(proposal_id: u64) -> Result<Vec<ProposalAction>, ApiError> {
    let mut actions: Vec<ProposalAction> =
        db_find_by::<ProposalAction>(ProposalAction::PROPOSAL_ID, Val::Integer(proposal_id as i64))?;
    actions.sort_by_key(|a| a.seq);
    Ok(actions)
}

/// Flip a `timelock` proposal to `executing` and enqueue the durable execution
/// job (idempotency-keyed on the proposal). The status flip is one `tx`; the
/// enqueue follows the commit (job enqueue stays outside the local tx — the
/// proven independent-writes pattern). // independent-writes
pub fn enqueue_execution(proposal_id: u64) -> Result<(), ApiError> {
    let now = now_ms();
    let flipped = tx::<_, _, ApiError>(|| {
        let row = get_row(Proposal::TABLE, proposal_id)?.ok_or_else(ApiError::not_found)?;
        let mut p = Proposal::from_row(&row);
        if p.status != ProposalStatus::Timelock.as_str() {
            return Ok(false); // already advanced (idempotent)
        }
        p.status = ProposalStatus::Executing.as_str().to_string();
        p.updated_at = Timestamp::new(now);
        db_update::<Proposal>(proposal_id, &p)?;
        Ok(true)
    })?;
    if !flipped {
        return Ok(());
    }
    jobs_enqueue(JobSpec {
        handler: "execute_proposal".to_string(),
        payload: serde_json::to_vec(&serde_json::json!({ "proposal_id": proposal_id }))
            .map_err(|e| ApiError::internal(format!("encode exec payload: {e}")))?,
        idempotency_key: Some(format!("execute_proposal:{proposal_id}")),
        not_before_unix_s: None,
        max_attempts: None,
    })
    .map_err(|e| ApiError::internal(format!("enqueue execution: {e:?}")))?;
    Ok(())
}

#[derive(Deserialize)]
pub struct ExecPayload {
    pub proposal_id: u64,
}

/// Durable execution of one passed proposal's actions. Runs each `pending`
/// action in `seq` order; on success marks it `done`, on failure marks it
/// `failed`, records the detail, and STOPS (a later action must not run on a
/// failed predecessor). When all actions are `done` the proposal becomes
/// `executed`; a failing action leaves it `failed` for operator replay.
///
/// Idempotent: an action already `done` is skipped; re-delivery resumes at the
/// first non-`done` action.
#[job("execute_proposal")]
pub fn execute_proposal(_ctx: JobContext, payload: ExecPayload) -> Result<(), JobError> {
    let pid = payload.proposal_id;
    let actions = actions_for(pid).map_err(|e| JobError::Retry(format!("load actions: {e:?}")))?;

    for action in actions {
        match claim_running(action.id.get()).map_err(|e| JobError::Retry(format!("claim: {e:?}")))? {
            Claim::Done => continue,
            Claim::Busy => {
                // Another worker holds this action or it was interrupted mid-flight.
                // Do NOT double-fire; flag the proposal failed so the operator can
                // inspect and replay with reset=true if the side effect was safe.
                set_proposal_status(pid, ProposalStatus::Failed.as_str())
                    .map_err(|e| JobError::Retry(format!("flag busy: {e:?}")))?;
                return Err(JobError::Terminal(format!(
                    "action {} was in-flight (possible interrupted side effect); resolve via replay",
                    action.seq
                )));
            }
            Claim::Failed => {
                return Err(JobError::Terminal(format!(
                    "action {} previously failed",
                    action.seq
                )));
            }
            Claim::Won => {}
        }
        match run_action(&action) {
            Ok(d) => mark_action(action.id.get(), "done", &d)
                .map_err(|e| JobError::Retry(format!("{e:?}")))?,
            Err(d) => {
                mark_action(action.id.get(), "failed", &d)
                    .map_err(|e| JobError::Retry(format!("{e:?}")))?;
                set_proposal_status(pid, ProposalStatus::Failed.as_str())
                    .map_err(|e| JobError::Retry(format!("{e:?}")))?;
                return Err(JobError::Terminal(format!(
                    "action {} failed: {d}",
                    action.seq
                )));
            }
        }
    }

    set_proposal_status(pid, ProposalStatus::Executed.as_str())
        .map_err(|e| JobError::Retry(format!("set executed: {e:?}")))?;
    Ok(())
}

/// Run one encoded action verbatim. Returns `Ok(detail)` on a 2xx, `Err(detail)`
/// otherwise. The host enforces the allow-list / capability envelope.
fn run_action(a: &ProposalAction) -> Result<String, String> {
    let headers: Vec<(String, String)> = serde_json::from_str::<serde_json::Value>(&a.headers)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .map(|o| {
            o.into_iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let body = if a.body.is_empty() {
        None
    } else {
        Some(a.body.clone().into_bytes())
    };

    match a.action_type.as_str() {
        "http" => {
            let secret_headers = if a.secret_header_ref.is_empty() {
                Vec::new()
            } else {
                vec![("Authorization".to_string(), a.secret_header_ref.clone())]
            };
            let req = outbound_http::OutboundRequest {
                method: a.method.clone(),
                url: a.target.clone(),
                headers,
                body,
                timeout_ms: Some(10000),
                secret_headers,
            };
            let resp = outbound_http::fetch(&req).map_err(|e| format!("outbound: {e:?}"))?;
            if (200..300).contains(&resp.status) {
                Ok(format!("http {}", resp.status))
            } else {
                Err(format!("http {}", resp.status))
            }
        }
        "peer" => {
            // The peer surface is a top-level `peer_fetch(target, &PeerRequest)`
            // emitted by wit_glue!. PeerRequest has (method, path, headers, body)
            // — no `target` field. The target is the first argument to peer_fetch.
            let mut peer_req = PeerRequest::new(&a.method, "/");
            for (k, v) in headers {
                peer_req = peer_req.header(k, v);
            }
            if let Some(b) = body {
                peer_req = peer_req.body_bytes(b);
            }
            let resp = peer_fetch(&a.target, &peer_req)
                .map_err(|e| format!("peer: {e}"))?;
            if resp.is_success() {
                Ok(format!("peer {}", resp.status))
            } else {
                Err(format!("peer {}", resp.status))
            }
        }
        other => Err(format!("unknown action_type `{other}`")),
    }
}

/// Mark one action row's execution status + result. Does NOT increment `attempts`
/// because `claim_running` already did so when claiming `pending → running`.
fn mark_action(action_id: u64, status: &str, detail: &str) -> Result<(), ApiError> {
    tx::<_, _, ApiError>(|| {
        let row = get_row(ProposalAction::TABLE, action_id)?.ok_or_else(ApiError::not_found)?;
        let mut a = ProposalAction::from_row(&row);
        a.exec_status = status.to_string();
        a.exec_result = detail.to_string();
        db_update::<ProposalAction>(action_id, &a)?;
        Ok(())
    })
}

/// Set a proposal's status (+ fan-out) — used for the terminal exec outcomes.
fn set_proposal_status(pid: u64, status: &str) -> Result<(), ApiError> {
    tx::<_, _, ApiError>(|| {
        let row = get_row(Proposal::TABLE, pid)?.ok_or_else(ApiError::not_found)?;
        let mut p = Proposal::from_row(&row);
        p.status = status.to_string();
        p.updated_at = Timestamp::new(now_ms());
        db_update::<Proposal>(pid, &p)?;
        Ok(())
    })?;
    if let Ok(Some(row)) = get_row(Proposal::TABLE, pid) {
        crate::ws::publish_status(&Proposal::from_row(&row));
    }
    Ok(())
}

/// Re-drive execution for a `failed` proposal (operator replay only).
///
/// `reset_running`: when `true`, any action currently in `running` status is reset
/// to `pending` before re-enqueueing — the operator is accepting the double-fire
/// risk (use only after verifying the in-flight action did NOT commit its side
/// effect). When `false` (default), a `running` action blocks the replay with 409
/// so the operator must first verify and explicitly pass `reset=true`.
///
/// The stable idempotency key `execute_proposal:replay:{pid}` prevents concurrent
/// replays from enqueueing more than one job at a time.
pub fn replay(pid: u64, reset_running: bool) -> Result<(), ApiError> {
    let row = get_row(Proposal::TABLE, pid)?.ok_or_else(ApiError::not_found)?;
    let p = Proposal::from_row(&row);
    if p.status != ProposalStatus::Failed.as_str() {
        return Err(ApiError::conflict(
            "proposal is not in a replayable state (must be failed)",
        ));
    }

    // Check for any running actions before proceeding.
    let actions = actions_for(pid)?;
    let has_running = actions.iter().any(|a| a.exec_status == "running");
    if has_running && !reset_running {
        return Err(ApiError::conflict(
            "an action is still marked running — verify it did not commit its side effect, \
             then replay with reset=true to accept the double-fire risk",
        ));
    }

    // Reset running actions to pending so the job can re-claim them.
    if reset_running && has_running {
        for action in &actions {
            if action.exec_status == "running" {
                tx::<_, _, ApiError>(|| {
                    let row = get_row(ProposalAction::TABLE, action.id.get())?
                        .ok_or_else(ApiError::not_found)?;
                    let mut a = ProposalAction::from_row(&row);
                    a.exec_status = "pending".to_string();
                    db_update::<ProposalAction>(action.id.get(), &a)?;
                    Ok(())
                })?;
            }
        }
    }

    // Flip the proposal back to executing so lifecycle + status reads are consistent.
    tx::<_, _, ApiError>(|| {
        let row = get_row(Proposal::TABLE, pid)?.ok_or_else(ApiError::not_found)?;
        let mut p = Proposal::from_row(&row);
        p.status = ProposalStatus::Executing.as_str().to_string();
        p.updated_at = Timestamp::new(now_ms());
        db_update::<Proposal>(pid, &p)?;
        Ok(())
    })?;

    jobs_enqueue(JobSpec {
        handler: "execute_proposal".to_string(),
        payload: serde_json::to_vec(&serde_json::json!({ "proposal_id": pid }))
            .map_err(|e| ApiError::internal(format!("encode: {e}")))?,
        // Stable key prevents concurrent replays.
        idempotency_key: Some(format!("execute_proposal:replay:{pid}")),
        not_before_unix_s: None,
        max_attempts: None,
    })
    .map(|_| ())
    .map_err(|e| ApiError::internal(format!("enqueue replay: {e:?}")))
}
