//! Time-based status advancement + the lifecycle_tick sweep job.
//!
//! A proposal advances when a window elapses: `voting` → tally at `voting_end`;
//! a passed proposal → `timelock` then (at `timelock_end`) enqueues
//! `execute_proposal`. We advance both lazily (on read via `touch`) AND on a
//! periodic `lifecycle_tick` sweep, so a tally is never stale when observed.

use boogy_sdk::model::{Model, Timestamp};
use boogy_sdk::store::SortDir;
use govern_base_core::{decide, Electorate, Outcome, ProposalStatus, TallyParams};

use crate::admin::frac;
use crate::models::Proposal;
use crate::voting::aggregate;
use crate::{db_update, get_row, now_ms, tx, ApiError};

/// Lazily advance one proposal's time-based status on read. Best-effort:
/// failures are swallowed (the sweep is the durable backstop).
pub fn touch(id: u64) {
    let _ = advance(id);
}

/// Advance a single proposal if a window has elapsed. Idempotent. Returns the new
/// status string when it changed, else None.
pub fn advance(id: u64) -> Result<Option<String>, ApiError> {
    let now = now_ms();
    let row = match get_row(Proposal::TABLE, id)? {
        Some(r) => r,
        None => return Ok(None),
    };
    let p = Proposal::from_row(&row);

    // voting → tally
    if p.status == ProposalStatus::Voting.as_str() && now >= p.voting_end && p.voting_end > 0 {
        return finalize_vote(id).map(Some);
    }
    // timelock → enqueue execution (handled by execution module)
    if p.status == ProposalStatus::Timelock.as_str() && now >= p.timelock_end && p.timelock_end > 0
    {
        crate::execution::enqueue_execution(id)?;
        return Ok(Some(ProposalStatus::Executing.as_str().to_string()));
    }
    Ok(None)
}

/// Tally a closed vote and write the terminal/intermediate status + final tally
/// in one `tx`. A `Passed` proposal WITH actions enters `timelock`; without
/// actions it is `executed` immediately (signal-only); `Rejected`/`Vetoed` are
/// terminal.
fn finalize_vote(id: u64) -> Result<String, ApiError> {
    let t = aggregate(id)?;
    let cfg_now = now_ms();

    let new_status = tx::<_, _, ApiError>(|| {
        let row = get_row(Proposal::TABLE, id)?.ok_or_else(ApiError::not_found)?;
        let mut p = Proposal::from_row(&row);
        if p.status != ProposalStatus::Voting.as_str() {
            return Ok(p.status.clone()); // already advanced (idempotent)
        }
        let params = TallyParams {
            quorum: frac(&p.quorum),
            threshold: frac(&p.threshold),
            veto_threshold: frac(&p.veto_threshold),
        };
        let electorate = if p.eligibility == "open" {
            Electorate::Open
        } else {
            Electorate::Bounded { total_power: p.total_eligible_power }
        };
        let outcome = decide(&t, &params, &electorate, p.min_participation);

        p.final_yes = t.yes;
        p.final_no = t.no;
        p.final_abstain = t.abstain;
        p.final_veto = t.veto;
        p.final_ballots = t.ballots;

        let has_actions = !crate::execution::actions_for(id)?.is_empty();
        p.status = match outcome {
            Outcome::Vetoed => ProposalStatus::Vetoed.as_str().to_string(),
            Outcome::Rejected => ProposalStatus::Rejected.as_str().to_string(),
            Outcome::Passed if has_actions => {
                p.timelock_end = cfg_now + crate::admin::load_config().timelock_ms;
                ProposalStatus::Timelock.as_str().to_string()
            }
            Outcome::Passed => ProposalStatus::Executed.as_str().to_string(),
        };
        p.updated_at = Timestamp::new(cfg_now);
        db_update::<Proposal>(id, &p)?;
        Ok(p.status.clone())
    })?;

    // Best-effort fan-out after commit.
    if let Ok(Some(row)) = get_row(Proposal::TABLE, id) {
        let p = Proposal::from_row(&row);
        crate::ws::publish_tally(&p);
        crate::ws::publish_status(&p);
    }
    Ok(new_status)
}

/// Sweep all proposals in time-sensitive states and advance any that are due.
/// Bounded full scan over the two active-state lists; acceptable at catalog
/// scale (a high-volume deployment would precompute a due-index).
pub fn sweep() -> Result<(), ApiError> {
    for state in [ProposalStatus::Voting, ProposalStatus::Timelock] {
        let rows = crate::Query::on(Proposal::TABLE)
            .where_eq(Proposal::STATUS, state.as_str())
            .keyset_by(Proposal::CREATED_AT, SortDir::Asc)
            .limit(200)
            .fetch_all()?;
        for r in rows {
            let p = Proposal::from_row(&r);
            let _ = advance(p.id.get());
        }
    }
    Ok(())
}

use boogy_sdk::{job, JobError};

/// Periodic sweep (manifest `schedule`) advancing due proposals. Returns
/// `Err(Retry)` on a transient store failure so the platform retries.
#[job("lifecycle_tick")]
pub fn lifecycle_tick() -> Result<(), JobError> {
    sweep().map_err(|e| JobError::Retry(format!("lifecycle sweep: {e:?}")))
}
