//! Vote casting + tally endpoint.

use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::store::Val;
use govern_base_core::{tally_votes, Tally, VoteOption};

use crate::models::{Proposal, Vote};
use crate::{
    db_find_by, db_insert, get_row, now_ms, require_voter, tx, Deserialize, Json, Req,
    Serialize, ApiError,
};

/// `POST /proposals/{id}/vote` body.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct VoteReq {
    /// `yes` | `no` | `abstain` | `veto`.
    pub option: String,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct VoteAck {
    pub proposal_id: u64,
    pub option: String,
}

/// Aggregate all ballots for a proposal into a [`Tally`] (1p1v: weight 1).
pub fn aggregate(proposal_id: u64) -> Result<Tally, ApiError> {
    let votes: Vec<Vote> =
        db_find_by::<Vote>(Vote::PROPOSAL_ID, Val::Integer(proposal_id as i64))?;
    let pairs: Vec<(VoteOption, i64)> = votes
        .iter()
        .filter_map(|v| VoteOption::from_str(&v.option).map(|o| (o, v.weight)))
        .collect();
    Ok(tally_votes(&pairs))
}

/// Cast a ballot. Phase 1 is single-cast: a second ballot from the same voter is
/// a 409 (Phase 2 makes this an UPSERT for re-votable ballots). The insert is one
/// `tx` so a failed dedupe check rolls back cleanly.
pub fn cast_vote(req: &mut Req<'_>) -> Result<Json<VoteAck>, ApiError> {
    let voter = require_voter()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let body: VoteReq = boogy_sdk::error::parse_body(req.body())?;
    let option = VoteOption::from_str(&body.option)
        .ok_or_else(|| ApiError::bad_request("option must be yes|no|abstain|veto"))?;
    let owner = crate::self_identity().owner;
    let now = now_ms();

    tx::<_, _, ApiError>(|| {
        let row = get_row(Proposal::TABLE, id)?.ok_or_else(ApiError::not_found)?;
        let p = Proposal::from_row(&row);
        if p.status != govern_base_core::ProposalStatus::Voting.as_str() {
            return Err(ApiError::conflict("proposal is not open for voting"));
        }
        if now >= p.voting_end {
            return Err(ApiError::conflict("voting has closed"));
        }
        let existing: Vec<Vote> =
            db_find_by::<Vote>(Vote::PROPOSAL_ID, Val::Integer(id as i64))?;
        if existing.iter().any(|v| v.voter == voter) {
            return Err(ApiError::conflict("already voted"));
        }
        db_insert(&Vote {
            id: Id::new(0),
            owner_principal: owner.clone(),
            proposal_id: id as i64,
            voter: voter.clone(),
            option: option.as_str().to_string(),
            weight: 1,
            cast_at: Timestamp::new(now),
            updated_at: Timestamp::new(now),
        })?;
        Ok(())
    })?;

    // Best-effort live update AFTER commit (never inside the tx).
    if let Ok(Some(row)) = get_row(Proposal::TABLE, id) {
        let mut p = Proposal::from_row(&row);
        let t = aggregate(id).unwrap_or_default();
        p.final_yes = t.yes;
        p.final_no = t.no;
        p.final_abstain = t.abstain;
        p.final_veto = t.veto;
        p.final_ballots = t.ballots;
        crate::ws::publish_tally(&p);
    }

    Ok(Json(VoteAck { proposal_id: id, option: option.as_str().to_string() }))
}

/// `GET /proposals/{id}/tally` — the live aggregated tally (read-gated).
pub fn get_tally(req: &mut Req<'_>) -> Result<Json<Tally>, ApiError> {
    crate::gate_read()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let _ = get_row(Proposal::TABLE, id)?.ok_or_else(ApiError::not_found)?;
    Ok(Json(aggregate(id)?))
}
