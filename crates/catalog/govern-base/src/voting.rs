//! Vote casting + tally endpoint.

use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::store::Val;
use govern_base_core::{Tally, VoteOption};

use crate::models::{Proposal, Vote};
use crate::{
    db_insert, get_row, now_ms, require_voter, tx, Deserialize, Json, Req,
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

/// How many vote-option groups the tally will materialize.
///
/// `group_by(option)` yields one item per DISTINCT option value, and the
/// options a ballot may carry are a closed set (`yes` / `no` / `abstain` /
/// `veto`). Spare slots so a value written by an older or newer version of this
/// service is returned and skipped rather than silently cutting the tally
/// short.
const MAX_VOTE_OPTIONS: usize = 16;

/// Aggregate all ballots for a proposal into a [`Tally`] (1p1v: weight 1).
///
/// The fold happens in the STORE, not in this component. It used to read every
/// ballot row for the proposal into a `Vec` and count them here — one `Vec<Vote>`
/// per tally, growing with turnout, in a 32 MiB guest heap. What comes back now
/// is one row per option, whatever the turnout, and the platform pays for the
/// walk that produces it.
pub fn aggregate(proposal_id: u64) -> Result<Tally, ApiError> {
    let groups: Vec<(String, i64, i64)> = crate::Query::on(Vote::TABLE)
        .filter(Vote::proposal_id.eq(proposal_id as i64))
        .group_by(Vote::OPTION)
        .sum(Vote::WEIGHT)
        .count_all()
        .limit(MAX_VOTE_OPTIONS)
        .fetch_groups(|g| {
            (
                g.key().map(Val::as_text).unwrap_or_default(),
                g.sum(Vote::WEIGHT).unwrap_or(0),
                g.count_all(),
            )
        })?;

    // An option this build does not recognise contributes NOTHING — neither
    // weight nor a ballot — which is exactly what the row-by-row version did
    // (its `filter_map` dropped the pair before `tally_votes` counted it).
    let mut t = Tally::default();
    for (option, weight, ballots) in groups {
        match VoteOption::from_str(&option) {
            Some(VoteOption::Yes) => t.yes += weight,
            Some(VoteOption::No) => t.no += weight,
            Some(VoteOption::Abstain) => t.abstain += weight,
            Some(VoteOption::Veto) => t.veto += weight,
            None => continue,
        }
        t.ballots += ballots;
    }
    Ok(t)
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
        // An existence probe, not a listing: this asks whether THIS voter has a
        // ballot, so it is one predicate the store answers with a number. The
        // previous form read every ballot on the proposal to find out, which
        // made the cost of casting a vote grow with the votes already cast.
        let already_voted = crate::Query::on(Vote::TABLE)
            .filter(Vote::proposal_id.eq(id as i64))
            .filter(Vote::voter.eq(voter.clone()))
            .count()?;
        if already_voted > 0 {
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
