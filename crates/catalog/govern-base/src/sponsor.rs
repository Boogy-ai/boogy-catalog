//! Co-sponsorship handler + sponsorship-threshold → voting transition.

use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::store::Val;
use govern_base_core::ProposalStatus;

use crate::admin::load_config;
use crate::models::{Proposal, Sponsorship};
use crate::proposals::{proposal_out, ProposalOut};
use crate::{
    db_find_by, db_insert, db_update, get_row, now_ms, require_voter, tx, Json, Req, ApiError,
};

/// `POST /proposals/{id}/sponsor` — an eligible principal endorses a proposal in
/// `sponsorship`. Idempotent per principal. When the distinct sponsor count
/// reaches the proposal's `sponsorship_threshold`, the SAME `tx` flips it to
/// `voting` and stamps the window — the endorsement and the transition it
/// triggers must commit atomically (rollback-on-error).
pub fn sponsor_proposal(req: &mut Req<'_>) -> Result<Json<ProposalOut>, ApiError> {
    let principal = require_voter()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let cfg = load_config();
    let now = now_ms();
    let owner = crate::self_identity().owner;

    let out = tx::<_, _, ApiError>(|| {
        let row = get_row(Proposal::TABLE, id)?.ok_or_else(ApiError::not_found)?;
        let mut p = Proposal::from_row(&row);
        if p.status != ProposalStatus::Sponsorship.as_str() {
            return Err(ApiError::conflict("proposal is not accepting sponsors"));
        }
        // HD-6: author cannot sponsor their own proposal.
        if principal == p.author {
            return Err(ApiError::forbidden("author cannot sponsor own proposal"));
        }

        // Idempotent: already sponsored → return current state unchanged.
        let existing: Vec<Sponsorship> =
            db_find_by::<Sponsorship>(Sponsorship::PROPOSAL_ID, Val::Integer(id as i64))?;
        if existing.iter().any(|s| s.principal == principal) {
            return Ok(proposal_out(&p));
        }

        db_insert(&Sponsorship {
            id: Id::new(0),
            owner_principal: owner.clone(),
            proposal_id: id as i64,
            principal: principal.clone(),
            created_at: Timestamp::new(now),
        })?;
        p.sponsor_count = existing.len() as i64 + 1;

        if p.sponsor_count >= p.sponsorship_threshold {
            // HD-7: clamp to minimum voting period floor.
            let period = cfg.voting_period_ms.max(cfg.min_voting_period_ms);
            p.status = ProposalStatus::Voting.as_str().to_string();
            p.voting_start = now;
            p.voting_end = now + period;
            // Snapshot electorate size so decide() quorum gate is non-zero for
            // bounded eligibility modes.
            p.total_eligible_power = if cfg.eligibility != "open" {
                crate::Query::on(crate::models::Member::TABLE)
                    .count()
                    .map(|n| n as i64)
                    .unwrap_or(0)
            } else {
                0
            };
        }
        p.updated_at = Timestamp::new(now);
        db_update::<Proposal>(id, &p)?;
        Ok(proposal_out(&p))
    })?;
    Ok(Json(out))
}
