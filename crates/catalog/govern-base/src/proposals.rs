//! Proposal create / read / list / submit / withdraw handlers.

use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::pagination::CursorPage;
use boogy_sdk::store::SortDir;
use govern_base_core::{validate_action, ActionSpec, ProposalStatus};

use crate::admin::load_config;
use crate::models::{Proposal, ProposalAction};
use crate::{
    db_insert, get_row, now_ms, page_params, require_principal, tx, Audience, Deserialize,
    Json, Req, Serialize, ApiError,
};

/// One action in a create request (transparent + immutable once submitted).
#[derive(Deserialize, schemars::JsonSchema)]
pub struct ActionInput {
    pub action_type: String,
    pub target: String,
    pub method: String,
    #[serde(default)]
    pub headers: Option<serde_json::Value>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub secret_header_ref: Option<String>,
}

/// `POST /proposals` request body.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct CreateProposalReq {
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub actions: Vec<ActionInput>,
}

/// `POST /proposals` response.
#[derive(Serialize, schemars::JsonSchema)]
pub struct ProposalCreated {
    pub id: u64,
    pub status: String,
}

/// Public projection of a proposal row.
#[derive(Serialize, schemars::JsonSchema)]
pub struct ProposalOut {
    pub id: u64,
    pub author: String,
    pub title: String,
    pub body: String,
    pub kind: String,
    pub status: String,
    pub category: String,
    pub sponsor_count: i64,
    pub sponsorship_threshold: i64,
    pub voting_start: i64,
    pub voting_end: i64,
    pub timelock_end: i64,
    pub final_yes: i64,
    pub final_no: i64,
    pub final_abstain: i64,
    pub final_veto: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

pub fn proposal_out(p: &Proposal) -> ProposalOut {
    ProposalOut {
        id: p.id.get(),
        author: p.author.clone(),
        title: p.title.clone(),
        body: p.body.clone(),
        kind: p.kind.clone(),
        status: p.status.clone(),
        category: p.category.clone(),
        sponsor_count: p.sponsor_count,
        sponsorship_threshold: p.sponsorship_threshold,
        voting_start: p.voting_start,
        voting_end: p.voting_end,
        timelock_end: p.timelock_end,
        final_yes: p.final_yes,
        final_no: p.final_no,
        final_abstain: p.final_abstain,
        final_veto: p.final_veto,
        created_at: p.created_at.get(),
        updated_at: p.updated_at.get(),
    }
}

/// Create a `draft` proposal with its immutable encoded actions. The proposal +
/// all action rows are written in ONE `tx`: if any action insert fails the whole
/// proposal rolls back (rollback-on-error — a half-created proposal must never
/// persist), and the actions are frozen from here on.
pub fn create_proposal(
    req: &mut Req<'_>,
) -> Result<Json<ProposalCreated>, ApiError> {
    let principal = match crate::audience() {
        Audience::Owner => crate::self_identity().owner,
        Audience::Voter(p) => p,
        _ => return Err(ApiError::forbidden("must be an eligible member to propose")),
    };

    let body: CreateProposalReq = boogy_sdk::error::parse_body(req.body())?;
    if body.title.trim().is_empty() {
        return Err(ApiError::bad_request("title is required"));
    }
    // Validate every action's shape before persisting any of them.
    for a in &body.actions {
        validate_action(&ActionSpec {
            action_type: a.action_type.clone(),
            target: a.target.clone(),
            method: a.method.clone(),
        })
        .map_err(ApiError::bad_request)?;
    }

    let cfg = load_config();
    let now_epoch = now_ms();
    let now = Timestamp::new(now_epoch);
    let actions = body.actions;
    let owner = crate::self_identity().owner;

    // HD-8: per-author proposal rate limit — checked BEFORE the insert tx.
    if cfg.author_cooldown_ms > 0 {
        let recent_rows = crate::Query::on(Proposal::TABLE)
            .where_eq(Proposal::AUTHOR, principal.as_str())
            .keyset_by(Proposal::CREATED_AT, SortDir::Desc)
            .limit(1)
            .fetch_all()?;
        if let Some(row) = recent_rows.into_iter().next() {
            let last = Proposal::from_row(&row);
            if now_epoch - last.created_at.get() < cfg.author_cooldown_ms {
                return Err(ApiError::conflict(
                    "author proposal cooldown active; try again shortly",
                ));
            }
        }
    }

    let proposal_id = tx::<_, _, ApiError>(|| {
        let pid = db_insert(&Proposal {
            id: Id::new(0),
            owner_principal: owner.clone(),
            author: principal.clone(),
            title: body.title.clone(),
            body: body.body.clone(),
            kind: "standard".to_string(),
            status: ProposalStatus::Draft.as_str().to_string(),
            category: body.category.clone().unwrap_or_default(),
            strategy: cfg.voting_strategy.clone(),
            eligibility: cfg.eligibility.clone(),
            quorum: cfg.quorum.clone(),
            threshold: cfg.threshold.clone(),
            veto_threshold: cfg.veto_threshold.clone(),
            total_eligible_power: 0,
            min_participation: cfg.min_participation,
            sponsor_count: 0,
            sponsorship_threshold: cfg.sponsorship_threshold,
            voting_start: 0,
            voting_end: 0,
            timelock_end: 0,
            final_yes: 0,
            final_no: 0,
            final_abstain: 0,
            final_veto: 0,
            final_ballots: 0,
            created_at: now,
            updated_at: now,
        })?;
        for (i, a) in actions.iter().enumerate() {
            db_insert(&ProposalAction {
                id: Id::new(0),
                owner_principal: owner.clone(),
                proposal_id: pid as i64,
                seq: i as i64,
                action_type: a.action_type.clone(),
                target: a.target.clone(),
                method: a.method.to_ascii_uppercase(),
                headers: a
                    .headers
                    .as_ref()
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "{}".to_string()),
                body: a.body.clone().unwrap_or_default(),
                secret_header_ref: a.secret_header_ref.clone().unwrap_or_default(),
                exec_status: "pending".to_string(),
                exec_result: String::new(),
                attempts: 0,
                created_at: now,
            })?;
        }
        Ok(pid)
    })?;

    Ok(Json(ProposalCreated {
        id: proposal_id,
        status: ProposalStatus::Draft.as_str().to_string(),
    }))
}

/// `GET /proposals/{id}` — read access gated by Config.read_access (anon allowed
/// only when public). Lazily advances time-based status before returning.
pub fn get_proposal(req: &mut Req<'_>) -> Result<Json<ProposalOut>, ApiError> {
    crate::gate_read()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    crate::lifecycle::touch(id);
    let row = get_row(Proposal::TABLE, id)?.ok_or_else(ApiError::not_found)?;
    Ok(Json(proposal_out(&Proposal::from_row(&row))))
}

/// `GET /proposals` — keyset-paginated, newest first, optional `?status=` /
/// `?author=` equality filters (each rides a `list_by` composite).
pub fn list_proposals(req: &mut Req<'_>) -> Result<Json<CursorPage<ProposalOut>>, ApiError> {
    crate::gate_read()?;
    let (limit, cursor) = page_params(req);
    let mut q = crate::Query::on(Proposal::TABLE);
    if let Some(s) = req.query("status").filter(|s| !s.is_empty()) {
        q = q.where_eq(Proposal::STATUS, s);
    }
    if let Some(a) = req.query("author").filter(|s| !s.is_empty()) {
        q = q.where_eq(Proposal::AUTHOR, a);
    }
    let page = q
        .keyset_by(Proposal::CREATED_AT, SortDir::Desc)
        .limit(limit)
        .cursor(cursor)
        .fetch_page(|r| proposal_out(&Proposal::from_row(r)))?;
    Ok(Json(page))
}

use crate::db_update;
use boogy_sdk::NoContent;

/// `POST /proposals/{id}/submit` — author/owner moves a `draft` to either
/// `sponsorship` (if a threshold is configured) or straight to `voting`. Single
/// `tx`: the status flip + any window stamping commit together.
pub fn submit_proposal(req: &mut Req<'_>) -> Result<Json<ProposalOut>, ApiError> {
    let caller = require_principal()?;
    let is_owner = matches!(crate::audience(), Audience::Owner);
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let cfg = load_config();
    let now = now_ms();

    let out = tx::<_, _, ApiError>(|| {
        let row = get_row(Proposal::TABLE, id)?.ok_or_else(ApiError::not_found)?;
        let mut p = Proposal::from_row(&row);
        let is_author = p.author == caller;
        if !is_author && !is_owner {
            return Err(ApiError::forbidden("only the author or owner may submit"));
        }
        if p.status != ProposalStatus::Draft.as_str() {
            return Err(ApiError::conflict("proposal is not a draft"));
        }
        // Exempt proposers (the owner, or a configured trusted principal/workload)
        // skip co-sponsorship and open for voting immediately — even when a
        // sponsorship threshold is set. The check is on the proposal's AUTHOR.
        if cfg.sponsorship_threshold > 0 && !crate::admin::is_exempt_proposer(&p.author, &cfg) {
            p.status = ProposalStatus::Sponsorship.as_str().to_string();
        } else {
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

/// `POST /proposals/{id}/withdraw` — author/owner withdraws before voting ends.
pub fn withdraw_proposal(req: &mut Req<'_>) -> Result<NoContent, ApiError> {
    let caller = require_principal()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    tx::<_, _, ApiError>(|| {
        let row = get_row(Proposal::TABLE, id)?.ok_or_else(ApiError::not_found)?;
        let mut p = Proposal::from_row(&row);
        let is_author = p.author == caller;
        let is_owner = matches!(crate::audience(), Audience::Owner);
        if !is_author && !is_owner {
            return Err(ApiError::forbidden("only the author or owner may withdraw"));
        }
        let st = p.status.as_str();
        if st != ProposalStatus::Draft.as_str()
            && st != ProposalStatus::Sponsorship.as_str()
            && st != ProposalStatus::Voting.as_str()
        {
            return Err(ApiError::conflict("proposal can no longer be withdrawn"));
        }
        // HD-5: cannot withdraw after voting has closed (window elapsed).
        if st == ProposalStatus::Voting.as_str() && now_ms() >= p.voting_end {
            return Err(ApiError::conflict("voting has closed"));
        }
        p.status = ProposalStatus::Withdrawn.as_str().to_string();
        p.updated_at = Timestamp::new(now_ms());
        db_update::<Proposal>(id, &p)?;
        Ok(())
    })?;
    Ok(NoContent)
}
