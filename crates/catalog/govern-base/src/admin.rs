//! Operator surface + shared config access for govern-base.

use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::pagination::CursorPage;
use boogy_sdk::store::{SortDir, Val};
use govern_base_core::ProposalStatus;

use crate::models::{AdminAudit, Config, Member, Proposal};
use crate::{
    db_find_by, db_insert, db_update, get_row, now_ms, page_params, require_owner, self_identity,
    tx, ApiError, Deserialize, Json, NoContent, Req, Serialize,
};

/// Default config values for a fresh deployment (before the operator PUTs one).
pub fn default_config(owner: &str) -> Config {
    let now = Timestamp::new(now_ms());
    Config {
        id: Id::new(0),
        owner_principal: owner.to_string(),
        eligibility: "open".to_string(),
        read_access: "authenticated".to_string(),
        voting_strategy: "one_principal_one_vote".to_string(),
        voting_period_ms: 7 * 24 * 60 * 60 * 1000, // 7 days
        timelock_ms: 24 * 60 * 60 * 1000,          // 1 day
        quorum: "0.4".to_string(),
        threshold: "0.5".to_string(),
        veto_threshold: "0.334".to_string(),
        sponsorship_threshold: 1,
        min_participation: 1,
        guardian_principals: String::new(),
        min_voting_period_ms: 3_600_000, // 1 hour floor
        author_cooldown_ms: 0,           // disabled by default
        exempt_proposers: String::new(), // only the owner is exempt by default
        created_at: now,
        updated_at: now,
    }
}

/// True if `author` may skip co-sponsorship — the deployment owner (always) or a
/// principal/workload listed in `cfg.exempt_proposers`. An exempt author's
/// proposal opens for voting immediately on submit, even when a sponsorship
/// threshold is configured.
pub fn is_exempt_proposer(author: &str, cfg: &Config) -> bool {
    author == crate::self_identity().owner
        || cfg
            .exempt_proposers
            .split(',')
            .map(|s| s.trim())
            .any(|p| !p.is_empty() && p == author)
}

/// True if `principal` is on this deployment's Member roll (bounded electorates).
pub fn is_member(principal: &str) -> bool {
    crate::db_find_by::<crate::models::Member>(
        crate::models::Member::PRINCIPAL,
        boogy_sdk::store::Val::Text(principal.to_string()),
    )
    .map(|hits| !hits.is_empty())
    .unwrap_or(false)
}

/// Load this deployment's single Config row, or synthesize defaults if the
/// operator has not configured one yet (so the service is usable immediately).
pub fn load_config() -> Config {
    let owner = self_identity().owner;
    let hits: Vec<Config> = db_find_by::<Config>(Config::OWNER_PRINCIPAL, Val::Text(owner.clone()))
        .unwrap_or_default();
    hits.into_iter().next().unwrap_or_else(|| default_config(&owner))
}

/// Append one operator-audit row. Best-effort: never fails the action it records.
pub fn write_admin_audit(action: &str, target: Option<&str>, detail: Option<String>) {
    let _ = db_insert(&AdminAudit {
        id: Id::new(0),
        owner_principal: self_identity().owner,
        actor: crate::auth::current_principal().unwrap_or_default(),
        action: action.to_string(),
        target: target.map(|s| s.to_string()),
        detail,
        at: Timestamp::new(now_ms()),
    });
}

/// Parse a stored decimal-string fraction (e.g. `"0.4"`) to f64, clamped 0..=1.
pub fn frac(s: &str) -> f64 {
    s.parse::<f64>().unwrap_or(0.0).clamp(0.0, 1.0)
}

/// True if `principal` is listed in this deployment's `guardian_principals`.
/// Guardians may cancel a timelocked proposal in addition to the service owner.
fn is_guardian(principal: &str) -> bool {
    load_config()
        .guardian_principals
        .split(',')
        .map(|s| s.trim())
        .any(|g| !g.is_empty() && g == principal)
}

/// Operator/guardian gate: the service owner OR any configured guardian principal.
/// Use this in place of `require_owner()` for actions guardians may also perform.
pub fn require_owner_or_guardian() -> Result<(), ApiError> {
    if matches!(crate::audience(), crate::Audience::Owner) {
        return Ok(());
    }
    if let Some(p) = crate::auth::current_principal() {
        if is_guardian(&p) {
            return Ok(());
        }
    }
    Err(ApiError::forbidden("owner or configured guardian required"))
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ConfigOut {
    pub eligibility: String,
    pub read_access: String,
    pub voting_strategy: String,
    pub voting_period_ms: i64,
    pub timelock_ms: i64,
    pub quorum: String,
    pub threshold: String,
    pub veto_threshold: String,
    pub sponsorship_threshold: i64,
    pub min_participation: i64,
    pub guardian_principals: String,
    /// Floor for any voting window (ms). Actual voting window is
    /// `max(voting_period_ms, min_voting_period_ms)`.
    pub min_voting_period_ms: i64,
    /// Minimum gap (ms) an author must wait between proposals. `0` = disabled.
    pub author_cooldown_ms: i64,
    /// Comma-separated trusted proposers who skip co-sponsorship (owner always
    /// exempt implicitly).
    pub exempt_proposers: String,
}

fn config_out(c: &Config) -> ConfigOut {
    ConfigOut {
        eligibility: c.eligibility.clone(),
        read_access: c.read_access.clone(),
        voting_strategy: c.voting_strategy.clone(),
        voting_period_ms: c.voting_period_ms,
        timelock_ms: c.timelock_ms,
        quorum: c.quorum.clone(),
        threshold: c.threshold.clone(),
        veto_threshold: c.veto_threshold.clone(),
        sponsorship_threshold: c.sponsorship_threshold,
        min_participation: c.min_participation,
        guardian_principals: c.guardian_principals.clone(),
        min_voting_period_ms: c.min_voting_period_ms,
        author_cooldown_ms: c.author_cooldown_ms,
        exempt_proposers: c.exempt_proposers.clone(),
    }
}

/// `GET /admin/config` (owner-only).
pub fn get_config(_req: &mut Req<'_>) -> Result<Json<ConfigOut>, ApiError> {
    require_owner()?;
    Ok(Json(config_out(&load_config())))
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ConfigPut {
    pub eligibility: Option<String>,
    pub read_access: Option<String>,
    pub voting_strategy: Option<String>,
    pub voting_period_ms: Option<i64>,
    pub timelock_ms: Option<i64>,
    pub quorum: Option<String>,
    pub threshold: Option<String>,
    pub veto_threshold: Option<String>,
    pub sponsorship_threshold: Option<i64>,
    pub min_participation: Option<i64>,
    pub guardian_principals: Option<String>,
    pub min_voting_period_ms: Option<i64>,
    pub author_cooldown_ms: Option<i64>,
    pub exempt_proposers: Option<String>,
}

/// `PUT /admin/config` (owner-only). Upserts the single config row in one `tx`.
pub fn put_config(req: &mut Req<'_>) -> Result<Json<ConfigOut>, ApiError> {
    require_owner()?;
    let body: ConfigPut = boogy_sdk::error::parse_body(req.body())?;
    let owner = crate::self_identity().owner;
    let now = Timestamp::new(now_ms());

    let out = tx::<_, _, ApiError>(|| {
        let existing: Vec<Config> =
            db_find_by::<Config>(Config::OWNER_PRINCIPAL, Val::Text(owner.clone()))?;
        let mut c = existing.into_iter().next().unwrap_or_else(|| default_config(&owner));
        if let Some(v) = body.eligibility.clone() { c.eligibility = v; }
        if let Some(v) = body.read_access.clone() { c.read_access = v; }
        if let Some(v) = body.voting_strategy.clone() { c.voting_strategy = v; }
        if let Some(v) = body.voting_period_ms { c.voting_period_ms = v; }
        if let Some(v) = body.timelock_ms { c.timelock_ms = v; }
        if let Some(v) = body.quorum.clone() { c.quorum = v; }
        if let Some(v) = body.threshold.clone() { c.threshold = v; }
        if let Some(v) = body.veto_threshold.clone() { c.veto_threshold = v; }
        if let Some(v) = body.sponsorship_threshold { c.sponsorship_threshold = v; }
        if let Some(v) = body.min_participation { c.min_participation = v; }
        if let Some(v) = body.guardian_principals.clone() { c.guardian_principals = v; }
        if let Some(v) = body.min_voting_period_ms { c.min_voting_period_ms = v; }
        if let Some(v) = body.author_cooldown_ms { c.author_cooldown_ms = v; }
        if let Some(v) = body.exempt_proposers.clone() { c.exempt_proposers = v; }
        c.updated_at = now;
        if c.id.get() == 0 {
            c.created_at = now;
            let id = db_insert(&c)?;
            c.id = Id::new(id);
        } else {
            db_update::<Config>(c.id.get(), &c)?;
        }
        Ok(config_out(&c))
    })?;
    write_admin_audit("config.update", None, None);
    Ok(Json(out))
}

/// `POST /admin/proposals/{id}/cancel` — guardian (owner, or a Config-listed
/// guardian principal) cancels a passed proposal during timelock.
pub fn cancel_proposal(req: &mut Req<'_>) -> Result<Json<crate::proposals::ProposalOut>, ApiError> {
    require_owner_or_guardian()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let out = tx::<_, _, ApiError>(|| {
        let row = get_row(Proposal::TABLE, id)?.ok_or_else(ApiError::not_found)?;
        let mut p = Proposal::from_row(&row);
        if p.status != ProposalStatus::Timelock.as_str() {
            return Err(ApiError::conflict("only a timelocked proposal can be canceled"));
        }
        p.status = ProposalStatus::Canceled.as_str().to_string();
        p.updated_at = Timestamp::new(now_ms());
        db_update::<Proposal>(id, &p)?;
        Ok(crate::proposals::proposal_out(&p))
    })?;
    write_admin_audit("proposal.cancel", Some(&id.to_string()), None);
    Ok(Json(out))
}

/// `POST /admin/proposals/{id}/replay-execution?reset=true|false` — re-drive a
/// failed execution. Default (`reset=false`): a `running` action blocks with 409,
/// prompting the operator to verify the side effect before passing `reset=true`.
pub fn replay_execution(req: &mut Req<'_>) -> Result<NoContent, ApiError> {
    require_owner()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let reset = req.query("reset").map(|v| v == "true").unwrap_or(false);
    crate::execution::replay(id, reset)?;
    write_admin_audit("proposal.replay", Some(&id.to_string()), None);
    Ok(NoContent)
}

/// `POST /admin/comments/{id}/hide` — moderate a comment.
pub fn hide_comment(req: &mut Req<'_>) -> Result<NoContent, ApiError> {
    require_owner()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    tx::<_, _, ApiError>(|| {
        let row = get_row(crate::models::Comment::TABLE, id)?.ok_or_else(ApiError::not_found)?;
        let mut c = crate::models::Comment::from_row(&row);
        c.hidden = true;
        db_update::<crate::models::Comment>(id, &c)?;
        Ok(())
    })?;
    write_admin_audit("comment.hide", Some(&id.to_string()), None);
    Ok(NoContent)
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct AuditOut {
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub at: i64,
}

/// Request body for adding a member to the electorate roll.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct AddMemberReq {
    /// Principal to enroll (agent id or workload URI).
    pub principal: String,
    /// Voting weight (reserved for Phase 2; defaults to 1).
    #[serde(default)]
    pub weight: Option<i64>,
    /// Optional role label (e.g. `"guardian"`, `"delegate"`).
    #[serde(default)]
    pub role: Option<String>,
}

/// Public projection of a Member row.
#[derive(Serialize, schemars::JsonSchema)]
pub struct MemberOut {
    pub id: u64,
    pub principal: String,
    pub weight: i64,
    pub role: String,
    pub added_at: i64,
}

fn member_out(m: &Member) -> MemberOut {
    MemberOut {
        id: m.id.get(),
        principal: m.principal.clone(),
        weight: m.weight,
        role: m.role.clone(),
        added_at: m.added_at.get(),
    }
}

/// `POST /admin/members` — idempotent add a principal to the Member roll.
/// If the principal is already enrolled the existing row is returned unchanged.
pub fn add_member(req: &mut Req<'_>) -> Result<Json<MemberOut>, ApiError> {
    require_owner()?;
    let body: AddMemberReq = boogy_sdk::error::parse_body(req.body())?;
    if body.principal.trim().is_empty() {
        return Err(ApiError::bad_request("principal is required"));
    }
    let owner = crate::self_identity().owner;
    let now = Timestamp::new(now_ms());

    let out = tx::<_, _, ApiError>(|| {
        let existing: Vec<Member> = db_find_by::<Member>(
            Member::PRINCIPAL,
            Val::Text(body.principal.clone()),
        )?;
        if let Some(m) = existing.into_iter().next() {
            return Ok(member_out(&m));
        }
        let m = Member {
            id: Id::new(0),
            owner_principal: owner.clone(),
            principal: body.principal.clone(),
            weight: body.weight.unwrap_or(1),
            role: body.role.clone().unwrap_or_default(),
            added_at: now,
        };
        let mid = db_insert(&m)?;
        Ok(member_out(&Member { id: Id::new(mid), ..m }))
    })?;
    write_admin_audit("member.add", Some(&body.principal), None);
    Ok(Json(out))
}

/// `DELETE /admin/members/{principal}` — remove a principal from the Member roll.
pub fn remove_member(req: &mut Req<'_>) -> Result<NoContent, ApiError> {
    require_owner()?;
    let principal = req.params.get("principal").unwrap_or("").to_string();
    if principal.is_empty() {
        return Err(ApiError::bad_request("principal param is required"));
    }
    let existing: Vec<Member> =
        db_find_by::<Member>(Member::PRINCIPAL, Val::Text(principal.clone()))?;
    if existing.is_empty() {
        return Err(ApiError::not_found());
    }
    for m in &existing {
        crate::db_delete::<Member>(m.id.get())?;
    }
    write_admin_audit("member.remove", Some(&principal), None);
    Ok(NoContent)
}

/// `GET /admin/members` — list all members on the electorate roll (owner-only).
pub fn list_members(req: &mut Req<'_>) -> Result<Json<CursorPage<MemberOut>>, ApiError> {
    require_owner()?;
    let (limit, cursor) = page_params(req);
    let page = crate::Query::on(Member::TABLE)
        .keyset_by(Member::ADDED_AT, SortDir::Desc)
        .limit(limit)
        .cursor(cursor)
        .fetch_page(|r| member_out(&Member::from_row(r)))?;
    Ok(Json(page))
}

/// `GET /admin/audit` — keyset-paginated operator audit log (owner-only).
pub fn list_audit(req: &mut Req<'_>) -> Result<Json<CursorPage<AuditOut>>, ApiError> {
    require_owner()?;
    let (limit, cursor) = page_params(req);
    let mut q = crate::Query::on(AdminAudit::TABLE);
    if let Some(a) = req.query("action").filter(|s| !s.is_empty()) {
        q = q.where_eq(AdminAudit::ACTION, a);
    }
    let page = q
        .keyset_by(AdminAudit::AT, SortDir::Desc)
        .limit(limit)
        .cursor(cursor)
        .fetch_page(|r| {
            let a = AdminAudit::from_row(r);
            AuditOut { actor: a.actor, action: a.action, target: a.target, detail: a.detail, at: a.at.get() }
        })?;
    Ok(Json(page))
}
