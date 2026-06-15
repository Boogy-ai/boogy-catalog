//! govern-base — a provisionable governance engine (catalog service).
//!
//! Runs the proven governance lifecycle (propose → co-sponsor → vote → tally →
//! timelock → execute) for a tenant's internal or public-facing space. A passed
//! proposal executes its immutable, transparently-encoded actions (in-mesh peer
//! calls or outbound calls) bounded by the operator's manifest capability
//! envelope. Pure decision logic lives in the host-testable sibling crate
//! `govern-base-core`. Authorization is in-handler via `audience()` — the module
//! hardcodes no owner (it is provisionable by anyone).

mod bindings {
    wit_bindgen::generate!({
        world: "service-with-jobs",
        path: "../../boogy-wit/wit",
    });
}

boogy_sdk::wit_glue!(bindings, GovernBase, with_jobs);

use boogy_sdk::{Api, JobRouter};

mod admin;
mod comments;
mod execution;
mod lifecycle;
mod mcp;
mod models;
mod proposals;
mod sponsor;
mod voting;
mod ws;

use models::{AdminAudit, Comment, Config, Member, Proposal, ProposalAction, Sponsorship, Vote};

use boogy_sdk::pagination::{decode, Cursor};

/// The caller's audience for this deployment — host-attested, hardcodes NO
/// identity (the module is provisionable by anyone).
///
/// - `Owner` — the SERVICE OWNER's agent (`caller_is_service_owner()`): config,
///   moderation, guardian-cancel, `/admin/*`.
/// - `Voter(principal)` — an eligible participant per `Config.eligibility`:
///   propose / sponsor / vote / comment.
/// - `Reader` — an anonymous caller on a read route (allowed only when
///   `read_access = public`).
/// - `Denied` — anyone else.
pub enum Audience {
    Owner,
    Voter(String),
    Reader,
    Denied,
}

/// Resolve the caller's audience from the ATTESTED identity + the deployment
/// `Config`. Eligibility:
/// - `open` → any authenticated principal is a `Voter` (permissionless by design).
/// - `members` / `workloads` → only principals on the operator's Member roll are
///   `Voter`; anyone else authenticated becomes `Denied` (curated electorate).
pub fn audience() -> Audience {
    if caller_is_service_owner() {
        return Audience::Owner;
    }
    match auth::current_principal() {
        Some(p) => {
            let cfg = admin::load_config();
            if cfg.eligibility == "open" || admin::is_member(&p) {
                Audience::Voter(p)
            } else {
                Audience::Denied
            }
        }
        None => Audience::Reader,
    }
}

/// Operator gate: the SERVICE OWNER only.
pub fn require_owner() -> Result<(), ApiError> {
    match audience() {
        Audience::Owner => Ok(()),
        _ => Err(ApiError::forbidden("operator (service owner) access required")),
    }
}

/// The authenticated principal, or 401.
pub fn require_principal() -> Result<String, ApiError> {
    auth::current_principal().ok_or_else(ApiError::unauthenticated)
}

/// Eligible voter gate: returns the principal for `Owner` (the owner's own
/// principal) or `Voter(p)`, and 403 for `Denied` (not on the member roll in
/// bounded electorates) or `Reader` (not authenticated).
pub fn require_voter() -> Result<String, ApiError> {
    match audience() {
        Audience::Owner => auth::current_principal()
            .ok_or_else(ApiError::unauthenticated),
        Audience::Voter(p) => Ok(p),
        Audience::Denied => Err(ApiError::forbidden(
            "not an eligible member of this governance space",
        )),
        Audience::Reader => Err(ApiError::unauthenticated()),
    }
}

/// Shared keyset-pagination params: `?limit=` (default 50, clamped 1..=200) +
/// opaque `?cursor=` (fail-soft to page one).
pub fn page_params(req: &mut Req<'_>) -> (usize, Option<Cursor>) {
    let limit = req
        .query("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let cursor = req.query("cursor").and_then(decode);
    (limit, cursor)
}

/// Current time in epoch millis as i64 (the store column type).
pub fn now_ms() -> i64 {
    now_millis() as i64
}

/// Read-access gate: when `Config.read_access != "public"`, a read requires an
/// authenticated principal (anonymous `Reader` → 401). Public deployments allow
/// anonymous reads.
pub fn gate_read() -> Result<(), ApiError> {
    if admin::load_config().read_access == "public" {
        return Ok(());
    }
    match audience() {
        Audience::Reader => Err(ApiError::unauthenticated()),
        _ => Ok(()),
    }
}

struct GovernBase;

impl Api for GovernBase {
    fn init_tables() {
        create_model::<Config>();
        create_model::<Member>();
        create_model::<Proposal>();
        create_model::<ProposalAction>();
        create_model::<Vote>();
        create_model::<Sponsorship>();
        create_model::<Comment>();
        create_model::<AdminAudit>();
    }

    fn build_router() -> Router {
        Router::new()
            .info(
                "Governance",
                "0.1.0",
                Some("Provisionable governance: propose, co-sponsor, vote, and \
                      execute the outcomes of passed proposals."),
            )
            .summary("Create a proposal")
            .description("Create a draft proposal with its immutable, \
                          transparently-encoded actions. Submit it separately to \
                          open co-sponsorship/voting.")
            .post("/proposals", proposals::create_proposal)
            .summary("List proposals")
            .description("Keyset-paginated, newest first. Optional ?status= and \
                          ?author= filters; ?limit= (max 200) + ?cursor=.")
            .get("/proposals", proposals::list_proposals)
            .summary("Get a proposal")
            .description("Fetch one proposal by id (lazily advancing its status \
                          if a window has elapsed).")
            .get("/proposals/{id}", proposals::get_proposal)
            .summary("Submit a proposal")
            .description("Move a draft into co-sponsorship (or straight to voting \
                          when no sponsorship threshold is set).")
            .post("/proposals/{id}/submit", proposals::submit_proposal)
            .summary("Withdraw a proposal")
            .description("Author/owner withdraws a proposal before voting ends.")
            .post("/proposals/{id}/withdraw", proposals::withdraw_proposal)
            .summary("Co-sponsor a proposal")
            .description("Endorse a proposal in the sponsorship stage. When enough \
                          distinct sponsors endorse, voting opens automatically.")
            .post("/proposals/{id}/sponsor", sponsor::sponsor_proposal)
            .summary("Cast a vote")
            .description("Cast a ballot (yes|no|abstain|veto) on a proposal that \
                          is open for voting.")
            .post("/proposals/{id}/vote", voting::cast_vote)
            .summary("Get the tally")
            .description("The live aggregated tally for a proposal.")
            .get("/proposals/{id}/tally", voting::get_tally)
            .summary("Comment on a proposal")
            .description("Add a deliberation comment (optionally threaded under a \
                          parent comment) to a proposal.")
            .post("/proposals/{id}/comments", comments::add_comment)
            .summary("List comments")
            .description("Keyset-paginated comments for a proposal, oldest first.")
            .get("/proposals/{id}/comments", comments::list_comments)
            .summary("Get config (operator)")
            .description("Operator-only: the deployment's governance configuration.")
            .get("/admin/config", admin::get_config)
            .summary("Update config (operator)")
            .description("Operator-only: update eligibility, read access, tally \
                          gates, windows, sponsorship threshold, and guardians.")
            .put("/admin/config", admin::put_config)
            .summary("Cancel a proposal (guardian)")
            .description("Operator/guardian: cancel a passed proposal during its \
                          timelock, before it executes.")
            .post("/admin/proposals/{id}/cancel", admin::cancel_proposal)
            .summary("Replay execution (operator)")
            .description("Operator-only: re-drive a failed proposal's action \
                          execution from the first incomplete action.")
            .post("/admin/proposals/{id}/replay-execution", admin::replay_execution)
            .summary("Hide a comment (operator)")
            .description("Operator-only: moderate (hide) a deliberation comment.")
            .post("/admin/comments/{id}/hide", admin::hide_comment)
            .summary("Add a member to the electorate roll (operator)")
            .description("Operator-only: idempotent enroll of a principal on the \
                          curated electorate roll. Required when eligibility is \
                          `members` or `workloads`. Weight defaults to 1.")
            .post("/admin/members", admin::add_member)
            .summary("Remove a member from the electorate roll (operator)")
            .description("Operator-only: remove a principal from the Member roll. \
                          Returns 404 if the principal was not enrolled.")
            .delete("/admin/members/{principal}", admin::remove_member)
            .summary("List electorate members (operator)")
            .description("Operator-only: keyset-paginated list of enrolled members, \
                          newest first.")
            .get("/admin/members", admin::list_members)
            .summary("Operator audit log")
            .description("Operator-only: append-only log of operator actions, \
                          newest first; optional ?action= filter.")
            .get("/admin/audit", admin::list_audit)
            .mcp("/mcp", mcp::mcp_dispatch)
    }

    fn build_job_router() -> JobRouter {
        JobRouter::new()
            .exact(lifecycle::lifecycle_tick)
            .exact(execution::execute_proposal)
    }
}
