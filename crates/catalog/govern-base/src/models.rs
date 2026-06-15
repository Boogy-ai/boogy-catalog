//! Typed store models for govern-base. Each is `#[derive(Model)]`: the derive
//! emits the per-field column-name consts (`Proposal::STATUS`, …), the schema
//! (columns + the indexes its `#[index]`/`#[lookup_by]`/`list_by`/`ranked_by`
//! attrs imply), and the `from_row` round-trip — handlers go through `db_*` + the
//! `Query` DSL and never touch raw column literals.
//!
//! Tenancy: every row is scoped on `owner_principal` (the deployment owner) — the
//! SDK `DEFAULT_OWNER_COL`. A `Proposal` is the aggregate root; child rows
//! (`ProposalAction`, `Vote`, `Sponsorship`, `Comment`) carry `proposal_id`.

use boogy_sdk::model::{Id, Timestamp};
use boogy_sdk::Model;

/// Singleton-per-owner deployment configuration. Exactly one row is maintained
/// (the operator PUTs it); handlers read it to resolve eligibility, read access,
/// default tally params, and the sponsorship/timelock/voting windows.
#[derive(Model)]
#[model(table = "config", ranked_by(highest = "updated_at"))]
pub struct Config {
    #[pk]
    pub id: Id<Config>,
    #[index]
    pub owner_principal: String,
    /// `open` | `members` | `workloads`.
    pub eligibility: String,
    /// `authenticated` | `public`.
    pub read_access: String,
    /// `one_principal_one_vote` (Phase 1 default). Phase 2 adds `weighted`.
    pub voting_strategy: String,
    pub voting_period_ms: i64,
    pub timelock_ms: i64,
    pub quorum: String,          // fraction, stored as a decimal string e.g. "0.4"
    pub threshold: String,       // fraction
    pub veto_threshold: String,  // fraction
    pub sponsorship_threshold: i64,
    /// Absolute ballot floor used as quorum in `open` eligibility.
    pub min_participation: i64,
    /// Comma-separated guardian principals allowed to cancel during timelock;
    /// empty → owner only.
    pub guardian_principals: String,
    /// Floor for any voting window (ms). Voting ends no sooner than
    /// `voting_start + min_voting_period_ms` regardless of `voting_period_ms`.
    pub min_voting_period_ms: i64,
    /// Minimum time (ms) an author must wait between creating proposals. `0`
    /// disables the cooldown.
    pub author_cooldown_ms: i64,
    /// Comma-separated principals/workloads whose proposals SKIP co-sponsorship
    /// and open for voting immediately on submit (even when
    /// `sponsorship_threshold > 0`). The deployment owner is always exempt
    /// implicitly; this list designates additional trusted proposers (agents,
    /// services). Empty → only the owner is exempt.
    pub exempt_proposers: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// A governance proposal — the aggregate root. Tally params + strategy are
/// SNAPSHOTTED here at activation so a later config change never alters an open
/// vote. Final tally fields are filled at finalization.
#[derive(Model)]
#[model(
    table = "proposals",
    list_by(filter = "status", newest = "created_at"),
    list_by(filter = "author", newest = "created_at"),
    ranked_by(highest = "created_at")
)]
pub struct Proposal {
    #[pk]
    pub id: Id<Proposal>,
    #[index]
    pub owner_principal: String,
    pub author: String,
    pub title: String,
    pub body: String,
    /// `standard` (Phase 1). Phase 3 adds `budget`.
    pub kind: String,
    /// One of govern_base_core::ProposalStatus::as_str().
    pub status: String,
    /// Delegation scope key (Phase 2). Free-text category; "" when unset.
    pub category: String,
    // ── snapshotted electorate + gates ──
    pub strategy: String,
    pub eligibility: String,
    pub quorum: String,
    pub threshold: String,
    pub veto_threshold: String,
    pub total_eligible_power: i64, // bounded electorates; 0 in open
    pub min_participation: i64,    // open electorate floor
    pub sponsor_count: i64,
    pub sponsorship_threshold: i64,
    // ── windows (epoch ms; 0 until set) ──
    pub voting_start: i64,
    pub voting_end: i64,
    pub timelock_end: i64,
    // ── final tally (0 until finalized) ──
    pub final_yes: i64,
    pub final_no: i64,
    pub final_abstain: i64,
    pub final_veto: i64,
    pub final_ballots: i64,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// One immutable, transparently-encoded executable action attached to a proposal.
/// Frozen once the proposal leaves `draft`. Executed verbatim by `execute_proposal`.
///
/// **Immutability invariant:** after the action row is created, ONLY
/// `exec_status`, `exec_result`, and `attempts` are ever written (by
/// `claim_running` and `mark_action` in `execution.rs`). The content fields
/// `target`, `method`, `body`, `headers`, and `secret_header_ref` are NEVER
/// mutated after creation — they represent the transparently-encoded, operator-
/// readable intent of the proposal exactly as the author submitted it.
#[derive(Model)]
#[model(table = "proposal_actions", list_by(filter = "proposal_id", newest = "seq"))]
pub struct ProposalAction {
    #[pk]
    pub id: Id<ProposalAction>,
    #[index]
    pub owner_principal: String,
    #[index]
    pub proposal_id: i64,
    pub seq: i64,
    /// `peer` | `http`.
    pub action_type: String,
    pub target: String,
    pub method: String,
    /// JSON object of header name → value (never contains secrets).
    pub headers: String,
    /// Verbatim request body bytes, stored as text.
    pub body: String,
    /// Operator-bound secret NAME injected as a header at the wire edge; "" = none.
    pub secret_header_ref: String,
    /// `pending` | `running` | `done` | `failed` | `skipped`.
    pub exec_status: String,
    pub exec_result: String,
    pub attempts: i64,
    pub created_at: Timestamp,
}

/// One ballot. Phase 1: single-cast per (proposal_id, voter) — re-casting is a
/// 409 (Phase 2 makes it re-votable via UPSERT). `weight` is 1 under 1p1v.
#[derive(Model)]
#[model(table = "votes", list_by(filter = "proposal_id", newest = "cast_at"))]
pub struct Vote {
    #[pk]
    pub id: Id<Vote>,
    #[index]
    pub owner_principal: String,
    #[index]
    pub proposal_id: i64,
    #[index]
    pub voter: String,
    /// One of govern_base_core::VoteOption::as_str().
    pub option: String,
    pub weight: i64,
    pub cast_at: Timestamp,
    pub updated_at: Timestamp,
}

/// A co-sponsor endorsement (the non-monetary deposit). One per (proposal_id,
/// principal); `sponsorship_threshold` distinct rows open voting.
#[derive(Model)]
#[model(table = "sponsorships", list_by(filter = "proposal_id", newest = "created_at"))]
pub struct Sponsorship {
    #[pk]
    pub id: Id<Sponsorship>,
    #[index]
    pub owner_principal: String,
    #[index]
    pub proposal_id: i64,
    #[index]
    pub principal: String,
    pub created_at: Timestamp,
}

/// Threaded deliberation on a proposal. `parent_id = 0` is a top-level comment.
#[derive(Model)]
#[model(table = "comments", list_by(filter = "proposal_id", newest = "created_at"))]
pub struct Comment {
    #[pk]
    pub id: Id<Comment>,
    #[index]
    pub owner_principal: String,
    #[index]
    pub proposal_id: i64,
    pub parent_id: i64,
    pub author: String,
    pub body: String,
    pub hidden: bool,
    pub created_at: Timestamp,
}

/// A member of the curated electorate. Used when `Config.eligibility` is
/// `members` or `workloads` to gate propose/sponsor/vote/comment to only
/// principals the operator has explicitly added.
#[derive(Model)]
#[model(table = "members", ranked_by(highest = "added_at"))]
pub struct Member {
    #[pk]
    pub id: Id<Member>,
    #[index]
    pub owner_principal: String,
    /// The principal that is granted voting rights.
    #[lookup_by]
    pub principal: String,
    /// Voting weight (reserved for Phase 2 weighted voting; always 1 in Phase 1).
    pub weight: i64,
    /// Optional role label (e.g. `"guardian"`, `"delegate"`).
    pub role: String,
    pub added_at: Timestamp,
}

/// Append-only operator action log (the in-store equivalent of stripe-base's).
#[derive(Model)]
#[model(
    table = "admin_audit",
    list_by(filter = "action", newest = "at"),
    ranked_by(highest = "at")
)]
pub struct AdminAudit {
    #[pk]
    pub id: Id<AdminAudit>,
    #[index]
    pub owner_principal: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub at: Timestamp,
}
