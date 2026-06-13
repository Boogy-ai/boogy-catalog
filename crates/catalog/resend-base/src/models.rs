//! Typed models for resend-base. Both tables are `#[derive(Model)]`
//! structs — the derive emits the per-field column-name consts
//! (`Message::STATUS`, `Template::NAME`, …), the schema (columns + the
//! indexes the declared access patterns / `#[index]` attrs imply), and the
//! `from_row`/`to_columns` round-trip, so handlers go through `db_*` + the
//! `Query` DSL and never touch raw column literals. This replaces a
//! hand-written `cols` module.
//!
//! The owner column stays a real field named `owner_principal` (the SDK's
//! `DEFAULT_OWNER_COL`) so the principal-scoped auth helpers
//! (`auth::owns_resource` / `find_owned` / `load_owned`) keep working
//! against the Model-backed tables.

use boogy_sdk::model::{Id, Timestamp};
use boogy_sdk::Model;

/// A single outbound email and its delivery state.
///
/// - `owner_principal` is the tenancy column (`#[index]` backs the
///   owner-scoped list seek the auth helpers do).
/// - `status` is one of `queued` | `sent` | `failed` | `canceled`; `#[index]`
///   backs status-filtered listing / the send-job scan. `sent`, `failed`, and
///   `canceled` are TERMINAL. `failed` is reachable: the `send_email` job
///   flips a message to `failed` on its terminal attempt (`ctx.attempts >=
///   MAX_ATTEMPTS`); `canceled` is set by the operator `cancel` route.
/// - `template_id` / `provider_message_id` / `error` / `sent_at` are unset
///   (`None`) until the relevant lifecycle step populates them.
/// - `body_html` / `body_text` store the *rendered* email body at send time
///   (after any template substitution). The send path renders once; the
///   durable `send_email` job reloads the row and resends verbatim from
///   these columns, so it never has to re-render (the template + vars are
///   not retained — the rendered body is the single source of truth).
/// ## Access patterns (keyset-pagination-backed)
///
/// Listings are keyset-paginated newest-first by `created_at`; the model
/// declares the covering composite indexes that back the walks:
/// - `list_by(filter = "owner_principal", …)` — the principal's own messages
///   (`GET /messages`). `owner_principal` keeps its `#[index]` too: the SDK auth
///   helpers (`find_owned`/`load_owned`) seek on it.
/// - `list_by(filter = "status", …)` — the operator `?status=` filter.
/// - `ranked_by(highest = "created_at")` — the operator's unfiltered
///   all-principals feed (`GET /admin/messages`).
#[derive(Model)]
#[model(
    table = "messages",
    list_by(filter = "owner_principal", newest = "created_at"),
    list_by(filter = "status", newest = "created_at"),
    ranked_by(highest = "created_at")
)]
pub struct Message {
    #[pk]
    pub id: Id<Message>,
    #[index]
    pub owner_principal: String,
    pub to_addr: String,
    pub from_addr: String,
    pub subject: String,
    pub body_html: Option<String>,
    pub body_text: Option<String>,
    pub template_id: Option<String>,
    pub provider_message_id: Option<String>,
    pub status: String, // queued | sent | failed | canceled
    pub error: Option<String>,
    pub created_at: Timestamp,
    pub sent_at: Option<Timestamp>,
}

/// A principal blocked from sending by the deployment operator.
///
/// `/send` (+ `/send/batch`) pre-check the calling principal against this
/// table and return `403` if blocked. `principal` is a unique point-lookup
/// (`#[lookup_by]`) so the check is a single keyed read; `created_by` records
/// which operator set the block.
/// `ranked_by(highest = "created_at")` backs the operator's keyset-paginated
/// block list (`GET /admin/blocks`, newest first).
#[derive(Model)]
#[model(table = "blocked_senders", ranked_by(highest = "created_at"))]
pub struct BlockedSender {
    #[pk]
    pub id: Id<BlockedSender>,
    #[lookup_by]
    pub principal: String,
    pub reason: Option<String>,
    pub created_by: String,
    pub created_at: Timestamp,
}

/// A reusable email template owned by a principal.
///
/// `name` is a human label; `subject` / `html` are the renderable bodies
/// (`{{var}}` placeholders substituted by `resend_base_core::render` at send
/// time). `text` is an optional plain-text alternative.
/// `list_by(filter = "owner_principal", newest = "created_at")` backs the
/// principal's keyset-paginated template list (`GET /templates`, newest first).
/// `owner_principal` keeps its `#[index]` (the SDK auth helpers seek on it).
#[derive(Model)]
#[model(
    table = "templates",
    list_by(filter = "owner_principal", newest = "created_at")
)]
pub struct Template {
    #[pk]
    pub id: Id<Template>,
    #[index]
    pub owner_principal: String,
    pub name: String,
    pub subject: String,
    pub html: String,
    pub text: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}
