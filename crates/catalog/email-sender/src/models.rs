//! Typed models for email-sender. Both tables are `#[derive(Model)]`
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
/// - `status` is one of `queued` | `sent` | `failed`; `#[index]` backs
///   status-filtered listing / the retry-job scan.
/// - `template_id` / `provider_message_id` / `error` / `sent_at` are unset
///   (`None`) until the relevant lifecycle step populates them.
/// - `body_html` / `body_text` store the *rendered* email body at send time
///   (after any template substitution). The send path renders once; the
///   durable `retry_send` job reloads the row and resends verbatim from
///   these columns, so it never has to re-render (the template + vars are
///   not retained — the rendered body is the single source of truth).
#[derive(Model)]
#[model(table = "messages")]
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
    #[index]
    pub status: String, // queued | sent | failed
    pub error: Option<String>,
    pub created_at: Timestamp,
    pub sent_at: Option<Timestamp>,
}

/// A reusable email template owned by a principal.
///
/// `name` is a human label; `subject` / `html` are the renderable bodies
/// (`{{var}}` placeholders substituted by `email_core::render` at send
/// time). `text` is an optional plain-text alternative.
#[derive(Model)]
#[model(table = "templates")]
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
