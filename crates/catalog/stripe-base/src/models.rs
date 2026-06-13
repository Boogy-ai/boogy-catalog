//! Typed models for stripe-base. Both tables are `#[derive(Model)]`
//! structs — the derive emits the per-field column-name consts
//! (`Order::STATUS`, `WebhookEvent::PROCESS_STATUS`, …), the schema (columns +
//! the indexes its `#[index]` / `#[lookup_by]` attrs imply), and the
//! `from_row`/`to_columns` round-trip, so handlers go through `db_*` + the
//! `Query` DSL and never touch raw column literals. This replaces a
//! hand-written `cols` module.
//!
//! ## Multi-client-service partitioning
//!
//! ONE provisioned stripe-base deployment fronts MANY of the provisioner's
//! own client apps. Payment data is partitioned on two axes:
//!
//! - `owner_principal` — the deployment owner (the provisioner). The SDK's
//!   `DEFAULT_OWNER_COL`; the owner-scoped auth helpers key on it.
//! - `client_service` — WHICH of the provisioner's apps a payment belongs to.
//!   Derived from the attested caller workload when called via peer
//!   (`identity.actor` / a workload principal), else an explicit `client_ref`
//!   for direct callers — attested takes precedence so a client cannot
//!   impersonate another. The deployment owner lists across ALL apps (optional
//!   `?client=` filter); a client app sees only its own `client_service`
//!   (deny-mask). Both columns are `#[index]` so each scan is an equality seek.

use boogy_sdk::model::{Id, Timestamp};
use boogy_sdk::Model;

/// A single Stripe Checkout Session and its payment state.
///
/// - `owner_principal` (`#[index]`) is the deployment-tenancy column the auth
///   helpers seek on; `client_service` (`#[index]`) is the per-app partition.
/// - `stripe_session_id` (`#[lookup_by]`) is the natural key: the webhook-apply
///   job resolves the order from the Stripe session id as a unique point lookup.
///   It is EMPTY (`""`) while an async order is `queued` — the durable
///   `create_checkout` job fills it once the Stripe session is created. The
///   webhook only ever looks up by a real `cs_...` id, so the transient empties
///   never collide.
/// - `checkout_url` is the hosted Stripe Checkout URL. NULL while `queued`
///   (the async request returns before Stripe is called); the `create_checkout`
///   job (or the inline `synchronous` path) populates it when the session is
///   created. Clients poll `GET /orders/{id}` (or, later, a websocket push) for it.
/// - `status` is one of `queued` | `pending` | `paid` | `expired` | `failed`;
///   `#[index]` backs status-filtered listing. `queued` = session not yet
///   created (async, in-flight job); `pending` = session created, awaiting
///   payment; `failed` = the `create_checkout` job exhausted its retries.
/// - `error` holds the last failure detail when a `create_checkout` job fails
///   (null otherwise); surfaced to the owner so a `failed` order is diagnosable.
/// - `customer_ref` (`#[index]`) is the provisioner's end-customer attribution
///   (set from `CheckoutReq.customer_ref`); `""` when unset. An owner admin filter
///   axis (`GET /admin/orders?customer=…`), so it is an equality-seek index.
/// - `amount_refunded` is the running refunded total (minor units); `0` until a
///   refund succeeds. The order flips to `refunded` once it reaches `amount`; a
///   `paid` order with `amount_refunded > 0` is partially refunded.
/// - `metadata` holds optional caller JSON; `created_at` / `updated_at` track
///   the lifecycle (`updated_at` bumped when the job/webhook flips the status).
/// ## Access patterns (keyset-pagination-backed)
///
/// Every listing is keyset-paginated newest-first by `created_at`. The model
/// declares the covering composite indexes that back those walks, so a
/// `where_eq(<filter>).keyset_by("created_at", Desc).fetch_page(...)` is an
/// index walk, never a scan:
/// - `list_by(filter = "client_service", …)` — a client app's own orders, and
///   the admin `?client=` filter. Its prefix also serves the plain
///   `where_eq(client_service)` equality seek (so no separate `#[index]`).
/// - `list_by(filter = "customer_ref", …)` — the admin `?customer=` filter.
/// - `list_by(filter = "status", …)` — the admin `?status=` filter.
/// - `ranked_by(highest = "created_at")` — the owner's unfiltered, all-apps
///   newest-first feed (no filter column).
#[derive(Model)]
#[model(
    table = "orders",
    list_by(filter = "client_service", newest = "created_at"),
    list_by(filter = "customer_ref", newest = "created_at"),
    list_by(filter = "status", newest = "created_at"),
    ranked_by(highest = "created_at")
)]
pub struct Order {
    #[pk]
    pub id: Id<Order>,
    #[index]
    pub owner_principal: String,
    pub client_service: String,
    #[lookup_by]
    pub stripe_session_id: String,
    pub amount: i64,
    pub currency: String,
    pub status: String, // queued | pending | paid | refunded | canceled | expired | failed
    pub checkout_url: Option<String>,
    pub error: Option<String>,
    pub customer_ref: String, // end-customer attribution; "" = unset
    pub amount_refunded: i64,
    pub metadata: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// A received Stripe webhook event, recorded for dedupe + durable apply.
///
/// - `stripe_event_id` (`#[lookup_by]`) is the natural key the handler dedupes
///   on: it `db_find_by`-pre-checks this id before recording, so a duplicate
///   Stripe redelivery is an idempotent no-op (and the `apply_webhook` job's
///   idempotency key collapses any enqueue race). `#[lookup_by]` is a point-
///   lookup access pattern, not an insert-rejecting unique constraint.
/// - `owner_principal` (`#[index]`) is the deployment owner; `client_service` is
///   resolved from the matched `Order` in the apply job (the webhook itself
///   carries no Boogy identity, so the partition is recovered from the order).
/// - `event_type` is the Stripe event name (e.g. `checkout.session.completed`);
///   `payload` is the raw event JSON; `process_status` tracks apply progress
///   and `processed_at` is set when the apply job completes.
#[derive(Model)]
#[model(table = "webhook_events")]
pub struct WebhookEvent {
    #[pk]
    pub id: Id<WebhookEvent>,
    #[lookup_by]
    pub stripe_event_id: String,
    #[index]
    pub owner_principal: String,
    pub client_service: String,
    pub event_type: String,
    pub payload: String,
    pub received_at: Timestamp,
    pub processed_at: Option<Timestamp>,
    pub process_status: String,
}

/// A client app blocked from creating checkouts by the deployment owner.
///
/// `create_checkout` pre-checks the resolved `client_service` against this table
/// (a `#[lookup_by]` point read) and returns `403` before inserting the order, so
/// a blocked app can't open new payments. `ranked_by(highest = "blocked_at")`
/// backs a keyset-paginated block list (newest first).
#[derive(Model)]
#[model(table = "blocked_clients", ranked_by(highest = "blocked_at"))]
pub struct BlockedClient {
    #[pk]
    pub id: Id<BlockedClient>,
    #[index]
    pub owner_principal: String,
    #[lookup_by]
    pub client_service: String,
    pub reason: Option<String>,
    /// The owner principal that set the block (audit trail).
    pub blocked_by: String,
    pub blocked_at: Timestamp,
}

/// Append-only operator action log, kept in the SERVICE store (the control-plane
/// host audit log records platform actions; a provisionable wasm can't write
/// there). One row per `/admin` MUTATION (refund / cancel / block / unblock /
/// webhook replay), written best-effort after the action commits.
///
/// `ranked_by(highest = "at")` backs the unfiltered keyset log; `list_by(filter =
/// "action", newest = "at")` backs the `?action=` filter.
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
    /// Who performed it — the attested owner principal.
    pub actor: String,
    /// Action verb: `order.refund` | `order.cancel` | `client.block` |
    /// `client.unblock` | `webhook.replay`.
    pub action: String,
    /// The target the action acted on (order id / client_service / event id).
    pub target: Option<String>,
    /// Optional JSON detail (e.g. refund amount, block reason).
    pub detail: Option<String>,
    pub at: Timestamp,
}
