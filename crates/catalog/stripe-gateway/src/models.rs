//! Typed models for stripe-gateway. Both tables are `#[derive(Model)]`
//! structs — the derive emits the per-field column-name consts
//! (`Order::STATUS`, `WebhookEvent::PROCESS_STATUS`, …), the schema (columns +
//! the indexes its `#[index]` / `#[lookup_by]` attrs imply), and the
//! `from_row`/`to_columns` round-trip, so handlers go through `db_*` + the
//! `Query` DSL and never touch raw column literals. This replaces a
//! hand-written `cols` module.
//!
//! ## Multi-client-service partitioning
//!
//! ONE provisioned stripe-gateway instance fronts MANY of the provisioner's
//! own client apps. Payment data is partitioned on two axes:
//!
//! - `owner_principal` — the instance owner (the provisioner). The SDK's
//!   `DEFAULT_OWNER_COL`; the owner-scoped auth helpers key on it.
//! - `client_service` — WHICH of the provisioner's apps a payment belongs to.
//!   Derived (Task 3.4) from the attested caller workload when called via peer
//!   (`identity.actor` / a workload principal), else an explicit `client_ref`
//!   for direct callers — attested takes precedence so a client cannot
//!   impersonate another. The instance owner lists across ALL apps (optional
//!   `?client=` filter); a client app sees only its own `client_service`
//!   (deny-mask). Both columns are `#[index]` so each scan is an equality seek.

use boogy_sdk::model::{Id, Timestamp};
use boogy_sdk::Model;

/// A single Stripe Checkout Session and its payment state.
///
/// - `owner_principal` (`#[index]`) is the instance-tenancy column the auth
///   helpers seek on; `client_service` (`#[index]`) is the per-app partition.
/// - `stripe_session_id` (`#[lookup_by]`) is the natural key: the webhook-apply
///   job resolves the order from the Stripe session id as a unique point lookup.
/// - `status` is one of `pending` | `paid` | `expired` | `failed`; `#[index]`
///   backs status-filtered listing.
/// - `metadata` holds optional caller JSON; `created_at` / `updated_at` track
///   the lifecycle (`updated_at` bumped when the webhook flips the status).
#[derive(Model)]
#[model(table = "orders")]
pub struct Order {
    #[pk]
    pub id: Id<Order>,
    #[index]
    pub owner_principal: String,
    #[index]
    pub client_service: String,
    #[lookup_by]
    pub stripe_session_id: String,
    pub amount: i64,
    pub currency: String,
    #[index]
    pub status: String, // pending | paid | expired | failed
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
/// - `owner_principal` (`#[index]`) is the instance owner; `client_service` is
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
