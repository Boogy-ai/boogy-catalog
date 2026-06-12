//! Background-job handler bodies for stripe-gateway.
//!
//! The only job is `apply_webhook`: the durable application of a verified,
//! deduped Stripe event. The `POST /webhook` handler verifies the signature
//! (host-side HMAC), records the event (deduped on the Stripe event id),
//! enqueues this job, and returns 200 fast. The platform re-invokes this
//! handler per the manifest backoff (`max_attempts = 5`, `backoff_ms = 2000`)
//! until it succeeds or dead-letters.
//!
//! Returning `Err(String)` signals a *retryable* failure (the platform backs
//! off and re-runs); returning `Ok(())` marks the job succeeded.
//!
//! ## State + partition recovery
//!
//! The webhook carries no Boogy identity, so the `client_service` partition is
//! recovered HERE from the matched `Order` (resolved by the event's Stripe
//! session id), not from the webhook. For `checkout.session.completed` the job
//! flips the order to `paid` and stamps the event `applied` in ONE store `tx`
//! (both writes are pure store ops — no outbound/jobs inside, so they CAN and
//! SHOULD be atomic).
//!
//! ## Transient vs terminal (the email-sender lesson)
//!
//! A `#[job]` body cannot tell which attempt is the terminal one (the
//! `JobRouter::dispatch` surface does not thread `attempts`/`max_attempts`), so
//! we only ever set a TERMINAL `process_status` on a definitive outcome:
//! `applied` (state transition committed) or `no_match` (no order for this
//! session — retrying forever can't help). A TRANSIENT store failure returns
//! `Err(..)` and LEAVES the event in `received`, so the platform's backoff
//! retries it honestly.

use boogy_sdk::job;
use boogy_sdk::model::Timestamp;
use boogy_sdk::store::Val;

use crate::bindings::boogy::platform::runtime;
use crate::models::{Order, WebhookEvent};
use crate::{db_find_by, db_get, db_update, tx, Deserialize};

/// Payload the `webhook` handler enqueues. Only the recorded webhook-event row
/// id travels — the row already holds the raw Stripe payload + event type, so
/// the job is self-describing on reload.
#[derive(Deserialize)]
pub struct ApplyPayload {
    pub webhook_event_id: u64,
}

/// Durable application of one verified Stripe event.
///
/// Reloads the `WebhookEvent` by row id, then:
/// - `checkout.session.completed` → extract `data.object.id` (the Stripe
///   session id), find the matching `Order` by `stripe_session_id`, and in ONE
///   `tx` flip the order to `paid` (+ `updated_at`) AND stamp the event
///   `applied` with the `client_service` recovered FROM THE ORDER (+
///   `processed_at`). No matching order → `no_match` (terminal; a missing order
///   never resolves on retry).
/// - any other event type → `ignored` (terminal; v1 only acts on completion).
///
/// An event already in a terminal state (`applied`/`no_match`/`ignored`) is a
/// no-op success (covers an at-least-once re-delivery of this job).
///
/// A TRANSIENT store error returns `Err(..)`; the event stays `received` and
/// the platform retries per the manifest backoff.
#[job("apply_webhook")]
pub fn apply_webhook(payload: ApplyPayload) -> Result<(), String> {
    let event_row_id = payload.webhook_event_id;

    let event = db_get::<WebhookEvent>(event_row_id)
        .map_err(|e| format!("reload webhook_event {event_row_id}: {e:?}"))?
        .ok_or_else(|| format!("webhook_event {event_row_id} not found"))?;

    // Already terminal — idempotent no-op (job re-delivery / belt-and-braces).
    if event.process_status != "received" {
        return Ok(());
    }

    // v1 only acts on completion; everything else is recorded + ignored.
    if event.event_type != "checkout.session.completed" {
        return finalize_event(event_row_id, /* client_service */ None, "ignored");
    }

    // Extract the Stripe session id (`data.object.id`) from the stored payload.
    let parsed: serde_json::Value = serde_json::from_str(&event.payload)
        .map_err(|e| format!("parse stored payload for event {event_row_id}: {e}"))?;
    let session_id = parsed
        .get("data")
        .and_then(|d| d.get("object"))
        .and_then(|o| o.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let session_id = match session_id {
        Some(s) if !s.is_empty() => s,
        // A completion event with no session id will never match an order —
        // terminal no_match, not an infinite retry.
        _ => return finalize_event(event_row_id, None, "no_match"),
    };

    // Resolve the order (and its partition) by the natural key.
    let order = db_find_by::<Order>(Order::STRIPE_SESSION_ID, Val::Text(session_id.clone()))
        .map_err(|e| format!("lookup order by session {session_id}: {e:?}"))?
        .into_iter()
        .next();

    let order = match order {
        Some(o) => o,
        // Unknown session — no order to mark paid. Terminal (retrying can't
        // conjure an order); record it so the event isn't stuck `received`.
        None => return finalize_event(event_row_id, Some(String::new()), "no_match"),
    };

    let order_id = order.id.get();
    let client_service = order.client_service.clone();
    let now = Timestamp::new(runtime::now_millis() as i64);

    // Multi-write, both pure store ops → ONE atomic tx (no outbound/jobs inside).
    // Re-read inside the tx so a concurrent writer can't be clobbered, and the
    // partition is recovered FROM THE ORDER (not the webhook).
    tx::<_, _, String>(|| {
        let mut order = db_get::<Order>(order_id)
            .map_err(|e| format!("reload order {order_id} in tx: {e:?}"))?
            .ok_or_else(|| format!("order {order_id} vanished mid-tx"))?;
        order.status = "paid".to_string();
        order.updated_at = now;
        db_update(order_id, &order).map_err(|e| format!("update order {order_id}: {e:?}"))?;

        let mut event = db_get::<WebhookEvent>(event_row_id)
            .map_err(|e| format!("reload event {event_row_id} in tx: {e:?}"))?
            .ok_or_else(|| format!("event {event_row_id} vanished mid-tx"))?;
        event.client_service = client_service.clone();
        event.process_status = "applied".to_string();
        event.processed_at = Some(now);
        db_update(event_row_id, &event)
            .map_err(|e| format!("update event {event_row_id}: {e:?}"))?;
        Ok(())
    })
}

/// Stamp the event with a TERMINAL `process_status` (+ `processed_at`, +
/// optional recovered `client_service`) as a single store write. Used for the
/// non-`paid` outcomes (`ignored`, `no_match`) that don't touch an order, so no
/// `tx` is needed. A failure here is transient → `Err(..)` (platform retries).
fn finalize_event(
    event_row_id: u64,
    client_service: Option<String>,
    status: &str,
) -> Result<(), String> {
    let mut event = db_get::<WebhookEvent>(event_row_id)
        .map_err(|e| format!("reload event {event_row_id}: {e:?}"))?
        .ok_or_else(|| format!("event {event_row_id} not found"))?;
    if let Some(cs) = client_service {
        event.client_service = cs;
    }
    event.process_status = status.to_string();
    event.processed_at = Some(Timestamp::new(runtime::now_millis() as i64));
    db_update(event_row_id, &event).map_err(|e| format!("finalize event {event_row_id}: {e:?}"))
}
