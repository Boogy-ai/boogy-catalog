//! Background-job handler bodies for email-sender.
//!
//! The only job today is `retry_send`: a durable retry of a transient
//! Resend send failure. The HTTP `send` handler inserts the `Message`
//! row (status `queued`, rendered body stored in `body_html`/`body_text`)
//! and enqueues `retry_send` carrying just the message id. The platform
//! re-invokes this handler per the manifest backoff
//! (`max_attempts = 5`, `backoff_ms = 2000`) until it succeeds or
//! dead-letters.
//!
//! Returning `Err(String)` signals a *retryable* failure (the platform
//! backs off and re-runs); returning `Ok(())` marks the job succeeded.

use boogy_sdk::job;
use boogy_sdk::model::Timestamp;

use crate::bindings::boogy::platform::runtime;
use crate::db_get;
use crate::db_update;
use crate::models::Message;
use crate::resend_send;
use crate::Deserialize;
use email_core::SendInput;

/// Payload the `send` handler enqueues for a durable retry. Only the
/// message id travels — the row already holds everything needed to
/// rebuild the Resend request (recipient, sender, subject, rendered
/// body), so the job is fully self-describing on reload.
#[derive(Deserialize)]
pub struct RetryPayload {
    pub message_id: u64,
}

/// Durable retry of one queued message.
///
/// Reloads the `Message` by id, rebuilds the Resend `SendInput` from the
/// stored (already-rendered) columns, and re-issues the outbound call via
/// the same secret-header path the `send` handler uses. On success the row
/// is updated to `sent` (provider id + `sent_at` recorded); on a provider
/// failure the row stays `queued` (last error recorded) and the handler
/// returns `Err(..)` so the platform retries per the manifest backoff.
/// `failed` is TERMINAL and is never set here — see the failure branch for
/// the dead-letter limitation.
///
/// A message already in `sent` state is a no-op success — covers the case
/// where the original synchronous send actually reached Resend but the
/// caller still enqueued a retry (idempotency belt-and-braces).
#[job("retry_send")]
pub fn retry_send(payload: RetryPayload) -> Result<(), String> {
    // independent-writes: the success-path update (→ sent) and the failure-path
    // update (→ failed) are mutually-exclusive branches around one outbound
    // Resend call — exactly one runs per invocation, and outbound_http is denied
    // inside a store tx, so they cannot (and need not) be one transaction.
    let id = payload.message_id;

    let mut msg = db_get::<Message>(id)
        .map_err(|e| format!("reload message {id}: {e:?}"))?
        .ok_or_else(|| format!("message {id} not found"))?;

    // Already delivered — nothing to do.
    if msg.status == "sent" {
        return Ok(());
    }

    let input = SendInput {
        from: msg.from_addr.clone(),
        to: msg.to_addr.clone(),
        subject: msg.subject.clone(),
        html: msg.body_html.clone(),
        text: msg.body_text.clone(),
    };

    match resend_send(&input) {
        Ok(provider_id) => {
            msg.status = "sent".to_string();
            msg.provider_message_id = Some(provider_id);
            msg.sent_at = Some(Timestamp::new(runtime::now_millis() as i64));
            msg.error = None;
            db_update(id, &msg).map_err(|e| format!("update message {id}: {e:?}"))?;
            Ok(())
        }
        Err(err) => {
            // Record the latest error for observability but KEEP the row
            // `queued`: `failed` is TERMINAL (retries exhausted) and we cannot
            // detect the terminal attempt here. The `#[job]` handler surface
            // does not thread the `job-context` (which carries the 1-based
            // `attempts`) through `JobRouter::dispatch`, and even `attempts`
            // alone can't tell us "this is the last try" without `max_attempts`
            // (which the context omits). So we never flip to `failed` early.
            //
            // LIMITATION: when the platform exhausts retries and dead-letters
            // this job, the row is left `queued` (not `failed`). A dead-letter
            // reconciliation hook (sweep DLQ → mark the message `failed`) is
            // future work. Keeping it `queued` is honest; marking `failed` on
            // every transient error was incoherent (it would flip back to
            // `sent` on the next successful retry).
            //
            // Best-effort write — if the bookkeeping update fails we still
            // return the send error so the platform retries.
            msg.error = Some(err.clone());
            let _ = db_update(id, &msg);
            Err(err)
        }
    }
}
