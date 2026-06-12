//! Background-job handler bodies for resend-base.
//!
//! The only job is `send_email`: the durable send of one queued message. It is
//! the default send path — `POST /send` inserts the `Message` row (status
//! `queued`, rendered body stored in `body_html`/`body_text`) and enqueues
//! `send_email` carrying just the message id; the job performs the actual
//! Resend call. (A `synchronous: true` send does the Resend call inline and
//! only enqueues `send_email` if that inline call fails.)
//!
//! Because the enqueue stages in the transaction outbox, a caller can wrap
//! `POST /send` in a cross-service `tx`: the send job is submitted iff the
//! transaction commits.
//!
//! Retries ARE the platform re-invoking this handler per the manifest backoff
//! (`max_attempts = 5`, `backoff_ms = 2000`). The handler reads `ctx.attempts`
//! to recognize its terminal attempt and flip the row to `failed` (rather than
//! leaving it `queued`) before returning [`JobError::Terminal`]. A non-terminal
//! transient failure returns [`JobError::Retry`].

use boogy_sdk::job;
use boogy_sdk::model::Timestamp;
use boogy_sdk::{JobContext, JobError};

use crate::bindings::boogy::platform::runtime;
use crate::db_get;
use crate::db_update;
use crate::models::Message;
use crate::resend_send;
use crate::Deserialize;
use resend_base_core::SendInput;

/// Must mirror `[background_jobs.handlers.send_email] max_attempts` in
/// `boogy.toml`. The handler can't read its own manifest at runtime, so the
/// terminal-attempt detection compares `ctx.attempts` against this const.
const MAX_ATTEMPTS: u32 = 5;

/// Payload the send path enqueues. Only the message id travels — the row
/// already holds everything needed to rebuild the Resend request (recipient,
/// sender, subject, rendered body), so the job is self-describing on reload.
#[derive(Deserialize)]
pub struct SendJobPayload {
    pub message_id: u64,
}

/// Durable send of one queued message.
///
/// Reloads the `Message` by id, rebuilds the Resend `SendInput` from the stored
/// (already-rendered) columns, and issues the outbound call via the same
/// secret-header path the synchronous send uses. On success the row is updated
/// to `sent` (provider id + `sent_at` recorded).
///
/// On a provider failure the last error is recorded, then:
/// - if this is the terminal attempt (`ctx.attempts >= MAX_ATTEMPTS`) the row
///   is flipped to `failed` and the handler returns [`JobError::Terminal`] — so
///   the dead-lettered job leaves a coherent `failed` row, not a stuck `queued`
///   one.
/// - otherwise the handler returns [`JobError::Retry`] and the platform backs
///   off and re-runs.
///
/// A message already in a terminal state (`sent` / `failed` / `canceled`) is a
/// no-op success — covers an at-least-once re-delivery of this job and the
/// operator having canceled the message before the job ran.
#[job("send_email")]
pub fn send_email(ctx: JobContext, payload: SendJobPayload) -> Result<(), JobError> {
    // independent-writes: the success-path update (→ sent) and the failure-path
    // update (→ failed, or error-record while keeping queued) are mutually-
    // exclusive branches around one outbound Resend call — exactly one runs per
    // invocation, and outbound_http is denied inside a store tx, so they cannot
    // (and need not) be one transaction.
    let id = payload.message_id;

    let mut msg = db_get::<Message>(id)
        .map_err(|e| JobError::Retry(format!("reload message {id}: {e:?}")))?
        .ok_or_else(|| JobError::Terminal(format!("message {id} not found")))?;

    // Already terminal — nothing to do (delivered, failed, or operator-canceled).
    match msg.status.as_str() {
        "sent" | "failed" | "canceled" => return Ok(()),
        _ => {}
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
            db_update(id, &msg).map_err(|e| JobError::Retry(format!("update message {id}: {e:?}")))?;
            Ok(())
        }
        Err(err) => {
            msg.error = Some(err.clone());
            if ctx.attempts >= MAX_ATTEMPTS {
                // Terminal attempt: record the failure so the dead-lettered job
                // leaves a coherent `failed` row. Best-effort write — even if it
                // fails we still surface Terminal so the platform dead-letters.
                msg.status = "failed".to_string();
                let _ = db_update(id, &msg);
                Err(JobError::Terminal(err))
            } else {
                // Transient: keep `queued`, record the error, let the platform retry.
                let _ = db_update(id, &msg);
                Err(JobError::Retry(err))
            }
        }
    }
}
