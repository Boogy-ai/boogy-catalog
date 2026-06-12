//! email-sender — a BYO-key Resend transactional-email wrapper (catalog service).
//!
//! The owner binds their own Resend API key (via the admin secrets endpoint);
//! this service templates + sends email through it and keeps a per-owner
//! message log. Pure logic (`{{var}}` template rendering, Resend request-body
//! shaping) lives in the host-testable sibling crate `email-core`
//! (`email_core::{render, resend_body, SendInput}`).
//!
//! `POST /send` + the durable `retry_send` job, the per-owner message log
//! (`GET /messages`, `GET /messages/{id}`), and template CRUD (`POST/GET
//! /templates`, `GET/DELETE /templates/{id}`) are all implemented. Every
//! read/list is principal-scoped (`auth::current_principal` + an owner-column
//! filter, or `auth::load_owned` for single loads, 404-masking
//! missing/not-owned); the template delete sits behind an `auth::owns_resource`
//! guard group.
//!
//! Tables are `#[derive(Model)]` structs (see [`models`]); CRUD goes through
//! the typed `db_*` + `Query` layer (handlers never touch raw column literals).

mod bindings {
    wit_bindgen::generate!({
        world: "service-with-jobs",
        path: "wit",
    });
}

boogy_sdk::wit_glue!(bindings, EmailSender, with_jobs);

use boogy_sdk::jobs::JobSpec;
use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::{Api, JobRouter};

use bindings::boogy::platform::outbound_http;
use email_core::SendInput;

mod jobs;
mod models;
use models::{Message, Template};

struct EmailSender;

impl Api for EmailSender {
    fn init_tables() {
        // Typed registration: each model's schema (columns + the indexes its
        // `#[index]` attrs imply) is created from `#[derive(Model)]`; no
        // hand-built `Table`.
        create_model::<Message>();
        create_model::<Template>();
    }

    fn build_router() -> Router {
        Router::new()
            .info(
                "Email Sender",
                "0.1.0",
                Some("A BYO-key Resend transactional-email wrapper: templated \
                      send through the owner's own Resend key, plus a per-owner \
                      message log and reusable templates."),
            )
            // ── Send ──────────────────────────────────────────────────────
            .summary("Send an email")
            .description("Render (optional template) and send a transactional \
                          email through the owner's Resend key; logs the message.")
            .post("/send", send)

            // ── Messages (read-only log) ──────────────────────────────────
            .summary("List sent messages")
            .description("List the authenticated owner's messages, newest first.")
            .get("/messages", list_messages)
            .summary("Get a message")
            .description("Fetch one of the owner's messages by id (404-masked if \
                          missing or not owned).")
            .get("/messages/{id}", get_message)

            // ── Templates (CRUD) ──────────────────────────────────────────
            .summary("Create a template")
            .description("Create a reusable email template for the authenticated owner.")
            .post("/templates", create_template)
            .summary("List templates")
            .description("List the authenticated owner's templates, newest first.")
            .get("/templates", list_templates)
            .summary("Get a template")
            .description("Fetch one of the owner's templates by id (404-masked if \
                          missing or not owned).")
            .get("/templates/{id}", get_template)
            // Delete is guarded by `owns_resource`: it loads + ownership-checks
            // the row (404-masking missing/not-owned) before the handler runs,
            // so the handler's `db_delete` always targets a real, owned row.
            .group([auth::owns_resource(Template::TABLE, DEFAULT_OWNER_COL, "id")], |g| g
                .summary("Delete a template")
                .description("Delete one of the owner's templates by id (404-masked if \
                              missing or not owned).")
                .delete("/templates/{id}", delete_template))
    }

    fn build_job_router() -> JobRouter {
        JobRouter::new().exact(jobs::retry_send)
    }
}

// ─── Send ────────────────────────────────────────────────────────────────

/// Request body for `POST /send`. Either supply an inline `subject`/`html`/
/// `text`, or a `template_id` (+ `vars`) to render one of the owner's stored
/// templates. `vars` are `(key, value)` pairs substituted into the template's
/// `{{key}}` placeholders.
#[derive(Deserialize, schemars::JsonSchema)]
struct SendReq {
    to: String,
    from: String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    html: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    template_id: Option<String>,
    #[serde(default)]
    vars: Vec<(String, String)>,
}

/// Response for `POST /send`: the persisted message id and its lifecycle status
/// (`queued` while a retry may be in flight, `sent` once delivered).
#[derive(Serialize, schemars::JsonSchema)]
struct SendResult {
    message_id: u64,
    status: String,
}

/// Send a transactional email through the owner's BYO Resend key.
///
/// Flow: resolve the body (inline or rendered from a stored template) →
/// insert a `queued` `Message` row (storing the *rendered* body so a retry
/// can resend without re-rendering) → call Resend via the secret-header
/// outbound path. On a 2xx the row is updated to `sent`; on any provider
/// failure/timeout a durable `retry_send` job is enqueued and the row stays
/// `queued` (the last error is recorded for observability) — the call returns
/// `queued`, matching the row, and the platform retries per the manifest
/// backoff.
///
/// # Status model
///
/// `queued` (pending; a retry may be in flight) → `sent` (delivered) is the
/// happy path; `failed` is TERMINAL (retries exhausted) and is the *only*
/// other end state. A message mid-retry is `queued`, never `failed`. This
/// keeps the row coherent with the response and with the `status` index the
/// message log filters on.
///
/// # Multi-write
///
/// This handler does an insert (queued) followed by a later update (sent) —
/// but the two writes straddle an `outbound_http` call, and `outbound_http`
/// is *denied* while a store `tx` is open. So they cannot be one transaction;
/// they are genuinely independent writes (the queued row is a durable,
/// observable intermediate state, and the update/enqueue reconcile it after
/// the external call returns). See the `// independent-writes:` marker below.
fn send(Json(body): Json<SendReq>) -> Result<Json<SendResult>, ApiError> {
    // independent-writes: insert (queued) and the success-update / retry-enqueue
    // straddle the Resend outbound call; outbound_http is denied inside an open
    // store tx, so these writes cannot be atomic by construction. The `queued` row
    // is a durable intermediate state the retry job reconciles.
    let owner = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;

    // Resolve subject + body: a stored template (rendered with `vars`) takes
    // precedence; otherwise the inline fields are used as-is.
    let (subject, html, text) = if let Some(tid) = &body.template_id {
        let tid_u64: u64 = tid
            .parse()
            .map_err(|_| ApiError::bad_request("template_id must be a numeric id"))?;
        let row = auth::load_owned(Template::TABLE, DEFAULT_OWNER_COL, tid_u64)?
            .ok_or_else(ApiError::not_found)?;
        let tpl = Template::from_row(&row);
        let subject = email_core::render(&tpl.subject, &body.vars);
        let html = Some(email_core::render(&tpl.html, &body.vars));
        let text = tpl.text.as_ref().map(|t| email_core::render(t, &body.vars));
        (subject, html, text)
    } else {
        let subject = body
            .subject
            .clone()
            .ok_or_else(|| ApiError::bad_request("subject is required without a template_id"))?;
        if body.html.is_none() && body.text.is_none() {
            return Err(ApiError::bad_request(
                "html or text is required without a template_id",
            ));
        }
        (subject, body.html.clone(), body.text.clone())
    };

    let now = Timestamp::new(now_millis() as i64);

    // Insert the message in `queued` state with the rendered body retained so
    // a durable retry can resend verbatim. `Id::new(0)` is the insert sentinel
    // — the store assigns the real `_id` and returns it.
    let message_id = db_insert(&Message {
        id: Id::new(0),
        owner_principal: owner.clone(),
        to_addr: body.to.clone(),
        from_addr: body.from.clone(),
        subject: subject.clone(),
        body_html: html.clone(),
        body_text: text.clone(),
        template_id: body.template_id.clone(),
        provider_message_id: None,
        status: "queued".to_string(),
        error: None,
        created_at: now,
        sent_at: None,
    })?;

    let input = SendInput {
        from: body.from,
        to: body.to,
        subject,
        html,
        text,
    };

    match resend_send(&input) {
        Ok(provider_id) => {
            // Reload + update to `sent`. The fresh read keeps us robust to a
            // concurrent retry having already touched the row.
            if let Some(mut msg) = db_get::<Message>(message_id)? {
                msg.status = "sent".to_string();
                msg.provider_message_id = Some(provider_id);
                msg.sent_at = Some(Timestamp::new(now_millis() as i64));
                msg.error = None;
                db_update(message_id, &msg)?;
            }
            Ok(Json(SendResult { message_id, status: "sent".to_string() }))
        }
        Err(err) => {
            // Record the last error for observability but KEEP the row `queued`:
            // a durable `retry_send` job is about to run, so the message is not
            // terminal. `failed` is reserved for retries-exhausted. This keeps
            // the row coherent with the `status:"queued"` response below (and
            // with the `status` index the message-log filter relies on). The
            // idempotency key collapses duplicate enqueues for the same message.
            if let Some(mut msg) = db_get::<Message>(message_id)? {
                msg.error = Some(err.clone());
                db_update(message_id, &msg)?;
            }
            jobs_enqueue(JobSpec {
                handler: "retry_send".to_string(),
                payload: json::to_vec(&json::json!({ "message_id": message_id }))
                    .map_err(|e| ApiError::internal(format!("encode retry payload: {e}")))?,
                idempotency_key: Some(format!("retry_send:{message_id}")),
                ..Default::default()
            })
            .map_err(|e| ApiError::internal(format!("enqueue retry: {e}")))?;
            Ok(Json(SendResult { message_id, status: "queued".to_string() }))
        }
    }
}

/// Issue the Resend `POST /emails` call for one message via the secret-header
/// outbound path. Shared by the synchronous `send` handler and the durable
/// `retry_send` job so the provider contract lives in exactly one place.
///
/// On a 2xx, returns the provider message id parsed from the response body
/// (`{"id": "..."}`). Any non-2xx status or transport error returns an
/// `Err(String)` describing the failure — the caller decides whether to
/// enqueue a retry (handler) or signal a retryable job failure (job).
///
/// # Secret injection
///
/// The bearer credential is *not* in wasm. We pass the pair
/// `("Authorization", "resend_api_key")` in `secret_headers`; the host
/// resolves the manifest-declared `resend_api_key` secret and injects its
/// value **verbatim** as the `Authorization` header at the wire edge. The
/// operator therefore binds the full header value (e.g. `Bearer re_...`) —
/// this code adds no `Bearer ` prefix, because the injected value replaces
/// the header outright.
pub(crate) fn resend_send(input: &SendInput) -> Result<String, String> {
    let request = outbound_http::OutboundRequest {
        method: "POST".to_string(),
        url: "https://api.resend.com/emails".to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: Some(email_core::resend_body(input)),
        timeout_ms: Some(8000),
        // (header-name, secret-ref): host injects the bound `resend_api_key`
        // value as the Authorization header; wasm never sees it.
        secret_headers: vec![("Authorization".to_string(), "resend_api_key".to_string())],
    };

    let resp = outbound_http::fetch(&request).map_err(|e| format!("resend fetch: {e:?}"))?;

    if !(200..300).contains(&resp.status) {
        let detail = resp
            .body
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");
        // Bound the provider body before it lands in an error string (and,
        // ultimately, the `error` column): a hostile/large Resend response
        // must not be stored unbounded. Truncate to 512 bytes on a char
        // boundary.
        return Err(format!(
            "resend returned {}: {}",
            resp.status,
            truncate_on_char_boundary(detail, 512)
        ));
    }

    // Parse `{"id": "..."}` from the success body.
    let bytes = resp
        .body
        .ok_or_else(|| "resend success response had no body".to_string())?;
    let parsed: json::Value =
        json::from_slice(&bytes).map_err(|e| format!("parse resend response: {e}"))?;
    parsed
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "resend response missing `id`".to_string())
}

/// Truncate `s` to at most `max` bytes, never splitting a UTF-8 char (so the
/// result is always valid `&str`). Used to cap untrusted provider error bodies
/// before they reach the `error` column.
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    // Walk back from `max` to the nearest char boundary (≤ 4 bytes).
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ─── Messages (read-only log) ─────────────────────────────────────────────

/// Public projection of a `messages` row — the exact shape the message log
/// exposes (no `owner_principal`; the *rendered* `body_html`/`body_text` stay
/// internal). `id` is the store row id; timestamps are epoch-millis integers.
#[derive(Serialize, schemars::JsonSchema)]
struct MessageOut {
    id: u64,
    to_addr: String,
    from_addr: String,
    subject: String,
    template_id: Option<String>,
    provider_message_id: Option<String>,
    status: String,
    error: Option<String>,
    created_at: i64,
    sent_at: Option<i64>,
}

/// List wrapper for `GET /messages` (mirrors shortlinks' `LinksList`).
#[derive(Serialize, schemars::JsonSchema)]
struct MessageList {
    items: Vec<MessageOut>,
    count: usize,
}

/// Project a `messages` row to its public typed DTO (no `owner_principal`).
fn message_out(r: &Row) -> MessageOut {
    let m = Message::from_row(r);
    MessageOut {
        id: m.id.get(),
        to_addr: m.to_addr,
        from_addr: m.from_addr,
        subject: m.subject,
        template_id: m.template_id,
        provider_message_id: m.provider_message_id,
        status: m.status,
        error: m.error,
        created_at: m.created_at.get(),
        sent_at: m.sent_at.map(|t| t.get()),
    }
}

/// List the authenticated owner's messages, newest first.
///
/// Owner-scoped equality seek on the `owner_principal` index, `_id` desc for
/// newest-first (mirrors shortlinks' `list_links`). `find_owned` returns rows
/// unordered, so the `Query` DSL is used here to add the ordering.
fn list_messages(_req: &mut Req<'_>) -> Result<Json<MessageList>, ApiError> {
    let principal = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    let rows = Query::on(Message::TABLE)
        .where_eq(DEFAULT_OWNER_COL, principal.as_str())
        .order_by_desc("_id")
        .fetch_all()?;
    let items: Vec<MessageOut> = rows.iter().map(message_out).collect();
    let count = items.len();
    Ok(Json(MessageList { items, count }))
}

/// Fetch one of the owner's messages by id (404-masked if missing or not owned).
///
/// `auth::load_owned` loads the row only when it exists AND belongs to the
/// caller; `None` (missing or someone else's) is masked to 404.
fn get_message(req: &mut Req<'_>) -> Result<Json<MessageOut>, ApiError> {
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let row = auth::load_owned(Message::TABLE, DEFAULT_OWNER_COL, id)?
        .ok_or_else(ApiError::not_found)?;
    Ok(Json(message_out(&row)))
}

// ─── Templates (CRUD) ─────────────────────────────────────────────────────

/// Request body for `POST /templates`.
#[derive(Deserialize, schemars::JsonSchema)]
struct CreateTemplate {
    name: String,
    subject: String,
    html: String,
    #[serde(default)]
    text: Option<String>,
}

/// Public projection of a `templates` row — the exact shape template reads
/// expose (no `owner_principal`). `id` is the store row id; timestamps are
/// epoch-millis integers.
#[derive(Serialize, schemars::JsonSchema)]
struct TemplateOut {
    id: u64,
    name: String,
    subject: String,
    html: String,
    text: Option<String>,
    created_at: i64,
    updated_at: i64,
}

/// List wrapper for `GET /templates`.
#[derive(Serialize, schemars::JsonSchema)]
struct TemplateList {
    items: Vec<TemplateOut>,
    count: usize,
}

/// Project a `templates` row to its public typed DTO (no `owner_principal`).
fn template_out(r: &Row) -> TemplateOut {
    let t = Template::from_row(r);
    TemplateOut {
        id: t.id.get(),
        name: t.name,
        subject: t.subject,
        html: t.html,
        text: t.text,
        created_at: t.created_at.get(),
        updated_at: t.updated_at.get(),
    }
}

/// Create a reusable email template for the authenticated owner.
///
/// Single typed insert with `owner_principal = current_principal()`
/// (unauthenticated → 401). `Id::new(0)` is the insert sentinel; the store
/// assigns the real `_id` and returns it.
fn create_template(Json(input): Json<CreateTemplate>) -> Result<Created<TemplateOut>, ApiError> {
    let owner = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    let now = Timestamp::new(now_millis() as i64);
    let id = db_insert(&Template {
        id: Id::new(0),
        owner_principal: owner,
        name: input.name.clone(),
        subject: input.subject.clone(),
        html: input.html.clone(),
        text: input.text.clone(),
        created_at: now,
        updated_at: now,
    })?;
    Ok(Created(TemplateOut {
        id,
        name: input.name,
        subject: input.subject,
        html: input.html,
        text: input.text,
        created_at: now.get(),
        updated_at: now.get(),
    }))
}

/// List the authenticated owner's templates, newest first.
fn list_templates(_req: &mut Req<'_>) -> Result<Json<TemplateList>, ApiError> {
    let principal = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    let rows = Query::on(Template::TABLE)
        .where_eq(DEFAULT_OWNER_COL, principal.as_str())
        .order_by_desc("_id")
        .fetch_all()?;
    let items: Vec<TemplateOut> = rows.iter().map(template_out).collect();
    let count = items.len();
    Ok(Json(TemplateList { items, count }))
}

/// Fetch one of the owner's templates by id (404-masked if missing or not owned).
fn get_template(req: &mut Req<'_>) -> Result<Json<TemplateOut>, ApiError> {
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let row = auth::load_owned(Template::TABLE, DEFAULT_OWNER_COL, id)?
        .ok_or_else(ApiError::not_found)?;
    Ok(Json(template_out(&row)))
}

/// Delete one of the owner's templates by id.
///
/// The `auth::owns_resource` guard (declared on the route group) already
/// confirmed the row exists and is owned by the caller (404-masking
/// otherwise), so the delete always targets a real, owned row.
fn delete_template(req: &mut Req<'_>) -> Result<NoContent, ApiError> {
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    db_delete::<Template>(id)?;
    Ok(NoContent)
}

