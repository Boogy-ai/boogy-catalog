//! resend-base — a BYO-key Resend transactional-email wrapper (catalog service).
//!
//! The provisioner binds their own Resend API key (via the admin secrets
//! endpoint); this service templates + sends email through it, keeps a
//! per-principal message log, and gives the provisioner an operator surface
//! over all of it. Pure logic (`{{ var }}` template rendering, Resend
//! request-body shaping, workload-owner parsing) lives in the host-testable
//! sibling crate `resend-base-core`.
//!
//! ## Send model (async by default)
//!
//! `POST /send` inserts a `queued` message and **enqueues a durable
//! `send_email` job** by default; the job does the Resend call. Because the
//! enqueue stages in the transaction outbox, a caller can wrap `POST /send` in
//! a cross-service `tx` and the email is sent **iff the transaction commits**.
//! `synchronous: true` instead sends inline (and only enqueues `send_email` as
//! a durable retry if the inline call fails) — for fire-now cases outside a tx.
//!
//! ## Two audiences
//!
//! - **End users** (any authenticated principal of the app) use `/send`,
//!   `/send/batch`, `/messages`, `/templates` — every read is principal-scoped
//!   (`auth::current_principal` + an owner-column filter, 404-masking).
//! - **The operator** (the provisioner's OWN backend services) uses `/admin/*`
//!   to list/filter ALL principals' messages and to block/unblock a sender.
//!   `/admin/*` admits only deployed workloads at the ingress layer (`internal`)
//!   and [`require_operator`] narrows them to the SAME owner as this instance —
//!   learned at runtime from the self-identity capability, so NO identity is
//!   hardcoded in the manifest (the module is provisionable by anyone).
//!
//! Tables are `#[derive(Model)]` structs (see [`models`]); CRUD goes through
//! the typed `db_*` + `Query` layer (handlers never touch raw column literals).

mod bindings {
    wit_bindgen::generate!({
        world: "service-with-jobs",
        path: "wit",
    });
}

boogy_sdk::wit_glue!(bindings, ResendBase, with_jobs);

use boogy_sdk::jobs::JobSpec;
use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::store::Val;
use boogy_sdk::{Api, JobRouter};

use bindings::boogy::platform::outbound_http;
use resend_base_core::{render, workload_owner, SendInput};

mod jobs;
mod models;
use models::{BlockedSender, Message, Template};

struct ResendBase;

impl Api for ResendBase {
    fn init_tables() {
        create_model::<Message>();
        create_model::<Template>();
        create_model::<BlockedSender>();
    }

    fn build_router() -> Router {
        Router::new()
            .info(
                "Resend Email Sender",
                "0.2.0",
                Some("A BYO-key Resend transactional-email wrapper: async-by-default \
                      (transaction-safe) templated send through the provisioner's own \
                      Resend key, a per-principal message log, reusable templates, a \
                      batch send, and an operator surface (list-all + sender blocking)."),
            )
            // ── Send ──────────────────────────────────────────────────────
            .summary("Send an email")
            .description("Render (optional template) and send a transactional email \
                          through the owner's Resend key. Async by default (enqueues a \
                          durable job, transaction-safe); set synchronous=true to send \
                          inline.")
            .post("/send", send)
            .summary("Send a batch of emails")
            .description("Send to up to 100 recipients in one call, each its own message \
                          + durable job. Per-recipient render/validation errors are \
                          reported inline (status \"rejected\"); the rest still send.")
            .post("/send/batch", send_batch)

            // ── Messages (read-only log; principal-scoped) ────────────────
            .summary("List sent messages")
            .description("List the authenticated principal's messages, newest first.")
            .get("/messages", list_messages)
            .summary("Get a message")
            .description("Fetch one of the principal's messages by id (404-masked if \
                          missing or not owned).")
            .get("/messages/{id}", get_message)

            // ── Templates (CRUD; principal-scoped) ────────────────────────
            .summary("Create a template")
            .description("Create a reusable email template for the authenticated principal.")
            .post("/templates", create_template)
            .summary("List templates")
            .description("List the authenticated principal's templates, newest first.")
            .get("/templates", list_templates)
            .summary("Get a template")
            .description("Fetch one of the principal's templates by id (404-masked).")
            .get("/templates/{id}", get_template)
            .group([auth::owns_resource(Template::TABLE, DEFAULT_OWNER_COL, "id")], |g| g
                .summary("Delete a template")
                .description("Delete one of the principal's templates by id (404-masked).")
                .delete("/templates/{id}", delete_template))

            // ── Operator surface (/admin/*; owner-only via ingress + require_operator) ─
            .summary("List all messages (operator)")
            .description("Operator-only: list/filter messages across ALL principals. \
                          Filters: ?principal=, ?status=, ?to=, ?since= (epoch-ms), \
                          ?limit= (default 100, max 1000). Newest first.")
            .get("/admin/messages", admin_list_messages)
            .summary("Get any message (operator)")
            .description("Operator-only: fetch any message by id, including its rendered body.")
            .get("/admin/messages/{id}", admin_get_message)
            .summary("Cancel a queued message (operator)")
            .description("Operator-only: cancel a still-queued message; the send job then \
                          no-ops. Returns the resulting status.")
            .post("/admin/messages/{id}/cancel", admin_cancel_message)
            .summary("List blocked senders (operator)")
            .description("Operator-only: list principals blocked from sending.")
            .get("/admin/blocks", admin_list_blocks)
            .summary("Block a sender (operator)")
            .description("Operator-only: block a principal from sending (idempotent). \
                          Subsequent /send calls by that principal return 403.")
            .post("/admin/blocks", admin_create_block)
            .summary("Unblock a sender (operator)")
            .description("Operator-only: remove a sender block.")
            .delete("/admin/blocks/{principal}", admin_delete_block)
    }

    fn build_job_router() -> JobRouter {
        JobRouter::new().exact(jobs::send_email)
    }
}

// ─── Operator identity ─────────────────────────────────────────────────────

/// Operator check for `/admin/*`. This is the PRIMARY gate, and it hardcodes
/// NO identity — the module is provisionable by anyone, so the owner is learned
/// at RUNTIME from the ungated self-identity capability.
///
/// The instance's owner is `self_identity().owner` (host-pinned to whoever
/// provisioned this instance). A caller is the operator iff their ATTESTED
/// workload (the principal, or the OBO `actor`) is owned by that same owner —
/// i.e. one of the provisioner's OWN backend services. The `/admin/*` ingress
/// override already admits only deployed workloads (`internal` mode rejects
/// humans/anonymous); this narrows them to same-owner workloads. A cross-owner
/// workload (which ingress's `["*"]` lets reach the handler) gets 403 here.
///
/// Direct human/dashboard admin access therefore goes through the provisioner's
/// own backend (which calls these routes as a workload) — not a raw agent token,
/// which carries no owner handle a wasm component could verify.
fn require_operator() -> Result<(), ApiError> {
    let our_owner = self_identity().owner;
    let identity = bindings::boogy::platform::auth::current_identity();
    let principal = identity.as_ref().map(|i| i.principal.as_str()).unwrap_or("");
    let actor = identity.as_ref().and_then(|i| i.actor.as_deref());
    match workload_owner(principal).or_else(|| actor.and_then(workload_owner)) {
        Some(o) if o == our_owner => Ok(()),
        _ => Err(ApiError::forbidden("operator access required")),
    }
}

/// True if `principal` is on the block list (a single keyed lookup).
fn is_blocked(principal: &str) -> Result<bool, ApiError> {
    let hits: Vec<BlockedSender> =
        db_find_by::<BlockedSender>(BlockedSender::PRINCIPAL, Val::Text(principal.to_string()))?;
    Ok(!hits.is_empty())
}

// ─── Send (shared core) ────────────────────────────────────────────────────

/// Resolve the subject + body for one send: a stored template (rendered with
/// `vars`) takes precedence; otherwise the inline fields are used as-is. A
/// missing template variable surfaces as a `400` (see `resend_base_core::render`).
fn resolve_body(
    template_id: &Option<String>,
    vars: &[(String, String)],
    subject: &Option<String>,
    html: &Option<String>,
    text: &Option<String>,
) -> Result<(String, Option<String>, Option<String>), ApiError> {
    if let Some(tid) = template_id {
        let tid_u64: u64 = tid
            .parse()
            .map_err(|_| ApiError::bad_request("template_id must be a numeric id"))?;
        let row = auth::load_owned(Template::TABLE, DEFAULT_OWNER_COL, tid_u64)?
            .ok_or_else(ApiError::not_found)?;
        let tpl = Template::from_row(&row);
        let subject = render(&tpl.subject, vars).map_err(|e| ApiError::bad_request(e.to_string()))?;
        let html = Some(render(&tpl.html, vars).map_err(|e| ApiError::bad_request(e.to_string()))?);
        let text = match &tpl.text {
            Some(t) => Some(render(t, vars).map_err(|e| ApiError::bad_request(e.to_string()))?),
            None => None,
        };
        Ok((subject, html, text))
    } else {
        let subject = subject
            .clone()
            .ok_or_else(|| ApiError::bad_request("subject is required without a template_id"))?;
        if html.is_none() && text.is_none() {
            return Err(ApiError::bad_request(
                "html or text is required without a template_id",
            ));
        }
        Ok((subject, html.clone(), text.clone()))
    }
}

/// Insert a `queued` message and dispatch it. Default (async): enqueue a durable
/// `send_email` job and return `queued`. `synchronous`: call Resend inline,
/// return `sent` on success or fall back to enqueuing the durable job (and
/// return `queued`) on failure.
///
/// independent-writes: the insert and the enqueue (or the success-update after
/// the inline Resend call) are separate writes — `background_jobs`/`outbound_http`
/// cannot share a store `tx`. The enqueue stages in the transaction outbox, so
/// inside a caller `tx` the queued row + the staged job commit together.
fn insert_and_dispatch(
    owner: &str,
    to: &str,
    from: &str,
    subject: String,
    html: Option<String>,
    text: Option<String>,
    template_id: Option<String>,
    synchronous: bool,
) -> Result<(u64, String), ApiError> {
    // independent-writes: the queued insert and the enqueue (async) / success-
    // update (sync) straddle a job-enqueue or an outbound Resend call, neither of
    // which is allowed inside an open store tx — so they cannot be atomic by
    // construction. The enqueue stages in the transaction outbox, so inside a
    // caller tx the queued row + the staged send job still commit together.
    let now = Timestamp::new(now_millis() as i64);
    let message_id = db_insert(&Message {
        id: Id::new(0),
        owner_principal: owner.to_string(),
        to_addr: to.to_string(),
        from_addr: from.to_string(),
        subject: subject.clone(),
        body_html: html.clone(),
        body_text: text.clone(),
        template_id,
        provider_message_id: None,
        status: "queued".to_string(),
        error: None,
        created_at: now,
        sent_at: None,
    })?;

    if !synchronous {
        enqueue_send(message_id)?;
        return Ok((message_id, "queued".to_string()));
    }

    // Synchronous: send inline.
    let input = SendInput {
        from: from.to_string(),
        to: to.to_string(),
        subject,
        html,
        text,
    };
    match resend_send(&input) {
        Ok(provider_id) => {
            if let Some(mut msg) = db_get::<Message>(message_id)? {
                msg.status = "sent".to_string();
                msg.provider_message_id = Some(provider_id);
                msg.sent_at = Some(Timestamp::new(now_millis() as i64));
                msg.error = None;
                db_update(message_id, &msg)?;
            }
            Ok((message_id, "sent".to_string()))
        }
        Err(err) => {
            // Record the error and fall back to the durable job (keeps `queued`).
            if let Some(mut msg) = db_get::<Message>(message_id)? {
                msg.error = Some(err);
                db_update(message_id, &msg)?;
            }
            enqueue_send(message_id)?;
            Ok((message_id, "queued".to_string()))
        }
    }
}

/// Enqueue the durable `send_email` job for one message (idempotency-keyed on
/// the message id). Stages in the transaction outbox when a `tx` is open.
fn enqueue_send(message_id: u64) -> Result<(), ApiError> {
    jobs_enqueue(JobSpec {
        handler: "send_email".to_string(),
        payload: json::to_vec(&json::json!({ "message_id": message_id }))
            .map_err(|e| ApiError::internal(format!("encode send payload: {e}")))?,
        idempotency_key: Some(format!("send_email:{message_id}")),
        ..Default::default()
    })
    .map_err(|e| ApiError::internal(format!("enqueue send: {e}")))?;
    Ok(())
}

// ─── Send (HTTP) ───────────────────────────────────────────────────────────

/// Request body for `POST /send`. Supply inline `subject`/`html`/`text`, or a
/// `template_id` (+ `vars`) to render a stored template. `synchronous` (default
/// false) sends inline instead of via the durable job.
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
    #[serde(default)]
    synchronous: bool,
}

/// Response for `POST /send`: the persisted message id and its status
/// (`queued` for async / fell-back; `sent` once an inline send delivered).
#[derive(Serialize, schemars::JsonSchema)]
struct SendResult {
    message_id: u64,
    status: String,
}

/// Send a transactional email (async by default).
fn send(Json(body): Json<SendReq>) -> Result<Json<SendResult>, ApiError> {
    let owner = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    if is_blocked(&owner)? {
        return Err(ApiError::forbidden("sender is blocked"));
    }
    let (subject, html, text) =
        resolve_body(&body.template_id, &body.vars, &body.subject, &body.html, &body.text)?;
    let (message_id, status) = insert_and_dispatch(
        &owner,
        &body.to,
        &body.from,
        subject,
        html,
        text,
        body.template_id.clone(),
        body.synchronous,
    )?;
    Ok(Json(SendResult { message_id, status }))
}

// ─── Batch send ────────────────────────────────────────────────────────────

/// One recipient in a `POST /send/batch` call. Supply inline `subject`/`html`/
/// `text`, or a `template_id` (+ `vars`); a per-recipient `template_id`
/// overrides the batch `default_template_id`.
#[derive(Deserialize, schemars::JsonSchema)]
struct Recipient {
    to: String,
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

/// Request body for `POST /send/batch`. `recipients` must hold 1..=100 entries.
#[derive(Deserialize, schemars::JsonSchema)]
struct BatchReq {
    from: String,
    #[serde(default)]
    default_template_id: Option<String>,
    recipients: Vec<Recipient>,
    #[serde(default)]
    synchronous: bool,
}

/// Per-recipient outcome. `message_id` is set when accepted; `reason` is set
/// when `status == "rejected"` (a render/validation/dispatch failure for that
/// recipient only).
#[derive(Serialize, schemars::JsonSchema)]
struct BatchItem {
    to: String,
    message_id: Option<u64>,
    status: String,
    reason: Option<String>,
}

/// Response for `POST /send/batch`.
#[derive(Serialize, schemars::JsonSchema)]
struct BatchResult {
    items: Vec<BatchItem>,
    count: usize,
    accepted: usize,
    rejected: usize,
}

/// Send to a list of recipients. One bad recipient doesn't sink the batch — its
/// item is `rejected` with a reason; the rest still send. Structural problems
/// (empty / >100 / blocked sender) fail the whole request.
fn send_batch(Json(body): Json<BatchReq>) -> Result<Json<BatchResult>, ApiError> {
    let owner = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    if is_blocked(&owner)? {
        return Err(ApiError::forbidden("sender is blocked"));
    }
    if body.recipients.is_empty() || body.recipients.len() > 100 {
        return Err(ApiError::bad_request(
            "recipients must contain between 1 and 100 entries",
        ));
    }

    let mut items = Vec::with_capacity(body.recipients.len());
    let (mut accepted, mut rejected) = (0usize, 0usize);

    for r in &body.recipients {
        // Per-recipient template overrides the batch default.
        let template_id = r.template_id.clone().or_else(|| body.default_template_id.clone());
        let outcome = resolve_body(&template_id, &r.vars, &r.subject, &r.html, &r.text).and_then(
            |(subject, html, text)| {
                insert_and_dispatch(
                    &owner,
                    &r.to,
                    &body.from,
                    subject,
                    html,
                    text,
                    template_id.clone(),
                    body.synchronous,
                )
            },
        );
        match outcome {
            Ok((message_id, status)) => {
                accepted += 1;
                items.push(BatchItem { to: r.to.clone(), message_id: Some(message_id), status, reason: None });
            }
            Err(e) => {
                rejected += 1;
                items.push(BatchItem {
                    to: r.to.clone(),
                    message_id: None,
                    status: "rejected".to_string(),
                    reason: Some(e.to_string()),
                });
            }
        }
    }

    let count = items.len();
    Ok(Json(BatchResult { items, count, accepted, rejected }))
}

// ─── Resend outbound (shared by sync send + the send_email job) ────────────

/// Issue the Resend `POST /emails` call for one message via the secret-header
/// outbound path. The host injects the bound `resend_api_key` secret as the
/// `Authorization` header (verbatim — the operator binds the full `Bearer re_…`
/// value); the wasm never sees it. Returns the provider message id on success.
pub(crate) fn resend_send(input: &SendInput) -> Result<String, String> {
    let request = outbound_http::OutboundRequest {
        method: "POST".to_string(),
        url: "https://api.resend.com/emails".to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: Some(resend_base_core::resend_body(input)),
        timeout_ms: Some(8000),
        secret_headers: vec![("Authorization".to_string(), "resend_api_key".to_string())],
    };

    let resp = outbound_http::fetch(&request).map_err(|e| format!("resend fetch: {e:?}"))?;

    if !(200..300).contains(&resp.status) {
        let detail = resp
            .body
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");
        return Err(format!(
            "resend returned {}: {}",
            resp.status,
            truncate_on_char_boundary(detail, 512)
        ));
    }

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

/// Truncate `s` to at most `max` bytes without splitting a UTF-8 char, so an
/// untrusted provider error body is bounded before it reaches an error string.
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ─── Messages (read-only log; principal-scoped) ────────────────────────────

/// Public projection of a `messages` row (no `owner_principal`, no stored body).
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

#[derive(Serialize, schemars::JsonSchema)]
struct MessageList {
    items: Vec<MessageOut>,
    count: usize,
}

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

/// List the authenticated principal's messages, newest first.
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

/// Fetch one of the principal's messages by id (404-masked).
fn get_message(req: &mut Req<'_>) -> Result<Json<MessageOut>, ApiError> {
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let row = auth::load_owned(Message::TABLE, DEFAULT_OWNER_COL, id)?
        .ok_or_else(ApiError::not_found)?;
    Ok(Json(message_out(&row)))
}

// ─── Templates (CRUD; principal-scoped) ────────────────────────────────────

#[derive(Deserialize, schemars::JsonSchema)]
struct CreateTemplate {
    name: String,
    subject: String,
    html: String,
    #[serde(default)]
    text: Option<String>,
}

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

#[derive(Serialize, schemars::JsonSchema)]
struct TemplateList {
    items: Vec<TemplateOut>,
    count: usize,
}

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

/// Create a reusable email template for the authenticated principal.
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

fn get_template(req: &mut Req<'_>) -> Result<Json<TemplateOut>, ApiError> {
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let row = auth::load_owned(Template::TABLE, DEFAULT_OWNER_COL, id)?
        .ok_or_else(ApiError::not_found)?;
    Ok(Json(template_out(&row)))
}

/// Delete one of the principal's templates by id (guarded by `owns_resource`).
fn delete_template(req: &mut Req<'_>) -> Result<NoContent, ApiError> {
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    db_delete::<Template>(id)?;
    Ok(NoContent)
}

// ─── Operator surface (/admin/*) ───────────────────────────────────────────

/// Operator projection of a `messages` row — includes `owner_principal` (WHICH
/// principal sent it) and the rendered body, which the principal-scoped log omits.
#[derive(Serialize, schemars::JsonSchema)]
struct AdminMessageOut {
    id: u64,
    owner_principal: String,
    to_addr: String,
    from_addr: String,
    subject: String,
    body_html: Option<String>,
    body_text: Option<String>,
    template_id: Option<String>,
    provider_message_id: Option<String>,
    status: String,
    error: Option<String>,
    created_at: i64,
    sent_at: Option<i64>,
}

#[derive(Serialize, schemars::JsonSchema)]
struct AdminMessageList {
    items: Vec<AdminMessageOut>,
    count: usize,
}

fn admin_message_out(r: &Row) -> AdminMessageOut {
    let m = Message::from_row(r);
    AdminMessageOut {
        id: m.id.get(),
        owner_principal: m.owner_principal,
        to_addr: m.to_addr,
        from_addr: m.from_addr,
        subject: m.subject,
        body_html: m.body_html,
        body_text: m.body_text,
        template_id: m.template_id,
        provider_message_id: m.provider_message_id,
        status: m.status,
        error: m.error,
        created_at: m.created_at.get(),
        sent_at: m.sent_at.map(|t| t.get()),
    }
}

/// Operator-only: list/filter messages across ALL principals.
fn admin_list_messages(req: &mut Req<'_>) -> Result<Json<AdminMessageList>, ApiError> {
    require_operator()?;

    let limit = req
        .query("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);

    let mut q = Query::on(Message::TABLE);
    if let Some(p) = req.query("principal").filter(|s| !s.is_empty()) {
        q = q.where_eq(Message::OWNER_PRINCIPAL, p);
    } else if let Some(s) = req.query("status").filter(|s| !s.is_empty()) {
        q = q.where_eq(Message::STATUS, s);
    } else {
        q = q.allow_full_scan("operator lists across all principals");
    }
    let rows = q.order_by_desc("_id").limit(limit).fetch_all()?;

    // `to` / `since` are not indexed — post-filter the (bounded) page in Rust.
    let to_filter = req.query("to").map(|s| s.to_string());
    let since_filter = req.query("since").and_then(|s| s.parse::<i64>().ok());

    let items: Vec<AdminMessageOut> = rows
        .iter()
        .map(admin_message_out)
        .filter(|m| to_filter.as_ref().is_none_or(|t| &m.to_addr == t))
        .filter(|m| since_filter.is_none_or(|s| m.created_at >= s))
        .collect();
    let count = items.len();
    Ok(Json(AdminMessageList { items, count }))
}

/// Operator-only: fetch any message by id (including its rendered body).
fn admin_get_message(req: &mut Req<'_>) -> Result<Json<AdminMessageOut>, ApiError> {
    require_operator()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let row = get_row(Message::TABLE, id)?.ok_or_else(ApiError::not_found)?;
    Ok(Json(admin_message_out(&row)))
}

/// Result of `POST /admin/messages/{id}/cancel`: the resulting status (`canceled`
/// if it was queued; otherwise the existing terminal status, unchanged).
#[derive(Serialize, schemars::JsonSchema)]
struct CancelResult {
    message_id: u64,
    status: String,
}

/// Operator-only: cancel a still-queued message.
fn admin_cancel_message(req: &mut Req<'_>) -> Result<Json<CancelResult>, ApiError> {
    require_operator()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let mut msg = db_get::<Message>(id)?.ok_or_else(ApiError::not_found)?;
    if msg.status == "queued" {
        msg.status = "canceled".to_string();
        db_update(id, &msg)?;
    }
    Ok(Json(CancelResult { message_id: id, status: msg.status }))
}

#[derive(Serialize, schemars::JsonSchema)]
struct BlockOut {
    principal: String,
    reason: Option<String>,
    created_by: String,
    created_at: i64,
}

#[derive(Serialize, schemars::JsonSchema)]
struct BlockList {
    items: Vec<BlockOut>,
    count: usize,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct CreateBlock {
    principal: String,
    #[serde(default)]
    reason: Option<String>,
}

fn block_out(r: &Row) -> BlockOut {
    let b = BlockedSender::from_row(r);
    BlockOut {
        principal: b.principal,
        reason: b.reason,
        created_by: b.created_by,
        created_at: b.created_at.get(),
    }
}

/// Operator-only: list blocked senders, newest first.
fn admin_list_blocks(_req: &mut Req<'_>) -> Result<Json<BlockList>, ApiError> {
    require_operator()?;
    let rows = Query::on(BlockedSender::TABLE)
        .allow_full_scan("operator lists all blocked senders")
        .order_by_desc("_id")
        .fetch_all()?;
    let items: Vec<BlockOut> = rows.iter().map(block_out).collect();
    let count = items.len();
    Ok(Json(BlockList { items, count }))
}

/// Operator-only: block a principal from sending (idempotent — re-blocking
/// returns the existing block).
fn admin_create_block(Json(body): Json<CreateBlock>) -> Result<Json<BlockOut>, ApiError> {
    require_operator()?;
    let operator = auth::current_principal().unwrap_or_default();

    let existing: Vec<BlockedSender> = db_find_by::<BlockedSender>(
        BlockedSender::PRINCIPAL,
        Val::Text(body.principal.clone()),
    )?;
    if let Some(b) = existing.into_iter().next() {
        return Ok(Json(BlockOut {
            principal: b.principal,
            reason: b.reason,
            created_by: b.created_by,
            created_at: b.created_at.get(),
        }));
    }

    let now = Timestamp::new(now_millis() as i64);
    db_insert(&BlockedSender {
        id: Id::new(0),
        principal: body.principal.clone(),
        reason: body.reason.clone(),
        created_by: operator.clone(),
        created_at: now,
    })?;
    Ok(Json(BlockOut {
        principal: body.principal,
        reason: body.reason,
        created_by: operator,
        created_at: now.get(),
    }))
}

/// Operator-only: remove a sender block. (`{principal}` is a path segment, so
/// this targets agent principals; workload principals are not block targets.)
fn admin_delete_block(req: &mut Req<'_>) -> Result<NoContent, ApiError> {
    require_operator()?;
    let principal = req.params.get("principal").unwrap_or("").to_string();
    let hits: Vec<BlockedSender> =
        db_find_by::<BlockedSender>(BlockedSender::PRINCIPAL, Val::Text(principal))?;
    for b in hits {
        db_delete::<BlockedSender>(b.id.get())?;
    }
    Ok(NoContent)
}
