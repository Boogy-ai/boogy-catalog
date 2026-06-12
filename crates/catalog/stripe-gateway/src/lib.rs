//! stripe-gateway — a BYO-key Stripe Checkout wrapper (catalog service).
//!
//! The provisioner binds their own Stripe secret + webhook signing secret
//! (via the admin secrets endpoint); this service creates hosted Checkout
//! Sessions through the secret-header outbound path, records orders, and
//! applies signature-verified completion webhooks durably. Pure logic (Stripe
//! checkout form-body shaping, `Stripe-Signature` parsing + signed-message
//! construction + replay tolerance) lives in the host-testable sibling crate
//! `stripe-core` (`stripe_core::{checkout_form_body, stripe_sig_parts}`).
//!
//! ## Multi-client-service model
//!
//! ONE provisioned instance fronts MANY of the provisioner's own client apps.
//! Orders are partitioned by `client_service` (which app) on top of
//! `owner_principal` (the instance owner). See [`models`] for the partition
//! derivation rules. The instance owner lists across all apps; a client app
//! sees only its own partition.
//!
//! ## Ingress posture (per-route — Task 3.4)
//!
//! Per-route ingress. The service-wide default is `mode = "mixed"`: the
//! management routes (`/checkout`, `/orders`, `/orders/{id}`) are reachable
//! ONLY by this owner's own apps (internal branch, `allowed_origins =
//! ["boogy://alice/services/*"]`) OR the provisioner directly (allowlist
//! branch, `allowed_agents = ["alice"]`). The anonymous Stripe `POST /webhook`
//! callback carves out `mode = "public"` via a single `[[ingress.routes]]`
//! override (it is authenticated by HMAC signature in-handler, not by identity).
//!
//! Defense in depth: ingress already rejects strangers from the management
//! routes, AND each management handler derives the ATTESTED `client_service`
//! (host-set workload, unspoofable) and scopes every read/write to it, so a
//! client app can only ever see its own orders — cross-client isolation holds
//! regardless of ingress.
//!
//! Tables are `#[derive(Model)]` structs (see [`models`]); CRUD goes through
//! the typed `db_*` + `Query` layer (handlers never touch raw column literals).

mod bindings {
    wit_bindgen::generate!({
        world: "service-with-jobs",
        path: "wit",
    });
}

boogy_sdk::wit_glue!(bindings, StripeGateway, with_jobs);

use boogy_sdk::jobs::JobSpec;
use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::store::Val;
use boogy_sdk::{Api, JobRouter};

use bindings::boogy::platform::outbound_http;
use stripe_core::CheckoutInput;

mod jobs;
mod models;
use models::{Order, WebhookEvent};

/// Sentinel `client_service` for the provisioner's OWN direct checkouts — a
/// direct (agent) caller who supplies no `client_ref`. Collision-proof against
/// any real app name: service ids are ASCII alphanumeric / `-` / `_` only (see
/// the host's `validate_path_segment`), so a value containing `/` can NEVER be
/// a valid service id and therefore never collides with a real client app's
/// attested partition.
const OWNER_SENTINEL: &str = "_owner/direct";

struct StripeGateway;

impl Api for StripeGateway {
    fn init_tables() {
        // Typed registration: each model's schema (columns + the indexes its
        // `#[index]` / `#[lookup_by]` attrs imply) is created from the
        // `#[derive(Model)]` definition; no hand-built `Table`.
        create_model::<Order>();
        create_model::<WebhookEvent>();
    }

    fn build_router() -> Router {
        Router::new()
            .info(
                "Stripe Gateway",
                "0.1.0",
                Some("A BYO-key Stripe Checkout wrapper: hosted Checkout Sessions \
                      through the provisioner's own Stripe key, signature-verified \
                      completion webhooks, and per-app order tracking. One instance \
                      fronts many of the provisioner's client apps (orders \
                      partitioned by client_service)."),
            )
            // ── Checkout (management; in-handler authed) ──────────────────
            .summary("Create a Checkout Session")
            .description("Create a hosted Stripe Checkout Session through the \
                          provisioner's Stripe key and record a pending order \
                          for the calling client app. Returns the checkout URL \
                          and order id.")
            .post("/checkout", create_checkout)

            // ── Orders (management; in-handler authed + client-scoped) ────
            .summary("List orders")
            .description("List orders for the caller. A client app sees only its \
                          own client_service partition; the instance owner sees \
                          all apps (optional ?client= filter). Newest first.")
            .get("/orders", list_orders)
            .summary("Get an order")
            .description("Fetch a single order by id, scoped to the caller's \
                          client_service partition (404-masked if missing or not \
                          in the caller's partition).")
            .get("/orders/{id}", get_order)

            // ── Webhook (PUBLIC — Stripe callback, anonymous) ─────────────
            // Reachable without a Boogy identity (Stripe holds none);
            // authenticated by HMAC signature-verification + event-id dedupe,
            // not by ingress. The manifest carves this one route out to
            // `mode = "public"` via a `[[ingress.routes]]` override, while the
            // service-wide default stays `mixed` (management routes).
            .summary("Stripe webhook callback")
            .description("Anonymous Stripe event callback: verify the \
                          Stripe-Signature HMAC (host-side), dedupe by event id, \
                          enqueue a durable apply job, and return 200 fast. \
                          Idempotent on the Stripe event id.")
            .post("/webhook", webhook)
    }

    fn build_job_router() -> JobRouter {
        JobRouter::new().exact(jobs::apply_webhook)
    }
}

// ─── Identity / audience ─────────────────────────────────────────────────────

/// The caller's audience for this instance.
///
/// - `ClientApp(name)` — an ATTESTED peer caller (one of the provisioner's own
///   apps). `name` is the host-set workload service id (unspoofable). It scopes
///   every read/write to its own `client_service` partition.
/// - `Owner` — a direct (agent) caller via the allowlist branch: the
///   provisioner themselves. Sees ALL apps' orders (optional `?client=` filter)
///   and, on checkout, may target an explicit `client_ref`.
enum Audience {
    ClientApp(String),
    Owner,
}

/// Resolve the caller's audience from the ATTESTED identity (never the body).
///
/// Reads the raw WIT identity so the OBO `actor` field is visible:
/// `client_service_from_workload` returns the attested workload service id from
/// the principal (direct peer) or the actor (delegated hop). If present, the
/// caller is a client app scoped to that partition; otherwise the caller is the
/// owner (a direct agent admitted by the allowlist branch). Ingress has already
/// rejected anyone who is neither — this is the in-handler partition split, not
/// the authn boundary.
fn audience() -> Audience {
    let identity = bindings::boogy::platform::auth::current_identity();
    let principal = identity.as_ref().map(|i| i.principal.as_str()).unwrap_or("");
    let actor = identity.as_ref().and_then(|i| i.actor.as_deref());
    match stripe_core::client_service_from_workload(principal, actor) {
        Some(name) => Audience::ClientApp(name),
        None => Audience::Owner,
    }
}

// ─── Checkout ──────────────────────────────────────────────────────────────

/// Request body for `POST /checkout`.
///
/// `client_ref` is honored ONLY for a direct owner caller with no attested
/// workload; an attested workload caller's `client_service` is derived from its
/// host-set identity and IGNORES any `client_ref` (no impersonation).
#[derive(Deserialize, schemars::JsonSchema)]
struct CheckoutReq {
    amount: i64,
    currency: String,
    product_name: String,
    success_url: String,
    cancel_url: String,
    #[serde(default)]
    metadata: Option<json::Value>,
    #[serde(default)]
    client_ref: Option<String>,
}

/// Response for `POST /checkout`: the hosted Stripe Checkout URL the caller
/// redirects the buyer to, plus the recorded order's id.
#[derive(Serialize, schemars::JsonSchema)]
struct CheckoutCreated {
    checkout_url: String,
    order_id: u64,
}

/// Create a hosted Stripe Checkout Session for the calling client app.
///
/// Resolves the `client_service` partition (ATTESTED workload wins; else an
/// explicit `client_ref`; else the owner sentinel), calls Stripe
/// `POST /v1/checkout/sessions` via the secret-header outbound path, inserts a
/// `pending` order, and returns `{ checkout_url, order_id }`.
fn create_checkout(Json(body): Json<CheckoutReq>) -> Result<Json<CheckoutCreated>, ApiError> {
    // independent-writes: a single Stripe outbound call followed by a single
    // order insert. `outbound_http` is denied inside an open store tx, so the
    // insert necessarily happens AFTER (and outside) the external call — there
    // is no multi-write transaction to wrap. The order row is written once,
    // post-call, from the Stripe response.
    let owner_principal = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;

    // Derive the partition. Attested workload (host-set) wins; a direct owner
    // caller may pass an explicit client_ref; else the owner sentinel.
    let client_service = match audience() {
        Audience::ClientApp(name) => name,
        Audience::Owner => body
            .client_ref
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| OWNER_SENTINEL.to_string()),
    };

    // Build + issue the Stripe Checkout Session via the secret-header outbound
    // path (the host injects the bound `stripe_secret_key` verbatim as the
    // Authorization header — the operator binds the full `Bearer sk_...` value).
    let (session_id, checkout_url) = create_stripe_session(&CheckoutInput {
        amount: body.amount,
        currency: body.currency.clone(),
        product_name: body.product_name.clone(),
        success_url: body.success_url.clone(),
        cancel_url: body.cancel_url.clone(),
    })?;

    let now = Timestamp::new(now_millis() as i64);
    let metadata = body
        .metadata
        .as_ref()
        .map(|m| m.to_string());

    let order_id = db_insert(&Order {
        id: Id::new(0),
        owner_principal,
        client_service,
        stripe_session_id: session_id,
        amount: body.amount,
        currency: body.currency,
        status: "pending".to_string(),
        metadata,
        created_at: now,
        updated_at: now,
    })?;

    Ok(Json(CheckoutCreated { checkout_url, order_id }))
}

/// Issue the Stripe `POST /v1/checkout/sessions` call via the secret-header
/// outbound path; returns `(session_id, checkout_url)` on success.
///
/// # Secret injection
///
/// The credential is NOT in wasm. We pass `("Authorization", "stripe_secret_key")`
/// in `secret_headers`; the host resolves the manifest-declared secret and
/// injects its value VERBATIM as the `Authorization` header at the wire edge.
/// The operator therefore binds the full header value (`Bearer sk_...`) — this
/// code adds no `Bearer ` prefix.
fn create_stripe_session(input: &CheckoutInput) -> Result<(String, String), ApiError> {
    let request = outbound_http::OutboundRequest {
        method: "POST".to_string(),
        url: "https://api.stripe.com/v1/checkout/sessions".to_string(),
        headers: vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: Some(stripe_core::checkout_form_body(input).into_bytes()),
        timeout_ms: Some(8000),
        secret_headers: vec![("Authorization".to_string(), "stripe_secret_key".to_string())],
    };

    let resp = outbound_http::fetch(&request)
        .map_err(|e| ApiError::internal(format!("stripe fetch: {e:?}")))?;

    if !(200..300).contains(&resp.status) {
        let detail = resp
            .body
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");
        return Err(ApiError::service_unavailable(format!(
            "stripe returned {}: {}",
            resp.status,
            truncate_on_char_boundary(detail, 512)
        )));
    }

    let bytes = resp
        .body
        .ok_or_else(|| ApiError::service_unavailable("stripe success response had no body"))?;
    let parsed: json::Value = json::from_slice(&bytes)
        .map_err(|e| ApiError::service_unavailable(format!("parse stripe response: {e}")))?;
    let session_id = parsed
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::service_unavailable("stripe response missing `id`"))?
        .to_string();
    let checkout_url = parsed
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::service_unavailable("stripe response missing `url`"))?
        .to_string();
    Ok((session_id, checkout_url))
}

/// Truncate `s` to at most `max` bytes without splitting a UTF-8 char, so an
/// untrusted Stripe error body is bounded before it reaches an error string.
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

// ─── Orders ────────────────────────────────────────────────────────────────

/// List the caller's orders, partitioned by `client_service`.
///
/// Dual-audience (the security split):
/// - A CLIENT-APP caller (attested workload) sees ONLY its own `client_service`
///   partition — an equality seek pinned to its host-set service id. Any
///   `?client=` query param is IGNORED (a client app can never read another's
///   orders).
/// - The OWNER (direct agent caller) sees ALL apps' orders for this instance,
///   with an optional `?client=<name>` filter to narrow to one app.
///
/// Newest-first; the JSON projection omits nothing sensitive (no secrets are
/// stored on the row) and includes `client_service` (the partition key).
fn list_orders(req: &mut Req<'_>) -> Result<Json<OrderList>, ApiError> {
    let rows = match audience() {
        // Client app: pinned to its attested partition, query param ignored.
        Audience::ClientApp(name) => Query::on(Order::TABLE)
            .where_eq(Order::CLIENT_SERVICE, name.as_str())
            .order_by_desc("_id")
            .fetch_all()?,
        // Owner: all apps, with an optional ?client= filter.
        Audience::Owner => {
            let mut q = Query::on(Order::TABLE);
            match req.query("client").filter(|s| !s.is_empty()) {
                Some(client) => {
                    q = q.where_eq(Order::CLIENT_SERVICE, client);
                }
                None => {
                    // No partition filter: the whole instance is this owner's,
                    // so a full ordered walk is the intent.
                    q = q.allow_full_scan(
                        "owner audience lists across all client_service partitions",
                    );
                }
            }
            q.order_by_desc("_id").fetch_all()?
        }
    };

    let items: Vec<OrderOut> = rows.iter().map(order_out).collect();
    let count = items.len();
    Ok(Json(OrderList { items, count }))
}

/// Public projection of an `orders` row. Omits `owner_principal` (the
/// instance-tenancy column); includes `client_service` (the partition key) so
/// the owner can tell apps apart. No secret material is stored on the row. `id`
/// is the store row id; timestamps are epoch-millis integers; `metadata` is the
/// caller's opaque JSON, retained verbatim as a string.
#[derive(Serialize, schemars::JsonSchema)]
struct OrderOut {
    id: u64,
    client_service: String,
    stripe_session_id: String,
    amount: i64,
    currency: String,
    status: String,
    metadata: Option<String>,
    created_at: i64,
    updated_at: i64,
}

/// List wrapper for `GET /orders`.
#[derive(Serialize, schemars::JsonSchema)]
struct OrderList {
    items: Vec<OrderOut>,
    count: usize,
}

/// Project an `orders` row to its public typed DTO.
fn order_out(r: &Row) -> OrderOut {
    let o = Order::from_row(r);
    OrderOut {
        id: o.id.get(),
        client_service: o.client_service,
        stripe_session_id: o.stripe_session_id,
        amount: o.amount,
        currency: o.currency,
        status: o.status,
        metadata: o.metadata,
        created_at: o.created_at.get(),
        updated_at: o.updated_at.get(),
    }
}

/// Fetch one order by id within the caller's `client_service` partition.
///
/// Deny-by-existence-mask: a client-app caller may load an order ONLY if its
/// `client_service` equals the caller's attested partition; the owner may load
/// any order in the instance. Missing OR not-in-partition both → 404, so a
/// client app cannot probe for another app's order ids.
fn get_order(req: &mut Req<'_>) -> Result<Json<OrderOut>, ApiError> {
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let row = get_row(Order::TABLE, id)?.ok_or_else(ApiError::not_found)?;

    if let Audience::ClientApp(name) = audience() {
        // Cross-client isolation: mask anything outside the caller's partition.
        // Read the partition column straight off the row; a mismatch is a 404,
        // identical to "missing", so a client app cannot probe other apps' ids.
        let order = Order::from_row(&row);
        if order.client_service != name {
            return Err(ApiError::not_found());
        }
    }
    // Owner audience: any order in the instance is visible.

    Ok(Json(order_out(&row)))
}

// ─── Webhook (public) ────────────────────────────────────────────────────────

/// Acknowledgement for `POST /webhook`: `status` is `received` (a fresh event
/// recorded + apply enqueued) or `duplicate` (a Stripe redelivery deduped to a
/// no-op); `event_id` echoes the Stripe event id the ack pertains to.
#[derive(Serialize, schemars::JsonSchema)]
struct WebhookAck {
    status: String,
    event_id: String,
}

/// Replay-tolerance window (seconds) for the `Stripe-Signature` timestamp.
/// Matches Stripe's documented default — an event older than this (abs diff vs
/// the host clock) is rejected as a stale/replayed signature.
const SIG_TOLERANCE_S: i64 = 300;

/// Anonymous Stripe event callback — authenticated by HMAC SIGNATURE, not by
/// ingress identity (the `[[ingress.routes]] path="/webhook" mode="public"`
/// override admits anonymous callers; Stripe holds no Boogy identity).
///
/// Flow (fast-path, work is durable in the `apply_webhook` job):
/// 1. Read the RAW body bytes + the `Stripe-Signature` header (missing → 400).
/// 2. `stripe_core::stripe_sig_parts` parses the header, enforces the replay
///    tolerance, and builds the signed message `"{t}.{payload}"` + the
///    expected hex MAC (malformed / stale / missing `t`/`v1` → 400).
/// 3. **HOST-VERIFY**: `secrets_verify_hmac_sha256` has the host compute the
///    HMAC over the signed message with the KMS-wrapped `stripe_webhook_secret`
///    and constant-time-compare it to the expected hex. The wasm NEVER sees the
///    secret. `Ok(false)` (forged) → 400; `Err(..)` (unknown/internal) → 400
///    (fail-closed; we do not leak which). A bad/forged signature therefore
///    never reaches dedupe or enqueue.
/// 4. Parse the event `id` + `type` from the JSON body (unparseable → 400).
/// 5. **Dedupe**: a `db_find_by(STRIPE_EVENT_ID, id)` pre-check — Stripe retries
///    a delivered event, so an already-recorded event id → return 200 with no
///    re-insert and no re-enqueue (idempotent; no double-apply).
/// 6. Otherwise insert a `received` `WebhookEvent` and enqueue `apply_webhook`
///    (idempotency-keyed on the event id) — these are two independent writes
///    around the enqueue (`background_jobs` is denied inside a store tx).
/// 7. Return 200 fast; the order state transition happens in the durable job.
///
/// The `client_service` partition is left empty here: the webhook carries no
/// Boogy identity, so the apply job recovers the partition from the matched
/// `Order` (resolved by the event's Stripe session id), not from the webhook.
fn webhook(req: &mut Req<'_>) -> Result<Json<WebhookAck>, ApiError> {
    // independent-writes: the dedupe `WebhookEvent` insert and the `apply_webhook`
    // enqueue are two separate writes — `background_jobs` (the enqueue) is DENIED
    // inside an open store tx, so they cannot be one transaction by construction.
    // The recorded `received` event row is the durable hand-off the apply job
    // reconciles; idempotency on the Stripe event id (pre-check + the job's
    // idempotency key) keeps a Stripe retry a no-op.

    // 1. Raw body + signature header. Missing/empty either → 400 (no identity to
    //    fall back on; a webhook with no signature is unauthenticated).
    let body = req.body().unwrap_or(&[]).to_vec();
    let sig_header = req
        .header("Stripe-Signature")
        .ok_or_else(|| ApiError::bad_request("missing Stripe-Signature header"))?
        .to_string();

    // 2. Parse the signature header + build the signed message (replay-tolerant).
    //    Any malformed/stale header is a flat 400 — we deliberately do not echo
    //    the parser's reason (avoid leaking which check failed).
    let now_s = (now_millis() / 1000) as i64;
    let parts = stripe_core::stripe_sig_parts(&body, &sig_header, now_s, SIG_TOLERANCE_S)
        .map_err(|_| ApiError::bad_request("invalid Stripe-Signature header"))?;

    // 3. HOST-VERIFY the HMAC against the KMS-wrapped `stripe_webhook_secret`.
    //    The wasm never sees the secret. Anything but Ok(true) is a flat 400 so
    //    a forged signature and an unavailable/unknown secret are
    //    indistinguishable to the caller — and neither reaches dedupe/enqueue.
    match crate::secrets_verify_hmac_sha256(
        "stripe_webhook_secret",
        &parts.signed_message,
        &parts.expected_hex,
    ) {
        Ok(true) => { /* verified — proceed */ }
        Ok(false) => return Err(ApiError::bad_request("signature verification failed")),
        Err(_) => return Err(ApiError::bad_request("signature verification failed")),
    }

    // 4. Parse the Stripe event envelope: `id` (event id, the dedupe key) +
    //    `type` (event name). Verified payloads only reach this point.
    let event: json::Value =
        json::from_slice(&body).map_err(|_| ApiError::bad_request("event body is not JSON"))?;
    let event_id = event
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::bad_request("event missing `id`"))?
        .to_string();
    let event_type = event
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // 5. Dedupe pre-check. `#[lookup_by]` on `stripe_event_id` emits a unique
    //    point-lookup access pattern (not an insert-rejecting DB constraint), so
    //    the cleanest correct dedupe is a `db_find_by` pre-check: an already-seen
    //    event id (Stripe redelivery) returns 200 with NO re-insert and NO
    //    re-enqueue. The apply job's idempotency key (`apply_webhook:{id}`) is
    //    the second line of defense against a rare insert/enqueue race.
    let existing: Vec<WebhookEvent> =
        db_find_by::<WebhookEvent>(WebhookEvent::STRIPE_EVENT_ID, Val::Text(event_id.clone()))?;
    if !existing.is_empty() {
        return Ok(Json(WebhookAck { status: "duplicate".to_string(), event_id }));
    }

    // The instance owner of this gateway records the event; the per-app
    // `client_service` partition is resolved later from the matched order.
    let owner_principal = auth::current_principal().unwrap_or_default();
    let payload = String::from_utf8_lossy(&body).into_owned();
    let now = Timestamp::new(now_millis() as i64);

    // 6a. Record the event (status `received`) — the durable hand-off.
    let webhook_event_id = db_insert(&WebhookEvent {
        id: Id::new(0),
        stripe_event_id: event_id.clone(),
        owner_principal,
        // Recovered by the apply job from the matched order, not the webhook.
        client_service: String::new(),
        event_type,
        payload,
        received_at: now,
        processed_at: None,
        process_status: "received".to_string(),
    })?;

    // 6b. Enqueue the durable apply. The idempotency key collapses duplicate
    //     enqueues for the same Stripe event (e.g. an insert/enqueue race).
    jobs_enqueue(JobSpec {
        handler: "apply_webhook".to_string(),
        payload: json::to_vec(&json::json!({ "webhook_event_id": webhook_event_id }))
            .map_err(|e| ApiError::internal(format!("encode apply payload: {e}")))?,
        idempotency_key: Some(format!("apply_webhook:{event_id}")),
        ..Default::default()
    })
    .map_err(|e| ApiError::internal(format!("enqueue apply: {e}")))?;

    // 7. Return 200 fast — the order transition is the job's work.
    Ok(Json(WebhookAck { status: "received".to_string(), event_id }))
}
