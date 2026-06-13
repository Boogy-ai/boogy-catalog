//! stripe-base — a BYO-key Stripe Checkout wrapper (catalog service).
//!
//! The provisioner binds their own Stripe secret + webhook signing secret
//! (via the admin secrets endpoint); this service creates hosted Checkout
//! Sessions through the secret-header outbound path, records orders, and
//! applies signature-verified completion webhooks durably. Pure logic (Stripe
//! checkout form-body shaping, `Stripe-Signature` parsing + signed-message
//! construction + replay tolerance) lives in the host-testable sibling crate
//! `stripe-base-core` (`stripe_base_core::{checkout_form_body, stripe_sig_parts}`).
//!
//! ## Multi-client-service model
//!
//! ONE provisioned deployment fronts MANY of the provisioner's own client apps.
//! Orders are partitioned by `client_service` (which app) on top of
//! `owner_principal` (the deployment owner). See [`models`] for the partition
//! derivation rules. The deployment owner lists across all apps; a client app
//! sees only its own partition.
//!
//! ## Ingress posture + in-handler authorization
//!
//! The service-wide ingress default is plain `mode = "authenticated"` — NO owner
//! is hardcoded (the module is provisionable by anyone, so it cannot bake in one
//! provisioner's id). The anonymous Stripe `POST /webhook` callback carves out
//! `mode = "public"` via a single `[[ingress.routes]]` override (authenticated by
//! HMAC signature in-handler, not by identity).
//!
//! Cross-owner authorization is NOT an ingress allowlist — it lives in the
//! handler's [`audience()`], which derives the caller's owner from the ATTESTED
//! identity (workload URI, or the owner's agent via `caller_is_service_owner`)
//! and compares it to the service owner: one of the owner's own apps → that app's
//! partition; the owner's agent → all apps; a different owner's workload / a
//! non-owner agent / anon → `Denied` (403). So cross-client AND cross-owner
//! isolation both hold in-handler, host-attested, correct for every provisioner.
//!
//! Tables are `#[derive(Model)]` structs (see [`models`]); CRUD goes through
//! the typed `db_*` + `Query` layer (handlers never touch raw column literals).

mod bindings {
    wit_bindgen::generate!({
        world: "service-with-jobs",
        path: "wit",
    });
}

boogy_sdk::wit_glue!(bindings, StripeBase, with_jobs);

use boogy_sdk::jobs::JobSpec;
use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::pagination::{decode, CursorPage};
use boogy_sdk::store::{SortDir, Val};
use boogy_sdk::{Api, JobRouter};

use bindings::boogy::platform::outbound_http;
use stripe_base_core::CheckoutInput;

mod jobs;
mod models;
use models::{AdminAudit, BlockedClient, Order, WebhookEvent};

/// Sentinel `client_service` for the provisioner's OWN direct checkouts — a
/// direct (agent) caller who supplies no `client_ref`. Collision-proof against
/// any real app name: service ids are ASCII alphanumeric / `-` / `_` only (see
/// the host's `validate_path_segment`), so a value containing `/` can NEVER be
/// a valid service id and therefore never collides with a real client app's
/// attested partition.
const OWNER_SENTINEL: &str = "_owner/direct";

struct StripeBase;

impl Api for StripeBase {
    fn init_tables() {
        // Typed registration: each model's schema (columns + the indexes its
        // `#[index]` / `#[lookup_by]` attrs imply) is created from the
        // `#[derive(Model)]` definition; no hand-built `Table`.
        create_model::<Order>();
        create_model::<WebhookEvent>();
        create_model::<BlockedClient>();
        create_model::<AdminAudit>();
    }

    fn build_router() -> Router {
        Router::new()
            .info(
                "Stripe Gateway",
                "0.1.0",
                Some("A BYO-key Stripe Checkout wrapper: hosted Checkout Sessions \
                      through the provisioner's own Stripe key, signature-verified \
                      completion webhooks, and per-app order tracking. One deployment \
                      fronts many of the provisioner's client apps (orders \
                      partitioned by client_service)."),
            )
            // ── Checkout (management; in-handler authed) ──────────────────
            .summary("Create a Checkout Session")
            .description("Record a queued order for the calling client app and \
                          create a hosted Stripe Checkout Session through the \
                          provisioner's Stripe key. Async by default (a durable, \
                          transaction-safe job creates the session; poll the order \
                          for the URL); set synchronous=true to create it inline \
                          and get the checkout URL in the response.")
            .post("/checkout", create_checkout)

            // ── Orders (management; in-handler authed + client-scoped) ────
            .summary("List orders")
            .description("List orders for the caller. A client app sees only its \
                          own client_service partition; the deployment owner sees \
                          all apps (optional ?client= filter). Newest first.")
            .get("/orders", list_orders)
            .summary("Get an order")
            .description("Fetch a single order by id, scoped to the caller's \
                          client_service partition (404-masked if missing or not \
                          in the caller's partition).")
            .get("/orders/{id}", get_order)

            // ── Operator surface (/admin/*; owner-only via require_owner) ──
            .summary("List orders (operator)")
            .description("Operator-only: keyset-paginated orders across ALL the \
                          provisioner's apps, filterable by client/customer/status \
                          and a created_at from/to window. ?limit= (max 200) + \
                          opaque ?cursor= for paging.")
            .get("/admin/orders", admin_list_orders)
            .summary("Get an order (operator)")
            .description("Operator-only: fetch any order by id (full record, \
                          including owner_principal).")
            .get("/admin/orders/{id}", admin_get_order)
            .summary("Order summary (operator)")
            .description("Operator-only: aggregate stats — counts by status, gross \
                          collected + total refunded, and a per-app breakdown; \
                          optional created_at from/to window.")
            .get("/admin/summary", admin_summary)
            .summary("List client apps (operator)")
            .description("Operator-only: every distinct client_service partition in \
                          this deployment, each with its order count and whether it \
                          is currently blocked from creating checkouts.")
            .get("/admin/clients", admin_list_clients)
            .summary("Block a client app (operator)")
            .description("Operator-only: block a client app from creating new \
                          checkouts (idempotent — re-blocking returns the existing \
                          block). Optional JSON body {reason?}. create_checkout \
                          rejects a blocked app with 403.")
            .post("/admin/clients/{client}/block", admin_block_client)
            .summary("Unblock a client app (operator)")
            .description("Operator-only: lift a client app's block (idempotent — \
                          unblocking an un-blocked app is a no-op 204).")
            .post("/admin/clients/{client}/unblock", admin_unblock_client)
            .summary("Operator audit log")
            .description("Operator-only: append-only log of operator mutations \
                          (block/unblock and, as they land, refund/cancel/replay), \
                          newest-first. Optional ?action= filter; ?limit= (max 200) \
                          + opaque ?cursor= keyset pagination.")
            .get("/admin/audit", admin_list_audit)

            // ── Webhook (PUBLIC — Stripe callback, anonymous) ─────────────
            // Reachable without a Boogy identity (Stripe holds none);
            // authenticated by HMAC signature-verification + event-id dedupe,
            // not by ingress. The manifest carves this one route out to
            // `mode = "public"` via a `[[ingress.routes]]` override, while the
            // service-wide default stays `authenticated` (management routes,
            // owner-scoped in-handler by audience()).
            .summary("Stripe webhook callback")
            .description("Anonymous Stripe event callback: verify the \
                          Stripe-Signature HMAC (host-side), dedupe by event id, \
                          enqueue a durable apply job, and return 200 fast. \
                          Idempotent on the Stripe event id.")
            .post("/webhook", webhook)
    }

    fn build_job_router() -> JobRouter {
        JobRouter::new()
            .exact(jobs::apply_webhook)
            .exact(jobs::create_checkout)
    }
}

// ─── Identity / audience ─────────────────────────────────────────────────────

/// The caller's audience for this deployment — host-attested, hardcodes NO
/// identity (the module is provisionable by anyone).
///
/// - `ClientApp(name)` — an ATTESTED caller workload OWNED BY THIS SERVICE'S
///   OWNER (one of the provisioner's own apps). `name` is the host-set workload
///   service id (unspoofable); reads/writes scope to its `client_service` partition.
/// - `Owner` — the SERVICE OWNER themselves (their agent token, attested by the
///   `caller_is_service_owner` capability). Sees ALL apps' orders (optional
///   `?client=` filter) and may target an explicit `client_ref` on checkout.
/// - `Denied` — anyone else: a DIFFERENT owner's workload, a non-owner agent, or
///   anonymous. Management handlers reject this with `403`.
enum Audience {
    ClientApp(String),
    Owner,
    Denied,
}

/// Resolve the caller's audience from the ATTESTED identity (never the body),
/// enforcing cross-owner isolation in-handler — no hardcoded identity, no
/// owner-scoped ingress allowlist.
///
/// 1. An attested caller workload (the `principal`, or the OBO `actor`) must be
///    owned by THIS service's owner to be a client app. A different owner's
///    workload → `Denied` (it is not an app of this deployment).
/// 2. Otherwise the caller is an agent: only the SERVICE OWNER's agent (attested
///    by `caller_is_service_owner()`) is the `Owner`; any other agent / anonymous
///    → `Denied`.
fn audience() -> Audience {
    let our_owner = self_identity().owner;
    let identity = bindings::boogy::platform::auth::current_identity();
    let principal = identity.as_ref().map(|i| i.principal.as_str()).unwrap_or("");
    let actor = identity.as_ref().and_then(|i| i.actor.as_deref());

    if let Some((wl_owner, service)) = stripe_base_core::workload_owner_service(principal, actor) {
        // An attested workload — but ONLY the service owner's own apps qualify.
        if wl_owner == our_owner {
            return Audience::ClientApp(service);
        }
        return Audience::Denied; // a different owner's workload
    }
    // No attested workload → an agent. Only the service owner's agent is Owner.
    if caller_is_service_owner() {
        return Audience::Owner;
    }
    Audience::Denied // anonymous, or a non-owner agent
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
    /// Optional end-customer attribution (e.g. your user id / email). Stored on the
    /// order and filterable by the owner via `GET /admin/orders?customer=…`.
    #[serde(default)]
    customer_ref: Option<String>,
    /// Default `false` → enqueue a durable `create_checkout` job (transaction-safe;
    /// the request path makes NO outbound call) and return `queued`. `true` → call
    /// Stripe inline and return `pending` with the `checkout_url` (falls back to the
    /// durable job if the inline call fails).
    #[serde(default)]
    synchronous: bool,
}

/// Response for `POST /checkout`: the recorded order's id, its lifecycle status,
/// and (when already created) the hosted Stripe Checkout URL the caller redirects
/// the buyer to.
#[derive(Serialize, schemars::JsonSchema)]
struct CheckoutCreated {
    order_id: u64,
    /// `queued` (async — the durable job will create the session) or `pending`
    /// (created inline via `synchronous: true`).
    status: String,
    /// The hosted Stripe Checkout URL. Present once the session exists (sync
    /// success); `null` for a `queued` order — poll `GET /orders/{id}` for it.
    checkout_url: Option<String>,
}

/// Create a hosted Stripe Checkout Session for the calling client app.
///
/// Resolves the `client_service` partition (ATTESTED workload wins; else an
/// explicit `client_ref`; else the owner sentinel) and inserts a `queued` order.
/// Then DEFAULT (async): enqueues the durable `create_checkout` job and returns
/// `{ order_id, status: "queued", checkout_url: null }` — the request path makes
/// NO outbound call, so it is transaction-safe (usable inside a caller `tx`).
/// `synchronous: true`: calls Stripe inline and returns `pending` with the URL,
/// falling back to the durable job (and `queued`) if the inline call fails.
fn create_checkout(Json(body): Json<CheckoutReq>) -> Result<Json<CheckoutCreated>, ApiError> {
    // independent-writes: the `queued` insert and the enqueue (async) / inline
    // Stripe call (sync) straddle a job-enqueue or an outbound call, neither of
    // which is allowed inside an open store tx — so they cannot be atomic by
    // construction. The enqueue stages in the transaction outbox, so inside a
    // CALLER tx the queued order + the staged create_checkout job still commit
    // together (the whole point of the async default: payments in a transaction).
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
        Audience::Denied => return Err(ApiError::forbidden("not the owner or one of their apps")),
    };

    // Operator block list: a blocked client APP cannot open new checkouts. The
    // owner's own direct partition (OWNER_SENTINEL) is exempt — a stray block row
    // must never lock the owner out of their own direct checkouts.
    if client_service != OWNER_SENTINEL && is_client_blocked(&client_service)? {
        return Err(ApiError::forbidden("client app is blocked from creating checkouts"));
    }

    let now = Timestamp::new(now_millis() as i64);
    let metadata = body.metadata.as_ref().map(|m| m.to_string());

    // Insert the order as `queued`: no Stripe session yet (id empty, url null).
    // The dispatch below fills them.
    let order_id = db_insert(&Order {
        id: Id::new(0),
        owner_principal,
        client_service,
        stripe_session_id: String::new(),
        amount: body.amount,
        currency: body.currency.clone(),
        status: "queued".to_string(),
        checkout_url: None,
        error: None,
        customer_ref: body.customer_ref.clone().unwrap_or_default(),
        amount_refunded: 0,
        metadata,
        created_at: now,
        updated_at: now,
    })?;

    let input = CheckoutInput {
        amount: body.amount,
        currency: body.currency.clone(),
        product_name: body.product_name.clone(),
        success_url: body.success_url.clone(),
        cancel_url: body.cancel_url.clone(),
    };

    // Default: enqueue the durable job; return immediately (no outbound here).
    if !body.synchronous {
        enqueue_create_checkout(order_id, &input)?;
        return Ok(Json(CheckoutCreated {
            order_id,
            status: "queued".to_string(),
            checkout_url: None,
        }));
    }

    // Synchronous: create the session inline. Stripe Idempotency-Key keyed on the
    // order so the inline call and any later job retry resolve to the SAME session.
    match create_stripe_session(&input, Some(&order_idempotency_key(order_id))) {
        Ok((session_id, checkout_url)) => {
            set_order_pending(order_id, &session_id, &checkout_url)
                .map_err(ApiError::internal)?;
            Ok(Json(CheckoutCreated {
                order_id,
                status: "pending".to_string(),
                checkout_url: Some(checkout_url),
            }))
        }
        Err(e) => {
            // Record the detail and fall back to the durable job (stays `queued`).
            record_checkout_error(order_id, &format!("{e:?}"));
            enqueue_create_checkout(order_id, &input)?;
            Ok(Json(CheckoutCreated {
                order_id,
                status: "queued".to_string(),
                checkout_url: None,
            }))
        }
    }
}

/// Stripe `Idempotency-Key` for an order's checkout-session creation. Stable per
/// order, so the inline `synchronous` call and any subsequent durable-job retry
/// resolve to the SAME Stripe session (no duplicate session, no double charge).
pub(crate) fn order_idempotency_key(order_id: u64) -> String {
    format!("order:{order_id}")
}

/// Enqueue the durable `create_checkout` job for one order (idempotency-keyed on
/// the order id). Stages in the transaction outbox when a `tx` is open. The job
/// payload carries the checkout inputs not persisted on the order row
/// (`product_name`/`success_url`/`cancel_url`).
fn enqueue_create_checkout(order_id: u64, input: &CheckoutInput) -> Result<(), ApiError> {
    jobs_enqueue(JobSpec {
        handler: "create_checkout".to_string(),
        payload: json::to_vec(&json::json!({
            "order_id": order_id,
            "amount": input.amount,
            "currency": input.currency,
            "product_name": input.product_name,
            "success_url": input.success_url,
            "cancel_url": input.cancel_url,
        }))
        .map_err(|e| ApiError::internal(format!("encode checkout payload: {e}")))?,
        idempotency_key: Some(format!("create_checkout:{order_id}")),
        ..Default::default()
    })
    .map_err(|e| ApiError::internal(format!("enqueue create_checkout: {e}")))?;
    Ok(())
}

/// Transition a `queued` order to `pending` with the created session id + URL.
/// Only flips a still-`queued` order (idempotent under job re-delivery; never
/// downgrades a `paid`/`failed` order). Shared by the inline path + the job.
/// Calls publish_order_status after the update — never call this inside an open store tx.
pub(crate) fn set_order_pending(
    order_id: u64,
    session_id: &str,
    checkout_url: &str,
) -> Result<(), String> {
    if let Some(mut o) =
        db_get::<Order>(order_id).map_err(|e| format!("reload order {order_id}: {e:?}"))?
    {
        if o.status == "queued" {
            o.status = "pending".to_string();
            o.stripe_session_id = session_id.to_string();
            o.checkout_url = Some(checkout_url.to_string());
            o.error = None;
            o.updated_at = Timestamp::new(now_millis() as i64);
            db_update(order_id, &o).map_err(|e| format!("update order {order_id}: {e:?}"))?;
            publish_order_status(&o);
        }
    }
    Ok(())
}

/// Transition a `queued` order to `failed` with the last error detail (the
/// durable job's terminal outcome). Only flips a still-`queued` order. Shared.
/// Calls publish_order_status after the update — never call this inside an open store tx.
pub(crate) fn set_order_failed(order_id: u64, err: &str) -> Result<(), String> {
    if let Some(mut o) =
        db_get::<Order>(order_id).map_err(|e| format!("reload order {order_id}: {e:?}"))?
    {
        if o.status == "queued" {
            o.status = "failed".to_string();
            o.error = Some(err.to_string());
            o.updated_at = Timestamp::new(now_millis() as i64);
            db_update(order_id, &o).map_err(|e| format!("update order {order_id}: {e:?}"))?;
            publish_order_status(&o);
        }
    }
    Ok(())
}

/// Best-effort: push an `order.status` envelope to the order's customer room.
/// NEVER fails the caller (a dropped publish is reconciled via the snapshot on
/// reconnect or a GET /orders/{id} poll) and is NEVER called inside a `tx`.
/// No-op when the order has no customer_ref (nothing to address).
pub(crate) fn publish_order_status(o: &Order) {
    if o.customer_ref.is_empty() {
        return;
    }
    let data = json::json!({
        "order_id": o.id.get(),
        "status": o.status,
        "amount": o.amount,
        "currency": o.currency,
        "amount_refunded": o.amount_refunded,
        "checkout_url": o.checkout_url,
    });
    let _ = ws_publish_event("orders", &o.customer_ref, "order.status", 1, data);
}

/// Best-effort: record a transient checkout error on the order WITHOUT changing
/// its status (it stays `queued` for the durable job to retry). Failures to
/// record are swallowed — the order is still queued and the job is the source of
/// truth for the eventual outcome.
fn record_checkout_error(order_id: u64, err: &str) {
    if let Ok(Some(mut o)) = db_get::<Order>(order_id) {
        o.error = Some(err.to_string());
        o.updated_at = Timestamp::new(now_millis() as i64);
        let _ = db_update(order_id, &o);
    }
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
///
/// `idempotency_key`, when set, is sent as Stripe's `Idempotency-Key` header so a
/// retried call (the durable job re-running after a partial failure) returns the
/// SAME checkout session instead of creating a duplicate — no double charge.
pub(crate) fn create_stripe_session(
    input: &CheckoutInput,
    idempotency_key: Option<&str>,
) -> Result<(String, String), ApiError> {
    let mut headers = vec![(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    )];
    if let Some(key) = idempotency_key {
        headers.push(("Idempotency-Key".to_string(), key.to_string()));
    }
    let request = outbound_http::OutboundRequest {
        method: "POST".to_string(),
        url: "https://api.stripe.com/v1/checkout/sessions".to_string(),
        headers,
        body: Some(stripe_base_core::checkout_form_body(input).into_bytes()),
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
/// - The OWNER (direct agent caller) sees ALL apps' orders for this deployment,
///   with an optional `?client=<name>` filter to narrow to one app.
///
/// Newest-first; the JSON projection omits nothing sensitive (no secrets are
/// stored on the row) and includes `client_service` (the partition key).
fn list_orders(req: &mut Req<'_>) -> Result<Json<CursorPage<OrderOut>>, ApiError> {
    let (limit, cursor) = page_params(req);
    let page = match audience() {
        // Client app: pinned to its attested partition, query param ignored.
        // Backed by `list_by(filter = "client_service", newest = "created_at")`.
        Audience::ClientApp(name) => Query::on(Order::TABLE)
            .where_eq(Order::CLIENT_SERVICE, name.as_str())
            .keyset_by(Order::CREATED_AT, SortDir::Desc)
            .limit(limit)
            .cursor(cursor)
            .fetch_page(|r| order_out(r))?,
        // Owner: all apps, with an optional ?client= filter. With a filter →
        // the client_service list_by composite; without → the
        // `ranked_by(highest = "created_at")` global feed (no full scan needed).
        Audience::Owner => {
            let mut q = Query::on(Order::TABLE);
            if let Some(client) = req.query("client").filter(|s| !s.is_empty()) {
                q = q.where_eq(Order::CLIENT_SERVICE, client);
            }
            q.keyset_by(Order::CREATED_AT, SortDir::Desc)
                .limit(limit)
                .cursor(cursor)
                .fetch_page(|r| order_out(r))?
        }
        Audience::Denied => {
            return Err(ApiError::forbidden("not the owner or one of their apps"))
        }
    };
    Ok(Json(page))
}

/// Public projection of an `orders` row. Omits `owner_principal` (the
/// deployment-tenancy column); includes `client_service` (the partition key) so
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
    /// The hosted Stripe Checkout URL once the session exists; `null` while
    /// `queued`. Clients poll this endpoint to pick it up for an async order.
    checkout_url: Option<String>,
    /// Last failure detail when `status == "failed"`; `null` otherwise.
    error: Option<String>,
    /// End-customer attribution set at checkout; `""` when unset.
    customer_ref: String,
    /// Running refunded total (minor units); `0` unless refunded.
    amount_refunded: i64,
    metadata: Option<String>,
    created_at: i64,
    updated_at: i64,
}

/// Shared keyset-pagination params for every list endpoint: `?limit=` (default
/// 50, clamped 1..=200) + an opaque `?cursor=` decoded back to a [`Cursor`]
/// (`None` on the first page or a malformed cursor — fail-soft to page one).
fn page_params(req: &mut Req<'_>) -> (usize, Option<boogy_sdk::pagination::Cursor>) {
    let limit = req
        .query("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let cursor = req.query("cursor").and_then(decode);
    (limit, cursor)
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
        checkout_url: o.checkout_url,
        error: o.error,
        customer_ref: o.customer_ref,
        amount_refunded: o.amount_refunded,
        metadata: o.metadata,
        created_at: o.created_at.get(),
        updated_at: o.updated_at.get(),
    }
}

/// Fetch one order by id within the caller's `client_service` partition.
///
/// Deny-by-existence-mask: a client-app caller may load an order ONLY if its
/// `client_service` equals the caller's attested partition; the owner may load
/// any order in the deployment. Missing OR not-in-partition both → 404, so a
/// client app cannot probe for another app's order ids.
fn get_order(req: &mut Req<'_>) -> Result<Json<OrderOut>, ApiError> {
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let row = get_row(Order::TABLE, id)?.ok_or_else(ApiError::not_found)?;

    match audience() {
        // Owner: any order in the deployment is visible.
        Audience::Owner => Ok(Json(order_out(&row))),
        // Cross-client isolation: a client app may load an order ONLY in its own
        // partition; a mismatch is a 404 (identical to "missing"), so a client
        // app cannot probe other apps' ids.
        Audience::ClientApp(name) => {
            if Order::from_row(&row).client_service != name {
                return Err(ApiError::not_found());
            }
            Ok(Json(order_out(&row)))
        }
        // Stranger to this deployment (different owner / non-owner agent / anon).
        Audience::Denied => Err(ApiError::forbidden("not the owner or one of their apps")),
    }
}

// ─── Operator surface (/admin/*; owner-only) ─────────────────────────────────
//
// Every /admin/* handler gates on `require_owner()` first. Ingress is just
// `authenticated`; this is the real gate (host-attested, no hardcoded id).

/// Operator gate for `/admin/*`: the SERVICE OWNER ONLY — their attested agent
/// (the `Owner` audience), host-attested, NO hardcoded identity.
///
/// DELIBERATELY STRICTER than "any workload owned by the owner". `/admin` is a
/// cross-client surface (lists every app's orders; issues refunds), so it gates
/// on `audience() == Owner` — a client-app WORKLOAD owned by the same owner is
/// `ClientApp`, NOT `Owner`, and is rejected. If it were admitted (e.g. via a
/// bare `caller_is_service_owner()`, which is true for ANY owner-workload), one
/// client app could read another app's orders — or refund them — through
/// `/admin`, bypassing the per-client isolation the public routes enforce. The
/// owner operates `/admin` as their own agent (a dashboard authenticated as the
/// owner principal). If backend-workload `/admin` access is ever needed, add an
/// explicit admin-workload allowlist to the manifest — do NOT widen this to all
/// owner-workloads.
fn require_owner() -> Result<(), ApiError> {
    match audience() {
        Audience::Owner => Ok(()),
        _ => Err(ApiError::forbidden("operator (service owner) access required")),
    }
}

/// Operator projection of an `orders` row — the full record INCLUDING
/// `owner_principal` (which the public `OrderOut` omits).
#[derive(Serialize, schemars::JsonSchema)]
struct AdminOrderOut {
    id: u64,
    owner_principal: String,
    client_service: String,
    customer_ref: String,
    stripe_session_id: String,
    amount: i64,
    currency: String,
    status: String,
    checkout_url: Option<String>,
    error: Option<String>,
    amount_refunded: i64,
    metadata: Option<String>,
    created_at: i64,
    updated_at: i64,
}

fn admin_order_out(r: &Row) -> AdminOrderOut {
    let o = Order::from_row(r);
    AdminOrderOut {
        id: o.id.get(),
        owner_principal: o.owner_principal,
        client_service: o.client_service,
        customer_ref: o.customer_ref,
        stripe_session_id: o.stripe_session_id,
        amount: o.amount,
        currency: o.currency,
        status: o.status,
        checkout_url: o.checkout_url,
        error: o.error,
        amount_refunded: o.amount_refunded,
        metadata: o.metadata,
        created_at: o.created_at.get(),
        updated_at: o.updated_at.get(),
    }
}

/// Operator: keyset-paginated, multi-axis order listing across ALL apps.
///
/// Filters (all optional, combine with AND): `client` (client_service),
/// `customer` (customer_ref), `status`, `from`/`to` (created_at epoch-ms range).
/// Newest-first by `created_at`; `?limit=`/`?cursor=` keyset pagination. One
/// equality filter rides its `list_by` composite; the rest are residual filters
/// on the same keyset walk (correct, just not separately index-accelerated).
fn admin_list_orders(req: &mut Req<'_>) -> Result<Json<CursorPage<AdminOrderOut>>, ApiError> {
    require_owner()?;
    let (limit, cursor) = page_params(req);

    let mut q = Query::on(Order::TABLE);
    if let Some(c) = req.query("client").filter(|s| !s.is_empty()) {
        q = q.where_eq(Order::CLIENT_SERVICE, c);
    }
    if let Some(c) = req.query("customer").filter(|s| !s.is_empty()) {
        q = q.where_eq(Order::CUSTOMER_REF, c);
    }
    if let Some(s) = req.query("status").filter(|s| !s.is_empty()) {
        q = q.where_eq(Order::STATUS, s);
    }
    if let Some(from) = req.query("from").and_then(|s| s.parse::<i64>().ok()) {
        q = q.where_gte(Order::CREATED_AT, from);
    }
    if let Some(to) = req.query("to").and_then(|s| s.parse::<i64>().ok()) {
        q = q.where_lte(Order::CREATED_AT, to);
    }
    let page = q
        .keyset_by(Order::CREATED_AT, SortDir::Desc)
        .limit(limit)
        .cursor(cursor)
        .fetch_page(|r| admin_order_out(r))?;
    Ok(Json(page))
}

/// Operator: fetch any order by id (full record). Owner-only — no partition mask.
fn admin_get_order(req: &mut Req<'_>) -> Result<Json<AdminOrderOut>, ApiError> {
    require_owner()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let row = get_row(Order::TABLE, id)?.ok_or_else(ApiError::not_found)?;
    Ok(Json(admin_order_out(&row)))
}

#[derive(Serialize, schemars::JsonSchema)]
struct StatusCount {
    status: String,
    count: usize,
}

#[derive(Serialize, schemars::JsonSchema)]
struct ClientStat {
    client_service: String,
    orders: usize,
    /// Sum of `amount` for `paid`/`refunded` orders in this partition.
    paid_amount: i64,
}

/// Aggregate operator stats over the orders table.
#[derive(Serialize, schemars::JsonSchema)]
struct AdminSummary {
    total_orders: usize,
    by_status: Vec<StatusCount>,
    /// Sum of `amount` over `paid` + `refunded` orders (gross collected).
    total_paid_amount: i64,
    /// Sum of `amount_refunded` over all orders.
    total_refunded: i64,
    by_client: Vec<ClientStat>,
}

/// Operator: aggregate summary (counts by status, gross/refunded totals, per-app
/// breakdown), with an optional `from`/`to` (created_at epoch-ms) window.
///
/// independent-reads: this aggregates the whole orders table in one full ordered
/// walk (`allow_full_scan`). Bounded by the deployment's order count; a very
/// high-volume deployment would precompute rollups instead. Acceptable for v1.
fn admin_summary(req: &mut Req<'_>) -> Result<Json<AdminSummary>, ApiError> {
    require_owner()?;
    let mut q = Query::on(Order::TABLE);
    if let Some(from) = req.query("from").and_then(|s| s.parse::<i64>().ok()) {
        q = q.where_gte(Order::CREATED_AT, from);
    }
    if let Some(to) = req.query("to").and_then(|s| s.parse::<i64>().ok()) {
        q = q.where_lte(Order::CREATED_AT, to);
    }
    let rows = q
        .allow_full_scan("operator summary aggregates the whole orders table")
        .fetch_all()?;

    let mut status_counts: Vec<(String, usize)> = Vec::new();
    let mut client_stats: Vec<(String, usize, i64)> = Vec::new();
    let mut total_paid_amount: i64 = 0;
    let mut total_refunded: i64 = 0;

    for r in &rows {
        let o = Order::from_row(r);
        let paid = o.status == "paid" || o.status == "refunded";
        if paid {
            total_paid_amount += o.amount;
        }
        total_refunded += o.amount_refunded;

        match status_counts.iter_mut().find(|(s, _)| s == &o.status) {
            Some((_, c)) => *c += 1,
            None => status_counts.push((o.status.clone(), 1)),
        }
        match client_stats.iter_mut().find(|(c, _, _)| c == &o.client_service) {
            Some((_, n, amt)) => {
                *n += 1;
                if paid {
                    *amt += o.amount;
                }
            }
            None => client_stats.push((
                o.client_service.clone(),
                1,
                if paid { o.amount } else { 0 },
            )),
        }
    }

    Ok(Json(AdminSummary {
        total_orders: rows.len(),
        by_status: status_counts
            .into_iter()
            .map(|(status, count)| StatusCount { status, count })
            .collect(),
        total_paid_amount,
        total_refunded,
        by_client: client_stats
            .into_iter()
            .map(|(client_service, orders, paid_amount)| ClientStat {
                client_service,
                orders,
                paid_amount,
            })
            .collect(),
    }))
}

// ─── Operator: client block list + audit ────────────────────────────────────

/// True if `client_service` is on the operator block list — a single
/// `#[lookup_by]` point read (no scan). `create_checkout` consults this before
/// inserting an order, so a blocked app cannot open new checkouts.
fn is_client_blocked(client_service: &str) -> Result<bool, ApiError> {
    let hits: Vec<BlockedClient> = db_find_by::<BlockedClient>(
        BlockedClient::CLIENT_SERVICE,
        Val::Text(client_service.to_string()),
    )?;
    Ok(!hits.is_empty())
}

/// Append one row to the in-store operator audit log. BEST-EFFORT: a failure to
/// record never fails the mutation it documents (the action already committed).
/// `owner_principal` is the deployment owner (the tenancy/index key); `actor` is
/// the attested principal that performed it (the owner's agent, per `require_owner`).
fn write_admin_audit(action: &str, target: Option<&str>, detail: Option<String>) {
    let _ = db_insert(&AdminAudit {
        id: Id::new(0),
        owner_principal: self_identity().owner,
        actor: auth::current_principal().unwrap_or_default(),
        action: action.to_string(),
        target: target.map(|s| s.to_string()),
        detail,
        at: Timestamp::new(now_millis() as i64),
    });
}

/// One client-app partition in the operator client list.
#[derive(Serialize, schemars::JsonSchema)]
struct ClientInfo {
    client_service: String,
    /// Orders recorded for this app across all statuses.
    orders: usize,
    /// Whether the app is currently blocked from creating checkouts.
    blocked: bool,
}

/// Operator: the deployment's client-app partitions — each distinct
/// `client_service` with its order count and current block status.
///
/// independent-reads: one ordered full scan of the orders table (bounded by the
/// deployment's order count, same posture as `admin_summary`) tallied per app,
/// overlaid with the (small) block list. Acceptable for v1; a high-volume
/// deployment would precompute rollups.
fn admin_list_clients(_req: &mut Req<'_>) -> Result<Json<Vec<ClientInfo>>, ApiError> {
    require_owner()?;

    let order_rows = Query::on(Order::TABLE)
        .allow_full_scan("operator client list aggregates the whole orders table")
        .fetch_all()?;
    let mut counts: Vec<(String, usize)> = Vec::new();
    for r in &order_rows {
        let cs = Order::from_row(r).client_service;
        match counts.iter_mut().find(|(k, _)| *k == cs) {
            Some((_, n)) => *n += 1,
            None => counts.push((cs, 1)),
        }
    }

    let blocked: Vec<String> = Query::on(BlockedClient::TABLE)
        .allow_full_scan("operator client list overlays the (small) block list")
        .fetch_all()?
        .iter()
        .map(|r| BlockedClient::from_row(r).client_service)
        .collect();

    // A pre-emptively blocked client (blocked before it ever created an order)
    // still belongs in the operator's view — surface it with a zero order count.
    for b in &blocked {
        if !counts.iter().any(|(cs, _)| cs == b) {
            counts.push((b.clone(), 0));
        }
    }

    let items = counts
        .into_iter()
        .map(|(client_service, orders)| ClientInfo {
            blocked: blocked.iter().any(|b| *b == client_service),
            client_service,
            orders,
        })
        .collect();
    Ok(Json(items))
}

/// Optional JSON body for `POST /admin/clients/{client}/block`.
#[derive(Deserialize, schemars::JsonSchema)]
struct BlockReq {
    #[serde(default)]
    reason: Option<String>,
}

/// Operator projection of a `blocked_clients` row.
#[derive(Serialize, schemars::JsonSchema)]
struct BlockedClientOut {
    client_service: String,
    reason: Option<String>,
    /// The owner principal that set the block.
    blocked_by: String,
    blocked_at: i64,
}

fn blocked_client_out(b: BlockedClient) -> BlockedClientOut {
    BlockedClientOut {
        client_service: b.client_service,
        reason: b.reason,
        blocked_by: b.blocked_by,
        blocked_at: b.blocked_at.get(),
    }
}

/// Operator: block a client app from creating checkouts (idempotent — re-blocking
/// an already-blocked app returns the existing block, unchanged, with no new audit
/// row). Optional body `{ reason? }`. Writes a `client.block` audit row on a
/// newly-created block.
fn admin_block_client(req: &mut Req<'_>) -> Result<Json<BlockedClientOut>, ApiError> {
    require_owner()?;
    let client = req.params.get("client").unwrap_or("").to_string();
    if client.is_empty() {
        return Err(ApiError::bad_request("missing client path segment"));
    }
    // Body is optional; if present it must parse.
    let reason = match req.body().filter(|b| !b.is_empty()) {
        Some(b) => {
            json::from_slice::<BlockReq>(b)
                .map_err(|e| ApiError::bad_request(format!("invalid request body: {e}")))?
                .reason
        }
        None => None,
    };

    // Idempotent: an existing block for this client wins (no duplicate, no audit).
    let existing: Vec<BlockedClient> =
        db_find_by::<BlockedClient>(BlockedClient::CLIENT_SERVICE, Val::Text(client.clone()))?;
    if let Some(b) = existing.into_iter().next() {
        return Ok(Json(blocked_client_out(b)));
    }

    let now = Timestamp::new(now_millis() as i64);
    // owner_principal = the deployment owner (the stable tenancy/index key);
    // blocked_by = the attested principal that performed the block (the actor),
    // matching write_admin_audit's actor semantics + resend-base's created_by.
    let owner_principal = self_identity().owner;
    let blocked_by = auth::current_principal().unwrap_or_else(|| owner_principal.clone());
    db_insert(&BlockedClient {
        id: Id::new(0),
        owner_principal: owner_principal.clone(),
        client_service: client.clone(),
        reason: reason.clone(),
        blocked_by: blocked_by.clone(),
        blocked_at: now,
    })?;
    write_admin_audit("client.block", Some(&client), reason.clone());
    Ok(Json(BlockedClientOut {
        client_service: client,
        reason,
        blocked_by,
        blocked_at: now.get(),
    }))
}

/// Operator: lift a client app's block (idempotent — a no-op `204` if the app was
/// not blocked). Writes a `client.unblock` audit row only when a block was removed.
fn admin_unblock_client(req: &mut Req<'_>) -> Result<NoContent, ApiError> {
    require_owner()?;
    let client = req.params.get("client").unwrap_or("").to_string();
    if client.is_empty() {
        return Err(ApiError::bad_request("missing client path segment"));
    }
    let hits: Vec<BlockedClient> =
        db_find_by::<BlockedClient>(BlockedClient::CLIENT_SERVICE, Val::Text(client.clone()))?;
    let removed = !hits.is_empty();
    for b in hits {
        db_delete::<BlockedClient>(b.id.get())?;
    }
    if removed {
        write_admin_audit("client.unblock", Some(&client), None);
    }
    Ok(NoContent)
}

/// Operator projection of an `admin_audit` row.
#[derive(Serialize, schemars::JsonSchema)]
struct AuditOut {
    actor: String,
    action: String,
    target: Option<String>,
    detail: Option<String>,
    at: i64,
}

fn audit_out(r: &Row) -> AuditOut {
    let a = AdminAudit::from_row(r);
    AuditOut {
        actor: a.actor,
        action: a.action,
        target: a.target,
        detail: a.detail,
        at: a.at.get(),
    }
}

/// Operator: keyset-paginated operator audit log, newest-first by `at`. An
/// optional `?action=` equality filter rides the `list_by(filter="action",
/// newest="at")` composite; unfiltered uses the `ranked_by(highest="at")` feed.
fn admin_list_audit(req: &mut Req<'_>) -> Result<Json<CursorPage<AuditOut>>, ApiError> {
    require_owner()?;
    let (limit, cursor) = page_params(req);
    let mut q = Query::on(AdminAudit::TABLE);
    if let Some(action) = req.query("action").filter(|s| !s.is_empty()) {
        q = q.where_eq(AdminAudit::ACTION, action);
    }
    let page = q
        .keyset_by(AdminAudit::AT, SortDir::Desc)
        .limit(limit)
        .cursor(cursor)
        .fetch_page(|r| audit_out(r))?;
    Ok(Json(page))
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
/// 2. `stripe_base_core::stripe_sig_parts` parses the header, enforces the replay
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
    let parts = stripe_base_core::stripe_sig_parts(&body, &sig_header, now_s, SIG_TOLERANCE_S)
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

    // The deployment owner of this gateway records the event; the per-app
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
