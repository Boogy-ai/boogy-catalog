# Boogy catalog

First-party, **provisionable** wasm building blocks that tenants deploy with their
own configuration (bring-your-own-key). Each service runs as Rust compiled to
`wasm32-wasip2` on the Boogy runtime, with isolated per-service transactional
storage, capability-based security, and cross-service calls.

These are real services you can deploy into your own tenant: bind your own keys,
get your own isolated instance and data. They double as **canonical best-practice
examples** — each one is written exactly the way the
[Boogy SDK](https://github.com/Boogy-ai/boogy-sdk) recommends, so you can read them
to understand how a production Boogy service is structured.

See [ARCHITECTURE.md](../../ARCHITECTURE.md) for how provisioning and isolation work,
and [boogy.ai](https://boogy.ai) for platform documentation.

---

## Services

### govern-base — Governance engine

Run real decision-making for your community, DAO, cooperative, or app. Members
**propose** changes, gather **co-sponsors**, and **vote** (one member, one vote)
with **quorum, a pass threshold, and a veto gate**. A passed proposal waits out
a **timelock** and then **executes its effects** — calling another service in your
mesh or an external API — exactly as encoded in the proposal. You bring your own
membership list and policy configuration.

**BYO secrets:** no third-party API key required. If your proposals make
authenticated outbound calls, you can bind a named secret out-of-band and reference
it from a proposal action's `secret_header_ref`; it is injected at the wire edge and
never appears in the proposal body.

**Surface:**

| Route | What it does |
|-------|-------------|
| `POST /proposals` | Create a draft proposal with immutable, transparently-encoded actions |
| `GET /proposals` · `GET /proposals/{id}` | List (filterable by `?status=`, `?author=`) / read one |
| `POST /proposals/{id}/submit` | Open co-sponsorship or voting |
| `POST /proposals/{id}/withdraw` | Withdraw before voting ends |
| `POST /proposals/{id}/sponsor` | Endorse a proposal (self-sponsorship blocked) |
| `POST /proposals/{id}/vote` | Cast a ballot: `yes` / `no` / `abstain` / `veto` |
| `GET /proposals/{id}/tally` | Live aggregated tally |
| `POST /proposals/{id}/comments` · `GET …/comments` | Threaded deliberation |
| `/admin/*` | Operator surface: policy config, electorate roll, guardian cancel, replay, audit log |
| `/mcp` | MCP tools (`list_proposals`, `get_proposal`) for LLM clients |

**WebSocket channel:** `proposals` (public, replay buffer) pushes `tally.update`
and `proposal.status` events per proposal as votes are cast and states change.

**Patterns demonstrated:** host-attested in-handler authorization (no hardcoded
owner identity; `audience()` resolves role from the attested principal on every
request), durable exactly-once job execution for proposal effects, live
WebSocket fan-out, an MCP read surface, and pure decision logic in a sibling
`govern-base-core` crate for fast unit testing off-wasm.

---

### resend-base — Transactional email (Resend)

Send transactional email from your app through your own
[Resend](https://resend.com) account. Write a message inline or save reusable
`{{variable}}` templates, send one or a batch, and keep a per-principal message
log. By default sends are queued as durable jobs, so a send can be part of a
cross-service transaction — the email goes out only if the transaction commits.
Operators get a cross-sender view and can block individual senders.

**BYO secrets:**
- `resend_api_key` — your Resend API key. Declared as an outbound-header secret:
  the host injects it as the `Authorization` header on calls to `api.resend.com`.
  The wasm never reads the value.

**Surface:**

| Route | What it does |
|-------|-------------|
| `POST /send` | Send a transactional email (async/durable by default; `synchronous: true` for inline) |
| `POST /send/batch` | Send to up to 100 recipients in one call; per-recipient errors don't fail the batch |
| `GET /messages` · `GET /messages/{id}` | Message log for the authenticated principal |
| `POST /templates` · `GET /templates` · `GET /templates/{id}` · `DELETE /templates/{id}` | Reusable template CRUD, principal-scoped |
| `GET /admin/messages` · `GET /admin/messages/{id}` | Operator: all messages across all principals |
| `POST /admin/messages/{id}/cancel` | Operator: cancel a still-queued message |
| `GET /admin/blocks` · `POST /admin/blocks` · `DELETE /admin/blocks/{principal}` | Operator: sender block list |

**Patterns demonstrated:** durable transaction-safe sends (job stages in the
transaction outbox so a caller can wrap `POST /send` in a `tx` and the email
commits or cancels with it), `{{variable}}` template rendering in a pure
`resend-base-core` crate, two-audience design (end-user routes + operator
`/admin/*`), and outbound-header secret injection.

---

### stripe-base — Payments (Stripe Checkout)

Take payments with Stripe Checkout using your own Stripe account. Send a
customer to a hosted Stripe payment page, record the order, and apply the
completion webhook durably once Stripe confirms payment. Stripe callbacks are
HMAC-signature-verified before any state changes — the signature check runs
host-side against the KMS-wrapped secret, so the wasm never reads it. One
deployment can front multiple of the provisioner's own client apps, with each
app's orders kept in an isolated partition.

**BYO secrets:**
- `stripe_secret_key` — your Stripe secret key. Injected as an outbound-header
  secret on calls to `api.stripe.com`; the wasm never reads it.
- `stripe_webhook_secret` — your Stripe webhook signing secret. Used exclusively
  via the host-side HMAC-verify capability (`hmac-verify` usage): the host
  computes and constant-time-compares the signature; the wasm never sees the key.

**Surface:**

| Route | What it does |
|-------|-------------|
| `POST /checkout` | Create a hosted Stripe Checkout Session (async/durable by default; `synchronous: true` for inline) |
| `GET /orders` · `GET /orders/{id}` | Orders for the caller, scoped to the caller's client-app partition |
| `GET /admin/orders` · `GET /admin/orders/{id}` | Operator: all orders across all apps |
| `GET /admin/summary` | Operator: aggregate stats — counts by status, gross collected, per-app breakdown |
| `GET /admin/clients` | Operator: distinct client-app partitions with order counts and block status |
| `POST /admin/clients/{client}/block` · `/unblock` | Operator: block/unblock a client app from creating checkouts |
| `GET /admin/audit` | Operator: append-only audit log of operator mutations |
| `POST /webhook` | Anonymous Stripe event callback — HMAC-verified host-side, deduped by event id, applied by a durable job |

**WebSocket channel:** `orders` (`class = "principal"`) pushes `order.status`
envelopes to the addressed customer's own room as order states change.

**Patterns demonstrated:** host-side HMAC signature verification for anonymous
webhook callbacks, multi-client-app partitioning from a single deployment,
durable transaction-safe checkout creation (async default works inside a caller
`tx`), idempotency keys to prevent double-charges on retry, and pure logic in
`stripe-base-core` for fast off-wasm testing.

---

## How provisioning works

A catalog service is a **template**: the same wasm binary is correct for every
provisioner because it hardcodes no owner identity. Authorization is resolved
host-side, per request, from the attested caller identity.

When you provision a catalog service:

1. The wasm is deployed into **your tenant** at `boogy://<your-id>/services/<name>`.
2. Your instance gets **its own isolated per-service store** — no data is shared
   with other tenants' instances of the same service.
3. You **bind your own secrets** (API keys, signing secrets) out-of-band via the
   admin endpoint; the service references them by name, not value.
4. You configure the service through its own API (governance policy, member rolls,
   etc.) — changes apply only to your instance.

This is distinct from platform-operated shared services, which are compiled into
the host itself, operate under a mesh-global identity, and share a single instance
across all tenants. Catalog services are sandboxed wasm; platform services are
native Rust compiled into the runtime binary.

See [ARCHITECTURE.md](../../ARCHITECTURE.md) for diagrams.

---

## Conventions every service follows

Every service in this catalog is built the same way. Read any one of them to
understand the others.

**`wit_glue!`** — the macro that wires the WIT interface bindings (`boogy-wit`)
into the service: emits the imports (`auth`, `store`, `clock`, `outbound_http`,
`background_jobs`, `websockets`, …), the standard type aliases
(`Router`, `ApiError`, `Row`, …), and the `create_model` / `db_*` / `Query`
store helpers. The service then exports `impl Api` — `init_tables()` and
`build_router()`.

**`boogy.toml` manifest** — declares the service id and version, routing, ingress
mode (and per-route overrides), the capabilities it requests (`store`, `auth`,
`outbound_http`, …), the outbound host allowlist, secrets (with `usage` tags),
background-job handlers (with deadlines, retry policy, and optional cron schedule),
WebSocket channels, and resource limits. The host enforces the capability envelope
at runtime; no capability is available unless the manifest grants it.

**`#[derive(Model)]` tables** — every persisted table is a typed struct deriving
`Model`. The derive emits the table name (`T::TABLE`), per-field column-name
constants, and index definitions. Handlers go through `db_insert` / `db_get` /
`db_update` / `db_delete` and the `Query` DSL — never raw column-name strings.

**Annotated routes with `JsonSchema` DTOs** — every route has a `.summary()` and
`.description()` annotation on the router. Every request/response type derives
`schemars::JsonSchema` so the auto-generated `GET /openapi.json` document is
complete without a separate spec file.

**Pure logic in a `*-core` crate** — each service separates its host-independent
logic (tally math, template rendering, signature parsing, request-body shaping)
into a sibling `*-core` crate: a plain `rlib` with no runtime dependencies.
Unit tests run in the host's native environment (fast, no wasm toolchain needed),
and the wasm component depends on `*-core` for the logic and calls the platform
capabilities for I/O.

---

## Building

These crates depend on the public SDK as git deps:

```toml
[dependencies]
boogy-sdk = { git = "https://github.com/Boogy-ai/boogy-sdk", rev = "<pin>" }

[build-dependencies]
boogy-wit = { git = "https://github.com/Boogy-ai/boogy-sdk", rev = "<pin>" }
```

Each service has a `build.rs` that syncs the WIT interface files from the pinned
`boogy-wit` into a local `wit/` directory, so `wit_bindgen::generate!` always
sees definitions matching the SDK revision in `Cargo.lock` (the same pattern the
SDK's `smoke/` template uses). The `wit/` directories are generated and gitignored.

```bash
# build the deployable wasm components
cargo build -p resend-base -p stripe-base --target wasm32-wasip2 --release

# run the pure-logic unit tests (the *-core crates)
cargo test --workspace
```

Deploy with the `boogy` CLI:

```bash
boogy deploy --manifest crates/catalog/resend-base/boogy.toml
```

For coding agents, expert skills for building Boogy services are published at
[Boogy-ai/boogy-superpowers](https://github.com/Boogy-ai/boogy-superpowers).
The SDK's `AGENTS.md` is the canonical handler-authoring reference.

---

## License

MIT OR Apache-2.0, at your option.
