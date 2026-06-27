# Boogy catalog

First-party, **provisionable** building-block services for
[Boogy](https://boogy.ai) — Rust compiled to `wasm32-wasip2`, deployed to a
shared runtime with isolated transactional storage, capability-based security,
cross-service calls, durable background jobs, and a built-in MCP surface.

These are real services tenants can deploy with their own configuration
(bring-your-own-key). They double as **canonical best-practice examples**: each
one is written exactly the way the [Boogy SDK](https://github.com/Boogy-ai/boogy-sdk)
recommends, so you can read them to learn how a production Boogy service is
structured.

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the provisioning + isolation
model and the BYO-key flow (with diagrams), and
**[`crates/catalog/README.md`](crates/catalog/README.md)** for a per-service
surface breakdown.

> **Status: early development.** APIs change without notice. These services
> track the SDK; pin a matching git `rev` if you build against them.

## What's here

| Crate | What it is |
|-------|------------|
| `crates/catalog/govern-base` | Governance engine: members **propose → co-sponsor → vote** (quorum, pass threshold, veto), then a **timelock** elapses and the proposal **executes its encoded effects** — a call to another service in your mesh or an external API. Live WebSocket tallies + an MCP read surface; no third-party key required. |
| `crates/catalog/govern-base/govern-base-core` | Pure, host-testable logic (tally math, eligibility, proposal state transitions). |
| `crates/catalog/resend-base` | BYO-key transactional email (Resend wrapper): **async-by-default (transaction-safe) send** + a synchronous option, batch send, `{{variable}}` templates, a per-sender message log, and an operator surface (list-all + sender blocking). The owner's API key is bound as a secret the service never reads. |
| `crates/catalog/resend-base/resend-base-core` | Pure, host-testable logic (template rendering, request-body shaping) — unit-tested off-wasm. |
| `crates/catalog/stripe-base` | BYO-key payments (Stripe Checkout wrapper): create hosted Checkout Sessions, record orders, and apply signature-verified completion webhooks durably. One deployment can front many of the provisioner's apps, with each app's orders kept separate. |
| `crates/catalog/stripe-base/stripe-base-core` | Pure, host-testable logic (checkout form-body shaping, `Stripe-Signature` parsing + replay tolerance). |

## Patterns to learn from

Each service demonstrates the conventions the SDK's `AGENTS.md` prescribes:

- **`#[derive(Model)]` tables** + the typed `db_*` / `Query` CRUD layer — handlers
  never touch raw column literals.
- **Principal-scoped reads** (`auth::current_principal`, `auth::load_owned`,
  `auth::owns_resource`) with deny-by-existence-mask (missing and not-yours both 404).
- **Typed `JsonSchema` DTOs** on every route so the auto-generated OpenAPI is complete.
- **Bring-your-own-key secrets** bound out-of-band — injected as outbound headers
  or verified host-side (HMAC), so the wasm never reads the secret value.
- **Durable background jobs** for work that must survive a crash (retry on
  transient failure; apply a verified webhook after returning `200` fast).
- **Per-route ingress** (`stripe-base`): owner-only management routes alongside
  an anonymous, signature-authenticated webhook route.
- **Independent-writes vs. transactions**: where an external call or a job-enqueue
  sits between two writes, they cannot be one transaction — the services show the
  durable-intermediate-state pattern instead.

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
SDK's `smoke/` template uses). The `wit/` directories are generated and
gitignored.

```bash
# build the deployable wasm components
cargo build -p resend-base -p stripe-base --target wasm32-wasip2 --release

# run the pure-logic unit tests (the *-core crates)
cargo test --workspace
```

> Building pulls the SDK from git, so the first build needs network access to
> resolve `Boogy-ai/boogy-sdk`. The `*-core` crates are plain `rlib`s and test
> in isolation.
>
> **SDK version note:** `stripe-base` uses the SDK's host-side HMAC
> signature-verification helper for Stripe webhooks. If your pinned SDK
> revision predates that capability, pin `boogy-sdk` / `boogy-wit` to a
> revision that includes it (or build `resend-base` alone). `resend-base`
> builds against any recent SDK revision.

Write a manifest (each service ships a `boogy.toml`) and deploy with the `boogy`
CLI from the SDK repo.

## For coding agents

Expert skills for building Boogy services are published as agent skills.
**Claude Code (preferred):** `claude plugin marketplace add Boogy-ai/boogy-superpowers` then
`claude plugin install boogy-superpowers` — bundles skills + MCP + onramp gate; tell the human
to run **`/reload-plugins`** so the plugin activates mid-session.
**Other agents / vendor route:** `boogy skills install` (or `npx degit Boogy-ai/boogy-superpowers/skills
.claude/skills` — flat, no wrapper suffix); skills load automatically — if `.claude/skills/` was just
created, tell the human to **restart Claude Code**. The SDK's
`AGENTS.md` is the canonical handler-authoring reference.

## License

MIT OR Apache-2.0, at your option.
