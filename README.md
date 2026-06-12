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

> **Status: early development.** APIs change without notice. These services
> track the SDK; pin a matching git `rev` if you build against them.

## What's here

| Crate | What it is |
|-------|------------|
| `crates/catalog/email-sender` | BYO-key transactional email (Resend wrapper): templated send with `{{variables}}`, a per-owner message log, and automatic retry of failed sends. The owner's API key is bound as a secret the service never reads. |
| `crates/catalog/email-sender/email-core` | Pure, host-testable logic (template rendering, request-body shaping) — unit-tested off-wasm. |
| `crates/catalog/stripe-gateway` | BYO-key payments (Stripe Checkout wrapper): create hosted Checkout Sessions, record orders, and apply signature-verified completion webhooks durably. One deployment can front many of the provisioner's apps, with each app's orders kept separate. |
| `crates/catalog/stripe-gateway/stripe-core` | Pure, host-testable logic (checkout form-body shaping, `Stripe-Signature` parsing + replay tolerance). |

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
- **Per-route ingress** (`stripe-gateway`): owner-only management routes alongside
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
cargo build -p email-sender -p stripe-gateway --target wasm32-wasip2 --release

# run the pure-logic unit tests (the *-core crates)
cargo test --workspace
```

> Building pulls the SDK from git, so the first build needs network access to
> resolve `Boogy-ai/boogy-sdk`. The `*-core` crates are plain `rlib`s and test
> in isolation.
>
> **SDK version note:** `stripe-gateway` uses the SDK's host-side HMAC
> signature-verification helper for Stripe webhooks. If your pinned SDK
> revision predates that capability, pin `boogy-sdk` / `boogy-wit` to a
> revision that includes it (or build `email-sender` alone). `email-sender`
> builds against any recent SDK revision.

Write a manifest (each service ships a `boogy.toml`) and deploy with the `boogy`
CLI from the SDK repo.

## For coding agents

Expert skills for building Boogy services are published as agent skills:
`boogy skills install` (or `npx degit Boogy-ai/boogy-superpowers/skills
.claude/skills/boogy`). The SDK's `AGENTS.md` is the canonical
handler-authoring reference.

## License

MIT OR Apache-2.0, at your option.
