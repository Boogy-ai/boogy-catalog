# Boogy catalog

First-party, **provisionable** wasm building blocks tenants deploy with their
own config (bring-your-own-key). They double as canonical best-practice
examples — each service is written the way the [Boogy SDK](https://github.com/Boogy-ai/boogy-sdk)
recommends.

Each crate follows the same conventions: `wit_glue!`, a `boogy.toml` manifest,
`#[derive(Model)]` tables, annotated routes, typed `JsonSchema` DTOs. Pure,
host-testable logic lives in a sibling `*-core` crate.

See the workspace [`README.md`](../../README.md) for the build story.
