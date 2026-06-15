# govern-base — maintainer notes

Working notes for changing this crate. For how to *use* the service see
[`AGENTS.md`](./AGENTS.md); for the design see [`README.md`](./README.md). This is
a provisionable governance catalog service: propose → co-sponsor → vote → tally →
timelock → execute, with anti-gaming guards.

## Shape

- **`govern-base-core/`** — pure decision logic, **no I/O**, host-unit-tested:
  the `VoteOption`/`ProposalStatus` enums, weighted tally aggregation (`tally_votes`),
  the quorum/threshold/veto rule (`decide`), and action-envelope validation. Put
  any new *pure* governance rule here with tests — it's the cheap, fast layer.
- **`src/`** — the wasm component. Handlers are thin: resolve identity, validate,
  call core for decisions, persist via `db_*`/`Query`. `lib.rs` holds the auth spine
  (`audience()` / `require_voter()` / `require_owner()` / `gate_read()`); the rest is
  one file per concern (proposals, sponsor, voting, lifecycle, execution, comments,
  admin, mcp, ws, models).

## Invariants — do not break these

These are the correctness + anti-gaming guarantees the tests pin. Changing them
needs a matching test change and a very good reason.

1. **Eligibility is enforced on every mutation.** In `members`/`workloads` mode a
   non-member must be `Denied`. `propose` checks `audience()`; `vote`/`sponsor`/
   `comment` use `require_voter()`. Never downgrade these to bare `require_principal()`.
2. **`total_eligible_power` is snapshotted at vote-open** (= roll size in bounded
   modes), in the same `tx` that stamps the voting window — in *both* `submit`
   (no-threshold OR exempt-proposer fast-track path) and `sponsor` (threshold-met
   path). Any path that opens voting MUST snapshot. If it stays `0`, bounded
   quorum can never be met and every such proposal silently rejects. (This was a real
   unit-green / integration-red bug — `decide()` was correct; the caller fed it `0`.
   The `members_mode_single_voter_passes` integration test guards it.)
3. **Encoded actions are immutable after `draft`.** Only `exec_status`/`exec_result`/
   `attempts` are ever written post-creation (by `claim_running`/`mark_action`).
   Never add a path that rewrites `target`/`method`/`body`/`headers`/`secret_header_ref`.
4. **Exactly-once execution.** `execute_proposal` claims each action `pending→running`
   in a `tx` *before* the call. A `running` action on re-entry must NOT be re-fired
   (it flags `failed` for operator replay). The automatic path never double-fires.
5. **Snapshotted gates.** A proposal snapshots `quorum`/`threshold`/`veto_threshold`/
   `eligibility`/`strategy` at creation; finalization reads the snapshot, never live
   config. A mid-vote config change must not alter an open vote.
6. **Transition guards + idempotency.** Every transition re-checks `status` inside
   its `tx`. The lifecycle advances both via the `lifecycle_tick` sweep AND lazily on
   read (`touch`), so finalize/enqueue/execute must be no-ops on re-entry.
7. **Transaction discipline (rollback-on-error).** Wrap a handler in `tx` whenever a
   mid-handler error should roll back the state change — not only for multi-write.
   Effectful calls (`peer`/`outbound`) and `jobs_enqueue` stay **outside** any open
   `tx` (the platform denies them inside one).

## Conventions

- Tables are `#[derive(Model)]`; go through `db_*` + the `Query` DSL, never raw
  column-name literals (the derive emits `T::TABLE` + per-field consts).
- Annotate every route with `.summary(...)`/`.description(...)` (the service-
  conventions gate requires it).
- Public copy: keep all comments/docs neutral — say "the store", name no specific
  storage engine, and carry no setup/infrastructure references.
- Imports that bite: `Deserialize`/`Serialize` come from `crate::` (macro-injected),
  the `Model` *trait* is `boogy_sdk::model::Model`, and `Query` is `crate::Query`.

## Testing

- **Core (fast):** `cargo build -j2; cargo test -p govern-base-core` — pure rlib,
  no runtime/store. Run this on every core change.
- **Integration (adversarial):** `crates/tests-integration/src/catalog_governance.rs`
  — 14 cases (happy path + Sybil/eligibility, double-vote, illegal transitions,
  self-sponsor, guardian, veto/quorum outcomes, author cooldown, the
  `total_eligible_power` regression). Needs a running store cluster; the harness
  builds the wasm fixture on demand via `ensure_built(&["govern-base"])`.
- Prefer adding a **negative/adversarial** case for any new guard, not just a happy
  path — that's where the bugs that matter hide.

## Extending (later phases — each its own change)

- **Delegation / liquid democracy:** add a `Delegation` table; resolve inherited
  power at tally for voters with no direct ballot (cycle-safe, depth-capped); a
  direct vote overrides inheritance. `tally_votes` already takes weights.
- **Weighted voting:** read `Member.weight` (already on the model) into the `Vote`
  weight at cast time; snapshot `total_eligible_power` as the weight sum, not count.
- **Re-votable ballots:** make `cast_vote` an UPSERT keyed on `(proposal, voter)`
  (last vote wins) instead of single-cast 409.
- **Participatory budgeting:** add `BudgetItem`/`BudgetBallot` + a budget tally and
  per-item funded-action execution; gate via a `kind = "budget"` proposal.

When you touch the lifecycle or execution, re-read the invariants above first.
