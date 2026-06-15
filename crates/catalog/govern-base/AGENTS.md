# govern-base — integration guide (for agents)

How to **integrate and use** this governance module from another Boogy service or
an LLM client. For the design/architecture, see [`README.md`](./README.md).

## What it is

A provisionable governance engine. You deploy one instance, configure your policy
once, and your members propose / co-sponsor / vote / deliberate within it. A passed
proposal can execute real effects (a peer call or an outbound call) verbatim, behind
a timelock. One deployment = one governance space, owned by **you** (the deploying
principal). The manifest declares no owner.

## Setup (once)

1. Build + deploy the module. The owner is **you** (the deploying principal).
2. **Set `[outbound] allowed_hosts`** in the manifest to the external hosts your
   proposals may call — this is the execution blast-radius floor.
3. Configure policy: `PUT /admin/config` (eligibility, tally gates, windows,
   sponsorship threshold, `min_voting_period_ms`, `author_cooldown_ms`, guardians).
4. In `members`/`workloads` mode, curate the roll: `POST /admin/members`.
5. *(Optional)* Bind a secret for authenticated outbound actions; reference it from
   an action's `secret_header_ref` (the value never appears in a proposal).

## Caller contract — who can do what

Authorization is **host-attested, in-handler** — no identity is configured anywhere.
Your role is resolved per request:

| You are… | Role | Can |
|---|---|---|
| the service owner (your own agent token, attested by `caller_is_service_owner`) | **Owner** | operate `/admin/*`, manage the roll, moderate, guardian-cancel — **and** participate as a voter |
| an eligible participant | **Voter** | propose, co-sponsor, vote, comment |
| anyone, when `read_access = public` | **Reader** | read proposals / tallies / comments |

Eligibility (who is a **Voter**) is set by `Config.eligibility`:

- `open` — any authenticated principal (permissionless; Sybil-vulnerable by design).
- `members` / `workloads` — only principals/workloads on the **Member roll**;
  a non-member is `403` on every mutation.

## Proposing

`POST /proposals` — create a draft with zero or more **immutable, encoded actions**
(what executes verbatim if it passes). Actions are frozen the moment you submit.

```jsonc
{ "title": "Fund the docs grant", "body": "Pay 500 to the docs team.",
  "actions": [
    { "action_type": "peer",                 // "peer" | "http"
      "method": "POST",                       // GET | POST | PUT | DELETE
      "target": "boogy://acme/services/treasury",
      "body": "{\"amount\":500,\"to\":\"docs\"}",
      "secret_header_ref": null }             // optional operator-bound secret name
  ] }
// → { "id": 7, "status": "draft" }
```

Omit `actions` for a **signal-only** proposal (records the outcome, no side effects).

## The lifecycle (your calls)

1. `POST /proposals/{id}/submit` — opens **sponsorship** (if a threshold is set) or
   **voting** directly. Author/owner only. **Exempt proposers** — the owner, and any
   principals/workloads in `Config.exempt_proposers` — skip sponsorship and open for
   voting immediately, even when a threshold is set.
2. `POST /proposals/{id}/sponsor` — endorse a proposal in sponsorship. Enough
   distinct sponsors opens voting. **You can't sponsor your own proposal.**
3. `POST /proposals/{id}/vote {"option":"yes"|"no"|"abstain"|"veto"}` — single-cast
   (a second ballot is `409`). Only while `voting` and before `voting_end`.
4. `GET /proposals/{id}/tally` — the live `{yes,no,abstain,veto,ballots}`.
5. After `voting_end`, the tally finalizes automatically (quorum / threshold / veto).
   A passed proposal **with actions** waits out a timelock, then executes them
   **exactly once**; a signal-only pass is recorded as `executed`.
6. `POST /proposals/{id}/withdraw` — author/owner, before `voting_end`.

## Deliberation

`POST /proposals/{id}/comments {"body":"…","parent_id":0}` (threaded), and
`GET /proposals/{id}/comments` (oldest first; hidden comments omitted).

## Reading

`GET /proposals` (keyset-paginated; `?status=`, `?author=`, `?limit=`, `?cursor=`),
`GET /proposals/{id}`, `GET /proposals/{id}/tally`. Subject to `read_access`
(anonymous reads only when `public`).

## Operator surface (`/admin/*`, owner only)

| Call | Does |
|---|---|
| `GET` / `PUT /admin/config` | read / update policy |
| `POST` / `GET /admin/members`, `DELETE /admin/members/{principal}` | manage the electorate roll (DELETE → `204`) |
| `POST /admin/proposals/{id}/cancel` | guardian (owner or a `guardian_principals` member) cancels during timelock |
| `POST /admin/proposals/{id}/replay-execution?reset=true\|false` | re-drive a `failed` proposal's actions (`reset=true` re-runs an interrupted action) |
| `POST /admin/comments/{id}/hide` | moderate a comment |
| `GET /admin/audit` | operator action log (`?action=` filter) |

## MCP (for LLM clients)

Mounted at `/mcp`: `list_proposals` and `get_proposal` typed tools (schemas
auto-derived). Reads honor the same `read_access` gate; auth flows through the same
PASETO/API-key path.

## Status & error vocabulary

- Proposal `status`: `draft` → `sponsorship`/`voting` → `passed`/`rejected`/`vetoed`;
  a passed-with-actions proposal → `timelock` → `executing` → `executed`/`failed`.
  Also `withdrawn`, `expired`, `canceled`. Action `exec_status`: `pending` →
  `running` → `done`/`failed`/`skipped`.
- `400` — bad request (e.g. an invalid action shape or vote option).
- `401` — unauthenticated (anonymous on an authenticated read/any mutation).
- `403` — a non-member mutating in a bounded mode, a non-owner on `/admin/*`,
  self-sponsorship, or a non-guardian cancelling.
- `404` — missing (deny-by-existence).
- `409` — double-vote, an illegal transition (vote on a non-`voting` proposal,
  submit a non-draft, sponsor a non-`sponsorship` proposal, withdraw after
  `voting_end`), the author cooldown, or a replay blocked by an in-flight action.

## Capabilities required (already in the manifest)

`store`, `auth`, `clock`, `entropy`, `peer`, `outbound_http`, `background_jobs`,
`websockets`. `outbound_http` is bounded by `[outbound] allowed_hosts`.

---

*Part of the [Boogy catalog](../README.md).*
