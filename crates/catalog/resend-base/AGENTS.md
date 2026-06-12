# resend-base — integration guide (for agents)

How to **integrate and use** this module from another Boogy service. For the
design/architecture, see [`README.md`](./README.md).

## What it is

A provisionable, bring-your-own-key transactional-email service. You deploy one
instance, bind your Resend key once, and your backend calls it over `peer` to
send email, manage templates, and (as the operator) administer everyone's mail.

## Setup (once)

1. Build + deploy the module. The owner is **you** (the deploying principal) —
   the manifest declares no owner.
2. Bind your Resend key as a secret (the full `Authorization` header value):
   ```bash
   printf 'Bearer re_your_key' | boogy secret set <owner>/resend-base/resend_api_key --stdin
   ```
   The module never reads the value; the host injects it on the outbound call.

## Caller contract — who calls, and how

All calls arrive over `peer::fetch` from your own backend. Three shapes:

| You are calling… | Identity the module sees | Use it for |
|---|---|---|
| on behalf of a user (OBO) | `principal = agent_<user>`, `actor = boogy://<you>/services/<svc>` | user-triggered mail (welcome, receipt) — the message is owned by that user |
| as your service | `principal = boogy://<you>/services/<svc>` | system mail |
| as the operator | a workload owned by you (any `boogy://<you>/services/*`) | the `/admin/*` surface |

End-user routes are scoped to `principal` (each sender sees only their own
mail). The operator surface is reachable only by **your own backend workloads**
(checked at runtime via self-identity — no identity is configured anywhere).

## Sending

`POST /send` — **async by default**: it queues the message and returns; a
durable job does the actual send.

```jsonc
{ "to": "buyer@x.com", "from": "hello@acme.com",
  // inline:
  "subject": "Welcome", "html": "<h1>Hi</h1>", "text": "Hi",
  // or a stored template:
  "template_id": "12", "vars": [["name", "Ada"]],
  "synchronous": false }          // default
```

- **Use the default (async) inside a transaction.** If your backend does
  `tx(|| { create_order(); peer POST /send {…} })`, the send is **staged in the
  transaction outbox** and goes out *iff the transaction commits*. This is the
  main reason to embed this module rather than call Resend yourself.
- **Use `synchronous: true`** only for fire-now cases outside a transaction
  (e.g. a password reset) where you want the send attempted inline.
- A **missing template variable is a `400`** (templates resolve strictly).
- `POST /send/batch` sends to ≤100 recipients, each its own message; a bad
  recipient is reported inline (`status: "rejected"`) while the rest send.

Responses: `{ message_id, status }`. `status` is `queued` (async / will send) or
`sent` (a synchronous send delivered).

## Templates

`POST /templates {name, subject, html, text?}` (the bodies are `{{ var }}`
templates), `GET /templates`, `GET /templates/{id}`, `DELETE /templates/{id}` —
all scoped to the calling principal.

## Reading your mail

`GET /messages` / `GET /messages/{id}` — the calling principal's messages only.

## Operator surface (`/admin/*`, your backend only)

| Call | Does |
|---|---|
| `GET /admin/messages?principal=&status=&to=&since=&limit=` | list/filter ALL senders' messages |
| `GET /admin/messages/{id}` | any message (incl. body) |
| `POST /admin/messages/{id}/cancel` | cancel a `queued` message |
| `GET/POST /admin/blocks`, `DELETE /admin/blocks/{principal}` | block / unblock a sender (blocked senders get `403` on `/send`) |

## Status & error vocabulary

- Message `status`: `queued` → `sent` | `failed` (terminal attempt failed) |
  `canceled` (operator). `sent`/`failed`/`canceled` are terminal.
- `400` — bad request / missing template variable. `401` — unauthenticated.
- `403` — blocked sender, or a non-operator on `/admin/*`. `404` — missing or
  not-yours (deny-by-existence-mask).

## Capabilities required (already in the manifest)

`store`, `auth`, `clock`, `entropy`, `outbound_http` (Resend only),
`background_jobs`. Self-identity is ungated (always available).

---

*Part of the [Boogy catalog](../README.md).*
