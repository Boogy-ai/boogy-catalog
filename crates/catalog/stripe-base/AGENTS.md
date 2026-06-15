# stripe-base — integration guide (for agents)

How to **integrate and use** this module from another Boogy service. For the
design/architecture, see [`README.md`](./README.md).

## What it is

A provisionable, bring-your-own-key payments service wrapping Stripe Checkout. You
deploy one instance, bind your Stripe keys once, and your apps create hosted
Checkout Sessions and receive signature-verified completion webhooks. **One
deployment fronts MANY of your apps** — orders are partitioned per app, isolated by
host-attested workload identity. The owner is **you** (the deploying principal); the
manifest declares no owner.

## Setup (once)

1. Build + deploy the module.
2. Bind your two Stripe secrets out-of-band (the module never reads them):
   ```bash
   # secret key — bind the FULL Authorization header value:
   printf 'Bearer sk_live_...' | boogy secret set <owner>/stripe-base/stripe_secret_key --stdin
   # webhook signing secret — the raw whsec_... value:
   printf 'whsec_...'          | boogy secret set <owner>/stripe-base/stripe_webhook_secret --stdin
   ```
   `stripe_secret_key` is injected as the `Authorization` header on outbound calls;
   `stripe_webhook_secret` is verified host-side (the wasm never sees either).
3. Point a Stripe webhook at `https://<host>/<owner>/webhook` for the
   `checkout.session.completed` event.

## Caller contract — the multi-client model

`client_service` (which of your apps an order belongs to) is **attested, not
claimed** — derived host-side from the caller's workload identity, never from the
body. Your role is resolved per request:

| You are calling… | Identity the module sees | Role | Sees |
|---|---|---|---|
| one of **your** apps (peer call) | attested `boogy://<you>/services/<app>` | `ClientApp(app)` | only that app's orders |
| **you** directly (your own agent token) | attested by `caller_is_service_owner` | `Owner` | all your apps (`?client=` to filter) |
| Stripe (the webhook) | none (anonymous) | — | authenticated by HMAC signature, not identity |
| a different owner's workload / non-owner agent / anon | — | `Denied` | `403` |

A client app's partition is pinned to its attested identity — any `client_ref` in
the body is ignored for an attested caller (no impersonation).

## Creating a checkout

`POST /checkout` — **async by default**: it records a `queued` order and a durable
job creates the Stripe session; the request path makes no outbound call, so it is
**transaction-safe** (usable inside a caller `tx`).

```jsonc
{ "amount": 2000, "currency": "usd", "product_name": "Pro Plan",
  "success_url": "https://app/ok", "cancel_url": "https://app/cancel",
  "metadata": { "plan": "pro" },     // optional, opaque, stored verbatim
  "customer_ref": "user_42",         // optional end-customer attribution
  "client_ref": "storefront",        // honored ONLY for a direct owner call w/o attested workload
  "synchronous": false }             // default: durable job (tx-safe)
// → { "order_id": 42, "status": "queued", "checkout_url": null }
```

- Use the **default (async)** inside a transaction — the queued order + the staged
  job commit together; the session is created only if the transaction commits.
- Use **`synchronous: true`** (outside a tx) to call Stripe inline and get the
  `checkout_url` in the response (falls back to the durable job on inline failure).
- The same per-order Stripe `Idempotency-Key` is used inline and on retry, so a
  session is never created twice — no double charge.

Poll `GET /orders/{id}` for the `checkout_url` of an async order, then redirect the
buyer to it.

## Reading orders

`GET /orders` (newest first; a client app sees only its partition; the owner sees
all apps, `?client=` to filter) and `GET /orders/{id}` (scoped to the caller's
partition — `404` if missing **or** outside it).

## Webhook (Stripe, anonymous)

`POST /webhook` — verified host-side against `stripe_webhook_secret` (HMAC +
±300s replay tolerance), deduped on the Stripe event id, then a durable job applies
the state transition (`checkout.session.completed` → order `paid`). Returns `200`
fast; a forged/stale signature is a flat `400`.

## Operator surface (`/admin/*`, the service owner only)

| Call | Does |
|---|---|
| `GET /admin/orders?client=&customer=&status=&from=&to=` | keyset-paginated orders across all apps |
| `GET /admin/orders/{id}` | any order (full record) |
| `GET /admin/summary?from=&to=` | counts by status, gross/refunded totals, per-app breakdown |
| `GET /admin/clients` | every client-app partition + order count + block status |
| `POST /admin/clients/{client}/block` · `/unblock` | block/unblock an app from creating checkouts |
| `GET /admin/audit?action=` | operator action log |

## Status & error vocabulary

- Order `status`: `queued` → `pending` → `paid` (or `refunded`/`canceled`/`expired`),
  or `failed` (the durable job exhausted retries). Webhook event `process_status`:
  `received` → `applied` | `no_match` | `ignored`.
- `400` — bad request, or an invalid/forged/stale webhook signature.
- `401` — unauthenticated. `403` — a different owner's workload, a non-owner on
  `/admin/*`, or a blocked client app creating a checkout.
- `404` — missing or outside your partition (deny-by-existence-mask).

## Capabilities required (already in the manifest)

`store`, `auth`, `clock`, `entropy`, `outbound_http` (`api.stripe.com` only),
`background_jobs`, `websockets`.

---

*Part of the [Boogy catalog](../README.md).*
