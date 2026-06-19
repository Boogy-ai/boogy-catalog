# wallet-base

A multi-chain custodial wallet catalog service. **EVM, Cosmos, Solana, and Bitcoin are live.**

This is a provisionable, best-practice catalog example: you deploy it with your own config, your own RPC endpoint, and your own keys — the platform does not operate it on your behalf.

---

## What it does

wallet-base gives each of your users a custodial EVM wallet (and eventually wallets on other chains). On first use the platform generates a secp256k1 signing key and stores it in its secure key store — **the private key never enters the wasm binary, never appears in logs, and is never exportable**. Your users interact with their wallet through the REST API or the MCP surface; signing happens inside the platform's key-custody layer.

Core operations:

- **Create or retrieve a wallet** (`POST /wallets`) — idempotent; the key is generated on the first call and reused on every subsequent call.
- **Sign a transaction** (`POST /evm/sign`) — sign a fully-specified intent (nonce + fees already provided); no broadcast.
- **Send a transaction** (`POST /evm/send`) — resolve missing nonce/fees, simulate, policy-check, sign, persist, and enqueue broadcast atomically. Broadcast and confirmation run asynchronously.
- **Simulate** (`POST /evm/simulate`) — run `eth_estimateGas` / `eth_call` without committing.
- **Fee estimates** (`GET /evm/fees`) — current base fee, priority fee, and a conservative max-fee ceiling.
- **Spend policy** (`GET /PUT /evm/policy`) — per-tx cap, rolling 24h cap, recipient/contract allowlists, and a `refuse_on_revert` flag.

### Cosmos

Cosmos support follows the same custody model — one non-exportable secp256k1 key per `(user_principal, chain)` pair — over the Cosmos transaction format:

- **bank `MsgSend` transfers** with `SIGN_MODE_DIRECT` (the canonical SignDoc digest is SHA-256 of the encoded SignDoc).
- **bech32 addresses** (e.g. `cosmos1…`), derived from the public key the same way the chain spec defines.
- **Fee model:** Cosmos has no EIP-1559 base-fee market. Fees are `gas_used × gas_price`, where the gas price is operator/chain-configured. `/cosmos/simulate` returns the estimated gas; `/cosmos/fees` multiplies it by the configured price.
- The full pipeline (`POST /cosmos/send`) and per-chain spend policy mirror the EVM surface, including the reject-before-signing guardrails and the blocked-principal gate.

### Solana

Solana support follows the same custody model, but over a different signing primitive — **Ed25519**, not secp256k1:

- **SystemProgram transfers** — a transfer of lamports from the caller's wallet to a recipient.
- **Ed25519 signing.** Solana signs the **whole serialized message**, not a 32-byte digest. The signature is a raw 64-byte Ed25519 signature.
- **Addresses are the public key.** A Solana address is simply the base58 encoding of the 32-byte Ed25519 public key — no hashing. This is structurally distinct from the secp256k1 chains (EVM/Cosmos), so a digest minted for one chain can never be replayed as a Solana sign input.
- **Amounts are in lamports** (1 SOL = 1,000,000,000 lamports).
- **Fee model:** a per-signature base fee — there is no EIP-1559 fee market. `/solana/fees` queries the chain via `getFeeForMessage` for the fee of a specific message. `/solana/simulate` uses `simulateTransaction` with `sigVerify: false` (a dummy signature), so the read path never touches the key.
- The full pipeline (`POST /solana/send`) and per-chain spend policy mirror the EVM and Cosmos surfaces, including the reject-before-signing guardrails and the blocked-principal gate.

### Bitcoin

Bitcoin support follows the same custody model — one non-exportable secp256k1 key per `(user_principal, chain)` pair — over Bitcoin's UTXO transaction model:

- **Native-SegWit P2WPKH** — addresses are bech32 (`bc1q…` on mainnet), derived from the public key the way the spec defines.
- **UTXO model.** A Bitcoin balance is a set of unspent transaction outputs, not a single account balance. A send **selects confirmed UTXOs** to cover the amount plus the fee, sends the requested amount to the recipient, and **returns change** to the sender's own address. Because a send may consume several UTXOs, **N inputs produce N signatures** — one BIP143 sighash is signed per input, each under the same host-derived `principal#btc` label.
- **secp256k1 signing** — the same key-custody model as the EVM and Cosmos chains; each per-input sighash is signed and the signatures are assembled back into the witness.
- **Amounts are in satoshis** (1 BTC = 100,000,000 satoshis).
- **Fee model:** there is no EIP-1559 base-fee market. The fee is **sat/vB × transaction vsize** — a fee rate (satoshis per virtual byte) multiplied by the estimated virtual size of the transaction. `/btc/fees` returns current fee-rate estimates; the actual fee is computed from the rate and the selected-input transaction size.
- **No simulation step.** UTXO chains have no analogue of `eth_estimateGas` / `eth_call`, so there is no `/btc/simulate`.
- UTXOs are fetched, and the signed transaction is broadcast, via an Esplora-compatible REST endpoint.
- The full pipeline (`POST /btc/send`) and per-chain spend policy mirror the other chains, including the reject-before-signing guardrails and the blocked-principal gate.

---

## Custody model

Keys are **non-exportable**. The platform generates a secp256k1 key per `(user_principal, chain)` pair and holds it in its key-custody layer. The wasm binary only ever sees the public key (to derive the address) and the compact ECDSA signature (after signing). There is no API to export, rotate, or view a raw private key.

**Honest limitation:** key custody is at the platform level, not at the hardware level in the current phase. If the platform's key-custody layer is compromised, user keys are at risk. A future phase will add HSM/enclave-backed custody.

---

## Spend guardrails

Guardrails run **before the signing key is touched** (the reject-before-signing invariant):

| Check | Config |
|---|---|
| Per-tx value cap | `max_value_wei` in the policy |
| Rolling 24h cap | `daily_cap_wei` in the policy |
| Recipient allowlist | `recipient_allowlist` (empty = no restriction) |
| Contract allowlist | `contract_allowlist` (empty = no restriction) |
| Refuse-on-revert | `refuse_on_revert` (default `true`) |
| Blocked principal | operator `POST /admin/block/{principal}` |

**Important limitation:** these guardrails are **app-level checks inside the wasm**. They are enforced by this service's code, not by the host. A future platform policy engine will move enforcement host-side, making the checks tamper-resistant even against a compromised wasm binary. Until then, treat them as best-effort application guardrails.

---

## Surfaces

### REST API

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Liveness probe |
| `POST` | `/wallets` | Ensure a wallet for a chain |
| `GET` | `/wallets` | List the caller's wallets |
| `GET` | `/wallets/{chain}` | Get the caller's wallet for one chain |
| `POST` | `/evm/sign` | Sign a fully-specified EVM transaction |
| `GET` | `/evm/fees` | Current EVM fee estimates |
| `POST` | `/evm/simulate` | Simulate an EVM transaction |
| `POST` | `/evm/send` | Full pipeline: simulate → policy → sign → broadcast |
| `GET` | `/evm/policy` | Get the caller's spend policy |
| `PUT` | `/evm/policy` | Set the caller's spend policy |
| `POST` | `/cosmos/sign` | Sign a fully-specified Cosmos transaction |
| `POST` | `/cosmos/simulate` | Simulate a Cosmos transaction (no commit) |
| `POST` | `/cosmos/fees` | Estimate gas + fee for a Cosmos transaction |
| `POST` | `/cosmos/send` | Full pipeline: simulate → policy → sign → broadcast |
| `GET` | `/cosmos/policy` | Get the caller's Cosmos spend policy |
| `PUT` | `/cosmos/policy` | Set the caller's Cosmos spend policy |
| `POST` | `/solana/sign` | Sign a fully-specified Solana transaction |
| `POST` | `/solana/simulate` | Simulate a Solana transaction (no commit) |
| `POST` | `/solana/fees` | Estimate the per-signature fee for a Solana transaction |
| `POST` | `/solana/send` | Full pipeline: simulate → policy → sign → broadcast |
| `GET` | `/solana/policy` | Get the caller's Solana spend policy |
| `PUT` | `/solana/policy` | Set the caller's Solana spend policy |
| `POST` | `/btc/sign` | Sign a fully-specified Bitcoin transaction |
| `POST` | `/btc/fees` | Estimate the fee rate (sat/vB) for a Bitcoin transaction |
| `POST` | `/btc/send` | Full pipeline: select UTXOs → policy → sign → broadcast |
| `GET` | `/btc/policy` | Get the caller's Bitcoin spend policy |
| `PUT` | `/btc/policy` | Set the caller's Bitcoin spend policy |

(There is no `/btc/simulate` — UTXO chains have no simulation step.)

OpenAPI schema: `GET /openapi.json`

### MCP tools

Mounted at `/mcp`. Tools: `get_address`, `get_balance`, `estimate_fee`, `simulate_transaction`, `send_transaction`, `list_transactions`.

### Operator admin (`/admin/*`)

Requires the service owner's agent token. Endpoints: list all wallets/transactions, get/set any principal's policy, block/unblock a principal, view the audit log.

---

## Configuration

The manifest's `rpc.example.com` placeholder must be replaced with your actual EVM JSON-RPC endpoint when you provision this service. Set the `evm_rpc_key` secret if your RPC provider requires an API key. For Cosmos, replace the `lcd.example.com` placeholder with your actual Cosmos LCD (REST) endpoint and set the `cosmos_rpc_key` secret if your provider requires an API key. For Solana, replace the `solana-rpc.example.com` placeholder with your actual Solana JSON-RPC endpoint and set the `solana_rpc_key` secret if your provider requires an API key. For Bitcoin, replace the `esplora.example.com` placeholder with your actual Esplora-compatible REST endpoint (used to fetch UTXOs and broadcast transactions) and set the `btc_rpc_key` secret if your provider requires an API key. Wallet data is isolated in the platform store — each provisioned instance has its own isolated data namespace.

---

## Multi-chain status

| Chain | Status |
|---|---|
| EVM (Ethereum-compatible) | Live |
| Cosmos | Live |
| Solana | Live |
| Bitcoin | Live |
