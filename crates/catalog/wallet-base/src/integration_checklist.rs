//! Handler-level adversarial integration checklist for wallet-base.
//!
//! Each function below names ONE adversarial scenario that requires the live
//! host + control-plane + store harness to exercise (it cannot be proven in plain `cargo
//! test`). The bodies are `todo!()` placeholders — the value of this file is
//! the **named, durable checklist** of scenarios to wire up once the integration
//! harness is running.
//!
//! Gate: none of these execute in `cargo test`; they are excluded from the
//! default test runner via `#[ignore]`.  The `#![allow(dead_code)]` suppress
//! the compiler's "unused" warnings on the stubs.
#![allow(dead_code)]

/// **owner_b_cannot_read_owner_a_wallet**
///
/// Scenario: Owner B holds a valid PASETO for their own agent. They issue a
/// `GET /wallets/evm` request bearing Owner A's wallet chain. Because the
/// wallet row is filtered by `owner_principal` (the host-attested principal,
/// not a URL param), the row simply does not appear in Owner B's query scope.
///
/// Expected: HTTP 404 (deny-by-existence-mask). The response is
/// indistinguishable from a genuinely missing wallet. Never 200, never 403.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn owner_b_cannot_read_owner_a_wallet() {
    // 1. Deploy wallet-base under Owner A; call POST /wallets (chain=evm) to
    //    create a wallet row keyed to A's principal.
    // 2. Obtain a valid PASETO token for Owner B's agent (distinct principal).
    // 3. Issue GET /wallets/evm as Owner B.
    // 4. Assert HTTP 404 in the response — not 200, not 403.
    todo!("wire up in the integration harness")
}

/// **obo_authorizes_on_principal_not_actor**
///
/// Scenario: Service X calls `POST /evm/send` on behalf of user U via OBO
/// delegation (the PASETO carries `principal = U`, `actor = service_X`).
///
/// Expected:
/// - The signing label is `U#evm` (derived from the principal, never the actor).
/// - Authorization checks (wallet row lookup, policy, spend cap) key on U.
/// - Service X's identity is irrelevant to which key signs or which policy applies.
/// - The persisted `Transaction` row has `owner_principal = U`.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn obo_authorizes_on_principal_not_actor() {
    // 1. Provision wallet-base; create an EVM wallet for user U.
    // 2. Mint an OBO PASETO where principal=U, actor=service_X.
    // 3. Call POST /evm/send with that token.
    // 4. Assert the resulting Transaction row has owner_principal == U.
    // 5. Confirm the signing host used label "U#evm", not "service_X#evm".
    todo!("wire up in the integration harness")
}

/// **over_cap_send_rejected_before_signing**
///
/// Scenario: Owner sets a per-tx cap of 1 ETH (1e18 wei). A send request for
/// 2 ETH is submitted.
///
/// Expected: HTTP 4xx (guardrail rejection from `check_policy`) and NO
/// `signing_sign_digest` call has been made (the key is never touched when
/// guardrails reject the intent).
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn over_cap_send_rejected_before_signing() {
    // 1. PUT /evm/policy with max_value_wei = "1000000000000000000" (1 ETH).
    // 2. POST /evm/send with value_wei = "2000000000000000000" (2 ETH).
    // 3. Assert HTTP 4xx response.
    // 4. Assert no Transaction row was inserted (DB count unchanged).
    // 5. Optionally: use host metrics / signing audit to confirm signing was not called.
    todo!("wire up in the integration harness")
}

/// **refuse_on_revert_blocks_broadcast**
///
/// Scenario: `refuse_on_revert = true` (the default). Simulation via
/// `eth_estimateGas` / `eth_call` returns a revert.
///
/// Expected: HTTP 4xx, no `Transaction` row persisted, no `broadcast_tx` job
/// enqueued. The signing key is never touched.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn refuse_on_revert_blocks_broadcast() {
    // 1. Set up wallet-base with a node that will return a revert for the intent.
    // 2. Ensure the principal's policy has refuse_on_revert = true (default).
    // 3. POST /evm/send with a reverting intent.
    // 4. Assert HTTP 4xx.
    // 5. Assert no Transaction row (DB count unchanged).
    // 6. Assert no job was enqueued for broadcast_tx.
    todo!("wire up in the integration harness")
}

/// **blocked_principal_cannot_send**
///
/// Scenario: The operator calls `POST /admin/block/{principal}` to block user
/// U. User U then attempts `POST /evm/send`.
///
/// Expected: HTTP 403 from `do_send` (the `is_blocked` guard fires at the top
/// of the function, before any RPC, sign, or DB write occurs).
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn blocked_principal_cannot_send() {
    // 1. Create an EVM wallet for user U.
    // 2. As operator, call POST /admin/block/U.
    // 3. As user U, call POST /evm/send.
    // 4. Assert HTTP 403 in the response body / status.
    // 5. Assert no Transaction row was inserted.
    todo!("wire up in the integration harness")
}

/// **label_cannot_be_set_from_body**
///
/// Scenario: A crafted request body includes extra fields attempting to set
/// `label`, `owner_principal`, or `owner` to an arbitrary value (e.g. another
/// principal's label).
///
/// Expected: The request is processed normally; the signing subject is always
/// `current_principal()#evm` (host-attested, never body-derived). The extra
/// fields are silently ignored by `serde`. No escalation to another principal's
/// key occurs.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn label_cannot_be_set_from_body() {
    // 1. As user U, POST /evm/send with a JSON body that includes
    //    "label": "victim#evm", "owner": "victim", "owner_principal": "victim".
    // 2. Assert the request succeeds (or fails on independent grounds), but any
    //    signing that occurred used U's own label, NOT "victim#evm".
    // 3. Verify the Transaction row (if created) has owner_principal == U.
    todo!("wire up in the integration harness")
}

/// **concurrent_evm_sends_get_distinct_nonces** (#8)
///
/// Scenario: two `POST /evm/send` requests for the SAME user race (neither tx
/// has hit the chain yet, so the on-chain pending nonce is identical for both).
///
/// Expected: the durable `NonceReservation` counter serializes them — each send
/// is assigned a DISTINCT nonce (`max(on-chain pending, stored_next)`, advancing
/// `stored_next` by one per reservation). Because the reservation read+write
/// happens inside one store `tx`, two truly-simultaneous reservers conflict on
/// the row and the loser receives HTTP 409 (commit conflict) and retries the
/// whole request, getting the next nonce. No two persisted EVM `Transaction`
/// rows for one account ever share a nonce. The pure reservation arithmetic is
/// proven by `wallet-base-core`'s `nonce.rs` tests; this stub is the
/// handler-level confirmation under a real concurrent race.
///
/// Caveat (by design, not a bug): a permanently-failed/abandoned send leaves a
/// nonce GAP — subsequent sends keep advancing and the gap nonce is never
/// filled (inherent to EVM pending pipelines; cancel/replace is out of scope).
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn concurrent_evm_sends_get_distinct_nonces() {
    // 1. Create an EVM wallet for user U; point the RPC stub at a fixed pending
    //    nonce N (neither in-flight tx is visible to the node yet).
    // 2. Fire two POST /evm/send concurrently (no explicit nonce in either body).
    // 3. Assert the two persisted Transaction rows have nonces N and N+1 (in some
    //    order) — never both N. A 409 on one is acceptable (client retries → N+1).
    todo!("wire up in the integration harness")
}

// ─── Cosmos adversarial scenarios ──────────────────────────────────────────────
//
// The Cosmos surface (`/cosmos/*`) shares the security spine with EVM (host-
// derived label, reject-before-signing guardrails, is_blocked gate) but over a
// distinct address/tx format and a REST (LCD) RPC. These scenarios cover the new
// attack surface and confirm the shared invariants hold on the Cosmos path.

/// **cosmos_blocked_principal_cannot_send**
///
/// Scenario: The operator blocks user U. U then attempts `POST /cosmos/send`.
///
/// Expected: HTTP 403 from `do_cosmos_send` — the `is_blocked` guard fires at the
/// TOP of the function, before any account fetch, gas estimate, sign, or DB
/// write. No `Transaction` row, no `broadcast_tx` job.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn cosmos_blocked_principal_cannot_send() {
    // 1. Create a cosmos wallet for user U (POST /wallets chain=cosmos).
    // 2. As operator, POST /admin/block/U.
    // 3. As user U, POST /cosmos/send.
    // 4. Assert HTTP 403; assert no Transaction row was inserted.
    todo!("wire up in the integration harness")
}

/// **cosmos_over_cap_send_rejected_before_signing**
///
/// Scenario: U sets a Cosmos per-tx cap (base denom) via `PUT /cosmos/policy`.
/// A `POST /cosmos/send` for an amount over the cap is submitted.
///
/// Expected: HTTP 4xx (guardrail rejection from `check_policy`), NO
/// `signing_sign_digest` call (the key is never touched when guardrails reject),
/// no `Transaction` row, no broadcast job. Confirms guardrails run BEFORE signing
/// on the Cosmos path, identically to EVM.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn cosmos_over_cap_send_rejected_before_signing() {
    // 1. PUT /cosmos/policy with max_value_wei = "1000000" (base denom cap).
    // 2. POST /cosmos/send with amount = "2000000".
    // 3. Assert HTTP 4xx; assert no Transaction row; confirm signing not called.
    todo!("wire up in the integration harness")
}

/// **cosmos_label_cannot_be_set_from_body**
///
/// Scenario: A crafted `/cosmos/send` body sets `from_address` to a victim's
/// bech32 address (and/or extra label/owner fields).
///
/// Expected: `from_address` is ALWAYS overwritten from the caller's stored
/// `Wallet` row and the signing label is always `current_principal()#cosmos`
/// (host-attested). The body's `from_address` is ignored; no signing occurs as
/// any other subject; the persisted row has `owner_principal == U`.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn cosmos_label_cannot_be_set_from_body() {
    // 1. As user U (with a cosmos wallet), POST /cosmos/send with a body whose
    //    from_address = "<victim bech32>" plus "label"/"owner" decoys.
    // 2. Assert any signing used label "U#cosmos" and from_address == U's wallet
    //    address — never the victim's.
    // 3. Verify the Transaction row (if created) has owner_principal == U.
    todo!("wire up in the integration harness")
}

/// **cosmos_simulate_never_touches_key**
///
/// Scenario: `POST /cosmos/simulate` (and `/cosmos/fees`, which wraps it) is
/// called. The Cosmos LCD simulate endpoint does not verify signatures.
///
/// Expected: NO `signing_sign_digest` call occurs — the tx is assembled with a
/// DUMMY all-zero signature for the read path. Confirms the no-key-touch
/// invariant on the Cosmos simulate/fees read paths.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn cosmos_simulate_never_touches_key() {
    // 1. Create a cosmos wallet for U.
    // 2. POST /cosmos/simulate (and /cosmos/fees) with a valid intent.
    // 3. Assert no signing call was made (host signing audit / metrics).
    todo!("wire up in the integration harness")
}

/// **cosmos_chain_rejected_broadcast_marks_failed**
///
/// Scenario: A signed Cosmos tx is broadcast but the LCD returns a nonzero
/// `tx_response.code` (e.g. sequence mismatch / insufficient funds).
///
/// Expected: `cosmos_broadcast` treats the nonzero code as a TERMINAL chain
/// rejection — the `Transaction` row flips to `failed` (not retried), a
/// `tx.status` WS envelope is published, and the job returns `Terminal`.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn cosmos_chain_rejected_broadcast_marks_failed() {
    // 1. Send a cosmos tx that the (mock) LCD rejects with code != 0.
    // 2. Let the broadcast_tx job run.
    // 3. Assert the Transaction row is "failed" and the job did NOT retry.
    todo!("wire up in the integration harness")
}

/// **cosmos_cross_chain_digest_misuse_rejected**
///
/// Scenario: An attacker holds a signature/digest minted for ONE chain's intent
/// (e.g. the EVM keccak sig-hash) and attempts to have it authorize the OTHER
/// chain's tx at the handler level.
///
/// Expected: This is structurally impossible — the adapters are chain-specific
/// and `/cosmos/sign` only ever signs a Cosmos SignDoc digest (SHA-256) under the
/// `current_principal()#cosmos` label, never an EVM digest. The pure domain-
/// separation property (EVM keccak digest ≠ Cosmos SHA-256 digest for an
/// analogous transfer) is already proven by `wallet-base-core`'s
/// `tests/cross_chain.rs`; this stub is the handler-level end-to-end confirmation
/// that the `/cosmos/*` surface cannot be driven to sign anything but a Cosmos
/// SignDoc, so a cross-chain digest can never be replayed through it.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn cosmos_cross_chain_digest_misuse_rejected() {
    // 1. Create both an EVM and a Cosmos wallet for user U.
    // 2. Build an EVM intent and capture its signing digest (keccak sig-hash).
    // 3. Call POST /cosmos/sign with a Cosmos intent; capture the digest the
    //    Cosmos path actually signed.
    // 4. Assert the Cosmos-path digest != the EVM digest (it is a SHA-256 SignDoc
    //    digest), and that the label used was "U#cosmos", never "U#evm".
    // 5. Confirm there is no handler path that signs an EVM digest under a cosmos
    //    label (or vice-versa).
    todo!("wire up in the integration harness")
}

/// **cosmos_bad_bech32_recipient_rejected**
///
/// Scenario: `POST /cosmos/send` is submitted with a malformed `to_address`
/// (invalid bech32, e.g. "garbage" or "cosmos1notvalid!!").
///
/// Expected: HTTP 400 (the adapter's `build_unsigned` rejects the bad bech32
/// before any signing). The signing key is never touched and no `Transaction`
/// row is written / no broadcast job is enqueued. The pure rejection is already
/// covered by `wallet-base-core`'s `cosmos_vectors.rs::
/// cosmos_build_unsigned_rejects_bad_bech32`; this stub is the handler-level
/// check that the bad input surfaces as a 400 with no side effects.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn cosmos_bad_bech32_recipient_rejected() {
    // 1. Create a cosmos wallet for user U.
    // 2. POST /cosmos/send with to_address = "garbage" (malformed bech32).
    // 3. Assert HTTP 400.
    // 4. Assert no Transaction row was inserted and no broadcast job enqueued.
    // 5. Confirm signing was not called (host signing audit / metrics).
    todo!("wire up in the integration harness")
}

// ─── Solana adversarial scenarios ──────────────────────────────────────────────
//
// The Solana surface (`/solana/*`) shares the security spine with EVM and Cosmos
// (host-derived label, reject-before-signing guardrails, is_blocked gate) but is
// distinguished by its signing primitive: an Ed25519 signature over the WHOLE
// serialized message — never a secp256k1 32-byte digest. These scenarios cover
// the new attack surface and confirm the shared invariants plus the Ed25519
// end-to-end property hold on the Solana path.

/// **solana_send_guardrail_rejects_over_cap**
///
/// Scenario: U sets a Solana per-tx cap (lamports) via `PUT /solana/policy`. A
/// `POST /solana/send` for an amount over the cap is submitted.
///
/// Expected: HTTP 4xx (guardrail rejection from `check_policy`), NO
/// `signing_sign_message` call (the key is never touched when guardrails reject),
/// no `Transaction` row, no broadcast job. Confirms guardrails run BEFORE signing
/// on the Solana path, identically to EVM/Cosmos.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn solana_send_guardrail_rejects_over_cap() {
    // 1. PUT /solana/policy with a per-tx lamports cap (e.g. max = "1000000").
    // 2. POST /solana/send with lamports = 2000000 (over the cap).
    // 3. Assert HTTP 4xx; assert no Transaction row was inserted.
    // 4. Confirm no signing_sign_message call was made (host signing audit / metrics).
    todo!("wire up in the integration harness")
}

/// **solana_bad_base58_recipient_rejected**
///
/// Scenario: `POST /solana/send` is submitted with a malformed base58
/// `to_address` (e.g. "0OIl" — chars outside the base58 alphabet, or a
/// valid-base58 but wrong-length blob).
///
/// Expected: HTTP 400 (the adapter's `build_unsigned` rejects the bad base58
/// before any signing). The signing key is never touched and no `Transaction`
/// row is written / no broadcast job is enqueued. The pure rejection is already
/// covered by `wallet-base-core`'s `solana_vectors.rs::
/// solana_build_unsigned_rejects_bad_base58`; this stub is the handler-level
/// check that the bad input surfaces as a 400 with no side effects.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn solana_bad_base58_recipient_rejected() {
    // 1. Create a solana wallet for user U.
    // 2. POST /solana/send with to_address = "0OIl" (malformed base58).
    // 3. Assert HTTP 400.
    // 4. Assert no Transaction row was inserted and no broadcast job enqueued.
    // 5. Confirm signing was not called (host signing audit / metrics).
    todo!("wire up in the integration harness")
}

/// **solana_uses_ed25519_not_secp256k1**
///
/// Scenario: A Solana wallet is created and a `/solana/send` is driven through to
/// signing.
///
/// Expected: The Solana wallet key is created with Ed25519 (the address IS the
/// base58 of the 32-byte public key — no hashing), and signing goes through the
/// sign-MESSAGE path (`signing_sign_message`), never the secp256k1
/// sign-DIGEST path. There is no handler route that drives a Solana wallet
/// through the secp256k1 digest path. The address derivation and the sign path
/// are Ed25519 end-to-end. The pure structural property (Solana emits a
/// `SignRequest::Message`, never a `SignRequest::Digest`) is already proven by
/// `wallet-base-core`'s `tests/cross_chain.rs`; this stub is the handler-level
/// confirmation that the live `/solana/*` surface is Ed25519 end-to-end.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn solana_uses_ed25519_not_secp256k1() {
    // 1. POST /wallets chain=solana for user U; capture the address.
    // 2. Assert the address is the base58 of the 32-byte Ed25519 public key
    //    (round-trips: bs58-decode → 32 bytes; no keccak/hash applied).
    // 3. POST /solana/send (within policy) and confirm the host signed via the
    //    sign-message (Ed25519) path, NOT the secp256k1 sign-digest path.
    // 4. Confirm there is no handler path that drives a solana wallet through the
    //    secp256k1 digest path.
    todo!("wire up in the integration harness")
}

/// **solana_simulate_never_touches_key**
///
/// Scenario: `POST /solana/simulate` (and `/solana/fees`, which wraps it) is
/// called. The Solana `simulateTransaction` RPC is invoked with
/// `sigVerify: false`, so a dummy signature suffices for the read path.
///
/// Expected: NO `signing_sign_message` call occurs — the transaction is
/// assembled with a DUMMY signature for the read path. Confirms the no-key-touch
/// invariant on the Solana simulate/fees read paths.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn solana_simulate_never_touches_key() {
    // 1. Create a solana wallet for U.
    // 2. POST /solana/simulate (and /solana/fees) with a valid intent.
    // 3. Assert no signing_sign_message call was made (host signing audit / metrics).
    todo!("wire up in the integration harness")
}

// ─── Bitcoin adversarial scenarios ──────────────────────────────────────────────
//
// The Bitcoin surface (`/btc/*`) shares the security spine with EVM, Cosmos, and
// Solana (host-derived label, reject-before-signing guardrails, is_blocked gate)
// but is distinguished by the UTXO model: a send selects confirmed UTXOs and a
// multi-input send produces N BIP143 sighashes — one signature per input — rather
// than a single per-tx signature. There is no simulation step (UTXO chains have
// no analogue of `eth_estimateGas` / `eth_call`). These scenarios cover the new
// attack surface and confirm the shared invariants plus the per-input signing
// property hold on the Bitcoin path.

/// **btc_send_guardrail_rejects_over_cap**
///
/// Scenario: U sets a Bitcoin per-tx cap (satoshis) via `PUT /btc/policy`. A
/// `POST /btc/send` for an amount over the cap is submitted.
///
/// Expected: HTTP 4xx (guardrail rejection from `check_policy`), NO
/// `signing_sign_digest` call for ANY input (the key is never touched when
/// guardrails reject), no `Transaction` row, no broadcast job. Confirms guardrails
/// run BEFORE signing on the Bitcoin path, identically to the other chains.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn btc_send_guardrail_rejects_over_cap() {
    // 1. PUT /btc/policy with a per-tx sats cap (e.g. max = "100000").
    // 2. POST /btc/send with amount_sat = 200000 (over the cap).
    // 3. Assert HTTP 4xx; assert no Transaction row was inserted.
    // 4. Confirm no signing_sign_digest call was made for any input (host signing
    //    audit / metrics) — the key is never touched.
    todo!("wire up in the integration harness")
}

/// **btc_wrong_network_recipient_rejected**
///
/// Scenario: `POST /btc/send` on a MAINNET wallet is submitted with a TESTNET
/// (`tb1q…`) recipient address (and the mirror case: a `bc1q…` mainnet address on
/// a testnet wallet).
///
/// Expected: HTTP 400 — the adapter's `build_unsigned` rejects the wrong-network
/// recipient before any signing. The signing key is never touched and no
/// `Transaction` row is written / no broadcast job is enqueued. The pure rejection
/// is already covered by `wallet-base-core`'s `btc_vectors.rs::
/// btc_wrong_network_to_address_errs`; this stub is the handler-level check that
/// the wrong-network input surfaces as a 400 with no side effects.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn btc_wrong_network_recipient_rejected() {
    // 1. Create a mainnet btc wallet for user U.
    // 2. POST /btc/send with to_address = "<tb1q… testnet address>".
    // 3. Assert HTTP 400.
    // 4. Repeat the mirror case (testnet wallet, bc1q… mainnet recipient) → 400.
    // 5. Assert no Transaction row was inserted and no broadcast job enqueued;
    //    confirm signing was not called (host signing audit / metrics).
    todo!("wire up in the integration harness")
}

/// **btc_insufficient_funds_rejected**
///
/// Scenario: `POST /btc/send` requests an amount that exceeds the wallet's total
/// confirmed UTXO value (amount + fee cannot be covered by the available coins).
///
/// Expected: HTTP 400 — coin selection fails closed (the adapter's
/// `build_unsigned` returns an error when no UTXO subset covers amount + fee). The
/// signing key is never touched and no `Transaction` row is written / no broadcast
/// job is enqueued. The pure rejection is already covered by `wallet-base-core`'s
/// `btc_vectors.rs::btc_insufficient_funds_errs`; this stub is the handler-level
/// check that coin-selection failure surfaces as a 400 with no side effects.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn btc_insufficient_funds_rejected() {
    // 1. Create a btc wallet for user U whose confirmed UTXO total is small.
    // 2. POST /btc/send with amount_sat greater than the confirmed UTXO total.
    // 3. Assert HTTP 400 (coin selection fail-closed).
    // 4. Assert no Transaction row was inserted and no broadcast job enqueued;
    //    confirm signing was not called (host signing audit / metrics).
    todo!("wire up in the integration harness")
}

/// **btc_blocked_principal_cannot_send**
///
/// Scenario: The operator blocks user U. U then attempts `POST /btc/send`.
///
/// Expected: HTTP 403 from `do_btc_send` — the `is_blocked` guard fires at the TOP
/// of the function, before any UTXO fetch (RPC), coin selection, sign, or DB
/// write. No `Transaction` row, no broadcast job, no key touch.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn btc_blocked_principal_cannot_send() {
    // 1. Create a btc wallet for user U (POST /wallets chain=btc).
    // 2. As operator, POST /admin/block/U.
    // 3. As user U, POST /btc/send.
    // 4. Assert HTTP 403; assert no Transaction row and no broadcast job; confirm
    //    no UTXO-fetch RPC and no signing call occurred (host audit / metrics).
    todo!("wire up in the integration harness")
}

/// **btc_each_input_signed_under_principal_label**
///
/// Scenario: A multi-UTXO `POST /btc/send` (two or more inputs required to fund
/// the transfer) is driven through to signing.
///
/// Expected: The host signs EACH input's BIP143 sighash via the sign-DIGEST path
/// under the SAME `current_principal()#btc` label (host-derived, never from the
/// request body) — N inputs → N `signing_sign_digest` calls, all under U's label,
/// never the actor's and never a body-supplied label. The persisted `Transaction`
/// row has `owner_principal == U`. The pure per-input-digest property (N inputs →
/// N `SignRequest::Digest`s, all 32-byte BIP143 sighashes distinct from the
/// EVM/Cosmos digests) is already proven by `wallet-base-core`'s
/// `tests/cross_chain.rs`; this stub is the handler-level confirmation that every
/// input is signed under the host-attested principal label.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn btc_each_input_signed_under_principal_label() {
    // 1. Create a btc wallet for user U funded by 2+ confirmed UTXOs.
    // 2. POST /btc/send (within policy) for an amount that requires multiple inputs,
    //    with a body that also includes decoy "label"/"owner"/"owner_principal".
    // 3. Assert the host made N signing_sign_digest calls (one per input), ALL under
    //    label "U#btc" — never the actor's label, never a body-supplied label.
    // 4. Verify the persisted Transaction row has owner_principal == U.
    todo!("wire up in the integration harness")
}

/// **multi_chain_assemble_self_verifies_signature** (#15)
///
/// Scenario: every chain's `assemble_signed` now self-verifies the host-produced
/// signature against the exact message it must sign BEFORE emitting the
/// broadcast-ready tx — "sign what you see," enforced per chain:
///   - BTC: each input's signature vs its BIP143 sighash under the sender pubkey.
///   - Cosmos: the secp256k1 sig vs the SignDoc sighash under the signer pubkey.
///   - Solana: the Ed25519 sig vs the serialized message under the fee-payer key.
///   - EVM: recover the signer from the sighash + (r,s,recovery_id) and compare
///     to the host-set wallet address (catches a wrong recovery bit / corrupt r,s
///     that the recovery_id ∈ {0,1} range check alone cannot).
/// A wrong/misordered/corrupt signature fails loud (no broadcast of a tx the
/// network would reject or that recovers to the wrong account). The simulate
/// read-paths (Cosmos/Solana) use a separate `assemble_for_simulation` that
/// splices a dummy sig WITHOUT verification (node runs sigVerify off).
///
/// This is proven at Layer 1 (`wallet-base-core`): `btc/tx.rs`
/// (`assemble_rejects_wrong_signature` / `…_misordered_signatures`),
/// `cosmos/tx.rs` + `solana/tx.rs` (`assemble_accepts_valid_signature` /
/// `assemble_rejects_wrong_signature`), and `tests/evm_vectors.rs`
/// (`eip155_self_verify_accepts_correct_signer` / `…_rejects_wrong_signer`).
/// This stub records the handler-level expectation that a host that ever returns
/// a mismatched signature surfaces a 5xx and NEVER broadcasts.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn multi_chain_assemble_self_verifies_signature() {
    // 1. Drive a send on each chain to a successful broadcast (happy path).
    // 2. With a fault-injected signer returning a wrong/misordered signature,
    //    assert the send fails (5xx) and no Transaction row reaches `broadcasting`.
    todo!("wire up in the integration harness")
}

/// **btc_fee_bound_and_counted_toward_cap** (#2 BTC fee bound)
///
/// Scenario: The coin-selected fee (`fee_rate_sat_vb × estimated vsize`) is now
/// surfaced into the spend gate on BOTH `/btc/send` and `/btc/sign`, so the
/// Bitcoin path enforces the per-tx fee cap and counts the fee toward the daily
/// cap — identically to EVM/Cosmos (total outflow = value + fee).
///
/// Expected:
/// - A `/btc/send` whose selected fee exceeds `max_fee_wei` (sats) is rejected
///   BEFORE the key is touched (no signature, no broadcast, no daily debit).
/// - A `/btc/send` where `value + fee` exceeds the daily cap is rejected even
///   when `value` alone is within it.
/// - On a successful send, the persisted `Transaction.fee_wei` equals the
///   coin-selected fee and `DailySpend` is debited `value + fee` (denom `sat`).
/// - `/btc/sign` enforces and debits the same way (the daily debit is mandatory
///   on the sign path so the cap can't be bypassed by self-broadcasting).
/// The pure fee bound + total-outflow accounting are already proven by
/// `wallet-base-core`'s `guardrails.rs` (`fee_over_fee_cap_rejected`,
/// `fee_counts_toward_daily_cap`) and the surfaced fee by `coinselect.rs`; this
/// stub is the handler-level confirmation that the BTC path wires the selected
/// fee into the gate and the ledger.
#[cfg(test)]
#[test]
#[ignore = "needs the docker host + control-plane + store harness"]
fn btc_fee_bound_and_counted_toward_cap() {
    // 1. Create a btc wallet for user U funded by a confirmed UTXO.
    // 2. PUT /btc/policy with a tiny per-tx fee cap (max_fee_wei in sats) and a
    //    high fee_rate_sat_vb on the send so the selected fee exceeds it.
    // 3. POST /btc/send → assert HTTP 400 (over fee cap), no Transaction row, no
    //    DailySpend debit.
    // 4. Set a daily cap where value alone fits but value + fee does not; assert
    //    the send is rejected for the daily cap.
    // 5. On an in-policy send, assert Transaction.fee_wei == the selected fee and
    //    DailySpend advanced by value + fee.
    todo!("wire up in the integration harness")
}
