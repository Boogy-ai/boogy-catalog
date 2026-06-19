//! wallet-base — a multi-chain custodial wallet (catalog service).
//!
//! Per-tenant key custody, address derivation, and transaction signing. Pure
//! EVM logic (alloy-backed key derivation, address computation, RLP transaction
//! encoding + signing) lives in the host-testable sibling crate
//! `wallet-base-core` (rlib); its unit tests run via `cargo test -p
//! wallet-base-core`.
//!
//! This task implements the wallets CRUD surface plus the EXTERNAL-SIGNER,
//! sign-only EVM endpoint:
//!
//! - `POST /wallets` — idempotently ensure the caller's wallet for a chain
//!   exists (creates a host-custodied secp256k1 key on first call), returns its
//!   address.
//! - `GET /wallets` — list the caller's wallets.
//! - `GET /wallets/{chain}` — the caller's wallet for one chain (404-masked).
//! - `POST /evm/sign` — sign a fully-specified EVM intent (nonce + fees carried
//!   by the intent) with the caller's host-held key and return the broadcast-
//!   ready raw transaction hex. The private key never enters the wasm.
//!
//! Security invariant: the signing-key LABEL is always derived from the
//! host-attested principal via `wallet_label_checked(current_principal(),
//! chain)` — NEVER from request input. That is the sign-as-anyone guard.

mod bindings {
    wit_bindgen::generate!({
        world: "service-with-jobs",
        path: "../../boogy-wit/wit",
    });
}

boogy_sdk::wit_glue!(bindings, WalletBase, with_jobs);

mod admin;
mod btc;
mod cosmos;
mod integration_checklist;
mod jobs;
mod mcp;
mod models;
mod rpc_client;
mod solana;
use models::{
    AdminAudit, BlockedPrincipal, DailySpend, NonceReservation, Transaction, Wallet, WalletPolicy,
};
use rpc_client::call_evm_rpc;

use boogy_sdk::jobs::JobSpec;
use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::pagination::decode;
use boogy_sdk::signing::SigAlg;
use boogy_sdk::{Api, JobRouter};
use wallet_base_core::btc::{BtcAdapter, BtcNetwork};
use wallet_base_core::cosmos::CosmosAdapter;
use wallet_base_core::evm::EvmAdapter;
use wallet_base_core::solana::SolanaAdapter;
use wallet_base_core::types::{ChainAdapter, ChainState, EvmIntent, SignRequest};

struct WalletBase;

impl Api for WalletBase {
    fn init_tables() {
        create_model::<Wallet>();
        create_model::<Transaction>();
        create_model::<WalletPolicy>();
        create_model::<DailySpend>();
        create_model::<BlockedPrincipal>();
        create_model::<AdminAudit>();
        create_model::<NonceReservation>();
    }

    fn build_router() -> Router {
        Router::new()
            .info("Wallet", "0.1.0", Some("Multi-chain custodial wallet"))
            .summary("Liveness probe")
            .description(
                "Returns 200 with a trivial body confirming the wallet \
                 service is mounted and serving.",
            )
            .get("/healthz", healthz)
            .summary("Ensure a wallet")
            .description(
                "Idempotently ensure the caller's wallet for a chain exists. On \
                 first call a host-custodied secp256k1 key is generated and its \
                 address derived; repeat calls return the existing address. The \
                 private key never leaves the host. Only `evm` is supported in \
                 this phase.",
            )
            .post("/wallets", ensure_wallet)
            .summary("List wallets")
            .description(
                "List the calling principal's wallets across all chains. \
                 Principal-scoped: a caller only ever sees their own wallets.",
            )
            .get("/wallets", list_wallets)
            .summary("Get a wallet")
            .description(
                "Fetch the caller's wallet for a single chain. 404-masked: a \
                 missing wallet and another principal's wallet are \
                 indistinguishable.",
            )
            .get("/wallets/{chain}", get_wallet)
            .summary("Sign an EVM transaction")
            .description(
                "Sign a fully-specified EVM intent (nonce + fees carried by the \
                 intent) with the caller's host-held key and return the \
                 broadcast-ready raw transaction hex. Sign-only: no nonce/fee \
                 fetch and no broadcast. The signing key is selected from the \
                 host-attested principal, never from the request body.",
            )
            .post("/evm/sign", evm_sign)
            .summary("Get current EVM fee estimates")
            .description(
                "Fetches the current EVM base fee (from the pending block) and \
                 the suggested max priority fee, then computes a conservative \
                 max fee per gas (base × 2 + priority fee). All values are \
                 returned as decimal strings (wei).",
            )
            .get("/evm/fees", evm_fees)
            .summary("Simulate an EVM transaction")
            .description(
                "Runs eth_estimateGas for the caller's EVM intent. If estimation \
                 fails (e.g. the transaction would revert), falls back to \
                 eth_call to capture the revert reason. Returns success, the \
                 estimated gas, and any error message. Requires the caller to \
                 have an EVM wallet (POST /wallets first).",
            )
            .post("/evm/simulate", evm_simulate)
            .summary("Send an EVM transaction")
            .description(
                "Resolve, simulate, policy-check, sign, persist, and enqueue \
                 broadcast of an EVM transaction in one call. Missing nonce/fees \
                 are fetched on-chain; the transaction is simulated and checked \
                 against the caller's spend policy (per-tx + daily caps, \
                 recipient/contract allowlists, refuse-on-revert) BEFORE the key \
                 is touched. On success the signed tx + spend accumulator are \
                 committed and a durable broadcast job is enqueued atomically; \
                 the response carries the new transaction id with status \
                 `signed`. Broadcast + confirmation proceed asynchronously and \
                 are streamed on the `wallet` WS channel.",
            )
            .post("/evm/send", evm_send)
            .summary("Get the caller's EVM spend policy")
            .description(
                "Return the calling principal's EVM `WalletPolicy` (per-tx cap, \
                 daily cap, recipient/contract allowlists, refuse-on-revert). \
                 Principal-scoped; defaults (no caps, empty allowlists, \
                 refuse_on_revert = true) are returned when no policy is set.",
            )
            .get("/evm/policy", get_policy)
            .summary("Set the caller's EVM spend policy")
            .description(
                "Upsert the calling principal's EVM `WalletPolicy`. Caps are \
                 decimal-wei strings (\"0\" or empty = no cap); allowlists are \
                 arrays of lowercased `0x` addresses (empty = no restriction). \
                 Principal-scoped: a caller only ever writes their own policy.",
            )
            .put("/evm/policy", put_policy)
            // ── Cosmos surface ────────────────────────────────────────────────
            .summary("Sign a Cosmos transaction")
            .description(
                "Sign a fully-specified Cosmos bank-send intent (account_number, \
                 sequence, and gas_limit carried by the body) with the caller's \
                 host-held key and return the broadcast-ready raw transaction hex \
                 (a TxRaw, hex-encoded). Sign-only: no account fetch and no \
                 broadcast. The signing key is selected from the host-attested \
                 principal, never from the request body. Requires the caller to \
                 have a Cosmos wallet (POST /wallets first).",
            )
            .post("/cosmos/sign", cosmos::cosmos_sign)
            .summary("Simulate a Cosmos transaction")
            .description(
                "Estimate gas for the caller's Cosmos intent via the LCD simulate \
                 endpoint. The signing key is NOT touched — the transaction is \
                 assembled with a dummy signature, which the simulate endpoint \
                 does not verify. Account number/sequence are read from the body \
                 or fetched on-chain when absent. Returns success, the estimated \
                 gas, and any error. Requires the caller to have a Cosmos wallet.",
            )
            .post("/cosmos/simulate", cosmos::cosmos_simulate)
            .summary("Estimate Cosmos gas")
            .description(
                "Estimate the gas for a posted Cosmos intent. Cosmos has no \
                 EIP-1559 base-fee market: the fee is `gas_used × gas_price`, \
                 where the gas price is operator/chain-configured. This runs the \
                 same simulate as /cosmos/simulate and returns just the gas \
                 estimate; the caller multiplies by their chosen gas price. The \
                 signing key is not touched.",
            )
            .post("/cosmos/fees", cosmos::cosmos_fees)
            .summary("Send a Cosmos transaction")
            .description(
                "Resolve, policy-check, sign, persist, and enqueue broadcast of a \
                 Cosmos bank-send in one call. Account number/sequence are fetched \
                 on-chain when absent and a missing gas_limit is estimated via \
                 simulate; the transfer is checked against the caller's spend \
                 policy (per-tx + daily caps, recipient allowlist) BEFORE the key \
                 is touched. On success the signed tx + spend accumulator are \
                 committed and a durable broadcast job is enqueued atomically; the \
                 response carries the new transaction id with status `signed`. \
                 Broadcast + confirmation proceed asynchronously and are streamed \
                 on the `wallet` WS channel.",
            )
            .post("/cosmos/send", cosmos::cosmos_send)
            .summary("Get the caller's Cosmos spend policy")
            .description(
                "Return the calling principal's Cosmos `WalletPolicy` (per-tx cap, \
                 daily cap, recipient allowlist, refuse-on-revert). Caps are \
                 decimal base-denom amounts. Principal-scoped; defaults (no caps, \
                 empty allowlists, refuse_on_revert = true) are returned when no \
                 policy is set.",
            )
            .get("/cosmos/policy", cosmos::cosmos_get_policy)
            .summary("Set the caller's Cosmos spend policy")
            .description(
                "Upsert the calling principal's Cosmos `WalletPolicy`. Caps are \
                 decimal base-denom strings (\"0\" or empty = no cap); the \
                 recipient allowlist is an array of bech32 addresses (empty = no \
                 restriction). Principal-scoped: a caller only ever writes their \
                 own policy.",
            )
            .put("/cosmos/policy", cosmos::cosmos_put_policy)
            // ── Solana surface ────────────────────────────────────────────────
            .summary("Sign a Solana transaction")
            .description(
                "Sign a fully-specified Solana SystemProgram transfer \
                 (recent_blockhash carried by the body) with the caller's \
                 host-held Ed25519 key and return the broadcast-ready raw \
                 transaction hex. Sign-only: no blockhash fetch and no broadcast. \
                 The signing key is selected from the host-attested principal, \
                 never from the request body. Requires the caller to have a \
                 Solana wallet (POST /wallets first).",
            )
            .post("/solana/sign", solana::solana_sign)
            .summary("Simulate a Solana transaction")
            .description(
                "Dry-run the caller's Solana transfer via simulateTransaction. \
                 The signing key is NOT touched — the transaction is assembled \
                 with a dummy signature, which simulate (sigVerify:false) does \
                 not verify. recent_blockhash is read from the body or fetched \
                 on-chain when absent. Returns success, the compute units \
                 consumed, and any error. Requires the caller to have a Solana \
                 wallet.",
            )
            .post("/solana/simulate", solana::solana_simulate)
            .summary("Estimate Solana fees")
            .description(
                "Return the network fee (lamports) for a posted Solana transfer \
                 via getFeeForMessage. recent_blockhash is read from the body or \
                 fetched on-chain when absent. fee_lamports is null when the \
                 blockhash is unknown/expired — refresh the blockhash and retry. \
                 The signing key is not touched.",
            )
            .post("/solana/fees", solana::solana_fees)
            .summary("Send a Solana transaction")
            .description(
                "Resolve, policy-check, sign, persist, and enqueue broadcast of a \
                 Solana SystemProgram transfer in one call. recent_blockhash is \
                 fetched on-chain when absent; the transfer is checked against the \
                 caller's spend policy (per-tx + daily caps, recipient allowlist) \
                 BEFORE the key is touched. On success the signed tx + spend \
                 accumulator are committed and a durable broadcast job is enqueued \
                 atomically; the response carries the new transaction id with \
                 status `signed`. Broadcast + confirmation proceed asynchronously \
                 and are streamed on the `wallet` WS channel.",
            )
            .post("/solana/send", solana::solana_send)
            .summary("Get the caller's Solana spend policy")
            .description(
                "Return the calling principal's Solana `WalletPolicy` (per-tx cap, \
                 daily cap, recipient allowlist, refuse-on-revert). Caps are \
                 decimal lamport amounts. Principal-scoped; defaults (no caps, \
                 empty allowlists, refuse_on_revert = true) are returned when no \
                 policy is set.",
            )
            .get("/solana/policy", solana::solana_get_policy)
            .summary("Set the caller's Solana spend policy")
            .description(
                "Upsert the calling principal's Solana `WalletPolicy`. Caps are \
                 decimal lamport strings (\"0\" or empty = no cap); the recipient \
                 allowlist is an array of base58 addresses (empty = no \
                 restriction). Principal-scoped: a caller only ever writes their \
                 own policy.",
            )
            .put("/solana/policy", solana::solana_put_policy)
            // ── Bitcoin surface ──────────────────────────────────────────────
            .summary("Sign a Bitcoin transaction")
            .description(
                "Sign a fully-specified Bitcoin P2WPKH transfer (the UTXO set and \
                 fee rate carried by the body) with the caller's host-held \
                 secp256k1 key and return the broadcast-ready raw transaction hex. \
                 Each selected input is signed independently (one ECDSA signature \
                 over its BIP143 sighash). Sign-only: no UTXO fetch and no \
                 broadcast. The signing key is selected from the host-attested \
                 principal, never from the request body. Requires the caller to \
                 have a Bitcoin wallet (POST /wallets first).",
            )
            .post("/btc/sign", btc::btc_sign)
            .summary("Estimate Bitcoin fees")
            .description(
                "Fetch the current sat/vB fee-rate estimates and return a fast \
                 (next-block) and a normal (6-block) rate. Bitcoin has no \
                 account-fee market: the fee is the chosen rate × the \
                 transaction's virtual size, paid as inputs minus outputs. The \
                 signing key is not touched.",
            )
            .post("/btc/fees", btc::btc_fees)
            .summary("Send a Bitcoin transaction")
            .description(
                "Fetch, policy-check, sign, persist, and enqueue broadcast of a \
                 Bitcoin P2WPKH transfer in one call. The spendable (confirmed) \
                 UTXO set is fetched on-chain and a missing fee rate is fetched \
                 from the fee estimator; the transfer is checked against the \
                 caller's spend policy (per-tx + daily caps, recipient allowlist) \
                 BEFORE the key is touched. Coin selection runs and each selected \
                 input is signed independently. On success the signed tx + spend \
                 accumulator are committed and a durable broadcast job is enqueued \
                 atomically; the response carries the new transaction id with \
                 status `signed`. Broadcast + confirmation proceed asynchronously \
                 and are streamed on the `wallet` WS channel.",
            )
            .post("/btc/send", btc::btc_send)
            .summary("Get the caller's Bitcoin spend policy")
            .description(
                "Return the calling principal's Bitcoin `WalletPolicy` (per-tx \
                 cap, daily cap, recipient allowlist, refuse-on-revert). Caps are \
                 decimal satoshi amounts. Principal-scoped; defaults (no caps, \
                 empty allowlists, refuse_on_revert = true) are returned when no \
                 policy is set.",
            )
            .get("/btc/policy", btc::btc_get_policy)
            .summary("Set the caller's Bitcoin spend policy")
            .description(
                "Upsert the calling principal's Bitcoin `WalletPolicy`. Caps are \
                 decimal satoshi strings (\"0\" or empty = no cap); the recipient \
                 allowlist is an array of bech32 addresses (empty = no \
                 restriction). Principal-scoped: a caller only ever writes their \
                 own policy.",
            )
            .put("/btc/policy", btc::btc_put_policy)
            // ── MCP surface ──────────────────────────────────────────────────
            .mcp("/mcp", mcp::mcp_dispatch)
            // ── Operator admin surface (/admin/*; owner-only) ─────────────────
            .summary("List all wallets (operator)")
            .description(
                "Operator view of all wallets across all principals. \
                 Requires the service owner's agent token.",
            )
            .get("/admin/wallets", admin::admin_list_wallets)
            .summary("List all transactions (operator)")
            .description(
                "Operator view of all transactions across all principals. \
                 Optional `?status=` and `?owner=` residual filters.",
            )
            .get("/admin/transactions", admin::admin_list_transactions)
            .summary("Get a principal's EVM policy (operator)")
            .description(
                "Return the EVM spend policy for any principal. \
                 Returns defaults when no policy is set.",
            )
            .get("/admin/policy/{principal}", admin::admin_get_policy)
            .summary("Set a principal's EVM policy (operator)")
            .description(
                "Upsert the EVM spend policy for any principal. \
                 The operator can tighten a user's per-tx / daily caps.",
            )
            .put("/admin/policy/{principal}", admin::admin_put_policy)
            .summary("Block a principal (operator)")
            .description(
                "Block a principal from sending transactions (idempotent). \
                 Optional body `{ reason? }`. Writes an audit row on a newly-created block.",
            )
            .post("/admin/block/{principal}", admin::admin_block_principal)
            .summary("Unblock a principal (operator)")
            .description(
                "Lift a principal's block (idempotent — `204` if not currently blocked). \
                 Writes an audit row only when a block was removed.",
            )
            .post("/admin/unblock/{principal}", admin::admin_unblock_principal)
            .summary("Operator audit log")
            .description(
                "Keyset-paginated operator audit log, newest-first. \
                 Optional `?action=` equality filter.",
            )
            .get("/admin/audit", admin::admin_list_audit)
    }

    fn build_job_router() -> JobRouter {
        JobRouter::new()
            .exact(jobs::broadcast_tx)
            .exact(jobs::poll_confirmation)
    }
}

/// Liveness response body.
#[derive(Serialize, schemars::JsonSchema)]
struct Health {
    status: String,
}

fn healthz(_req: &mut Req<'_>) -> Result<Json<Health>, ApiError> {
    Ok(Json(Health { status: "ok".into() }))
}

// ─── DTOs ────────────────────────────────────────────────────────────────────

/// Request body for `POST /wallets`. Only the chain is caller-supplied; the
/// owning principal is host-attested, never sent.
#[derive(Deserialize, schemars::JsonSchema)]
struct EnsureWalletReq {
    /// Target chain. Only `evm` is supported in this phase.
    chain: String,
}

/// A wallet projection returned to the caller. The `pubkey_hex` is the SEC1
/// public key; no secret material is ever exposed.
#[derive(Serialize, schemars::JsonSchema)]
struct WalletOut {
    chain: String,
    address: String,
}

/// Thin request DTO mirroring the core `EvmIntent`. It exists so the OpenAPI
/// spec gets a `JsonSchema` without `wallet-base-core` taking a `schemars`
/// dependency; it `.into()`s the core type verbatim.
#[derive(Deserialize, schemars::JsonSchema)]
struct EvmIntentReq {
    /// `0x`-hex recipient address; omit for contract creation.
    to: Option<String>,
    /// Transfer amount in wei, as a decimal string (u256-safe).
    value_wei: String,
    /// `0x`-prefixed calldata; `""` or `"0x"` means empty.
    data_hex: String,
    chain_id: u64,
    /// Transaction nonce. Required for sign-only (no on-chain fetch happens).
    nonce: Option<u64>,
    max_fee_per_gas: Option<String>,
    max_priority_fee_per_gas: Option<String>,
    gas_limit: Option<u64>,
    /// `true` for a legacy (type-0) transaction; otherwise EIP-1559 (type-2).
    legacy: bool,
    /// Gas price for a legacy transaction (decimal string).
    gas_price: Option<String>,
}

impl From<EvmIntentReq> for EvmIntent {
    fn from(r: EvmIntentReq) -> Self {
        EvmIntent {
            to: r.to,
            // The signer is NEVER taken from the request body — do_send sets it
            // host-side from the wallet row (the #15 self-verify anchor).
            from_address: String::new(),
            value_wei: r.value_wei,
            data_hex: r.data_hex,
            chain_id: r.chain_id,
            nonce: r.nonce,
            max_fee_per_gas: r.max_fee_per_gas,
            max_priority_fee_per_gas: r.max_priority_fee_per_gas,
            gas_limit: r.gas_limit,
            legacy: r.legacy,
            gas_price: r.gas_price,
        }
    }
}

/// Result of `POST /evm/sign`: the broadcast-ready raw transaction hex.
#[derive(Serialize, schemars::JsonSchema)]
struct SignOut {
    /// `0x`-prefixed RLP-encoded signed transaction, ready to broadcast.
    raw: String,
}

// ─── Wallets CRUD ────────────────────────────────────────────────────────────

/// Core of `POST /wallets`: idempotently ensure the caller's wallet for a
/// chain and return its address. Shared by the REST handler and the MCP
/// `get_address` tool.
///
/// Resolve the signing label from `(principal, chain)` (NEVER from the body),
/// look up an existing wallet row for `(owner_principal, chain)`. If present,
/// return its address; else generate a host-custodied secp256k1 key, derive the
/// EVM address from the returned SEC1 public key, persist the row, and return
/// the address.
pub(crate) fn do_ensure_wallet(principal: &str, chain: &str) -> Result<WalletOut, ApiError> {
    // A blocked principal cannot mint a new signing key.
    if is_blocked(principal)? {
        return Err(ApiError::forbidden("this account is blocked"));
    }

    // Label derives ONLY from the attested principal + chain — the
    // sign-as-anyone guard. Also validates the chain string (∈ {evm,btc,cosmos,solana}).
    let label = wallet_base_core::subject::wallet_label_checked(principal, chain)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    // Idempotent: an existing wallet for this (principal, chain) wins.
    if let Some(row) = Query::on(Wallet::TABLE)
        .where_eq(Wallet::OWNER_PRINCIPAL, principal)
        .where_eq(Wallet::CHAIN, chain)
        .fetch_one()?
    {
        let w = Wallet::from_row(&row);
        return Ok(WalletOut { chain: w.chain, address: w.address });
    }

    // First call: create the host-held key (returns the public key), then derive
    // the per-chain address from it. The signing curve is chain-specific: EVM and
    // Cosmos share a secp256k1 key (only the address encoding differs); Solana
    // uses Ed25519 (the address IS the 32-byte pubkey, base58). Pick the alg
    // BEFORE creating the key. The private key never enters the wasm.
    let alg = match chain {
        "solana" => SigAlg::Ed25519,
        _ => SigAlg::EcdsaSecp256k1,
    };
    let pubkey = signing_create_key(&label, alg)
        .map_err(|e| ApiError::internal(format!("create signing key: {e}")))?;

    // The STORED pubkey is per-chain. EVM/Cosmos/Solana store the host pubkey
    // exactly as returned. BTC P2WPKH is defined ONLY over the 33-byte
    // COMPRESSED secp256k1 key (the host may return uncompressed 65-byte SEC1),
    // and the address + every witness MUST commit to that SAME compressed key —
    // so the btc arm compresses first, then both derives the address from and
    // stores the compressed form.
    let stored_pubkey = match chain {
        "btc" => wallet_base_core::btc::compress_pubkey(&pubkey)
            .map_err(|e| ApiError::internal(format!("compress pubkey: {e}")))?,
        _ => pubkey,
    };

    let address = match chain {
        "evm" => EvmAdapter
            .derive_address(&stored_pubkey)
            .map_err(|e| ApiError::internal(format!("derive address: {e}")))?,
        "cosmos" => CosmosAdapter::address_from_pubkey(&stored_pubkey, COSMOS_HRP)
            .map_err(|e| ApiError::internal(format!("derive address: {e}")))?,
        // pubkey is the 32-byte Ed25519 key; the Solana address IS its base58.
        "solana" => SolanaAdapter::address_from_pubkey(&stored_pubkey)
            .map_err(|e| ApiError::internal(format!("derive address: {e}")))?,
        // bech32(P2WPKH(hash160(compressed_pubkey))) on this deployment's network.
        "btc" => BtcAdapter::address_from_pubkey(&stored_pubkey, BTC_NETWORK)
            .map_err(|e| ApiError::internal(format!("derive address: {e}")))?,
        _ => return Err(ApiError::bad_request("chain not yet supported")),
    };

    db_insert(&Wallet {
        id: Id::new(0),
        owner_principal: principal.to_string(),
        chain: chain.to_string(),
        label,
        address: address.clone(),
        pubkey_hex: hex::encode(&stored_pubkey),
        created_at: Timestamp::new(now_millis() as i64),
    })
    .map_err(ApiError::from)?;

    Ok(WalletOut { chain: chain.to_string(), address })
}

/// `POST /wallets` — idempotently ensure the caller's wallet for a chain.
fn ensure_wallet(Json(body): Json<EnsureWalletReq>) -> Result<Json<WalletOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    do_ensure_wallet(&p, &body.chain).map(Json)
}

/// `GET /wallets` — list the caller's wallets across all chains.
fn list_wallets(_req: &mut Req<'_>) -> Result<Json<Vec<WalletOut>>, ApiError> {
    let rows = auth::find_owned(Wallet::TABLE, Wallet::OWNER_PRINCIPAL)?;
    let out = rows
        .iter()
        .map(|r| {
            let w = Wallet::from_row(r);
            WalletOut { chain: w.chain, address: w.address }
        })
        .collect();
    Ok(Json(out))
}

/// `GET /wallets/{chain}` — the caller's wallet for one chain (404-masked).
fn get_wallet(req: &mut Req<'_>) -> Result<Json<WalletOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    let chain = req.params.get("chain").unwrap_or_default().to_string();

    let row = Query::on(Wallet::TABLE)
        .where_eq(Wallet::OWNER_PRINCIPAL, p.as_str())
        .where_eq(Wallet::CHAIN, chain.as_str())
        .fetch_one()?
        .ok_or_else(ApiError::not_found)?;

    let w = Wallet::from_row(&row);
    Ok(Json(WalletOut { chain: w.chain, address: w.address }))
}

// ─── EVM sign-only ───────────────────────────────────────────────────────────

/// `POST /evm/sign` — sign a fully-specified EVM intent.
///
/// Resolves the host-attested principal, derives the `evm` signing label from
/// it (NEVER the body), and requires the caller's local `evm` wallet row to
/// exist (its presence is the local key cache — we do NOT probe the signer with
/// `signing_list_keys`). Builds the unsigned tx from the intent alone
/// (`ChainState::default()`; the intent carries nonce + fees), signs each digest
/// with the host-held key, converts the compact signature, and assembles the
/// raw tx. Sign-only: no broadcast.
fn evm_sign(Json(body): Json<EvmIntentReq>) -> Result<Json<SignOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;

    // A blocked principal cannot sign (gate parity with /send — the returned raw
    // tx is a complete, self-broadcastable spend of the custodial key).
    if is_blocked(&p)? {
        return Err(ApiError::forbidden("this account is blocked"));
    }

    // Label is host-derived; this also re-validates that "evm" is a known chain.
    let label = wallet_base_core::subject::wallet_label_checked(&p, "evm")
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    // Local key cache: require the wallet row before touching the signer. A
    // missing row → the key was never created for this principal.
    let wallet_row = Query::on(Wallet::TABLE)
        .where_eq(Wallet::OWNER_PRINCIPAL, p.as_str())
        .where_eq(Wallet::CHAIN, "evm")
        .fetch_one()?
        .ok_or_else(|| ApiError::bad_request("no evm wallet; create one first"))?;
    let wallet = Wallet::from_row(&wallet_row);

    let mut intent: EvmIntent = body.into();
    // Anchor the #15 post-assembly self-verify on the host-attested wallet
    // address (never the body) — the sign path returns a broadcast-ready,
    // fully-authorizing tx, so it self-verifies the signature like /send.
    intent.from_address = wallet.address;

    // ── Guardrails BEFORE the key is touched (#1) ──
    // Sign-only returns a broadcast-ready, fully-authorizing tx, so it MUST honour
    // the same block-list + spend policy as /send, and MUST debit daily-spend (or
    // a caller bypasses the daily cap by signing N times). No simulation runs on
    // this path, so contract-ness is inferred from calldata only and there is no
    // revert signal (sim_success = true).
    let total_fee_wei = {
        let gas_limit = intent.gas_limit.unwrap_or(21_000) as u128;
        let per_gas = if intent.legacy {
            intent.gas_price.as_deref()
        } else {
            intent.max_fee_per_gas.as_deref()
        };
        let per_gas = per_gas.and_then(|s| s.trim().parse::<u128>().ok()).unwrap_or(0);
        gas_limit.saturating_mul(per_gas).to_string()
    };
    let recipient = intent.to.clone().unwrap_or_default().to_lowercase();
    enforce_spend_policy(
        &p,
        EVM_CHAIN,
        &Spend {
            value: intent.value_wei.clone(),
            fee: total_fee_wei.clone(),
            denom: "wei".to_string(),
            recipient,
            sim_success: true,
        },
    )?;

    let unsigned = EvmAdapter
        .build_unsigned(&intent, &ChainState::default())
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let mut sigs = Vec::with_capacity(unsigned.sign_requests.len());
    for sr in &unsigned.sign_requests {
        let digest = match sr {
            SignRequest::Digest(d) => d,
            SignRequest::Message(_) => {
                return Err(ApiError::internal("evm adapter produced a non-digest sign request"))
            }
        };
        let sdk_sig = signing_sign_digest(&label, digest, SigAlg::EcdsaSecp256k1)
            .map_err(|e| ApiError::internal(format!("sign digest: {e}")))?;
        let sig = wallet_base_core::secp_sig_from_compact(&sdk_sig.bytes, sdk_sig.recovery_id)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        sigs.push(sig);
    }

    let raw = EvmAdapter
        .assemble_signed(&unsigned, &sigs)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let raw_hex = raw.to_hex();

    // Record the signed tx + debit daily-spend (no broadcast job — the caller
    // self-broadcasts). status `signed_external`.
    let intent_json = serde_json::to_string(&intent)
        .map_err(|e| ApiError::internal(format!("encode intent: {e}")))?;
    let to_addr = intent.to.clone().unwrap_or_default();
    let nonce_i64 = intent.nonce.unwrap_or(0) as i64;
    record_external_sign(
        &p,
        EVM_CHAIN,
        "wei",
        &to_addr,
        &intent.value_wei,
        nonce_i64,
        &total_fee_wei,
        &raw_hex,
        &intent_json,
    )?;

    Ok(Json(SignOut { raw: raw_hex }))
}

// ─── EVM fees ────────────────────────────────────────────────────────────────

/// Response for `GET /evm/fees`.
///
/// All gas values are in wei, serialized as decimal strings (u128 fits 39
/// decimal digits; JavaScript's `BigInt` or a `uint256` in the caller handles
/// them safely).
#[derive(Serialize, schemars::JsonSchema)]
struct FeesOut {
    /// Conservative max fee per gas: `base_fee × 2 + max_priority_fee` (wei,
    /// decimal string). Use this as the EIP-1559 `maxFeePerGas`.
    max_fee_per_gas: String,
    /// Suggested max priority fee per gas (wei, decimal string).
    max_priority_fee_per_gas: String,
    /// Current base fee per gas from the pending block (wei, decimal string).
    base_fee_per_gas: String,
}

/// Core of `GET /evm/fees`: fetch current EVM base + priority fees and compute
/// a conservative max fee. Shared by the REST handler and the MCP
/// `estimate_fee` tool.
pub(crate) fn do_fees() -> Result<FeesOut, ApiError> {
    // Shares fetch_base_and_tip, so the node-fee safety ceiling (#3) applies here
    // too — /evm/fees never echoes an absurd node-reported fee.
    let (base, tip) = fetch_base_and_tip()?;
    let max_fee = base.saturating_mul(2).saturating_add(tip);

    Ok(FeesOut {
        max_fee_per_gas: max_fee.to_string(),
        max_priority_fee_per_gas: tip.to_string(),
        base_fee_per_gas: base.to_string(),
    })
}

/// `GET /evm/fees` — fetch current EVM base + priority fees and compute a
/// conservative max fee.
///
/// Makes two sequential outbound JSON-RPC calls:
/// 1. `eth_maxPriorityFeePerGas` → tip
/// 2. `eth_getBlockByNumber("pending", false)` → base fee
///
/// Returns `max_fee_per_gas = base_fee × 2 + tip` (a common conservative
/// ceiling that accommodates block-to-block base-fee variance).
fn evm_fees(_req: &mut Req<'_>) -> Result<Json<FeesOut>, ApiError> {
    do_fees().map(Json)
}

// ─── EVM simulate ────────────────────────────────────────────────────────────

/// Response for `POST /evm/simulate`.
#[derive(Serialize, schemars::JsonSchema)]
struct SimOut {
    /// `true` if the transaction would succeed on-chain.
    success: bool,
    /// Estimated gas units consumed. `null` when the transaction reverts or
    /// when only `eth_call` (not `eth_estimateGas`) was used.
    gas_used: Option<u64>,
    /// Revert reason or RPC error message when `success` is `false`.
    error: Option<String>,
}

/// Core of `POST /evm/simulate`: simulate an EVM transaction for a given
/// principal. Shared by the REST handler and the MCP `simulate_transaction`
/// tool.
pub(crate) fn do_simulate(principal: &str, body: EvmIntentReq) -> Result<SimOut, ApiError> {
    use wallet_base_core::evm::rpc::{
        call_request, estimate_gas_request, parse_estimate_gas, parse_simulation,
    };

    // Resolve the caller's EVM wallet address so estimateGas uses the correct sender.
    let wallet_row = Query::on(Wallet::TABLE)
        .where_eq(Wallet::OWNER_PRINCIPAL, principal)
        .where_eq(Wallet::CHAIN, "evm")
        .fetch_one()?
        .ok_or_else(|| ApiError::bad_request("no evm wallet; create one first"))?;
    let from_addr = Wallet::from_row(&wallet_row).address;

    // Convert decimal value_wei → 0x-prefixed hex for the JSON-RPC call object.
    // This is the simulate-only path (no spend guardrail runs here), so an
    // unparseable value must be an explicit error — NOT silently coerced to "0x0",
    // which would simulate a different (zero-value) tx and could report
    // success: true for a tx that behaves differently (#16).
    let value_hex = {
        let v = body
            .value_wei
            .trim()
            .parse::<u128>()
            .map_err(|_| ApiError::bad_request("value_wei must be a decimal u128"))?;
        format!("0x{v:x}")
    };

    // Normalize calldata: ensure it is "0x"-prefixed (or empty → "0x").
    let data = if body.data_hex.is_empty() || body.data_hex == "0x" {
        "0x".to_string()
    } else if body.data_hex.starts_with("0x") {
        body.data_hex.clone()
    } else {
        format!("0x{}", body.data_hex)
    };

    let mut call_obj = serde_json::json!({
        "from": from_addr,
        "value": value_hex,
        "data": data,
    });
    if let Some(to) = &body.to {
        call_obj["to"] = serde_json::Value::String(to.clone());
    }

    // Try eth_estimateGas first.
    let estimate_resp = call_evm_rpc(&estimate_gas_request(call_obj.clone()))?;
    match parse_estimate_gas(&estimate_resp) {
        Ok(sim) if sim.success => {
            return Ok(SimOut { success: true, gas_used: sim.gas_used, error: None });
        }
        Ok(sim) => {
            // estimateGas surfaced a revert reason — return it directly.
            return Ok(SimOut { success: false, gas_used: None, error: sim.error });
        }
        Err(_) => {
            // Parsing failed; fall through to eth_call for the revert reason.
        }
    }

    // Fall back to eth_call to capture the revert reason.
    let call_resp = call_evm_rpc(&call_request(call_obj))?;
    let sim = parse_simulation(&call_resp)
        .map_err(|e| ApiError::service_unavailable(e.to_string()))?;

    Ok(SimOut { success: sim.success, gas_used: sim.gas_used, error: sim.error })
}

/// `POST /evm/simulate` — simulate an EVM transaction via `eth_estimateGas`,
/// falling back to `eth_call` to capture the revert reason on failure.
///
/// The `from` field is set to the caller's EVM wallet address so that
/// `eth_estimateGas` accounts for the correct sender context (token allowances,
/// balance checks, etc.). A 400 is returned when the caller has no EVM wallet.
///
/// The decimal `value_wei` from the intent is converted to a `0x`-prefixed hex
/// string for the JSON-RPC call object.
fn evm_simulate(Json(body): Json<EvmIntentReq>) -> Result<Json<SimOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    do_simulate(&p, body).map(Json)
}

// ─── EVM policy ──────────────────────────────────────────────────────────────

/// The fixed chain key for the EVM spend policy / daily-spend rows. Only `evm`
/// is supported in this phase, so policy is keyed by `(principal, "evm")`.
const EVM_CHAIN: &str = "evm";

/// The fixed chain key for the Cosmos spend policy / daily-spend rows.
pub(crate) const COSMOS_CHAIN: &str = "cosmos";

/// The fixed chain key for the Solana spend policy / daily-spend rows.
pub(crate) const SOLANA_CHAIN: &str = "solana";

/// The fixed chain key for the Bitcoin spend policy / daily-spend rows.
pub(crate) const BTC_CHAIN: &str = "btc";

/// The Bitcoin network this deployment signs for. Mainnet by default; a
/// testnet/signet deployment flips this const (and re-derives addresses
/// accordingly). The network gates `to_address` parsing and selects the bech32
/// HRP (`bc1q…` vs `tb1q…`).
pub(crate) const BTC_NETWORK: BtcNetwork = BtcNetwork::Mainnet;

/// Default bech32 human-readable prefix for Cosmos addresses (Cosmos Hub).
/// The Cosmos intent may override it per-request for other Cosmos SDK chains.
pub(crate) const COSMOS_HRP: &str = "cosmos";

/// Window length (seconds) of the rolling daily-spend accumulator.
const DAILY_WINDOW_SECS: i64 = 24 * 60 * 60;

/// Absolute safety ceiling (wei) on a NODE-supplied per-gas fee (base fee or
/// priority tip). 10,000 gwei — multiple orders of magnitude above any sane
/// mainnet fee, so it never rejects a legitimate spike, but fails closed when a
/// malicious/compromised RPC node inflates the fee to drain the wallet via gas
/// (review #3). Caller-supplied fees are bounded separately by the per-tx fee
/// cap (`max_fee_wei`); this ceiling backstops the auto-fetch path.
const MAX_NODE_FEE_PER_GAS_WEI: u128 = 10_000_000_000_000;

/// Request / response body for the EVM spend policy. Caps are decimal-wei
/// strings (`"0"` or empty = no cap); allowlists are arrays of lowercased `0x`
/// addresses (empty = no restriction).
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
struct PolicyReq {
    /// Per-transaction cap (decimal wei). `"0"`/empty = no per-tx cap.
    max_value_wei: String,
    /// Per-transaction FEE cap (decimal wei). `"0"`/empty = no fee cap. Bounds
    /// the resolved tx fee (gas/gas-price for EVM, `fee_amount` for Cosmos,
    /// fee-rate×vsize for BTC) — the fund-drain guard. The fee also counts
    /// toward the daily cap (total outflow = value + fee).
    #[serde(default)]
    max_fee_wei: String,
    /// Rolling 24h cap (decimal wei). `"0"`/empty = no daily cap.
    daily_cap_wei: String,
    /// Allowed recipient addresses (lowercased `0x`). Empty = no restriction.
    recipient_allowlist: Vec<String>,
    /// Allowed contract addresses (lowercased `0x`), checked when the
    /// destination is a contract. Empty = no restriction.
    contract_allowlist: Vec<String>,
    /// Reject a send whose simulation indicates an on-chain revert.
    refuse_on_revert: bool,
}

impl Default for PolicyReq {
    fn default() -> Self {
        PolicyReq {
            max_value_wei: String::new(),
            max_fee_wei: String::new(),
            daily_cap_wei: String::new(),
            recipient_allowlist: Vec::new(),
            contract_allowlist: Vec::new(),
            refuse_on_revert: true,
        }
    }
}

/// Parse a JSON-array-text allowlist column into a `Vec<String>`. A malformed
/// value yields an empty list (fail-open on the *list*, never on the decision —
/// an empty list means "no restriction", which is the conservative default for
/// an unparseable stored value and matches the no-policy case).
fn parse_allowlist(s: &str) -> Vec<String> {
    if s.trim().is_empty() {
        return Vec::new();
    }
    serde_json::from_str(s).unwrap_or_default()
}

impl From<&WalletPolicy> for PolicyReq {
    fn from(p: &WalletPolicy) -> Self {
        PolicyReq {
            max_value_wei: p.max_value_wei.clone(),
            max_fee_wei: p.max_fee_wei.clone(),
            daily_cap_wei: p.daily_cap_wei.clone(),
            recipient_allowlist: parse_allowlist(&p.recipient_allowlist),
            contract_allowlist: parse_allowlist(&p.contract_allowlist),
            refuse_on_revert: p.refuse_on_revert,
        }
    }
}

/// Load the caller's `WalletPolicy` row for a given chain, if any.
pub(crate) fn load_policy(
    principal: &str,
    chain: &str,
) -> Result<Option<WalletPolicy>, ApiError> {
    Ok(Query::on(WalletPolicy::TABLE)
        .where_eq(WalletPolicy::OWNER_PRINCIPAL, principal)
        .where_eq(WalletPolicy::CHAIN, chain)
        .fetch_one()?
        .map(|r| WalletPolicy::from_row(&r)))
}

/// `GET /evm/policy` — return the caller's EVM spend policy (defaults if none).
fn get_policy(_req: &mut Req<'_>) -> Result<Json<PolicyReq>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    let policy = load_policy(&p, EVM_CHAIN)?;
    Ok(Json(policy.as_ref().map(PolicyReq::from).unwrap_or_default()))
}

/// Upsert a principal's spend policy for one chain. Allowlists are stored as
/// JSON-array text. Shared by the EVM and Cosmos policy handlers.
pub(crate) fn put_policy_for(
    principal: &str,
    chain: &str,
    body: &PolicyReq,
) -> Result<PolicyReq, ApiError> {
    // independent-writes: this is a single-row upsert — the db_update and
    // db_insert below are mutually-exclusive branches (exactly one runs per
    // call), so there are never two dependent writes to make atomic.
    let recipient_allowlist = serde_json::to_string(&body.recipient_allowlist)
        .map_err(|e| ApiError::internal(format!("encode recipient allowlist: {e}")))?;
    let contract_allowlist = serde_json::to_string(&body.contract_allowlist)
        .map_err(|e| ApiError::internal(format!("encode contract allowlist: {e}")))?;
    let now = Timestamp::new(now_millis() as i64);

    match load_policy(principal, chain)? {
        Some(mut existing) => {
            existing.max_value_wei = body.max_value_wei.clone();
            existing.max_fee_wei = body.max_fee_wei.clone();
            existing.daily_cap_wei = body.daily_cap_wei.clone();
            existing.recipient_allowlist = recipient_allowlist;
            existing.contract_allowlist = contract_allowlist;
            existing.refuse_on_revert = body.refuse_on_revert;
            existing.updated_at = now;
            db_update(existing.id.get(), &existing).map_err(ApiError::from)?;
        }
        None => {
            db_insert(&WalletPolicy {
                id: Id::new(0),
                owner_principal: principal.to_string(),
                chain: chain.to_string(),
                max_value_wei: body.max_value_wei.clone(),
                max_fee_wei: body.max_fee_wei.clone(),
                daily_cap_wei: body.daily_cap_wei.clone(),
                recipient_allowlist,
                contract_allowlist,
                refuse_on_revert: body.refuse_on_revert,
                updated_at: now,
            })
            .map_err(ApiError::from)?;
        }
    }

    // Echo back the now-persisted policy.
    Ok(load_policy(principal, chain)?.as_ref().map(PolicyReq::from).unwrap_or_default())
}

/// `PUT /evm/policy` — upsert the caller's EVM spend policy. Allowlists are
/// stored as JSON-array text. Principal-scoped.
fn put_policy(Json(body): Json<PolicyReq>) -> Result<Json<PolicyReq>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    put_policy_for(&p, EVM_CHAIN, &body).map(Json)
}

// ─── EVM send ────────────────────────────────────────────────────────────────

/// Result of `POST /evm/send`: the new transaction row id and its status. The
/// status is always `signed` on success — broadcast + confirmation proceed
/// asynchronously and are streamed on the `wallet` WS channel.
#[derive(Serialize, schemars::JsonSchema)]
struct SendOut {
    /// The new `transactions` row id.
    tx_id: u64,
    /// `signed` — the durable pipeline takes it to `pending`/`confirmed`.
    status: String,
}

/// Core of `POST /evm/send`: the full resolve → simulate → policy → sign →
/// persist → enqueue pipeline for a given principal. Shared by the REST handler
/// and the MCP `send_transaction` tool.
///
/// Guardrails run BEFORE the key is touched (the reject-before-signing
/// invariant). The signing label is derived from the principal, never the body.
/// On success the `Transaction` row (status `signed`), the `DailySpend`
/// accumulator, and the `broadcast_tx` job enqueue commit together in one store
/// transaction.
/// Check whether `principal` is in the operator-blocked list.
///
/// A blocked principal is denied key-touch operations (send, sign). The check
/// is intentionally cheap: a single `#[lookup_by]` index scan on `principal`.
pub(crate) fn is_blocked(principal: &str) -> Result<bool, ApiError> {
    use boogy_sdk::store::Val;
    let hits: Vec<BlockedPrincipal> =
        db_find_by::<BlockedPrincipal>(BlockedPrincipal::PRINCIPAL, Val::Text(principal.to_string()))
            .map_err(ApiError::from)?;
    Ok(!hits.is_empty())
}

/// The resolved spend a chain handler hands to [`enforce_spend_policy`]. All
/// amounts are decimal strings in the chain's base unit (wei / uatom / lamport /
/// satoshi). `fee` is the resolved transaction fee (`""` = not resolved / network-
/// set, treated as 0 by the guardrail) — see [`enforce_spend_policy`].
pub(crate) struct Spend {
    pub value: String,
    pub fee: String,
    /// Denom/unit of `value` — the daily-spend accumulator key (`wei` / `lamport`
    /// / `sat` / the Cosmos base denom). Keeps multi-denom Cosmos caps honest (#6).
    pub denom: String,
    pub recipient: String,
    pub sim_success: bool,
}

/// Run the full spend-policy gate for `(principal, chain)` — the single
/// reject-before-signing enforcement point shared by EVERY key-touching path
/// (`/*/send` AND `/*/sign`). Loads the caller's `WalletPolicy` + `DailySpend`
/// window and runs `guardrails::check_policy`: per-tx value cap, **per-tx fee
/// cap**, daily cap on total outflow (`value + fee`), recipient/contract
/// allowlists, and refuse-on-revert. Fee bounding lives here so a huge
/// caller/node-supplied fee can never drain the wallet past the value cap.
///
/// The caller must ALSO have checked [`is_blocked`] and must debit the SAME
/// `(value, fee)` via [`upsert_daily_spend`] inside its persist `tx`.
/// Persist a sign-only transaction (status `signed_external` — the caller will
/// broadcast it themselves; NO `broadcast_tx` job) and debit the daily-spend
/// accumulator in ONE store `tx`. Shared by all four `/*/sign` gates.
///
/// The daily debit is the load-bearing half: without it a caller bypasses the
/// daily cap by calling `/sign` N times and self-broadcasting each signed tx.
/// `value`/`fee` are the SAME amounts passed to [`enforce_spend_policy`];
/// `nonce` reuses the `Transaction.nonce` column per the chain's convention
/// (EVM nonce / Cosmos sequence / 0 for Solana+BTC).
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_external_sign(
    owner: &str,
    chain: &str,
    denom: &str,
    to_addr: &str,
    value: &str,
    nonce: i64,
    fee: &str,
    raw_hex: &str,
    intent_json: &str,
) -> Result<u64, ApiError> {
    let now_secs = now_millis() as i64 / 1000;
    let now = Timestamp::new(now_millis() as i64);
    tx::<_, _, ApiError>(|| {
        let tx_id = db_insert(&Transaction {
            id: Id::new(0),
            owner_principal: owner.to_string(),
            chain: chain.to_string(),
            status: "signed_external".to_string(),
            intent_json: intent_json.to_string(),
            raw_hex: raw_hex.to_string(),
            tx_hash: String::new(),
            to_addr: to_addr.to_string(),
            value_wei: value.to_string(),
            nonce,
            fee_wei: fee.to_string(),
            sim_json: String::new(),
            confirmations: 0,
            created_at: now,
            updated_at: now,
        })
        .map_err(ApiError::from)?;
        upsert_daily_spend(owner, chain, denom, now_secs, value, fee, now)?;
        Ok(tx_id)
    })
}

pub(crate) fn enforce_spend_policy(
    principal: &str,
    chain: &str,
    s: &Spend,
) -> Result<(), ApiError> {
    let policy = load_policy(principal, chain)?;
    let now_secs = now_millis() as i64 / 1000;
    let daily = load_daily_spend(principal, chain, &s.denom, now_secs)?;

    let (max_value_wei, max_fee_wei, daily_cap_wei, recipient_allow, contract_allow, refuse_on_revert) =
        match &policy {
            Some(pol) => (
                pol.max_value_wei.clone(),
                pol.max_fee_wei.clone(),
                pol.daily_cap_wei.clone(),
                parse_allowlist(&pol.recipient_allowlist),
                parse_allowlist(&pol.contract_allowlist),
                pol.refuse_on_revert,
            ),
            None => (String::new(), String::new(), String::new(), Vec::new(), Vec::new(), true),
        };

    let pi = wallet_base_core::guardrails::PolicyInput {
        value_wei: s.value.clone(),
        fee_wei: s.fee.clone(),
        max_value_wei,
        max_fee_wei,
        daily_cap_wei,
        daily_spent_wei: daily.as_ref().map(|d| d.spent_wei.clone()).unwrap_or_default(),
        recipient: s.recipient.clone(),
        recipient_allowlist: recipient_allow,
        contract_allowlist: contract_allow,
        sim_success: s.sim_success,
        refuse_on_revert,
    };
    wallet_base_core::guardrails::check_policy(&pi)
        .map_err(|e| ApiError::bad_request(e.to_string()))
}

pub(crate) fn do_send(principal: &str, body: EvmIntentReq) -> Result<SendOut, ApiError> {
    use wallet_base_core::evm::rpc::{
        call_request, estimate_gas_request, nonce_request, parse_estimate_gas, parse_nonce,
        parse_simulation,
    };

    // A blocked principal cannot sign or send.
    if is_blocked(principal)? {
        return Err(ApiError::forbidden("this account is blocked"));
    }

    // Label is host-derived; also re-validates "evm" as a known chain.
    let label = wallet_base_core::subject::wallet_label_checked(principal, EVM_CHAIN)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    // Require the caller's EVM wallet (the local key cache).
    let wallet_row = Query::on(Wallet::TABLE)
        .where_eq(Wallet::OWNER_PRINCIPAL, principal)
        .where_eq(Wallet::CHAIN, EVM_CHAIN)
        .fetch_one()?
        .ok_or_else(|| ApiError::bad_request("no evm wallet; create one first"))?;
    let wallet = Wallet::from_row(&wallet_row);

    let mut intent: EvmIntent = body.into();
    // Anchor the #15 post-assembly self-verify on the host-attested wallet
    // address (never the body): assemble_signed recovers the signer from the
    // signature and rejects a tx that doesn't recover to this address.
    intent.from_address = wallet.address.clone();

    // ── Resolve nonce (reserve if absent) ──
    // Fetch the chain's pending nonce OUTSIDE any store tx (outbound_http is
    // denied inside a tx), then reserve through the durable per-account counter
    // so two concurrent sends can't grab the same nonce (#8).
    if intent.nonce.is_none() {
        let resp = call_evm_rpc(&nonce_request(&wallet.address))?;
        let on_chain_pending =
            parse_nonce(&resp).map_err(|e| ApiError::service_unavailable(e.to_string()))?;
        intent.nonce = Some(reserve_nonce(principal, EVM_CHAIN, on_chain_pending)?);
    }

    // ── Resolve fees (fetch if absent) ──
    if intent.legacy {
        if intent.gas_price.is_none() {
            // Reuse the EIP-1559 tip+base derivation as a conservative legacy
            // gas price (base × 2 + tip).
            let (base, tip) = fetch_base_and_tip()?;
            intent.gas_price = Some(base.saturating_mul(2).saturating_add(tip).to_string());
        }
    } else {
        if intent.max_fee_per_gas.is_none() || intent.max_priority_fee_per_gas.is_none() {
            let (base, tip) = fetch_base_and_tip()?;
            let max_fee = base.saturating_mul(2).saturating_add(tip);
            intent
                .max_fee_per_gas
                .get_or_insert_with(|| max_fee.to_string());
            intent
                .max_priority_fee_per_gas
                .get_or_insert_with(|| tip.to_string());
        }
    }

    // ── Simulate (estimateGas, fall back to eth_call for the revert reason) ──
    let call_obj = build_call_obj(&wallet.address, &intent);
    let estimate_resp = call_evm_rpc(&estimate_gas_request(call_obj.clone()))?;
    let sim = match parse_estimate_gas(&estimate_resp) {
        Ok(s) if s.success => s,
        Ok(s) => s, // estimateGas surfaced a revert reason
        Err(_) => {
            // Parsing failed; fall back to eth_call for the revert reason.
            let call_resp = call_evm_rpc(&call_request(call_obj))?;
            parse_simulation(&call_resp)
                .map_err(|e| ApiError::service_unavailable(e.to_string()))?
        }
    };
    let sim_json = serde_json::json!({
        "success": sim.success,
        "gas_used": sim.gas_used,
        "error": sim.error,
    });

    // Use the simulated gas as the gas_limit when the intent omitted one (with a
    // headroom margin); fall back to a plain transfer limit if estimation gave
    // nothing.
    if intent.gas_limit.is_none() {
        let limit = sim
            .gas_used
            .map(|g| g.saturating_add(g / 10).max(21_000)) // +10% headroom
            .unwrap_or(21_000);
        intent.gas_limit = Some(limit);
    }

    // ── Resolved fee (gas_limit × per-gas) for the fee guard + daily outflow ──
    // This is the WORST-CASE fee the signed tx authorizes — `gas_limit ×
    // max_fee_per_gas` (1559) or `gas_limit × gas_price` (legacy). Bounding it is
    // the fund-drain guard (#2): a tiny `value` with a huge node/caller fee must
    // not slip past the value cap.
    let total_fee_wei = {
        let gas_limit = intent.gas_limit.unwrap_or(21_000) as u128;
        let per_gas = if intent.legacy {
            intent.gas_price.as_deref()
        } else {
            intent.max_fee_per_gas.as_deref()
        };
        let per_gas = per_gas.and_then(|s| s.trim().parse::<u128>().ok()).unwrap_or(0);
        gas_limit.saturating_mul(per_gas).to_string()
    };

    // ── Guardrails — BEFORE signing (single enforcement point) ──
    // The allowlist is enforced as a recipient ∪ contract union (#4) — we no
    // longer derive contract-ness from the untrusted node's gas estimate.
    let now_secs = now_millis() as i64 / 1000;
    let recipient = intent.to.clone().unwrap_or_default().to_lowercase();
    enforce_spend_policy(
        principal,
        EVM_CHAIN,
        &Spend {
            value: intent.value_wei.clone(),
            fee: total_fee_wei.clone(),
            denom: "wei".to_string(),
            recipient,
            sim_success: sim.success,
        },
    )?;

    // ── Sign (key is touched only after guardrails pass) ──
    let unsigned = EvmAdapter
        .build_unsigned(&intent, &ChainState::default())
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let mut sigs = Vec::with_capacity(unsigned.sign_requests.len());
    for sr in &unsigned.sign_requests {
        let digest = match sr {
            SignRequest::Digest(d) => d,
            SignRequest::Message(_) => {
                return Err(ApiError::internal("evm adapter produced a non-digest sign request"))
            }
        };
        let sdk_sig = signing_sign_digest(&label, digest, SigAlg::EcdsaSecp256k1)
            .map_err(|e| ApiError::internal(format!("sign digest: {e}")))?;
        let sig = wallet_base_core::secp_sig_from_compact(&sdk_sig.bytes, sdk_sig.recovery_id)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        sigs.push(sig);
    }
    let raw = EvmAdapter
        .assemble_signed(&unsigned, &sigs)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let raw_hex = raw.to_hex();

    // Snapshot values needed for persistence (intent is consumed below).
    let intent_json = serde_json::to_string(&intent)
        .map_err(|e| ApiError::internal(format!("encode intent: {e}")))?;
    let sim_json_str = sim_json.to_string();
    let to_addr = intent.to.clone().unwrap_or_default();
    let value_wei = intent.value_wei.clone();
    let nonce_i64 = intent.nonce.unwrap_or(0) as i64;
    let fee_wei = if intent.legacy {
        intent.gas_price.clone().unwrap_or_default()
    } else {
        intent.max_fee_per_gas.clone().unwrap_or_default()
    };
    let now = Timestamp::new(now_millis() as i64);
    let owner = principal.to_string();

    // ── Persist + enqueue atomically ──
    //
    // Insert the `Transaction` row, bump/insert the `DailySpend` accumulator,
    // and enqueue `broadcast_tx` — all inside ONE store `tx`. The job enqueue
    // is staged to the transactional outbox and relayed to the queue only after
    // this tx commits, so a committed signed tx always has a broadcast job (and
    // a rollback drops both the row and the job).
    let tx_id = tx::<_, _, ApiError>(|| {
        let tx_id = db_insert(&Transaction {
            id: Id::new(0),
            owner_principal: owner.clone(),
            chain: EVM_CHAIN.to_string(),
            status: "signed".to_string(),
            intent_json: intent_json.clone(),
            raw_hex: raw_hex.clone(),
            tx_hash: String::new(),
            to_addr: to_addr.clone(),
            value_wei: value_wei.clone(),
            nonce: nonce_i64,
            fee_wei: fee_wei.clone(),
            sim_json: sim_json_str.clone(),
            confirmations: 0,
            created_at: now,
            updated_at: now,
        })
        .map_err(ApiError::from)?;

        // Accumulate total outflow (value + fee) into today's window (slide/reset
        // the window if stale, re-read inside the tx so a concurrent send can't be
        // clobbered).
        upsert_daily_spend(&owner, EVM_CHAIN, "wei", now_secs, &value_wei, &total_fee_wei, now)?;

        jobs_enqueue(JobSpec {
            handler: "broadcast_tx".into(),
            payload: serde_json::to_vec(&serde_json::json!({ "tx_id": tx_id }))
                .map_err(|e| ApiError::internal(format!("encode broadcast payload: {e}")))?,
            idempotency_key: Some(format!("broadcast:{tx_id}")),
            ..Default::default()
        })
        .map_err(|e| ApiError::internal(format!("enqueue broadcast: {e}")))?;

        Ok(tx_id)
    })?;

    Ok(SendOut { tx_id, status: "signed".to_string() })
}

/// `POST /evm/send` — the full resolve → simulate → policy → sign → persist →
/// enqueue pipeline.
///
/// Guardrails run BEFORE the key is touched (the reject-before-signing
/// invariant). The signing label is derived from the host-attested principal,
/// never the body. On success the `Transaction` row (status `signed`), the
/// `DailySpend` accumulator, and the `broadcast_tx` job enqueue commit together
/// in one store transaction (the job is staged to the transactional outbox and
/// relayed only on commit), so a committed signed tx always has a broadcast job
/// and vice versa.
fn evm_send(Json(body): Json<EvmIntentReq>) -> Result<Json<SendOut>, ApiError> {
    let p = auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    do_send(&p, body).map(Json)
}

/// Keyset-pagination helper: parse `?limit=` (default 50, clamped 1..=200) and
/// `?cursor=` from the request's query string.
pub(crate) fn page_params(req: &mut Req<'_>) -> (usize, Option<boogy_sdk::pagination::Cursor>) {
    let limit = req
        .query("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let cursor = req.query("cursor").and_then(decode);
    (limit, cursor)
}

/// Core of `list_transactions` MCP tool: principal-scoped transaction list
/// for a given chain, newest first, up to `limit` rows.
pub(crate) fn do_list_transactions(
    principal: &str,
    chain: &str,
    limit: usize,
) -> Result<Vec<mcp::TxItem>, ApiError> {
    use boogy_sdk::store::SortDir;

    let rows = Query::on(Transaction::TABLE)
        .where_eq(Transaction::OWNER_PRINCIPAL, principal)
        .where_eq(Transaction::CHAIN, chain)
        .keyset_by(Transaction::CREATED_AT, SortDir::Desc)
        .limit(limit)
        .fetch_all()?;

    Ok(rows
        .iter()
        .map(|r| {
            let t = Transaction::from_row(r);
            mcp::TxItem {
                id: t.id.get(),
                chain: t.chain,
                status: t.status,
                to_addr: t.to_addr,
                value_wei: t.value_wei,
                tx_hash: t.tx_hash,
                nonce: t.nonce,
                fee_wei: t.fee_wei,
                confirmations: t.confirmations,
                created_at: t.created_at.get(),
            }
        })
        .collect())
}

/// Fetch the current base fee (pending block) and suggested tip. Shared by
/// `/evm/fees` semantics and the send-path fee resolution.
fn fetch_base_and_tip() -> Result<(u128, u128), ApiError> {
    use wallet_base_core::evm::rpc::{
        base_fee_request, max_priority_fee_request, parse_base_fee, parse_max_priority_fee,
    };
    let tip_resp = call_evm_rpc(&max_priority_fee_request())?;
    let tip = parse_max_priority_fee(&tip_resp)
        .map_err(|e| ApiError::service_unavailable(e.to_string()))?;
    let base_resp = call_evm_rpc(&base_fee_request())?;
    let base = parse_base_fee(&base_resp)
        .map_err(|e| ApiError::service_unavailable(e.to_string()))?;
    // Fail closed if the node reports an absurd fee — a malicious/compromised node
    // must not be able to dictate an arbitrary gas spend (review #3).
    if base > MAX_NODE_FEE_PER_GAS_WEI || tip > MAX_NODE_FEE_PER_GAS_WEI {
        return Err(ApiError::service_unavailable(
            "RPC node reported a gas fee above the safety ceiling",
        ));
    }
    Ok((base, tip))
}

/// Build the JSON-RPC call object for estimateGas / eth_call from the resolved
/// intent + sender address.
fn build_call_obj(from_addr: &str, intent: &EvmIntent) -> serde_json::Value {
    let value_hex = intent
        .value_wei
        .trim()
        .parse::<u128>()
        .map(|v| format!("0x{v:x}"))
        .unwrap_or_else(|_| "0x0".to_string());
    let data = if intent.data_hex.is_empty() || intent.data_hex == "0x" {
        "0x".to_string()
    } else if intent.data_hex.starts_with("0x") {
        intent.data_hex.clone()
    } else {
        format!("0x{}", intent.data_hex)
    };
    let mut call_obj = serde_json::json!({
        "from": from_addr,
        "value": value_hex,
        "data": data,
    });
    if let Some(to) = &intent.to {
        call_obj["to"] = serde_json::Value::String(to.clone());
    }
    call_obj
}

/// Load the caller's current `DailySpend` row IF it is still within the active
/// 24h window; a stale row (older window) reads as `None` so the accumulator
/// resets on the next write.
pub(crate) fn load_daily_spend(
    principal: &str,
    chain: &str,
    denom: &str,
    now_secs: i64,
) -> Result<Option<DailySpend>, ApiError> {
    let row = Query::on(DailySpend::TABLE)
        .where_eq(DailySpend::OWNER_PRINCIPAL, principal)
        .where_eq(DailySpend::CHAIN, chain)
        .where_eq(DailySpend::DENOM, denom)
        .fetch_one()?;
    let Some(row) = row else { return Ok(None) };
    let d = DailySpend::from_row(&row);
    if now_secs - d.window_start >= DAILY_WINDOW_SECS {
        // Window expired — treat as zero prior spend.
        Ok(None)
    } else {
        Ok(Some(d))
    }
}

/// Add `value_wei` to the caller's EVM daily-spend accumulator. Slides/reset the
/// window when the existing row is stale (or absent). Called INSIDE the send
/// `tx`, so it re-reads the row for the latest committed value. Wei amounts are
/// summed as `u128` (a parse failure is a guardrails-rejected intent and never
/// reaches here, but we fail closed on overflow).
pub(crate) fn upsert_daily_spend(
    principal: &str,
    chain: &str,
    denom: &str,
    now_secs: i64,
    value_wei: &str,
    fee_wei: &str,
    now: Timestamp,
) -> Result<(), ApiError> {
    // independent-writes: a single-row upsert — the db_update / db_insert below
    // are mutually-exclusive branches (exactly one runs per call). Atomicity
    // with the Transaction insert is already guaranteed: this fn is only ever
    // called from inside the `*_send` / `*_sign` `tx::<_, _, ApiError>(|| …)`
    // closure.
    //
    // The accumulator stores total OUTFLOW (value + fee), matching the daily-cap
    // check in `guardrails::check_policy` (which bounds `spent + value + fee`).
    // Debiting value-only would let cumulative fees escape the daily cap.
    let value = value_wei
        .trim()
        .parse::<u128>()
        .map_err(|_| ApiError::bad_request("unparseable value_wei"))?;
    let fee = {
        let f = fee_wei.trim();
        if f.is_empty() {
            0u128
        } else {
            f.parse::<u128>().map_err(|_| ApiError::bad_request("unparseable fee_wei"))?
        }
    };
    let add = value
        .checked_add(fee)
        .ok_or_else(|| ApiError::bad_request("value + fee overflow"))?;

    let existing = Query::on(DailySpend::TABLE)
        .where_eq(DailySpend::OWNER_PRINCIPAL, principal)
        .where_eq(DailySpend::CHAIN, chain)
        .where_eq(DailySpend::DENOM, denom)
        .fetch_one()?
        .map(|r| DailySpend::from_row(&r));

    match existing {
        Some(mut d) if now_secs - d.window_start < DAILY_WINDOW_SECS => {
            let prior = d.spent_wei.trim().parse::<u128>().unwrap_or(0);
            let total = prior
                .checked_add(add)
                .ok_or_else(|| ApiError::bad_request("daily spend overflow"))?;
            d.spent_wei = total.to_string();
            d.updated_at = now;
            db_update(d.id.get(), &d).map_err(ApiError::from)?;
        }
        Some(mut d) => {
            // Stale window — reset to a fresh window with just this spend.
            d.window_start = now_secs;
            d.spent_wei = add.to_string();
            d.updated_at = now;
            db_update(d.id.get(), &d).map_err(ApiError::from)?;
        }
        None => {
            db_insert(&DailySpend {
                id: Id::new(0),
                owner_principal: principal.to_string(),
                chain: chain.to_string(),
                denom: denom.to_string(),
                window_start: now_secs,
                spent_wei: add.to_string(),
                updated_at: now,
            })
            .map_err(ApiError::from)?;
        }
    }
    Ok(())
}

/// Reserve the next nonce for `(principal, chain)` durably, serializing
/// concurrent sends (#8). Fetch the chain's pending nonce OUTSIDE this call (it
/// is `outbound_http`, denied inside a `tx`); pass it in. Inside one small store
/// `tx` this reads the per-account counter, reserves
/// `max(on_chain_pending, stored_next)`, and advances the counter to
/// `reserved + 1`. Two concurrent reservations read+write the same row, so the
/// loser's commit conflicts and the platform returns 409 — the client retries
/// the whole request. A permanently-failed tx leaves a nonce GAP (inherent to
/// EVM pending pipelines; see `NonceReservation`).
pub(crate) fn reserve_nonce(
    principal: &str,
    chain: &str,
    on_chain_pending: u64,
) -> Result<u64, ApiError> {
    let now = Timestamp::new(now_millis() as i64);
    tx::<_, _, ApiError>(|| {
        // independent-writes: a single-row upsert — the db_update / db_insert
        // branches are mutually exclusive (exactly one runs). The read + write
        // are atomic within this `tx`; concurrent reservers conflict on the row.
        let existing = Query::on(NonceReservation::TABLE)
            .where_eq(NonceReservation::OWNER_PRINCIPAL, principal)
            .where_eq(NonceReservation::CHAIN, chain)
            .fetch_one()?
            .map(|r| NonceReservation::from_row(&r));
        let stored_next = existing.as_ref().map(|n| n.next_nonce.max(0) as u64).unwrap_or(0);
        let (reserved, new_stored) =
            wallet_base_core::nonce::reserve(on_chain_pending, stored_next);
        match existing {
            Some(mut n) => {
                n.next_nonce = new_stored as i64;
                n.updated_at = now;
                db_update(n.id.get(), &n).map_err(ApiError::from)?;
            }
            None => {
                db_insert(&NonceReservation {
                    id: Id::new(0),
                    owner_principal: principal.to_string(),
                    chain: chain.to_string(),
                    next_nonce: new_stored as i64,
                    updated_at: now,
                })
                .map_err(ApiError::from)?;
            }
        }
        Ok(reserved)
    })
}
