//! MCP tool surface for wallet-base.
//!
//! Mounted at `/mcp` via `Router::mcp("/mcp", mcp_dispatch)`. Each tool is
//! scoped to `auth::current_principal()` — anonymous callers are rejected.
//! Tool implementations call the same shared helper functions the REST handlers
//! use (`do_ensure_wallet`, `do_fees`, `do_simulate`, `do_send`,
//! `do_list_transactions`) — no logic is duplicated.

use boogy_sdk::mcp::{tool, McpServer};
use boogy_sdk::response::HttpResponse;
use boogy_sdk::router::Req;
use wallet_base_core::types::RpcRequest;

use crate::{
    do_ensure_wallet, do_fees, do_list_transactions, do_send, do_simulate,
    ApiError, EvmIntentReq, FeesOut, SendOut, SimOut, WalletOut,
};
use serde::Serialize;

// ─── Shared result types ──────────────────────────────────────────────────────

/// A single transaction row as returned by the `list_transactions` tool.
/// Also used by `lib.rs`'s `do_list_transactions` helper.
#[derive(Serialize, schemars::JsonSchema)]
pub struct TxItem {
    pub id: u64,
    pub chain: String,
    pub status: String,
    pub to_addr: String,
    pub value_wei: String,
    pub tx_hash: String,
    pub nonce: i64,
    pub fee_wei: String,
    pub confirmations: i64,
    pub created_at: i64,
}

// ─── Arg / result structs ─────────────────────────────────────────────────────

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct GetAddressArgs {
    /// Target chain. Only `evm` is supported in this phase.
    pub chain: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct GetBalanceArgs {
    /// Target chain. Only `evm` is supported in this phase.
    pub chain: String,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct BalanceOut {
    /// The caller's wallet address.
    pub address: String,
    /// Balance in wei as a decimal string.
    pub balance_wei: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct EstimateFeeArgs {
    /// Target chain. Only `evm` is supported in this phase.
    #[allow(dead_code)]
    pub chain: String,
}

/// MCP intent arg struct — same fields as `EvmIntentReq`, re-declared here
/// so this module derives `JsonSchema` independently without touching the
/// core type's dependency graph.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct SimulateArgs {
    /// `0x`-hex recipient address; omit for contract creation.
    pub to: Option<String>,
    /// Transfer amount in wei, as a decimal string.
    pub value_wei: String,
    /// `0x`-prefixed calldata; `""` or `"0x"` means empty.
    pub data_hex: String,
    pub chain_id: u64,
    pub nonce: Option<u64>,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub gas_limit: Option<u64>,
    /// `true` for a legacy (type-0) transaction; otherwise EIP-1559 (type-2).
    pub legacy: bool,
    pub gas_price: Option<String>,
}

impl From<SimulateArgs> for EvmIntentReq {
    fn from(a: SimulateArgs) -> Self {
        EvmIntentReq {
            to: a.to,
            value_wei: a.value_wei,
            data_hex: a.data_hex,
            chain_id: a.chain_id,
            nonce: a.nonce,
            max_fee_per_gas: a.max_fee_per_gas,
            max_priority_fee_per_gas: a.max_priority_fee_per_gas,
            gas_limit: a.gas_limit,
            legacy: a.legacy,
            gas_price: a.gas_price,
        }
    }
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct SendArgs {
    pub to: Option<String>,
    pub value_wei: String,
    pub data_hex: String,
    pub chain_id: u64,
    pub nonce: Option<u64>,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub gas_limit: Option<u64>,
    pub legacy: bool,
    pub gas_price: Option<String>,
}

impl From<SendArgs> for EvmIntentReq {
    fn from(a: SendArgs) -> Self {
        EvmIntentReq {
            to: a.to,
            value_wei: a.value_wei,
            data_hex: a.data_hex,
            chain_id: a.chain_id,
            nonce: a.nonce,
            max_fee_per_gas: a.max_fee_per_gas,
            max_priority_fee_per_gas: a.max_priority_fee_per_gas,
            gas_limit: a.gas_limit,
            legacy: a.legacy,
            gas_price: a.gas_price,
        }
    }
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ListTransactionsArgs {
    /// Target chain. Only `evm` is supported in this phase.
    pub chain: String,
    /// Maximum number of rows to return (default 20, max 100).
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct TransactionsList {
    pub items: Vec<TxItem>,
    pub count: usize,
}

// ─── Tool handlers ────────────────────────────────────────────────────────────

fn get_address_tool(args: GetAddressArgs) -> Result<WalletOut, ApiError> {
    let principal = crate::auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    do_ensure_wallet(&principal, &args.chain)
}

fn get_balance_tool(args: GetBalanceArgs) -> Result<BalanceOut, ApiError> {
    use wallet_base_core::evm::rpc::{parse_hex_u128, result_str};

    let principal = crate::auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    let wallet = do_ensure_wallet(&principal, &args.chain)?;
    let address = wallet.address.clone();

    // eth_getBalance(address, "latest") — returns 0x-prefixed hex wei.
    let req = RpcRequest {
        method: "eth_getBalance".to_string(),
        params: serde_json::json!([address, "latest"]),
    };
    let resp = crate::rpc_client::call_evm_rpc(&req)?;
    let hex = result_str(&resp)
        .map_err(|e| ApiError::service_unavailable(e.to_string()))?;
    let balance_wei = parse_hex_u128(hex)
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "0".to_string());

    Ok(BalanceOut { address, balance_wei })
}

fn estimate_fee_tool(_args: EstimateFeeArgs) -> Result<FeesOut, ApiError> {
    crate::auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    do_fees()
}

fn simulate_transaction_tool(args: SimulateArgs) -> Result<SimOut, ApiError> {
    let principal = crate::auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    do_simulate(&principal, args.into())
}

fn send_transaction_tool(args: SendArgs) -> Result<SendOut, ApiError> {
    let principal = crate::auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    do_send(&principal, args.into())
}

fn list_transactions_tool(args: ListTransactionsArgs) -> Result<TransactionsList, ApiError> {
    let principal = crate::auth::current_principal().ok_or_else(ApiError::unauthenticated)?;
    let limit = args.limit.unwrap_or(20).clamp(1, 100);
    let items = do_list_transactions(&principal, &args.chain, limit)?;
    let count = items.len();
    Ok(TransactionsList { items, count })
}

// ─── MCP dispatch ─────────────────────────────────────────────────────────────

pub fn mcp_dispatch(req: &mut Req<'_>) -> HttpResponse {
    McpServer::new("wallet-base", env!("CARGO_PKG_VERSION"))
        .tool_typed(
            tool("get_address").description(
                "Ensure and return the caller's wallet address for a chain. \
                 Creates the wallet on first call.",
            ),
            get_address_tool,
        )
        .tool_typed(
            tool("get_balance").description(
                "Return the caller's on-chain balance for a chain \
                 (calls eth_getBalance). Balance is returned in wei as a decimal string.",
            ),
            get_balance_tool,
        )
        .tool_typed(
            tool("estimate_fee").description(
                "Return current EVM fee estimates: base fee, priority fee, and \
                 conservative max fee per gas (all in wei as decimal strings).",
            ),
            estimate_fee_tool,
        )
        .tool_typed(
            tool("simulate_transaction").description(
                "Simulate an EVM transaction via eth_estimateGas (falls back to \
                 eth_call on revert). Returns {success, gas_used, error}.",
            ),
            simulate_transaction_tool,
        )
        .tool_typed(
            tool("send_transaction").description(
                "Resolve, simulate, policy-check, sign, persist, and enqueue broadcast \
                 of an EVM transaction. Returns {tx_id, status}. Broadcast and \
                 confirmation proceed asynchronously.",
            ),
            send_transaction_tool,
        )
        .tool_typed(
            tool("list_transactions").description(
                "List the caller's recent transactions for a chain, newest first.",
            ),
            list_transactions_tool,
        )
        .handle(req.request)
}
