//! Typed models for wallet-base. All four tables use `#[derive(Model)]`
//! — the derive emits column-name consts, the schema (columns + indexes
//! implied by `#[index]` / `#[lookup_by]`), and the `from_row`/`to_columns`
//! round-trip. Handlers go through `db_*` + the `Query` DSL and never touch
//! raw column literals.
//!
//! ## (owner_principal, chain) uniqueness
//!
//! `Wallet` needs at most one row per `(owner_principal, chain)` pair.  The
//! `#[derive(Model)]` attribute supports `lookup_by` for single-column point
//! lookups only — no composite `lookup_by` attribute exists.  We therefore
//! put `#[index]` on `owner_principal` (the primary equality-seek axis) and
//! enforce the pair uniqueness in the handler via a residual `.where_eq(chain)`
//! filter at query time before insert.  This is an application-level uniqueness
//! check, not a storage-level constraint; concurrent inserts are prevented by
//! the caller holding a transaction.

use boogy_sdk::model::{Id, Timestamp};
use boogy_sdk::Model;

/// A custodial wallet entry for one chain, owned by one principal.
///
/// - `owner_principal` (`#[index]`) is the row-ownership column the auth
///   helpers key on.
/// - `list_by(filter = "owner_principal")` backs the keyset-paginated wallet
///   list for an authenticated owner.
/// - For the one-wallet-per-`(owner_principal, chain)` invariant, handlers
///   check `where_eq(chain)` after filtering by `owner_principal` before
///   inserting (see module-level note above).
#[derive(Model)]
#[model(table = "wallets", list_by(filter = "owner_principal", newest = "created_at"))]
pub struct Wallet {
    #[pk]
    pub id: Id<Wallet>,
    #[index]
    pub owner_principal: String,
    pub chain: String,
    pub label: String,
    pub address: String,
    pub pubkey_hex: String,
    pub created_at: Timestamp,
}

/// A signed / submitted / confirmed EVM transaction.
///
/// - `owner_principal` (`#[index]`) is the tenancy column.
/// - `tx_hash` (`#[lookup_by]`) is the on-chain natural key used for
///   confirmation polling and webhook deduplication.
/// - `list_by(filter = "owner_principal", newest = "created_at")` backs
///   the keyset-paginated transaction history newest-first.
/// - `value_wei` and `fee_wei` are decimal strings (u256-safe).
/// - `status` is one of `signed | pending | confirmed | failed`.
#[derive(Model)]
#[model(
    table = "transactions",
    list_by(filter = "owner_principal", newest = "created_at")
)]
pub struct Transaction {
    #[pk]
    pub id: Id<Transaction>,
    #[index]
    pub owner_principal: String,
    pub chain: String,
    pub status: String, // signed | pending | confirmed | failed
    pub intent_json: String,
    pub raw_hex: String,
    #[lookup_by]
    pub tx_hash: String,
    pub to_addr: String,
    pub value_wei: String,
    pub nonce: i64,
    pub fee_wei: String,
    pub sim_json: String,
    pub confirmations: i64,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// Per-owner, per-chain spend policy.
///
/// - `owner_principal` (`#[index]`) is the tenancy column.
/// - `max_value_wei` / `daily_cap_wei` are decimal strings (u256-safe).
/// - `recipient_allowlist` / `contract_allowlist` are JSON arrays serialized
///   as text (empty array `"[]"` = no restriction).
/// - `refuse_on_revert` (`bool`) aborts a transaction if the simulation
///   indicates it would revert on-chain.
/// - `list_by(filter = "owner_principal")` backs the owner's policy list.
#[derive(Model)]
#[model(table = "wallet_policies", list_by(filter = "owner_principal", newest = "updated_at"))]
pub struct WalletPolicy {
    #[pk]
    pub id: Id<WalletPolicy>,
    #[index]
    pub owner_principal: String,
    pub chain: String,
    pub max_value_wei: String,
    /// Per-transaction fee cap (decimal). `"0"`/`""` = no fee cap. Bounds the
    /// resolved tx fee (EVM `gas_limit × max_fee`, Cosmos `fee_amount`, BTC
    /// `fee_rate × vsize`) so a huge fee cannot drain the wallet past the value
    /// cap. The fee also counts toward `daily_cap_wei` (total outflow).
    pub max_fee_wei: String,
    pub daily_cap_wei: String,
    pub recipient_allowlist: String, // JSON array as text
    pub contract_allowlist: String,  // JSON array as text
    pub refuse_on_revert: bool,
    pub updated_at: Timestamp,
}

/// Rolling 24-hour spend accumulator per owner + chain + **denom**.
///
/// - `owner_principal` (`#[index]`) is the tenancy column.
/// - `chain` + `denom` complete the accumulator key. Keying by denom (not just
///   chain) is load-bearing on multi-denom Cosmos: without it, sends of
///   different denoms collapse into one bucket and the cap is meaningless (#6).
///   Single-denom chains use a fixed native unit (`wei` / `lamport` / `sat`).
/// - `window_start` is a Unix timestamp (seconds) marking the start of the
///   current 24-hour window; handlers slide the window on access.
/// - `spent_wei` is a decimal string (u256-safe) accumulating total OUTFLOW
///   (value + fee) within the window for this `(chain, denom)`. Debited at
///   SIGN time (in the same tx that persists the signed row), NOT at confirm
///   time, and deliberately NOT credited back if the broadcast later fails —
///   this fail-safe over-restricts (a user near their cap whose tx fails waits
///   out the window) rather than risk under-counting a tx that actually landed
///   (#17).
/// - `list_by(filter = "owner_principal")` backs the owner's daily-spend view.
#[derive(Model)]
#[model(table = "daily_spend", list_by(filter = "owner_principal", newest = "updated_at"))]
pub struct DailySpend {
    #[pk]
    pub id: Id<DailySpend>,
    #[index]
    pub owner_principal: String,
    pub chain: String,
    pub denom: String,
    pub window_start: i64,
    pub spent_wei: String,
    pub updated_at: Timestamp,
}

/// Per-(owner, chain) reservation counter for account-based nonces/sequences
/// (EVM nonce today; the Cosmos sequence is the analogous future use).
///
/// - `owner_principal` (`#[index]`) is the tenancy column; one row per
///   `(owner_principal, chain)` (same application-level pair-uniqueness pattern
///   as `Wallet`, enforced by a residual `where_eq(chain)` inside the reserving
///   `tx`).
/// - `next_nonce` is the next nonce to hand out. Reserving reads the row, sets
///   `reserved = max(on-chain pending, next_nonce)`, writes `next_nonce =
///   reserved + 1`, all inside ONE store `tx` so two concurrent sends can't grab
///   the same nonce — the loser's commit conflicts and the request retries (409).
///   See `wallet_base_core::nonce::reserve` (#8).
///
/// Caveat (documented, by design): a permanently-failed/abandoned tx leaves a
/// nonce GAP (the counter advanced but no tx ever lands at that nonce). This is
/// inherent to EVM pending pipelines; a cancel/replace flow to fill gaps is out
/// of scope.
#[derive(Model)]
#[model(table = "nonce_reservations", list_by(filter = "owner_principal", newest = "updated_at"))]
pub struct NonceReservation {
    #[pk]
    pub id: Id<NonceReservation>,
    #[index]
    pub owner_principal: String,
    pub chain: String,
    pub next_nonce: i64,
    pub updated_at: Timestamp,
}

/// Operator-blocked principal — a user the service owner has blocked from
/// sending transactions. One row per blocked principal.
///
/// - `owner_principal` (`#[index]`) is the deployment owner (tenancy key).
/// - `principal` (`#[lookup_by]`) is the blocked user's principal string.
/// - `ranked_by(highest = "blocked_at")` backs the newest-first block list.
#[derive(Model)]
#[model(table = "blocked_principals", ranked_by(highest = "blocked_at"))]
pub struct BlockedPrincipal {
    #[pk]
    pub id: Id<BlockedPrincipal>,
    #[index]
    pub owner_principal: String,
    #[lookup_by]
    pub principal: String,
    pub reason: Option<String>,
    /// The attested principal (owner's agent) that set the block.
    pub blocked_by: String,
    pub blocked_at: Timestamp,
}

/// Append-only operator action log. One row per `/admin` mutation
/// (policy.set / principal.block / principal.unblock), written best-effort
/// after the action commits.
///
/// - `ranked_by(highest = "at")` backs the unfiltered newest-first log.
/// - `list_by(filter = "action", newest = "at")` backs `?action=` filtering.
#[derive(Model)]
#[model(
    table = "admin_audit",
    list_by(filter = "action", newest = "at"),
    ranked_by(highest = "at")
)]
pub struct AdminAudit {
    #[pk]
    pub id: Id<AdminAudit>,
    #[index]
    pub owner_principal: String,
    /// The attested principal that performed the action.
    pub actor: String,
    /// Action verb: `policy.set` | `principal.block` | `principal.unblock`.
    pub action: String,
    /// Target of the action (principal string for block/unblock, etc.).
    pub target: Option<String>,
    /// Optional JSON detail (e.g. block reason).
    pub detail: Option<String>,
    pub at: Timestamp,
}
