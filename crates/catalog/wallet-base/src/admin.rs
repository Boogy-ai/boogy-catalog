//! Operator admin surface for wallet-base (`/admin/*`).
//!
//! Every handler calls [`require_owner()`] first — a host-attested gate that
//! admits only the service owner's own agent. No hardcoded identity; no body
//! flag. Mirrors stripe-base's admin pattern exactly.
//!
//! Routes:
//! - `GET  /admin/wallets`                — all wallets across all principals
//! - `GET  /admin/transactions`           — all transactions; `?status=` / `?owner=`
//! - `GET  /admin/policy/{principal}`     — view guardrails for a principal
//! - `PUT  /admin/policy/{principal}`     — set guardrails for a principal
//! - `POST /admin/block/{principal}`      — block a principal
//! - `POST /admin/unblock/{principal}`    — unblock a principal
//! - `GET  /admin/audit`                  — append-only operator audit log

use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::pagination::CursorPage;
use boogy_sdk::store::{SortDir, Val};

use crate::models::{AdminAudit, BlockedPrincipal, Transaction, Wallet, WalletPolicy};
use serde::{Deserialize, Serialize};

use crate::{
    db_delete, db_find_by, db_insert, db_update, now_millis, page_params, self_identity,
    ApiError, Json, NoContent, Query, Req,
};
use crate::{EVM_CHAIN, PolicyReq};

// ─── Operator gate ────────────────────────────────────────────────────────────

/// Operator gate: admit ONLY the service owner's agent (host-attested).
///
/// `/admin` is a cross-principal surface (lists every principal's wallets, can
/// tighten/loosen any principal's policy, block anyone), so it is AGENT-ONLY.
///
/// `caller_is_service_owner()` is NOT sufficient on its own: it returns `true`
/// for ANY workload whose owner segment equals this deployment's owner — i.e.
/// every OTHER service the same owner deployed. So we first reject any attested
/// workload caller (principal OR OBO actor parses as a `boogy://…/services/…`
/// URI) — even one of the owner's own apps — then require the owner's agent.
/// This mirrors stripe-base's `audience()` (which admits owner-workloads as
/// client apps; a fund-holding admin surface must not). Closes review #5.
pub fn require_owner() -> Result<(), ApiError> {
    let identity = crate::bindings::boogy::platform::auth::current_identity();
    let principal = identity.as_ref().map(|i| i.principal.as_str()).unwrap_or("");
    let actor = identity.as_ref().and_then(|i| i.actor.as_deref());
    if wallet_base_core::subject::workload_owner_service(principal, actor).is_some() {
        // An attested workload (even a sibling owner-workload) is never an operator.
        return Err(ApiError::forbidden("operator (service owner) access required"));
    }
    // No attested workload → an agent. Only the service owner's agent qualifies.
    if crate::caller_is_service_owner() {
        Ok(())
    } else {
        Err(ApiError::forbidden("operator (service owner) access required"))
    }
}

// ─── Operator wallet list ─────────────────────────────────────────────────────

/// Operator projection of a `wallets` row — includes the owner principal.
#[derive(Serialize, schemars::JsonSchema)]
pub struct AdminWalletOut {
    pub id: u64,
    pub owner_principal: String,
    pub chain: String,
    pub address: String,
    pub created_at: i64,
}

fn admin_wallet_out(r: &crate::Row) -> AdminWalletOut {
    let w = Wallet::from_row(r);
    AdminWalletOut {
        id: w.id.get(),
        owner_principal: w.owner_principal,
        chain: w.chain,
        address: w.address,
        created_at: w.created_at.get(),
    }
}

/// Operator: all wallets across all principals.
pub fn admin_list_wallets(_req: &mut Req<'_>) -> Result<Json<Vec<AdminWalletOut>>, ApiError> {
    require_owner()?;
    let rows = Query::on(Wallet::TABLE)
        .allow_full_scan("operator lists all wallets")
        .fetch_all()?;
    Ok(Json(rows.iter().map(admin_wallet_out).collect()))
}

// ─── Operator transaction list ────────────────────────────────────────────────

/// Operator projection of a `transactions` row — includes owner_principal.
#[derive(Serialize, schemars::JsonSchema)]
pub struct AdminTxOut {
    pub id: u64,
    pub owner_principal: String,
    pub chain: String,
    pub status: String,
    pub to_addr: String,
    pub value_wei: String,
    pub tx_hash: String,
    pub nonce: i64,
    pub fee_wei: String,
    pub confirmations: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

fn admin_tx_out(r: &crate::Row) -> AdminTxOut {
    let t = Transaction::from_row(r);
    AdminTxOut {
        id: t.id.get(),
        owner_principal: t.owner_principal,
        chain: t.chain,
        status: t.status,
        to_addr: t.to_addr,
        value_wei: t.value_wei,
        tx_hash: t.tx_hash,
        nonce: t.nonce,
        fee_wei: t.fee_wei,
        confirmations: t.confirmations,
        created_at: t.created_at.get(),
        updated_at: t.updated_at.get(),
    }
}

/// Operator: all transactions; optional `?status=` and `?owner=` residual filters.
pub fn admin_list_transactions(
    req: &mut Req<'_>,
) -> Result<Json<Vec<AdminTxOut>>, ApiError> {
    require_owner()?;
    let mut q = Query::on(Transaction::TABLE)
        .allow_full_scan("operator lists all transactions");

    if let Some(status) = req.query("status").filter(|s| !s.is_empty()) {
        q = q.where_eq(Transaction::STATUS, status);
    }
    if let Some(owner) = req.query("owner").filter(|s| !s.is_empty()) {
        q = q.where_eq(Transaction::OWNER_PRINCIPAL, owner);
    }

    let rows = q.fetch_all()?;
    Ok(Json(rows.iter().map(admin_tx_out).collect()))
}

// ─── Operator policy view/set ─────────────────────────────────────────────────

/// Operator: view the EVM spend policy for a specific principal (defaults if none).
pub fn admin_get_policy(req: &mut Req<'_>) -> Result<Json<PolicyReq>, ApiError> {
    require_owner()?;
    let principal = req.params.get("principal").unwrap_or_default().to_string();
    if principal.is_empty() {
        return Err(ApiError::bad_request("missing principal path segment"));
    }

    let row = Query::on(WalletPolicy::TABLE)
        .where_eq(WalletPolicy::OWNER_PRINCIPAL, principal.as_str())
        .where_eq(WalletPolicy::CHAIN, EVM_CHAIN)
        .fetch_one()?
        .map(|r| WalletPolicy::from_row(&r));

    Ok(Json(row.as_ref().map(PolicyReq::from).unwrap_or_default()))
}

/// Operator: upsert the EVM spend policy for a specific principal (tighten limits).
pub fn admin_put_policy(req: &mut Req<'_>) -> Result<Json<PolicyReq>, ApiError> {
    // independent-writes: single-row upsert — db_update and db_insert are
    // mutually-exclusive branches (exactly one runs per call).
    require_owner()?;
    let principal = req.params.get("principal").unwrap_or_default().to_string();
    if principal.is_empty() {
        return Err(ApiError::bad_request("missing principal path segment"));
    }

    let body = req.body().filter(|b| !b.is_empty()).ok_or_else(|| {
        ApiError::bad_request("request body required")
    })?;
    let pol: PolicyReq = serde_json::from_slice(body)
        .map_err(|e| ApiError::bad_request(format!("invalid request body: {e}")))?;

    let recipient_allowlist = serde_json::to_string(&pol.recipient_allowlist)
        .map_err(|e| ApiError::internal(format!("encode recipient allowlist: {e}")))?;
    let contract_allowlist = serde_json::to_string(&pol.contract_allowlist)
        .map_err(|e| ApiError::internal(format!("encode contract allowlist: {e}")))?;
    let now = Timestamp::new(now_millis() as i64);

    let existing = Query::on(WalletPolicy::TABLE)
        .where_eq(WalletPolicy::OWNER_PRINCIPAL, principal.as_str())
        .where_eq(WalletPolicy::CHAIN, EVM_CHAIN)
        .fetch_one()?
        .map(|r| WalletPolicy::from_row(&r));

    match existing {
        Some(mut e) => {
            e.max_value_wei = pol.max_value_wei.clone();
            e.max_fee_wei = pol.max_fee_wei.clone();
            e.daily_cap_wei = pol.daily_cap_wei.clone();
            e.recipient_allowlist = recipient_allowlist;
            e.contract_allowlist = contract_allowlist;
            e.refuse_on_revert = pol.refuse_on_revert;
            e.updated_at = now;
            db_update(e.id.get(), &e).map_err(ApiError::from)?;
        }
        None => {
            db_insert(&WalletPolicy {
                id: Id::new(0),
                owner_principal: principal.clone(),
                chain: EVM_CHAIN.to_string(),
                max_value_wei: pol.max_value_wei.clone(),
                max_fee_wei: pol.max_fee_wei.clone(),
                daily_cap_wei: pol.daily_cap_wei.clone(),
                recipient_allowlist,
                contract_allowlist,
                refuse_on_revert: pol.refuse_on_revert,
                updated_at: now,
            })
            .map_err(ApiError::from)?;
        }
    }

    write_admin_audit("policy.set", Some(&principal), None);

    let result = Query::on(WalletPolicy::TABLE)
        .where_eq(WalletPolicy::OWNER_PRINCIPAL, principal.as_str())
        .where_eq(WalletPolicy::CHAIN, EVM_CHAIN)
        .fetch_one()?
        .map(|r| WalletPolicy::from_row(&r));
    Ok(Json(result.as_ref().map(PolicyReq::from).unwrap_or_default()))
}

// ─── Operator block / unblock ─────────────────────────────────────────────────

/// Optional JSON body for `POST /admin/block/{principal}`.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct BlockReq {
    #[serde(default)]
    pub reason: Option<String>,
}

/// Operator projection of a `blocked_principals` row.
#[derive(Serialize, schemars::JsonSchema)]
pub struct BlockedPrincipalOut {
    pub principal: String,
    pub reason: Option<String>,
    pub blocked_by: String,
    pub blocked_at: i64,
}

fn blocked_principal_out(b: BlockedPrincipal) -> BlockedPrincipalOut {
    BlockedPrincipalOut {
        principal: b.principal,
        reason: b.reason,
        blocked_by: b.blocked_by,
        blocked_at: b.blocked_at.get(),
    }
}

/// Operator: block a principal from sending transactions (idempotent — re-blocking
/// returns the existing block with no new audit row).
pub fn admin_block_principal(
    req: &mut Req<'_>,
) -> Result<Json<BlockedPrincipalOut>, ApiError> {
    require_owner()?;
    let principal = req.params.get("principal").unwrap_or("").to_string();
    if principal.is_empty() {
        return Err(ApiError::bad_request("missing principal path segment"));
    }

    let reason = match req.body().filter(|b| !b.is_empty()) {
        Some(b) => {
            serde_json::from_slice::<BlockReq>(b)
                .map_err(|e| ApiError::bad_request(format!("invalid request body: {e}")))?
                .reason
        }
        None => None,
    };

    // Idempotent: an existing block wins.
    let existing: Vec<BlockedPrincipal> = db_find_by::<BlockedPrincipal>(
        BlockedPrincipal::PRINCIPAL,
        Val::Text(principal.clone()),
    )?;
    if let Some(b) = existing.into_iter().next() {
        return Ok(Json(blocked_principal_out(b)));
    }

    let now = Timestamp::new(now_millis() as i64);
    let owner_principal = self_identity().owner;
    let blocked_by = crate::auth::current_principal().unwrap_or_else(|| owner_principal.clone());

    db_insert(&BlockedPrincipal {
        id: Id::new(0),
        owner_principal: owner_principal.clone(),
        principal: principal.clone(),
        reason: reason.clone(),
        blocked_by: blocked_by.clone(),
        blocked_at: now,
    })?;
    write_admin_audit("principal.block", Some(&principal), reason.clone());

    Ok(Json(BlockedPrincipalOut {
        principal,
        reason,
        blocked_by,
        blocked_at: now.get(),
    }))
}

/// Operator: lift a principal's block (idempotent — `204` if not currently blocked).
pub fn admin_unblock_principal(req: &mut Req<'_>) -> Result<NoContent, ApiError> {
    require_owner()?;
    let principal = req.params.get("principal").unwrap_or("").to_string();
    if principal.is_empty() {
        return Err(ApiError::bad_request("missing principal path segment"));
    }

    let hits: Vec<BlockedPrincipal> = db_find_by::<BlockedPrincipal>(
        BlockedPrincipal::PRINCIPAL,
        Val::Text(principal.clone()),
    )?;
    let removed = !hits.is_empty();
    for b in hits {
        db_delete::<BlockedPrincipal>(b.id.get())?;
    }
    if removed {
        write_admin_audit("principal.unblock", Some(&principal), None);
    }
    Ok(NoContent)
}

// ─── Operator audit log ───────────────────────────────────────────────────────

/// Operator projection of an `admin_audit` row.
#[derive(Serialize, schemars::JsonSchema)]
pub struct AuditOut {
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub at: i64,
}

fn audit_out(r: &crate::Row) -> AuditOut {
    let a = AdminAudit::from_row(r);
    AuditOut {
        actor: a.actor,
        action: a.action,
        target: a.target,
        detail: a.detail,
        at: a.at.get(),
    }
}

/// Operator: keyset-paginated audit log, newest-first. Optional `?action=` filter.
pub fn admin_list_audit(req: &mut Req<'_>) -> Result<Json<CursorPage<AuditOut>>, ApiError> {
    require_owner()?;
    let (limit, cursor) = page_params(req);
    let mut q = Query::on(AdminAudit::TABLE);
    if let Some(action) = req.query("action").filter(|s| !s.is_empty()) {
        q = q.where_eq(AdminAudit::ACTION, action);
    }
    let page = q
        .keyset_by(AdminAudit::AT, SortDir::Desc)
        .limit(limit)
        .cursor(cursor)
        .fetch_page(audit_out)?;
    Ok(Json(page))
}

// ─── Shared audit helper ──────────────────────────────────────────────────────

/// Append one row to the in-store operator audit log. Best-effort: a failure to
/// record never fails the mutation it documents.
pub fn write_admin_audit(action: &str, target: Option<&str>, detail: Option<String>) {
    let _ = db_insert(&AdminAudit {
        id: Id::new(0),
        owner_principal: self_identity().owner,
        actor: crate::auth::current_principal().unwrap_or_default(),
        action: action.to_string(),
        target: target.map(|s| s.to_string()),
        detail,
        at: Timestamp::new(now_millis() as i64),
    });
}
