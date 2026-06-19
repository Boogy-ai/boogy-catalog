// src/evm/tx.rs
use crate::types::*;
use serde::{Deserialize, Serialize};

use alloy_consensus::{SignableTransaction, TxEip1559, TxLegacy};
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
// The EIP-2718 typed-envelope encoder lives on `Signed<T>` via this trait.
use alloy_eips::eip2718::Encodable2718;

/// Final resolved tx fields, carried as JSON in `Unsigned.preimage` so
/// `assemble_signed` can rebuild the identical alloy tx without an RLP
/// decode round-trip.
#[derive(Serialize, Deserialize)]
struct ResolvedTx {
    chain_id: u64,
    nonce: u64,
    to: Option<String>, // 0x-hex; None = create
    /// Signer's 0x address (host-derived), for the #15 recover-and-compare.
    /// Empty = skip (lower-level encoding paths).
    #[serde(default)]
    from_address: String,
    value_wei: String,  // decimal
    input_hex: String,  // hex w/o 0x
    legacy: bool,
    // 1559:
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    // legacy:
    gas_price: u128,
    gas_limit: u64,
}

fn parse_u256_decimal(s: &str) -> Result<U256, AdapterError> {
    // An empty string parses to 0 in alloy; reject it explicitly so a hostile
    // `value_wei: ""` cannot be silently coerced into a zero-value transaction.
    if s.is_empty() {
        return Err(AdapterError::BadIntent("empty decimal value".into()));
    }
    U256::from_str_radix(s, 10)
        .map_err(|e| AdapterError::BadIntent(format!("invalid decimal value: {e}")))
}

fn parse_u128_decimal(s: &str, field: &str) -> Result<u128, AdapterError> {
    s.parse::<u128>()
        .map_err(|e| AdapterError::BadIntent(format!("invalid decimal {field}: {e}")))
}

fn decode_input(data_hex: &str) -> Result<Bytes, AdapterError> {
    let stripped = data_hex.strip_prefix("0x").unwrap_or(data_hex);
    if stripped.is_empty() {
        return Ok(Bytes::new());
    }
    let bytes = hex::decode(stripped)
        .map_err(|e| AdapterError::BadIntent(format!("invalid data_hex: {e}")))?;
    Ok(Bytes::from(bytes))
}

fn parse_to(to: &Option<String>) -> Result<TxKind, AdapterError> {
    match to {
        None => Ok(TxKind::Create),
        Some(s) => {
            let addr = s
                .parse::<Address>()
                .map_err(|e| AdapterError::BadIntent(format!("invalid to address: {e}")))?;
            Ok(TxKind::Call(addr))
        }
    }
}

/// Build the alloy `TxLegacy` from resolved fields.
fn legacy_tx(r: &ResolvedTx) -> Result<TxLegacy, AdapterError> {
    Ok(TxLegacy {
        chain_id: Some(r.chain_id),
        nonce: r.nonce,
        gas_price: r.gas_price,
        gas_limit: r.gas_limit,
        to: parse_to(&r.to)?,
        value: parse_u256_decimal(&r.value_wei)?,
        input: decode_input(&r.input_hex)?,
    })
}

/// Build the alloy `TxEip1559` from resolved fields.
fn eip1559_tx(r: &ResolvedTx) -> Result<TxEip1559, AdapterError> {
    Ok(TxEip1559 {
        chain_id: r.chain_id,
        nonce: r.nonce,
        gas_limit: r.gas_limit,
        max_fee_per_gas: r.max_fee_per_gas,
        max_priority_fee_per_gas: r.max_priority_fee_per_gas,
        to: parse_to(&r.to)?,
        value: parse_u256_decimal(&r.value_wei)?,
        input: decode_input(&r.input_hex)?,
        access_list: Default::default(),
    })
}

pub fn build_unsigned(intent: &EvmIntent, state: &ChainState) -> Result<Unsigned, AdapterError> {
    let nonce = intent
        .nonce
        .or(state.nonce)
        .ok_or_else(|| AdapterError::BadIntent("nonce required".into()))?;
    let gas_limit = intent
        .gas_limit
        .or(state.gas_limit)
        .ok_or_else(|| AdapterError::BadIntent("gas_limit required".into()))?;

    // Validate value + input + to up front (also fails fast on bad intents).
    let _ = parse_u256_decimal(&intent.value_wei)?;
    let _ = decode_input(&intent.data_hex)?;
    let _ = parse_to(&intent.to)?;

    let (gas_price, max_fee_per_gas, max_priority_fee_per_gas);
    if intent.legacy {
        gas_price = match &intent.gas_price {
            Some(s) => parse_u128_decimal(s, "gas_price")?,
            None => state
                .gas_price
                .ok_or_else(|| AdapterError::BadIntent("gas_price required".into()))?,
        };
        max_fee_per_gas = 0;
        max_priority_fee_per_gas = 0;
    } else {
        max_fee_per_gas = match &intent.max_fee_per_gas {
            Some(s) => parse_u128_decimal(s, "max_fee_per_gas")?,
            None => state
                .base_fee_per_gas
                .ok_or_else(|| AdapterError::BadIntent("max_fee_per_gas required".into()))?,
        };
        max_priority_fee_per_gas = match &intent.max_priority_fee_per_gas {
            Some(s) => parse_u128_decimal(s, "max_priority_fee_per_gas")?,
            None => state.max_priority_fee_per_gas.unwrap_or(0),
        };
        gas_price = 0;
    }

    let input_hex = {
        let stripped = intent.data_hex.strip_prefix("0x").unwrap_or(&intent.data_hex);
        stripped.to_string()
    };

    let resolved = ResolvedTx {
        chain_id: intent.chain_id,
        nonce,
        to: intent.to.clone(),
        from_address: intent.from_address.clone(),
        value_wei: intent.value_wei.clone(),
        input_hex,
        legacy: intent.legacy,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas_price,
        gas_limit,
    };

    let digest = if resolved.legacy {
        legacy_tx(&resolved)?.signature_hash()
    } else {
        eip1559_tx(&resolved)?.signature_hash()
    };

    let preimage = serde_json::to_vec(&resolved)
        .map_err(|e| AdapterError::Encoding(format!("serialize resolved tx: {e}")))?;

    Ok(Unsigned {
        preimage,
        sign_requests: vec![SignRequest::Digest(digest.0)],
    })
}

pub fn assemble_signed(
    unsigned: &Unsigned,
    sigs: &[Secp256k1Signature],
) -> Result<RawTx, AdapterError> {
    let resolved: ResolvedTx = serde_json::from_slice(&unsigned.preimage)
        .map_err(|e| AdapterError::Encoding(format!("deserialize resolved tx: {e}")))?;

    if sigs.len() != 1 {
        return Err(AdapterError::BadIntent(format!(
            "EVM requires exactly 1 signature, got {}",
            sigs.len()
        )));
    }
    let sig = &sigs[0];
    // The recovery id MUST be 0 or 1 (#14). A stray 2/3 (or anything else) would
    // otherwise collapse to y_parity=false and recover a DIFFERENT address — a tx
    // that fails to land. Fail closed.
    if sig.recovery_id != 0 && sig.recovery_id != 1 {
        return Err(AdapterError::BadIntent(format!(
            "EVM signature recovery_id must be 0 or 1, got {}",
            sig.recovery_id
        )));
    }
    let r = U256::from_be_slice(&sig.r);
    let s = U256::from_be_slice(&sig.s);
    let y_parity = sig.recovery_id == 1;
    let signature = Signature::new(r, s, y_parity);

    // SELF-VERIFY (#15): recover the signer from the sighash + (r, s, recovery_id)
    // and confirm it matches the host-set wallet address. This catches a wrong
    // recovery bit or corrupted r/s that the recovery_id range check (#14) alone
    // cannot — fail loud rather than broadcast a tx that recovers to a DIFFERENT
    // account. Skipped only when `from_address` is empty (lower-level encoding
    // paths / fixtures); the production send path always sets it.
    if !resolved.from_address.trim().is_empty() {
        let digest = match unsigned.sign_requests.first() {
            Some(SignRequest::Digest(d)) => *d,
            _ => return Err(AdapterError::Encoding("missing EVM sighash".into())),
        };
        let rid = k256::ecdsa::RecoveryId::from_byte(sig.recovery_id)
            .ok_or_else(|| AdapterError::BadIntent("invalid EVM recovery id".into()))?;
        let mut compact = [0u8; 64];
        compact[0..32].copy_from_slice(&sig.r);
        compact[32..64].copy_from_slice(&sig.s);
        let ksig = k256::ecdsa::Signature::from_slice(&compact)
            .map_err(|e| AdapterError::BadIntent(format!("invalid signature scalars: {e}")))?;
        let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &ksig, rid)
            .map_err(|_| AdapterError::BadIntent("signature does not recover a key".into()))?;
        let recovered = super::address::address_from_pubkey(vk.to_encoded_point(false).as_bytes())?;
        if !recovered.eq_ignore_ascii_case(resolved.from_address.trim()) {
            return Err(AdapterError::BadIntent(
                "recovered signer does not match the wallet address".into(),
            ));
        }
    }

    let bytes = if resolved.legacy {
        let tx = legacy_tx(&resolved)?;
        // With `chain_id: Some(_)` alloy applies the EIP-155 `v`. For a legacy
        // tx `encoded_2718` returns the plain EIP-155 RLP (no type prefix).
        tx.into_signed(signature).encoded_2718()
    } else {
        let tx = eip1559_tx(&resolved)?;
        // EIP-2718 typed envelope: first byte is the 0x02 type marker.
        tx.into_signed(signature).encoded_2718()
    };

    Ok(RawTx(bytes))
}
