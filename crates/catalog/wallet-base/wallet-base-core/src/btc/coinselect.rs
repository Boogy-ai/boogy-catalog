//! Pure coin selection for P2WPKH spends — accumulate-until-covered.
//!
//! This is a deliberately simple, deterministic selector (NOT a privacy- or
//! fee-optimal one; branch-and-bound / privacy heuristics are deferred — YAGNI):
//!
//!  - Walk the caller's UTXOs in the order given, accumulating value until the
//!    running total covers `amount + estimated_fee`. The fee estimate grows with
//!    each added input (each input adds vbytes), so we re-evaluate the target on
//!    every step.
//!  - The fee is `fee_rate_sat_vb * estimated_vsize`, where vsize is estimated
//!    from the selected-input count and the output count using P2WPKH constants
//!    (see [`estimate_vsize`]).
//!  - Change = `selected_total - amount - fee`. If change is below the dust
//!    threshold ([`DUST_THRESHOLD_SAT`]) it is folded into the fee and NO change
//!    output is emitted (returning `change_sat == 0`); otherwise it funds a
//!    change output back to the sender's own P2WPKH.
//!  - If the inputs cannot cover `amount + fee`, selection fails closed with
//!    [`AdapterError::BadIntent`] — we never emit an under-funded tx.

use crate::btc::Utxo;
use crate::types::AdapterError;

/// Per-input vsize (vbytes) for a P2WPKH spend: ~36 (outpoint) + ~4 (sequence) +
/// ~1 (empty script_sig len) + ~27 (witness, weight-discounted) ≈ 68 vB.
const VBYTES_PER_P2WPKH_INPUT: u64 = 68;

/// Per-output vsize (vbytes) for a P2WPKH output: 8 (value) + 1 (script len) +
/// 22 (witness program) ≈ 31 vB.
const VBYTES_PER_P2WPKH_OUTPUT: u64 = 31;

/// Fixed tx overhead (vbytes): version (4) + locktime (4) + segwit marker/flag
/// (weight-discounted ~0.5) + input/output count varints ≈ 11 vB.
const VBYTES_TX_OVERHEAD: u64 = 11;

/// Dust threshold (sats). Change below this is uneconomical to ever spend (the
/// fee to redeem a P2WPKH output exceeds its value at typical fee rates), so we
/// fold it into the fee rather than emit an unspendable output. The canonical
/// P2WPKH dust limit at the reference relay fee is ~294 sat.
pub const DUST_THRESHOLD_SAT: u64 = 294;

/// The outcome of coin selection: which UTXOs to spend + the change amount
/// (0 = no change output; change folded into fee or exactly zero).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// UTXOs to spend, in selection order (== the resulting input order).
    pub selected: Vec<Utxo>,
    /// Change to return to the sender's own P2WPKH; 0 = no change output.
    pub change_sat: u64,
    /// The fee this selection pays (`selected_total - amount - change_sat`).
    pub fee_sat: u64,
}

/// Estimate the vsize (vbytes) of a P2WPKH tx with `num_inputs` inputs and
/// `num_outputs` outputs. Used only for fee estimation; the actual serialized
/// size is irrelevant to validity (we never round-trip this number into the tx).
pub fn estimate_vsize(num_inputs: u64, num_outputs: u64) -> u64 {
    VBYTES_TX_OVERHEAD
        + num_inputs * VBYTES_PER_P2WPKH_INPUT
        + num_outputs * VBYTES_PER_P2WPKH_OUTPUT
}

/// Accumulate-until-covered selection. See the module docs for the heuristic.
///
/// `target_sat` is the recipient amount; the fee is computed internally from
/// `fee_rate_sat_vb` and the running input/output counts. Returns the selected
/// UTXOs plus the resolved change and fee, or [`AdapterError::BadIntent`] on
/// empty UTXO set / insufficient funds.
pub fn select_coins(
    utxos: &[Utxo],
    target_sat: u64,
    fee_rate_sat_vb: u64,
) -> Result<Selection, AdapterError> {
    if utxos.is_empty() {
        return Err(AdapterError::BadIntent("no UTXOs to spend".into()));
    }

    let mut selected: Vec<Utxo> = Vec::new();
    let mut total: u64 = 0;

    for utxo in utxos {
        selected.push(utxo.clone());
        total = total.saturating_add(utxo.value_sat);

        let n_in = selected.len() as u64;

        // Fee assuming we emit a change output (2 outputs): recipient + change.
        let fee_with_change = fee_rate_sat_vb.saturating_mul(estimate_vsize(n_in, 2));
        let need_with_change = target_sat
            .saturating_add(fee_with_change)
            .saturating_add(DUST_THRESHOLD_SAT);

        if total >= need_with_change {
            // Funds cover amount + fee + a non-dust change output. The guard
            // `need_with_change = target + fee_with_change + DUST` provably makes
            // `change = total - target - fee_with_change >= DUST`, so no inner
            // dust re-check is needed (#20 — the old fall-through was dead code).
            let change = total - target_sat - fee_with_change;
            return Ok(Selection {
                selected,
                change_sat: change,
                fee_sat: fee_with_change,
            });
        }

        // Fee assuming NO change output (1 output): recipient only.
        let fee_no_change = fee_rate_sat_vb.saturating_mul(estimate_vsize(n_in, 1));
        let need_no_change = target_sat.saturating_add(fee_no_change);
        if total >= need_no_change {
            // Cover amount + fee with no economical change → omit change, the
            // residue (which is < dust + a sliver) is folded into the fee.
            let actual_fee = total - target_sat;
            return Ok(Selection {
                selected,
                change_sat: 0,
                fee_sat: actual_fee,
            });
        }
        // Not yet covered — add another input.
    }

    Err(AdapterError::BadIntent(format!(
        "insufficient funds: have {} sat across {} UTXO(s), need {} sat + fee",
        total,
        selected.len(),
        target_sat
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utxo(value: u64) -> Utxo {
        Utxo {
            txid: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            vout: 0,
            value_sat: value,
        }
    }

    #[test]
    fn selects_enough_and_computes_change() {
        // One fat UTXO covers a small send with non-dust change left over.
        let sel = select_coins(&[utxo(100_000)], 10_000, 1).expect("covered");
        assert_eq!(sel.selected.len(), 1);
        assert!(sel.change_sat >= DUST_THRESHOLD_SAT, "non-dust change");
        // Conservation: total == amount + fee + change.
        assert_eq!(100_000, 10_000 + sel.fee_sat + sel.change_sat);
    }

    #[test]
    fn accumulates_multiple_inputs() {
        let sel = select_coins(&[utxo(5_000), utxo(5_000), utxo(5_000)], 12_000, 1)
            .expect("covered after accumulation");
        assert!(sel.selected.len() >= 3 || sel.selected.iter().map(|u| u.value_sat).sum::<u64>() >= 12_000);
        let total: u64 = sel.selected.iter().map(|u| u.value_sat).sum();
        assert_eq!(total, 12_000 + sel.fee_sat + sel.change_sat);
    }

    #[test]
    fn dust_change_folded_into_fee() {
        // Pick amount + fee so the residue is below dust → no change output.
        // With 1 input, 1 output: vsize = 11 + 68 + 31 = 110; fee@1 = 110.
        // total = amount + fee + (dust-1): 10_000 + 110 + 293 = 10_403.
        let sel = select_coins(&[utxo(10_403)], 10_000, 1).expect("covered");
        assert_eq!(sel.change_sat, 0, "dust change folded into fee");
        assert_eq!(sel.fee_sat, 10_403 - 10_000);
    }

    #[test]
    fn insufficient_funds_errs() {
        let err = select_coins(&[utxo(5_000)], 10_000, 1).unwrap_err();
        assert!(matches!(err, AdapterError::BadIntent(_)));
    }

    #[test]
    fn empty_utxos_errs() {
        let err = select_coins(&[], 10_000, 1).unwrap_err();
        assert!(matches!(err, AdapterError::BadIntent(_)));
    }
}
