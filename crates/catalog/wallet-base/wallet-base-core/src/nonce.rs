//! Pure nonce-reservation arithmetic for account-based chains (EVM nonce /
//! Cosmos sequence). The durable state machine + the serializing store
//! transaction live in the service crate; this is just the decision the
//! reservation commits, kept pure so it is unit-testable.
//!
//! The hazard it closes (#8): two concurrent sends for one account both fetch
//! the SAME on-chain pending nonce (the chain hasn't seen either tx yet) and
//! both sign with it — one tx is then dropped/replaced. A durable per-account
//! counter, advanced inside a store transaction, serializes the reservation so
//! each send gets a distinct nonce; concurrent reservations conflict on the row
//! and the loser retries (the service maps the conflict to a 409).

/// Decide the nonce to reserve and the new stored "next" counter, given the
/// chain's pending nonce and our last stored counter.
///
/// The reserved nonce is `max(on_chain_pending, stored_next)`:
/// - if the chain is AHEAD of our counter (e.g. txs landed out-of-band, or this
///   is the first send), use the chain's value and jump our counter forward;
/// - if our counter is ahead (we've handed out nonces the chain hasn't seen
///   confirmed yet — the in-flight pipeline), keep advancing from it so two
///   pending sends never collide.
///
/// Returns `(reserved, new_stored)` where `new_stored = reserved + 1`
/// (saturating; a u64 nonce never realistically reaches the ceiling).
pub fn reserve(on_chain_pending: u64, stored_next: u64) -> (u64, u64) {
    let reserved = on_chain_pending.max(stored_next);
    (reserved, reserved.saturating_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_ever_send_uses_chain_pending() {
        // No stored counter yet (0); the chain reports pending nonce 5.
        let (reserved, next) = reserve(5, 0);
        assert_eq!(reserved, 5, "use the chain's pending nonce");
        assert_eq!(next, 6, "advance the counter past it");
    }

    #[test]
    fn counter_ahead_of_chain_keeps_advancing() {
        // Two sends already in flight: chain still reports 5, our counter is 7.
        // The next reservation must be 7 (not 5) so the in-flight pipeline does
        // not collide on a nonce.
        let (reserved, next) = reserve(5, 7);
        assert_eq!(reserved, 7);
        assert_eq!(next, 8);
    }

    #[test]
    fn chain_ahead_of_counter_jumps_forward() {
        // Out-of-band txs advanced the chain past our stale counter.
        let (reserved, next) = reserve(20, 12);
        assert_eq!(reserved, 20, "never reuse a nonce the chain advanced past");
        assert_eq!(next, 21);
    }

    #[test]
    fn equal_picks_that_value() {
        let (reserved, next) = reserve(9, 9);
        assert_eq!(reserved, 9);
        assert_eq!(next, 10);
    }

    #[test]
    fn sequential_reservations_are_distinct() {
        // Simulate the stored counter threading through back-to-back reserves
        // while the chain's pending nonce stays put (txs not yet seen).
        let chain = 3;
        let (r1, n1) = reserve(chain, 0);
        let (r2, n2) = reserve(chain, n1);
        let (r3, _n3) = reserve(chain, n2);
        assert_eq!((r1, r2, r3), (3, 4, 5), "each sequential send gets a distinct nonce");
    }
}
