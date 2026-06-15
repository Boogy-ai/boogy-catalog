//! Best-effort websocket publish helpers for live tally + status. Never fail the
//! caller (a dropped publish is reconciled by snapshot on reconnect / GET) and
//! are NEVER called inside a `tx`.

use crate::models::Proposal;
use crate::ws_publish_event;

/// Push a `tally.update` envelope to a proposal's public room (room key = id).
pub fn publish_tally(p: &Proposal) {
    let data = serde_json::json!({
        "proposal_id": p.id.get(),
        "status": p.status,
        "yes": p.final_yes,
        "no": p.final_no,
        "abstain": p.final_abstain,
        "veto": p.final_veto,
        "ballots": p.final_ballots,
    });
    let _ = ws_publish_event("proposals", &p.id.get().to_string(), "tally.update", 1, data);
}

/// Push a `proposal.status` envelope to a proposal's public room.
pub fn publish_status(p: &Proposal) {
    let data = serde_json::json!({
        "proposal_id": p.id.get(),
        "status": p.status,
    });
    let _ = ws_publish_event("proposals", &p.id.get().to_string(), "proposal.status", 1, data);
}
