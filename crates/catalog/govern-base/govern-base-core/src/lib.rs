//! govern-base-core — pure, host-testable governance decision logic for the
//! govern-base catalog service: vote-option + proposal-status enums, weighted
//! tally aggregation, the quorum/threshold/veto decision rule, and
//! action-envelope validation. No I/O — unit-tested on the host.

/// A ballot choice. Cosmos-aligned: `Abstain` counts toward quorum but not the
/// yes/no ratio; `Veto` is the malicious-but-popular guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteOption {
    Yes,
    No,
    Abstain,
    Veto,
}

impl VoteOption {
    pub fn as_str(self) -> &'static str {
        match self {
            VoteOption::Yes => "yes",
            VoteOption::No => "no",
            VoteOption::Abstain => "abstain",
            VoteOption::Veto => "veto",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "yes" => Some(VoteOption::Yes),
            "no" => Some(VoteOption::No),
            "abstain" => Some(VoteOption::Abstain),
            "veto" => Some(VoteOption::Veto),
            _ => None,
        }
    }
}

/// Proposal lifecycle states (see the spec state machine).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalStatus {
    Draft,
    Sponsorship,
    Voting,
    Passed,
    Rejected,
    Vetoed,
    Timelock,
    Executing,
    Executed,
    Failed,
    Expired,
    Withdrawn,
    Canceled,
}

impl ProposalStatus {
    pub const ALL: [ProposalStatus; 13] = [
        ProposalStatus::Draft,
        ProposalStatus::Sponsorship,
        ProposalStatus::Voting,
        ProposalStatus::Passed,
        ProposalStatus::Rejected,
        ProposalStatus::Vetoed,
        ProposalStatus::Timelock,
        ProposalStatus::Executing,
        ProposalStatus::Executed,
        ProposalStatus::Failed,
        ProposalStatus::Expired,
        ProposalStatus::Withdrawn,
        ProposalStatus::Canceled,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ProposalStatus::Draft => "draft",
            ProposalStatus::Sponsorship => "sponsorship",
            ProposalStatus::Voting => "voting",
            ProposalStatus::Passed => "passed",
            ProposalStatus::Rejected => "rejected",
            ProposalStatus::Vetoed => "vetoed",
            ProposalStatus::Timelock => "timelock",
            ProposalStatus::Executing => "executing",
            ProposalStatus::Executed => "executed",
            ProposalStatus::Failed => "failed",
            ProposalStatus::Expired => "expired",
            ProposalStatus::Withdrawn => "withdrawn",
            ProposalStatus::Canceled => "canceled",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        ProposalStatus::ALL.into_iter().find(|st| st.as_str() == s)
    }
}

#[cfg(test)]
mod option_status_tests {
    use super::*;

    #[test]
    fn vote_option_roundtrips() {
        for o in [VoteOption::Yes, VoteOption::No, VoteOption::Abstain, VoteOption::Veto] {
            assert_eq!(VoteOption::from_str(o.as_str()), Some(o));
        }
        assert_eq!(VoteOption::from_str("nope"), None);
    }

    #[test]
    fn status_roundtrips() {
        for s in ProposalStatus::ALL {
            assert_eq!(ProposalStatus::from_str(s.as_str()), Some(s));
        }
        assert_eq!(ProposalStatus::from_str("bogus"), None);
    }
}

/// Weighted vote sums for a proposal. `ballots` is the raw count of distinct
/// ballots (the quorum basis in open electorates, where there is no fixed power).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct Tally {
    pub yes: i64,
    pub no: i64,
    pub abstain: i64,
    pub veto: i64,
    pub ballots: i64,
}

impl Tally {
    /// Power that counts toward the pass/veto ratios (abstain excluded).
    pub fn participating(&self) -> i64 {
        self.yes + self.no + self.veto
    }

    /// Power that counts toward quorum in a bounded electorate (abstain included).
    pub fn total(&self) -> i64 {
        self.yes + self.no + self.veto + self.abstain
    }
}

/// Aggregate `(option, weight)` ballots into a [`Tally`]. In Phase 1 (1p1v) every
/// weight is `1`; the signature takes weights so Phase 2 (weighted/delegation)
/// reuses it unchanged.
///
/// PRECONDITION: pass exactly ONE entry per voter (each voter's final ballot).
/// `ballots` counts entries, so duplicate entries for the same voter overcount
/// both `ballots` (the open-electorate quorum basis) and the vote sums. Callers
/// resolve a voter's latest ballot before tallying — single-cast in Phase 1, an
/// UPSERT in Phase 2 — so each voter appears once.
pub fn tally_votes(votes: &[(VoteOption, i64)]) -> Tally {
    let mut t = Tally::default();
    for (opt, w) in votes {
        t.ballots += 1;
        match opt {
            VoteOption::Yes => t.yes += w,
            VoteOption::No => t.no += w,
            VoteOption::Abstain => t.abstain += w,
            VoteOption::Veto => t.veto += w,
        }
    }
    t
}

#[cfg(test)]
mod tally_tests {
    use super::*;

    #[test]
    fn aggregates_weighted_votes() {
        let votes = [
            (VoteOption::Yes, 3),
            (VoteOption::Yes, 1),
            (VoteOption::No, 2),
            (VoteOption::Abstain, 5),
            (VoteOption::Veto, 1),
        ];
        let t = tally_votes(&votes);
        assert_eq!(t.yes, 4);
        assert_eq!(t.no, 2);
        assert_eq!(t.abstain, 5);
        assert_eq!(t.veto, 1);
        assert_eq!(t.participating(), 7); // yes+no+veto
        assert_eq!(t.total(), 12); // + abstain
        assert_eq!(t.ballots, 5);
    }

    #[test]
    fn empty_tally_is_zero() {
        let t = tally_votes(&[]);
        assert_eq!(t.participating(), 0);
        assert_eq!(t.total(), 0);
        assert_eq!(t.ballots, 0);
    }
}

/// Tally gates, all fractions in `0.0..=1.0`.
#[derive(Clone, Copy, Debug)]
pub struct TallyParams {
    /// Quorum fraction of total eligible power (bounded electorates only).
    pub quorum: f64,
    /// Minimum `yes / participating` to pass.
    pub threshold: f64,
    /// `veto / participating` at or above this vetoes the proposal.
    pub veto_threshold: f64,
}

/// The electorate shape, deciding how quorum is measured.
#[derive(Clone, Copy, Debug)]
pub enum Electorate {
    /// A known total voting power (members / weighted / registered workloads).
    Bounded { total_power: i64 },
    /// No fixed electorate (any authenticated principal); quorum is an absolute
    /// ballot-count floor instead of a fraction.
    Open,
}

/// The terminal outcome of a tally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Rejected,
    Vetoed,
}

/// Apply the Cosmos-aligned three-gate decision. `min_participation` is the
/// absolute ballot floor used only when `electorate` is `Open` (ignored otherwise).
///
/// Order: quorum first (unmet → Rejected), then veto (overrides a pass), then
/// the pass threshold; anything else → Rejected.
pub fn decide(
    tally: &Tally,
    params: &TallyParams,
    electorate: &Electorate,
    min_participation: i64,
) -> Outcome {
    let quorum_met = match electorate {
        Electorate::Bounded { total_power } => {
            *total_power > 0 && (tally.total() as f64) >= params.quorum * (*total_power as f64)
        }
        Electorate::Open => tally.ballots >= min_participation,
    };
    if !quorum_met {
        return Outcome::Rejected;
    }

    let p = tally.participating();
    if p <= 0 {
        return Outcome::Rejected;
    }
    let p = p as f64;

    if (tally.veto as f64) / p >= params.veto_threshold {
        return Outcome::Vetoed;
    }
    if (tally.yes as f64) / p >= params.threshold {
        return Outcome::Passed;
    }
    Outcome::Rejected
}

#[cfg(test)]
mod decide_tests {
    use super::*;

    fn params() -> TallyParams {
        TallyParams { quorum: 0.4, threshold: 0.5, veto_threshold: 1.0 / 3.0 }
    }

    #[test]
    fn bounded_quorum_unmet_is_rejected() {
        // total power 100, only 30 participated+abstained → below 40% quorum.
        let t = Tally { yes: 30, no: 0, abstain: 0, veto: 0, ballots: 30 };
        let e = Electorate::Bounded { total_power: 100 };
        assert_eq!(decide(&t, &params(), &e, 0), Outcome::Rejected);
    }

    #[test]
    fn bounded_passes_on_threshold() {
        // 60 yes / (60 yes + 30 no) = 0.666 ≥ 0.5; total 90 ≥ 40 quorum.
        let t = Tally { yes: 60, no: 30, abstain: 0, veto: 0, ballots: 90 };
        let e = Electorate::Bounded { total_power: 100 };
        assert_eq!(decide(&t, &params(), &e, 0), Outcome::Passed);
    }

    #[test]
    fn veto_overrides_pass() {
        // would pass on yes-ratio, but veto/participating = 40/100 ≥ 1/3.
        let t = Tally { yes: 55, no: 5, abstain: 0, veto: 40, ballots: 100 };
        let e = Electorate::Bounded { total_power: 100 };
        assert_eq!(decide(&t, &params(), &e, 0), Outcome::Vetoed);
    }

    #[test]
    fn abstain_counts_for_quorum_not_ratio() {
        // 30 yes, 10 no, 60 abstain. quorum: total 100 ≥ 40 ✓.
        // threshold: 30/(30+10) = 0.75 ≥ 0.5 → Passed (abstain excluded).
        let t = Tally { yes: 30, no: 10, abstain: 60, veto: 0, ballots: 100 };
        let e = Electorate::Bounded { total_power: 100 };
        assert_eq!(decide(&t, &params(), &e, 0), Outcome::Passed);
    }

    #[test]
    fn open_quorum_uses_ballot_floor() {
        let t = Tally { yes: 3, no: 1, abstain: 0, veto: 0, ballots: 4 };
        let e = Electorate::Open;
        // min_participation = 5 → 4 ballots below floor → Rejected.
        assert_eq!(decide(&t, &params(), &e, 5), Outcome::Rejected);
        // min_participation = 4 → meets floor; 3/4 ≥ 0.5 → Passed.
        assert_eq!(decide(&t, &params(), &e, 4), Outcome::Passed);
    }

    #[test]
    fn no_participation_is_rejected() {
        let t = Tally { yes: 0, no: 0, abstain: 10, veto: 0, ballots: 10 };
        let e = Electorate::Bounded { total_power: 10 };
        assert_eq!(decide(&t, &params(), &e, 0), Outcome::Rejected);
    }
}

/// The transparently-encoded shape of one executable action a proposal carries.
/// This mirrors the persisted `ProposalAction` fields the validator needs; the
/// full row also stores headers/body/secret_header_ref, which need no pure
/// validation here (their safety floor is the host's manifest envelope at
/// execution time).
#[derive(Clone, Debug)]
pub struct ActionSpec {
    /// `"peer"` (in-mesh call) or `"http"` (outbound call).
    pub action_type: String,
    /// For `http`: an absolute `http`/`https` URL. For `peer`: a `boogy://` URI.
    pub target: String,
    /// HTTP method, restricted to a safe verb set.
    pub method: String,
}

const ALLOWED_METHODS: [&str; 4] = ["GET", "POST", "PUT", "DELETE"];

/// Shape-validate one action at proposal-creation time. This is a sanity gate,
/// NOT the security boundary — the host's manifest `[outbound] allowed_hosts` +
/// peer capability bound what can actually execute. Returns `Err(reason)`.
pub fn validate_action(a: &ActionSpec) -> Result<(), String> {
    let method = a.method.to_ascii_uppercase();
    if !ALLOWED_METHODS.contains(&method.as_str()) {
        return Err(format!("unsupported method `{}`", a.method));
    }
    if a.target.trim().is_empty() {
        return Err("action target is empty".into());
    }
    match a.action_type.as_str() {
        "http" => {
            if !(a.target.starts_with("http://") || a.target.starts_with("https://")) {
                return Err("http action target must be an http(s) URL".into());
            }
            Ok(())
        }
        "peer" => {
            if !a.target.starts_with("boogy://") {
                return Err("peer action target must be a boogy:// workload URI".into());
            }
            Ok(())
        }
        other => Err(format!("unknown action_type `{other}`")),
    }
}

/// True if `author` appears in a comma-separated exempt-proposers list (entries
/// are trimmed; empty entries never match). The pure, listable half of the
/// co-sponsorship fast-track — the owner-identity check stays in the service layer
/// (it needs host-attested identity), but the configurable allow-list match is
/// here so it is unit-tested.
pub fn proposer_in_exempt_list(author: &str, list: &str) -> bool {
    list.split(',')
        .map(|s| s.trim())
        .any(|e| !e.is_empty() && e == author)
}

#[cfg(test)]
mod action_tests {
    use super::*;

    fn http(target: &str, method: &str) -> ActionSpec {
        ActionSpec {
            action_type: "http".into(),
            target: target.into(),
            method: method.into(),
        }
    }

    #[test]
    fn accepts_valid_http_and_peer() {
        assert!(validate_action(&http("https://api.example.com/x", "POST")).is_ok());
        assert!(validate_action(&ActionSpec {
            action_type: "peer".into(),
            target: "boogy://alice/services/treasury".into(),
            method: "POST".into(),
        })
        .is_ok());
    }

    #[test]
    fn rejects_unknown_type_method_and_empty_target() {
        assert!(validate_action(&ActionSpec {
            action_type: "ftp".into(),
            target: "x".into(),
            method: "POST".into(),
        })
        .is_err());
        assert!(validate_action(&http("https://api.example.com/x", "TRACE")).is_err());
        assert!(validate_action(&http("", "POST")).is_err());
    }

    #[test]
    fn rejects_non_http_url_for_http_action() {
        assert!(validate_action(&http("ftp://api.example.com", "POST")).is_err());
        assert!(validate_action(&http("api.example.com/x", "POST")).is_err());
    }

    #[test]
    fn rejects_non_uri_target_for_peer_action() {
        assert!(validate_action(&ActionSpec {
            action_type: "peer".into(),
            target: "treasury".into(),
            method: "POST".into(),
        })
        .is_err());
    }
}

#[cfg(test)]
mod exempt_list_tests {
    use super::*;

    #[test]
    fn matches_single_and_whitespaced_multi_entry_lists() {
        assert!(proposer_in_exempt_list("alice", "alice"));
        assert!(proposer_in_exempt_list(
            "boogy://acme/services/council",
            "agent_x, boogy://acme/services/council , agent_y"
        ));
    }

    #[test]
    fn rejects_non_member_empty_and_substring() {
        assert!(!proposer_in_exempt_list("mallory", "alice,bob")); // not listed
        assert!(!proposer_in_exempt_list("alice", "")); // empty list
        assert!(!proposer_in_exempt_list("", "")); // empty author vs empty entries
        assert!(!proposer_in_exempt_list("", "alice,bob")); // empty author never matches
        assert!(!proposer_in_exempt_list("alice", "alice2")); // substring is not a match
    }
}
