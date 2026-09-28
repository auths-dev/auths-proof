//! The presence rule of the signed outcome: which facts an outcome of each
//! stage carries.
//!
//! Four facts appear in every outcome (the commitment, the stage, the
//! evaluation time, and the recipe digest). The others are optional, and
//! [`outcome_facts_present`] decides whether a given set is the one an
//! outcome of its stage may carry. The rule reuses the attempt record's
//! stage predicates, so an outcome can never carry a fact its stage could
//! not have stored.
//!
//! This module is a translated leaf: one closed enum, one record of
//! booleans, no loops, and no standard-library call.

use crate::transition::{
    Stage, observed_stage, permits_response, provider_stage, refusal_stage, requires_response,
};

/// Which of the optional outcome facts are present.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag per optional fact is the rule's exact input"
)]
pub struct OutcomeFacts {
    /// `counters-digest`: at least one count or sum slot was reserved.
    pub counters_digest: bool,
    /// `refusal`: the stable code of a refused entry.
    pub refusal: bool,
    /// `http-status`: a complete response was recorded.
    pub http_status: bool,
    /// `response-digest`: the SHA-256 of that response.
    pub response_digest: bool,
    /// `observation`: the read-back comparison.
    pub observation: bool,
    /// `evidence-digest`: the SHA-256 of provider-held evidence.
    pub evidence_digest: bool,
    /// `pre-entry-digest`: pre-entry observations were recorded.
    pub pre_entry_digest: bool,
    /// `relative-basis`: a relative-ceiling basis was recorded.
    pub relative_basis: bool,
    /// `relative-basis-digest`: the SHA-256 of the basis response.
    pub relative_basis_digest: bool,
}

/// Whether an outcome may name `stage`: every stage but `attempting`, which
/// an outcome reports as `unknown`.
#[must_use]
pub const fn outcome_stage(stage: Stage) -> bool {
    match stage {
        Stage::Attempting => false,
        Stage::NotEntered
        | Stage::Unknown
        | Stage::ResponseRecorded
        | Stage::Observed
        | Stage::ObservedByProvider => true,
    }
}

/// Whether `facts` is a fact set an outcome of `stage` may carry: a refusal
/// exactly when `not-entered`; the response status and digest together,
/// always for `response-recorded` and `observed`, and never before a
/// response could exist; a comparison exactly when `observed`; provider
/// evidence exactly when `observed-by-provider`; and the basis and its
/// digest together. The counter-set and pre-entry digests may accompany any
/// stage, because a refusal can follow a reservation or a pre-entry read.
#[must_use]
pub const fn outcome_facts_present(stage: Stage, facts: OutcomeFacts) -> bool {
    outcome_stage(stage)
        && refusal_stage(stage) == facts.refusal
        && facts.http_status == facts.response_digest
        && (!requires_response(stage) || facts.http_status)
        && (!facts.http_status || permits_response(stage))
        && observed_stage(stage) == facts.observation
        && provider_stage(stage) == facts.evidence_digest
        && facts.relative_basis == facts.relative_basis_digest
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: OutcomeFacts = OutcomeFacts {
        counters_digest: false,
        refusal: false,
        http_status: false,
        response_digest: false,
        observation: false,
        evidence_digest: false,
        pre_entry_digest: false,
        relative_basis: false,
        relative_basis_digest: false,
    };

    const RESPONSE: OutcomeFacts = OutcomeFacts {
        http_status: true,
        response_digest: true,
        ..NONE
    };

    #[test]
    fn each_stage_accepts_its_documented_minimum() {
        assert!(outcome_facts_present(
            Stage::NotEntered,
            OutcomeFacts {
                refusal: true,
                ..NONE
            }
        ));
        assert!(outcome_facts_present(Stage::Unknown, NONE));
        assert!(outcome_facts_present(Stage::ResponseRecorded, RESPONSE));
        assert!(outcome_facts_present(
            Stage::Observed,
            OutcomeFacts {
                observation: true,
                ..RESPONSE
            }
        ));
        assert!(outcome_facts_present(
            Stage::ObservedByProvider,
            OutcomeFacts {
                evidence_digest: true,
                ..NONE
            }
        ));
        assert!(!outcome_facts_present(Stage::Attempting, NONE));
    }

    #[test]
    fn broken_pairs_and_misplaced_facts_are_refused() {
        assert!(!outcome_facts_present(Stage::NotEntered, NONE));
        assert!(!outcome_facts_present(
            Stage::ResponseRecorded,
            OutcomeFacts {
                response_digest: false,
                ..RESPONSE
            }
        ));
        assert!(!outcome_facts_present(
            Stage::ResponseRecorded,
            OutcomeFacts {
                refusal: true,
                ..RESPONSE
            }
        ));
        assert!(!outcome_facts_present(
            Stage::Unknown,
            OutcomeFacts {
                relative_basis_digest: true,
                ..NONE
            }
        ));
        assert!(!outcome_facts_present(Stage::Unknown, RESPONSE));
        assert!(!outcome_facts_present(
            Stage::Observed,
            OutcomeFacts {
                observation: true,
                evidence_digest: true,
                ..RESPONSE
            }
        ));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_stage() -> Stage {
        match kani::any::<u8>() % 6 {
            0 => Stage::Attempting,
            1 => Stage::NotEntered,
            2 => Stage::Unknown,
            3 => Stage::ResponseRecorded,
            4 => Stage::Observed,
            _ => Stage::ObservedByProvider,
        }
    }

    /// Exhaustive over every stage and every subset of the optional facts:
    /// the rule accepts exactly the table of the signed outcome, written
    /// here stage by stage.
    #[kani::proof]
    fn presence_rule_matches_the_outcome_table() {
        let stage = any_stage();
        let facts = OutcomeFacts {
            counters_digest: kani::any(),
            refusal: kani::any(),
            http_status: kani::any(),
            response_digest: kani::any(),
            observation: kani::any(),
            evidence_digest: kani::any(),
            pre_entry_digest: kani::any(),
            relative_basis: kani::any(),
            relative_basis_digest: kani::any(),
        };
        let pairs = facts.http_status == facts.response_digest
            && facts.relative_basis == facts.relative_basis_digest;
        let table = match stage {
            Stage::Attempting => false,
            Stage::NotEntered => {
                facts.refusal && !facts.http_status && !facts.observation && !facts.evidence_digest
            }
            Stage::Unknown => {
                !facts.refusal && !facts.http_status && !facts.observation && !facts.evidence_digest
            }
            Stage::ResponseRecorded => {
                !facts.refusal && facts.http_status && !facts.observation && !facts.evidence_digest
            }
            Stage::Observed => {
                !facts.refusal && facts.http_status && facts.observation && !facts.evidence_digest
            }
            Stage::ObservedByProvider => {
                !facts.refusal && !facts.observation && facts.evidence_digest
            }
        };
        assert_eq!(outcome_facts_present(stage, facts), pairs && table);
    }
}
