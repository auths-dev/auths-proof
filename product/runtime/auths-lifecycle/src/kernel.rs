//! Aeneas-shaped pure lifecycle transition predicates.
//!
//! These functions are the production decision boundary. Rich carriers
//! validate commitments and capacity snapshots before projecting into this
//! closed, allocation-free kernel.

use crate::LifecycleState;

/// Closed operation presented to the pure lifecycle kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationCode {
    /// Create a durable decision from record absence.
    RecordDecision,
    /// Acquire every reservation.
    Reserve,
    /// Bind exact execution intent.
    RecordExecutionIntent,
    /// Authorize credential acquisition.
    AuthorizeCredential,
    /// Record one provider attempt.
    StartAttempt,
    /// Record provider call entry.
    MarkProviderCallEntered,
    /// Record definite effect.
    Commit,
    /// Record definite non-effect.
    Release,
    /// Record ambiguity.
    MarkOutcomeUnknown,
    /// Reconcile to definite effect.
    ReconcileEffect,
    /// Reconcile to definite non-effect.
    ReconcileNonEffect,
    /// Persist inconclusive reconciliation evidence.
    ReconcileInconclusive,
}

/// Complete Boolean projection supplied by the validated rich transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// This is the deliberately flat Aeneas boundary: each rich proposition is
// translated as one Boolean and proved equivalent in Lean.
#[allow(clippy::struct_excessive_bools)]
pub struct TransitionGates {
    /// Core proof authorization succeeded.
    pub core_authorized: bool,
    /// AP-SPEC-025 eligibility succeeded with complete outputs.
    pub policy_eligible: bool,
    /// Required, originally executed, and currently executed configuration match.
    pub configuration_matches: bool,
    /// Current authority is not revoked.
    pub not_revoked: bool,
    /// Current authority is not expired.
    pub not_expired: bool,
    /// Every reservation intent fits atomically.
    pub capacity_available: bool,
    /// Execution intent exists and matches the command.
    pub execution_intent_present: bool,
    /// Credential acquisition was durably authorized.
    pub credential_authorized: bool,
    /// At least one attempt exists.
    pub attempt_present: bool,
    /// Provider call entry is durably recorded.
    pub provider_call_entered: bool,
    /// Domain cancellation policy allows pre-attempt release.
    pub cancellation_allowed: bool,
    /// Domain evidence proves effect.
    pub definite_effect: bool,
    /// Domain evidence proves non-effect.
    pub definite_non_effect: bool,
    /// Reconciliation evidence is fresh.
    pub reconciliation_fresh: bool,
    /// Reconciliation evidence binds the exact execution/request.
    pub reconciliation_matches: bool,
}

/// Stable result selected inside the translated kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelCode {
    /// Legal transition to the returned state.
    Applied(LifecycleState),
    /// Inconclusive reconciliation is appended without changing state.
    ObservationOnly,
    /// Existing terminal record cannot transition.
    Terminal,
    /// Current state and operation do not form a legal edge.
    IllegalTransition,
    /// Core proof was not authorized.
    NotAuthorized,
    /// Pure policy was not eligible.
    NotEligible,
    /// Configuration commitments differ.
    ConfigurationMismatch,
    /// Authority is revoked.
    Revoked,
    /// Authority is expired.
    Expired,
    /// Atomic capacity is unavailable.
    CapacityExceeded,
    /// Execution intent is absent or inconsistent.
    ExecutionIntentMissing,
    /// Credential authorization is absent.
    CredentialNotAuthorized,
    /// Provider attempt is absent.
    AttemptMissing,
    /// Provider call entry is absent.
    ProviderCallNotEntered,
    /// Definite effect evidence is absent.
    EffectNotProved,
    /// Definite non-effect evidence is absent.
    NonEffectNotProved,
    /// Reconciliation evidence is stale.
    ReconciliationStale,
    /// Reconciliation evidence does not bind the exact effect.
    ReconciliationMismatch,
}

/// Selects one legal transition or stable failure in immutable diagnostic order.
#[must_use]
// Keeping the complete closed table in one translated function makes drift
// between Rust and Lean visible; splitting it would obscure diagnostic order.
#[allow(clippy::too_many_lines)]
pub const fn transition_code(
    current: Option<LifecycleState>,
    operation: OperationCode,
    gates: TransitionGates,
) -> KernelCode {
    if match current {
        Some(state) => state.is_terminal(),
        None => false,
    } {
        return KernelCode::Terminal;
    }
    match (current, operation) {
        (None, OperationCode::RecordDecision) => {
            if !gates.core_authorized {
                KernelCode::NotAuthorized
            } else if !gates.policy_eligible {
                KernelCode::NotEligible
            } else if !gates.configuration_matches {
                KernelCode::ConfigurationMismatch
            } else if !gates.not_revoked {
                KernelCode::Revoked
            } else if !gates.not_expired {
                KernelCode::Expired
            } else {
                KernelCode::Applied(LifecycleState::DecisionRecorded)
            }
        }
        (Some(LifecycleState::DecisionRecorded), OperationCode::Reserve) => {
            if !gates.configuration_matches {
                KernelCode::ConfigurationMismatch
            } else if !gates.not_revoked {
                KernelCode::Revoked
            } else if !gates.not_expired {
                KernelCode::Expired
            } else if !gates.capacity_available {
                KernelCode::CapacityExceeded
            } else {
                KernelCode::Applied(LifecycleState::Reserved)
            }
        }
        (Some(LifecycleState::Reserved), OperationCode::RecordExecutionIntent) => {
            if !gates.configuration_matches {
                KernelCode::ConfigurationMismatch
            } else if !gates.not_revoked {
                KernelCode::Revoked
            } else if !gates.not_expired {
                KernelCode::Expired
            } else if !gates.execution_intent_present {
                KernelCode::ExecutionIntentMissing
            } else {
                KernelCode::Applied(LifecycleState::ExecutionIntentRecorded)
            }
        }
        (Some(LifecycleState::ExecutionIntentRecorded), OperationCode::AuthorizeCredential) => {
            if !gates.configuration_matches {
                KernelCode::ConfigurationMismatch
            } else if !gates.not_revoked {
                KernelCode::Revoked
            } else if !gates.not_expired {
                KernelCode::Expired
            } else if !gates.execution_intent_present {
                KernelCode::ExecutionIntentMissing
            } else if gates.credential_authorized {
                KernelCode::IllegalTransition
            } else {
                KernelCode::Applied(LifecycleState::ExecutionIntentRecorded)
            }
        }
        (Some(LifecycleState::ExecutionIntentRecorded), OperationCode::StartAttempt) => {
            if !gates.configuration_matches {
                KernelCode::ConfigurationMismatch
            } else if !gates.not_revoked {
                KernelCode::Revoked
            } else if !gates.not_expired {
                KernelCode::Expired
            } else if !gates.execution_intent_present {
                KernelCode::ExecutionIntentMissing
            } else if !gates.credential_authorized {
                KernelCode::CredentialNotAuthorized
            } else {
                KernelCode::Applied(LifecycleState::Executing)
            }
        }
        (Some(LifecycleState::Executing), OperationCode::MarkProviderCallEntered) => {
            if gates.provider_call_entered {
                KernelCode::IllegalTransition
            } else if gates.attempt_present {
                KernelCode::Applied(LifecycleState::Executing)
            } else {
                KernelCode::AttemptMissing
            }
        }
        (Some(LifecycleState::Executing), OperationCode::Commit) => {
            if !gates.attempt_present {
                KernelCode::AttemptMissing
            } else if !gates.provider_call_entered {
                KernelCode::ProviderCallNotEntered
            } else if !gates.definite_effect {
                KernelCode::EffectNotProved
            } else {
                KernelCode::Applied(LifecycleState::Committed)
            }
        }
        (Some(LifecycleState::Reserved), OperationCode::Release) => {
            if gates.attempt_present {
                KernelCode::IllegalTransition
            } else if !gates.cancellation_allowed && !gates.definite_non_effect {
                KernelCode::NonEffectNotProved
            } else {
                KernelCode::Applied(LifecycleState::Released)
            }
        }
        (Some(LifecycleState::ExecutionIntentRecorded), OperationCode::Release) => {
            if gates.attempt_present {
                KernelCode::IllegalTransition
            } else {
                KernelCode::Applied(LifecycleState::Released)
            }
        }
        (Some(LifecycleState::Executing), OperationCode::Release) => {
            if !gates.attempt_present {
                KernelCode::AttemptMissing
            } else if !gates.definite_non_effect {
                KernelCode::NonEffectNotProved
            } else {
                KernelCode::Applied(LifecycleState::Released)
            }
        }
        (Some(LifecycleState::Executing), OperationCode::MarkOutcomeUnknown) => {
            if gates.attempt_present {
                KernelCode::Applied(LifecycleState::OutcomeUnknown)
            } else {
                KernelCode::AttemptMissing
            }
        }
        (Some(LifecycleState::OutcomeUnknown), OperationCode::ReconcileEffect) => {
            reconciliation_code(gates, LifecycleState::ReconciledCommitted)
        }
        (Some(LifecycleState::OutcomeUnknown), OperationCode::ReconcileNonEffect) => {
            reconciliation_code(gates, LifecycleState::ReconciledReleased)
        }
        (Some(LifecycleState::OutcomeUnknown), OperationCode::ReconcileInconclusive) => {
            if !gates.reconciliation_fresh {
                KernelCode::ReconciliationStale
            } else if !gates.reconciliation_matches {
                KernelCode::ReconciliationMismatch
            } else {
                KernelCode::ObservationOnly
            }
        }
        _ => KernelCode::IllegalTransition,
    }
}

const fn reconciliation_code(gates: TransitionGates, next: LifecycleState) -> KernelCode {
    if !gates.reconciliation_fresh {
        KernelCode::ReconciliationStale
    } else if !gates.reconciliation_matches {
        KernelCode::ReconciliationMismatch
    } else {
        KernelCode::Applied(next)
    }
}

/// Returns whether adding one exact amount preserves additive capacity.
#[must_use]
pub const fn additive_capacity_available(
    ceiling: u64,
    committed: u64,
    active: u64,
    requested: u64,
) -> bool {
    if ceiling == 0 || requested == 0 {
        return false;
    }
    let Some(used) = committed.checked_add(active) else {
        return false;
    };
    let Some(next) = used.checked_add(requested) else {
        return false;
    };
    next <= ceiling
}

/// Returns whether an exclusive scope can be acquired by this reservation.
#[must_use]
pub const fn exclusive_capacity_available(
    has_live_owner: bool,
    owner_is_exact_replay: bool,
) -> bool {
    !has_live_owner || owner_is_exact_replay
}

/// Stable replay classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayCode {
    /// No record exists for this workflow.
    Absent,
    /// Every bound semantic commitment matches.
    ExactReplay,
    /// Workflow matches but at least one commitment differs.
    Conflict,
}

/// Classifies one workflow lookup without creating a second identity.
#[must_use]
pub const fn replay_code(record_exists: bool, commitments_equal: bool) -> ReplayCode {
    if !record_exists {
        ReplayCode::Absent
    } else if commitments_equal {
        ReplayCode::ExactReplay
    } else {
        ReplayCode::Conflict
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn additive_capacity_never_wraps_or_overcommits() {
        let ceiling: u64 = kani::any();
        let committed: u64 = kani::any();
        let active: u64 = kani::any();
        let requested: u64 = kani::any();
        if additive_capacity_available(ceiling, committed, active, requested) {
            let widened = u128::from(committed) + u128::from(active) + u128::from(requested);
            assert!(requested > 0);
            assert!(widened <= u128::from(ceiling));
        }
    }

    #[kani::proof]
    fn exact_replay_never_becomes_absent_or_conflict() {
        assert_eq!(replay_code(true, true), ReplayCode::ExactReplay);
    }

    #[kani::proof]
    fn terminals_never_transition() {
        let gates = TransitionGates {
            core_authorized: kani::any(),
            policy_eligible: kani::any(),
            configuration_matches: kani::any(),
            not_revoked: kani::any(),
            not_expired: kani::any(),
            capacity_available: kani::any(),
            execution_intent_present: kani::any(),
            credential_authorized: kani::any(),
            attempt_present: kani::any(),
            provider_call_entered: kani::any(),
            cancellation_allowed: kani::any(),
            definite_effect: kani::any(),
            definite_non_effect: kani::any(),
            reconciliation_fresh: kani::any(),
            reconciliation_matches: kani::any(),
        };
        let operation = match kani::any::<u8>() % 12 {
            0 => OperationCode::RecordDecision,
            1 => OperationCode::Reserve,
            2 => OperationCode::RecordExecutionIntent,
            3 => OperationCode::AuthorizeCredential,
            4 => OperationCode::StartAttempt,
            5 => OperationCode::MarkProviderCallEntered,
            6 => OperationCode::Commit,
            7 => OperationCode::Release,
            8 => OperationCode::MarkOutcomeUnknown,
            9 => OperationCode::ReconcileEffect,
            10 => OperationCode::ReconcileNonEffect,
            _ => OperationCode::ReconcileInconclusive,
        };
        for state in [
            LifecycleState::Committed,
            LifecycleState::Released,
            LifecycleState::ReconciledCommitted,
            LifecycleState::ReconciledReleased,
        ] {
            assert_eq!(
                transition_code(Some(state), operation, gates),
                KernelCode::Terminal
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: TransitionGates = TransitionGates {
        core_authorized: true,
        policy_eligible: true,
        configuration_matches: true,
        not_revoked: true,
        not_expired: true,
        capacity_available: true,
        execution_intent_present: true,
        credential_authorized: true,
        attempt_present: true,
        provider_call_entered: true,
        cancellation_allowed: true,
        definite_effect: true,
        definite_non_effect: true,
        reconciliation_fresh: true,
        reconciliation_matches: true,
    };

    #[test]
    fn complete_happy_path_is_explicit() {
        let mut current = None;
        for (operation, next) in [
            (
                OperationCode::RecordDecision,
                LifecycleState::DecisionRecorded,
            ),
            (OperationCode::Reserve, LifecycleState::Reserved),
            (
                OperationCode::RecordExecutionIntent,
                LifecycleState::ExecutionIntentRecorded,
            ),
            (
                OperationCode::AuthorizeCredential,
                LifecycleState::ExecutionIntentRecorded,
            ),
            (OperationCode::StartAttempt, LifecycleState::Executing),
            (
                OperationCode::MarkProviderCallEntered,
                LifecycleState::Executing,
            ),
            (OperationCode::Commit, LifecycleState::Committed),
        ] {
            let mut gates = ALL;
            if operation == OperationCode::AuthorizeCredential {
                gates.credential_authorized = false;
            }
            if operation == OperationCode::MarkProviderCallEntered {
                gates.provider_call_entered = false;
            }
            assert_eq!(
                transition_code(current, operation, gates),
                KernelCode::Applied(next)
            );
            current = Some(next);
        }
    }

    #[test]
    fn configuration_mismatch_precedes_every_side_effectful_gate() {
        let mut gates = ALL;
        gates.configuration_matches = false;
        for (state, operation) in [
            (LifecycleState::DecisionRecorded, OperationCode::Reserve),
            (
                LifecycleState::Reserved,
                OperationCode::RecordExecutionIntent,
            ),
            (
                LifecycleState::ExecutionIntentRecorded,
                OperationCode::AuthorizeCredential,
            ),
            (
                LifecycleState::ExecutionIntentRecorded,
                OperationCode::StartAttempt,
            ),
        ] {
            assert_eq!(
                transition_code(Some(state), operation, gates),
                KernelCode::ConfigurationMismatch
            );
        }
    }

    #[test]
    fn unknown_outcome_cannot_release_without_reconciliation() {
        assert_eq!(
            transition_code(
                Some(LifecycleState::OutcomeUnknown),
                OperationCode::Release,
                ALL
            ),
            KernelCode::IllegalTransition
        );
    }
}
