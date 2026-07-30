//! Rich validation and deterministic application around the translated kernel.

use alloc::vec::Vec;

use auths_bounded_policy::{
    CommitmentDigest, ConfigurationMatch, VerifierTime, configuration_match,
};
use sha2::{Digest as _, Sha256};

use crate::model::{can_append_attempt, can_append_event, can_append_observation};
use crate::{
    CapacityEntryV1, DecisionInputV1, DomainReceiptDigest, EffectConclusion, LifecycleEventKind,
    LifecycleEventV1, LifecycleReceiptDigest, LifecycleReceiptEnvelopeV1, LifecycleRecordV1,
    LifecycleState, LifecycleWork, ProviderAttemptV1, ReservationEntryV1, ReservationMode,
    TransitionCommandV1, TransitionContextV1,
    kernel::{
        KernelCode, OperationCode, ReplayCode, TransitionGates, additive_capacity_available,
        exclusive_capacity_available, replay_code, transition_code,
    },
};

/// Whether a successful request changed state or returned an exact replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionDisposition {
    /// One durable mutation must be committed.
    Applied,
    /// The exact existing workflow was returned without mutation.
    ExactReplay,
}

/// A deterministic lifecycle transition result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionResultV1 {
    /// Resulting or replayed record.
    pub record: LifecycleRecordV1,
    /// Whether persistence is required.
    pub disposition: TransitionDisposition,
    /// Bounded work performed by the rich validation layer.
    pub work: LifecycleWork,
}

/// Stable shared lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleFailure {
    /// The workflow identity exists with different commitments.
    Conflict,
    /// The requested edge is not legal.
    IllegalTransition,
    /// Core authorization was absent.
    NotAuthorized,
    /// Pure policy eligibility was absent or incomplete.
    NotEligible,
    /// Required, original, and current executed configurations differ.
    ConfigurationMismatch,
    /// Authority was revoked.
    Revoked,
    /// Authority expired.
    Expired,
    /// Atomic capacity was unavailable or malformed.
    CapacityExceeded,
    /// Exact execution intent was absent.
    ExecutionIntentMissing,
    /// Durable credential authorization was absent.
    CredentialNotAuthorized,
    /// Durable provider attempt was absent.
    AttemptMissing,
    /// Provider call entry was not durable.
    ProviderCallNotEntered,
    /// Effect evidence was absent.
    EffectNotProved,
    /// Non-effect evidence was absent.
    NonEffectNotProved,
    /// Reconciliation evidence was stale.
    ReconciliationStale,
    /// Reconciliation evidence did not bind the exact request.
    ReconciliationMismatch,
    /// A terminal record cannot transition.
    Terminal,
    /// A hard record or history limit was reached.
    LimitExceeded,
    /// Checked revision arithmetic overflowed.
    RevisionOverflow,
}

/// Pure transition failure with stable cause and measured work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionError {
    /// Stable shared cause.
    pub failure: LifecycleFailure,
    /// Bounded work completed before failure.
    pub work: LifecycleWork,
}

/// Applies one total, deterministic lifecycle transition without I/O.
///
/// # Errors
///
/// Returns a stable [`TransitionError`] without exposing a partially mutated
/// record when replay conflicts, a gate fails, an edge is illegal, or a hard
/// limit is reached.
pub fn apply_transition(
    current: Option<&LifecycleRecordV1>,
    command: &TransitionCommandV1,
    context: &TransitionContextV1,
) -> Result<TransitionResultV1, TransitionError> {
    let mut work = inspected_work(current, context);
    if let TransitionCommandV1::RecordDecision(input) = command {
        return record_decision(current, input, context, work);
    }
    let Some(existing) = current else {
        return Err(failure(LifecycleFailure::IllegalTransition, work));
    };
    if !can_append_event(existing) {
        return Err(failure(LifecycleFailure::LimitExceeded, work));
    }
    if matches!(command, TransitionCommandV1::StartAttempt) && !can_append_attempt(existing) {
        return Err(failure(LifecycleFailure::LimitExceeded, work));
    }
    if matches!(command, TransitionCommandV1::Reconcile { .. }) && !can_append_observation(existing)
    {
        return Err(failure(LifecycleFailure::LimitExceeded, work));
    }

    let operation = operation_for(command);
    let gates = gates_for(existing, command, context);
    work.transition_predicates = 15;
    let code = transition_code(Some(existing.state), operation, gates);
    let next_state = match code {
        KernelCode::Applied(state) => state,
        KernelCode::ObservationOnly => existing.state,
        other => return Err(failure(map_kernel_failure(other), work)),
    };

    let mut next = existing.clone();
    let from = next.state;
    let trigger = trigger_digest(command, &next);
    let domain_receipt = domain_receipt(command);
    apply_payload(&mut next, command, next_state, context.verifier_time)?;
    append_transition(
        &mut next,
        from,
        next_state,
        trigger,
        domain_receipt,
        context,
    )?;
    Ok(TransitionResultV1 {
        record: next,
        disposition: TransitionDisposition::Applied,
        work,
    })
}

fn record_decision(
    current: Option<&LifecycleRecordV1>,
    input: &DecisionInputV1,
    context: &TransitionContextV1,
    mut work: LifecycleWork,
) -> Result<TransitionResultV1, TransitionError> {
    if let Some(existing) = current {
        if !configuration_matches(input, context) {
            return Err(failure(LifecycleFailure::ConfigurationMismatch, work));
        }
        return match replay_code(true, existing.input == *input) {
            ReplayCode::ExactReplay => Ok(TransitionResultV1 {
                record: existing.clone(),
                disposition: TransitionDisposition::ExactReplay,
                work,
            }),
            ReplayCode::Conflict => Err(failure(LifecycleFailure::Conflict, work)),
            ReplayCode::Absent => unreachable!("record exists"),
        };
    }
    if !decision_bindings_complete(input) {
        return Err(failure(LifecycleFailure::NotEligible, work));
    }
    let gates = TransitionGates {
        core_authorized: input.core_authorized,
        policy_eligible: true,
        configuration_matches: configuration_matches(input, context),
        not_revoked: !context.revocation.revoked,
        not_expired: context.verifier_time <= input.expires_at,
        capacity_available: true,
        execution_intent_present: false,
        credential_authorized: false,
        attempt_present: false,
        provider_call_entered: false,
        cancellation_allowed: false,
        definite_effect: false,
        definite_non_effect: false,
        reconciliation_fresh: false,
        reconciliation_matches: false,
    };
    work.transition_predicates = 5;
    match transition_code(None, OperationCode::RecordDecision, gates) {
        KernelCode::Applied(LifecycleState::DecisionRecorded) => {}
        other => return Err(failure(map_kernel_failure(other), work)),
    }

    let now = context.verifier_time;
    let mut record = LifecycleRecordV1 {
        input: input.clone(),
        state: LifecycleState::DecisionRecorded,
        revision: 0,
        created_at: now,
        updated_at: now,
        reservation_entries: Vec::new(),
        execution_intent: None,
        credential_authorized: false,
        attempts: Vec::new(),
        observations: Vec::new(),
        terminal_result: None,
        events: Vec::new(),
        receipts: Vec::new(),
    };
    let trigger = CommitmentDigest::new(*input.decision_receipt_digest.bytes());
    append_transition(
        &mut record,
        None,
        LifecycleState::DecisionRecorded,
        trigger,
        Some(input.domain_decision_receipt_digest),
        context,
    )?;
    Ok(TransitionResultV1 {
        record,
        disposition: TransitionDisposition::Applied,
        work,
    })
}

fn inspected_work(
    current: Option<&LifecycleRecordV1>,
    context: &TransitionContextV1,
) -> LifecycleWork {
    LifecycleWork {
        reservation_intents: current.map_or(0, |record| {
            bounded_count(record.input.reservations.entries().len())
        }),
        capacity_entries: bounded_count(context.capacity.entries().len()),
        events: current.map_or(0, |record| bounded_count(record.events.len())),
        attempts: current.map_or(0, |record| bounded_count(record.attempts.len())),
        observations: current.map_or(0, |record| bounded_count(record.observations.len())),
        transition_predicates: 0,
    }
}

fn bounded_count(value: usize) -> u8 {
    u8::try_from(value).unwrap_or(u8::MAX)
}

fn decision_bindings_complete(input: &DecisionInputV1) -> bool {
    let outputs = input.outputs.reservation_intents();
    let requests = input.reservations.entries();
    outputs.len() == requests.len()
        && requests.iter().all(|request| {
            outputs.iter().any(|intent| {
                intent.intent_id() == request.intent_id()
                    && intent.canonical_digest() == request.intent_digest()
                    && intent.scope_digest() == request.scope_digest()
                    && intent.window_digest() == request.window_digest()
            })
        })
}

fn configuration_matches(input: &DecisionInputV1, context: &TransitionContextV1) -> bool {
    input.commitments.executed_configuration() == &context.executed_configuration
        && configuration_match(
            input.commitments.required_configuration(),
            &context.executed_configuration,
        ) == ConfigurationMatch::Match
}

fn gates_for(
    record: &LifecycleRecordV1,
    command: &TransitionCommandV1,
    context: &TransitionContextV1,
) -> TransitionGates {
    let conclusion = command_conclusion(command);
    let observation = match command {
        TransitionCommandV1::Reconcile { observation, .. } => Some(observation),
        _ => None,
    };
    TransitionGates {
        core_authorized: record.input.core_authorized,
        policy_eligible: true,
        configuration_matches: configuration_matches(&record.input, context),
        not_revoked: !context.revocation.revoked,
        not_expired: context.verifier_time <= record.input.expires_at,
        capacity_available: capacity_available(record, context),
        execution_intent_present: record.execution_intent.is_some()
            || matches!(command, TransitionCommandV1::RecordExecutionIntent(_)),
        credential_authorized: record.credential_authorized,
        attempt_present: !record.attempts.is_empty()
            || matches!(command, TransitionCommandV1::StartAttempt),
        provider_call_entered: record
            .attempts
            .last()
            .is_some_and(|attempt| attempt.call_entered),
        cancellation_allowed: record.input.cancellation
            == crate::CancellationDisposition::BeforeAttemptAllowed,
        definite_effect: conclusion == Some(EffectConclusion::Effect),
        definite_non_effect: conclusion == Some(EffectConclusion::NonEffect),
        reconciliation_fresh: observation.is_some_and(|value| {
            value.observed_at <= context.verifier_time && context.verifier_time <= value.fresh_until
        }),
        reconciliation_matches: observation.is_some_and(|value| {
            record.execution_intent.as_ref().is_some_and(|intent| {
                value.provider_request_digest == intent.provider_request_digest()
            })
        }),
    }
}

fn capacity_available(record: &LifecycleRecordV1, context: &TransitionContextV1) -> bool {
    record.input.reservations.entries().iter().all(|request| {
        context
            .capacity
            .entries()
            .iter()
            .any(|entry| match (request.mode(), entry) {
                (
                    ReservationMode::Additive { unit, amount },
                    CapacityEntryV1::Additive {
                        scope_digest,
                        window_digest,
                        unit: capacity_unit,
                        ceiling,
                        committed,
                        active,
                    },
                ) => {
                    request.scope_digest() == *scope_digest
                        && request.window_digest() == *window_digest
                        && unit == capacity_unit
                        && additive_capacity_available(*ceiling, *committed, *active, *amount)
                }
                (
                    ReservationMode::Exclusive,
                    CapacityEntryV1::Exclusive {
                        scope_digest,
                        window_digest,
                        live_owner,
                    },
                ) => {
                    request.scope_digest() == *scope_digest
                        && request.window_digest() == *window_digest
                        && exclusive_capacity_available(
                            live_owner.is_some(),
                            live_owner.as_ref() == Some(request.reservation_id()),
                        )
                }
                _ => false,
            })
    })
}

fn operation_for(command: &TransitionCommandV1) -> OperationCode {
    match command {
        TransitionCommandV1::RecordDecision(_) => OperationCode::RecordDecision,
        TransitionCommandV1::Reserve => OperationCode::Reserve,
        TransitionCommandV1::RecordExecutionIntent(_) => OperationCode::RecordExecutionIntent,
        TransitionCommandV1::AuthorizeCredential => OperationCode::AuthorizeCredential,
        TransitionCommandV1::StartAttempt => OperationCode::StartAttempt,
        TransitionCommandV1::MarkProviderCallEntered => OperationCode::MarkProviderCallEntered,
        TransitionCommandV1::Commit { .. } => OperationCode::Commit,
        TransitionCommandV1::Release { .. } => OperationCode::Release,
        TransitionCommandV1::MarkOutcomeUnknown { .. } => OperationCode::MarkOutcomeUnknown,
        TransitionCommandV1::Reconcile { observation, .. } => match observation.conclusion {
            EffectConclusion::Effect => OperationCode::ReconcileEffect,
            EffectConclusion::NonEffect => OperationCode::ReconcileNonEffect,
            EffectConclusion::Unknown | EffectConclusion::Inconclusive => {
                OperationCode::ReconcileInconclusive
            }
        },
    }
}

fn command_conclusion(command: &TransitionCommandV1) -> Option<EffectConclusion> {
    match command {
        TransitionCommandV1::Commit { .. } => Some(EffectConclusion::Effect),
        TransitionCommandV1::Release { conclusion, .. } => Some(*conclusion),
        TransitionCommandV1::MarkOutcomeUnknown { .. } => Some(EffectConclusion::Unknown),
        TransitionCommandV1::Reconcile { observation, .. } => Some(observation.conclusion),
        _ => None,
    }
}

fn apply_payload(
    record: &mut LifecycleRecordV1,
    command: &TransitionCommandV1,
    next_state: LifecycleState,
    now: VerifierTime,
) -> Result<(), TransitionError> {
    match command {
        TransitionCommandV1::Reserve => {
            record.reservation_entries = record
                .input
                .reservations
                .entries()
                .iter()
                .cloned()
                .map(ReservationEntryV1::reserved)
                .collect();
        }
        TransitionCommandV1::RecordExecutionIntent(intent) => {
            record.execution_intent = Some(intent.clone());
        }
        TransitionCommandV1::AuthorizeCredential => {
            record.credential_authorized = true;
        }
        TransitionCommandV1::StartAttempt => {
            let Some(intent) = record.execution_intent.as_ref() else {
                return Err(failure(
                    LifecycleFailure::ExecutionIntentMissing,
                    LifecycleWork::default(),
                ));
            };
            let ordinal = u8::try_from(record.attempts.len() + 1)
                .ok()
                .and_then(|value| crate::AttemptOrdinal::new(value).ok())
                .ok_or_else(|| {
                    failure(LifecycleFailure::LimitExceeded, LifecycleWork::default())
                })?;
            record.attempts.push(ProviderAttemptV1 {
                ordinal,
                started_at: now,
                provider_request_digest: intent.provider_request_digest(),
                provider_condition_digest: intent.provider_condition_digest(),
                provider_contract_id: intent.provider_contract_id().clone(),
                call_entered: false,
            });
            record.credential_authorized = false;
        }
        TransitionCommandV1::MarkProviderCallEntered => {
            let attempt = record.attempts.last_mut().ok_or_else(|| {
                failure(LifecycleFailure::AttemptMissing, LifecycleWork::default())
            })?;
            attempt.call_entered = true;
        }
        TransitionCommandV1::Commit { result_digest, .. } => {
            for reservation in &mut record.reservation_entries {
                reservation.mark_committed();
            }
            record.terminal_result = Some(*result_digest);
        }
        TransitionCommandV1::Release { result_digest, .. } => {
            for reservation in &mut record.reservation_entries {
                reservation.mark_released();
            }
            record.terminal_result = Some(*result_digest);
        }
        TransitionCommandV1::MarkOutcomeUnknown { .. } | TransitionCommandV1::RecordDecision(_) => {
        }
        TransitionCommandV1::Reconcile { observation, .. } => {
            record.observations.push(observation.clone());
            match observation.conclusion {
                EffectConclusion::Effect => {
                    for reservation in &mut record.reservation_entries {
                        reservation.mark_committed();
                    }
                }
                EffectConclusion::NonEffect => {
                    for reservation in &mut record.reservation_entries {
                        reservation.mark_released();
                    }
                }
                EffectConclusion::Unknown | EffectConclusion::Inconclusive => {}
            }
        }
    }
    record.state = next_state;
    Ok(())
}

fn append_transition(
    record: &mut LifecycleRecordV1,
    from: impl Into<Option<LifecycleState>>,
    to: LifecycleState,
    trigger: CommitmentDigest,
    domain_receipt: Option<DomainReceiptDigest>,
    context: &TransitionContextV1,
) -> Result<(), TransitionError> {
    let revision = record
        .revision
        .checked_add(1)
        .ok_or_else(|| failure(LifecycleFailure::RevisionOverflow, LifecycleWork::default()))?;
    let from = from.into();
    let receipt = make_receipt(
        record,
        revision,
        from,
        to,
        trigger,
        domain_receipt,
        context.verifier_time,
    );
    record.revision = revision;
    record.updated_at = context.verifier_time;
    record.events.push(LifecycleEventV1 {
        kind: event_kind_for(from, to),
        revision,
        verifier_time: context.verifier_time,
        trigger_digest: trigger,
    });
    record.receipts.push(receipt);
    Ok(())
}

fn make_receipt(
    record: &LifecycleRecordV1,
    revision: u64,
    from: Option<LifecycleState>,
    to: LifecycleState,
    trigger: CommitmentDigest,
    domain_receipt: Option<DomainReceiptDigest>,
    verifier_time: VerifierTime,
) -> LifecycleReceiptEnvelopeV1 {
    let previous = record.receipts.last().map(|receipt| receipt.receipt_digest);
    let required = record.input.commitments.required_configuration().clone();
    let executed = record.input.commitments.executed_configuration().clone();
    let mut hasher = Sha256::new();
    hasher.update(b"AUTHS-LIFECYCLE-RECEIPT\x00\x01");
    hasher.update(record.input.lifecycle_id.as_str().as_bytes());
    hasher.update(record.input.execution_id.as_str().as_bytes());
    hasher.update(revision.to_be_bytes());
    hasher.update([from.map_or(u8::MAX, state_code), state_code(to)]);
    hasher.update(trigger.as_bytes());
    hasher.update(verifier_time.unix_seconds().to_be_bytes());
    hash_configuration(&mut hasher, &required);
    hash_configuration(&mut hasher, &executed);
    hasher.update(record.input.implementation_id.as_str().as_bytes());
    if let Some(previous) = previous {
        hasher.update([1]);
        hasher.update(previous.bytes());
    } else {
        hasher.update([0]);
    }
    if let Some(domain_receipt) = domain_receipt {
        hasher.update([1]);
        hasher.update(domain_receipt.bytes());
    } else {
        hasher.update([0]);
    }
    LifecycleReceiptEnvelopeV1 {
        revision,
        previous,
        from,
        to,
        trigger_digest: trigger,
        verifier_time,
        required_configuration: required,
        executed_configuration: executed,
        implementation_id: record.input.implementation_id.clone(),
        domain_receipt_digest: domain_receipt,
        receipt_digest: LifecycleReceiptDigest::new(hasher.finalize().into()),
    }
}

fn hash_configuration(
    hasher: &mut Sha256,
    value: &auths_bounded_policy::ConfigurationCommitmentV1,
) {
    hasher.update(value.semantic_id().as_str().as_bytes());
    hasher.update(value.canonicalization_id().as_str().as_bytes());
    hasher.update(value.configuration_digest().as_bytes());
    if let Some(implementation) = value.implementation_id() {
        hasher.update([1]);
        hasher.update(implementation.as_str().as_bytes());
    } else {
        hasher.update([0]);
    }
}

fn trigger_digest(command: &TransitionCommandV1, record: &LifecycleRecordV1) -> CommitmentDigest {
    match command {
        TransitionCommandV1::RecordDecision(input) => {
            CommitmentDigest::new(*input.decision_receipt_digest.bytes())
        }
        TransitionCommandV1::Reserve => {
            CommitmentDigest::new(*record.input.reservations.commitment().bytes())
        }
        TransitionCommandV1::RecordExecutionIntent(intent) => {
            CommitmentDigest::new(*intent.intent_digest().bytes())
        }
        TransitionCommandV1::AuthorizeCredential => record
            .execution_intent
            .as_ref()
            .map_or(CommitmentDigest::new([0; 32]), |intent| {
                CommitmentDigest::new(*intent.intent_digest().bytes())
            }),
        TransitionCommandV1::StartAttempt | TransitionCommandV1::MarkProviderCallEntered => record
            .execution_intent
            .as_ref()
            .map_or(CommitmentDigest::new([0; 32]), |intent| {
                CommitmentDigest::new(*intent.provider_request_digest().bytes())
            }),
        TransitionCommandV1::Commit { result_digest, .. }
        | TransitionCommandV1::Release { result_digest, .. } => {
            CommitmentDigest::new(*result_digest.bytes())
        }
        TransitionCommandV1::MarkOutcomeUnknown {
            domain_receipt_digest,
        } => CommitmentDigest::new(*domain_receipt_digest.bytes()),
        TransitionCommandV1::Reconcile { observation, .. } => {
            CommitmentDigest::new(*observation.observation_digest.bytes())
        }
    }
}

fn domain_receipt(command: &TransitionCommandV1) -> Option<DomainReceiptDigest> {
    match command {
        TransitionCommandV1::Commit {
            domain_receipt_digest,
            ..
        }
        | TransitionCommandV1::Release {
            domain_receipt_digest,
            ..
        }
        | TransitionCommandV1::MarkOutcomeUnknown {
            domain_receipt_digest,
        }
        | TransitionCommandV1::Reconcile {
            domain_receipt_digest,
            ..
        } => Some(*domain_receipt_digest),
        _ => None,
    }
}

const fn state_code(state: LifecycleState) -> u8 {
    match state {
        LifecycleState::DecisionRecorded => 0,
        LifecycleState::Reserved => 1,
        LifecycleState::ExecutionIntentRecorded => 2,
        LifecycleState::Executing => 3,
        LifecycleState::Committed => 4,
        LifecycleState::Released => 5,
        LifecycleState::OutcomeUnknown => 6,
        LifecycleState::ReconciledCommitted => 7,
        LifecycleState::ReconciledReleased => 8,
    }
}

fn event_kind_for(from: Option<LifecycleState>, to: LifecycleState) -> LifecycleEventKind {
    match (from, to) {
        (None, LifecycleState::DecisionRecorded) => LifecycleEventKind::DecisionPersisted,
        (_, LifecycleState::Reserved) => LifecycleEventKind::ReservationPersisted,
        (Some(LifecycleState::Reserved), LifecycleState::ExecutionIntentRecorded) => {
            LifecycleEventKind::ExecutionIntentPersisted
        }
        (
            Some(LifecycleState::ExecutionIntentRecorded),
            LifecycleState::ExecutionIntentRecorded,
        ) => LifecycleEventKind::CredentialAuthorized,
        (Some(LifecycleState::ExecutionIntentRecorded), LifecycleState::Executing) => {
            LifecycleEventKind::AttemptPersisted
        }
        (Some(LifecycleState::Executing), LifecycleState::Executing) => {
            LifecycleEventKind::ProviderCallEntered
        }
        (_, LifecycleState::Committed | LifecycleState::Released) => {
            LifecycleEventKind::ProviderResultPersisted
        }
        (_, LifecycleState::OutcomeUnknown) => LifecycleEventKind::OutcomeUnknownPersisted,
        (_, LifecycleState::ReconciledCommitted | LifecycleState::ReconciledReleased) => {
            LifecycleEventKind::ReconciliationPersisted
        }
        _ => LifecycleEventKind::ReconciliationObserved,
    }
}

const fn map_kernel_failure(code: KernelCode) -> LifecycleFailure {
    match code {
        KernelCode::Terminal => LifecycleFailure::Terminal,
        KernelCode::IllegalTransition | KernelCode::ObservationOnly | KernelCode::Applied(_) => {
            LifecycleFailure::IllegalTransition
        }
        KernelCode::NotAuthorized => LifecycleFailure::NotAuthorized,
        KernelCode::NotEligible => LifecycleFailure::NotEligible,
        KernelCode::ConfigurationMismatch => LifecycleFailure::ConfigurationMismatch,
        KernelCode::Revoked => LifecycleFailure::Revoked,
        KernelCode::Expired => LifecycleFailure::Expired,
        KernelCode::CapacityExceeded => LifecycleFailure::CapacityExceeded,
        KernelCode::ExecutionIntentMissing => LifecycleFailure::ExecutionIntentMissing,
        KernelCode::CredentialNotAuthorized => LifecycleFailure::CredentialNotAuthorized,
        KernelCode::AttemptMissing => LifecycleFailure::AttemptMissing,
        KernelCode::ProviderCallNotEntered => LifecycleFailure::ProviderCallNotEntered,
        KernelCode::EffectNotProved => LifecycleFailure::EffectNotProved,
        KernelCode::NonEffectNotProved => LifecycleFailure::NonEffectNotProved,
        KernelCode::ReconciliationStale => LifecycleFailure::ReconciliationStale,
        KernelCode::ReconciliationMismatch => LifecycleFailure::ReconciliationMismatch,
    }
}

const fn failure(failure: LifecycleFailure, work: LifecycleWork) -> TransitionError {
    TransitionError { failure, work }
}
