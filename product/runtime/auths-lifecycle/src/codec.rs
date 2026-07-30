//! Canonical, versioned lifecycle-record persistence bytes.
//!
//! The public semantic carriers intentionally do not implement generic
//! serialization. This module maps them through a private closed wire DTO,
//! validates semantic reconstruction, and rejects any byte sequence that does
//! not round-trip byte-for-byte.

use alloc::{string::String, vec::Vec};

use auths_bounded_policy::{
    BoundedOutputs, CanonicalizationId, CommitmentDigest, ConfigurationCommitmentV1,
    ConfigurationSemanticId, EvaluationCommitmentsV1, EvaluatorSemanticId, EvidenceSourceId,
    ImplementationId, IntentId, ObligationClass, ObligationCommitmentV1, ObligationId,
    PolicyCommitmentV1, PolicyTypeId, ProfileId, ReservationIntentCommitmentV1, ReservationKind,
    SchemaId, UnitId, VerifierTime,
};
use serde::{Deserialize, Serialize};

use crate::{
    AttemptOrdinal, CancellationDisposition, DecisionInputV1, DecisionReceiptDigest, DomainId,
    DomainReceiptDigest, EffectConclusion, ExecutionId, ExecutionIntentV1, ExecutorAudienceId,
    LifecycleEventKind, LifecycleEventV1, LifecycleId, LifecycleReceiptDigest,
    LifecycleReceiptEnvelopeV1, LifecycleRecordV1, LifecycleState, MAX_LIFECYCLE_RECORD_BYTES,
    ObservationDigest, ProviderAttemptV1, ProviderConditionDigest, ProviderContractId,
    ProviderRequestDigest, ProviderResultDigest, ProviderRetryClass, ReconciliationId,
    ReconciliationObservationV1, ReservationAlgebraId, ReservationEntryV1, ReservationSetV1,
    WorkflowId, transition::validate_record_integrity,
};

const WIRE_VERSION: u8 = 1;

/// Canonical lifecycle-record codec failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// Input exceeded the fixed V1 record ceiling.
    TooLarge,
    /// Bytes were truncated, malformed, or contained trailing data.
    Malformed,
    /// The record version is not supported.
    UnsupportedVersion,
    /// Decoded bytes did not use the one canonical representation.
    NonCanonical,
    /// The wire values could not reconstruct a valid semantic record.
    InvalidSemantics,
}

/// Encodes one validated record into canonical V1 bytes.
///
/// # Errors
///
/// Returns [`CodecError`] if the record is internally inconsistent, cannot be
/// reconstructed exactly, or exceeds the 256 KiB V1 ceiling.
pub fn encode_record(record: &LifecycleRecordV1) -> Result<Vec<u8>, CodecError> {
    if !validate_record_integrity(record) {
        return Err(CodecError::InvalidSemantics);
    }
    let bytes = encode_unchecked(record)?;
    let reconstructed = decode_wire(&bytes)?;
    if reconstructed != *record {
        return Err(CodecError::InvalidSemantics);
    }
    Ok(bytes)
}

/// Decodes only canonical, semantically valid V1 lifecycle bytes.
///
/// # Errors
///
/// Returns [`CodecError`] for oversized, malformed, unsupported,
/// non-canonical, or semantically inconsistent input.
pub fn decode_record(bytes: &[u8]) -> Result<LifecycleRecordV1, CodecError> {
    if bytes.len() > MAX_LIFECYCLE_RECORD_BYTES {
        return Err(CodecError::TooLarge);
    }
    let record = decode_wire(bytes)?;
    if !validate_record_integrity(&record) {
        return Err(CodecError::InvalidSemantics);
    }
    if encode_unchecked(&record)?.as_slice() != bytes {
        return Err(CodecError::NonCanonical);
    }
    Ok(record)
}

fn encode_unchecked(record: &LifecycleRecordV1) -> Result<Vec<u8>, CodecError> {
    let wire = WireEnvelope {
        version: WIRE_VERSION,
        record: WireRecord::from(record),
    };
    let bytes = postcard::to_allocvec(&wire).map_err(|_| CodecError::Malformed)?;
    if bytes.len() > MAX_LIFECYCLE_RECORD_BYTES {
        return Err(CodecError::TooLarge);
    }
    Ok(bytes)
}

fn decode_wire(bytes: &[u8]) -> Result<LifecycleRecordV1, CodecError> {
    let wire: WireEnvelope = postcard::from_bytes(bytes).map_err(|_| CodecError::Malformed)?;
    if wire.version != WIRE_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }
    LifecycleRecordV1::try_from(wire.record)
}

#[derive(Serialize, Deserialize)]
struct WireEnvelope {
    version: u8,
    record: WireRecord,
}

#[derive(Serialize, Deserialize)]
struct WireRecord {
    input: WireDecision,
    state: u8,
    revision: u64,
    created_at: u64,
    updated_at: u64,
    reservation_statuses: Vec<(bool, bool)>,
    execution_intent: Option<WireExecutionIntent>,
    credential_authorized: bool,
    attempts: Vec<WireAttempt>,
    observations: Vec<WireObservation>,
    terminal_result: Option<[u8; 32]>,
    events: Vec<WireEvent>,
    receipts: Vec<WireReceipt>,
}

#[derive(Serialize, Deserialize)]
struct WireDecision {
    core_authorized: bool,
    core_authorization_digest: [u8; 32],
    workflow_id: String,
    lifecycle_id: String,
    execution_id: String,
    domain_id: String,
    executor_audience: String,
    reservation_algebra_id: String,
    commitments: WireCommitments,
    outputs: WireOutputs,
    decision_receipt_digest: [u8; 32],
    domain_decision_receipt_digest: [u8; 32],
    implementation_id: String,
    implementation_build_digest: [u8; 32],
    expires_at: u64,
    cancellation: u8,
}

#[derive(Serialize, Deserialize)]
struct WireCommitments {
    profile_id: String,
    exact_action_digest: [u8; 32],
    policy: WirePolicy,
    evidence_schema_id: String,
    evidence_digest: [u8; 32],
    evidence_source_id: String,
    evidence_observed_at: u64,
    state_snapshot_schema_id: String,
    state_snapshot_digest: [u8; 32],
    verifier_time: u64,
    required_configuration: WireConfiguration,
    executed_configuration: WireConfiguration,
}

#[derive(Serialize, Deserialize)]
struct WirePolicy {
    policy_type: String,
    policy_version: u16,
    canonicalization_id: String,
    policy_digest: [u8; 32],
    evaluator_semantic_id: String,
}

#[derive(Serialize, Deserialize)]
struct WireConfiguration {
    semantic_id: String,
    canonicalization_id: String,
    configuration_digest: [u8; 32],
    implementation_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct WireOutputs {
    reservations: Vec<WireReservationIntent>,
    obligations: Vec<WireObligation>,
    reservation_intents_commitment: [u8; 32],
    obligations_commitment: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct WireReservationIntent {
    schema_id: String,
    intent_id: String,
    scope_digest: [u8; 32],
    kind: u8,
    unit: Option<String>,
    amount: Option<u64>,
    window_digest: Option<[u8; 32]>,
    action_digest: [u8; 32],
    policy_digest: [u8; 32],
    evidence_digest: [u8; 32],
    canonical_digest: [u8; 32],
    canonical_bytes: u32,
}

#[derive(Serialize, Deserialize)]
struct WireObligation {
    schema_id: String,
    obligation_id: String,
    class: u8,
    payload_digest: [u8; 32],
    canonical_bytes: u32,
}

#[derive(Serialize, Deserialize)]
struct WireExecutionIntent {
    verified_command_digest: [u8; 32],
    provider_request_digest: [u8; 32],
    provider_condition_digest: [u8; 32],
    provider_contract_id: String,
    retry_class: u8,
}

#[derive(Serialize, Deserialize)]
struct WireAttempt {
    ordinal: u8,
    started_at: u64,
    provider_request_digest: [u8; 32],
    provider_condition_digest: [u8; 32],
    provider_contract_id: String,
    call_entered: bool,
}

#[derive(Serialize, Deserialize)]
struct WireObservation {
    reconciliation_id: String,
    source_id: String,
    observed_at: u64,
    fresh_until: u64,
    observation_digest: [u8; 32],
    conclusion: u8,
    provider_request_digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct WireEvent {
    kind: u8,
    revision: u64,
    verifier_time: u64,
    trigger_digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct WireReceipt {
    revision: u64,
    previous: Option<[u8; 32]>,
    from: Option<u8>,
    to: u8,
    trigger_digest: [u8; 32],
    verifier_time: u64,
    required_configuration: WireConfiguration,
    executed_configuration: WireConfiguration,
    implementation_id: String,
    domain_receipt_digest: Option<[u8; 32]>,
    receipt_digest: [u8; 32],
}

impl From<&LifecycleRecordV1> for WireRecord {
    fn from(record: &LifecycleRecordV1) -> Self {
        Self {
            input: WireDecision::from(&record.input),
            state: state_code(record.state),
            revision: record.revision,
            created_at: record.created_at.unix_seconds(),
            updated_at: record.updated_at.unix_seconds(),
            reservation_statuses: record
                .reservation_entries
                .iter()
                .map(|entry| (entry.is_committed(), entry.is_released()))
                .collect(),
            execution_intent: record
                .execution_intent
                .as_ref()
                .map(WireExecutionIntent::from),
            credential_authorized: record.credential_authorized,
            attempts: record.attempts.iter().map(WireAttempt::from).collect(),
            observations: record
                .observations
                .iter()
                .map(WireObservation::from)
                .collect(),
            terminal_result: record.terminal_result.map(|digest| *digest.bytes()),
            events: record.events.iter().map(WireEvent::from).collect(),
            receipts: record.receipts.iter().map(WireReceipt::from).collect(),
        }
    }
}

impl From<&DecisionInputV1> for WireDecision {
    fn from(input: &DecisionInputV1) -> Self {
        Self {
            core_authorized: input.core_authorized,
            core_authorization_digest: *input.core_authorization_digest.as_bytes(),
            workflow_id: input.workflow_id.as_str().into(),
            lifecycle_id: input.lifecycle_id.as_str().into(),
            execution_id: input.execution_id.as_str().into(),
            domain_id: input.domain_id.as_str().into(),
            executor_audience: input.executor_audience.as_str().into(),
            reservation_algebra_id: input.reservation_algebra_id.as_str().into(),
            commitments: WireCommitments::from(&input.commitments),
            outputs: WireOutputs::from(&input.outputs),
            decision_receipt_digest: *input.decision_receipt_digest.bytes(),
            domain_decision_receipt_digest: *input.domain_decision_receipt_digest.bytes(),
            implementation_id: input.implementation_id.as_str().into(),
            implementation_build_digest: *input.implementation_build_digest.as_bytes(),
            expires_at: input.expires_at.unix_seconds(),
            cancellation: cancellation_code(input.cancellation),
        }
    }
}

impl From<&EvaluationCommitmentsV1> for WireCommitments {
    fn from(value: &EvaluationCommitmentsV1) -> Self {
        Self {
            profile_id: value.profile_id().as_str().into(),
            exact_action_digest: *value.exact_action_digest().as_bytes(),
            policy: WirePolicy::from(value.policy_commitment()),
            evidence_schema_id: value.evidence_schema_id().as_str().into(),
            evidence_digest: *value.evidence_digest().as_bytes(),
            evidence_source_id: value.evidence_source_id().as_str().into(),
            evidence_observed_at: value.evidence_observed_at().unix_seconds(),
            state_snapshot_schema_id: value.state_snapshot_schema_id().as_str().into(),
            state_snapshot_digest: *value.state_snapshot_digest().as_bytes(),
            verifier_time: value.verifier_time().unix_seconds(),
            required_configuration: WireConfiguration::from(value.required_configuration()),
            executed_configuration: WireConfiguration::from(value.executed_configuration()),
        }
    }
}

impl From<&PolicyCommitmentV1> for WirePolicy {
    fn from(value: &PolicyCommitmentV1) -> Self {
        Self {
            policy_type: value.policy_type().as_str().into(),
            policy_version: value.policy_version(),
            canonicalization_id: value.canonicalization_id().as_str().into(),
            policy_digest: *value.policy_digest().as_bytes(),
            evaluator_semantic_id: value.evaluator_semantic_id().as_str().into(),
        }
    }
}

impl From<&ConfigurationCommitmentV1> for WireConfiguration {
    fn from(value: &ConfigurationCommitmentV1) -> Self {
        Self {
            semantic_id: value.semantic_id().as_str().into(),
            canonicalization_id: value.canonicalization_id().as_str().into(),
            configuration_digest: *value.configuration_digest().as_bytes(),
            implementation_id: value.implementation_id().map(|id| id.as_str().into()),
        }
    }
}

impl From<&BoundedOutputs> for WireOutputs {
    fn from(value: &BoundedOutputs) -> Self {
        Self {
            reservations: value
                .reservation_intents()
                .iter()
                .map(WireReservationIntent::from)
                .collect(),
            obligations: value
                .obligations()
                .iter()
                .map(WireObligation::from)
                .collect(),
            reservation_intents_commitment: *value.reservation_intents_commitment().as_bytes(),
            obligations_commitment: *value.obligations_commitment().as_bytes(),
        }
    }
}

impl From<&ReservationIntentCommitmentV1> for WireReservationIntent {
    fn from(value: &ReservationIntentCommitmentV1) -> Self {
        let (kind, unit, amount) = match value.kind() {
            ReservationKind::Additive { unit, amount } => {
                (0, Some(unit.as_str().into()), Some(*amount))
            }
            ReservationKind::Exclusive => (1, None, None),
        };
        Self {
            schema_id: value.schema_id().as_str().into(),
            intent_id: value.intent_id().as_str().into(),
            scope_digest: *value.scope_digest().as_bytes(),
            kind,
            unit,
            amount,
            window_digest: value.window_digest().map(|digest| *digest.as_bytes()),
            action_digest: *value.action_digest().as_bytes(),
            policy_digest: *value.policy_digest().as_bytes(),
            evidence_digest: *value.evidence_digest().as_bytes(),
            canonical_digest: *value.canonical_digest().as_bytes(),
            canonical_bytes: value.canonical_bytes(),
        }
    }
}

impl From<&ObligationCommitmentV1> for WireObligation {
    fn from(value: &ObligationCommitmentV1) -> Self {
        Self {
            schema_id: value.schema_id().as_str().into(),
            obligation_id: value.obligation_id().as_str().into(),
            class: obligation_code(value.class()),
            payload_digest: *value.payload_digest().as_bytes(),
            canonical_bytes: value.canonical_bytes(),
        }
    }
}

impl From<&ExecutionIntentV1> for WireExecutionIntent {
    fn from(value: &ExecutionIntentV1) -> Self {
        Self {
            verified_command_digest: *value.verified_command_digest().as_bytes(),
            provider_request_digest: *value.provider_request_digest().bytes(),
            provider_condition_digest: *value.provider_condition_digest().bytes(),
            provider_contract_id: value.provider_contract_id().as_str().into(),
            retry_class: retry_code(value.retry_class()),
        }
    }
}

impl From<&ProviderAttemptV1> for WireAttempt {
    fn from(value: &ProviderAttemptV1) -> Self {
        Self {
            ordinal: value.ordinal.get(),
            started_at: value.started_at.unix_seconds(),
            provider_request_digest: *value.provider_request_digest.bytes(),
            provider_condition_digest: *value.provider_condition_digest.bytes(),
            provider_contract_id: value.provider_contract_id.as_str().into(),
            call_entered: value.call_entered,
        }
    }
}

impl From<&ReconciliationObservationV1> for WireObservation {
    fn from(value: &ReconciliationObservationV1) -> Self {
        Self {
            reconciliation_id: value.reconciliation_id.as_str().into(),
            source_id: value.source_id.as_str().into(),
            observed_at: value.observed_at.unix_seconds(),
            fresh_until: value.fresh_until.unix_seconds(),
            observation_digest: *value.observation_digest.bytes(),
            conclusion: conclusion_code(value.conclusion),
            provider_request_digest: *value.provider_request_digest.bytes(),
        }
    }
}

impl From<&LifecycleEventV1> for WireEvent {
    fn from(value: &LifecycleEventV1) -> Self {
        Self {
            kind: event_code(value.kind),
            revision: value.revision,
            verifier_time: value.verifier_time.unix_seconds(),
            trigger_digest: *value.trigger_digest.as_bytes(),
        }
    }
}

impl From<&LifecycleReceiptEnvelopeV1> for WireReceipt {
    fn from(value: &LifecycleReceiptEnvelopeV1) -> Self {
        Self {
            revision: value.revision,
            previous: value.previous.map(|digest| *digest.bytes()),
            from: value.from.map(state_code),
            to: state_code(value.to),
            trigger_digest: *value.trigger_digest.as_bytes(),
            verifier_time: value.verifier_time.unix_seconds(),
            required_configuration: WireConfiguration::from(&value.required_configuration),
            executed_configuration: WireConfiguration::from(&value.executed_configuration),
            implementation_id: value.implementation_id.as_str().into(),
            domain_receipt_digest: value.domain_receipt_digest.map(|digest| *digest.bytes()),
            receipt_digest: *value.receipt_digest.bytes(),
        }
    }
}

impl TryFrom<WireRecord> for LifecycleRecordV1 {
    type Error = CodecError;

    fn try_from(wire: WireRecord) -> Result<Self, Self::Error> {
        let input = DecisionInputV1::try_from(wire.input)?;
        let statuses = wire.reservation_statuses;
        let state = parse_state(wire.state)?;
        let expected_statuses = if state == LifecycleState::DecisionRecorded {
            0
        } else {
            input.reservations.entries().len()
        };
        if statuses.len() != expected_statuses {
            return Err(CodecError::InvalidSemantics);
        }
        let mut reservation_entries = if statuses.is_empty() {
            Vec::new()
        } else {
            input
                .reservations
                .entries()
                .iter()
                .cloned()
                .map(ReservationEntryV1::reserved)
                .collect::<Vec<_>>()
        };
        for (entry, (committed, released)) in reservation_entries.iter_mut().zip(statuses) {
            if committed && released {
                return Err(CodecError::InvalidSemantics);
            }
            if committed {
                entry.mark_committed();
            }
            if released {
                entry.mark_released();
            }
        }
        Ok(Self {
            input,
            state,
            revision: wire.revision,
            created_at: VerifierTime::from_unix_seconds(wire.created_at),
            updated_at: VerifierTime::from_unix_seconds(wire.updated_at),
            reservation_entries,
            execution_intent: wire
                .execution_intent
                .map(ExecutionIntentV1::try_from)
                .transpose()?,
            credential_authorized: wire.credential_authorized,
            attempts: wire
                .attempts
                .into_iter()
                .map(ProviderAttemptV1::try_from)
                .collect::<Result<_, _>>()?,
            observations: wire
                .observations
                .into_iter()
                .map(ReconciliationObservationV1::try_from)
                .collect::<Result<_, _>>()?,
            terminal_result: wire.terminal_result.map(ProviderResultDigest::new),
            events: wire
                .events
                .into_iter()
                .map(LifecycleEventV1::try_from)
                .collect::<Result<_, _>>()?,
            receipts: wire
                .receipts
                .into_iter()
                .map(LifecycleReceiptEnvelopeV1::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<WireDecision> for DecisionInputV1 {
    type Error = CodecError;

    fn try_from(wire: WireDecision) -> Result<Self, Self::Error> {
        let workflow_id = WorkflowId::parse(&wire.workflow_id).map_err(semantic)?;
        let lifecycle_id = LifecycleId::parse(&wire.lifecycle_id).map_err(semantic)?;
        let execution_id = ExecutionId::parse(&wire.execution_id).map_err(semantic)?;
        let domain_id = DomainId::parse(&wire.domain_id).map_err(semantic)?;
        let executor_audience =
            ExecutorAudienceId::parse(&wire.executor_audience).map_err(semantic)?;
        let reservation_algebra_id =
            ReservationAlgebraId::parse(&wire.reservation_algebra_id).map_err(semantic)?;
        let commitments = EvaluationCommitmentsV1::try_from(wire.commitments)?;
        let outputs = BoundedOutputs::try_from(wire.outputs)?;
        let reservations = ReservationSetV1::derive(
            &workflow_id,
            &domain_id,
            commitments.profile_id(),
            commitments.policy_commitment().evaluator_semantic_id(),
            &executor_audience,
            &reservation_algebra_id,
            &outputs,
        )
        .map_err(semantic)?;
        Ok(Self {
            core_authorized: wire.core_authorized,
            core_authorization_digest: CommitmentDigest::new(wire.core_authorization_digest),
            workflow_id,
            lifecycle_id,
            execution_id,
            domain_id,
            executor_audience,
            reservation_algebra_id,
            commitments,
            outputs,
            reservations,
            decision_receipt_digest: DecisionReceiptDigest::new(wire.decision_receipt_digest),
            domain_decision_receipt_digest: DomainReceiptDigest::new(
                wire.domain_decision_receipt_digest,
            ),
            implementation_id: ImplementationId::parse(&wire.implementation_id)
                .map_err(semantic)?,
            implementation_build_digest: CommitmentDigest::new(wire.implementation_build_digest),
            expires_at: VerifierTime::from_unix_seconds(wire.expires_at),
            cancellation: parse_cancellation(wire.cancellation)?,
        })
    }
}

impl TryFrom<WireCommitments> for EvaluationCommitmentsV1 {
    type Error = CodecError;

    fn try_from(wire: WireCommitments) -> Result<Self, Self::Error> {
        Ok(Self::new(
            ProfileId::parse(&wire.profile_id).map_err(semantic)?,
            CommitmentDigest::new(wire.exact_action_digest),
            PolicyCommitmentV1::try_from(wire.policy)?,
            SchemaId::parse(&wire.evidence_schema_id).map_err(semantic)?,
            CommitmentDigest::new(wire.evidence_digest),
            EvidenceSourceId::parse(&wire.evidence_source_id).map_err(semantic)?,
            VerifierTime::from_unix_seconds(wire.evidence_observed_at),
            SchemaId::parse(&wire.state_snapshot_schema_id).map_err(semantic)?,
            CommitmentDigest::new(wire.state_snapshot_digest),
            VerifierTime::from_unix_seconds(wire.verifier_time),
            ConfigurationCommitmentV1::try_from(wire.required_configuration)?,
            ConfigurationCommitmentV1::try_from(wire.executed_configuration)?,
        ))
    }
}

impl TryFrom<WirePolicy> for PolicyCommitmentV1 {
    type Error = CodecError;

    fn try_from(wire: WirePolicy) -> Result<Self, Self::Error> {
        Self::new(
            PolicyTypeId::parse(&wire.policy_type).map_err(semantic)?,
            wire.policy_version,
            CanonicalizationId::parse(&wire.canonicalization_id).map_err(semantic)?,
            CommitmentDigest::new(wire.policy_digest),
            EvaluatorSemanticId::parse(&wire.evaluator_semantic_id).map_err(semantic)?,
        )
        .map_err(semantic)
    }
}

impl TryFrom<WireConfiguration> for ConfigurationCommitmentV1 {
    type Error = CodecError;

    fn try_from(wire: WireConfiguration) -> Result<Self, Self::Error> {
        Ok(Self::new(
            ConfigurationSemanticId::parse(&wire.semantic_id).map_err(semantic)?,
            CanonicalizationId::parse(&wire.canonicalization_id).map_err(semantic)?,
            CommitmentDigest::new(wire.configuration_digest),
            wire.implementation_id
                .map(|value| ImplementationId::parse(&value).map_err(semantic))
                .transpose()?,
        ))
    }
}

impl TryFrom<WireOutputs> for BoundedOutputs {
    type Error = CodecError;

    fn try_from(wire: WireOutputs) -> Result<Self, Self::Error> {
        Self::new(
            wire.reservations
                .into_iter()
                .map(ReservationIntentCommitmentV1::try_from)
                .collect::<Result<_, _>>()?,
            wire.obligations
                .into_iter()
                .map(ObligationCommitmentV1::try_from)
                .collect::<Result<_, _>>()?,
            CommitmentDigest::new(wire.reservation_intents_commitment),
            CommitmentDigest::new(wire.obligations_commitment),
        )
        .map_err(semantic)
    }
}

impl TryFrom<WireReservationIntent> for ReservationIntentCommitmentV1 {
    type Error = CodecError;

    fn try_from(wire: WireReservationIntent) -> Result<Self, Self::Error> {
        let kind = match (wire.kind, wire.unit, wire.amount) {
            (0, Some(unit), Some(amount)) => {
                ReservationKind::additive(UnitId::parse(&unit).map_err(semantic)?, amount)
                    .map_err(semantic)?
            }
            (1, None, None) => ReservationKind::Exclusive,
            _ => return Err(CodecError::InvalidSemantics),
        };
        Self::new(
            SchemaId::parse(&wire.schema_id).map_err(semantic)?,
            IntentId::parse(&wire.intent_id).map_err(semantic)?,
            CommitmentDigest::new(wire.scope_digest),
            kind,
            wire.window_digest.map(CommitmentDigest::new),
            CommitmentDigest::new(wire.action_digest),
            CommitmentDigest::new(wire.policy_digest),
            CommitmentDigest::new(wire.evidence_digest),
            CommitmentDigest::new(wire.canonical_digest),
            wire.canonical_bytes,
        )
        .map_err(semantic)
    }
}

impl TryFrom<WireObligation> for ObligationCommitmentV1 {
    type Error = CodecError;

    fn try_from(wire: WireObligation) -> Result<Self, Self::Error> {
        Self::new(
            SchemaId::parse(&wire.schema_id).map_err(semantic)?,
            ObligationId::parse(&wire.obligation_id).map_err(semantic)?,
            parse_obligation(wire.class)?,
            CommitmentDigest::new(wire.payload_digest),
            wire.canonical_bytes,
        )
        .map_err(semantic)
    }
}

impl TryFrom<WireExecutionIntent> for ExecutionIntentV1 {
    type Error = CodecError;

    fn try_from(wire: WireExecutionIntent) -> Result<Self, Self::Error> {
        Ok(Self::new(
            CommitmentDigest::new(wire.verified_command_digest),
            ProviderRequestDigest::new(wire.provider_request_digest),
            ProviderConditionDigest::new(wire.provider_condition_digest),
            ProviderContractId::parse(&wire.provider_contract_id).map_err(semantic)?,
            parse_retry(wire.retry_class)?,
        ))
    }
}

impl TryFrom<WireAttempt> for ProviderAttemptV1 {
    type Error = CodecError;

    fn try_from(wire: WireAttempt) -> Result<Self, Self::Error> {
        Ok(Self {
            ordinal: AttemptOrdinal::new(wire.ordinal).map_err(semantic)?,
            started_at: VerifierTime::from_unix_seconds(wire.started_at),
            provider_request_digest: ProviderRequestDigest::new(wire.provider_request_digest),
            provider_condition_digest: ProviderConditionDigest::new(wire.provider_condition_digest),
            provider_contract_id: ProviderContractId::parse(&wire.provider_contract_id)
                .map_err(semantic)?,
            call_entered: wire.call_entered,
        })
    }
}

impl TryFrom<WireObservation> for ReconciliationObservationV1 {
    type Error = CodecError;

    fn try_from(wire: WireObservation) -> Result<Self, Self::Error> {
        Ok(Self::new(
            ReconciliationId::parse(&wire.reconciliation_id).map_err(semantic)?,
            EvidenceSourceId::parse(&wire.source_id).map_err(semantic)?,
            VerifierTime::from_unix_seconds(wire.observed_at),
            VerifierTime::from_unix_seconds(wire.fresh_until),
            ObservationDigest::new(wire.observation_digest),
            parse_conclusion(wire.conclusion)?,
            ProviderRequestDigest::new(wire.provider_request_digest),
        ))
    }
}

impl TryFrom<WireEvent> for LifecycleEventV1 {
    type Error = CodecError;

    fn try_from(wire: WireEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            kind: parse_event(wire.kind)?,
            revision: wire.revision,
            verifier_time: VerifierTime::from_unix_seconds(wire.verifier_time),
            trigger_digest: CommitmentDigest::new(wire.trigger_digest),
        })
    }
}

impl TryFrom<WireReceipt> for LifecycleReceiptEnvelopeV1 {
    type Error = CodecError;

    fn try_from(wire: WireReceipt) -> Result<Self, Self::Error> {
        Ok(Self {
            revision: wire.revision,
            previous: wire.previous.map(LifecycleReceiptDigest::new),
            from: wire.from.map(parse_state).transpose()?,
            to: parse_state(wire.to)?,
            trigger_digest: CommitmentDigest::new(wire.trigger_digest),
            verifier_time: VerifierTime::from_unix_seconds(wire.verifier_time),
            required_configuration: ConfigurationCommitmentV1::try_from(
                wire.required_configuration,
            )?,
            executed_configuration: ConfigurationCommitmentV1::try_from(
                wire.executed_configuration,
            )?,
            implementation_id: ImplementationId::parse(&wire.implementation_id)
                .map_err(semantic)?,
            domain_receipt_digest: wire.domain_receipt_digest.map(DomainReceiptDigest::new),
            receipt_digest: LifecycleReceiptDigest::new(wire.receipt_digest),
        })
    }
}

fn semantic<T>(_: T) -> CodecError {
    CodecError::InvalidSemantics
}

const fn state_code(value: LifecycleState) -> u8 {
    match value {
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

const fn parse_state(value: u8) -> Result<LifecycleState, CodecError> {
    match value {
        0 => Ok(LifecycleState::DecisionRecorded),
        1 => Ok(LifecycleState::Reserved),
        2 => Ok(LifecycleState::ExecutionIntentRecorded),
        3 => Ok(LifecycleState::Executing),
        4 => Ok(LifecycleState::Committed),
        5 => Ok(LifecycleState::Released),
        6 => Ok(LifecycleState::OutcomeUnknown),
        7 => Ok(LifecycleState::ReconciledCommitted),
        8 => Ok(LifecycleState::ReconciledReleased),
        _ => Err(CodecError::InvalidSemantics),
    }
}

const fn retry_code(value: ProviderRetryClass) -> u8 {
    match value {
        ProviderRetryClass::ExactIdempotent => 0,
        ProviderRetryClass::Conditional => 1,
        ProviderRetryClass::ObserveBeforeRetry => 2,
        ProviderRetryClass::NonRetryable => 3,
    }
}

const fn parse_retry(value: u8) -> Result<ProviderRetryClass, CodecError> {
    match value {
        0 => Ok(ProviderRetryClass::ExactIdempotent),
        1 => Ok(ProviderRetryClass::Conditional),
        2 => Ok(ProviderRetryClass::ObserveBeforeRetry),
        3 => Ok(ProviderRetryClass::NonRetryable),
        _ => Err(CodecError::InvalidSemantics),
    }
}

const fn conclusion_code(value: EffectConclusion) -> u8 {
    match value {
        EffectConclusion::Effect => 0,
        EffectConclusion::NonEffect => 1,
        EffectConclusion::Unknown => 2,
        EffectConclusion::Inconclusive => 3,
    }
}

const fn parse_conclusion(value: u8) -> Result<EffectConclusion, CodecError> {
    match value {
        0 => Ok(EffectConclusion::Effect),
        1 => Ok(EffectConclusion::NonEffect),
        2 => Ok(EffectConclusion::Unknown),
        3 => Ok(EffectConclusion::Inconclusive),
        _ => Err(CodecError::InvalidSemantics),
    }
}

const fn cancellation_code(value: CancellationDisposition) -> u8 {
    match value {
        CancellationDisposition::BeforeAttemptAllowed => 0,
        CancellationDisposition::EvidenceRequired => 1,
    }
}

const fn parse_cancellation(value: u8) -> Result<CancellationDisposition, CodecError> {
    match value {
        0 => Ok(CancellationDisposition::BeforeAttemptAllowed),
        1 => Ok(CancellationDisposition::EvidenceRequired),
        _ => Err(CodecError::InvalidSemantics),
    }
}

const fn obligation_code(value: ObligationClass) -> u8 {
    match value {
        ObligationClass::PreExecution => 0,
        ObligationClass::CommandConstruction => 1,
        ObligationClass::PostExecutionObservation => 2,
    }
}

const fn parse_obligation(value: u8) -> Result<ObligationClass, CodecError> {
    match value {
        0 => Ok(ObligationClass::PreExecution),
        1 => Ok(ObligationClass::CommandConstruction),
        2 => Ok(ObligationClass::PostExecutionObservation),
        _ => Err(CodecError::InvalidSemantics),
    }
}

const fn event_code(value: LifecycleEventKind) -> u8 {
    match value {
        LifecycleEventKind::DecisionPersisted => 0,
        LifecycleEventKind::ReservationPersisted => 1,
        LifecycleEventKind::ExecutionIntentPersisted => 2,
        LifecycleEventKind::CredentialAuthorized => 3,
        LifecycleEventKind::AttemptPersisted => 4,
        LifecycleEventKind::ProviderCallEntered => 5,
        LifecycleEventKind::ProviderResultPersisted => 6,
        LifecycleEventKind::OutcomeUnknownPersisted => 7,
        LifecycleEventKind::ReconciliationObserved => 8,
        LifecycleEventKind::ReconciliationPersisted => 9,
    }
}

const fn parse_event(value: u8) -> Result<LifecycleEventKind, CodecError> {
    match value {
        0 => Ok(LifecycleEventKind::DecisionPersisted),
        1 => Ok(LifecycleEventKind::ReservationPersisted),
        2 => Ok(LifecycleEventKind::ExecutionIntentPersisted),
        3 => Ok(LifecycleEventKind::CredentialAuthorized),
        4 => Ok(LifecycleEventKind::AttemptPersisted),
        5 => Ok(LifecycleEventKind::ProviderCallEntered),
        6 => Ok(LifecycleEventKind::ProviderResultPersisted),
        7 => Ok(LifecycleEventKind::OutcomeUnknownPersisted),
        8 => Ok(LifecycleEventKind::ReconciliationObserved),
        9 => Ok(LifecycleEventKind::ReconciliationPersisted),
        _ => Err(CodecError::InvalidSemantics),
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::{
        TransitionCommandV1, apply_transition,
        test_support::{decision_transaction, transaction},
    };

    #[test]
    fn additive_decision_and_reservation_round_trip_exactly() {
        let decision = decision_transaction("workflow-1", Some(6));
        let first = apply_transition(None, &decision.command, &decision.context).unwrap();
        assert!(validate_record_integrity(&first.record));
        let bytes = encode_unchecked(&first.record).unwrap();
        let probe: WireEnvelope = postcard::from_bytes(&bytes).unwrap();
        assert!(
            DecisionInputV1::try_from(probe.record.input).is_ok(),
            "decision wire must reconstruct"
        );
        let reconstructed = decode_wire(&bytes).unwrap();
        assert_eq!(reconstructed, first.record);
        assert_eq!(decode_record(&bytes).unwrap(), first.record);
        let reserve = transaction("workflow-1", Some(1), TransitionCommandV1::Reserve, 11);
        let reserved = apply_transition(Some(&first.record), &reserve.command, &reserve.context);
        assert!(reserved.is_err(), "empty caller capacity must fail closed");
    }
}
