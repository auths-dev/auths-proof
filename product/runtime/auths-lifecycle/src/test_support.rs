//! Deterministic public fixtures for downstream conformance suites.

use alloc::{boxed::Box, vec, vec::Vec};

use auths_bounded_policy::{
    BoundedOutputs, CanonicalizationId, CommitmentDigest, ConfigurationCommitmentV1,
    ConfigurationSemanticId, EvaluationCommitmentsV1, EvaluatorSemanticId, EvidenceSourceId,
    ImplementationId, IntentId, PolicyCommitmentV1, PolicyTypeId, ProfileId,
    ReservationIntentCommitmentV1, ReservationKind, SchemaId, UnitId, VerifierTime,
};

use crate::{
    CancellationDisposition, CapacitySnapshotV1, DecisionInputV1, DecisionReceiptDigest, DomainId,
    DomainReceiptDigest, ExecutionId, ExecutorAudienceId, LifecycleId, ReservationAlgebraId,
    ReservationSetV1, RevocationSnapshotV1, StoreTransactionV1, TransitionCommandV1,
    TransitionContextV1, WorkflowId,
};

/// Shared fixture scope digest.
pub const CAPACITY_SCOPE: CommitmentDigest = CommitmentDigest::new([30; 32]);

/// Returns the deterministic reference configuration.
///
/// # Panics
///
/// Panics only if a compile-time fixture identifier stops satisfying its
/// declared production parser, which is a conformance failure.
#[must_use]
pub fn configuration() -> ConfigurationCommitmentV1 {
    ConfigurationCommitmentV1::new(
        ConfigurationSemanticId::parse("auths.test.config/1").unwrap(),
        CanonicalizationId::parse("auths.test.canonical/1").unwrap(),
        CommitmentDigest::new([7; 32]),
        Some(ImplementationId::parse("auths.test.impl/1").unwrap()),
    )
}

/// Returns explicit transition context. Stores replace its empty capacity
/// snapshot with transactionally derived state.
///
/// # Panics
///
/// Panics only if the fixed empty capacity fixture becomes invalid.
#[must_use]
pub fn context(now: u64) -> TransitionContextV1 {
    TransitionContextV1 {
        verifier_time: VerifierTime::from_unix_seconds(now),
        executed_configuration: configuration(),
        revocation: RevocationSnapshotV1 {
            revoked: false,
            snapshot_digest: CommitmentDigest::new([80; 32]),
        },
        capacity: CapacitySnapshotV1::new(Vec::new()).unwrap(),
    }
}

/// Constructs one complete eligible reference decision.
///
/// # Panics
///
/// Panics when `workflow` violates the production identifier contract or a
/// compile-time fixture no longer satisfies its production constructor.
#[must_use]
pub fn decision(workflow: &str, amount: Option<u64>) -> DecisionInputV1 {
    let workflow_id = WorkflowId::parse(workflow).unwrap();
    let policy = PolicyCommitmentV1::new(
        PolicyTypeId::parse("auths.test.policy/1").unwrap(),
        1,
        CanonicalizationId::parse("auths.test.canonical/1").unwrap(),
        CommitmentDigest::new([2; 32]),
        EvaluatorSemanticId::parse("auths.test.evaluator/1").unwrap(),
    )
    .unwrap();
    let config = configuration();
    let commitments = EvaluationCommitmentsV1::new(
        ProfileId::parse("auths.test.profile/1").unwrap(),
        CommitmentDigest::new([1; 32]),
        policy,
        SchemaId::parse("auths.test.evidence/1").unwrap(),
        CommitmentDigest::new([3; 32]),
        EvidenceSourceId::parse("auths.test.source/1").unwrap(),
        VerifierTime::from_unix_seconds(10),
        SchemaId::parse("auths.test.state/1").unwrap(),
        CommitmentDigest::new([4; 32]),
        VerifierTime::from_unix_seconds(10),
        config.clone(),
        config,
    );
    let intents = amount.map_or_else(Vec::new, |amount| {
        vec![
            ReservationIntentCommitmentV1::new(
                SchemaId::parse("auths.test.reservation/1").unwrap(),
                IntentId::parse("capacity").unwrap(),
                CAPACITY_SCOPE,
                ReservationKind::additive(UnitId::parse("requests").unwrap(), amount).unwrap(),
                None,
                CommitmentDigest::new([1; 32]),
                CommitmentDigest::new([2; 32]),
                CommitmentDigest::new([3; 32]),
                CommitmentDigest::new([31; 32]),
                64,
            )
            .unwrap(),
        ]
    });
    let outputs = BoundedOutputs::new(
        intents,
        Vec::new(),
        CommitmentDigest::new([5; 32]),
        CommitmentDigest::new([6; 32]),
    )
    .unwrap();
    let domain_id = DomainId::parse("test").unwrap();
    let audience = ExecutorAudienceId::parse("test://executor").unwrap();
    let algebra = ReservationAlgebraId::parse("auths.test.additive/1").unwrap();
    let reservations = ReservationSetV1::derive(
        &workflow_id,
        &domain_id,
        commitments.profile_id(),
        commitments.policy_commitment().evaluator_semantic_id(),
        &audience,
        &algebra,
        &outputs,
    )
    .unwrap();
    DecisionInputV1 {
        core_authorized: true,
        core_authorization_digest: CommitmentDigest::new([9; 32]),
        workflow_id,
        lifecycle_id: LifecycleId::parse(workflow).unwrap(),
        execution_id: ExecutionId::parse(workflow).unwrap(),
        domain_id,
        executor_audience: audience,
        reservation_algebra_id: algebra,
        commitments,
        outputs,
        reservations,
        decision_receipt_digest: DecisionReceiptDigest::new([10; 32]),
        domain_decision_receipt_digest: DomainReceiptDigest::new([11; 32]),
        implementation_id: ImplementationId::parse("auths.lifecycle.test/1").unwrap(),
        implementation_build_digest: CommitmentDigest::new([12; 32]),
        expires_at: VerifierTime::from_unix_seconds(100),
        cancellation: CancellationDisposition::BeforeAttemptAllowed,
    }
}

/// Constructs one reference store transaction.
///
/// # Panics
///
/// Panics when `workflow` violates the production identifier contract.
#[must_use]
pub fn transaction(
    workflow: &str,
    revision: Option<u64>,
    command: TransitionCommandV1,
    now: u64,
) -> StoreTransactionV1 {
    StoreTransactionV1 {
        workflow_id: WorkflowId::parse(workflow).unwrap(),
        expected_revision: revision,
        command,
        context: context(now),
    }
}

/// Constructs a decision-recording transaction.
#[must_use]
pub fn decision_transaction(workflow: &str, amount: Option<u64>) -> StoreTransactionV1 {
    transaction(
        workflow,
        None,
        TransitionCommandV1::RecordDecision(Box::new(decision(workflow, amount))),
        10,
    )
}
