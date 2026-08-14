use std::sync::Mutex;

use auths_bounded_policy::{
    BoundedOutputs, CanonicalizationId, CommitmentDigest, ConfigurationCommitmentV1,
    ConfigurationSemanticId, EvaluationCommitmentsV1, EvaluatorSemanticId, EvidenceSourceId,
    ImplementationId, PolicyCommitmentV1, PolicyTypeId, ProfileId, SchemaId, VerifierTime,
};
use auths_lifecycle::{
    CancellationDisposition, CapacitySnapshotV1, DecisionInputV1, DecisionReceiptDigest, DomainId,
    DomainReceiptDigest, ExecutionAuthorizationV1, ExecutionId, ExecutionIntentV1,
    ExecutorAudienceId, LifecycleId, LifecycleState, LifecycleStore, ProviderCallAuthorizationV1,
    ProviderConditionDigest, ProviderContractId, ProviderRequestDigest, ProviderRetryClass,
    ReservationAlgebraId, ReservationSetV1, RevocationSnapshotV1, StoreError, StoreTransactionV1,
    StoredTransitionV1, TransitionCommandV1, TransitionContextV1, TransitionDisposition,
    WorkflowId, apply_transition, decode_record, encode_record, execute_store_transaction,
};

struct MemoryStore {
    record: Mutex<Option<auths_lifecycle::LifecycleRecordV1>>,
}

impl MemoryStore {
    fn new() -> Self {
        Self {
            record: Mutex::new(None),
        }
    }
}

impl LifecycleStore for MemoryStore {
    fn transact(&self, transaction: &StoreTransactionV1) -> Result<StoredTransitionV1, StoreError> {
        let mut guard = self.record.lock().map_err(|_| StoreError::Unavailable)?;
        let revision = guard
            .as_ref()
            .map(auths_lifecycle::LifecycleRecordV1::revision);
        if revision != transaction.expected_revision {
            return Err(StoreError::Conflict);
        }
        let result = apply_transition(guard.as_ref(), &transaction.command, &transaction.context)
            .map_err(|_| StoreError::Conflict)?;
        if result.disposition == TransitionDisposition::Applied {
            *guard = Some(result.record.clone());
        }
        Ok(StoredTransitionV1::acknowledged(
            result.record,
            result.disposition,
        ))
    }
}

fn id_digest(byte: u8) -> CommitmentDigest {
    CommitmentDigest::new([byte; 32])
}

fn context(now: u64) -> TransitionContextV1 {
    TransitionContextV1 {
        verifier_time: VerifierTime::from_unix_seconds(now),
        executed_configuration: configuration(),
        revocation: RevocationSnapshotV1 {
            revoked: false,
            snapshot_digest: id_digest(80),
        },
        capacity: CapacitySnapshotV1::new(vec![]).unwrap(),
    }
}

fn configuration() -> ConfigurationCommitmentV1 {
    ConfigurationCommitmentV1::new(
        ConfigurationSemanticId::parse("auths.test.config/1").unwrap(),
        CanonicalizationId::parse("auths.test.canonical/1").unwrap(),
        id_digest(7),
        Some(ImplementationId::parse("auths.test.impl/1").unwrap()),
    )
}

fn decision() -> DecisionInputV1 {
    let policy = PolicyCommitmentV1::new(
        PolicyTypeId::parse("auths.test.policy/1").unwrap(),
        1,
        CanonicalizationId::parse("auths.test.canonical/1").unwrap(),
        id_digest(2),
        EvaluatorSemanticId::parse("auths.test.evaluator/1").unwrap(),
    )
    .unwrap();
    let config = configuration();
    let commitments = EvaluationCommitmentsV1::new(
        ProfileId::parse("auths.test.profile/1").unwrap(),
        id_digest(1),
        policy,
        SchemaId::parse("auths.test.evidence/1").unwrap(),
        id_digest(3),
        EvidenceSourceId::parse("auths.test.source/1").unwrap(),
        VerifierTime::from_unix_seconds(10),
        SchemaId::parse("auths.test.state/1").unwrap(),
        id_digest(4),
        VerifierTime::from_unix_seconds(10),
        config.clone(),
        config,
    );
    let outputs = BoundedOutputs::new(vec![], vec![], id_digest(5), id_digest(6)).unwrap();
    let reservations = ReservationSetV1::derive(
        &WorkflowId::parse("workflow-1").unwrap(),
        &DomainId::parse("test").unwrap(),
        commitments.profile_id(),
        commitments.policy_commitment().evaluator_semantic_id(),
        &ExecutorAudienceId::parse("test://executor").unwrap(),
        &ReservationAlgebraId::parse("auths.test.none/1").unwrap(),
        &outputs,
    )
    .unwrap();
    DecisionInputV1 {
        core_authorized: true,
        core_authorization_digest: id_digest(9),
        workflow_id: WorkflowId::parse("workflow-1").unwrap(),
        lifecycle_id: LifecycleId::parse("lifecycle-1").unwrap(),
        execution_id: ExecutionId::parse("execution-1").unwrap(),
        recovery_reference_digest: auths_lifecycle::RecoveryReferenceDigest::new([13; 32]),
        domain_id: DomainId::parse("test").unwrap(),
        executor_audience: ExecutorAudienceId::parse("test://executor").unwrap(),
        reservation_algebra_id: ReservationAlgebraId::parse("auths.test.none/1").unwrap(),
        commitments,
        outputs,
        reservations,
        decision_receipt_digest: DecisionReceiptDigest::new([10; 32]),
        domain_decision_receipt_digest: DomainReceiptDigest::new([11; 32]),
        implementation_id: ImplementationId::parse("auths.lifecycle.test/1").unwrap(),
        implementation_build_digest: id_digest(12),
        expires_at: VerifierTime::from_unix_seconds(100),
        cancellation: CancellationDisposition::BeforeAttemptAllowed,
    }
}

fn transaction(
    revision: Option<u64>,
    command: TransitionCommandV1,
    now: u64,
) -> StoreTransactionV1 {
    StoreTransactionV1 {
        workflow_id: WorkflowId::parse("workflow-1").unwrap(),
        expected_revision: revision,
        command,
        context: context(now),
    }
}

#[test]
fn credentials_and_provider_calls_require_durable_ordered_stages() {
    let store = MemoryStore::new();
    let decision = execute_store_transaction(
        &store,
        &transaction(
            None,
            TransitionCommandV1::RecordDecision(Box::new(decision())),
            10,
        ),
    )
    .unwrap();
    assert_eq!(decision.record().state(), LifecycleState::DecisionRecorded);
    assert!(ExecutionAuthorizationV1::from_durable(&decision).is_err());

    let reserved = execute_store_transaction(
        &store,
        &transaction(Some(1), TransitionCommandV1::Reserve, 11),
    )
    .unwrap();
    assert_eq!(reserved.record().state(), LifecycleState::Reserved);

    let intent = ExecutionIntentV1::new(
        id_digest(20),
        ProviderRequestDigest::new([21; 32]),
        ProviderConditionDigest::new([22; 32]),
        ProviderContractId::parse("auths.test.provider/1").unwrap(),
        ProviderRetryClass::NonRetryable,
    );
    let intent_recorded = execute_store_transaction(
        &store,
        &transaction(
            Some(2),
            TransitionCommandV1::RecordExecutionIntent(intent),
            12,
        ),
    )
    .unwrap();
    assert!(ExecutionAuthorizationV1::from_durable(&intent_recorded).is_err());

    let credential_stage = execute_store_transaction(
        &store,
        &transaction(Some(3), TransitionCommandV1::AuthorizeCredential, 13),
    )
    .unwrap();
    let credential_authorization =
        ExecutionAuthorizationV1::from_durable(&credential_stage).unwrap();
    assert_eq!(credential_authorization.revision(), 4);
    assert!(
        execute_store_transaction(
            &store,
            &transaction(Some(4), TransitionCommandV1::AuthorizeCredential, 13),
        )
        .is_err()
    );

    let attempt = execute_store_transaction(
        &store,
        &transaction(Some(4), TransitionCommandV1::StartAttempt, 14),
    )
    .unwrap();
    assert!(ProviderCallAuthorizationV1::from_durable(&attempt).is_err());

    let call_entry = execute_store_transaction(
        &store,
        &transaction(Some(5), TransitionCommandV1::MarkProviderCallEntered, 15),
    )
    .unwrap();
    let call_authorization = ProviderCallAuthorizationV1::from_durable(&call_entry).unwrap();
    assert_eq!(
        call_authorization.provider_request_digest(),
        ProviderRequestDigest::new([21; 32])
    );
    let canonical = encode_record(call_entry.record()).unwrap();
    let decoded = decode_record(&canonical).unwrap();
    assert_eq!(decoded, *call_entry.record());
    assert_eq!(encode_record(&decoded).unwrap(), canonical);

    let mut changed_receipt = canonical.clone();
    let last = changed_receipt.last_mut().unwrap();
    *last ^= 1;
    assert!(decode_record(&changed_receipt).is_err());
    assert!(decode_record(&canonical[..canonical.len() - 1]).is_err());
    let mut unsupported = canonical.clone();
    unsupported[0] = 3;
    assert!(matches!(
        decode_record(&unsupported),
        Err(auths_lifecycle::CodecError::UnsupportedVersion)
    ));
    let mut trailing = canonical;
    trailing.push(0);
    assert!(decode_record(&trailing).is_err());
    assert!(
        execute_store_transaction(
            &store,
            &transaction(Some(6), TransitionCommandV1::MarkProviderCallEntered, 15,),
        )
        .is_err()
    );
}

#[test]
fn exact_replay_returns_original_record_and_mutation_conflicts() {
    let store = MemoryStore::new();
    let first = execute_store_transaction(
        &store,
        &transaction(
            None,
            TransitionCommandV1::RecordDecision(Box::new(decision())),
            10,
        ),
    )
    .unwrap();
    let replay = execute_store_transaction(
        &store,
        &transaction(
            Some(1),
            TransitionCommandV1::RecordDecision(Box::new(decision())),
            10,
        ),
    )
    .unwrap();
    assert_eq!(first.record().revision(), 1);
    assert_eq!(replay.disposition(), TransitionDisposition::ExactReplay);
    assert_eq!(replay.record().revision(), 1);

    let mut conflicting = decision();
    conflicting.core_authorization_digest = id_digest(99);
    let conflict = execute_store_transaction(
        &store,
        &transaction(
            Some(1),
            TransitionCommandV1::RecordDecision(Box::new(conflicting)),
            10,
        ),
    );
    assert!(matches!(conflict, Err(StoreError::Conflict)));
}
