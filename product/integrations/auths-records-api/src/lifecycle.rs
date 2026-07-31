//! Exact create/read projection into the shared bounded-policy and lifecycle
//! contracts.
//!
//! Records retains ownership of record identity, protected values, disclosure
//! bytes, provider commands, reconciliation, stable codes, and public
//! receipts. Shared crates receive only canonical commitments plus the
//! additive create-unit, created-byte, or read-unit reservations.

use std::sync::Arc;

use auths_bounded_policy::{
    BoundedOutputs, CanonicalizationId, CommitmentDigest, ConfigurationCommitmentV1,
    ConfigurationSemanticId, EvaluationCommitmentsV1, EvaluatorSemanticId, EvidenceSourceId,
    ImplementationId, IntentId, ObligationClass, ObligationCommitmentV1, ObligationId,
    PolicyCommitmentV1, PolicyTypeId, ProfileId, ReservationIntentCommitmentV1, ReservationKind,
    SchemaId, UnitId, VerifierTime,
};
use auths_lifecycle::{
    CancellationDisposition, CapacityEntryV1, CapacitySnapshotV1, DecisionInputV1,
    DecisionReceiptDigest, DomainId, DomainReceiptDigest, ExecutionId, ExecutorAudienceId,
    LifecycleId, LifecycleRecordV1, LifecycleStore, ReservationAlgebraId, ReservationSetV1,
    RevocationSnapshotV1, StoreError, TransitionContextV1, WorkflowId,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    BoundedRecordApiPolicyV1, CREATE_PROFILE_ID, CreateRecordV1, DecisionClass, PROFILE_VERSION,
    READ_PROFILE_ID, ReadRecordV1, RecordsApiVerifierConfigurationV1, RecordsDecision,
    RecordsPresentationV1,
    canonical::{canonical_digest, canonical_json, sha256},
};

pub const POLICY_TYPE_ID: &str = "auths.demo.bounded-record-api-policy/1";
pub const IMPLEMENTATION_ID: &str = "auths-records-api/shared-lifecycle-production/1";
pub const CANONICALIZATION_ID: &str = "rfc8785-sha256-v1";
pub const CONFIGURATION_SEMANTIC_ID: &str = "auths.records.verifier-configuration/1";
pub const EVIDENCE_SCHEMA_ID: &str = "auths.records.presentation-evidence/1";
pub const EVIDENCE_SOURCE_ID: &str = "records-presentation-verifier/1";
pub const STATE_SCHEMA_ID: &str = "auths.records.pre-effect-state/1";
pub const CREATE_INTENT_SCHEMA_ID: &str = "auths.records.create-additive-intent/1";
pub const READ_INTENT_SCHEMA_ID: &str = "auths.records.read-additive-intent/1";
pub const CREATE_OBLIGATION_SCHEMA_ID: &str = "auths.records.verified-create-command/1";
pub const READ_OBLIGATION_SCHEMA_ID: &str = "auths.records.verified-read-command/1";
pub const RESERVATION_ALGEBRA_ID: &str = "auths.records.policy-additive/1";
pub const CREATE_PROVIDER_CONTRACT_ID: &str = "auths.records.create-provider/1";
pub const READ_PROVIDER_CONTRACT_ID: &str = "auths.records.read-provider/1";
pub const DOMAIN_ID: &str = "records";

/// One of the two closed records actions accepted by the lifecycle
/// projection.
#[derive(Clone, Copy)]
pub enum RecordsLifecycleAction<'a> {
    Create(&'a CreateRecordV1),
    Read(&'a ReadRecordV1),
}

impl RecordsLifecycleAction<'_> {
    fn digest(self) -> Result<String, RecordsLifecycleProjectionError> {
        match self {
            Self::Create(action) => action.digest().map_err(canonical),
            Self::Read(action) => action.digest().map_err(canonical),
        }
    }

    fn canonical_bytes(self) -> Result<Vec<u8>, RecordsLifecycleProjectionError> {
        match self {
            Self::Create(action) => action.canonical_bytes().map_err(canonical),
            Self::Read(action) => action.canonical_bytes().map_err(canonical),
        }
    }

    const fn profile_id(self) -> &'static str {
        match self {
            Self::Create(_) => CREATE_PROFILE_ID,
            Self::Read(_) => READ_PROFILE_ID,
        }
    }

    const fn evaluator_id(self) -> &'static str {
        match self {
            Self::Create(_) => "auths.records.create-evaluator/1",
            Self::Read(_) => "auths.records.read-evaluator/1",
        }
    }

    fn executor_audience(&self) -> &str {
        match self {
            Self::Create(action) => &action.executor_audience,
            Self::Read(action) => &action.executor_audience,
        }
    }
}

/// Complete domain inputs to the pure records projection.
pub struct RecordsLifecycleProjectionInput<'a> {
    pub action: RecordsLifecycleAction<'a>,
    pub policy: &'a BoundedRecordApiPolicyV1,
    pub presentation: &'a RecordsPresentationV1,
    pub required_configuration: &'a RecordsApiVerifierConfigurationV1,
    pub executed_configuration: &'a RecordsApiVerifierConfigurationV1,
    pub decision: &'a RecordsDecision,
    pub verifier_time: u64,
}

/// Validated shared projection of one authorized create or read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordsLifecycleProjectionV1 {
    pub commitments: EvaluationCommitmentsV1,
    pub outputs: BoundedOutputs,
    pub reservations: ReservationSetV1,
    pub workflow_id: WorkflowId,
    pub domain_id: DomainId,
    pub executor_audience: ExecutorAudienceId,
    pub reservation_algebra_id: ReservationAlgebraId,
    pub capacity: CapacitySnapshotV1,
}

/// Bindings available only after exact Auths authorization and construction
/// of the immutable records decision receipt.
pub struct RecordsLifecycleDecisionBindings<'a> {
    pub core_authorization_digest: &'a str,
    pub decision_receipt_digest: &'a str,
    pub implementation_build_digest: &'a str,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecordsLifecycleProjectionError {
    #[error("records decision is not authorized")]
    NotAuthorized,
    #[error("records lifecycle payload is not canonical")]
    Canonicalization,
    #[error("records lifecycle digest is malformed")]
    InvalidDigest,
    #[error("records lifecycle projection violates the shared contract")]
    InvalidProjection,
}

/// Shared lifecycle store plus the read needed for replay and recovery.
pub trait RecordsLifecycleStore: LifecycleStore + Send + Sync {
    fn load_records_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError>;
}

/// Domain-local registry selecting one durable capacity namespace per policy
/// digest. Delivery adapters never participate in this selection.
pub trait RecordsLifecycleRegistry: Send + Sync {
    fn for_policy(
        &self,
        policy: &BoundedRecordApiPolicyV1,
    ) -> Result<Arc<dyn RecordsLifecycleStore>, StoreError>;
}

impl<T: RecordsLifecycleRegistry + ?Sized> RecordsLifecycleRegistry for Arc<T> {
    fn for_policy(
        &self,
        policy: &BoundedRecordApiPolicyV1,
    ) -> Result<Arc<dyn RecordsLifecycleStore>, StoreError> {
        (**self).for_policy(policy)
    }
}

impl RecordsLifecycleProjectionInput<'_> {
    /// Projects an authorized records decision into canonical shared inputs.
    #[allow(
        clippy::too_many_lines,
        reason = "the complete create/read reservation projection stays visible as one audited unit"
    )]
    pub fn project(&self) -> Result<RecordsLifecycleProjectionV1, RecordsLifecycleProjectionError> {
        if self.decision.class != DecisionClass::Authorized {
            return Err(RecordsLifecycleProjectionError::NotAuthorized);
        }
        let commitments = project_commitments(self)?;
        let action_digest = commitments.exact_action_digest();
        let policy_digest = commitments.policy_commitment().policy_digest();
        let evidence_digest = commitments.evidence_digest();
        let (mut intents, capacity, obligation_schema, obligation_id) = match self.action {
            RecordsLifecycleAction::Create(action) => {
                let value_bytes =
                    u64::try_from(canonical_json(&action.customer).map_err(canonical)?.len())
                        .map_err(invalid)?;
                let intents = vec![
                    additive_intent(
                        "create-bytes",
                        CREATE_INTENT_SCHEMA_ID,
                        "created-bytes",
                        value_bytes,
                        action_digest,
                        policy_digest,
                        evidence_digest,
                    )?,
                    additive_intent(
                        "create-unit",
                        CREATE_INTENT_SCHEMA_ID,
                        "create-unit",
                        1,
                        action_digest,
                        policy_digest,
                        evidence_digest,
                    )?,
                ];
                let capacity = vec![
                    additive_capacity(
                        policy_digest,
                        "created-bytes",
                        self.policy.maximum_created_bytes,
                    )?,
                    additive_capacity(
                        policy_digest,
                        "create-unit",
                        u64::from(self.policy.maximum_creates),
                    )?,
                ];
                (
                    intents,
                    capacity,
                    CREATE_OBLIGATION_SCHEMA_ID,
                    "construct-exact-create-command",
                )
            }
            RecordsLifecycleAction::Read(_) => (
                vec![additive_intent(
                    "read-unit",
                    READ_INTENT_SCHEMA_ID,
                    "read-unit",
                    1,
                    action_digest,
                    policy_digest,
                    evidence_digest,
                )?],
                vec![additive_capacity(
                    policy_digest,
                    "read-unit",
                    u64::from(self.policy.maximum_reads),
                )?],
                READ_OBLIGATION_SCHEMA_ID,
                "construct-exact-read-command",
            ),
        };
        intents.sort_by(|left, right| left.intent_id().cmp(right.intent_id()));
        let action_bytes = self.action.canonical_bytes()?;
        let obligation = ObligationCommitmentV1::new(
            SchemaId::parse(obligation_schema).map_err(invalid)?,
            ObligationId::parse(obligation_id).map_err(invalid)?,
            ObligationClass::CommandConstruction,
            action_digest,
            u32::try_from(action_bytes.len()).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let outputs = BoundedOutputs::new(
            intents,
            vec![obligation],
            commitment(
                &canonical_digest(&BudgetCommitment {
                    maximum_creates: self.policy.maximum_creates,
                    maximum_reads: self.policy.maximum_reads,
                    maximum_created_bytes: self.policy.maximum_created_bytes,
                })
                .map_err(canonical)?,
            )?,
            commitment(&sha256(&action_bytes))?,
        )
        .map_err(invalid)?;
        let workflow_id = shared_workflow_id(self.action, policy_digest)?;
        let domain_id = DomainId::parse(DOMAIN_ID).map_err(invalid)?;
        let executor_audience =
            ExecutorAudienceId::parse(self.action.executor_audience()).map_err(invalid)?;
        let reservation_algebra_id =
            ReservationAlgebraId::parse(RESERVATION_ALGEBRA_ID).map_err(invalid)?;
        let reservations = ReservationSetV1::derive(
            &workflow_id,
            &domain_id,
            commitments.profile_id(),
            commitments.policy_commitment().evaluator_semantic_id(),
            &executor_audience,
            &reservation_algebra_id,
            &outputs,
        )
        .map_err(invalid)?;
        Ok(RecordsLifecycleProjectionV1 {
            commitments,
            outputs,
            reservations,
            workflow_id,
            domain_id,
            executor_audience,
            reservation_algebra_id,
            capacity: CapacitySnapshotV1::new(capacity).map_err(invalid)?,
        })
    }
}

impl RecordsLifecycleProjectionV1 {
    pub fn into_decision_input(
        self,
        bindings: &RecordsLifecycleDecisionBindings<'_>,
    ) -> Result<DecisionInputV1, RecordsLifecycleProjectionError> {
        let action_digest = self.commitments.exact_action_digest();
        let policy_digest = self.commitments.policy_commitment().policy_digest();
        let lifecycle_id = derived_identifier(
            b"AUTHS-RECORDS-LIFECYCLE\x00\x01",
            self.workflow_id.as_str(),
            action_digest,
            policy_digest,
        );
        let execution_id = derived_identifier(
            b"AUTHS-RECORDS-EXECUTION\x00\x01",
            self.workflow_id.as_str(),
            action_digest,
            policy_digest,
        );
        Ok(DecisionInputV1 {
            core_authorized: true,
            core_authorization_digest: commitment(bindings.core_authorization_digest)?,
            workflow_id: self.workflow_id,
            lifecycle_id: LifecycleId::parse(&lifecycle_id).map_err(invalid)?,
            execution_id: ExecutionId::parse(&execution_id).map_err(invalid)?,
            domain_id: self.domain_id,
            executor_audience: self.executor_audience,
            reservation_algebra_id: self.reservation_algebra_id,
            commitments: self.commitments,
            outputs: self.outputs,
            reservations: self.reservations,
            decision_receipt_digest: DecisionReceiptDigest::new(digest_bytes(
                bindings.decision_receipt_digest,
            )?),
            domain_decision_receipt_digest: DomainReceiptDigest::new(digest_bytes(
                bindings.decision_receipt_digest,
            )?),
            implementation_id: ImplementationId::parse(IMPLEMENTATION_ID).map_err(invalid)?,
            implementation_build_digest: commitment(bindings.implementation_build_digest)?,
            expires_at: VerifierTime::from_unix_seconds(bindings.expires_at),
            cancellation: CancellationDisposition::BeforeAttemptAllowed,
        })
    }

    #[must_use]
    pub fn transition_context(&self, verifier_time: u64) -> TransitionContextV1 {
        TransitionContextV1 {
            verifier_time: VerifierTime::from_unix_seconds(verifier_time),
            executed_configuration: self.commitments.executed_configuration().clone(),
            revocation: RevocationSnapshotV1 {
                revoked: false,
                snapshot_digest: commit_bytes(b"auths.records.revocation-not-configured/1"),
            },
            capacity: self.capacity.clone(),
        }
    }
}

fn project_commitments(
    input: &RecordsLifecycleProjectionInput<'_>,
) -> Result<EvaluationCommitmentsV1, RecordsLifecycleProjectionError> {
    let action_digest = commitment(&input.action.digest()?)?;
    let policy_digest = commitment(&input.policy.digest().map_err(canonical)?)?;
    let presentation_bytes = canonical_json(input.presentation).map_err(canonical)?;
    let evidence_digest = commitment(&sha256(&presentation_bytes))?;
    Ok(EvaluationCommitmentsV1::new(
        ProfileId::parse(&format!(
            "{}/{}",
            input.action.profile_id(),
            PROFILE_VERSION
        ))
        .map_err(invalid)?,
        action_digest,
        PolicyCommitmentV1::new(
            PolicyTypeId::parse(POLICY_TYPE_ID).map_err(invalid)?,
            u16::try_from(input.policy.policy_version).map_err(invalid)?,
            CanonicalizationId::parse(CANONICALIZATION_ID).map_err(invalid)?,
            policy_digest,
            EvaluatorSemanticId::parse(input.action.evaluator_id()).map_err(invalid)?,
        )
        .map_err(invalid)?,
        SchemaId::parse(EVIDENCE_SCHEMA_ID).map_err(invalid)?,
        evidence_digest,
        EvidenceSourceId::parse(EVIDENCE_SOURCE_ID).map_err(invalid)?,
        VerifierTime::from_unix_seconds(input.presentation.input.created_at),
        SchemaId::parse(STATE_SCHEMA_ID).map_err(invalid)?,
        commit_bytes(b"auths.records.no-protected-state-inspected/1"),
        VerifierTime::from_unix_seconds(input.verifier_time),
        configuration_commitment(input.required_configuration, false)?,
        configuration_commitment(input.executed_configuration, true)?,
    ))
}

fn configuration_commitment(
    configuration: &RecordsApiVerifierConfigurationV1,
    executed: bool,
) -> Result<ConfigurationCommitmentV1, RecordsLifecycleProjectionError> {
    Ok(ConfigurationCommitmentV1::new(
        ConfigurationSemanticId::parse(CONFIGURATION_SEMANTIC_ID).map_err(invalid)?,
        CanonicalizationId::parse(CANONICALIZATION_ID).map_err(invalid)?,
        commitment(&configuration.digest().map_err(canonical)?)?,
        executed
            .then(|| ImplementationId::parse(IMPLEMENTATION_ID))
            .transpose()
            .map_err(invalid)?,
    ))
}

#[derive(Serialize)]
#[allow(
    clippy::struct_field_names,
    reason = "field names mirror the committed policy JSON"
)]
struct BudgetCommitment {
    maximum_creates: u32,
    maximum_reads: u32,
    maximum_created_bytes: u64,
}

#[allow(clippy::too_many_arguments)]
fn additive_intent(
    intent_id: &str,
    schema_id: &str,
    unit_id: &str,
    amount: u64,
    action_digest: CommitmentDigest,
    policy_digest: CommitmentDigest,
    evidence_digest: CommitmentDigest,
) -> Result<ReservationIntentCommitmentV1, RecordsLifecycleProjectionError> {
    #[derive(Serialize)]
    struct Payload<'a> {
        unit: &'a str,
        amount: u64,
    }
    let payload = Payload {
        unit: unit_id,
        amount,
    };
    let bytes = canonical_json(&payload).map_err(canonical)?;
    ReservationIntentCommitmentV1::new(
        SchemaId::parse(schema_id).map_err(invalid)?,
        IntentId::parse(intent_id).map_err(invalid)?,
        policy_digest,
        ReservationKind::additive(UnitId::parse(unit_id).map_err(invalid)?, amount)
            .map_err(invalid)?,
        None,
        action_digest,
        policy_digest,
        evidence_digest,
        commitment(&sha256(&bytes))?,
        u32::try_from(bytes.len()).map_err(invalid)?,
    )
    .map_err(invalid)
}

fn additive_capacity(
    scope_digest: CommitmentDigest,
    unit_id: &str,
    ceiling: u64,
) -> Result<CapacityEntryV1, RecordsLifecycleProjectionError> {
    Ok(CapacityEntryV1::Additive {
        scope_digest,
        window_digest: None,
        unit: UnitId::parse(unit_id).map_err(invalid)?,
        ceiling,
        committed: 0,
        active: 0,
    })
}

fn shared_workflow_id(
    action: RecordsLifecycleAction<'_>,
    policy_digest: CommitmentDigest,
) -> Result<WorkflowId, RecordsLifecycleProjectionError> {
    let mut hasher = Sha256::new();
    hasher.update(b"AUTHS-RECORDS-SHARED-WORKFLOW\x00\x01");
    hasher.update(action.profile_id().as_bytes());
    hasher.update(action.digest()?.as_bytes());
    hasher.update(policy_digest.as_bytes());
    WorkflowId::parse(&hex::encode(hasher.finalize())).map_err(invalid)
}

fn commitment(value: &str) -> Result<CommitmentDigest, RecordsLifecycleProjectionError> {
    Ok(CommitmentDigest::new(digest_bytes(value)?))
}

fn digest_bytes(value: &str) -> Result<[u8; 32], RecordsLifecycleProjectionError> {
    hex::decode(value)
        .map_err(|_| RecordsLifecycleProjectionError::InvalidDigest)?
        .try_into()
        .map_err(|_| RecordsLifecycleProjectionError::InvalidDigest)
}

fn commit_bytes(value: &[u8]) -> CommitmentDigest {
    CommitmentDigest::new(Sha256::digest(value).into())
}

fn derived_identifier(
    domain: &[u8],
    workflow_id: &str,
    action_digest: CommitmentDigest,
    policy_digest: CommitmentDigest,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(workflow_id.as_bytes());
    hasher.update(action_digest.as_bytes());
    hasher.update(policy_digest.as_bytes());
    hex::encode(hasher.finalize())
}

fn canonical(_: impl core::fmt::Debug) -> RecordsLifecycleProjectionError {
    RecordsLifecycleProjectionError::Canonicalization
}

fn invalid(_: impl core::fmt::Debug) -> RecordsLifecycleProjectionError {
    RecordsLifecycleProjectionError::InvalidProjection
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use auths_lifecycle::{StoreTransactionV1, TransitionCommandV1, execute_store_transaction};
    use auths_stores::{InMemoryLifecycleStore, LifecycleCapacityRuleV1};

    use super::*;
    use crate::{
        CREATE_OPERATION, CreateEvaluation, CustomerRecordV1, PresentationInputV1, READ_OPERATION,
        ReadEvaluation, ReadField, ReadRecordV1, RecordIdentifier, demo_configuration,
        evaluate_create, evaluate_read,
    };

    #[test]
    fn concurrent_final_create_unit_has_one_reservation_winner() {
        let configuration = demo_configuration("https://records");
        let (policy, first_action, presentation) = fixture(&configuration);
        let mut second_action = first_action.clone();
        second_action.record_id = RecordIdentifier::parse("demo-2").unwrap();
        second_action.nonce = "fedcba9876543210".into();
        let first = projection(&policy, &configuration, &presentation, &first_action);
        let second = projection(&policy, &configuration, &presentation, &second_action);
        assert_ne!(first.workflow_id, second.workflow_id);

        let scope = commitment(&policy.digest().unwrap()).unwrap();
        let store = Arc::new(
            InMemoryLifecycleStore::new(
                vec![
                    LifecycleCapacityRuleV1::Additive {
                        scope_digest: scope,
                        window_digest: None,
                        unit: UnitId::parse("create-unit").unwrap(),
                        ceiling: 1,
                    },
                    LifecycleCapacityRuleV1::Additive {
                        scope_digest: scope,
                        window_digest: None,
                        unit: UnitId::parse("created-bytes").unwrap(),
                        ceiling: policy.maximum_created_bytes,
                    },
                ],
                8,
            )
            .unwrap(),
        );
        let first = decision_material(first);
        let second = decision_material(second);
        for (workflow_id, context, input) in [&first, &second] {
            execute_store_transaction(
                &*store,
                &StoreTransactionV1 {
                    workflow_id: workflow_id.clone(),
                    expected_revision: None,
                    command: TransitionCommandV1::RecordDecision(Box::new(input.clone())),
                    context: context.clone(),
                },
            )
            .unwrap();
        }

        let barrier = Arc::new(Barrier::new(3));
        let handles = [first, second].map(|(workflow_id, context, _)| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                execute_store_transaction(
                    &*store,
                    &StoreTransactionV1 {
                        workflow_id,
                        expected_revision: Some(1),
                        command: TransitionCommandV1::Reserve,
                        context,
                    },
                )
            })
        });
        barrier.wait();
        assert_eq!(
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap())
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_final_read_unit_has_one_reservation_winner() {
        let configuration = demo_configuration("https://records");
        let (policy, create, mut presentation) = fixture(&configuration);
        let first_action = read_action(&policy, &configuration, "0123456789abcdef");
        let second_action = read_action(&policy, &configuration, "fedcba9876543210");
        presentation.input.operation_id = READ_OPERATION.into();
        presentation.input.canonical_action_digest = first_action.digest().unwrap();
        let first = read_projection(&policy, &configuration, &presentation, &first_action);
        presentation.input.canonical_action_digest = second_action.digest().unwrap();
        let second = read_projection(&policy, &configuration, &presentation, &second_action);
        assert_ne!(first.workflow_id, second.workflow_id);
        assert_eq!(create.policy_digest, first_action.policy_digest);

        let scope = commitment(&policy.digest().unwrap()).unwrap();
        let store = Arc::new(
            InMemoryLifecycleStore::new(
                vec![LifecycleCapacityRuleV1::Additive {
                    scope_digest: scope,
                    window_digest: None,
                    unit: UnitId::parse("read-unit").unwrap(),
                    ceiling: 1,
                }],
                8,
            )
            .unwrap(),
        );
        let first = decision_material(first);
        let second = decision_material(second);
        for (workflow_id, context, input) in [&first, &second] {
            execute_store_transaction(
                &*store,
                &StoreTransactionV1 {
                    workflow_id: workflow_id.clone(),
                    expected_revision: None,
                    command: TransitionCommandV1::RecordDecision(Box::new(input.clone())),
                    context: context.clone(),
                },
            )
            .unwrap();
        }
        let barrier = Arc::new(Barrier::new(3));
        let handles = [first, second].map(|(workflow_id, context, _)| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                execute_store_transaction(
                    &*store,
                    &StoreTransactionV1 {
                        workflow_id,
                        expected_revision: Some(1),
                        command: TransitionCommandV1::Reserve,
                        context,
                    },
                )
            })
        });
        barrier.wait();
        assert_eq!(
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap())
                .count(),
            1
        );
    }

    fn projection<'a>(
        policy: &'a BoundedRecordApiPolicyV1,
        configuration: &'a RecordsApiVerifierConfigurationV1,
        presentation: &'a RecordsPresentationV1,
        action: &'a CreateRecordV1,
    ) -> RecordsLifecycleProjectionV1 {
        let decision = evaluate_create(&CreateEvaluation {
            action,
            policy,
            required_configuration: configuration,
            executed_configuration: configuration,
            now: 10,
        });
        RecordsLifecycleProjectionInput {
            action: RecordsLifecycleAction::Create(action),
            policy,
            presentation,
            required_configuration: configuration,
            executed_configuration: configuration,
            decision: &decision,
            verifier_time: 10,
        }
        .project()
        .unwrap()
    }

    fn read_projection<'a>(
        policy: &'a BoundedRecordApiPolicyV1,
        configuration: &'a RecordsApiVerifierConfigurationV1,
        presentation: &'a RecordsPresentationV1,
        action: &'a ReadRecordV1,
    ) -> RecordsLifecycleProjectionV1 {
        let decision = evaluate_read(&ReadEvaluation {
            action,
            policy,
            required_configuration: configuration,
            executed_configuration: configuration,
            now: 10,
        });
        RecordsLifecycleProjectionInput {
            action: RecordsLifecycleAction::Read(action),
            policy,
            presentation,
            required_configuration: configuration,
            executed_configuration: configuration,
            decision: &decision,
            verifier_time: 10,
        }
        .project()
        .unwrap()
    }

    fn read_action(
        policy: &BoundedRecordApiPolicyV1,
        configuration: &RecordsApiVerifierConfigurationV1,
        nonce: &str,
    ) -> ReadRecordV1 {
        ReadRecordV1 {
            profile: "auths.demo.records.read/1".into(),
            namespace_id: policy.namespace_id.clone(),
            record_id: RecordIdentifier::parse("demo-1").unwrap(),
            allowed_fields: vec![ReadField::Customer, ReadField::RecordId],
            maximum_response_bytes: 4096,
            expected_record_version: 1,
            policy_digest: policy.digest().unwrap(),
            required_evaluator: "auths.records.read-evaluator/1".into(),
            required_configuration_digest: configuration.digest().unwrap(),
            executor_audience: policy.executor_audience.clone(),
            expires_at: 50,
            nonce: nonce.into(),
        }
    }

    fn decision_material(
        projection: RecordsLifecycleProjectionV1,
    ) -> (WorkflowId, TransitionContextV1, DecisionInputV1) {
        let workflow_id = projection.workflow_id.clone();
        let context = projection.transition_context(10);
        let input = projection
            .into_decision_input(&RecordsLifecycleDecisionBindings {
                core_authorization_digest: &"a".repeat(64),
                decision_receipt_digest: &"b".repeat(64),
                implementation_build_digest: &"c".repeat(64),
                expires_at: 50,
            })
            .unwrap();
        (workflow_id, context, input)
    }

    fn fixture(
        configuration: &RecordsApiVerifierConfigurationV1,
    ) -> (
        BoundedRecordApiPolicyV1,
        CreateRecordV1,
        RecordsPresentationV1,
    ) {
        let policy = BoundedRecordApiPolicyV1 {
            policy_type: "auths.demo.bounded-record-api-policy".into(),
            policy_version: 1,
            policy_id: "policy-1".into(),
            namespace_id: RecordIdentifier::parse("visitor").unwrap(),
            presenter_principal: "key:demo".into(),
            allowed_operations: vec![CREATE_OPERATION.into(), READ_OPERATION.into()],
            allowed_record_ids: Vec::new(),
            allowed_record_id_prefixes: vec!["demo-".into()],
            maximum_value_bytes: 1024,
            maximum_response_bytes: 4096,
            allowed_read_fields: vec![ReadField::Customer, ReadField::RecordId],
            maximum_creates: 1,
            maximum_reads: 1,
            maximum_created_bytes: 4096,
            maximum_disclosed_bytes: 4096,
            fixed_and_rolling_budgets: Vec::new(),
            valid_from: 0,
            expires_at: 100,
            maximum_action_lifetime_seconds: 100,
            maximum_presentation_lifetime_seconds: 100,
            maximum_evidence_age_seconds: 100,
            executor_audience: "https://records".into(),
        };
        let action = CreateRecordV1 {
            profile: "auths.demo.records.create/1".into(),
            namespace_id: policy.namespace_id.clone(),
            record_id: RecordIdentifier::parse("demo-1").unwrap(),
            customer: CustomerRecordV1 {
                age: 25,
                name: "Bob".into(),
                notes: "Demo customer".into(),
                occupation: "Sales".into(),
            },
            value_encoding: "auths.demo.customer-record/1".into(),
            expected_absent: true,
            policy_digest: policy.digest().unwrap(),
            required_evaluator: "auths.records.create-evaluator/1".into(),
            required_configuration_digest: configuration.digest().unwrap(),
            executor_audience: policy.executor_audience.clone(),
            expires_at: 50,
            nonce: "0123456789abcdef".into(),
        };
        let presentation = RecordsPresentationV1 {
            input: PresentationInputV1 {
                presentation_version: "auths.records-presentation/1".into(),
                proof_digest: "d".repeat(64),
                presenter_principal: policy.presenter_principal.clone(),
                executor_audience: policy.executor_audience.clone(),
                operation_id: CREATE_OPERATION.into(),
                canonical_action_digest: action.digest().unwrap(),
                challenge: "e".repeat(64),
                created_at: 9,
                expires_at: 20,
                presentation_nonce: "presentation-1".into(),
            },
            presenter_public_key: "f".repeat(64),
            signature: "0".repeat(128),
        };
        (policy, action, presentation)
    }
}
