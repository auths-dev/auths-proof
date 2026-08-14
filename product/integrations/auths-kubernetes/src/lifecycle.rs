//! Exact projection from Kubernetes rollout semantics into shared policy and
//! lifecycle contracts.
//!
//! Kubernetes keeps ownership of rollout actions, cluster evidence, stable
//! decisions, provider behavior, reconciliation, and receipts. Shared crates
//! receive only canonical commitments and the domain-independent exclusive
//! reservation mechanism.

use auths_bounded_policy::{
    BoundedOutputs, CanonicalizationId, CommitmentDigest, ConfigurationCommitmentV1,
    ConfigurationSemanticId, EvaluationCommitmentsV1, EvaluatorSemanticId, EvidenceSourceId,
    ImplementationId, IntentId, ObligationClass, ObligationCommitmentV1, ObligationId,
    PolicyCommitmentV1, PolicyTypeId, ProfileId, ReservationIntentCommitmentV1, ReservationKind,
    SchemaId, VerifierTime,
};
use auths_lifecycle::{
    CancellationDisposition, CapacityEntryV1, CapacitySnapshotV1, DecisionInputV1,
    DecisionReceiptDigest, DomainId, DomainReceiptDigest, ExecutionId, ExecutorAudienceId,
    LifecycleId, ReservationAlgebraId, ReservationSetV1, RevocationSnapshotV1, TransitionContextV1,
    WorkflowId,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json, sha256},
    decision::{Decision, DecisionClass},
    types::{
        DigestHex, KubernetesEvidenceV1, KubernetesName, KubernetesVerifierConfiguration,
        KubernetesWorkloadRolloutV1, PROFILE_VERSION,
    },
};

pub const SHARED_PROFILE_ID: &str = "auths.kubernetes.workload-rollout/1";
pub const POLICY_TYPE_ID: &str = "auths.kubernetes.rollout-policy/1";
pub const EVALUATOR_SEMANTIC_ID: &str = "auths.kubernetes.workload-rollout.evaluate/1";
pub const IMPLEMENTATION_ID: &str = "auths-kubernetes/shared-lifecycle-production/1";
pub const CANONICALIZATION_ID: &str = "rfc8785-sha256-v1";
pub const CONFIGURATION_SEMANTIC_ID: &str = "auths.kubernetes.verifier-configuration/1";
pub const EVIDENCE_SCHEMA_ID: &str = "auths.kubernetes.rollout-evidence/1";
pub const EVIDENCE_SOURCE_ID: &str = "kubernetes-api-deployment-read-dry-run/1";
pub const STATE_SCHEMA_ID: &str = "auths.kubernetes.rollout-state-snapshot/1";
pub const INTENT_SCHEMA_ID: &str = "auths.kubernetes.rollout-exclusive-intent/1";
pub const RESERVATION_ALGEBRA_ID: &str = "auths.kubernetes.deployment-exclusive/1";
pub const OBLIGATION_SCHEMA_ID: &str = "auths.kubernetes.verified-rollout-command/1";
pub const PROVIDER_CONTRACT_ID: &str = "auths.kubernetes.server-side-apply/1";
pub const DOMAIN_ID: &str = "kubernetes";

/// Complete domain inputs to the pure commitment projection.
pub struct KubernetesLifecycleProjectionInput<'a> {
    pub action: &'a KubernetesWorkloadRolloutV1,
    pub evidence: &'a KubernetesEvidenceV1,
    pub required_configuration: &'a KubernetesVerifierConfiguration,
    pub executed_configuration: &'a KubernetesVerifierConfiguration,
    pub decision: &'a Decision,
    pub verifier_time: u64,
}

/// Validated shared projection of one authorized Kubernetes rollout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesLifecycleProjectionV1 {
    pub commitments: EvaluationCommitmentsV1,
    pub outputs: BoundedOutputs,
    pub reservations: ReservationSetV1,
    pub workflow_id: WorkflowId,
    pub domain_id: DomainId,
    pub executor_audience: ExecutorAudienceId,
    pub reservation_algebra_id: ReservationAlgebraId,
    pub capacity: CapacitySnapshotV1,
}

/// Durable bindings available only after Auths authorization and decision
/// receipt construction.
pub struct KubernetesLifecycleDecisionBindings<'a> {
    pub core_authorization_digest: &'a DigestHex,
    pub decision_receipt_digest: &'a DigestHex,
    pub implementation_build_digest: &'a DigestHex,
    pub expires_at: u64,
}

/// Closed failure before shared state can be persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum KubernetesLifecycleProjectionError {
    #[error("Kubernetes decision is not authorized")]
    NotAuthorized,
    #[error("Kubernetes lifecycle payload is not canonical")]
    Canonicalization,
    #[error("Kubernetes lifecycle digest is malformed")]
    InvalidDigest,
    #[error("Kubernetes lifecycle projection violates the shared contract")]
    InvalidProjection,
}

impl KubernetesLifecycleProjectionInput<'_> {
    /// Projects one authorized domain decision into shared commitments.
    ///
    /// # Errors
    ///
    /// Fails closed for a non-authorized decision, invalid identifiers,
    /// malformed canonical payloads, or exceeded shared limits.
    pub fn project(
        &self,
    ) -> Result<KubernetesLifecycleProjectionV1, KubernetesLifecycleProjectionError> {
        if self.decision.class != DecisionClass::Authorized {
            return Err(KubernetesLifecycleProjectionError::NotAuthorized);
        }
        let commitments = project_commitments(self)?;
        let scope = reservation_scope(
            self.action.cluster_audience(),
            self.action.namespace_name(),
            self.action.resource_name(),
        );
        let scope_bytes = canonical_json(&scope).map_err(canonical)?;
        let scope_digest = commitment(&sha256(&scope_bytes))?;
        let action_bytes = self.action.canonical_bytes().map_err(canonical)?;
        let action_digest = commitments.exact_action_digest();
        let policy_digest = commitments.policy_commitment().policy_digest();
        let evidence_digest = commitments.evidence_digest();
        let reservation = ReservationIntentCommitmentV1::new(
            SchemaId::parse(INTENT_SCHEMA_ID).map_err(invalid)?,
            IntentId::parse("deployment-rollout-exclusive").map_err(invalid)?,
            scope_digest,
            ReservationKind::Exclusive,
            None,
            action_digest,
            policy_digest,
            evidence_digest,
            commitment(&canonical_digest(&scope).map_err(canonical)?)?,
            u32::try_from(scope_bytes.len()).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let obligation = ObligationCommitmentV1::new(
            SchemaId::parse(OBLIGATION_SCHEMA_ID).map_err(invalid)?,
            ObligationId::parse("construct-exact-server-side-apply").map_err(invalid)?,
            ObligationClass::CommandConstruction,
            action_digest,
            u32::try_from(action_bytes.len()).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let outputs = BoundedOutputs::new(
            vec![reservation],
            vec![obligation],
            commitment(&canonical_digest(&scope).map_err(canonical)?)?,
            commitment(&sha256(&action_bytes))?,
        )
        .map_err(invalid)?;
        let workflow_id = WorkflowId::parse(self.action.workflow_id()).map_err(invalid)?;
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
        let capacity = CapacitySnapshotV1::new(vec![CapacityEntryV1::Exclusive {
            scope_digest,
            window_digest: None,
            live_owner: None,
        }])
        .map_err(invalid)?;
        Ok(KubernetesLifecycleProjectionV1 {
            commitments,
            outputs,
            reservations,
            workflow_id,
            domain_id,
            executor_audience,
            reservation_algebra_id,
            capacity,
        })
    }
}

impl KubernetesLifecycleProjectionV1 {
    /// Consumes the projection into one complete shared decision input.
    ///
    /// # Errors
    ///
    /// Rejects invalid exact digests or derived identifiers.
    pub fn into_decision_input(
        self,
        bindings: &KubernetesLifecycleDecisionBindings<'_>,
    ) -> Result<DecisionInputV1, KubernetesLifecycleProjectionError> {
        let action_digest = self.commitments.exact_action_digest();
        let policy_digest = self.commitments.policy_commitment().policy_digest();
        let lifecycle_id = derived_identifier(
            b"AUTHS-KUBERNETES-LIFECYCLE\x00\x01",
            self.workflow_id.as_str(),
            action_digest,
            policy_digest,
        );
        let execution_id = derived_identifier(
            b"AUTHS-KUBERNETES-EXECUTION\x00\x01",
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
            recovery_reference_digest: auths_lifecycle::RecoveryReferenceDigest::new(digest_bytes(
                bindings.decision_receipt_digest,
            )?),
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

    /// Constructs the explicit transition context for this evaluation.
    #[must_use]
    pub fn transition_context(&self, verifier_time: u64) -> TransitionContextV1 {
        TransitionContextV1 {
            verifier_time: VerifierTime::from_unix_seconds(verifier_time),
            executed_configuration: self.commitments.executed_configuration().clone(),
            revocation: RevocationSnapshotV1 {
                revoked: false,
                snapshot_digest: commit_bytes(b"auths.kubernetes.revocation-not-configured/1"),
            },
            capacity: self.capacity.clone(),
        }
    }
}

/// Returns the exact exclusive capacity scope used by the shared store.
///
/// # Errors
///
/// Fails only if canonical scope construction fails.
pub fn reservation_scope_digest(
    cluster_audience: &str,
    namespace: &KubernetesName,
    deployment: &KubernetesName,
) -> Result<CommitmentDigest, KubernetesLifecycleProjectionError> {
    commitment(
        &canonical_digest(&reservation_scope(cluster_audience, namespace, deployment))
            .map_err(canonical)?,
    )
}

fn project_commitments(
    input: &KubernetesLifecycleProjectionInput<'_>,
) -> Result<EvaluationCommitmentsV1, KubernetesLifecycleProjectionError> {
    let action_digest = commitment(&input.action.digest().map_err(canonical)?)?;
    let policy_digest = commitment(&input.required_configuration.digest().map_err(canonical)?)?;
    let evidence_digest = commitment(&input.evidence.digest().map_err(canonical)?)?;
    Ok(EvaluationCommitmentsV1::new(
        ProfileId::parse(SHARED_PROFILE_ID).map_err(invalid)?,
        action_digest,
        PolicyCommitmentV1::new(
            PolicyTypeId::parse(POLICY_TYPE_ID).map_err(invalid)?,
            PROFILE_VERSION,
            CanonicalizationId::parse(CANONICALIZATION_ID).map_err(invalid)?,
            policy_digest,
            EvaluatorSemanticId::parse(EVALUATOR_SEMANTIC_ID).map_err(invalid)?,
        )
        .map_err(invalid)?,
        SchemaId::parse(EVIDENCE_SCHEMA_ID).map_err(invalid)?,
        evidence_digest,
        EvidenceSourceId::parse(EVIDENCE_SOURCE_ID).map_err(invalid)?,
        VerifierTime::from_unix_seconds(input.evidence.observed_at),
        SchemaId::parse(STATE_SCHEMA_ID).map_err(invalid)?,
        evidence_digest,
        VerifierTime::from_unix_seconds(input.verifier_time),
        configuration_commitment(input.required_configuration, false)?,
        configuration_commitment(input.executed_configuration, true)?,
    ))
}

fn configuration_commitment(
    configuration: &KubernetesVerifierConfiguration,
    executed: bool,
) -> Result<ConfigurationCommitmentV1, KubernetesLifecycleProjectionError> {
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
struct KubernetesReservationScope<'a> {
    cluster_audience: &'a str,
    namespace: &'a str,
    deployment: &'a str,
}

fn reservation_scope<'a>(
    cluster_audience: &'a str,
    namespace: &'a KubernetesName,
    deployment: &'a KubernetesName,
) -> KubernetesReservationScope<'a> {
    KubernetesReservationScope {
        cluster_audience,
        namespace: namespace.as_str(),
        deployment: deployment.as_str(),
    }
}

fn commitment(value: &DigestHex) -> Result<CommitmentDigest, KubernetesLifecycleProjectionError> {
    Ok(CommitmentDigest::new(digest_bytes(value)?))
}

fn digest_bytes(value: &DigestHex) -> Result<[u8; 32], KubernetesLifecycleProjectionError> {
    hex::decode(value.as_str())
        .map_err(|_| KubernetesLifecycleProjectionError::InvalidDigest)?
        .try_into()
        .map_err(|_| KubernetesLifecycleProjectionError::InvalidDigest)
}

fn commit_bytes(value: &[u8]) -> CommitmentDigest {
    CommitmentDigest::new(Sha256::digest(value).into())
}

fn derived_identifier(
    domain: &[u8],
    workflow: &str,
    action: CommitmentDigest,
    policy: CommitmentDigest,
) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((workflow.len() as u64).to_be_bytes());
    digest.update(workflow.as_bytes());
    digest.update(action.as_bytes());
    digest.update(policy.as_bytes());
    hex::encode(digest.finalize())
}

fn canonical(_: CanonicalError) -> KubernetesLifecycleProjectionError {
    KubernetesLifecycleProjectionError::Canonicalization
}

fn invalid<T>(_: T) -> KubernetesLifecycleProjectionError {
    KubernetesLifecycleProjectionError::InvalidProjection
}

#[cfg(test)]
mod tests {
    use auths_lifecycle::{
        LifecycleState, TransitionCommandV1, TransitionDisposition, apply_transition,
    };

    use super::*;
    use crate::{
        EvaluationContext, evaluate,
        receipts::decision_receipt,
        test_support::{NOW, fixture},
    };

    #[test]
    fn authorized_reference_decision_projects_exact_commitments() {
        let fixture = fixture();
        let decision = evaluate(&EvaluationContext {
            action: &fixture.action,
            evidence: &fixture.evidence,
            required_configuration: &fixture.configuration,
            executed_configuration: &fixture.configuration,
            request_audience: fixture.configuration.executor_audience(),
            now: NOW,
        });
        let projection = KubernetesLifecycleProjectionInput {
            action: &fixture.action,
            evidence: &fixture.evidence,
            required_configuration: &fixture.configuration,
            executed_configuration: &fixture.configuration,
            decision: &decision,
            verifier_time: NOW,
        }
        .project()
        .unwrap();
        assert_eq!(
            projection.commitments.profile_id().as_str(),
            SHARED_PROFILE_ID
        );
        assert_eq!(
            projection.commitments.exact_action_digest(),
            commitment(&fixture.action.digest().unwrap()).unwrap()
        );
        assert_eq!(projection.outputs.reservation_intents().len(), 1);
        assert!(matches!(
            projection.outputs.reservation_intents()[0].kind(),
            ReservationKind::Exclusive
        ));
        assert_eq!(projection.outputs.obligations().len(), 1);
    }

    #[test]
    fn decision_reserve_path_refines_reference_authorization() {
        let fixture = fixture();
        let receipt = decision_receipt(
            &fixture.action,
            &fixture.evidence,
            &fixture.configuration,
            &fixture.configuration,
            fixture.configuration.executor_audience(),
            NOW,
        )
        .unwrap();
        let projection = KubernetesLifecycleProjectionInput {
            action: &fixture.action,
            evidence: &fixture.evidence,
            required_configuration: &fixture.configuration,
            executed_configuration: &fixture.configuration,
            decision: &receipt.decision,
            verifier_time: NOW,
        }
        .project()
        .unwrap();
        let context = projection.transition_context(NOW);
        let input = projection
            .into_decision_input(&KubernetesLifecycleDecisionBindings {
                core_authorization_digest: &sha256(b"core"),
                decision_receipt_digest: &receipt.digest().unwrap(),
                implementation_build_digest: &sha256(b"build"),
                expires_at: fixture.action.expires_at(),
            })
            .unwrap();
        let recorded = apply_transition(
            None,
            &TransitionCommandV1::RecordDecision(Box::new(input)),
            &context,
        )
        .unwrap();
        let reserved = apply_transition(
            Some(&recorded.record),
            &TransitionCommandV1::Reserve,
            &context,
        )
        .unwrap();
        assert_eq!(recorded.disposition, TransitionDisposition::Applied);
        assert_eq!(reserved.record.state(), LifecycleState::Reserved);
    }

    #[test]
    fn denial_cannot_be_projected_as_eligible() {
        let fixture = fixture();
        let executed = fixture.configuration_with_maximum_replicas(4);
        let decision = evaluate(&EvaluationContext {
            action: &fixture.action,
            evidence: &fixture.evidence,
            required_configuration: &fixture.configuration,
            executed_configuration: &executed,
            request_audience: fixture.configuration.executor_audience(),
            now: NOW,
        });
        assert_eq!(
            KubernetesLifecycleProjectionInput {
                action: &fixture.action,
                evidence: &fixture.evidence,
                required_configuration: &fixture.configuration,
                executed_configuration: &executed,
                decision: &decision,
                verifier_time: NOW,
            }
            .project(),
            Err(KubernetesLifecycleProjectionError::NotAuthorized)
        );
    }
}
