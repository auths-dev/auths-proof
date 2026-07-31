//! Exact projection from OpenTofu saved-plan semantics into shared policy and
//! durable-lifecycle contracts.
//!
//! OpenTofu keeps ownership of saved artifacts, backend and provider state,
//! credentials, reconciliation, stable codes, and public receipts. Shared
//! crates receive only canonical commitments and the provider-independent
//! exclusive reservation mechanism.

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
    action::OpenTofuSavedPlanApplyV1,
    canonical::{canonical_digest, canonical_json, sha256},
    decision::{Decision, DecisionClass},
    types::{DigestHex, OpenTofuStateEvidenceV1, OpenTofuVerifierConfigurationV1, PROFILE_VERSION},
};

pub const SHARED_PROFILE_ID: &str = "auths.opentofu.saved-plan-apply/1";
pub const POLICY_TYPE_ID: &str = "auths.opentofu.saved-plan-policy/1";
pub const EVALUATOR_SEMANTIC_ID: &str = "auths.opentofu.saved-plan-apply.evaluate/1";
pub const IMPLEMENTATION_ID: &str = "auths-opentofu/shared-lifecycle-production/1";
pub const CANONICALIZATION_ID: &str = "rfc8785-sha256-v1";
pub const CONFIGURATION_SEMANTIC_ID: &str = "auths.opentofu.verifier-configuration/1";
pub const EVIDENCE_SCHEMA_ID: &str = "auths.opentofu.saved-plan-state-evidence/1";
pub const EVIDENCE_SOURCE_ID: &str = "opentofu-backend-state-and-lock-read/1";
pub const STATE_SCHEMA_ID: &str = "auths.opentofu.backend-state-snapshot/1";
pub const INTENT_SCHEMA_ID: &str = "auths.opentofu.backend-workspace-exclusive-intent/1";
pub const RESERVATION_ALGEBRA_ID: &str = "auths.opentofu.backend-workspace-state-exclusive/1";
pub const OBLIGATION_SCHEMA_ID: &str = "auths.opentofu.verified-saved-plan-command/1";
pub const PROVIDER_CONTRACT_ID: &str = "auths.opentofu.fixed-argv-saved-plan-apply/1";
pub const DOMAIN_ID: &str = "opentofu";

/// Complete domain inputs to the pure shared-contract projection.
pub struct OpenTofuLifecycleProjectionInput<'a> {
    pub action: &'a OpenTofuSavedPlanApplyV1,
    pub evidence: &'a OpenTofuStateEvidenceV1,
    pub required_configuration: &'a OpenTofuVerifierConfigurationV1,
    pub executed_configuration: &'a OpenTofuVerifierConfigurationV1,
    pub decision: &'a Decision,
    pub verifier_time: u64,
}

/// Validated shared projection of one authorized saved-plan apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenTofuLifecycleProjectionV1 {
    pub commitments: EvaluationCommitmentsV1,
    pub outputs: BoundedOutputs,
    pub reservations: ReservationSetV1,
    pub workflow_id: WorkflowId,
    pub domain_id: DomainId,
    pub executor_audience: ExecutorAudienceId,
    pub reservation_algebra_id: ReservationAlgebraId,
    pub capacity: CapacitySnapshotV1,
}

/// Durable bindings available only after Auths authorization and domain
/// decision-receipt construction.
pub struct OpenTofuLifecycleDecisionBindings<'a> {
    pub core_authorization_digest: &'a DigestHex,
    pub decision_receipt_digest: &'a DigestHex,
    pub implementation_build_digest: &'a DigestHex,
    pub expires_at: u64,
}

/// Closed failure before shared state can be persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OpenTofuLifecycleProjectionError {
    #[error("OpenTofu decision is not authorized")]
    NotAuthorized,
    #[error("OpenTofu lifecycle payload is not canonical")]
    Canonicalization,
    #[error("OpenTofu lifecycle digest is malformed")]
    InvalidDigest,
    #[error("OpenTofu lifecycle projection violates the shared contract")]
    InvalidProjection,
}

impl OpenTofuLifecycleProjectionInput<'_> {
    /// Projects one authorized domain decision into shared commitments.
    ///
    /// # Errors
    ///
    /// Fails closed for a non-authorized decision, invalid identifiers,
    /// malformed canonical payloads, or exceeded shared limits.
    pub fn project(
        &self,
    ) -> Result<OpenTofuLifecycleProjectionV1, OpenTofuLifecycleProjectionError> {
        if self.decision.class != DecisionClass::Authorized {
            return Err(OpenTofuLifecycleProjectionError::NotAuthorized);
        }
        let commitments = project_commitments(self)?;
        let scope = reservation_scope(self.action);
        let scope_bytes = canonical_json(&scope).map_err(canonical)?;
        let scope_digest = commitment(&sha256(&scope_bytes))?;
        let action_bytes = self.action.canonical_bytes().map_err(canonical)?;
        let action_digest = commitments.exact_action_digest();
        let policy_digest = commitments.policy_commitment().policy_digest();
        let evidence_digest = commitments.evidence_digest();
        let reservation = ReservationIntentCommitmentV1::new(
            SchemaId::parse(INTENT_SCHEMA_ID).map_err(invalid)?,
            IntentId::parse("backend-workspace-state-exclusive").map_err(invalid)?,
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
            ObligationId::parse("apply-exact-saved-plan").map_err(invalid)?,
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
        let workflow_id = WorkflowId::parse(self.action.nonce().as_str()).map_err(invalid)?;
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
        Ok(OpenTofuLifecycleProjectionV1 {
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

impl OpenTofuLifecycleProjectionV1 {
    /// Consumes the projection into one complete shared decision input.
    ///
    /// # Errors
    ///
    /// Rejects malformed exact digests or derived identifiers.
    pub fn into_decision_input(
        self,
        bindings: &OpenTofuLifecycleDecisionBindings<'_>,
    ) -> Result<DecisionInputV1, OpenTofuLifecycleProjectionError> {
        let action_digest = self.commitments.exact_action_digest();
        let policy_digest = self.commitments.policy_commitment().policy_digest();
        let lifecycle_id = derived_identifier(
            b"AUTHS-OPENTOFU-LIFECYCLE\x00\x01",
            self.workflow_id.as_str(),
            action_digest,
            policy_digest,
        );
        let execution_id = derived_identifier(
            b"AUTHS-OPENTOFU-EXECUTION\x00\x01",
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

    /// Constructs the explicit transition context for this evaluation.
    #[must_use]
    pub fn transition_context(&self, verifier_time: u64) -> TransitionContextV1 {
        TransitionContextV1 {
            verifier_time: VerifierTime::from_unix_seconds(verifier_time),
            executed_configuration: self.commitments.executed_configuration().clone(),
            revocation: RevocationSnapshotV1 {
                revoked: false,
                snapshot_digest: commit_bytes(b"auths.opentofu.revocation-not-configured/1"),
            },
            capacity: self.capacity.clone(),
        }
    }
}

/// Returns the exact backend/workspace/state capacity scope used by the shared
/// store.
///
/// # Errors
///
/// Fails only if canonical scope construction fails.
pub fn reservation_scope_digest(
    action: &OpenTofuSavedPlanApplyV1,
) -> Result<CommitmentDigest, OpenTofuLifecycleProjectionError> {
    commitment(&canonical_digest(&reservation_scope(action)).map_err(canonical)?)
}

fn project_commitments(
    input: &OpenTofuLifecycleProjectionInput<'_>,
) -> Result<EvaluationCommitmentsV1, OpenTofuLifecycleProjectionError> {
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
    configuration: &OpenTofuVerifierConfigurationV1,
    executed: bool,
) -> Result<ConfigurationCommitmentV1, OpenTofuLifecycleProjectionError> {
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
struct OpenTofuReservationScope<'a> {
    executor_audience: &'a str,
    backend_identity: &'a str,
    workspace: &'a str,
    state_lineage: &'a str,
    prior_state_serial: u64,
}

fn reservation_scope(action: &OpenTofuSavedPlanApplyV1) -> OpenTofuReservationScope<'_> {
    OpenTofuReservationScope {
        executor_audience: action.executor_audience(),
        backend_identity: action.backend_identity(),
        workspace: action.workspace(),
        state_lineage: action.state_lineage(),
        prior_state_serial: action.state_serial(),
    }
}

fn commitment(value: &DigestHex) -> Result<CommitmentDigest, OpenTofuLifecycleProjectionError> {
    Ok(CommitmentDigest::new(digest_bytes(value)?))
}

fn digest_bytes(value: &DigestHex) -> Result<[u8; 32], OpenTofuLifecycleProjectionError> {
    hex::decode(value.as_str())
        .map_err(|_| OpenTofuLifecycleProjectionError::InvalidDigest)?
        .try_into()
        .map_err(|_| OpenTofuLifecycleProjectionError::InvalidDigest)
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

fn canonical(_: impl core::fmt::Debug) -> OpenTofuLifecycleProjectionError {
    OpenTofuLifecycleProjectionError::Canonicalization
}

fn invalid(_: impl core::fmt::Debug) -> OpenTofuLifecycleProjectionError {
    OpenTofuLifecycleProjectionError::InvalidProjection
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        receipts::decision_receipt,
        test_support::{NOW, configuration_with_maximum_resource_changes, fixture},
    };

    #[test]
    fn authorized_projection_binds_backend_workspace_and_prior_state() {
        let fixture = fixture();
        let receipt = decision_receipt(
            &fixture.action,
            &fixture.projection,
            &fixture.evidence,
            &fixture.configuration,
            &fixture.configuration,
            fixture.configuration.executor_audience(),
            NOW,
        )
        .unwrap();
        let projection = OpenTofuLifecycleProjectionInput {
            action: &fixture.action,
            evidence: &fixture.evidence,
            required_configuration: &fixture.configuration,
            executed_configuration: &fixture.configuration,
            decision: &receipt.decision,
            verifier_time: NOW,
        }
        .project()
        .unwrap();

        assert_eq!(projection.outputs.reservation_intents().len(), 1);
        assert_eq!(
            projection.outputs.reservation_intents()[0].scope_digest(),
            reservation_scope_digest(&fixture.action).unwrap()
        );
        assert_eq!(
            projection.workflow_id.as_str(),
            fixture.action.nonce().as_str()
        );
    }

    #[test]
    fn reference_denial_cannot_project_to_shared_authority() {
        let fixture = fixture();
        let executed = configuration_with_maximum_resource_changes(5);
        let receipt = decision_receipt(
            &fixture.action,
            &fixture.projection,
            &fixture.evidence,
            &fixture.configuration,
            &executed,
            fixture.configuration.executor_audience(),
            NOW,
        )
        .unwrap();
        assert_eq!(receipt.decision.class, DecisionClass::Denied);
        assert_eq!(
            OpenTofuLifecycleProjectionInput {
                action: &fixture.action,
                evidence: &fixture.evidence,
                required_configuration: &fixture.configuration,
                executed_configuration: &executed,
                decision: &receipt.decision,
                verifier_time: NOW,
            }
            .project(),
            Err(OpenTofuLifecycleProjectionError::NotAuthorized)
        );
    }
}
