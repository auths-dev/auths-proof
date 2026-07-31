//! Exact projection from Radicle issue-patch semantics into the shared policy
//! and durable-lifecycle contracts.
//!
//! Radicle keeps ownership of repository and collaborative-object identity,
//! candidate inspection, synchronized evidence, signer custody, publication,
//! announcement, propagation observation, reconciliation, stable codes, and
//! public receipts. Shared crates receive only canonical commitments and two
//! atomic exclusive reservations.

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
    LifecycleId, LifecycleRecordV1, LifecycleStore, ReservationAlgebraId, ReservationSetV1,
    RevocationSnapshotV1, StoreError, TransitionContextV1, WorkflowId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

use crate::{
    canonical::{canonical_digest, canonical_json, sha256},
    containment::{Decision, DecisionClass},
    executor::LocalPublication,
    types::{
        CandidateFacts, DigestHex, IssueAddressGrantV1, OpenPatchActionV1, PROFILE_VERSION,
        RadicleEvidenceV1, VerifierConfiguration,
    },
};

pub const PROFILE_ID: &str = "auths.radicle.issue-address/1";
pub const POLICY_TYPE_ID: &str = "auths.radicle.issue-address-grant/1";
pub const EVALUATOR_SEMANTIC_ID: &str = "auths.radicle.issue-address.evaluate/1";
pub const IMPLEMENTATION_ID: &str = "auths-radicle/shared-lifecycle-production/1";
pub const CANONICALIZATION_ID: &str = "rfc8785-sha256-v1";
pub const CONFIGURATION_SEMANTIC_ID: &str = "auths.radicle.verifier-configuration/1";
pub const EVIDENCE_SCHEMA_ID: &str = "auths.radicle.repository-issue-evidence/1";
pub const EVIDENCE_SOURCE_ID: &str = "radicle-synchronized-local-view/1";
pub const STATE_SCHEMA_ID: &str = "auths.radicle.patch-publication-snapshot/1";
pub const WORKFLOW_INTENT_SCHEMA_ID: &str = "auths.radicle.workflow-publication-budget-intent/1";
pub const ACTION_INTENT_SCHEMA_ID: &str = "auths.radicle.exact-action-claim-intent/1";
pub const RESERVATION_ALGEBRA_ID: &str = "auths.radicle.patch-open-exclusive-composite/1";
pub const OBLIGATION_SCHEMA_ID: &str = "auths.radicle.verified-open-patch-command/1";
pub const PROVIDER_CONTRACT_ID: &str = "auths.radicle.local-patch-publication/1";
pub const DOMAIN_ID: &str = "radicle";

/// Complete domain inputs to the pure shared-contract projection.
pub struct RadicleLifecycleProjectionInput<'a> {
    pub grant: &'a IssueAddressGrantV1,
    pub action: &'a OpenPatchActionV1,
    pub candidate: &'a CandidateFacts,
    pub evidence: &'a RadicleEvidenceV1,
    pub required_configuration: &'a VerifierConfiguration,
    pub executed_configuration: &'a VerifierConfiguration,
    pub decision: &'a Decision,
    pub verifier_time: u64,
}

/// Validated shared projection of one authorized local publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RadicleLifecycleProjectionV1 {
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
pub struct RadicleLifecycleDecisionBindings<'a> {
    pub core_authorization_digest: &'a DigestHex,
    pub decision_receipt_digest: &'a DigestHex,
    pub implementation_build_digest: &'a DigestHex,
    pub expires_at: u64,
}

/// Closed failure before shared state can be persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RadicleLifecycleProjectionError {
    #[error("Radicle decision is not authorized")]
    NotAuthorized,
    #[error("Radicle lifecycle payload is not canonical")]
    Canonicalization,
    #[error("Radicle lifecycle digest is malformed")]
    InvalidDigest,
    #[error("Radicle lifecycle projection violates the shared contract")]
    InvalidProjection,
}

/// Shared lifecycle store plus the read required for exact replay and
/// recovery.
pub trait RadicleLifecycleStore: LifecycleStore + Send + Sync {
    /// Loads one validated immutable shared lifecycle record.
    ///
    /// # Errors
    ///
    /// Returns a closed store error for unavailable or corrupt state.
    fn load_radicle_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError>;
}

/// Domain-local registry selecting the store that atomically enforces both
/// Radicle reservation scopes.
pub trait RadicleLifecycleRegistry: Send + Sync {
    /// Returns the shared lifecycle store for an exact action.
    ///
    /// # Errors
    ///
    /// Returns a closed store error when durable state cannot be opened.
    fn for_action(
        &self,
        action: &OpenPatchActionV1,
    ) -> Result<Arc<dyn RadicleLifecycleStore>, StoreError>;

    /// Persists immutable domain recovery material.
    ///
    /// # Errors
    ///
    /// Returns a closed error for unavailable, conflicting, or corrupt state.
    fn persist_recovery(&self, record: &RadicleRecoveryRecordV1) -> Result<(), StoreError>;

    /// Loads exact domain recovery material.
    ///
    /// # Errors
    ///
    /// Returns a closed error for unavailable or corrupt state.
    fn load_recovery(
        &self,
        workflow_id: &crate::types::WorkflowId,
    ) -> Result<Option<RadicleRecoveryRecordV1>, StoreError>;

    /// Persists the exact local publication used by replay and propagation
    /// resumption.
    ///
    /// # Errors
    ///
    /// Returns a closed error for unavailable or conflicting state.
    fn persist_publication(
        &self,
        workflow_id: &crate::types::WorkflowId,
        publication: &LocalPublication,
    ) -> Result<(), StoreError>;

    /// Loads the exact locally published result, if known.
    ///
    /// # Errors
    ///
    /// Returns a closed error for unavailable or corrupt state.
    fn load_publication(
        &self,
        workflow_id: &crate::types::WorkflowId,
    ) -> Result<Option<LocalPublication>, StoreError>;
}

impl<T: RadicleLifecycleRegistry + ?Sized> RadicleLifecycleRegistry for Arc<T> {
    fn for_action(
        &self,
        action: &OpenPatchActionV1,
    ) -> Result<Arc<dyn RadicleLifecycleStore>, StoreError> {
        (**self).for_action(action)
    }

    fn persist_recovery(&self, record: &RadicleRecoveryRecordV1) -> Result<(), StoreError> {
        (**self).persist_recovery(record)
    }

    fn load_recovery(
        &self,
        workflow_id: &crate::types::WorkflowId,
    ) -> Result<Option<RadicleRecoveryRecordV1>, StoreError> {
        (**self).load_recovery(workflow_id)
    }

    fn persist_publication(
        &self,
        workflow_id: &crate::types::WorkflowId,
        publication: &LocalPublication,
    ) -> Result<(), StoreError> {
        (**self).persist_publication(workflow_id, publication)
    }

    fn load_publication(
        &self,
        workflow_id: &crate::types::WorkflowId,
    ) -> Result<Option<LocalPublication>, StoreError> {
        (**self).load_publication(workflow_id)
    }
}

/// Domain-owned exact recovery material. It carries no execution authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadicleRecoveryRecordV1 {
    pub schema: String,
    pub workflow_id: crate::types::WorkflowId,
    pub shared_workflow_id: String,
    pub exact_action: OpenPatchActionV1,
    pub candidate_facts: CandidateFacts,
    pub planning_evidence: RadicleEvidenceV1,
    pub decision_receipt_digest: DigestHex,
    pub claim_id: DigestHex,
}

impl RadicleRecoveryRecordV1 {
    /// Validates internal commitments before recovery material is trusted.
    ///
    /// # Errors
    ///
    /// Rejects mismatched workflows, actions, evidence, or shared identifiers.
    pub fn validate(&self) -> Result<(), RadicleLifecycleProjectionError> {
        if self.schema != "auths.radicle.recovery-record/1"
            || self.exact_action.workflow_id() != &self.workflow_id
            || self.exact_action.candidate_oid() != self.candidate_facts.candidate_oid()
            || self.exact_action.evidence_snapshot_digest()
                != &self.planning_evidence.digest().map_err(canonical)?
            || WorkflowId::parse(&self.shared_workflow_id).is_err()
        {
            return Err(RadicleLifecycleProjectionError::InvalidProjection);
        }
        Ok(())
    }
}

impl RadicleLifecycleProjectionInput<'_> {
    /// Projects one authorized domain decision into shared commitments.
    ///
    /// # Errors
    ///
    /// Fails closed for inconsistent domain inputs, malformed identifiers, or
    /// exceeded shared limits.
    #[allow(
        clippy::too_many_lines,
        reason = "the complete two-scope security projection stays visible as one audited unit"
    )]
    pub fn project(&self) -> Result<RadicleLifecycleProjectionV1, RadicleLifecycleProjectionError> {
        if self.decision.class != DecisionClass::Authorized
            || self.action.workflow_id() != self.grant.workflow_id()
            || self.action.rid() != self.grant.rid()
            || self.action.issue_id() != self.grant.issue_id()
            || self.action.candidate_oid() != self.candidate.candidate_oid()
        {
            return Err(RadicleLifecycleProjectionError::NotAuthorized);
        }
        let commitments = project_commitments(self)?;
        let action_digest = commitments.exact_action_digest();
        let policy_digest = commitments.policy_commitment().policy_digest();
        let evidence_digest = commitments.evidence_digest();
        let workflow_scope = WorkflowBudgetScope {
            executor_audience: self.action.executor_audience().as_str(),
            workflow_id: self.action.workflow_id().as_str(),
            publication_budget_ordinal: self.action.publication_budget_ordinal(),
        };
        let action_scope = ExactActionScope {
            executor_audience: self.action.executor_audience().as_str(),
            action_digest: self.action.digest().map_err(canonical)?.as_str().to_owned(),
        };
        let workflow_scope_bytes = canonical_json(&workflow_scope).map_err(canonical)?;
        let action_scope_bytes = canonical_json(&action_scope).map_err(canonical)?;
        let workflow_scope_digest =
            commitment(&canonical_digest(&workflow_scope).map_err(canonical)?)?;
        let action_scope_digest = commitment(&canonical_digest(&action_scope).map_err(canonical)?)?;
        let action_bytes = self.action.canonical_bytes().map_err(canonical)?;
        let intents = vec![
            ReservationIntentCommitmentV1::new(
                SchemaId::parse(ACTION_INTENT_SCHEMA_ID).map_err(invalid)?,
                IntentId::parse("exact-action-claim").map_err(invalid)?,
                action_scope_digest,
                ReservationKind::Exclusive,
                None,
                action_digest,
                policy_digest,
                evidence_digest,
                commitment(&sha256(&action_scope_bytes))?,
                u32::try_from(action_scope_bytes.len()).map_err(invalid)?,
            )
            .map_err(invalid)?,
            ReservationIntentCommitmentV1::new(
                SchemaId::parse(WORKFLOW_INTENT_SCHEMA_ID).map_err(invalid)?,
                IntentId::parse("workflow-publication-budget").map_err(invalid)?,
                workflow_scope_digest,
                ReservationKind::Exclusive,
                None,
                action_digest,
                policy_digest,
                evidence_digest,
                commitment(&sha256(&workflow_scope_bytes))?,
                u32::try_from(workflow_scope_bytes.len()).map_err(invalid)?,
            )
            .map_err(invalid)?,
        ];
        let obligation = ObligationCommitmentV1::new(
            SchemaId::parse(OBLIGATION_SCHEMA_ID).map_err(invalid)?,
            ObligationId::parse("publish-exact-radicle-patch").map_err(invalid)?,
            ObligationClass::CommandConstruction,
            action_digest,
            u32::try_from(action_bytes.len()).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let outputs = BoundedOutputs::new(
            intents,
            vec![obligation],
            commitment(&canonical_digest(&(workflow_scope, action_scope)).map_err(canonical)?)?,
            commitment(&sha256(&action_bytes))?,
        )
        .map_err(invalid)?;
        let workflow_id = shared_workflow_id(self.action, policy_digest)?;
        let domain_id = DomainId::parse(DOMAIN_ID).map_err(invalid)?;
        let executor_audience =
            ExecutorAudienceId::parse(self.action.executor_audience().as_str()).map_err(invalid)?;
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
        let capacity = CapacitySnapshotV1::new(vec![
            CapacityEntryV1::Exclusive {
                scope_digest: workflow_scope_digest,
                window_digest: None,
                live_owner: None,
            },
            CapacityEntryV1::Exclusive {
                scope_digest: action_scope_digest,
                window_digest: None,
                live_owner: None,
            },
        ])
        .map_err(invalid)?;
        Ok(RadicleLifecycleProjectionV1 {
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

impl RadicleLifecycleProjectionV1 {
    /// Consumes the projection into one complete shared decision input.
    ///
    /// # Errors
    ///
    /// Rejects malformed exact digests or derived identifiers.
    pub fn into_decision_input(
        self,
        bindings: &RadicleLifecycleDecisionBindings<'_>,
    ) -> Result<DecisionInputV1, RadicleLifecycleProjectionError> {
        let action_digest = self.commitments.exact_action_digest();
        let policy_digest = self.commitments.policy_commitment().policy_digest();
        let lifecycle_id = derived_identifier(
            b"AUTHS-RADICLE-LIFECYCLE\x00\x01",
            self.workflow_id.as_str(),
            action_digest,
            policy_digest,
        );
        let execution_id = derived_identifier(
            b"AUTHS-RADICLE-EXECUTION\x00\x01",
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
                snapshot_digest: commit_bytes(b"auths.radicle.revocation-not-configured/1"),
            },
            capacity: self.capacity.clone(),
        }
    }
}

/// Returns the workflow-budget and exact-action scope commitments in canonical
/// reservation order.
///
/// # Errors
///
/// Fails only when the exact action cannot be canonicalized.
pub fn reservation_scope_digests(
    action: &OpenPatchActionV1,
) -> Result<[CommitmentDigest; 2], RadicleLifecycleProjectionError> {
    let workflow_scope = WorkflowBudgetScope {
        executor_audience: action.executor_audience().as_str(),
        workflow_id: action.workflow_id().as_str(),
        publication_budget_ordinal: action.publication_budget_ordinal(),
    };
    let action_scope = ExactActionScope {
        executor_audience: action.executor_audience().as_str(),
        action_digest: action.digest().map_err(canonical)?.as_str().to_owned(),
    };
    Ok([
        commitment(&canonical_digest(&workflow_scope).map_err(canonical)?)?,
        commitment(&canonical_digest(&action_scope).map_err(canonical)?)?,
    ])
}

fn project_commitments(
    input: &RadicleLifecycleProjectionInput<'_>,
) -> Result<EvaluationCommitmentsV1, RadicleLifecycleProjectionError> {
    let action_digest = commitment(&input.action.digest().map_err(canonical)?)?;
    let policy_digest = commitment(&input.grant.digest().map_err(canonical)?)?;
    let evidence_digest = commitment(&input.evidence.digest().map_err(canonical)?)?;
    let state_digest = commitment(&canonical_digest(input.candidate).map_err(canonical)?)?;
    Ok(EvaluationCommitmentsV1::new(
        ProfileId::parse(PROFILE_ID).map_err(invalid)?,
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
        VerifierTime::from_unix_seconds(input.evidence.synchronized_at()),
        SchemaId::parse(STATE_SCHEMA_ID).map_err(invalid)?,
        state_digest,
        VerifierTime::from_unix_seconds(input.verifier_time),
        configuration_commitment(input.required_configuration, false)?,
        configuration_commitment(input.executed_configuration, true)?,
    ))
}

fn configuration_commitment(
    configuration: &VerifierConfiguration,
    executed: bool,
) -> Result<ConfigurationCommitmentV1, RadicleLifecycleProjectionError> {
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
struct WorkflowBudgetScope<'a> {
    executor_audience: &'a str,
    workflow_id: &'a str,
    publication_budget_ordinal: u8,
}

#[derive(Serialize)]
struct ExactActionScope<'a> {
    executor_audience: &'a str,
    action_digest: String,
}

fn shared_workflow_id(
    action: &OpenPatchActionV1,
    policy_digest: CommitmentDigest,
) -> Result<WorkflowId, RadicleLifecycleProjectionError> {
    let mut hasher = Sha256::new();
    hasher.update(b"AUTHS-RADICLE-SHARED-WORKFLOW\x00\x01");
    hasher.update(action.workflow_id().as_str().as_bytes());
    hasher.update(action.digest().map_err(canonical)?.as_str().as_bytes());
    hasher.update(policy_digest.as_bytes());
    WorkflowId::parse(&hex::encode(hasher.finalize())).map_err(invalid)
}

fn commitment(value: &DigestHex) -> Result<CommitmentDigest, RadicleLifecycleProjectionError> {
    Ok(CommitmentDigest::new(digest_bytes(value)?))
}

fn digest_bytes(value: &DigestHex) -> Result<[u8; 32], RadicleLifecycleProjectionError> {
    hex::decode(value.as_str())
        .map_err(|_| RadicleLifecycleProjectionError::InvalidDigest)?
        .try_into()
        .map_err(|_| RadicleLifecycleProjectionError::InvalidDigest)
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

fn canonical(_: impl core::fmt::Debug) -> RadicleLifecycleProjectionError {
    RadicleLifecycleProjectionError::Canonicalization
}

fn invalid(_: impl core::fmt::Debug) -> RadicleLifecycleProjectionError {
    RadicleLifecycleProjectionError::InvalidProjection
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{Arc, Barrier},
        thread,
    };

    use auths_lifecycle::{StoreTransactionV1, TransitionCommandV1, execute_store_transaction};
    use auths_stores::{InMemoryLifecycleStore, LifecycleCapacityRuleV1};

    use super::*;
    use crate::{
        containment::{EvaluationContext, evaluate},
        test_support::{
            NOW, action, candidate, configuration, digest, evidence, grant, submission,
        },
    };

    #[test]
    fn different_actions_for_one_workflow_have_one_concurrent_reservation_winner() {
        let configuration = configuration(30);
        let grant = grant(configuration.clone());
        let first_submission = submission();
        let first_candidate = candidate(&first_submission);
        let planning_evidence = evidence(&grant, NOW);
        let first_action = action(
            &grant,
            &configuration,
            &first_submission,
            &first_candidate,
            &planning_evidence,
        );
        let mut second_submission = submission();
        second_submission.patch_body.push_str(" Second candidate.");
        let second_candidate = candidate(&second_submission);
        let second_action = action(
            &grant,
            &configuration,
            &second_submission,
            &second_candidate,
            &planning_evidence,
        );
        let first = projection(
            &grant,
            &configuration,
            &first_submission,
            &first_candidate,
            &planning_evidence,
            &first_action,
        );
        let second = projection(
            &grant,
            &configuration,
            &second_submission,
            &second_candidate,
            &planning_evidence,
            &second_action,
        );
        let first_scopes = reservation_scope_digests(&first_action).unwrap();
        let second_scopes = reservation_scope_digests(&second_action).unwrap();
        assert_eq!(first_scopes[0], second_scopes[0]);
        assert_ne!(first_scopes[1], second_scopes[1]);

        let rules = first_scopes
            .into_iter()
            .chain(second_scopes)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|scope_digest| LifecycleCapacityRuleV1::Exclusive {
                scope_digest,
                window_digest: None,
                retain_after_commit: true,
            })
            .collect();
        let store = Arc::new(InMemoryLifecycleStore::new(rules, 8).unwrap());
        let (first_id, first_context, first_input) = decision_material(first);
        let (second_id, second_context, second_input) = decision_material(second);
        for (workflow_id, context, input) in [
            (&first_id, &first_context, first_input),
            (&second_id, &second_context, second_input),
        ] {
            execute_store_transaction(
                &store,
                &StoreTransactionV1 {
                    workflow_id: workflow_id.clone(),
                    expected_revision: None,
                    command: TransitionCommandV1::RecordDecision(Box::new(input)),
                    context: context.clone(),
                },
            )
            .unwrap();
        }

        let barrier = Arc::new(Barrier::new(3));
        let handles = [(first_id, first_context), (second_id, second_context)]
            .into_iter()
            .map(|(workflow_id, context)| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    execute_store_transaction(
                        &store,
                        &StoreTransactionV1 {
                            workflow_id,
                            expected_revision: Some(1),
                            command: TransitionCommandV1::Reserve,
                            context,
                        },
                    )
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let winners = handles.into_iter().fold(0, |count, handle| {
            count + usize::from(handle.join().unwrap().is_ok())
        });
        assert_eq!(winners, 1);
    }

    fn projection<'a>(
        grant: &'a IssueAddressGrantV1,
        configuration: &'a VerifierConfiguration,
        submission: &'a crate::types::CandidateSubmission,
        candidate: &'a CandidateFacts,
        evidence: &'a RadicleEvidenceV1,
        action: &'a OpenPatchActionV1,
    ) -> RadicleLifecycleProjectionV1 {
        let decision = evaluate(&EvaluationContext {
            grant,
            action,
            submission,
            candidate,
            evidence,
            required_configuration: configuration,
            executed_configuration: configuration,
            request_audience: action.executor_audience().as_str(),
            now: NOW,
        });
        RadicleLifecycleProjectionInput {
            grant,
            action,
            candidate,
            evidence,
            required_configuration: configuration,
            executed_configuration: configuration,
            decision: &decision,
            verifier_time: NOW,
        }
        .project()
        .unwrap()
    }

    fn decision_material(
        projection: RadicleLifecycleProjectionV1,
    ) -> (WorkflowId, TransitionContextV1, DecisionInputV1) {
        let workflow_id = projection.workflow_id.clone();
        let context = projection.transition_context(NOW);
        let input = projection
            .into_decision_input(&RadicleLifecycleDecisionBindings {
                core_authorization_digest: &digest('a'),
                decision_receipt_digest: &digest('b'),
                implementation_build_digest: &digest('c'),
                expires_at: NOW + 300,
            })
            .unwrap();
        (workflow_id, context, input)
    }
}
