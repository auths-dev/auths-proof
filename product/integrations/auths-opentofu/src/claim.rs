//! OpenTofu-facing projection of the shared durable lifecycle.
//!
//! The public claim receipt remains domain-shaped. It is derived from a
//! store-acknowledged shared lifecycle record and is never an independent
//! source of execution authority.

use auths_lifecycle::{LifecycleRecordV1, LifecycleState};
use serde::{Deserialize, Serialize};

use crate::types::DigestHex;

/// Durable workflow stage exposed in the existing OpenTofu receipt schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimStage {
    Claimed,
    ArtifactVerified,
    CredentialAcquired,
    StateRechecked,
    ApplyStarted,
    StateCommitted,
    PostconditionsObserved,
    Converged,
    OutcomeUnknown,
    Failed,
}

/// Claim receipt projected from one canonical shared lifecycle record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    pub action_digest: DigestHex,
    pub stage: ClaimStage,
    pub claimed_at: u64,
    pub updated_at: u64,
}

impl ClaimRecord {
    /// Projects one explicit OpenTofu stage from durable shared state.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimProjectionError`] when the shared record has no durable
    /// event history.
    pub fn from_lifecycle(
        record: &LifecycleRecordV1,
        stage: ClaimStage,
    ) -> Result<Self, ClaimProjectionError> {
        let first = record
            .events()
            .first()
            .ok_or(ClaimProjectionError::MissingEvent)?;
        let last = record
            .events()
            .last()
            .ok_or(ClaimProjectionError::MissingEvent)?;
        Ok(Self {
            action_digest: DigestHex::from_digest_bytes(
                *record
                    .decision_input()
                    .commitments
                    .exact_action_digest()
                    .as_bytes(),
            ),
            stage,
            claimed_at: first.verifier_time.unix_seconds(),
            updated_at: last.verifier_time.unix_seconds(),
        })
    }

    /// Projects the most truthful public claim stage for replay or conflict.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimProjectionError`] for an invalid shared record.
    pub fn replay(record: &LifecycleRecordV1) -> Result<Self, ClaimProjectionError> {
        let stage = match record.state() {
            LifecycleState::DecisionRecorded | LifecycleState::Reserved => ClaimStage::Claimed,
            LifecycleState::ExecutionIntentRecorded => {
                if record.credential_authorized() {
                    ClaimStage::CredentialAcquired
                } else {
                    ClaimStage::ArtifactVerified
                }
            }
            LifecycleState::Executing => ClaimStage::ApplyStarted,
            LifecycleState::Committed | LifecycleState::ReconciledCommitted => {
                ClaimStage::Converged
            }
            LifecycleState::OutcomeUnknown => ClaimStage::OutcomeUnknown,
            LifecycleState::Released | LifecycleState::ReconciledReleased => ClaimStage::Failed,
        };
        Self::from_lifecycle(record, stage)
    }
}

/// Invalid domain projection of shared lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClaimProjectionError {
    #[error("shared OpenTofu lifecycle record has no durable events")]
    MissingEvent,
}

#[cfg(test)]
mod tests {
    use auths_lifecycle::{TransitionCommandV1, apply_transition};

    use super::*;
    use crate::{
        lifecycle::{OpenTofuLifecycleDecisionBindings, OpenTofuLifecycleProjectionInput},
        receipts::decision_receipt,
        test_support::{NOW, fixture},
    };

    #[test]
    fn claim_receipt_is_derived_from_shared_record() {
        let fixture = fixture();
        let decision = decision_receipt(
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
            decision: &decision.decision,
            verifier_time: NOW,
        }
        .project()
        .unwrap();
        let context = projection.transition_context(NOW);
        let input = projection
            .into_decision_input(&OpenTofuLifecycleDecisionBindings {
                core_authorization_digest: &crate::canonical::sha256(b"core"),
                decision_receipt_digest: &decision.digest().unwrap(),
                implementation_build_digest: &crate::canonical::sha256(b"build"),
                expires_at: fixture.action.expires_at(),
            })
            .unwrap();
        let recorded = apply_transition(
            None,
            &TransitionCommandV1::RecordDecision(Box::new(input)),
            &context,
        )
        .unwrap();
        let claim = ClaimRecord::from_lifecycle(&recorded.record, ClaimStage::Claimed).unwrap();

        assert_eq!(claim.action_digest, fixture.action.digest().unwrap());
        assert_eq!(claim.claimed_at, NOW);
    }
}
