//! PostgreSQL-facing projection of the shared durable lifecycle.
//!
//! The public claim receipt stays domain-shaped. It is derived from a
//! store-acknowledged shared lifecycle record and is never an independent
//! source of execution authority.

use auths_lifecycle::{LifecycleRecordV1, LifecycleState};
use serde::{Deserialize, Serialize};

use crate::schema::DigestHex;

/// PostgreSQL claim stage exposed in the existing domain receipt schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimStage {
    Claimed,
    CredentialAcquired,
    TransactionStarted,
    LedgerReserved,
    RowsLocked,
    MutationCommitted,
    Observed,
    Reconciled,
    OutcomeUnknown,
    Failed,
}

/// Claim receipt projected from one canonical shared lifecycle record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    pub action_digest: DigestHex,
    pub claim_id: String,
    pub stage: ClaimStage,
    pub claimed_at: u64,
    pub updated_at: u64,
}

impl ClaimRecord {
    /// Projects one explicit PostgreSQL stage from durable shared state.
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
            action_digest: DigestHex::from_bytes(
                *record
                    .decision_input()
                    .commitments
                    .exact_action_digest()
                    .as_bytes(),
            ),
            claim_id: record.execution_id().as_str().into(),
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
                    ClaimStage::Claimed
                }
            }
            LifecycleState::Executing => ClaimStage::TransactionStarted,
            LifecycleState::Committed => ClaimStage::Observed,
            LifecycleState::ReconciledCommitted => ClaimStage::Reconciled,
            LifecycleState::OutcomeUnknown => ClaimStage::OutcomeUnknown,
            LifecycleState::Released | LifecycleState::ReconciledReleased => ClaimStage::Failed,
        };
        Self::from_lifecycle(record, stage)
    }
}

/// Invalid domain projection of shared lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClaimProjectionError {
    #[error("shared PostgreSQL lifecycle record has no durable events")]
    MissingEvent,
}

#[cfg(test)]
mod tests {
    use auths_lifecycle::{TransitionCommandV1, apply_transition};

    use super::*;
    use crate::{
        lifecycle::{PostgresLifecycleDecisionBindings, PostgresLifecycleProjectionInput},
        receipts::decision_receipt,
        test_support::{NOW, fixture},
    };

    #[test]
    fn claim_receipt_is_derived_from_shared_record() {
        let fixture = fixture();
        let decision = decision_receipt(
            &fixture.action,
            &fixture.evidence,
            &fixture.configuration,
            &fixture.configuration,
            fixture.configuration.executor_audience(),
            NOW,
        )
        .unwrap();
        let projection = PostgresLifecycleProjectionInput {
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
            .into_decision_input(&PostgresLifecycleDecisionBindings {
                core_authorization_digest: &crate::canonical::sha256(b"core"),
                decision_receipt_digest: &decision.digest().unwrap(),
                implementation_build_digest: &crate::canonical::sha256(b"build"),
                expires_at: fixture.action.intent.expires_at,
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
        assert_eq!(claim.claim_id, recorded.record.execution_id().as_str());
    }
}
