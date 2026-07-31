//! Stage-sealed commands presented to the OpenTofu apply and reconciliation
//! boundaries.

use auths_bounded_policy::CommitmentDigest;
use auths_lifecycle::{
    ExecutionAuthorizationV1, ExecutionId, LifecycleRecordV1, LifecycleState,
    ProviderCallAuthorizationV1, WorkflowId,
};
use auths_sdk::Authorized;

use crate::{
    action::OpenTofuSavedPlanApplyV1, plan_projection::SavedPlanProjectionV1,
    profile::OpenTofuApplyCommand, types::OpenTofuStateEvidenceV1,
};

/// Exact state-recheck command constructible only after proof verification and
/// durable credential authorization.
pub struct VerifiedSavedPlanPreparationCommand {
    authorized: Authorized<OpenTofuApplyCommand>,
    projection: SavedPlanProjectionV1,
    planning_evidence: OpenTofuStateEvidenceV1,
    execution_authorization: ExecutionAuthorizationV1,
}

impl VerifiedSavedPlanPreparationCommand {
    pub(crate) const fn new(
        authorized: Authorized<OpenTofuApplyCommand>,
        projection: SavedPlanProjectionV1,
        planning_evidence: OpenTofuStateEvidenceV1,
        execution_authorization: ExecutionAuthorizationV1,
    ) -> Self {
        Self {
            authorized,
            projection,
            planning_evidence,
            execution_authorization,
        }
    }

    #[must_use]
    pub fn action(&self) -> &OpenTofuSavedPlanApplyV1 {
        self.authorized.command().action()
    }

    #[must_use]
    pub const fn projection(&self) -> &SavedPlanProjectionV1 {
        &self.projection
    }

    #[must_use]
    pub const fn planning_evidence(&self) -> &OpenTofuStateEvidenceV1 {
        &self.planning_evidence
    }

    #[must_use]
    pub const fn execution_authorization(&self) -> &ExecutionAuthorizationV1 {
        &self.execution_authorization
    }

    pub(crate) fn authorize_provider_call(
        self,
        provider_authorization: ProviderCallAuthorizationV1,
    ) -> VerifiedSavedPlanCommand {
        VerifiedSavedPlanCommand {
            authorized: self.authorized,
            projection: self.projection,
            planning_evidence: self.planning_evidence,
            provider_authorization,
        }
    }
}

/// Exact apply command constructible only after a durable provider-call entry.
pub struct VerifiedSavedPlanCommand {
    authorized: Authorized<OpenTofuApplyCommand>,
    projection: SavedPlanProjectionV1,
    planning_evidence: OpenTofuStateEvidenceV1,
    provider_authorization: ProviderCallAuthorizationV1,
}

impl VerifiedSavedPlanCommand {
    #[must_use]
    pub fn action(&self) -> &OpenTofuSavedPlanApplyV1 {
        self.authorized.command().action()
    }

    #[must_use]
    pub const fn projection(&self) -> &SavedPlanProjectionV1 {
        &self.projection
    }

    #[must_use]
    pub const fn planning_evidence(&self) -> &OpenTofuStateEvidenceV1 {
        &self.planning_evidence
    }

    #[must_use]
    pub const fn provider_authorization(&self) -> &ProviderCallAuthorizationV1 {
        &self.provider_authorization
    }
}

/// Store-read proof that only the original unknown OpenTofu execution may be
/// reconciled.
pub struct OpenTofuReconciliationAuthorizationV1 {
    workflow_id: WorkflowId,
    execution_id: ExecutionId,
    action_digest: CommitmentDigest,
}

impl OpenTofuReconciliationAuthorizationV1 {
    /// Derives authorization from an exact durable outcome-unknown record.
    ///
    /// # Errors
    ///
    /// Rejects any state that is not awaiting reconciliation.
    pub(crate) fn from_record(record: &LifecycleRecordV1) -> Result<Self, ReconciliationError> {
        if record.state() != LifecycleState::OutcomeUnknown {
            return Err(ReconciliationError::StageNotAuthorized);
        }
        Ok(Self {
            workflow_id: record.workflow_id().clone(),
            execution_id: record.execution_id().clone(),
            action_digest: record.decision_input().commitments.exact_action_digest(),
        })
    }

    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    #[must_use]
    pub const fn execution_id(&self) -> &ExecutionId {
        &self.execution_id
    }

    #[must_use]
    pub const fn action_digest(&self) -> CommitmentDigest {
        self.action_digest
    }
}

/// Exact provider/backend observation command for one durable unknown
/// execution.
pub struct VerifiedOpenTofuReconciliationCommand {
    authorized: Authorized<OpenTofuApplyCommand>,
    projection: SavedPlanProjectionV1,
    planning_evidence: OpenTofuStateEvidenceV1,
    authorization: OpenTofuReconciliationAuthorizationV1,
}

impl VerifiedOpenTofuReconciliationCommand {
    pub(crate) fn new(
        command: VerifiedSavedPlanCommand,
        authorization: OpenTofuReconciliationAuthorizationV1,
    ) -> Self {
        Self {
            authorized: command.authorized,
            projection: command.projection,
            planning_evidence: command.planning_evidence,
            authorization,
        }
    }

    pub(crate) const fn from_authorized(
        authorized: Authorized<OpenTofuApplyCommand>,
        projection: SavedPlanProjectionV1,
        planning_evidence: OpenTofuStateEvidenceV1,
        authorization: OpenTofuReconciliationAuthorizationV1,
    ) -> Self {
        Self {
            authorized,
            projection,
            planning_evidence,
            authorization,
        }
    }

    #[must_use]
    pub fn action(&self) -> &OpenTofuSavedPlanApplyV1 {
        self.authorized.command().action()
    }

    #[must_use]
    pub const fn projection(&self) -> &SavedPlanProjectionV1 {
        &self.projection
    }

    #[must_use]
    pub const fn planning_evidence(&self) -> &OpenTofuStateEvidenceV1 {
        &self.planning_evidence
    }

    #[must_use]
    pub const fn authorization(&self) -> &OpenTofuReconciliationAuthorizationV1 {
        &self.authorization
    }
}

/// Closed reconciliation-command construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReconciliationError {
    #[error("OpenTofu lifecycle is not awaiting reconciliation")]
    StageNotAuthorized,
}
