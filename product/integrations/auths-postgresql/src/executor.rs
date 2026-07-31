//! Stage-sealed commands presented to the database transaction and
//! reconciliation boundaries.

use auths_bounded_policy::CommitmentDigest;
use auths_lifecycle::{
    ExecutionId, LifecycleRecordV1, LifecycleState, ProviderCallAuthorizationV1, WorkflowId,
};
use auths_sdk::Authorized;

use crate::{
    compiler::CompiledBoundedUpdate, evidence::PostgresEvidenceV1, profile::PostgresUpdateCommand,
};

/// Exact command constructible only after proof verification and durable
/// provider-call authorization.
pub struct VerifiedBoundedUpdateCommand {
    authorized: Authorized<PostgresUpdateCommand>,
    evidence: PostgresEvidenceV1,
    compiled: CompiledBoundedUpdate,
    provider_authorization: ProviderCallAuthorizationV1,
}

impl VerifiedBoundedUpdateCommand {
    pub(crate) const fn new(
        authorized: Authorized<PostgresUpdateCommand>,
        evidence: PostgresEvidenceV1,
        compiled: CompiledBoundedUpdate,
        provider_authorization: ProviderCallAuthorizationV1,
    ) -> Self {
        Self {
            authorized,
            evidence,
            compiled,
            provider_authorization,
        }
    }

    #[must_use]
    pub fn action(&self) -> &crate::action::PostgresBoundedUpdateV1 {
        self.authorized.command().action()
    }

    #[must_use]
    pub const fn evidence(&self) -> &PostgresEvidenceV1 {
        &self.evidence
    }

    #[must_use]
    pub const fn compiled(&self) -> &CompiledBoundedUpdate {
        &self.compiled
    }

    #[must_use]
    pub const fn provider_authorization(&self) -> &ProviderCallAuthorizationV1 {
        &self.provider_authorization
    }

    #[must_use]
    pub fn claim_id(&self) -> &str {
        self.provider_authorization.execution_id().as_str()
    }

    pub(crate) fn into_reconciliation(
        self,
        authorization: PostgresReconciliationAuthorizationV1,
    ) -> VerifiedPostgresReconciliationCommand {
        VerifiedPostgresReconciliationCommand {
            authorized: self.authorized,
            evidence: self.evidence,
            compiled: self.compiled,
            authorization,
        }
    }
}

/// Store-read proof that only the original unknown PostgreSQL execution may
/// be reconciled.
pub struct PostgresReconciliationAuthorizationV1 {
    workflow_id: WorkflowId,
    execution_id: ExecutionId,
    action_digest: CommitmentDigest,
}

impl PostgresReconciliationAuthorizationV1 {
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

/// Exact ledger observation command for one durable unknown execution.
pub struct VerifiedPostgresReconciliationCommand {
    authorized: Authorized<PostgresUpdateCommand>,
    evidence: PostgresEvidenceV1,
    compiled: CompiledBoundedUpdate,
    authorization: PostgresReconciliationAuthorizationV1,
}

impl VerifiedPostgresReconciliationCommand {
    pub(crate) const fn new(
        authorized: Authorized<PostgresUpdateCommand>,
        evidence: PostgresEvidenceV1,
        compiled: CompiledBoundedUpdate,
        authorization: PostgresReconciliationAuthorizationV1,
    ) -> Self {
        Self {
            authorized,
            evidence,
            compiled,
            authorization,
        }
    }

    #[must_use]
    pub fn action(&self) -> &crate::action::PostgresBoundedUpdateV1 {
        self.authorized.command().action()
    }

    #[must_use]
    pub const fn evidence(&self) -> &PostgresEvidenceV1 {
        &self.evidence
    }

    #[must_use]
    pub const fn compiled(&self) -> &CompiledBoundedUpdate {
        &self.compiled
    }

    #[must_use]
    pub const fn authorization(&self) -> &PostgresReconciliationAuthorizationV1 {
        &self.authorization
    }

    #[must_use]
    pub fn claim_id(&self) -> &str {
        self.authorization.execution_id().as_str()
    }
}

/// Closed reconciliation-command construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReconciliationError {
    #[error("PostgreSQL lifecycle is not awaiting reconciliation")]
    StageNotAuthorized,
}
