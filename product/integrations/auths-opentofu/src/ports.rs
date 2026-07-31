//! Narrow protected effect ports for planning and saved-plan application.

use std::sync::Arc;

use auths_lifecycle::ExecutionAuthorizationV1;
use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext};

use crate::{
    action::OpenTofuSavedPlanApplyV1,
    errors::PortError,
    executor::{
        OpenTofuReconciliationAuthorizationV1, VerifiedOpenTofuReconciliationCommand,
        VerifiedSavedPlanCommand, VerifiedSavedPlanPreparationCommand,
    },
    profile::OpenTofuApplyCommand,
    receipts::OpenTofuReceipt,
    types::{OpenTofuApplyResult, OpenTofuStateEvidenceV1, PlanHandle},
};

/// Sensitive saved-plan bytes held only in the protected process.
pub struct SavedPlanArtifact(Vec<u8>);

impl SavedPlanArtifact {
    pub fn new(bytes: Vec<u8>) -> Result<Self, PortError> {
        if bytes.is_empty() || bytes.len() > 256 * 1024 * 1024 {
            return Err(PortError::LimitExceeded);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SavedPlanArtifact {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Backend/provider credential unavailable to callers and receipts.
pub struct OpenTofuCredential(Vec<u8>);

impl OpenTofuCredential {
    pub fn new(bytes: Vec<u8>) -> Result<Self, PortError> {
        if !(16..=64 * 1024).contains(&bytes.len()) {
            return Err(PortError::InvalidConfiguration);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for OpenTofuCredential {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Auths kernel outcome.
pub enum ProofDecision {
    Authorized(Box<Authorized<OpenTofuApplyCommand>>),
    Denied { code: String },
    Indeterminate { code: String },
}

pub trait ProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<ProofDecision, PortError>;
}

/// Protected encrypted saved-plan storage.
pub trait PlanArtifactStore: Send + Sync {
    fn put(&self, artifact: SavedPlanArtifact) -> Result<PlanHandle, PortError>;
    fn resolve(&self, handle: &PlanHandle) -> Result<SavedPlanArtifact, PortError>;
}

/// Protected credential broker called only through durable stage-sealed
/// authority.
pub trait CredentialProvider: Send + Sync {
    fn credential_after_authorization(
        &self,
        authorization: &ExecutionAuthorizationV1,
        action: &OpenTofuSavedPlanApplyV1,
    ) -> Result<OpenTofuCredential, PortError>;

    /// Acquires the same least-privilege credential solely for protected
    /// observation of an existing outcome-unknown execution.
    fn reconciliation_credential(
        &self,
        authorization: &OpenTofuReconciliationAuthorizationV1,
        action: &OpenTofuSavedPlanApplyV1,
    ) -> Result<OpenTofuCredential, PortError>;
}

/// Backend/state and exact saved-plan execution boundary.
pub trait OpenTofuGateway: Send + Sync {
    fn recheck_state(
        &self,
        command: &VerifiedSavedPlanPreparationCommand,
        credential: &OpenTofuCredential,
    ) -> Result<OpenTofuStateEvidenceV1, PortError>;

    fn apply_saved_plan(
        &self,
        command: &VerifiedSavedPlanCommand,
        artifact: &SavedPlanArtifact,
        credential: &OpenTofuCredential,
        now: u64,
    ) -> Result<OpenTofuApplyResult, PortError>;

    /// Reconciles an ambiguous apply without submitting the plan again.
    fn reconcile(
        &self,
        command: &VerifiedOpenTofuReconciliationCommand,
        credential: &OpenTofuCredential,
        now: u64,
    ) -> Result<OpenTofuApplyResult, PortError>;
}

pub trait ReceiptSink: Send + Sync {
    fn append(&self, receipt: &OpenTofuReceipt) -> Result<(), PortError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Result<u64, PortError>;
}

impl<T: ProofVerifier + ?Sized> ProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<ProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}
impl<T: PlanArtifactStore + ?Sized> PlanArtifactStore for Arc<T> {
    fn put(&self, artifact: SavedPlanArtifact) -> Result<PlanHandle, PortError> {
        (**self).put(artifact)
    }
    fn resolve(&self, handle: &PlanHandle) -> Result<SavedPlanArtifact, PortError> {
        (**self).resolve(handle)
    }
}
impl<T: CredentialProvider + ?Sized> CredentialProvider for Arc<T> {
    fn credential_after_authorization(
        &self,
        authorization: &ExecutionAuthorizationV1,
        action: &OpenTofuSavedPlanApplyV1,
    ) -> Result<OpenTofuCredential, PortError> {
        (**self).credential_after_authorization(authorization, action)
    }

    fn reconciliation_credential(
        &self,
        authorization: &OpenTofuReconciliationAuthorizationV1,
        action: &OpenTofuSavedPlanApplyV1,
    ) -> Result<OpenTofuCredential, PortError> {
        (**self).reconciliation_credential(authorization, action)
    }
}
impl<T: OpenTofuGateway + ?Sized> OpenTofuGateway for Arc<T> {
    fn recheck_state(
        &self,
        command: &VerifiedSavedPlanPreparationCommand,
        credential: &OpenTofuCredential,
    ) -> Result<OpenTofuStateEvidenceV1, PortError> {
        (**self).recheck_state(command, credential)
    }
    fn apply_saved_plan(
        &self,
        command: &VerifiedSavedPlanCommand,
        artifact: &SavedPlanArtifact,
        credential: &OpenTofuCredential,
        now: u64,
    ) -> Result<OpenTofuApplyResult, PortError> {
        (**self).apply_saved_plan(command, artifact, credential, now)
    }
    fn reconcile(
        &self,
        command: &VerifiedOpenTofuReconciliationCommand,
        credential: &OpenTofuCredential,
        now: u64,
    ) -> Result<OpenTofuApplyResult, PortError> {
        (**self).reconcile(command, credential, now)
    }
}
impl<T: ReceiptSink + ?Sized> ReceiptSink for Arc<T> {
    fn append(&self, receipt: &OpenTofuReceipt) -> Result<(), PortError> {
        (**self).append(receipt)
    }
}
impl<T: Clock + ?Sized> Clock for Arc<T> {
    fn now(&self) -> Result<u64, PortError> {
        (**self).now()
    }
}
