//! In-process authorization-before-execution integration kit.
//!
//! The service maps its real request into one profile input, then this kit
//! canonicalizes, verifies, and exposes only the command decoded from sealed
//! verified bytes. It performs no I/O and is transport-neutral.

#![forbid(unsafe_code)]

use auths_profile_api::{ActionProfile, ApprovalDisplay, ProfileContractError};
use auths_sdk::{Authorized, Explanation, RequestContext, SdkError, Verifier, VerifyResult};
use thiserror::Error;

/// A service-local enforcement boundary for one exact application profile.
pub struct Enforcement<P> {
    verifier: Verifier,
    profile: P,
}

impl<P> Enforcement<P>
where
    P: ActionProfile,
{
    /// Binds an embedded verifier to one application profile.
    #[must_use]
    pub const fn new(verifier: Verifier, profile: P) -> Self {
        Self { verifier, profile }
    }

    /// Canonicalizes a request for review or proof issuance.
    ///
    /// # Errors
    ///
    /// Returns a closed profile-contract error for malformed, ambiguous,
    /// unsupported, oversized, or non-canonical application input.
    pub fn prepare(&self, untrusted_action: &[u8]) -> Result<PreparedAction, EnforcementError> {
        let canonical = self.profile.canonicalize(untrusted_action)?;
        let display = self.profile.approval_display(&canonical)?;
        Ok(PreparedAction { canonical, display })
    }

    /// Verifies a prepared action and returns an executor-safe command only
    /// when exact authority is established.
    ///
    /// # Errors
    ///
    /// Returns a typed SDK or profile-contract failure. Protocol denial and
    /// indeterminate outcomes remain ordinary [`EnforcementDecision`] values.
    pub fn authorize(
        &self,
        proof_cbor: &[u8],
        prepared: &PreparedAction,
        request: &RequestContext,
    ) -> Result<EnforcementDecision<P::Command>, EnforcementError> {
        Ok(
            match self
                .verifier
                .verify(proof_cbor, prepared.canonical(), request, &self.profile)?
            {
                VerifyResult::Authorized(authorized) => EnforcementDecision::Authorized(authorized),
                VerifyResult::Denied(explanation) => EnforcementDecision::Denied(explanation),
                VerifyResult::Indeterminate(explanation) => {
                    EnforcementDecision::Indeterminate(explanation)
                }
            },
        )
    }

    /// Canonicalizes and verifies one request in the basic integration path.
    ///
    /// The caller must execute only the command from
    /// [`EnforcementDecision::Authorized`], never its original request.
    ///
    /// # Errors
    ///
    /// Returns a typed profile or SDK configuration failure.
    pub fn verify(
        &self,
        proof_cbor: &[u8],
        untrusted_action: &[u8],
        request: &RequestContext,
    ) -> Result<EnforcementDecision<P::Command>, EnforcementError> {
        let prepared = self.prepare(untrusted_action)?;
        self.authorize(proof_cbor, &prepared, request)
    }
}

/// Exact canonical request and its human-reviewable representation.
pub struct PreparedAction {
    canonical: auths_sdk::model::CanonicalAction,
    display: ApprovalDisplay,
}

impl PreparedAction {
    /// Returns the unique canonical action that must be signed and verified.
    #[must_use]
    pub const fn canonical(&self) -> &auths_sdk::model::CanonicalAction {
        &self.canonical
    }

    /// Returns a review display bound to the canonical action digest.
    #[must_use]
    pub const fn approval_display(&self) -> &ApprovalDisplay {
        &self.display
    }
}

/// Protocol outcome at a service enforcement boundary.
pub enum EnforcementDecision<C> {
    /// Exact authority was established; execute only this sealed command.
    Authorized(Box<Authorized<C>>),
    /// Available trustworthy facts established rejection.
    Denied(Explanation),
    /// A required trustworthy fact or implementation is unavailable.
    Indeterminate(Explanation),
}

impl<C> EnforcementDecision<C> {
    /// Executes only an authorized command and otherwise returns the stable
    /// explanation without invoking application code.
    ///
    /// # Errors
    ///
    /// Propagates the application executor's typed error.
    pub fn execute<E>(self, executor: &E) -> Result<Execution<E::Output>, E::Error>
    where
        E: CommandExecutor<C>,
    {
        Ok(match self {
            Self::Authorized(authorized) => {
                Execution::Executed(executor.execute(authorized.command())?)
            }
            Self::Denied(explanation) => Execution::Denied(explanation),
            Self::Indeterminate(explanation) => Execution::Indeterminate(explanation),
        })
    }
}

/// Application-owned executor that can receive only a verified command.
pub trait CommandExecutor<C> {
    /// Successful execution output.
    type Output;
    /// Application execution failure.
    type Error;

    /// Executes an executor-safe command decoded from sealed verifier output.
    ///
    /// # Errors
    ///
    /// Returns the application integration's typed execution error.
    fn execute(&self, command: &C) -> Result<Self::Output, Self::Error>;
}

/// Complete enforcement-and-execution outcome.
pub enum Execution<T> {
    /// The verified command was executed.
    Executed(T),
    /// The command was not executed because authority was denied.
    Denied(Explanation),
    /// The command was not executed because a requirement was unavailable.
    Indeterminate(Explanation),
}

/// HTTP middleware entry point.
pub type HttpMiddleware<P> = Enforcement<P>;
/// gRPC interceptor entry point.
pub type GrpcInterceptor<P> = Enforcement<P>;
/// CI authorization-gate entry point.
pub type CiGate<P> = Enforcement<P>;
/// Internal deployment service entry point.
pub type DeploymentEnforcement<P> = Enforcement<P>;
/// MCP server entry point.
pub type McpEnforcement<P> = Enforcement<P>;

/// Enforcement configuration or profile failure.
#[derive(Debug, Error)]
pub enum EnforcementError {
    /// Request input violated the selected application profile.
    #[error("request does not satisfy the selected Auths profile: {0}")]
    Profile(#[from] ProfileContractError),
    /// Embedded verifier configuration or verified decoding failed.
    #[error("Auths verification integration failed: {0}")]
    Sdk(#[from] SdkError),
}
