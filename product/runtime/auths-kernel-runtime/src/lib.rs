//! Minimal profile-free in-process Auths verification kernel.

#![forbid(unsafe_code)]

use auths_model::{Audience, CanonicalAction, Challenge, DenialReason, Timestamp, VerifierContext};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_registries::ImmutableRegistries;
use auths_verifier::{VerificationOutcome, verify};
use std::fmt;

/// Owned immutable verifier context and executable method registries.
pub struct AuthsKernel {
    context_template: VerifierContext,
    principal_methods: Vec<Box<dyn PrincipalMethod + Send + Sync>>,
    signature_suites: Vec<Box<dyn SignatureSuite + Send + Sync>>,
}

impl AuthsKernel {
    /// Constructs a profile-free kernel from explicit immutable inputs.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when either executable registry is empty.
    pub fn new(
        context_template: VerifierContext,
        principal_methods: Vec<Box<dyn PrincipalMethod + Send + Sync>>,
        signature_suites: Vec<Box<dyn SignatureSuite + Send + Sync>>,
    ) -> Result<Self, KernelConfigurationError> {
        if principal_methods.is_empty() || signature_suites.is_empty() {
            return Err(KernelConfigurationError::MissingRegistryImplementation);
        }
        Ok(Self {
            context_template,
            principal_methods,
            signature_suites,
        })
    }

    /// Verifies one canonical action and returns the exact request context used.
    ///
    /// The returned context lets optional outer runtimes bind receipts without reconstructing
    /// verifier inputs. This method performs no I/O, replay claim, budget claim, or command decode.
    ///
    /// # Errors
    ///
    /// Returns a stable denial reason when the request context cannot be constructed.
    pub fn verify_with_context(
        &self,
        proof: &[u8],
        canonical_action: &CanonicalAction,
        expected_audience: Audience,
        expected_challenge: Challenge,
        evaluation_time: Timestamp,
    ) -> Result<(VerificationOutcome, VerifierContext), DenialReason> {
        let context = self
            .context_template
            .for_request(expected_audience, expected_challenge, evaluation_time)
            .map_err(|_| DenialReason::LocalPolicyDenied)?;
        let methods: Vec<&dyn PrincipalMethod> = self
            .principal_methods
            .iter()
            .map(|method| method.as_ref() as &dyn PrincipalMethod)
            .collect();
        let suites: Vec<&dyn SignatureSuite> = self
            .signature_suites
            .iter()
            .map(|suite| suite.as_ref() as &dyn SignatureSuite)
            .collect();
        let registries = ImmutableRegistries::new(&methods, &suites)
            .map_err(|_| DenialReason::LocalPolicyDenied)?;
        Ok((
            verify(proof, canonical_action, &context, &registries),
            context,
        ))
    }

    /// Verifies one canonical action with explicit per-request values.
    ///
    /// This performs no I/O and does not claim replay or stateful budget.
    #[must_use]
    pub fn verify(
        &self,
        proof: &[u8],
        canonical_action: &CanonicalAction,
        expected_audience: Audience,
        expected_challenge: Challenge,
        evaluation_time: Timestamp,
    ) -> VerificationOutcome {
        self.verify_with_context(
            proof,
            canonical_action,
            expected_audience,
            expected_challenge,
            evaluation_time,
        )
        .map_or_else(VerificationOutcome::Denied, |(outcome, _)| outcome)
    }

    /// Returns the immutable context template.
    #[must_use]
    pub const fn context_template(&self) -> &VerifierContext {
        &self.context_template
    }
}

/// Minimal kernel configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelConfigurationError {
    /// No principal-method or signature-suite implementation was supplied.
    MissingRegistryImplementation,
}

impl fmt::Display for KernelConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("missing exact registry implementation")
    }
}

impl std::error::Error for KernelConfigurationError {}
