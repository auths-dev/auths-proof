//! Shared Auths and clock adapters for the Stripe profile.

use std::time::{SystemTime, UNIX_EPOCH};

use auths_sdk::{RequestContext, Verifier, VerifyResult};

use crate::{
    ports::{Clock, PortError, ProofDecision, ProofVerifier},
    profile::StripeRefundProfile,
};

/// Auths SDK adapter fixed to the exact-refund profile.
pub struct SdkProofVerifier {
    verifier: Verifier,
}

impl SdkProofVerifier {
    /// Wraps an explicitly configured Auths verifier.
    #[must_use]
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl ProofVerifier for SdkProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &auths_model::CanonicalAction,
        request: &RequestContext,
    ) -> Result<ProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &StripeRefundProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(authorized) => Ok(ProofDecision::Authorized(authorized)),
            VerifyResult::Denied(explanation) => Ok(ProofDecision::Denied {
                code: explanation.code().into(),
            }),
            VerifyResult::Indeterminate(explanation) => Ok(ProofDecision::Indeterminate {
                code: explanation.code().into(),
            }),
        }
    }
}

/// Trusted operating-system wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<u64, PortError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| PortError::InvalidConfiguration)
    }
}
