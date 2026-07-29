//! Small reusable in-memory adapters.

use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use auths_sdk::{RequestContext, Verifier, VerifyResult};

use crate::{
    ports::{Clock, PortError, ProofDecision, ProofVerifier, ReceiptSink},
    profile::KubernetesRolloutProfile,
    receipts::KubernetesReceipt,
};

/// Auths SDK adapter fixed to the Kubernetes rollout profile.
pub struct SdkProofVerifier {
    verifier: Verifier,
}

impl SdkProofVerifier {
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
            .verify(proof, action, request, &KubernetesRolloutProfile)
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

/// Append-only memory receipt sink.
#[derive(Clone, Default)]
pub struct MemoryReceiptSink {
    receipts: Arc<Mutex<Vec<KubernetesReceipt>>>,
}

impl MemoryReceiptSink {
    #[must_use]
    pub fn receipts(&self) -> Vec<KubernetesReceipt> {
        self.receipts
            .lock()
            .map_or_else(|_| Vec::new(), |receipts| receipts.clone())
    }
}

impl ReceiptSink for MemoryReceiptSink {
    fn append(&self, receipt: &KubernetesReceipt) -> Result<(), PortError> {
        self.receipts
            .lock()
            .map_err(|_| PortError::Persistence)?
            .push(receipt.clone());
        Ok(())
    }
}

/// Fixed trusted clock.
#[derive(Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now(&self) -> Result<u64, PortError> {
        Ok(self.0)
    }
}
