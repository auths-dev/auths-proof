//! Narrow protected effect boundary for bounded Stripe merchant collections.

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};

use super::profile::{StripePaymentCollectCommand, StripePaymentCollectProfile};
use crate::{
    merchant::{
        MerchantConnectAccount, MerchantPaymentEvidenceV1, StripeExactPaymentCollectV1,
        fixed_merchant_metadata_commitment,
        state::{MerchantProviderProjection, MerchantReservationRecord, ReconciledMerchantOutcome},
    },
    ports::{PortError, StripeCredential},
    types::{DigestHex, StripeAccountId},
};

/// Exact collection proof-verification result.
pub enum PaymentCollectProofDecision {
    /// Exact authority was established.
    Authorized(Box<Authorized<StripePaymentCollectCommand>>),
    /// Complete inputs establish denial.
    Denied {
        /// Stable Auths code.
        code: String,
    },
    /// Trusted verification input or implementation is unavailable.
    Indeterminate {
        /// Stable Auths code.
        code: String,
    },
}

/// Auths kernel boundary fixed to the exact collection profile.
pub trait PaymentCollectProofVerifier: Send + Sync {
    /// Verifies proof against an already canonicalized exact action.
    ///
    /// # Errors
    ///
    /// Returns a closed verifier integration failure.
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentCollectProofDecision, PortError>;
}

impl<T: PaymentCollectProofVerifier + ?Sized> PaymentCollectProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentCollectProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}

/// SDK adapter fixed to `auths.stripe.exact-payment-collect/1`.
pub struct SdkPaymentCollectProofVerifier {
    verifier: Verifier,
}

impl SdkPaymentCollectProofVerifier {
    /// Wraps an explicitly configured Auths verifier.
    #[must_use]
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl PaymentCollectProofVerifier for SdkPaymentCollectProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentCollectProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &StripePaymentCollectProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(authorized) => {
                Ok(PaymentCollectProofDecision::Authorized(authorized))
            }
            VerifyResult::Denied(explanation) => Ok(PaymentCollectProofDecision::Denied {
                code: explanation.code().into(),
            }),
            VerifyResult::Indeterminate(explanation) => {
                Ok(PaymentCollectProofDecision::Indeterminate {
                    code: explanation.code().into(),
                })
            }
        }
    }
}

/// Protected pre-provider collection command.
///
/// No public constructor exists. Only the service can combine an Auths-opened
/// exact action with completed bounded decision, reservation, and claim facts.
pub struct VerifiedPaymentCollectCommand {
    authorized: Authorized<StripePaymentCollectCommand>,
    workflow_id: String,
    evidence: MerchantPaymentEvidenceV1,
    policy_digest: DigestHex,
    reservation_id: DigestHex,
    decision_receipt_digest: DigestHex,
    required_configuration_digest: DigestHex,
    executed_configuration_digest: DigestHex,
    idempotency_key: String,
}

impl VerifiedPaymentCollectCommand {
    #[allow(
        clippy::too_many_arguments,
        reason = "the private command constructor requires every completed trust-boundary fact"
    )]
    pub(crate) fn new(
        authorized: Authorized<StripePaymentCollectCommand>,
        workflow_id: String,
        evidence: MerchantPaymentEvidenceV1,
        policy_digest: DigestHex,
        reservation_id: DigestHex,
        decision_receipt_digest: DigestHex,
        required_configuration_digest: DigestHex,
        executed_configuration_digest: DigestHex,
        idempotency_key: String,
    ) -> Self {
        Self {
            authorized,
            workflow_id,
            evidence,
            policy_digest,
            reservation_id,
            decision_receipt_digest,
            required_configuration_digest,
            executed_configuration_digest,
            idempotency_key,
        }
    }

    /// Exact action opened by Auths.
    #[must_use]
    pub fn action(&self) -> &StripeExactPaymentCollectV1 {
        self.authorized.command().action()
    }

    /// Durable workflow identity.
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Eligibility evidence bound to the command.
    #[must_use]
    pub const fn evidence(&self) -> &MerchantPaymentEvidenceV1 {
        &self.evidence
    }

    /// Immutable configured-policy commitment.
    #[must_use]
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }

    /// Durable reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> &DigestHex {
        &self.reservation_id
    }

    /// Durable decision receipt commitment.
    #[must_use]
    pub const fn decision_receipt_digest(&self) -> &DigestHex {
        &self.decision_receipt_digest
    }

    /// Required runtime configuration commitment.
    #[must_use]
    pub const fn required_configuration_digest(&self) -> &DigestHex {
        &self.required_configuration_digest
    }

    /// Executed runtime configuration commitment.
    #[must_use]
    pub const fn executed_configuration_digest(&self) -> &DigestHex {
        &self.executed_configuration_digest
    }

    /// Stable server-derived Stripe idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Fixed statement descriptor constructed by the product.
    #[must_use]
    pub const fn statement_descriptor(&self) -> &'static str {
        crate::merchant::PAYMENT_STATEMENT_DESCRIPTOR
    }

    /// Recomputes the exact fixed metadata commitment.
    ///
    /// # Errors
    ///
    /// Returns a closed malformed-command error.
    pub fn metadata_commitment(&self) -> Result<DigestHex, PortError> {
        fixed_merchant_metadata_commitment(
            &self.workflow_id,
            self.action().profile(),
            self.action().order_scope(),
            &self.policy_digest,
        )
        .map_err(|_| PortError::Malformed)
    }
}

/// Normalized result of one create-and-confirm collection request.
pub enum PaymentCollectEffect {
    /// Stripe accepted and returned one bounded response.
    Accepted(MerchantProviderProjection),
    /// Stripe definitively declined without collecting funds.
    Declined {
        /// Stable, non-secret provider category.
        code: String,
    },
    /// Adapter proved no create request was delivered to Stripe.
    NotDelivered {
        /// Stable non-secret transport category.
        code: String,
    },
    /// V1 forbids a customer-action continuation.
    CustomerActionRequired(MerchantProviderProjection),
    /// Stripe is processing; capacity remains unknown.
    Processing(MerchantProviderProjection),
    /// Delivery or response was ambiguous.
    OutcomeUnknown(Option<MerchantProviderProjection>),
}

/// Only Stripe provider surface reachable by a verified collection command.
pub trait PaymentCollectGateway: Send + Sync {
    /// Re-reads the critical Customer, `PaymentMethod`, and order facts.
    ///
    /// # Errors
    ///
    /// Returns a closed credential, provider, or evidence failure.
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentCollectCommand,
        credential: &StripeCredential,
        now: u64,
    ) -> Result<MerchantPaymentEvidenceV1, PortError>;

    /// Creates and confirms exactly one automatic-capture `PaymentIntent`.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter failure. Ambiguous delivery is normally
    /// represented by [`PaymentCollectEffect::OutcomeUnknown`].
    fn collect(
        &self,
        command: &VerifiedPaymentCollectCommand,
        credential: &StripeCredential,
        now: u64,
    ) -> Result<PaymentCollectEffect, PortError>;

    /// Retrieves the exact `PaymentIntent` and latest Charge after acceptance.
    ///
    /// # Errors
    ///
    /// Returns a closed retrieval or projection failure.
    fn observe(
        &self,
        command: &VerifiedPaymentCollectCommand,
        credential: &StripeCredential,
        payment_intent: &crate::types::PaymentIntentId,
        now: u64,
    ) -> Result<MerchantProviderProjection, PortError>;

    /// Reconciles durable state without issuing another create request.
    ///
    /// # Errors
    ///
    /// Returns a closed retrieval or projection failure.
    fn reconcile(
        &self,
        record: &MerchantReservationRecord,
        credential: &StripeCredential,
        now: u64,
    ) -> Result<ReconciledMerchantOutcome, PortError>;
}

impl<T: PaymentCollectGateway + ?Sized> PaymentCollectGateway for Arc<T> {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentCollectCommand,
        credential: &StripeCredential,
        now: u64,
    ) -> Result<MerchantPaymentEvidenceV1, PortError> {
        (**self).reread_critical_evidence(command, credential, now)
    }

    fn collect(
        &self,
        command: &VerifiedPaymentCollectCommand,
        credential: &StripeCredential,
        now: u64,
    ) -> Result<PaymentCollectEffect, PortError> {
        (**self).collect(command, credential, now)
    }

    fn observe(
        &self,
        command: &VerifiedPaymentCollectCommand,
        credential: &StripeCredential,
        payment_intent: &crate::types::PaymentIntentId,
        now: u64,
    ) -> Result<MerchantProviderProjection, PortError> {
        (**self).observe(command, credential, payment_intent, now)
    }

    fn reconcile(
        &self,
        record: &MerchantReservationRecord,
        credential: &StripeCredential,
        now: u64,
    ) -> Result<ReconciledMerchantOutcome, PortError> {
        (**self).reconcile(record, credential, now)
    }
}

/// Protected Connect header for the provider adapter.
#[must_use]
pub fn connected_account_header(connect: &MerchantConnectAccount) -> Option<&StripeAccountId> {
    connect.connected_account_id()
}
