//! Narrow protected effect boundary for bounded Stripe merchant collections.

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};

use super::profile::{StripePaymentCollectCommand, StripePaymentCollectProfile};
use crate::{
    merchant::{
        MerchantConnectAccount, MerchantPaymentEvidenceV1, StripeExactPaymentCollectV1,
        fixed_merchant_metadata_commitment,
        state::{MerchantProviderProjection, MerchantReservationRecord, MerchantReservationState},
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

/// Closed create-and-confirm request derived from a verified collection command.
///
/// The adapter can read these fixed fields but cannot add an endpoint,
/// arbitrary metadata, capture mode, redirect, or unrestricted parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentCollectProviderRequest {
    amount_minor: u64,
    currency: String,
    customer_id: String,
    payment_method_id: String,
    payment_method_type: String,
    confirmation_method: String,
    capture_method: String,
    statement_descriptor_suffix: String,
    profile: String,
    order_scope: String,
    policy_digest: String,
    workflow_id: String,
}

impl PaymentCollectProviderRequest {
    /// Exact amount in minor units.
    #[must_use]
    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }

    /// Exact lower-case currency.
    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// Exact Stripe Customer.
    #[must_use]
    pub fn customer_id(&self) -> &str {
        &self.customer_id
    }

    /// Exact attached `PaymentMethod`.
    #[must_use]
    pub fn payment_method_id(&self) -> &str {
        &self.payment_method_id
    }

    /// Fixed V1 `PaymentMethod` type.
    #[must_use]
    pub fn payment_method_type(&self) -> &str {
        &self.payment_method_type
    }

    /// Fixed server-side confirmation method.
    #[must_use]
    pub fn confirmation_method(&self) -> &str {
        &self.confirmation_method
    }

    /// Fixed automatic capture method.
    #[must_use]
    pub fn capture_method(&self) -> &str {
        &self.capture_method
    }

    /// Fixed protected statement suffix.
    #[must_use]
    pub fn statement_descriptor_suffix(&self) -> &str {
        &self.statement_descriptor_suffix
    }

    /// Exact collection profile metadata.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Exact protected order metadata.
    #[must_use]
    pub fn order_scope(&self) -> &str {
        &self.order_scope
    }

    /// Immutable policy metadata commitment.
    #[must_use]
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    /// Durable workflow metadata.
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
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

    /// Derives the only provider request shape accepted by this profile.
    #[must_use]
    pub fn provider_request(&self) -> PaymentCollectProviderRequest {
        PaymentCollectProviderRequest {
            amount_minor: self.action().amount_minor(),
            currency: self.action().currency().to_string(),
            customer_id: self.action().customer_id().to_string(),
            payment_method_id: self.action().payment_method_id().to_string(),
            payment_method_type: self.action().payment_method_type().into(),
            confirmation_method: self.action().confirmation_method().into(),
            capture_method: self.action().capture_method().into(),
            statement_descriptor_suffix: self.statement_descriptor().into(),
            profile: self.action().profile().into(),
            order_scope: self.action().order_scope().into(),
            policy_digest: self.policy_digest.to_string(),
            workflow_id: self.workflow_id.clone(),
        }
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

/// Closed events in the automatic-collection lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentCollectTransition {
    /// Exact verified command claims a new reservation.
    Claim,
    /// Provider delivery is about to begin.
    BeginAttempt,
    /// A bounded provider response is durably accepted.
    ProviderAccepted,
    /// Fresh observation proves automatic capture succeeded.
    CollectionCommitted,
    /// Definite non-execution returns capacity.
    DefiniteFailureReleased,
    /// Provider delivery or state is ambiguous.
    OutcomeBecameUnknown,
    /// Retrieval proves collection succeeded.
    ReconcileCommitted,
    /// Retrieval proves definite non-execution.
    ReconcileReleased,
    /// Retrieval remains ambiguous.
    ReconcileStillUnknown,
}

/// Returns the only legal next state for automatic collection.
///
/// This profile-owned function deliberately accepts no merchant-operation
/// selector. Other payment effects must define their own transition function.
#[must_use]
pub const fn transition_payment_collect(
    current: MerchantReservationState,
    event: PaymentCollectTransition,
) -> Option<MerchantReservationState> {
    use MerchantReservationState::{
        Attempting, Claimed, OutcomeUnknown, ProviderAccepted, Reserved,
    };
    use PaymentCollectTransition::{
        BeginAttempt, Claim, CollectionCommitted, DefiniteFailureReleased, OutcomeBecameUnknown,
        ProviderAccepted as ProviderAcceptedEvent, ReconcileCommitted, ReconcileReleased,
        ReconcileStillUnknown,
    };

    match (current, event) {
        (Reserved, Claim) => Some(Claimed),
        (Claimed, BeginAttempt) => Some(Attempting),
        (Attempting, ProviderAcceptedEvent) => Some(ProviderAccepted),
        (ProviderAccepted, CollectionCommitted) => Some(MerchantReservationState::Committed),
        (Reserved | Claimed | Attempting, DefiniteFailureReleased) => {
            Some(MerchantReservationState::Released)
        }
        (Claimed | Attempting | ProviderAccepted, OutcomeBecameUnknown)
        | (
            Reserved | Claimed | Attempting | ProviderAccepted | OutcomeUnknown,
            ReconcileStillUnknown,
        ) => Some(OutcomeUnknown),
        (
            Reserved | Claimed | Attempting | ProviderAccepted | OutcomeUnknown,
            ReconcileCommitted,
        ) => Some(MerchantReservationState::ReconciledCommitted),
        (
            Reserved | Claimed | Attempting | ProviderAccepted | OutcomeUnknown,
            ReconcileReleased,
        ) => Some(MerchantReservationState::ReconciledReleased),
        _ => None,
    }
}

/// Fresh Stripe facts used to reconcile one automatic collection.
pub enum PaymentCollectReconciliationOutcome {
    /// Retrieval proves the automatic collection succeeded.
    Committed(MerchantProviderProjection),
    /// Retrieval proves definite non-execution.
    Released(Option<MerchantProviderProjection>),
    /// Retrieval cannot yet establish a terminal result.
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
    ) -> Result<PaymentCollectReconciliationOutcome, PortError>;
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
    ) -> Result<PaymentCollectReconciliationOutcome, PortError> {
        (**self).reconcile(record, credential, now)
    }
}

/// Protected Connect header for the provider adapter.
#[must_use]
pub fn connected_account_header(connect: &MerchantConnectAccount) -> Option<&StripeAccountId> {
    connect.connected_account_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_transition_is_closed_and_profile_owned() {
        assert_eq!(
            transition_payment_collect(
                MerchantReservationState::Reserved,
                PaymentCollectTransition::Claim,
            ),
            Some(MerchantReservationState::Claimed)
        );
        assert_eq!(
            transition_payment_collect(
                MerchantReservationState::ProviderAccepted,
                PaymentCollectTransition::CollectionCommitted,
            ),
            Some(MerchantReservationState::Committed)
        );
        assert_eq!(
            transition_payment_collect(
                MerchantReservationState::Committed,
                PaymentCollectTransition::ReconcileReleased,
            ),
            None
        );
    }
}
