//! Narrow protected effect boundary for bounded Stripe merchant authorizations.

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};

use super::profile::{StripePaymentAuthorizeCommand, StripePaymentAuthorizeProfile};
use crate::{
    merchant::{
        MerchantConnectAccount, MerchantPaymentEvidenceV1, StripeExactPaymentAuthorizeV1,
        fixed_merchant_metadata_commitment,
        state::{MerchantProviderProjection, MerchantReservationRecord, MerchantReservationState},
    },
    ports::{PaymentAuthorizeCredential, PortError},
    types::{DigestHex, StripeAccountId},
};

/// Exact authorization proof-verification result.
pub enum PaymentAuthorizeProofDecision {
    /// Exact authority was established.
    Authorized(Box<Authorized<StripePaymentAuthorizeCommand>>),
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

/// Auths kernel boundary fixed to the exact authorization profile.
pub trait PaymentAuthorizeProofVerifier: Send + Sync {
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
    ) -> Result<PaymentAuthorizeProofDecision, PortError>;
}

impl<T: PaymentAuthorizeProofVerifier + ?Sized> PaymentAuthorizeProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentAuthorizeProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}

/// SDK adapter fixed to `auths.stripe.exact-payment-authorize/1`.
pub struct SdkPaymentAuthorizeProofVerifier {
    verifier: Verifier,
}

impl SdkPaymentAuthorizeProofVerifier {
    /// Wraps an explicitly configured Auths verifier.
    #[must_use]
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl PaymentAuthorizeProofVerifier for SdkPaymentAuthorizeProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentAuthorizeProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &StripePaymentAuthorizeProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(authorized) => {
                Ok(PaymentAuthorizeProofDecision::Authorized(authorized))
            }
            VerifyResult::Denied(explanation) => Ok(PaymentAuthorizeProofDecision::Denied {
                code: explanation.code().into(),
            }),
            VerifyResult::Indeterminate(explanation) => {
                Ok(PaymentAuthorizeProofDecision::Indeterminate {
                    code: explanation.code().into(),
                })
            }
        }
    }
}

/// Protected pre-provider authorization command.
///
/// No public constructor exists. Only the service can combine an Auths-opened
/// exact action with completed bounded decision, reservation, and claim facts.
pub struct VerifiedPaymentAuthorizeCommand {
    authorized: Authorized<StripePaymentAuthorizeCommand>,
    workflow_id: String,
    evidence: MerchantPaymentEvidenceV1,
    policy_digest: DigestHex,
    reservation_id: DigestHex,
    decision_receipt_digest: DigestHex,
    required_configuration_digest: DigestHex,
    executed_configuration_digest: DigestHex,
    minimum_capture_window_seconds: u64,
    idempotency_key: String,
}

/// Closed create-and-confirm request derived from a verified authorization command.
///
/// The adapter can read these fixed fields but cannot add an endpoint,
/// arbitrary metadata, capture mode, redirect, or unrestricted parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentAuthorizeProviderRequest {
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

impl PaymentAuthorizeProviderRequest {
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

    /// Fixed manual capture method.
    #[must_use]
    pub fn capture_method(&self) -> &str {
        &self.capture_method
    }

    /// Fixed protected statement suffix.
    #[must_use]
    pub fn statement_descriptor_suffix(&self) -> &str {
        &self.statement_descriptor_suffix
    }

    /// Exact authorization profile metadata.
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

impl VerifiedPaymentAuthorizeCommand {
    #[allow(
        clippy::too_many_arguments,
        reason = "the private command constructor requires every completed trust-boundary fact"
    )]
    pub(crate) fn new(
        authorized: Authorized<StripePaymentAuthorizeCommand>,
        workflow_id: String,
        evidence: MerchantPaymentEvidenceV1,
        policy_digest: DigestHex,
        reservation_id: DigestHex,
        decision_receipt_digest: DigestHex,
        required_configuration_digest: DigestHex,
        executed_configuration_digest: DigestHex,
        minimum_capture_window_seconds: u64,
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
            minimum_capture_window_seconds,
            idempotency_key,
        }
    }

    /// Exact action opened by Auths.
    #[must_use]
    pub fn action(&self) -> &StripeExactPaymentAuthorizeV1 {
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

    /// Minimum provider-observed time left to capture this hold.
    #[must_use]
    pub const fn minimum_capture_window_seconds(&self) -> u64 {
        self.minimum_capture_window_seconds
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
    pub fn provider_request(&self) -> PaymentAuthorizeProviderRequest {
        PaymentAuthorizeProviderRequest {
            amount_minor: self.action().authorized_amount_minor(),
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

/// Normalized result of one create-and-confirm authorization request.
pub enum PaymentAuthorizeEffect {
    /// Stripe accepted and returned one bounded response.
    Accepted(MerchantProviderProjection),
    /// Stripe definitively declined without authorizeing funds.
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

/// Closed events in the manual-capture authorization lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentAuthorizeTransition {
    /// Exact verified command claims a new reservation.
    Claim,
    /// Provider delivery is about to begin.
    BeginAttempt,
    /// A bounded provider response is durably accepted.
    ProviderAccepted,
    /// Fresh observation proves the authorization is held and capturable.
    AuthorizationHeld,
    /// Definite non-execution returns capacity.
    DefiniteFailureReleased,
    /// Provider delivery or state is ambiguous.
    OutcomeBecameUnknown,
    /// Retrieval proves the authorization remains held and capturable.
    ReconcileHeld,
    /// Retrieval proves definite non-execution.
    ReconcileReleased,
    /// Retrieval remains ambiguous.
    ReconcileStillUnknown,
}

/// Returns the only legal next state for manual-capture authorization.
///
/// This profile-owned function deliberately accepts no merchant-operation
/// selector. Other payment effects must define their own transition function.
#[must_use]
pub const fn transition_payment_authorize(
    current: MerchantReservationState,
    event: PaymentAuthorizeTransition,
) -> Option<MerchantReservationState> {
    use MerchantReservationState::{
        Attempting, Claimed, OutcomeUnknown, ProviderAccepted, Reserved,
    };
    use PaymentAuthorizeTransition::{
        AuthorizationHeld, BeginAttempt, Claim, DefiniteFailureReleased, OutcomeBecameUnknown,
        ProviderAccepted as ProviderAcceptedEvent, ReconcileHeld, ReconcileReleased,
        ReconcileStillUnknown,
    };

    match (current, event) {
        (Reserved, Claim) => Some(Claimed),
        (Claimed, BeginAttempt) => Some(Attempting),
        (Attempting, ProviderAcceptedEvent) => Some(ProviderAccepted),
        (ProviderAccepted, AuthorizationHeld) => Some(MerchantReservationState::Authorized),
        (Reserved | Claimed | Attempting, DefiniteFailureReleased) => {
            Some(MerchantReservationState::Released)
        }
        (Claimed | Attempting | ProviderAccepted, OutcomeBecameUnknown)
        | (
            Reserved | Claimed | Attempting | ProviderAccepted | OutcomeUnknown,
            ReconcileStillUnknown,
        ) => Some(OutcomeUnknown),
        (Reserved | Claimed | Attempting | ProviderAccepted | OutcomeUnknown, ReconcileHeld) => {
            Some(MerchantReservationState::ReconciledAuthorized)
        }
        (
            Reserved | Claimed | Attempting | ProviderAccepted | OutcomeUnknown,
            ReconcileReleased,
        ) => Some(MerchantReservationState::ReconciledReleased),
        _ => None,
    }
}

/// Fresh Stripe facts used to reconcile one manual-capture authorization.
pub enum PaymentAuthorizeReconciliationOutcome {
    /// Retrieval proves the authorization remains held and capturable.
    Held(MerchantProviderProjection),
    /// Retrieval proves definite non-execution.
    Released(Option<MerchantProviderProjection>),
    /// Retrieval cannot yet establish a terminal result.
    OutcomeUnknown(Option<MerchantProviderProjection>),
}

/// Only Stripe provider surface reachable by a verified authorization command.
pub trait PaymentAuthorizeGateway: Send + Sync {
    /// Re-reads the critical Customer, `PaymentMethod`, and order facts.
    ///
    /// # Errors
    ///
    /// Returns a closed credential, provider, or evidence failure.
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentAuthorizeCommand,
        credential: &PaymentAuthorizeCredential,
        now: u64,
    ) -> Result<MerchantPaymentEvidenceV1, PortError>;

    /// Creates and confirms exactly one manual-capture `PaymentIntent`.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter failure. Ambiguous delivery is normally
    /// represented by [`PaymentAuthorizeEffect::OutcomeUnknown`].
    fn authorize(
        &self,
        command: &VerifiedPaymentAuthorizeCommand,
        credential: &PaymentAuthorizeCredential,
        now: u64,
    ) -> Result<PaymentAuthorizeEffect, PortError>;

    /// Retrieves the exact `PaymentIntent` and latest Charge after acceptance.
    ///
    /// # Errors
    ///
    /// Returns a closed retrieval or projection failure.
    fn observe(
        &self,
        command: &VerifiedPaymentAuthorizeCommand,
        credential: &PaymentAuthorizeCredential,
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
        credential: &PaymentAuthorizeCredential,
        now: u64,
    ) -> Result<PaymentAuthorizeReconciliationOutcome, PortError>;
}

impl<T: PaymentAuthorizeGateway + ?Sized> PaymentAuthorizeGateway for Arc<T> {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentAuthorizeCommand,
        credential: &PaymentAuthorizeCredential,
        now: u64,
    ) -> Result<MerchantPaymentEvidenceV1, PortError> {
        (**self).reread_critical_evidence(command, credential, now)
    }

    fn authorize(
        &self,
        command: &VerifiedPaymentAuthorizeCommand,
        credential: &PaymentAuthorizeCredential,
        now: u64,
    ) -> Result<PaymentAuthorizeEffect, PortError> {
        (**self).authorize(command, credential, now)
    }

    fn observe(
        &self,
        command: &VerifiedPaymentAuthorizeCommand,
        credential: &PaymentAuthorizeCredential,
        payment_intent: &crate::types::PaymentIntentId,
        now: u64,
    ) -> Result<MerchantProviderProjection, PortError> {
        (**self).observe(command, credential, payment_intent, now)
    }

    fn reconcile(
        &self,
        record: &MerchantReservationRecord,
        credential: &PaymentAuthorizeCredential,
        now: u64,
    ) -> Result<PaymentAuthorizeReconciliationOutcome, PortError> {
        (**self).reconcile(record, credential, now)
    }
}

/// Protected Connect header for the provider adapter.
#[must_use]
#[allow(
    dead_code,
    reason = "the authorization demo adapter will consume this closed Connect header projection"
)]
pub fn connected_account_header(connect: &MerchantConnectAccount) -> Option<&StripeAccountId> {
    connect.connected_account_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_transition_is_closed_and_profile_owned() {
        assert_eq!(
            transition_payment_authorize(
                MerchantReservationState::Reserved,
                PaymentAuthorizeTransition::Claim,
            ),
            Some(MerchantReservationState::Claimed)
        );
        assert_eq!(
            transition_payment_authorize(
                MerchantReservationState::ProviderAccepted,
                PaymentAuthorizeTransition::AuthorizationHeld,
            ),
            Some(MerchantReservationState::Authorized)
        );
        assert_eq!(
            transition_payment_authorize(
                MerchantReservationState::Authorized,
                PaymentAuthorizeTransition::ReconcileReleased,
            ),
            None
        );
    }
}
