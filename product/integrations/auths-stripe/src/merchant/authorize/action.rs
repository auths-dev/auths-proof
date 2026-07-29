//! Exact manual-capture Stripe authorization action.

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::{Currency, CustomerId, DigestHex, PaymentMethodId, StripeAccountId},
};

use super::super::{
    MerchantConnectAccount, MerchantEvaluatorCommitment, MerchantValidationError,
    PAYMENT_AUTHORIZE_PROFILE, valid_api_version, valid_local_id, valid_payment_method_type,
};

const MAX_MONEY_MINOR: u64 = 99_999_999;

/// Exact manual-capture authorization action.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the exact action commits independent forbidden Stripe modes explicitly"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeExactPaymentAuthorizeV1 {
    profile: String,
    stripe_account_id: StripeAccountId,
    connect_account: MerchantConnectAccount,
    customer_id: CustomerId,
    payment_method_id: PaymentMethodId,
    payment_method_type: String,
    order_scope: String,
    authorized_amount_minor: u64,
    currency: Currency,
    capture_method: String,
    confirmation_method: String,
    off_session: bool,
    error_on_requires_action: bool,
    request_extended_authorization: bool,
    request_incremental_authorization: bool,
    statement_descriptor_commitment: DigestHex,
    fixed_metadata_commitment: DigestHex,
    stripe_api_version: String,
    required_policy_digest: DigestHex,
    required_evaluator: MerchantEvaluatorCommitment,
    required_configuration_digest: DigestHex,
    executor_audience: String,
    expires_at: u64,
    nonce: DigestHex,
}

/// Inputs for the exact manual-capture authorization action.
pub struct StripeExactPaymentAuthorizeInput {
    /// Stripe account.
    pub stripe_account_id: StripeAccountId,
    /// Platform or Connect context.
    pub connect_account: MerchantConnectAccount,
    /// Customer.
    pub customer_id: CustomerId,
    /// Attached `PaymentMethod`.
    pub payment_method_id: PaymentMethodId,
    /// `PaymentMethod` type.
    pub payment_method_type: String,
    /// Protected order scope.
    pub order_scope: String,
    /// Positive authorized minor units.
    pub authorized_amount_minor: u64,
    /// Currency.
    pub currency: Currency,
    /// Protected statement descriptor commitment.
    pub statement_descriptor_commitment: DigestHex,
    /// Protected fixed metadata commitment.
    pub fixed_metadata_commitment: DigestHex,
    /// Pinned Stripe API version.
    pub stripe_api_version: String,
    /// Required immutable policy.
    pub required_policy_digest: DigestHex,
    /// Required runtime configuration.
    pub required_configuration_digest: DigestHex,
    /// Exact executor audience.
    pub executor_audience: String,
    /// Action expiry.
    pub expires_at: u64,
    /// Fresh replay nonce.
    pub nonce: DigestHex,
}

impl StripeExactPaymentAuthorizeV1 {
    /// Builds V1 manual capture with no extended or incremental modes.
    ///
    /// # Errors
    ///
    /// Rejects malformed or unsafe exact-authorization input.
    pub fn new(input: StripeExactPaymentAuthorizeInput) -> Result<Self, MerchantValidationError> {
        let value = Self {
            profile: PAYMENT_AUTHORIZE_PROFILE.into(),
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            customer_id: input.customer_id,
            payment_method_id: input.payment_method_id,
            payment_method_type: input.payment_method_type,
            order_scope: input.order_scope,
            authorized_amount_minor: input.authorized_amount_minor,
            currency: input.currency,
            capture_method: "manual".into(),
            confirmation_method: "manual".into(),
            off_session: false,
            error_on_requires_action: true,
            request_extended_authorization: false,
            request_incremental_authorization: false,
            statement_descriptor_commitment: input.statement_descriptor_commitment,
            fixed_metadata_commitment: input.fixed_metadata_commitment,
            stripe_api_version: input.stripe_api_version,
            required_policy_digest: input.required_policy_digest,
            required_evaluator: MerchantEvaluatorCommitment::v1(),
            required_configuration_digest: input.required_configuration_digest,
            executor_audience: input.executor_audience,
            expires_at: input.expires_at,
            nonce: input.nonce,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates decoded exact authorization semantics.
    ///
    /// # Errors
    ///
    /// Rejects values outside the exact V1 authorization profile.
    pub fn validate(&self) -> Result<(), MerchantValidationError> {
        if self.profile != PAYMENT_AUTHORIZE_PROFILE
            || !valid_payment_method_type(&self.payment_method_type)
            || !valid_local_id(&self.order_scope)
            || self.authorized_amount_minor == 0
            || self.authorized_amount_minor > MAX_MONEY_MINOR
            || self.capture_method != "manual"
            || self.confirmation_method != "manual"
            || self.off_session
            || !self.error_on_requires_action
            || self.request_extended_authorization
            || self.request_incremental_authorization
            || !valid_api_version(&self.stripe_api_version)
            || self.required_evaluator != MerchantEvaluatorCommitment::v1()
            || Audience::parse(&self.executor_audience).is_err()
        {
            return Err(MerchantValidationError::InvalidAction);
        }
        Ok(())
    }

    /// Canonical exact-action bytes.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }

    /// Exact action digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Profile identifier.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Stripe account.
    #[must_use]
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }

    /// Connect context.
    #[must_use]
    pub const fn connect_account(&self) -> &MerchantConnectAccount {
        &self.connect_account
    }

    /// Customer.
    #[must_use]
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }

    /// `PaymentMethod`.
    #[must_use]
    pub const fn payment_method_id(&self) -> &PaymentMethodId {
        &self.payment_method_id
    }

    /// `PaymentMethod` type.
    #[must_use]
    pub fn payment_method_type(&self) -> &str {
        &self.payment_method_type
    }

    /// Protected order scope.
    #[must_use]
    pub fn order_scope(&self) -> &str {
        &self.order_scope
    }

    /// Exact authorized amount.
    #[must_use]
    pub const fn authorized_amount_minor(&self) -> u64 {
        self.authorized_amount_minor
    }

    /// Currency.
    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    /// Manual capture method.
    #[must_use]
    pub fn capture_method(&self) -> &str {
        &self.capture_method
    }

    /// Manual confirmation method.
    #[must_use]
    pub fn confirmation_method(&self) -> &str {
        &self.confirmation_method
    }

    /// Protected statement descriptor commitment.
    #[must_use]
    pub const fn statement_descriptor_commitment(&self) -> &DigestHex {
        &self.statement_descriptor_commitment
    }

    /// Protected fixed metadata commitment.
    #[must_use]
    pub const fn fixed_metadata_commitment(&self) -> &DigestHex {
        &self.fixed_metadata_commitment
    }

    /// Pinned Stripe API version.
    #[must_use]
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }

    /// Required policy commitment.
    #[must_use]
    pub const fn required_policy_digest(&self) -> &DigestHex {
        &self.required_policy_digest
    }

    /// Required configuration commitment.
    #[must_use]
    pub const fn required_configuration_digest(&self) -> &DigestHex {
        &self.required_configuration_digest
    }

    /// Executor audience.
    #[must_use]
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }

    /// Expiry.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Exact replay nonce.
    #[must_use]
    pub const fn nonce(&self) -> &DigestHex {
        &self.nonce
    }
}
