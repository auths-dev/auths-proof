//! Exact automatic-capture Stripe collection action.

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::{Currency, CustomerId, DigestHex, PaymentMethodId, StripeAccountId},
};

use super::super::{
    MerchantConnectAccount, MerchantEvaluatorCommitment, MerchantValidationError,
    PAYMENT_COLLECT_PROFILE, valid_api_version, valid_local_id, valid_payment_method_type,
};

const MAX_MONEY_MINOR: u64 = 99_999_999;

/// Exact automatic-capture collection action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeExactPaymentCollectV1 {
    profile: String,
    stripe_account_id: StripeAccountId,
    connect_account: MerchantConnectAccount,
    customer_id: CustomerId,
    payment_method_id: PaymentMethodId,
    payment_method_type: String,
    order_scope: String,
    amount_minor: u64,
    currency: Currency,
    confirmation_method: String,
    capture_method: String,
    off_session: bool,
    error_on_requires_action: bool,
    setup_future_usage: Option<String>,
    application_fee: Option<u64>,
    transfer_data: Option<String>,
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

/// Inputs for the exact automatic-capture collection action.
pub struct StripeExactPaymentCollectInput {
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
    /// Positive integer minor units.
    pub amount_minor: u64,
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

impl StripeExactPaymentCollectV1 {
    /// Builds V1 automatic capture with no unsafe optional modes.
    ///
    /// # Errors
    ///
    /// Rejects any malformed or unsafe exact-action input.
    pub fn new(input: StripeExactPaymentCollectInput) -> Result<Self, MerchantValidationError> {
        let value = Self {
            profile: PAYMENT_COLLECT_PROFILE.into(),
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            customer_id: input.customer_id,
            payment_method_id: input.payment_method_id,
            payment_method_type: input.payment_method_type,
            order_scope: input.order_scope,
            amount_minor: input.amount_minor,
            currency: input.currency,
            confirmation_method: "manual".into(),
            capture_method: "automatic".into(),
            off_session: false,
            error_on_requires_action: true,
            setup_future_usage: None,
            application_fee: None,
            transfer_data: None,
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

    /// Validates decoded exact collection semantics.
    ///
    /// # Errors
    ///
    /// Rejects values outside the exact V1 collection profile.
    pub fn validate(&self) -> Result<(), MerchantValidationError> {
        if self.profile != PAYMENT_COLLECT_PROFILE
            || !valid_payment_method_type(&self.payment_method_type)
            || !valid_local_id(&self.order_scope)
            || self.amount_minor == 0
            || self.amount_minor > MAX_MONEY_MINOR
            || self.confirmation_method != "manual"
            || self.capture_method != "automatic"
            || self.off_session
            || !self.error_on_requires_action
            || self.setup_future_usage.is_some()
            || self.application_fee.is_some()
            || self.transfer_data.is_some()
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

    /// Integer minor units.
    #[must_use]
    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }

    /// Currency.
    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    /// Exact confirmation method fixed by the profile.
    #[must_use]
    pub fn confirmation_method(&self) -> &str {
        &self.confirmation_method
    }

    /// Exact automatic capture method.
    #[must_use]
    pub fn capture_method(&self) -> &str {
        &self.capture_method
    }

    /// V1 rejects customer-action continuations.
    #[must_use]
    pub const fn error_on_requires_action(&self) -> bool {
        self.error_on_requires_action
    }

    /// Protected statement descriptor commitment.
    #[must_use]
    pub const fn statement_descriptor_commitment(&self) -> &DigestHex {
        &self.statement_descriptor_commitment
    }

    /// Protected metadata commitment.
    #[must_use]
    pub const fn fixed_metadata_commitment(&self) -> &DigestHex {
        &self.fixed_metadata_commitment
    }

    /// Pinned API version.
    #[must_use]
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }

    /// Required policy.
    #[must_use]
    pub const fn required_policy_digest(&self) -> &DigestHex {
        &self.required_policy_digest
    }

    /// Required configuration.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merchant::MerchantOperation,
        test_support::{merchant_collect_action, merchant_configuration, merchant_policy},
    };

    #[test]
    fn decoded_action_rejects_unknown_fields() {
        let policy = merchant_policy(MerchantOperation::Collect, 1_000, 2_000);
        let configuration = merchant_configuration(&policy);
        let action =
            merchant_collect_action("merchant-malformed-action-0001", &policy, &configuration, 1);
        let mut value = serde_json::to_value(action).unwrap();
        value.as_object_mut().unwrap().insert(
            "arbitrary_stripe_parameter".into(),
            serde_json::json!("unsafe"),
        );
        assert!(serde_json::from_value::<StripeExactPaymentCollectV1>(value).is_err());
    }

    #[test]
    fn exact_amount_hard_limit_and_boundary_plus_one_are_distinct() {
        let policy = merchant_policy(MerchantOperation::Collect, MAX_MONEY_MINOR, MAX_MONEY_MINOR);
        let configuration = merchant_configuration(&policy);
        assert!(
            merchant_collect_action(
                "merchant-amount-boundary-0001",
                &policy,
                &configuration,
                MAX_MONEY_MINOR,
            )
            .validate()
            .is_ok()
        );

        let input = StripeExactPaymentCollectInput {
            stripe_account_id: StripeAccountId::parse("acct_authsdemo01").unwrap(),
            connect_account: MerchantConnectAccount::Platform,
            customer_id: CustomerId::parse("cus_authsdemo00000001").unwrap(),
            payment_method_id: PaymentMethodId::parse("pm_authsdemo000000001").unwrap(),
            payment_method_type: "card".into(),
            order_scope: "order-demo-001".into(),
            amount_minor: MAX_MONEY_MINOR + 1,
            currency: Currency::parse("usd").unwrap(),
            statement_descriptor_commitment:
                crate::merchant::merchant_statement_descriptor_commitment(),
            fixed_metadata_commitment: crate::canonical::sha256(b"fixed"),
            stripe_api_version: "2025-04-30.basil".into(),
            required_policy_digest: policy.digest().unwrap(),
            required_configuration_digest: configuration.digest().unwrap(),
            executor_audience: configuration.executor_audience().into(),
            expires_at: crate::test_support::NOW + 120,
            nonce: crate::canonical::sha256(b"nonce"),
        };
        assert_eq!(
            StripeExactPaymentCollectV1::new(input),
            Err(MerchantValidationError::InvalidAction)
        );
    }
}
