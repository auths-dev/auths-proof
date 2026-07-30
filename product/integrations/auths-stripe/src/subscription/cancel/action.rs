//! Exact Subscription cancellation action.

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    subscription::{
        SUBSCRIPTION_EVALUATOR_ID, SubscriptionCancelMode, SubscriptionConnectAccount,
        SubscriptionValidationError, valid_api_version,
    },
    types::{Currency, CustomerId, DigestHex, StripeAccountId, SubscriptionId, TestClockId},
};

pub const SUBSCRIPTION_CANCEL_PROFILE: &str = "auths.stripe.exact-subscription-cancel/1";
pub const SUBSCRIPTION_CANCEL_RECEIPT_SCHEMA: &str = "auths.stripe.subscription-cancel-receipt/1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeExactSubscriptionCancelV1 {
    profile: String,
    stripe_account_id: StripeAccountId,
    connect_account: SubscriptionConnectAccount,
    subscription_id: SubscriptionId,
    customer_id: CustomerId,
    subscription_digest: DigestHex,
    item_set_digest: DigestHex,
    currency: Currency,
    current_period_end: u64,
    cancel_at: u64,
    mode: SubscriptionCancelMode,
    invoice_now: bool,
    prorate: bool,
    pending_update_digest: Option<DigestHex>,
    pending_invoice_items_digest: DigestHex,
    latest_invoice_digest: DigestHex,
    remaining_term_liability_minor: u64,
    current_period_liability_minor: u64,
    cancellation_reason_commitment: DigestHex,
    test_clock_id: TestClockId,
    stripe_api_version: String,
    required_policy_digest: DigestHex,
    required_evaluator: String,
    required_configuration_digest: DigestHex,
    executor_audience: String,
    expires_at: u64,
    nonce: DigestHex,
}

pub struct StripeExactSubscriptionCancelInput {
    pub stripe_account_id: StripeAccountId,
    pub connect_account: SubscriptionConnectAccount,
    pub subscription_id: SubscriptionId,
    pub customer_id: CustomerId,
    pub subscription_digest: DigestHex,
    pub item_set_digest: DigestHex,
    pub currency: Currency,
    pub current_period_end: u64,
    pub cancel_at: u64,
    pub mode: SubscriptionCancelMode,
    pub pending_invoice_items_digest: DigestHex,
    pub latest_invoice_digest: DigestHex,
    pub remaining_term_liability_minor: u64,
    pub current_period_liability_minor: u64,
    pub cancellation_reason_commitment: DigestHex,
    pub test_clock_id: TestClockId,
    pub stripe_api_version: String,
    pub required_policy_digest: DigestHex,
    pub required_configuration_digest: DigestHex,
    pub executor_audience: String,
    pub expires_at: u64,
    pub nonce: DigestHex,
}

impl StripeExactSubscriptionCancelV1 {
    pub fn new(
        input: StripeExactSubscriptionCancelInput,
    ) -> Result<Self, SubscriptionValidationError> {
        let value = Self {
            profile: SUBSCRIPTION_CANCEL_PROFILE.into(),
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            subscription_id: input.subscription_id,
            customer_id: input.customer_id,
            subscription_digest: input.subscription_digest,
            item_set_digest: input.item_set_digest,
            currency: input.currency,
            current_period_end: input.current_period_end,
            cancel_at: input.cancel_at,
            mode: input.mode,
            invoice_now: false,
            prorate: false,
            pending_update_digest: None,
            pending_invoice_items_digest: input.pending_invoice_items_digest,
            latest_invoice_digest: input.latest_invoice_digest,
            remaining_term_liability_minor: input.remaining_term_liability_minor,
            current_period_liability_minor: input.current_period_liability_minor,
            cancellation_reason_commitment: input.cancellation_reason_commitment,
            test_clock_id: input.test_clock_id,
            stripe_api_version: input.stripe_api_version,
            required_policy_digest: input.required_policy_digest,
            required_evaluator: SUBSCRIPTION_EVALUATOR_ID.into(),
            required_configuration_digest: input.required_configuration_digest,
            executor_audience: input.executor_audience,
            expires_at: input.expires_at,
            nonce: input.nonce,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SubscriptionValidationError> {
        let branch_valid = match self.mode {
            SubscriptionCancelMode::AtPeriodEnd => {
                self.cancel_at == self.current_period_end && self.current_period_end > 0
            }
            SubscriptionCancelMode::Immediate => {
                self.cancel_at > 0 && self.cancel_at <= self.current_period_end
            }
        };
        if self.profile == SUBSCRIPTION_CANCEL_PROFILE
            && self.required_evaluator == SUBSCRIPTION_EVALUATOR_ID
            && branch_valid
            && !self.invoice_now
            && !self.prorate
            && self.pending_update_digest.is_none()
            && self.remaining_term_liability_minor >= self.current_period_liability_minor
            && self.current_period_liability_minor > 0
            && valid_api_version(&self.stripe_api_version)
            && Audience::parse(&self.executor_audience).is_ok()
            && self.expires_at > 0
        {
            Ok(())
        } else {
            Err(SubscriptionValidationError::Action)
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }
    pub const fn connect_account(&self) -> &SubscriptionConnectAccount {
        &self.connect_account
    }
    pub const fn subscription_id(&self) -> &SubscriptionId {
        &self.subscription_id
    }
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }
    pub const fn subscription_digest(&self) -> &DigestHex {
        &self.subscription_digest
    }
    pub const fn item_set_digest(&self) -> &DigestHex {
        &self.item_set_digest
    }
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }
    pub const fn current_period_end(&self) -> u64 {
        self.current_period_end
    }
    pub const fn cancel_at(&self) -> u64 {
        self.cancel_at
    }
    pub const fn mode(&self) -> SubscriptionCancelMode {
        self.mode
    }
    pub const fn invoice_now(&self) -> bool {
        self.invoice_now
    }
    pub const fn prorate(&self) -> bool {
        self.prorate
    }
    pub const fn pending_update_digest(&self) -> Option<&DigestHex> {
        self.pending_update_digest.as_ref()
    }
    pub const fn pending_invoice_items_digest(&self) -> &DigestHex {
        &self.pending_invoice_items_digest
    }
    pub const fn latest_invoice_digest(&self) -> &DigestHex {
        &self.latest_invoice_digest
    }
    pub const fn remaining_term_liability_minor(&self) -> u64 {
        self.remaining_term_liability_minor
    }
    pub const fn current_period_liability_minor(&self) -> u64 {
        self.current_period_liability_minor
    }
    pub const fn test_clock_id(&self) -> &TestClockId {
        &self.test_clock_id
    }
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }
    pub const fn required_policy_digest(&self) -> &DigestHex {
        &self.required_policy_digest
    }
    pub const fn required_configuration_digest(&self) -> &DigestHex {
        &self.required_configuration_digest
    }
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}
