//! Protected evidence and configuration for Subscription cancellation.

use serde::{Deserialize, Serialize};

use super::{SUBSCRIPTION_CANCEL_PROFILE, SUBSCRIPTION_CANCEL_RECEIPT_SCHEMA};
use crate::{
    canonical::{CanonicalError, canonical_digest},
    subscription::{
        StripeBoundedSubscriptionPolicyV1, StripeSubscriptionConfigurationV1,
        SubscriptionCancelMode, SubscriptionConnectAccount, SubscriptionLiabilityState,
        SubscriptionValidationError, valid_api_version, valid_local,
    },
    types::{
        Currency, CustomerId, DigestHex, InvoiceId, PaymentIntentId, StripeAccountId,
        SubscriptionId, TestClockId,
    },
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeSubscriptionCancelConfigurationV1 {
    base: StripeSubscriptionConfigurationV1,
    supported_modes: Vec<SubscriptionCancelMode>,
    liability_release_schema: String,
    maximum_pending_invoice_items: u32,
}

impl StripeSubscriptionCancelConfigurationV1 {
    pub fn new(
        policy: &StripeBoundedSubscriptionPolicyV1,
        stripe_account_id: StripeAccountId,
        connect_account: SubscriptionConnectAccount,
        test_clock_id: TestClockId,
        stripe_api_version: String,
        executor_audience: String,
    ) -> Result<Self, SubscriptionValidationError> {
        let value = Self {
            base: StripeSubscriptionConfigurationV1::new(
                SUBSCRIPTION_CANCEL_PROFILE,
                SUBSCRIPTION_CANCEL_RECEIPT_SCHEMA,
                policy,
                stripe_account_id,
                connect_account,
                test_clock_id,
                stripe_api_version,
                executor_audience,
            )?,
            supported_modes: vec![
                SubscriptionCancelMode::AtPeriodEnd,
                SubscriptionCancelMode::Immediate,
            ],
            liability_release_schema: "auths.stripe.subscription-liability-release/1".into(),
            maximum_pending_invoice_items: 64,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), SubscriptionValidationError> {
        if self.base.validate().is_ok()
            && self.supported_modes
                == [
                    SubscriptionCancelMode::AtPeriodEnd,
                    SubscriptionCancelMode::Immediate,
                ]
            && self.liability_release_schema == "auths.stripe.subscription-liability-release/1"
            && self.maximum_pending_invoice_items == 64
        {
            Ok(())
        } else {
            Err(SubscriptionValidationError::Configuration)
        }
    }
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    pub const fn base(&self) -> &StripeSubscriptionConfigurationV1 {
        &self.base
    }
    pub fn supported_modes(&self) -> &[SubscriptionCancelMode] {
        &self.supported_modes
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCancelEvidenceV1 {
    pub schema: String,
    pub stripe_account_id: StripeAccountId,
    pub connect_account: SubscriptionConnectAccount,
    pub subscription_id: SubscriptionId,
    pub customer_id: CustomerId,
    pub subscription_digest: DigestHex,
    pub item_set_digest: DigestHex,
    pub status: String,
    pub currency: Currency,
    pub current_period_end: u64,
    pub cancel_at: Option<u64>,
    pub cancel_at_period_end: bool,
    pub canceled_at: Option<u64>,
    pub ended_at: Option<u64>,
    pub pending_update_digest: Option<DigestHex>,
    pub pending_invoice_items_digest: DigestHex,
    pub pending_invoice_item_count: u32,
    pub unhandled_pending_invoice_item_count: u32,
    pub latest_invoice_id: Option<InvoiceId>,
    pub latest_invoice_digest: DigestHex,
    pub latest_invoice_status: Option<String>,
    pub latest_payment_intent_id: Option<PaymentIntentId>,
    pub liability_id: DigestHex,
    pub liability_state: SubscriptionLiabilityState,
    pub remaining_term_liability_minor: u64,
    pub current_period_liability_minor: u64,
    pub renewal_or_modification_pending: bool,
    pub test_clock_id: TestClockId,
    pub livemode: bool,
    pub stripe_api_version: String,
    pub observed_at: u64,
    pub response_digest: DigestHex,
    pub source: String,
}

impl SubscriptionCancelEvidenceV1 {
    pub fn validate(&self) -> Result<(), SubscriptionValidationError> {
        let valid = self.schema == "auths.stripe.subscription-cancel-evidence/1"
            && valid_local(&self.status)
            && self.current_period_end > 0
            && self.pending_invoice_item_count <= 64
            && self.unhandled_pending_invoice_item_count <= self.pending_invoice_item_count
            && self.remaining_term_liability_minor >= self.current_period_liability_minor
            && self.current_period_liability_minor > 0
            && self
                .latest_invoice_status
                .as_ref()
                .is_none_or(|value| valid_local(value))
            && !self.livemode
            && valid_api_version(&self.stripe_api_version)
            && valid_local(&self.source);
        if valid {
            Ok(())
        } else {
            Err(SubscriptionValidationError::Evidence)
        }
    }
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCancelProviderProjection {
    pub subscription_id: SubscriptionId,
    pub customer_id: CustomerId,
    pub status: String,
    pub current_period_end: u64,
    pub cancel_at: Option<u64>,
    pub cancel_at_period_end: bool,
    pub canceled_at: Option<u64>,
    pub ended_at: Option<u64>,
    pub latest_invoice_id: Option<InvoiceId>,
    pub latest_invoice_status: Option<String>,
    pub invoice_now: bool,
    pub prorate: bool,
    pub stripe_request_id: Option<String>,
    pub observed_at: u64,
    pub response_digest: DigestHex,
}

impl SubscriptionCancelProviderProjection {
    pub fn terminal(&self) -> bool {
        self.status == "canceled" && self.ended_at.is_some()
    }
}
