//! Exact incoming Issuing authorization action.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    reason = "the exact action exposes auditable immutable commitments"
)]

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    issuing::{
        PURCHASE_AUTHORIZATION_PROFILE, PURCHASE_EVALUATOR_ID, PurchaseAuthorizationMethod,
        PurchaseError, valid_country, valid_local,
    },
    types::{
        Currency, DigestHex, EventId, IssuingAuthorizationId, IssuingCardId, IssuingCardholderId,
        StripeAccountId,
    },
};

const MAX_MONEY_MINOR: u64 = 99_999_999;

/// Exact protected network authorization.
#[allow(
    clippy::struct_excessive_bools,
    reason = "forbidden Issuing modes are committed independently"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeExactPurchaseAuthorizationV1 {
    profile: String,
    stripe_account_id: StripeAccountId,
    event_id: EventId,
    issuing_authorization_id: IssuingAuthorizationId,
    cardholder_id: IssuingCardholderId,
    card_id: IssuingCardId,
    amount_minor: u64,
    currency: Currency,
    merchant_amount_minor: u64,
    merchant_currency: Currency,
    merchant_id: String,
    merchant_name_commitment: DigestHex,
    merchant_category: String,
    merchant_country: String,
    authorization_method: PurchaseAuthorizationMethod,
    wallet: bool,
    recurring: bool,
    cashback_minor: u64,
    is_amount_controllable: bool,
    requested_approved_amount_minor: u64,
    procurement_scope: String,
    procurement_intent_digest: Option<DigestHex>,
    stripe_api_version: String,
    webhook_payload_digest: DigestHex,
    required_policy_digest: DigestHex,
    required_evaluator: String,
    required_configuration_digest: DigestHex,
    executor_audience: String,
    received_at: u64,
}

/// Constructor carrier for the exact action.
pub struct StripeExactPurchaseAuthorizationInput {
    pub stripe_account_id: StripeAccountId,
    pub event_id: EventId,
    pub issuing_authorization_id: IssuingAuthorizationId,
    pub cardholder_id: IssuingCardholderId,
    pub card_id: IssuingCardId,
    pub amount_minor: u64,
    pub currency: Currency,
    pub merchant_amount_minor: u64,
    pub merchant_currency: Currency,
    pub merchant_id: String,
    pub merchant_name_commitment: DigestHex,
    pub merchant_category: String,
    pub merchant_country: String,
    pub authorization_method: PurchaseAuthorizationMethod,
    pub procurement_scope: String,
    pub procurement_intent_digest: Option<DigestHex>,
    pub stripe_api_version: String,
    pub webhook_payload_digest: DigestHex,
    pub required_policy_digest: DigestHex,
    pub required_configuration_digest: DigestHex,
    pub executor_audience: String,
    pub received_at: u64,
}

impl StripeExactPurchaseAuthorizationV1 {
    /// Constructs a full-amount, one-time, non-wallet V1 authorization.
    ///
    /// # Errors
    ///
    /// Rejects malformed exact action data.
    pub fn new(input: StripeExactPurchaseAuthorizationInput) -> Result<Self, PurchaseError> {
        let value = Self {
            profile: PURCHASE_AUTHORIZATION_PROFILE.into(),
            stripe_account_id: input.stripe_account_id,
            event_id: input.event_id,
            issuing_authorization_id: input.issuing_authorization_id,
            cardholder_id: input.cardholder_id,
            card_id: input.card_id,
            amount_minor: input.amount_minor,
            currency: input.currency,
            merchant_amount_minor: input.merchant_amount_minor,
            merchant_currency: input.merchant_currency,
            merchant_id: input.merchant_id,
            merchant_name_commitment: input.merchant_name_commitment,
            merchant_category: input.merchant_category,
            merchant_country: input.merchant_country,
            authorization_method: input.authorization_method,
            wallet: false,
            recurring: false,
            cashback_minor: 0,
            is_amount_controllable: false,
            requested_approved_amount_minor: input.amount_minor,
            procurement_scope: input.procurement_scope,
            procurement_intent_digest: input.procurement_intent_digest,
            stripe_api_version: input.stripe_api_version,
            webhook_payload_digest: input.webhook_payload_digest,
            required_policy_digest: input.required_policy_digest,
            required_evaluator: PURCHASE_EVALUATOR_ID.into(),
            required_configuration_digest: input.required_configuration_digest,
            executor_audience: input.executor_audience,
            received_at: input.received_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PurchaseError> {
        if self.profile == PURCHASE_AUTHORIZATION_PROFILE
            && (1..=MAX_MONEY_MINOR).contains(&self.amount_minor)
            && (1..=MAX_MONEY_MINOR).contains(&self.merchant_amount_minor)
            && valid_local(&self.merchant_id)
            && valid_local(&self.merchant_category)
            && valid_country(&self.merchant_country)
            && !self.wallet
            && !self.recurring
            && self.cashback_minor == 0
            && !self.is_amount_controllable
            && self.requested_approved_amount_minor == self.amount_minor
            && valid_local(&self.procurement_scope)
            && valid_local(&self.stripe_api_version)
            && self.required_evaluator == PURCHASE_EVALUATOR_ID
            && Audience::parse(&self.executor_audience).is_ok()
        {
            Ok(())
        } else {
            Err(PurchaseError::InvalidAction)
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    pub fn profile(&self) -> &str {
        &self.profile
    }
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }
    pub const fn event_id(&self) -> &EventId {
        &self.event_id
    }
    pub const fn authorization_id(&self) -> &IssuingAuthorizationId {
        &self.issuing_authorization_id
    }
    pub const fn cardholder_id(&self) -> &IssuingCardholderId {
        &self.cardholder_id
    }
    pub const fn card_id(&self) -> &IssuingCardId {
        &self.card_id
    }
    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }
    pub const fn merchant_amount_minor(&self) -> u64 {
        self.merchant_amount_minor
    }
    pub const fn merchant_currency(&self) -> &Currency {
        &self.merchant_currency
    }
    pub fn merchant_id(&self) -> &str {
        &self.merchant_id
    }
    pub const fn merchant_name_commitment(&self) -> &DigestHex {
        &self.merchant_name_commitment
    }
    pub fn merchant_category(&self) -> &str {
        &self.merchant_category
    }
    pub fn merchant_country(&self) -> &str {
        &self.merchant_country
    }
    pub const fn authorization_method(&self) -> PurchaseAuthorizationMethod {
        self.authorization_method
    }
    pub fn procurement_scope(&self) -> &str {
        &self.procurement_scope
    }
    pub const fn procurement_intent_digest(&self) -> Option<&DigestHex> {
        self.procurement_intent_digest.as_ref()
    }
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }
    pub const fn webhook_payload_digest(&self) -> &DigestHex {
        &self.webhook_payload_digest
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
    pub const fn received_at(&self) -> u64 {
        self.received_at
    }
}
