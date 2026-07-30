//! Exact Connect Transfer action.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    reason = "the exact action exposes immutable provider commitments"
)]

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use super::{CONNECT_TRANSFER_EVALUATOR_ID, CONNECT_TRANSFER_PROFILE, ConnectTransferError};
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::{ChargeId, Currency, DigestHex, PaymentIntentId, StripeAccountId},
};

/// One exact platform-to-connected-account Transfer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeExactConnectTransferV1 {
    profile: String,
    platform_account_id: StripeAccountId,
    destination_connected_account_id: StripeAccountId,
    source_charge_id: ChargeId,
    source_payment_intent_id: PaymentIntentId,
    transfer_group: String,
    business_scope: String,
    amount_minor: u64,
    currency: Currency,
    description_commitment: DigestHex,
    fixed_metadata_commitment: DigestHex,
    stripe_api_version: String,
    required_policy_digest: DigestHex,
    required_evaluator: String,
    required_configuration_digest: DigestHex,
    executor_audience: String,
    expires_at: u64,
    nonce: DigestHex,
}

/// Constructor carrier for the exact Transfer.
pub struct StripeExactConnectTransferInput {
    pub platform_account_id: StripeAccountId,
    pub destination_connected_account_id: StripeAccountId,
    pub source_charge_id: ChargeId,
    pub source_payment_intent_id: PaymentIntentId,
    pub transfer_group: String,
    pub business_scope: String,
    pub amount_minor: u64,
    pub currency: Currency,
    pub description_commitment: DigestHex,
    pub fixed_metadata_commitment: DigestHex,
    pub stripe_api_version: String,
    pub required_policy_digest: DigestHex,
    pub required_configuration_digest: DigestHex,
    pub executor_audience: String,
    pub expires_at: u64,
    pub nonce: DigestHex,
}

impl StripeExactConnectTransferV1 {
    pub fn new(input: StripeExactConnectTransferInput) -> Result<Self, ConnectTransferError> {
        let value = Self {
            profile: CONNECT_TRANSFER_PROFILE.into(),
            platform_account_id: input.platform_account_id,
            destination_connected_account_id: input.destination_connected_account_id,
            source_charge_id: input.source_charge_id,
            source_payment_intent_id: input.source_payment_intent_id,
            transfer_group: input.transfer_group,
            business_scope: input.business_scope,
            amount_minor: input.amount_minor,
            currency: input.currency,
            description_commitment: input.description_commitment,
            fixed_metadata_commitment: input.fixed_metadata_commitment,
            stripe_api_version: input.stripe_api_version,
            required_policy_digest: input.required_policy_digest,
            required_evaluator: CONNECT_TRANSFER_EVALUATOR_ID.into(),
            required_configuration_digest: input.required_configuration_digest,
            executor_audience: input.executor_audience,
            expires_at: input.expires_at,
            nonce: input.nonce,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ConnectTransferError> {
        if self.profile == CONNECT_TRANSFER_PROFILE
            && self.platform_account_id != self.destination_connected_account_id
            && super::domain::domain_valid_local(&self.transfer_group)
            && super::domain::domain_valid_local(&self.business_scope)
            && (1..=99_999_999).contains(&self.amount_minor)
            && super::domain::domain_valid_local(&self.stripe_api_version)
            && self.required_evaluator == CONNECT_TRANSFER_EVALUATOR_ID
            && Audience::parse(&self.executor_audience).is_ok()
            && self.expires_at > 0
        {
            Ok(())
        } else {
            Err(ConnectTransferError::InvalidAction)
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    pub const fn platform_account_id(&self) -> &StripeAccountId {
        &self.platform_account_id
    }
    pub const fn destination_account_id(&self) -> &StripeAccountId {
        &self.destination_connected_account_id
    }
    pub const fn source_charge_id(&self) -> &ChargeId {
        &self.source_charge_id
    }
    pub const fn source_payment_intent_id(&self) -> &PaymentIntentId {
        &self.source_payment_intent_id
    }
    pub fn transfer_group(&self) -> &str {
        &self.transfer_group
    }
    pub fn business_scope(&self) -> &str {
        &self.business_scope
    }
    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }
    pub const fn description_commitment(&self) -> &DigestHex {
        &self.description_commitment
    }
    pub const fn fixed_metadata_commitment(&self) -> &DigestHex {
        &self.fixed_metadata_commitment
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
    pub const fn nonce(&self) -> &DigestHex {
        &self.nonce
    }
}
