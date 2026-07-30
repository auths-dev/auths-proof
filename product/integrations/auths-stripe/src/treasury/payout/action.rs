//! Exact manual Payout action.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    reason = "the exact action exposes immutable provider commitments"
)]

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use super::{PAYOUT_EVALUATOR_ID, PAYOUT_PROFILE, PayoutError};
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::{Currency, DigestHex, ExternalAccountId, StripeAccountId},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutMethod {
    Standard,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeExactPayoutV1 {
    profile: String,
    stripe_account_id: StripeAccountId,
    destination_external_account_id: ExternalAccountId,
    destination_type_commitment: DigestHex,
    business_scope: String,
    amount_minor: u64,
    currency: Currency,
    method: PayoutMethod,
    source_type: String,
    description_commitment: DigestHex,
    statement_descriptor_commitment: DigestHex,
    required_approval_commitments: Vec<DigestHex>,
    stripe_api_version: String,
    required_policy_digest: DigestHex,
    required_evaluator: String,
    required_configuration_digest: DigestHex,
    executor_audience: String,
    expires_at: u64,
    nonce: DigestHex,
}

pub struct StripeExactPayoutInput {
    pub stripe_account_id: StripeAccountId,
    pub destination_external_account_id: ExternalAccountId,
    pub destination_type_commitment: DigestHex,
    pub business_scope: String,
    pub amount_minor: u64,
    pub currency: Currency,
    pub source_type: String,
    pub description_commitment: DigestHex,
    pub statement_descriptor_commitment: DigestHex,
    pub required_approval_commitments: Vec<DigestHex>,
    pub stripe_api_version: String,
    pub required_policy_digest: DigestHex,
    pub required_configuration_digest: DigestHex,
    pub executor_audience: String,
    pub expires_at: u64,
    pub nonce: DigestHex,
}

impl StripeExactPayoutV1 {
    pub fn new(mut input: StripeExactPayoutInput) -> Result<Self, PayoutError> {
        input.required_approval_commitments.sort();
        let value = Self {
            profile: PAYOUT_PROFILE.into(),
            stripe_account_id: input.stripe_account_id,
            destination_external_account_id: input.destination_external_account_id,
            destination_type_commitment: input.destination_type_commitment,
            business_scope: input.business_scope,
            amount_minor: input.amount_minor,
            currency: input.currency,
            method: PayoutMethod::Standard,
            source_type: input.source_type,
            description_commitment: input.description_commitment,
            statement_descriptor_commitment: input.statement_descriptor_commitment,
            required_approval_commitments: input.required_approval_commitments,
            stripe_api_version: input.stripe_api_version,
            required_policy_digest: input.required_policy_digest,
            required_evaluator: PAYOUT_EVALUATOR_ID.into(),
            required_configuration_digest: input.required_configuration_digest,
            executor_audience: input.executor_audience,
            expires_at: input.expires_at,
            nonce: input.nonce,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PayoutError> {
        let approvals_valid = self.required_approval_commitments.len() <= 16
            && self
                .required_approval_commitments
                .windows(2)
                .all(|pair| pair[0] < pair[1]);
        if self.profile == PAYOUT_PROFILE
            && super::domain::payout_label_valid(&self.business_scope)
            && (1..=99_999_999).contains(&self.amount_minor)
            && self.method == PayoutMethod::Standard
            && super::domain::payout_label_valid(&self.source_type)
            && approvals_valid
            && super::domain::payout_label_valid(&self.stripe_api_version)
            && self.required_evaluator == PAYOUT_EVALUATOR_ID
            && Audience::parse(&self.executor_audience).is_ok()
            && self.expires_at > 0
        {
            Ok(())
        } else {
            Err(PayoutError::InvalidAction)
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
    pub const fn destination_external_account_id(&self) -> &ExternalAccountId {
        &self.destination_external_account_id
    }
    pub const fn destination_type_commitment(&self) -> &DigestHex {
        &self.destination_type_commitment
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
    pub const fn method(&self) -> PayoutMethod {
        self.method
    }
    pub fn source_type(&self) -> &str {
        &self.source_type
    }
    pub const fn description_commitment(&self) -> &DigestHex {
        &self.description_commitment
    }
    pub const fn statement_descriptor_commitment(&self) -> &DigestHex {
        &self.statement_descriptor_commitment
    }
    pub fn required_approval_commitments(&self) -> &[DigestHex] {
        &self.required_approval_commitments
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
