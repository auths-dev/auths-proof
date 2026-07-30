//! Immutable mandate policy and independently trusted consent/provider evidence.

use std::collections::BTreeMap;

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use super::{
    MandateAmountType, MandateInterval, MandateUsage, PAYMENT_MANDATE_CANONICALIZATION,
    PAYMENT_MANDATE_CAPABILITY_SCHEMA, PAYMENT_MANDATE_EVALUATOR_ID, PAYMENT_MANDATE_POLICY_TYPE,
    PAYMENT_MANDATE_PROFILE, PAYMENT_MANDATE_RECEIPT_SCHEMA, PaymentMandateValidationError,
    sorted_unique_nonempty, valid_api_version, valid_local,
};
use crate::{
    canonical::{CanonicalError, canonical_digest},
    types::{Currency, CustomerId, DigestHex, PaymentMethodId, SetupIntentId, StripeAccountId},
};

/// Platform versus one exact connected-account context.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "account")]
pub enum MandateConnectAccount {
    /// Platform account.
    Platform,
    /// One exact connected account.
    Connected(StripeAccountId),
}

/// Immutable configured policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeBoundedPaymentMandatePolicyV1 {
    policy_type: String,
    evaluator_id: String,
    valid_from: u64,
    expires_at: u64,
    allowed_test_account_ids: Vec<StripeAccountId>,
    allowed_customer_ids: Vec<CustomerId>,
    allowed_payment_method_ids: Vec<PaymentMethodId>,
    allowed_payment_method_types: Vec<String>,
    allowed_usage_modes: Vec<MandateUsage>,
    allowed_currencies: Vec<Currency>,
    allowed_intervals: Vec<MandateInterval>,
    per_future_charge_minor_by_currency: BTreeMap<Currency, u64>,
    maximum_active_mandates_per_customer: u32,
    maximum_consent_age_seconds: u64,
    maximum_evidence_age_seconds: u64,
    maximum_action_lifetime_seconds: u64,
    required_consent_assurance: u8,
    allowed_api_versions: Vec<String>,
    require_livemode: bool,
}

/// Constructor inputs for immutable policy.
pub struct StripeBoundedPaymentMandatePolicyInput {
    pub valid_from: u64,
    pub expires_at: u64,
    pub allowed_test_account_ids: Vec<StripeAccountId>,
    pub allowed_customer_ids: Vec<CustomerId>,
    pub allowed_payment_method_ids: Vec<PaymentMethodId>,
    pub allowed_payment_method_types: Vec<String>,
    pub allowed_usage_modes: Vec<MandateUsage>,
    pub allowed_currencies: Vec<Currency>,
    pub allowed_intervals: Vec<MandateInterval>,
    pub per_future_charge_minor_by_currency: BTreeMap<Currency, u64>,
    pub maximum_active_mandates_per_customer: u32,
    pub maximum_consent_age_seconds: u64,
    pub maximum_evidence_age_seconds: u64,
    pub maximum_action_lifetime_seconds: u64,
    pub required_consent_assurance: u8,
    pub allowed_api_versions: Vec<String>,
}

impl StripeBoundedPaymentMandatePolicyV1 {
    /// Builds a sorted, closed V1 policy.
    pub fn new(
        mut input: StripeBoundedPaymentMandatePolicyInput,
    ) -> Result<Self, PaymentMandateValidationError> {
        input.allowed_test_account_ids.sort();
        input.allowed_customer_ids.sort();
        input.allowed_payment_method_ids.sort();
        input.allowed_payment_method_types.sort();
        input.allowed_usage_modes.sort();
        input.allowed_currencies.sort();
        input.allowed_intervals.sort();
        input.allowed_api_versions.sort();
        let policy = Self {
            policy_type: PAYMENT_MANDATE_POLICY_TYPE.into(),
            evaluator_id: PAYMENT_MANDATE_EVALUATOR_ID.into(),
            valid_from: input.valid_from,
            expires_at: input.expires_at,
            allowed_test_account_ids: input.allowed_test_account_ids,
            allowed_customer_ids: input.allowed_customer_ids,
            allowed_payment_method_ids: input.allowed_payment_method_ids,
            allowed_payment_method_types: input.allowed_payment_method_types,
            allowed_usage_modes: input.allowed_usage_modes,
            allowed_currencies: input.allowed_currencies,
            allowed_intervals: input.allowed_intervals,
            per_future_charge_minor_by_currency: input.per_future_charge_minor_by_currency,
            maximum_active_mandates_per_customer: input.maximum_active_mandates_per_customer,
            maximum_consent_age_seconds: input.maximum_consent_age_seconds,
            maximum_evidence_age_seconds: input.maximum_evidence_age_seconds,
            maximum_action_lifetime_seconds: input.maximum_action_lifetime_seconds,
            required_consent_assurance: input.required_consent_assurance,
            allowed_api_versions: input.allowed_api_versions,
            require_livemode: false,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), PaymentMandateValidationError> {
        let valid = self.policy_type == PAYMENT_MANDATE_POLICY_TYPE
            && self.evaluator_id == PAYMENT_MANDATE_EVALUATOR_ID
            && self.valid_from < self.expires_at
            && sorted_unique_nonempty(&self.allowed_test_account_ids)
            && sorted_unique_nonempty(&self.allowed_customer_ids)
            && sorted_unique_nonempty(&self.allowed_payment_method_ids)
            && self.allowed_payment_method_types == ["card"]
            && sorted_unique_nonempty(&self.allowed_usage_modes)
            && sorted_unique_nonempty(&self.allowed_currencies)
            && sorted_unique_nonempty(&self.allowed_intervals)
            && !self.per_future_charge_minor_by_currency.is_empty()
            && self.maximum_active_mandates_per_customer > 0
            && self.maximum_active_mandates_per_customer <= 32
            && (1..=86_400).contains(&self.maximum_consent_age_seconds)
            && (1..=900).contains(&self.maximum_evidence_age_seconds)
            && (1..=3_600).contains(&self.maximum_action_lifetime_seconds)
            && self.required_consent_assurance > 0
            && sorted_unique_nonempty(&self.allowed_api_versions)
            && self
                .allowed_api_versions
                .iter()
                .all(|v| valid_api_version(v))
            && !self.require_livemode
            && self
                .per_future_charge_minor_by_currency
                .iter()
                .all(|(currency, amount)| {
                    self.allowed_currencies.binary_search(currency).is_ok()
                        && (1..=99_999_999).contains(amount)
                });
        if valid {
            Ok(())
        } else {
            Err(PaymentMandateValidationError::Policy)
        }
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    pub const fn valid_from(&self) -> u64 {
        self.valid_from
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn allowed_test_account_ids(&self) -> &[StripeAccountId] {
        &self.allowed_test_account_ids
    }
    pub fn allowed_customer_ids(&self) -> &[CustomerId] {
        &self.allowed_customer_ids
    }
    pub fn allowed_payment_method_ids(&self) -> &[PaymentMethodId] {
        &self.allowed_payment_method_ids
    }
    pub fn allowed_payment_method_types(&self) -> &[String] {
        &self.allowed_payment_method_types
    }
    pub fn allowed_usage_modes(&self) -> &[MandateUsage] {
        &self.allowed_usage_modes
    }
    pub fn allowed_currencies(&self) -> &[Currency] {
        &self.allowed_currencies
    }
    pub fn allowed_intervals(&self) -> &[MandateInterval] {
        &self.allowed_intervals
    }
    pub fn per_future_charge_minor_by_currency(&self) -> &BTreeMap<Currency, u64> {
        &self.per_future_charge_minor_by_currency
    }
    pub const fn maximum_active_mandates_per_customer(&self) -> u32 {
        self.maximum_active_mandates_per_customer
    }
    pub const fn maximum_consent_age_seconds(&self) -> u64 {
        self.maximum_consent_age_seconds
    }
    pub const fn maximum_evidence_age_seconds(&self) -> u64 {
        self.maximum_evidence_age_seconds
    }
    pub const fn maximum_action_lifetime_seconds(&self) -> u64 {
        self.maximum_action_lifetime_seconds
    }
    pub const fn required_consent_assurance(&self) -> u8 {
        self.required_consent_assurance
    }
    pub fn allowed_api_versions(&self) -> &[String] {
        &self.allowed_api_versions
    }
}

/// Evaluator/runtime identity that must match literally before state or I/O.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripePaymentMandateConfigurationV1 {
    profile: String,
    evaluator_id: String,
    implementation_id: String,
    canonicalization: String,
    policy_digest: DigestHex,
    stripe_account_id: StripeAccountId,
    connect_account: MandateConnectAccount,
    trusted_consent_context: String,
    stripe_api_version: String,
    capability_store_schema: String,
    receipt_schema: String,
    executor_audience: String,
    maximum_action_bytes: u32,
    maximum_collection_entries: u32,
    maximum_consent_age_seconds: u64,
    maximum_evidence_age_seconds: u64,
    maximum_active_capabilities: u32,
    maximum_work_units: u32,
}

impl StripePaymentMandateConfigurationV1 {
    #[allow(clippy::too_many_arguments, reason = "all trust anchors are explicit")]
    pub fn new(
        policy: &StripeBoundedPaymentMandatePolicyV1,
        stripe_account_id: StripeAccountId,
        connect_account: MandateConnectAccount,
        trusted_consent_context: String,
        stripe_api_version: String,
        executor_audience: String,
    ) -> Result<Self, PaymentMandateValidationError> {
        let config = Self {
            profile: PAYMENT_MANDATE_PROFILE.into(),
            evaluator_id: PAYMENT_MANDATE_EVALUATOR_ID.into(),
            implementation_id: "auths-stripe-mandate-rust/1".into(),
            canonicalization: PAYMENT_MANDATE_CANONICALIZATION.into(),
            policy_digest: policy
                .digest()
                .map_err(|_| PaymentMandateValidationError::Configuration)?,
            stripe_account_id,
            connect_account,
            trusted_consent_context,
            stripe_api_version,
            capability_store_schema: PAYMENT_MANDATE_CAPABILITY_SCHEMA.into(),
            receipt_schema: PAYMENT_MANDATE_RECEIPT_SCHEMA.into(),
            executor_audience,
            maximum_action_bytes: 65_536,
            maximum_collection_entries: 64,
            maximum_consent_age_seconds: policy.maximum_consent_age_seconds(),
            maximum_evidence_age_seconds: policy.maximum_evidence_age_seconds(),
            maximum_active_capabilities: policy.maximum_active_mandates_per_customer(),
            maximum_work_units: 256,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), PaymentMandateValidationError> {
        if self.profile != PAYMENT_MANDATE_PROFILE
            || self.evaluator_id != PAYMENT_MANDATE_EVALUATOR_ID
            || self.implementation_id != "auths-stripe-mandate-rust/1"
            || self.canonicalization != PAYMENT_MANDATE_CANONICALIZATION
            || !valid_local(&self.trusted_consent_context)
            || !valid_api_version(&self.stripe_api_version)
            || Audience::parse(&self.executor_audience).is_err()
            || self.capability_store_schema != PAYMENT_MANDATE_CAPABILITY_SCHEMA
            || self.receipt_schema != PAYMENT_MANDATE_RECEIPT_SCHEMA
            || self.maximum_action_bytes != 65_536
            || self.maximum_collection_entries != 64
            || self.maximum_work_units != 256
        {
            return Err(PaymentMandateValidationError::Configuration);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }
    pub const fn connect_account(&self) -> &MandateConnectAccount {
        &self.connect_account
    }
    pub fn trusted_consent_context(&self) -> &str {
        &self.trusted_consent_context
    }
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
}

/// Independently authenticated customer acceptance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentConsentEvidenceV1 {
    customer_id: CustomerId,
    payment_method_commitment: DigestHex,
    stripe_account_id: StripeAccountId,
    connect_account: MandateConnectAccount,
    usage: MandateUsage,
    mandate_amount_type: MandateAmountType,
    mandate_amount_minor: u64,
    currency: Currency,
    interval: MandateInterval,
    reference: String,
    displayed_terms_digest: DigestHex,
    accepted_at: u64,
    expires_at: u64,
    consent_principal: String,
    consent_assurance: u8,
    synthetic_test_consent: bool,
}

/// Constructor inputs for trusted consent.
pub struct PaymentConsentEvidenceInput {
    pub customer_id: CustomerId,
    pub payment_method_commitment: DigestHex,
    pub stripe_account_id: StripeAccountId,
    pub connect_account: MandateConnectAccount,
    pub usage: MandateUsage,
    pub mandate_amount_type: MandateAmountType,
    pub mandate_amount_minor: u64,
    pub currency: Currency,
    pub interval: MandateInterval,
    pub reference: String,
    pub displayed_terms_digest: DigestHex,
    pub accepted_at: u64,
    pub expires_at: u64,
    pub consent_principal: String,
    pub consent_assurance: u8,
    pub synthetic_test_consent: bool,
}

impl PaymentConsentEvidenceV1 {
    pub fn new(input: PaymentConsentEvidenceInput) -> Result<Self, PaymentMandateValidationError> {
        let evidence = Self {
            customer_id: input.customer_id,
            payment_method_commitment: input.payment_method_commitment,
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            usage: input.usage,
            mandate_amount_type: input.mandate_amount_type,
            mandate_amount_minor: input.mandate_amount_minor,
            currency: input.currency,
            interval: input.interval,
            reference: input.reference,
            displayed_terms_digest: input.displayed_terms_digest,
            accepted_at: input.accepted_at,
            expires_at: input.expires_at,
            consent_principal: input.consent_principal,
            consent_assurance: input.consent_assurance,
            synthetic_test_consent: input.synthetic_test_consent,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), PaymentMandateValidationError> {
        if self.mandate_amount_minor == 0
            || self.accepted_at >= self.expires_at
            || !valid_local(&self.reference)
            || !valid_local(&self.consent_principal)
            || self.consent_assurance == 0
        {
            return Err(PaymentMandateValidationError::Consent);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }
    pub const fn payment_method_commitment(&self) -> &DigestHex {
        &self.payment_method_commitment
    }
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }
    pub const fn connect_account(&self) -> &MandateConnectAccount {
        &self.connect_account
    }
    pub const fn usage(&self) -> MandateUsage {
        self.usage
    }
    pub const fn mandate_amount_type(&self) -> MandateAmountType {
        self.mandate_amount_type
    }
    pub const fn mandate_amount_minor(&self) -> u64 {
        self.mandate_amount_minor
    }
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }
    pub const fn interval(&self) -> MandateInterval {
        self.interval
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub const fn displayed_terms_digest(&self) -> &DigestHex {
        &self.displayed_terms_digest
    }
    pub const fn accepted_at(&self) -> u64 {
        self.accepted_at
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn consent_principal(&self) -> &str {
        &self.consent_principal
    }
    pub const fn consent_assurance(&self) -> u8 {
        self.consent_assurance
    }
    pub const fn synthetic_test_consent(&self) -> bool {
        self.synthetic_test_consent
    }
}

/// Fresh protected Stripe evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentMandateEvidenceV1 {
    stripe_account_id: StripeAccountId,
    connect_account: MandateConnectAccount,
    customer_id: CustomerId,
    customer_exists: bool,
    payment_method_id: PaymentMethodId,
    payment_method_type: String,
    payment_method_customer_id: CustomerId,
    existing_setup_intent_ids: Vec<SetupIntentId>,
    active_mandate_count: u32,
    duplicate_scope_exists: bool,
    ambiguous_setup_exists: bool,
    stripe_api_version: String,
    livemode: bool,
    observed_at: u64,
    source: String,
    response_commitment: DigestHex,
}

/// Constructor inputs for protected Stripe evidence.
pub struct PaymentMandateEvidenceInput {
    pub stripe_account_id: StripeAccountId,
    pub connect_account: MandateConnectAccount,
    pub customer_id: CustomerId,
    pub customer_exists: bool,
    pub payment_method_id: PaymentMethodId,
    pub payment_method_type: String,
    pub payment_method_customer_id: CustomerId,
    pub existing_setup_intent_ids: Vec<SetupIntentId>,
    pub active_mandate_count: u32,
    pub duplicate_scope_exists: bool,
    pub ambiguous_setup_exists: bool,
    pub stripe_api_version: String,
    pub livemode: bool,
    pub observed_at: u64,
    pub source: String,
    pub response_commitment: DigestHex,
}

impl PaymentMandateEvidenceV1 {
    pub fn new(
        mut input: PaymentMandateEvidenceInput,
    ) -> Result<Self, PaymentMandateValidationError> {
        input.existing_setup_intent_ids.sort();
        input.existing_setup_intent_ids.dedup();
        let evidence = Self {
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            customer_id: input.customer_id,
            customer_exists: input.customer_exists,
            payment_method_id: input.payment_method_id,
            payment_method_type: input.payment_method_type,
            payment_method_customer_id: input.payment_method_customer_id,
            existing_setup_intent_ids: input.existing_setup_intent_ids,
            active_mandate_count: input.active_mandate_count,
            duplicate_scope_exists: input.duplicate_scope_exists,
            ambiguous_setup_exists: input.ambiguous_setup_exists,
            stripe_api_version: input.stripe_api_version,
            livemode: input.livemode,
            observed_at: input.observed_at,
            source: input.source,
            response_commitment: input.response_commitment,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), PaymentMandateValidationError> {
        if self.payment_method_type != "card"
            || !valid_api_version(&self.stripe_api_version)
            || !valid_local(&self.source)
            || self.existing_setup_intent_ids.len() > 64
        {
            return Err(PaymentMandateValidationError::Evidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }
    pub const fn connect_account(&self) -> &MandateConnectAccount {
        &self.connect_account
    }
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }
    pub const fn customer_exists(&self) -> bool {
        self.customer_exists
    }
    pub const fn payment_method_id(&self) -> &PaymentMethodId {
        &self.payment_method_id
    }
    pub fn payment_method_type(&self) -> &str {
        &self.payment_method_type
    }
    pub const fn payment_method_customer_id(&self) -> &CustomerId {
        &self.payment_method_customer_id
    }
    pub fn existing_setup_intent_ids(&self) -> &[SetupIntentId] {
        &self.existing_setup_intent_ids
    }
    pub const fn active_mandate_count(&self) -> u32 {
        self.active_mandate_count
    }
    pub const fn duplicate_scope_exists(&self) -> bool {
        self.duplicate_scope_exists
    }
    pub const fn ambiguous_setup_exists(&self) -> bool {
        self.ambiguous_setup_exists
    }
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }
    pub const fn livemode(&self) -> bool {
        self.livemode
    }
    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }
}
