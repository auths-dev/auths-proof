//! Stripe Issuing purchase authorization domain.
//!
//! This family is intentionally separate from merchant payment collection:
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    reason = "the Issuing boundary keeps exhaustive field access and store commitments explicit"
)]

//! the provider initiates the authorization and the executor returns a bounded
//! direct webhook decision under a hard deadline.

pub mod purchase_authorization;

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::{
        Currency, DigestHex, EventId, IssuingAuthorizationId, IssuingCardId, IssuingCardholderId,
        StripeAccountId,
    },
};

pub use purchase_authorization::*;

/// Exact purchase-authorization action profile.
pub const PURCHASE_AUTHORIZATION_PROFILE: &str = "auths.stripe.exact-purchase-authorization/1";
/// Immutable purchase-policy identity.
pub const PURCHASE_POLICY_TYPE: &str = "auths.stripe.bounded-purchase-policy/1";
/// Shipping evaluator identity.
pub const PURCHASE_EVALUATOR_ID: &str = "auths.stripe.bounded-purchase-evaluator/1";
/// Purchase receipt family.
pub const PURCHASE_RECEIPT_SCHEMA: &str = "auths.stripe.purchase-authorization-receipt/1";
/// Trusted configuration provenance.
pub const PURCHASE_POLICY_PROVENANCE: &str = "executor-local-trusted-configuration";

const MAX_COLLECTION: usize = 64;
const MAX_MONEY_MINOR: u64 = 99_999_999;

fn valid_local(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_country(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn sorted_unique<T: Ord>(values: &[T]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_COLLECTION
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

/// Closed provider authorization method.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PurchaseAuthorizationMethod {
    Online,
    InStore,
}

/// Closed aggregate budget scope.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PurchaseBudgetScope {
    Global,
    Merchant(String),
    Category(String),
}

impl PurchaseBudgetScope {
    fn valid(&self) -> bool {
        match self {
            Self::Global => true,
            Self::Merchant(value) | Self::Category(value) => valid_local(value),
        }
    }
}

/// One fixed aggregate purchase budget.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregatePurchaseBudget {
    pub budget_id: String,
    pub scope: PurchaseBudgetScope,
    pub currency: Currency,
    pub limit_minor: u64,
    pub starts_at: u64,
    pub ends_at: u64,
}

impl AggregatePurchaseBudget {
    fn valid(&self) -> bool {
        valid_local(&self.budget_id)
            && self.scope.valid()
            && (1..=MAX_MONEY_MINOR).contains(&self.limit_minor)
            && self.starts_at < self.ends_at
    }
}

/// Closed capture tolerance for V1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PurchaseCaptureTolerancePolicy {
    ExactOrLower,
}

/// Immutable executor-configured procurement policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeBoundedPurchasePolicyV1 {
    policy_type: String,
    canonicalization: String,
    evaluator_semantic_id: String,
    evaluator_semantic_version: u16,
    policy_id: String,
    valid_from: u64,
    expires_at: u64,
    allowed_test_account_ids: Vec<StripeAccountId>,
    allowed_cardholder_ids: Vec<IssuingCardholderId>,
    allowed_card_ids: Vec<IssuingCardId>,
    allowed_currencies: Vec<Currency>,
    allowed_merchant_ids: Vec<String>,
    allowed_merchant_name_commitments: Vec<DigestHex>,
    allowed_merchant_categories: Vec<String>,
    blocked_merchant_categories: Vec<String>,
    allowed_merchant_countries: Vec<String>,
    blocked_merchant_countries: Vec<String>,
    allowed_procurement_scopes: Vec<String>,
    allowed_authorization_methods: Vec<PurchaseAuthorizationMethod>,
    allow_recurring: bool,
    allow_cash_withdrawal: bool,
    allow_wallet: bool,
    allow_partial_approval: bool,
    per_purchase_minor_by_currency: BTreeMap<Currency, u64>,
    per_merchant_minor_by_currency: BTreeMap<Currency, u64>,
    per_category_minor_by_currency: BTreeMap<Currency, u64>,
    aggregate_budgets: Vec<AggregatePurchaseBudget>,
    maximum_intent_age_seconds: u64,
    maximum_event_age_seconds: u64,
    decision_deadline_milliseconds: u64,
    capture_tolerance_policy: PurchaseCaptureTolerancePolicy,
    allowed_api_versions: Vec<String>,
    required_timeout_fallback: String,
}

/// Constructor carrier for the immutable policy.
pub struct StripeBoundedPurchasePolicyInput {
    pub policy_id: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub allowed_test_account_ids: Vec<StripeAccountId>,
    pub allowed_cardholder_ids: Vec<IssuingCardholderId>,
    pub allowed_card_ids: Vec<IssuingCardId>,
    pub allowed_currencies: Vec<Currency>,
    pub allowed_merchant_ids: Vec<String>,
    pub allowed_merchant_name_commitments: Vec<DigestHex>,
    pub allowed_merchant_categories: Vec<String>,
    pub blocked_merchant_categories: Vec<String>,
    pub allowed_merchant_countries: Vec<String>,
    pub blocked_merchant_countries: Vec<String>,
    pub allowed_procurement_scopes: Vec<String>,
    pub allowed_authorization_methods: Vec<PurchaseAuthorizationMethod>,
    pub per_purchase_minor_by_currency: BTreeMap<Currency, u64>,
    pub per_merchant_minor_by_currency: BTreeMap<Currency, u64>,
    pub per_category_minor_by_currency: BTreeMap<Currency, u64>,
    pub aggregate_budgets: Vec<AggregatePurchaseBudget>,
    pub maximum_intent_age_seconds: u64,
    pub maximum_event_age_seconds: u64,
    pub decision_deadline_milliseconds: u64,
    pub allowed_api_versions: Vec<String>,
}

impl StripeBoundedPurchasePolicyV1 {
    /// Constructs the exact deny-precedence V1 purchase policy.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unbounded, or unsafe policy input.
    pub fn new(mut input: StripeBoundedPurchasePolicyInput) -> Result<Self, PurchaseError> {
        input.allowed_test_account_ids.sort();
        input.allowed_cardholder_ids.sort();
        input.allowed_card_ids.sort();
        input.allowed_currencies.sort();
        input.allowed_merchant_ids.sort();
        input.allowed_merchant_name_commitments.sort();
        input.allowed_merchant_categories.sort();
        input.blocked_merchant_categories.sort();
        input.allowed_merchant_countries.sort();
        input.blocked_merchant_countries.sort();
        input.allowed_procurement_scopes.sort();
        input.allowed_authorization_methods.sort();
        input.allowed_api_versions.sort();
        input.aggregate_budgets.sort();
        let value = Self {
            policy_type: PURCHASE_POLICY_TYPE.into(),
            canonicalization: "rfc8785-sha256-v1".into(),
            evaluator_semantic_id: PURCHASE_EVALUATOR_ID.into(),
            evaluator_semantic_version: 1,
            policy_id: input.policy_id,
            valid_from: input.valid_from,
            expires_at: input.expires_at,
            allowed_test_account_ids: input.allowed_test_account_ids,
            allowed_cardholder_ids: input.allowed_cardholder_ids,
            allowed_card_ids: input.allowed_card_ids,
            allowed_currencies: input.allowed_currencies,
            allowed_merchant_ids: input.allowed_merchant_ids,
            allowed_merchant_name_commitments: input.allowed_merchant_name_commitments,
            allowed_merchant_categories: input.allowed_merchant_categories,
            blocked_merchant_categories: input.blocked_merchant_categories,
            allowed_merchant_countries: input.allowed_merchant_countries,
            blocked_merchant_countries: input.blocked_merchant_countries,
            allowed_procurement_scopes: input.allowed_procurement_scopes,
            allowed_authorization_methods: input.allowed_authorization_methods,
            allow_recurring: false,
            allow_cash_withdrawal: false,
            allow_wallet: false,
            allow_partial_approval: false,
            per_purchase_minor_by_currency: input.per_purchase_minor_by_currency,
            per_merchant_minor_by_currency: input.per_merchant_minor_by_currency,
            per_category_minor_by_currency: input.per_category_minor_by_currency,
            aggregate_budgets: input.aggregate_budgets,
            maximum_intent_age_seconds: input.maximum_intent_age_seconds,
            maximum_event_age_seconds: input.maximum_event_age_seconds,
            decision_deadline_milliseconds: input.decision_deadline_milliseconds,
            capture_tolerance_policy: PurchaseCaptureTolerancePolicy::ExactOrLower,
            allowed_api_versions: input.allowed_api_versions,
            required_timeout_fallback: "decline".into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates all closed policy bounds.
    ///
    /// # Errors
    ///
    /// Rejects malformed policy data.
    pub fn validate(&self) -> Result<(), PurchaseError> {
        let money_maps = [
            &self.per_purchase_minor_by_currency,
            &self.per_merchant_minor_by_currency,
            &self.per_category_minor_by_currency,
        ];
        let valid = self.policy_type == PURCHASE_POLICY_TYPE
            && self.canonicalization == "rfc8785-sha256-v1"
            && self.evaluator_semantic_id == PURCHASE_EVALUATOR_ID
            && self.evaluator_semantic_version == 1
            && valid_local(&self.policy_id)
            && self.valid_from < self.expires_at
            && sorted_unique(&self.allowed_test_account_ids)
            && sorted_unique(&self.allowed_cardholder_ids)
            && sorted_unique(&self.allowed_card_ids)
            && sorted_unique(&self.allowed_currencies)
            && sorted_unique(&self.allowed_merchant_ids)
            && sorted_unique(&self.allowed_merchant_name_commitments)
            && sorted_unique(&self.allowed_merchant_categories)
            && self.blocked_merchant_categories.len() <= MAX_COLLECTION
            && self
                .blocked_merchant_categories
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && sorted_unique(&self.allowed_merchant_countries)
            && self
                .allowed_merchant_countries
                .iter()
                .all(|value| valid_country(value))
            && self
                .blocked_merchant_countries
                .iter()
                .all(|value| valid_country(value))
            && self
                .blocked_merchant_countries
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && sorted_unique(&self.allowed_procurement_scopes)
            && sorted_unique(&self.allowed_authorization_methods)
            && !self.allow_recurring
            && !self.allow_cash_withdrawal
            && !self.allow_wallet
            && !self.allow_partial_approval
            && money_maps.iter().all(|map| {
                !map.is_empty()
                    && map.iter().all(|(currency, limit)| {
                        self.allowed_currencies.binary_search(currency).is_ok()
                            && (1..=MAX_MONEY_MINOR).contains(limit)
                    })
            })
            && !self.aggregate_budgets.is_empty()
            && self.aggregate_budgets.len() <= MAX_COLLECTION
            && self
                .aggregate_budgets
                .iter()
                .all(AggregatePurchaseBudget::valid)
            && self
                .aggregate_budgets
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && (1..=86_400).contains(&self.maximum_intent_age_seconds)
            && (1..=300).contains(&self.maximum_event_age_seconds)
            && (1..=1_500).contains(&self.decision_deadline_milliseconds)
            && self.capture_tolerance_policy == PurchaseCaptureTolerancePolicy::ExactOrLower
            && sorted_unique(&self.allowed_api_versions)
            && self
                .allowed_api_versions
                .iter()
                .all(|value| valid_local(value))
            && self.required_timeout_fallback == "decline";
        if valid {
            Ok(())
        } else {
            Err(PurchaseError::InvalidPolicy)
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
    pub const fn maximum_intent_age_seconds(&self) -> u64 {
        self.maximum_intent_age_seconds
    }
    pub const fn maximum_event_age_seconds(&self) -> u64 {
        self.maximum_event_age_seconds
    }
    pub const fn decision_deadline_milliseconds(&self) -> u64 {
        self.decision_deadline_milliseconds
    }
    pub fn allowed_accounts(&self) -> &[StripeAccountId] {
        &self.allowed_test_account_ids
    }
    pub fn allowed_cardholders(&self) -> &[IssuingCardholderId] {
        &self.allowed_cardholder_ids
    }
    pub fn allowed_cards(&self) -> &[IssuingCardId] {
        &self.allowed_card_ids
    }
    pub fn allowed_currencies(&self) -> &[Currency] {
        &self.allowed_currencies
    }
    pub fn allowed_merchants(&self) -> &[String] {
        &self.allowed_merchant_ids
    }
    pub fn allowed_merchant_names(&self) -> &[DigestHex] {
        &self.allowed_merchant_name_commitments
    }
    pub fn allowed_categories(&self) -> &[String] {
        &self.allowed_merchant_categories
    }
    pub fn blocked_categories(&self) -> &[String] {
        &self.blocked_merchant_categories
    }
    pub fn allowed_countries(&self) -> &[String] {
        &self.allowed_merchant_countries
    }
    pub fn blocked_countries(&self) -> &[String] {
        &self.blocked_merchant_countries
    }
    pub fn allowed_scopes(&self) -> &[String] {
        &self.allowed_procurement_scopes
    }
    pub fn allowed_methods(&self) -> &[PurchaseAuthorizationMethod] {
        &self.allowed_authorization_methods
    }
    pub fn purchase_limits(&self) -> &BTreeMap<Currency, u64> {
        &self.per_purchase_minor_by_currency
    }
    pub fn merchant_limits(&self) -> &BTreeMap<Currency, u64> {
        &self.per_merchant_minor_by_currency
    }
    pub fn category_limits(&self) -> &BTreeMap<Currency, u64> {
        &self.per_category_minor_by_currency
    }
    pub fn aggregate_budgets(&self) -> &[AggregatePurchaseBudget] {
        &self.aggregate_budgets
    }
    pub fn allowed_api_versions(&self) -> &[String] {
        &self.allowed_api_versions
    }
}

/// Immutable evaluator/executor configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripePurchaseConfigurationV1 {
    profile: String,
    evaluator_id: String,
    implementation_id: String,
    policy_digest: DigestHex,
    stripe_account_id: StripeAccountId,
    stripe_api_version: String,
    webhook_schema: String,
    timeout_fallback: String,
    decision_deadline_milliseconds: u64,
    store_schema: String,
    receipt_schema: String,
    executor_audience: String,
    maximum_action_bytes: u64,
    maximum_evidence_objects: u32,
    maximum_reservations: u32,
    maximum_work_units: u32,
}

impl StripePurchaseConfigurationV1 {
    pub fn new(
        policy: &StripeBoundedPurchasePolicyV1,
        stripe_account_id: StripeAccountId,
        stripe_api_version: String,
        executor_audience: String,
    ) -> Result<Self, PurchaseError> {
        let value = Self {
            profile: PURCHASE_AUTHORIZATION_PROFILE.into(),
            evaluator_id: PURCHASE_EVALUATOR_ID.into(),
            implementation_id: "auths-stripe-issuing-rust/1".into(),
            policy_digest: policy
                .digest()
                .map_err(|_| PurchaseError::Canonicalization)?,
            stripe_account_id,
            stripe_api_version,
            webhook_schema: "stripe.issuing_authorization.request".into(),
            timeout_fallback: "decline".into(),
            decision_deadline_milliseconds: policy.decision_deadline_milliseconds(),
            store_schema: "auths.stripe.issuing-authorization-reservations/1".into(),
            receipt_schema: PURCHASE_RECEIPT_SCHEMA.into(),
            executor_audience,
            maximum_action_bytes: 65_536,
            maximum_evidence_objects: 64,
            maximum_reservations: 64,
            maximum_work_units: 4_096,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PurchaseError> {
        if self.profile == PURCHASE_AUTHORIZATION_PROFILE
            && self.evaluator_id == PURCHASE_EVALUATOR_ID
            && self.implementation_id == "auths-stripe-issuing-rust/1"
            && valid_local(&self.stripe_api_version)
            && self.webhook_schema == "stripe.issuing_authorization.request"
            && self.timeout_fallback == "decline"
            && (1..=1_500).contains(&self.decision_deadline_milliseconds)
            && self.store_schema == "auths.stripe.issuing-authorization-reservations/1"
            && self.receipt_schema == PURCHASE_RECEIPT_SCHEMA
            && self.executor_audience.starts_with("https://")
            && self.maximum_action_bytes == 65_536
            && self.maximum_evidence_objects == 64
            && self.maximum_reservations == 64
            && self.maximum_work_units == 4_096
        {
            Ok(())
        } else {
            Err(PurchaseError::InvalidConfiguration)
        }
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
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
    pub const fn decision_deadline_milliseconds(&self) -> u64 {
        self.decision_deadline_milliseconds
    }
}

/// Durable agent procurement intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProcurementIntentV1 {
    pub schema: String,
    pub intent_id: String,
    pub agent_identity: String,
    pub procurement_scope: String,
    pub expected_merchant_id: String,
    pub maximum_amount_minor: u64,
    pub currency: Currency,
    pub recurring: bool,
    pub fulfillment_reference_commitment: DigestHex,
    pub valid_from: u64,
    pub expires_at: u64,
    pub nonce: DigestHex,
}

impl AgentProcurementIntentV1 {
    pub fn validate(&self) -> Result<(), PurchaseError> {
        if self.schema == "auths.stripe.agent-procurement-intent/1"
            && valid_local(&self.intent_id)
            && valid_local(&self.agent_identity)
            && valid_local(&self.procurement_scope)
            && valid_local(&self.expected_merchant_id)
            && (1..=MAX_MONEY_MINOR).contains(&self.maximum_amount_minor)
            && !self.recurring
            && self.valid_from < self.expires_at
        {
            Ok(())
        } else {
            Err(PurchaseError::InvalidIntent)
        }
    }
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Explicit verified webhook boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PurchaseWebhookEvidenceV1 {
    pub schema: String,
    pub event_id: EventId,
    pub event_type: String,
    pub payload_digest: DigestHex,
    pub signature_header_digest: DigestHex,
    pub signature_timestamp: u64,
    pub signature_verified: bool,
    pub account_id: StripeAccountId,
    pub api_version: String,
    pub livemode: bool,
    pub received_at: u64,
}

impl PurchaseWebhookEvidenceV1 {
    pub fn validate(&self) -> Result<(), PurchaseError> {
        if self.schema == "auths.stripe.issuing-webhook-evidence/1"
            && self.event_type == "issuing_authorization.request"
            && self.signature_verified
            && !self.livemode
            && valid_local(&self.api_version)
        {
            Ok(())
        } else {
            Err(PurchaseError::InvalidEvidence)
        }
    }
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Aggregate availability before a decision.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PurchaseAggregateSnapshot {
    pub held_minor_by_budget: BTreeMap<String, u64>,
}

/// Exact capacity intent produced by the pure evaluator.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PurchaseReservationIntent {
    pub budget_id: String,
    pub currency: Currency,
    pub amount_minor: u64,
    pub limit_minor: u64,
}

/// Sanitized later Issuing state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PurchaseAuthorizationProviderProjection {
    pub authorization_id: IssuingAuthorizationId,
    pub approved: bool,
    pub status: String,
    pub authorized_amount_minor: u64,
    pub captured_amount_minor: u64,
    pub currency: Currency,
    pub request_reason: String,
    pub observed_at: u64,
    pub response_digest: DigestHex,
}

/// Closed durable purchase lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PurchaseReservationState {
    Approved,
    Declined,
    OutcomeUnknown,
    Captured,
    Released,
    ObservationOutsidePolicy,
}

impl PurchaseReservationState {
    pub const fn holds_capacity(self) -> bool {
        matches!(self, Self::Approved | Self::OutcomeUnknown)
    }
}

/// Durable replay and capacity record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PurchaseReservationRecord {
    workflow_id: String,
    event_id: EventId,
    authorization_id: IssuingAuthorizationId,
    action_digest: DigestHex,
    policy_digest: DigestHex,
    decision_receipt_digest: DigestHex,
    amount_minor: u64,
    currency: Currency,
    reservations: Vec<PurchaseReservationIntent>,
    state: PurchaseReservationState,
    provider: Option<PurchaseAuthorizationProviderProjection>,
    updated_at: u64,
}

impl PurchaseReservationRecord {
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn authorization_id(&self) -> &IssuingAuthorizationId {
        &self.authorization_id
    }
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }
    pub const fn decision_receipt_digest(&self) -> &DigestHex {
        &self.decision_receipt_digest
    }
    pub const fn state(&self) -> PurchaseReservationState {
        self.state
    }
    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }
    pub fn provider(&self) -> Option<&PurchaseAuthorizationProviderProjection> {
        self.provider.as_ref()
    }
}

/// Atomic reservation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReservePurchaseResult {
    Reserved(PurchaseReservationRecord),
    Replay(PurchaseReservationRecord),
    Conflict(PurchaseReservationRecord),
    CapacityExceeded,
}

/// Atomic purchase reservation persistence.
pub trait PurchaseAuthorizationStore: Send + Sync {
    fn snapshot(
        &self,
        policy: &StripeBoundedPurchasePolicyV1,
        now: u64,
    ) -> Result<PurchaseAggregateSnapshot, PurchaseError>;
    #[allow(clippy::too_many_arguments)]
    fn reserve(
        &self,
        workflow_id: &str,
        event_id: &EventId,
        authorization_id: &IssuingAuthorizationId,
        action_digest: &DigestHex,
        policy_digest: &DigestHex,
        decision_receipt_digest: &DigestHex,
        amount_minor: u64,
        currency: &Currency,
        reservations: &[PurchaseReservationIntent],
        now: u64,
    ) -> Result<ReservePurchaseResult, PurchaseError>;
    fn get(&self, workflow_id: &str) -> Result<Option<PurchaseReservationRecord>, PurchaseError>;
    fn observe(
        &self,
        workflow_id: &str,
        provider: PurchaseAuthorizationProviderProjection,
        now: u64,
    ) -> Result<PurchaseReservationRecord, PurchaseError>;
    fn mark_unknown(
        &self,
        workflow_id: &str,
        now: u64,
    ) -> Result<PurchaseReservationRecord, PurchaseError>;
}

impl<T: PurchaseAuthorizationStore + ?Sized> PurchaseAuthorizationStore for std::sync::Arc<T> {
    fn snapshot(
        &self,
        policy: &StripeBoundedPurchasePolicyV1,
        now: u64,
    ) -> Result<PurchaseAggregateSnapshot, PurchaseError> {
        (**self).snapshot(policy, now)
    }

    fn reserve(
        &self,
        workflow_id: &str,
        event_id: &EventId,
        authorization_id: &IssuingAuthorizationId,
        action_digest: &DigestHex,
        policy_digest: &DigestHex,
        decision_receipt_digest: &DigestHex,
        amount_minor: u64,
        currency: &Currency,
        reservations: &[PurchaseReservationIntent],
        now: u64,
    ) -> Result<ReservePurchaseResult, PurchaseError> {
        (**self).reserve(
            workflow_id,
            event_id,
            authorization_id,
            action_digest,
            policy_digest,
            decision_receipt_digest,
            amount_minor,
            currency,
            reservations,
            now,
        )
    }

    fn get(&self, workflow_id: &str) -> Result<Option<PurchaseReservationRecord>, PurchaseError> {
        (**self).get(workflow_id)
    }

    fn observe(
        &self,
        workflow_id: &str,
        provider: PurchaseAuthorizationProviderProjection,
        now: u64,
    ) -> Result<PurchaseReservationRecord, PurchaseError> {
        (**self).observe(workflow_id, provider, now)
    }

    fn mark_unknown(
        &self,
        workflow_id: &str,
        now: u64,
    ) -> Result<PurchaseReservationRecord, PurchaseError> {
        (**self).mark_unknown(workflow_id, now)
    }
}

#[derive(Default, Serialize, Deserialize)]
struct PurchaseStoreData {
    records: HashMap<String, PurchaseReservationRecord>,
}

/// In-memory atomic purchase capacity.
#[derive(Default)]
pub struct InMemoryPurchaseAuthorizationStore {
    data: Mutex<PurchaseStoreData>,
}

impl InMemoryPurchaseAuthorizationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn snapshot_data(
    data: &PurchaseStoreData,
    policy: &StripeBoundedPurchasePolicyV1,
    now: u64,
) -> Result<PurchaseAggregateSnapshot, PurchaseError> {
    let mut result = PurchaseAggregateSnapshot::default();
    for budget in policy.aggregate_budgets() {
        if now >= budget.starts_at && now <= budget.ends_at {
            let held = data
                .records
                .values()
                .filter(|record| record.state.holds_capacity())
                .flat_map(|record| &record.reservations)
                .filter(|reservation| {
                    reservation.budget_id == budget.budget_id
                        && reservation.currency == budget.currency
                })
                .try_fold(0_u64, |sum, reservation| {
                    sum.checked_add(reservation.amount_minor)
                })
                .ok_or(PurchaseError::Arithmetic)?;
            result
                .held_minor_by_budget
                .insert(budget.budget_id.clone(), held);
        }
    }
    Ok(result)
}

fn reserve_data(
    data: &mut PurchaseStoreData,
    workflow_id: &str,
    event_id: &EventId,
    authorization_id: &IssuingAuthorizationId,
    action_digest: &DigestHex,
    policy_digest: &DigestHex,
    decision_receipt_digest: &DigestHex,
    amount_minor: u64,
    currency: &Currency,
    reservations: &[PurchaseReservationIntent],
    now: u64,
) -> Result<ReservePurchaseResult, PurchaseError> {
    if let Some(existing) = data.records.get(workflow_id) {
        if existing.event_id == *event_id
            && existing.action_digest == *action_digest
            && existing.policy_digest == *policy_digest
        {
            return Ok(ReservePurchaseResult::Replay(existing.clone()));
        }
        return Ok(ReservePurchaseResult::Conflict(existing.clone()));
    }
    if data
        .records
        .values()
        .any(|record| record.event_id == *event_id)
    {
        return Err(PurchaseError::EventReplay);
    }
    for reservation in reservations {
        let held = data
            .records
            .values()
            .filter(|record| record.state.holds_capacity())
            .flat_map(|record| &record.reservations)
            .filter(|existing| {
                existing.budget_id == reservation.budget_id
                    && existing.currency == reservation.currency
            })
            .try_fold(0_u64, |sum, existing| {
                sum.checked_add(existing.amount_minor)
            })
            .ok_or(PurchaseError::Arithmetic)?;
        if held
            .checked_add(reservation.amount_minor)
            .ok_or(PurchaseError::Arithmetic)?
            > reservation.limit_minor
        {
            return Ok(ReservePurchaseResult::CapacityExceeded);
        }
    }
    let record = PurchaseReservationRecord {
        workflow_id: workflow_id.into(),
        event_id: event_id.clone(),
        authorization_id: authorization_id.clone(),
        action_digest: action_digest.clone(),
        policy_digest: policy_digest.clone(),
        decision_receipt_digest: decision_receipt_digest.clone(),
        amount_minor,
        currency: currency.clone(),
        reservations: reservations.to_vec(),
        state: PurchaseReservationState::Approved,
        provider: None,
        updated_at: now,
    };
    data.records.insert(workflow_id.into(), record.clone());
    Ok(ReservePurchaseResult::Reserved(record))
}

fn observe_data(
    data: &mut PurchaseStoreData,
    workflow_id: &str,
    provider: PurchaseAuthorizationProviderProjection,
    now: u64,
) -> Result<PurchaseReservationRecord, PurchaseError> {
    let record = data
        .records
        .get_mut(workflow_id)
        .ok_or(PurchaseError::NotFound)?;
    if provider.authorization_id != record.authorization_id
        || provider.currency != record.currency
        || provider.authorized_amount_minor > record.amount_minor
    {
        record.state = PurchaseReservationState::ObservationOutsidePolicy;
    } else if provider.captured_amount_minor > 0 {
        record.state = if provider.captured_amount_minor <= record.amount_minor {
            PurchaseReservationState::Captured
        } else {
            PurchaseReservationState::ObservationOutsidePolicy
        };
    } else if matches!(provider.status.as_str(), "reversed" | "expired" | "closed")
        && !provider.approved
    {
        record.state = PurchaseReservationState::Released;
    } else if provider.approved {
        record.state = PurchaseReservationState::Approved;
    } else {
        record.state = PurchaseReservationState::Declined;
    }
    record.provider = Some(provider);
    record.updated_at = now;
    Ok(record.clone())
}

impl PurchaseAuthorizationStore for InMemoryPurchaseAuthorizationStore {
    fn snapshot(
        &self,
        policy: &StripeBoundedPurchasePolicyV1,
        now: u64,
    ) -> Result<PurchaseAggregateSnapshot, PurchaseError> {
        let data = self.data.lock().map_err(|_| PurchaseError::Persistence)?;
        snapshot_data(&data, policy, now)
    }

    fn reserve(
        &self,
        workflow_id: &str,
        event_id: &EventId,
        authorization_id: &IssuingAuthorizationId,
        action_digest: &DigestHex,
        policy_digest: &DigestHex,
        decision_receipt_digest: &DigestHex,
        amount_minor: u64,
        currency: &Currency,
        reservations: &[PurchaseReservationIntent],
        now: u64,
    ) -> Result<ReservePurchaseResult, PurchaseError> {
        let mut data = self.data.lock().map_err(|_| PurchaseError::Persistence)?;
        reserve_data(
            &mut data,
            workflow_id,
            event_id,
            authorization_id,
            action_digest,
            policy_digest,
            decision_receipt_digest,
            amount_minor,
            currency,
            reservations,
            now,
        )
    }

    fn get(&self, workflow_id: &str) -> Result<Option<PurchaseReservationRecord>, PurchaseError> {
        Ok(self
            .data
            .lock()
            .map_err(|_| PurchaseError::Persistence)?
            .records
            .get(workflow_id)
            .cloned())
    }

    fn observe(
        &self,
        workflow_id: &str,
        provider: PurchaseAuthorizationProviderProjection,
        now: u64,
    ) -> Result<PurchaseReservationRecord, PurchaseError> {
        let mut data = self.data.lock().map_err(|_| PurchaseError::Persistence)?;
        observe_data(&mut data, workflow_id, provider, now)
    }

    fn mark_unknown(
        &self,
        workflow_id: &str,
        now: u64,
    ) -> Result<PurchaseReservationRecord, PurchaseError> {
        let mut data = self.data.lock().map_err(|_| PurchaseError::Persistence)?;
        let record = data
            .records
            .get_mut(workflow_id)
            .ok_or(PurchaseError::NotFound)?;
        record.state = PurchaseReservationState::OutcomeUnknown;
        record.updated_at = now;
        Ok(record.clone())
    }
}

/// Durable JSON purchase store used by the demo.
pub struct PersistentPurchaseAuthorizationStore {
    path: PathBuf,
    data: Mutex<PurchaseStoreData>,
}

impl PersistentPurchaseAuthorizationStore {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, PurchaseError> {
        let path = path.as_ref().to_path_buf();
        let data = if path.exists() {
            serde_json::from_slice(&fs::read(&path).map_err(|_| PurchaseError::Persistence)?)
                .map_err(|_| PurchaseError::Persistence)?
        } else {
            PurchaseStoreData::default()
        };
        Ok(Self {
            path,
            data: Mutex::new(data),
        })
    }

    fn persist(&self, data: &PurchaseStoreData) -> Result<(), PurchaseError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|_| PurchaseError::Persistence)?;
        }
        let bytes = canonical_json(data).map_err(|_| PurchaseError::Canonicalization)?;
        let temporary = self.path.with_extension("tmp");
        fs::write(&temporary, bytes).map_err(|_| PurchaseError::Persistence)?;
        fs::rename(temporary, &self.path).map_err(|_| PurchaseError::Persistence)
    }
}

impl PurchaseAuthorizationStore for PersistentPurchaseAuthorizationStore {
    fn snapshot(
        &self,
        policy: &StripeBoundedPurchasePolicyV1,
        now: u64,
    ) -> Result<PurchaseAggregateSnapshot, PurchaseError> {
        let data = self.data.lock().map_err(|_| PurchaseError::Persistence)?;
        snapshot_data(&data, policy, now)
    }

    fn reserve(
        &self,
        workflow_id: &str,
        event_id: &EventId,
        authorization_id: &IssuingAuthorizationId,
        action_digest: &DigestHex,
        policy_digest: &DigestHex,
        decision_receipt_digest: &DigestHex,
        amount_minor: u64,
        currency: &Currency,
        reservations: &[PurchaseReservationIntent],
        now: u64,
    ) -> Result<ReservePurchaseResult, PurchaseError> {
        let mut data = self.data.lock().map_err(|_| PurchaseError::Persistence)?;
        let result = reserve_data(
            &mut data,
            workflow_id,
            event_id,
            authorization_id,
            action_digest,
            policy_digest,
            decision_receipt_digest,
            amount_minor,
            currency,
            reservations,
            now,
        )?;
        if matches!(result, ReservePurchaseResult::Reserved(_)) {
            self.persist(&data)?;
        }
        Ok(result)
    }

    fn get(&self, workflow_id: &str) -> Result<Option<PurchaseReservationRecord>, PurchaseError> {
        Ok(self
            .data
            .lock()
            .map_err(|_| PurchaseError::Persistence)?
            .records
            .get(workflow_id)
            .cloned())
    }

    fn observe(
        &self,
        workflow_id: &str,
        provider: PurchaseAuthorizationProviderProjection,
        now: u64,
    ) -> Result<PurchaseReservationRecord, PurchaseError> {
        let mut data = self.data.lock().map_err(|_| PurchaseError::Persistence)?;
        let record = observe_data(&mut data, workflow_id, provider, now)?;
        self.persist(&data)?;
        Ok(record)
    }

    fn mark_unknown(
        &self,
        workflow_id: &str,
        now: u64,
    ) -> Result<PurchaseReservationRecord, PurchaseError> {
        let mut data = self.data.lock().map_err(|_| PurchaseError::Persistence)?;
        let record = data
            .records
            .get_mut(workflow_id)
            .ok_or(PurchaseError::NotFound)?;
        record.state = PurchaseReservationState::OutcomeUnknown;
        record.updated_at = now;
        let result = record.clone();
        self.persist(&data)?;
        Ok(result)
    }
}

/// Closed purchase-domain failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PurchaseError {
    #[error("invalid purchase policy")]
    InvalidPolicy,
    #[error("invalid purchase intent")]
    InvalidIntent,
    #[error("invalid purchase evidence")]
    InvalidEvidence,
    #[error("invalid purchase action")]
    InvalidAction,
    #[error("invalid purchase configuration")]
    InvalidConfiguration,
    #[error("canonicalization failure")]
    Canonicalization,
    #[error("checked arithmetic failed")]
    Arithmetic,
    #[error("event replay")]
    EventReplay,
    #[error("purchase record not found")]
    NotFound,
    #[error("purchase persistence failure")]
    Persistence,
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc, thread};

    use super::*;
    use crate::canonical::sha256;

    fn policy(limit: u64) -> StripeBoundedPurchasePolicyV1 {
        StripeBoundedPurchasePolicyV1::new(StripeBoundedPurchasePolicyInput {
            policy_id: "purchase-fixture".into(),
            valid_from: 100,
            expires_at: 1_000,
            allowed_test_account_ids: vec![StripeAccountId::parse("acct_purchasefixture").unwrap()],
            allowed_cardholder_ids: vec![
                IssuingCardholderId::parse("ich_purchasefixture").unwrap(),
            ],
            allowed_card_ids: vec![IssuingCardId::parse("ic_purchasefixture").unwrap()],
            allowed_currencies: vec![Currency::parse("usd").unwrap()],
            allowed_merchant_ids: vec!["merchant-auths".into()],
            allowed_merchant_name_commitments: vec![sha256(b"Auths API")],
            allowed_merchant_categories: vec!["computer_software_stores".into()],
            blocked_merchant_categories: vec![],
            allowed_merchant_countries: vec!["US".into()],
            blocked_merchant_countries: vec![],
            allowed_procurement_scopes: vec!["api-access".into()],
            allowed_authorization_methods: vec![PurchaseAuthorizationMethod::Online],
            per_purchase_minor_by_currency: BTreeMap::from([(
                Currency::parse("usd").unwrap(),
                limit,
            )]),
            per_merchant_minor_by_currency: BTreeMap::from([(
                Currency::parse("usd").unwrap(),
                limit,
            )]),
            per_category_minor_by_currency: BTreeMap::from([(
                Currency::parse("usd").unwrap(),
                limit,
            )]),
            aggregate_budgets: vec![AggregatePurchaseBudget {
                budget_id: "global".into(),
                scope: PurchaseBudgetScope::Global,
                currency: Currency::parse("usd").unwrap(),
                limit_minor: limit,
                starts_at: 100,
                ends_at: 1_000,
            }],
            maximum_intent_age_seconds: 300,
            maximum_event_age_seconds: 60,
            decision_deadline_milliseconds: 1_000,
            allowed_api_versions: vec!["2025-04-30.basil".into()],
        })
        .unwrap()
    }

    #[test]
    fn concurrent_last_unit_has_one_winner() {
        let store = Arc::new(InMemoryPurchaseAuthorizationStore::new());
        let reservation = PurchaseReservationIntent {
            budget_id: "global".into(),
            currency: Currency::parse("usd").unwrap(),
            amount_minor: 500,
            limit_minor: 500,
        };
        let mut joins = Vec::new();
        for index in 0..2 {
            let store = Arc::clone(&store);
            let reservation = reservation.clone();
            joins.push(thread::spawn(move || {
                store
                    .reserve(
                        &format!("workflow-{index}"),
                        &EventId::parse(format!("evt_purchasefixture{index:08}")).unwrap(),
                        &IssuingAuthorizationId::parse(format!("iauth_purchasefixture{index:08}"))
                            .unwrap(),
                        &sha256(format!("action-{index}").as_bytes()),
                        &sha256(b"policy"),
                        &sha256(format!("receipt-{index}").as_bytes()),
                        500,
                        &Currency::parse("usd").unwrap(),
                        &[reservation],
                        200,
                    )
                    .unwrap()
            }));
        }
        let reserved = joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .filter(|result| matches!(result, ReservePurchaseResult::Reserved(_)))
            .count();
        assert_eq!(reserved, 1);
        assert_eq!(
            store
                .snapshot(&policy(500), 200)
                .unwrap()
                .held_minor_by_budget["global"],
            500
        );
    }

    #[test]
    fn duplicate_workflow_replays_and_duplicate_event_conflicts() {
        let store = InMemoryPurchaseAuthorizationStore::new();
        let event = EventId::parse("evt_purchasefixture").unwrap();
        let authorization = IssuingAuthorizationId::parse("iauth_purchasefixture").unwrap();
        let reservation = PurchaseReservationIntent {
            budget_id: "global".into(),
            currency: Currency::parse("usd").unwrap(),
            amount_minor: 100,
            limit_minor: 500,
        };
        let reserve = |workflow: &str| {
            store.reserve(
                workflow,
                &event,
                &authorization,
                &sha256(b"action"),
                &sha256(b"policy"),
                &sha256(b"receipt"),
                100,
                &Currency::parse("usd").unwrap(),
                std::slice::from_ref(&reservation),
                200,
            )
        };
        assert!(matches!(
            reserve("workflow-one").unwrap(),
            ReservePurchaseResult::Reserved(_)
        ));
        assert!(matches!(
            reserve("workflow-one").unwrap(),
            ReservePurchaseResult::Replay(_)
        ));
        assert_eq!(reserve("workflow-two"), Err(PurchaseError::EventReplay));
    }

    #[test]
    fn persistent_store_survives_restart_and_releases_capacity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("purchase-store.json");
        let event = EventId::parse("evt_purchasefixture").unwrap();
        let authorization = IssuingAuthorizationId::parse("iauth_purchasefixture").unwrap();
        let reservation = PurchaseReservationIntent {
            budget_id: "global".into(),
            currency: Currency::parse("usd").unwrap(),
            amount_minor: 300,
            limit_minor: 500,
        };
        {
            let store = PersistentPurchaseAuthorizationStore::new(&path).unwrap();
            assert!(matches!(
                store
                    .reserve(
                        "workflow-persistent",
                        &event,
                        &authorization,
                        &sha256(b"action"),
                        &sha256(b"policy"),
                        &sha256(b"receipt"),
                        300,
                        &Currency::parse("usd").unwrap(),
                        &[reservation],
                        200,
                    )
                    .unwrap(),
                ReservePurchaseResult::Reserved(_)
            ));
            store.mark_unknown("workflow-persistent", 201).unwrap();
        }
        let store = PersistentPurchaseAuthorizationStore::new(&path).unwrap();
        assert_eq!(
            store.get("workflow-persistent").unwrap().unwrap().state(),
            PurchaseReservationState::OutcomeUnknown
        );
        store
            .observe(
                "workflow-persistent",
                PurchaseAuthorizationProviderProjection {
                    authorization_id: authorization,
                    approved: false,
                    status: "reversed".into(),
                    authorized_amount_minor: 300,
                    captured_amount_minor: 0,
                    currency: Currency::parse("usd").unwrap(),
                    request_reason: "voided".into(),
                    observed_at: 202,
                    response_digest: sha256(b"provider"),
                },
                202,
            )
            .unwrap();
        assert_eq!(
            store
                .snapshot(&policy(500), 202)
                .unwrap()
                .held_minor_by_budget["global"],
            0
        );
    }
}
