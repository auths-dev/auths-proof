//! Closed Payout policy, evidence, configuration, approval, and durable state.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    reason = "payout commitments and atomic reservation dimensions remain explicit"
)]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use super::PayoutMethod;
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::{
        BalanceTransactionId, Currency, DigestHex, ExternalAccountId, PayoutId, StripeAccountId,
    },
};

pub const PAYOUT_PROFILE: &str = "auths.stripe.exact-payout/1";
pub const PAYOUT_POLICY_TYPE: &str = "auths.stripe.bounded-payout-policy/1";
pub const PAYOUT_EVALUATOR_ID: &str = "auths.stripe.bounded-payout-evaluator/1";
pub const PAYOUT_RECEIPT_SCHEMA: &str = "auths.stripe.payout-receipt/1";
pub const PAYOUT_POLICY_PROVENANCE: &str = "executor-local-trusted-configuration";

const MAX_COLLECTION: usize = 64;
const MAX_MONEY_MINOR: u64 = 99_999_999;

pub(super) fn payout_label_valid(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn sorted_unique<T: Ord>(values: &[T]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_COLLECTION
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PayoutBudgetScope {
    Global,
    Destination(ExternalAccountId),
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregatePayoutBudget {
    pub budget_id: String,
    pub scope: PayoutBudgetScope,
    pub currency: Currency,
    pub limit_minor: u64,
    pub starts_at: u64,
    pub ends_at: u64,
}

impl AggregatePayoutBudget {
    fn valid(&self) -> bool {
        payout_label_valid(&self.budget_id)
            && (1..=MAX_MONEY_MINOR).contains(&self.limit_minor)
            && self.starts_at < self.ends_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutApprovalThreshold {
    pub currency: Currency,
    pub amount_minor: u64,
    pub required_assurance: u8,
    pub required_approver_scope: String,
    pub required_distinct_principals: u8,
}

impl PayoutApprovalThreshold {
    fn valid(&self) -> bool {
        (1..=MAX_MONEY_MINOR).contains(&self.amount_minor)
            && self.required_assurance > 0
            && payout_label_valid(&self.required_approver_scope)
            && (1..=8).contains(&self.required_distinct_principals)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeBoundedPayoutPolicyV1 {
    policy_type: String,
    canonicalization: String,
    evaluator_semantic_id: String,
    evaluator_semantic_version: u16,
    policy_id: String,
    valid_from: u64,
    expires_at: u64,
    allowed_test_account_ids: Vec<StripeAccountId>,
    allowed_external_destination_ids: Vec<ExternalAccountId>,
    allowed_destination_type_commitments: Vec<DigestHex>,
    allowed_currencies: Vec<Currency>,
    allowed_source_types: Vec<String>,
    allowed_business_scopes: Vec<String>,
    allowed_methods: Vec<PayoutMethod>,
    per_payout_minor_by_currency: BTreeMap<Currency, u64>,
    per_destination_minor_by_currency: BTreeMap<Currency, u64>,
    aggregate_budgets: Vec<AggregatePayoutBudget>,
    approval_thresholds: Vec<PayoutApprovalThreshold>,
    minimum_available_balance_after_minor_by_currency: BTreeMap<Currency, u64>,
    maximum_balance_evidence_age_seconds: u64,
    maximum_destination_evidence_age_seconds: u64,
    maximum_action_lifetime_seconds: u64,
    allowed_api_versions: Vec<String>,
    require_manual_payout: bool,
    require_livemode: bool,
}

pub struct StripeBoundedPayoutPolicyInput {
    pub policy_id: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub allowed_test_account_ids: Vec<StripeAccountId>,
    pub allowed_external_destination_ids: Vec<ExternalAccountId>,
    pub allowed_destination_type_commitments: Vec<DigestHex>,
    pub allowed_currencies: Vec<Currency>,
    pub allowed_source_types: Vec<String>,
    pub allowed_business_scopes: Vec<String>,
    pub per_payout_minor_by_currency: BTreeMap<Currency, u64>,
    pub per_destination_minor_by_currency: BTreeMap<Currency, u64>,
    pub aggregate_budgets: Vec<AggregatePayoutBudget>,
    pub approval_thresholds: Vec<PayoutApprovalThreshold>,
    pub minimum_available_balance_after_minor_by_currency: BTreeMap<Currency, u64>,
    pub maximum_balance_evidence_age_seconds: u64,
    pub maximum_destination_evidence_age_seconds: u64,
    pub maximum_action_lifetime_seconds: u64,
    pub allowed_api_versions: Vec<String>,
}

impl StripeBoundedPayoutPolicyV1 {
    pub fn new(mut input: StripeBoundedPayoutPolicyInput) -> Result<Self, PayoutError> {
        input.allowed_test_account_ids.sort();
        input.allowed_external_destination_ids.sort();
        input.allowed_destination_type_commitments.sort();
        input.allowed_currencies.sort();
        input.allowed_source_types.sort();
        input.allowed_business_scopes.sort();
        input.aggregate_budgets.sort();
        input.approval_thresholds.sort();
        input.allowed_api_versions.sort();
        let value = Self {
            policy_type: PAYOUT_POLICY_TYPE.into(),
            canonicalization: "rfc8785-sha256-v1".into(),
            evaluator_semantic_id: PAYOUT_EVALUATOR_ID.into(),
            evaluator_semantic_version: 1,
            policy_id: input.policy_id,
            valid_from: input.valid_from,
            expires_at: input.expires_at,
            allowed_test_account_ids: input.allowed_test_account_ids,
            allowed_external_destination_ids: input.allowed_external_destination_ids,
            allowed_destination_type_commitments: input.allowed_destination_type_commitments,
            allowed_currencies: input.allowed_currencies,
            allowed_source_types: input.allowed_source_types,
            allowed_business_scopes: input.allowed_business_scopes,
            allowed_methods: vec![PayoutMethod::Standard],
            per_payout_minor_by_currency: input.per_payout_minor_by_currency,
            per_destination_minor_by_currency: input.per_destination_minor_by_currency,
            aggregate_budgets: input.aggregate_budgets,
            approval_thresholds: input.approval_thresholds,
            minimum_available_balance_after_minor_by_currency: input
                .minimum_available_balance_after_minor_by_currency,
            maximum_balance_evidence_age_seconds: input.maximum_balance_evidence_age_seconds,
            maximum_destination_evidence_age_seconds: input
                .maximum_destination_evidence_age_seconds,
            maximum_action_lifetime_seconds: input.maximum_action_lifetime_seconds,
            allowed_api_versions: input.allowed_api_versions,
            require_manual_payout: true,
            require_livemode: false,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PayoutError> {
        let map_valid = |map: &BTreeMap<Currency, u64>, allow_zero: bool| {
            !map.is_empty()
                && map.iter().all(|(currency, value)| {
                    self.allowed_currencies.binary_search(currency).is_ok()
                        && ((allow_zero && *value <= MAX_MONEY_MINOR)
                            || (!allow_zero && (1..=MAX_MONEY_MINOR).contains(value)))
                })
        };
        let valid = self.policy_type == PAYOUT_POLICY_TYPE
            && self.canonicalization == "rfc8785-sha256-v1"
            && self.evaluator_semantic_id == PAYOUT_EVALUATOR_ID
            && self.evaluator_semantic_version == 1
            && payout_label_valid(&self.policy_id)
            && self.valid_from < self.expires_at
            && sorted_unique(&self.allowed_test_account_ids)
            && sorted_unique(&self.allowed_external_destination_ids)
            && sorted_unique(&self.allowed_destination_type_commitments)
            && sorted_unique(&self.allowed_currencies)
            && sorted_unique(&self.allowed_source_types)
            && self
                .allowed_source_types
                .iter()
                .all(|value| payout_label_valid(value))
            && sorted_unique(&self.allowed_business_scopes)
            && self
                .allowed_business_scopes
                .iter()
                .all(|value| payout_label_valid(value))
            && self.allowed_methods == [PayoutMethod::Standard]
            && map_valid(&self.per_payout_minor_by_currency, false)
            && map_valid(&self.per_destination_minor_by_currency, false)
            && map_valid(
                &self.minimum_available_balance_after_minor_by_currency,
                true,
            )
            && !self.aggregate_budgets.is_empty()
            && self.aggregate_budgets.len() <= MAX_COLLECTION
            && self
                .aggregate_budgets
                .iter()
                .all(AggregatePayoutBudget::valid)
            && self
                .aggregate_budgets
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && self
                .aggregate_budgets
                .iter()
                .map(|budget| budget.budget_id.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                == self.aggregate_budgets.len()
            && self.approval_thresholds.len() <= MAX_COLLECTION
            && self.approval_thresholds.iter().all(|threshold| {
                threshold.valid()
                    && self
                        .allowed_currencies
                        .binary_search(&threshold.currency)
                        .is_ok()
            })
            && self
                .approval_thresholds
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && (1..=300).contains(&self.maximum_balance_evidence_age_seconds)
            && (1..=300).contains(&self.maximum_destination_evidence_age_seconds)
            && (1..=3_600).contains(&self.maximum_action_lifetime_seconds)
            && sorted_unique(&self.allowed_api_versions)
            && self
                .allowed_api_versions
                .iter()
                .all(|value| payout_label_valid(value))
            && self.require_manual_payout
            && !self.require_livemode;
        if valid {
            Ok(())
        } else {
            Err(PayoutError::InvalidPolicy)
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
    pub fn accounts(&self) -> &[StripeAccountId] {
        &self.allowed_test_account_ids
    }
    pub fn destinations(&self) -> &[ExternalAccountId] {
        &self.allowed_external_destination_ids
    }
    pub fn destination_types(&self) -> &[DigestHex] {
        &self.allowed_destination_type_commitments
    }
    pub fn currencies(&self) -> &[Currency] {
        &self.allowed_currencies
    }
    pub fn sources(&self) -> &[String] {
        &self.allowed_source_types
    }
    pub fn scopes(&self) -> &[String] {
        &self.allowed_business_scopes
    }
    pub fn payout_limits(&self) -> &BTreeMap<Currency, u64> {
        &self.per_payout_minor_by_currency
    }
    pub fn destination_limits(&self) -> &BTreeMap<Currency, u64> {
        &self.per_destination_minor_by_currency
    }
    pub fn minimum_balances(&self) -> &BTreeMap<Currency, u64> {
        &self.minimum_available_balance_after_minor_by_currency
    }
    pub fn budgets(&self) -> &[AggregatePayoutBudget] {
        &self.aggregate_budgets
    }
    pub fn thresholds(&self) -> &[PayoutApprovalThreshold] {
        &self.approval_thresholds
    }
    pub const fn maximum_balance_age(&self) -> u64 {
        self.maximum_balance_evidence_age_seconds
    }
    pub const fn maximum_destination_age(&self) -> u64 {
        self.maximum_destination_evidence_age_seconds
    }
    pub const fn maximum_action_lifetime(&self) -> u64 {
        self.maximum_action_lifetime_seconds
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripePayoutConfigurationV1 {
    profile: String,
    evaluator_id: String,
    implementation_id: String,
    policy_digest: DigestHex,
    stripe_account_id: StripeAccountId,
    source_type: String,
    stripe_api_version: String,
    approval_schema: String,
    store_schema: String,
    receipt_schema: String,
    executor_audience: String,
    maximum_action_bytes: u64,
    maximum_evidence_objects: u32,
    maximum_approvals: u32,
    maximum_reservations: u32,
    maximum_work_units: u32,
}

impl StripePayoutConfigurationV1 {
    pub fn new(
        policy: &StripeBoundedPayoutPolicyV1,
        stripe_account_id: StripeAccountId,
        source_type: String,
        stripe_api_version: String,
        executor_audience: String,
    ) -> Result<Self, PayoutError> {
        let value = Self {
            profile: PAYOUT_PROFILE.into(),
            evaluator_id: PAYOUT_EVALUATOR_ID.into(),
            implementation_id: "auths-stripe-payout-rust/1".into(),
            policy_digest: policy.digest().map_err(|_| PayoutError::Canonicalization)?,
            stripe_account_id,
            source_type,
            stripe_api_version,
            approval_schema: "auths.stripe.payout-approval-evidence/1".into(),
            store_schema: "auths.stripe.payout-reservations/1".into(),
            receipt_schema: PAYOUT_RECEIPT_SCHEMA.into(),
            executor_audience,
            maximum_action_bytes: 65_536,
            maximum_evidence_objects: 64,
            maximum_approvals: 16,
            maximum_reservations: 64,
            maximum_work_units: 4_096,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PayoutError> {
        if self.profile == PAYOUT_PROFILE
            && self.evaluator_id == PAYOUT_EVALUATOR_ID
            && self.implementation_id == "auths-stripe-payout-rust/1"
            && payout_label_valid(&self.source_type)
            && payout_label_valid(&self.stripe_api_version)
            && self.approval_schema == "auths.stripe.payout-approval-evidence/1"
            && self.store_schema == "auths.stripe.payout-reservations/1"
            && self.receipt_schema == PAYOUT_RECEIPT_SCHEMA
            && Audience::parse(&self.executor_audience).is_ok()
            && self.maximum_action_bytes == 65_536
            && self.maximum_evidence_objects == 64
            && self.maximum_approvals == 16
            && self.maximum_reservations == 64
            && self.maximum_work_units == 4_096
        {
            Ok(())
        } else {
            Err(PayoutError::InvalidConfiguration)
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
    pub fn source_type(&self) -> &str {
        &self.source_type
    }
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutApprovalEvidence {
    pub commitment: DigestHex,
    pub principal_commitment: DigestHex,
    pub approver_scope: String,
    pub assurance: u8,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutEvidenceV1 {
    pub schema: String,
    pub stripe_account_id: StripeAccountId,
    pub livemode: bool,
    pub manual_payouts_enabled: bool,
    pub available_balance_minor: u64,
    pub pending_balance_minor: u64,
    pub currency: Currency,
    pub source_type: String,
    pub destination_external_account_id: ExternalAccountId,
    pub destination_type_commitment: DigestHex,
    pub destination_fingerprint_commitment: DigestHex,
    pub destination_status: String,
    pub destination_observed_at: u64,
    pub existing_pending_payout_minor: u64,
    pub approvals: Vec<PayoutApprovalEvidence>,
    pub stripe_api_version: String,
    pub balance_observed_at: u64,
    pub response_digest: DigestHex,
    pub source: String,
}

impl PayoutEvidenceV1 {
    pub fn validate(&self) -> Result<(), PayoutError> {
        let approvals_valid = self.approvals.len() <= 16
            && self.approvals.windows(2).all(|pair| pair[0] < pair[1])
            && self.approvals.iter().all(|approval| {
                payout_label_valid(&approval.approver_scope) && approval.assurance > 0
            });
        if self.schema == "auths.stripe.payout-evidence/1"
            && self.available_balance_minor <= MAX_MONEY_MINOR
            && self.pending_balance_minor <= MAX_MONEY_MINOR
            && payout_label_valid(&self.source_type)
            && payout_label_valid(&self.destination_status)
            && self.existing_pending_payout_minor <= MAX_MONEY_MINOR
            && approvals_valid
            && payout_label_valid(&self.stripe_api_version)
            && payout_label_valid(&self.source)
        {
            Ok(())
        } else {
            Err(PayoutError::InvalidEvidence)
        }
    }
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutAggregateSnapshot {
    pub held_minor_by_reservation: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutReservationIntent {
    pub reservation_id: String,
    pub currency: Currency,
    pub amount_minor: u64,
    pub limit_minor: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutStatus {
    Pending,
    Paid,
    Failed,
    Canceled,
    Reversed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutProviderProjection {
    pub payout_id: PayoutId,
    pub destination_external_account_id: ExternalAccountId,
    pub amount_minor: u64,
    pub currency: Currency,
    pub method: PayoutMethod,
    pub source_type: String,
    pub status: PayoutStatus,
    pub balance_transaction_id: Option<BalanceTransactionId>,
    pub request_id: Option<String>,
    pub observed_at: u64,
    pub response_digest: DigestHex,
    pub funds_returned_to_available_balance: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutReservationState {
    Reserved,
    ProviderAccepted,
    OutcomeUnknown,
    DeliveryFailedAwaitingReturn,
    Released,
    ObservationOutsidePolicy,
}

impl PayoutReservationState {
    pub const fn holds_capacity(self) -> bool {
        !matches!(self, Self::Released)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutReservationRecord {
    workflow_id: String,
    action_digest: DigestHex,
    policy_digest: DigestHex,
    decision_receipt_digest: DigestHex,
    amount_minor: u64,
    currency: Currency,
    reservations: Vec<PayoutReservationIntent>,
    state: PayoutReservationState,
    provider: Option<PayoutProviderProjection>,
    updated_at: u64,
}

impl PayoutReservationRecord {
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }
    pub const fn decision_receipt_digest(&self) -> &DigestHex {
        &self.decision_receipt_digest
    }
    pub fn reservations(&self) -> &[PayoutReservationIntent] {
        &self.reservations
    }
    pub const fn state(&self) -> PayoutReservationState {
        self.state
    }
    pub fn provider(&self) -> Option<&PayoutProviderProjection> {
        self.provider.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReservePayoutResult {
    Reserved(PayoutReservationRecord),
    Replay(PayoutReservationRecord),
    Conflict(PayoutReservationRecord),
    CapacityExceeded,
}

pub trait PayoutReservationStore: Send + Sync {
    fn snapshot(&self) -> Result<PayoutAggregateSnapshot, PayoutError>;
    fn reserve(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        policy_digest: &DigestHex,
        decision_receipt_digest: &DigestHex,
        amount_minor: u64,
        currency: &Currency,
        reservations: &[PayoutReservationIntent],
        now: u64,
    ) -> Result<ReservePayoutResult, PayoutError>;
    fn get(&self, workflow_id: &str) -> Result<Option<PayoutReservationRecord>, PayoutError>;
    fn record_provider(
        &self,
        workflow_id: &str,
        provider: PayoutProviderProjection,
        state: PayoutReservationState,
        now: u64,
    ) -> Result<PayoutReservationRecord, PayoutError>;
    fn set_state(
        &self,
        workflow_id: &str,
        state: PayoutReservationState,
        now: u64,
    ) -> Result<PayoutReservationRecord, PayoutError>;
}

impl<T: PayoutReservationStore + ?Sized> PayoutReservationStore for Arc<T> {
    fn snapshot(&self) -> Result<PayoutAggregateSnapshot, PayoutError> {
        (**self).snapshot()
    }
    fn reserve(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        policy_digest: &DigestHex,
        decision_receipt_digest: &DigestHex,
        amount_minor: u64,
        currency: &Currency,
        reservations: &[PayoutReservationIntent],
        now: u64,
    ) -> Result<ReservePayoutResult, PayoutError> {
        (**self).reserve(
            workflow_id,
            action_digest,
            policy_digest,
            decision_receipt_digest,
            amount_minor,
            currency,
            reservations,
            now,
        )
    }
    fn get(&self, workflow_id: &str) -> Result<Option<PayoutReservationRecord>, PayoutError> {
        (**self).get(workflow_id)
    }
    fn record_provider(
        &self,
        workflow_id: &str,
        provider: PayoutProviderProjection,
        state: PayoutReservationState,
        now: u64,
    ) -> Result<PayoutReservationRecord, PayoutError> {
        (**self).record_provider(workflow_id, provider, state, now)
    }
    fn set_state(
        &self,
        workflow_id: &str,
        state: PayoutReservationState,
        now: u64,
    ) -> Result<PayoutReservationRecord, PayoutError> {
        (**self).set_state(workflow_id, state, now)
    }
}

#[derive(Default, Deserialize, Serialize)]
struct StoreData {
    records: HashMap<String, PayoutReservationRecord>,
}

fn snapshot(data: &StoreData) -> Result<PayoutAggregateSnapshot, PayoutError> {
    let mut held: BTreeMap<String, u64> = BTreeMap::new();
    for record in data
        .records
        .values()
        .filter(|record| record.state.holds_capacity())
    {
        for reservation in &record.reservations {
            let current = held.get(&reservation.reservation_id).copied().unwrap_or(0);
            held.insert(
                reservation.reservation_id.clone(),
                current
                    .checked_add(reservation.amount_minor)
                    .ok_or(PayoutError::Arithmetic)?,
            );
        }
    }
    Ok(PayoutAggregateSnapshot {
        held_minor_by_reservation: held,
    })
}

fn reserve(
    data: &mut StoreData,
    workflow_id: &str,
    action_digest: &DigestHex,
    policy_digest: &DigestHex,
    decision_receipt_digest: &DigestHex,
    amount_minor: u64,
    currency: &Currency,
    reservations: &[PayoutReservationIntent],
    now: u64,
) -> Result<ReservePayoutResult, PayoutError> {
    if let Some(existing) = data.records.get(workflow_id) {
        return Ok(if existing.action_digest == *action_digest {
            ReservePayoutResult::Replay(existing.clone())
        } else {
            ReservePayoutResult::Conflict(existing.clone())
        });
    }
    let current = snapshot(data)?;
    for reservation in reservations {
        if current
            .held_minor_by_reservation
            .get(&reservation.reservation_id)
            .copied()
            .unwrap_or(0)
            .checked_add(reservation.amount_minor)
            .is_none_or(|after| after > reservation.limit_minor)
        {
            return Ok(ReservePayoutResult::CapacityExceeded);
        }
    }
    let record = PayoutReservationRecord {
        workflow_id: workflow_id.into(),
        action_digest: action_digest.clone(),
        policy_digest: policy_digest.clone(),
        decision_receipt_digest: decision_receipt_digest.clone(),
        amount_minor,
        currency: currency.clone(),
        reservations: reservations.to_vec(),
        state: PayoutReservationState::Reserved,
        provider: None,
        updated_at: now,
    };
    data.records.insert(workflow_id.into(), record.clone());
    Ok(ReservePayoutResult::Reserved(record))
}

fn update(
    data: &mut StoreData,
    workflow_id: &str,
    provider: Option<PayoutProviderProjection>,
    state: PayoutReservationState,
    now: u64,
) -> Result<PayoutReservationRecord, PayoutError> {
    let record = data
        .records
        .get_mut(workflow_id)
        .ok_or(PayoutError::NotFound)?;
    if let Some(value) = provider {
        record.provider = Some(value);
    }
    record.state = state;
    record.updated_at = now;
    Ok(record.clone())
}

#[derive(Default)]
pub struct InMemoryPayoutReservationStore {
    data: Mutex<StoreData>,
}

impl InMemoryPayoutReservationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

macro_rules! store_impl {
    ($type:ty, $persist:expr) => {
        impl PayoutReservationStore for $type {
            fn snapshot(&self) -> Result<PayoutAggregateSnapshot, PayoutError> {
                let data = self.data.lock().map_err(|_| PayoutError::Persistence)?;
                snapshot(&data)
            }
            fn reserve(
                &self,
                workflow_id: &str,
                action_digest: &DigestHex,
                policy_digest: &DigestHex,
                decision_receipt_digest: &DigestHex,
                amount_minor: u64,
                currency: &Currency,
                reservations: &[PayoutReservationIntent],
                now: u64,
            ) -> Result<ReservePayoutResult, PayoutError> {
                let mut data = self.data.lock().map_err(|_| PayoutError::Persistence)?;
                let result = reserve(
                    &mut data,
                    workflow_id,
                    action_digest,
                    policy_digest,
                    decision_receipt_digest,
                    amount_minor,
                    currency,
                    reservations,
                    now,
                )?;
                if matches!(result, ReservePayoutResult::Reserved(_)) {
                    ($persist)(self, &data)?;
                }
                Ok(result)
            }
            fn get(
                &self,
                workflow_id: &str,
            ) -> Result<Option<PayoutReservationRecord>, PayoutError> {
                Ok(self
                    .data
                    .lock()
                    .map_err(|_| PayoutError::Persistence)?
                    .records
                    .get(workflow_id)
                    .cloned())
            }
            fn record_provider(
                &self,
                workflow_id: &str,
                provider: PayoutProviderProjection,
                state: PayoutReservationState,
                now: u64,
            ) -> Result<PayoutReservationRecord, PayoutError> {
                let mut data = self.data.lock().map_err(|_| PayoutError::Persistence)?;
                let record = update(&mut data, workflow_id, Some(provider), state, now)?;
                ($persist)(self, &data)?;
                Ok(record)
            }
            fn set_state(
                &self,
                workflow_id: &str,
                state: PayoutReservationState,
                now: u64,
            ) -> Result<PayoutReservationRecord, PayoutError> {
                let mut data = self.data.lock().map_err(|_| PayoutError::Persistence)?;
                let record = update(&mut data, workflow_id, None, state, now)?;
                ($persist)(self, &data)?;
                Ok(record)
            }
        }
    };
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the shared store macro requires one fallible persistence signature"
)]
fn no_persist(_: &InMemoryPayoutReservationStore, _: &StoreData) -> Result<(), PayoutError> {
    Ok(())
}
store_impl!(InMemoryPayoutReservationStore, no_persist);

pub struct PersistentPayoutReservationStore {
    path: PathBuf,
    data: Mutex<StoreData>,
}

impl PersistentPayoutReservationStore {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, PayoutError> {
        let path = path.as_ref().to_path_buf();
        let data = if path.exists() {
            serde_json::from_slice(&fs::read(&path).map_err(|_| PayoutError::Persistence)?)
                .map_err(|_| PayoutError::Persistence)?
        } else {
            StoreData::default()
        };
        Ok(Self {
            path,
            data: Mutex::new(data),
        })
    }
}

fn persist(store: &PersistentPayoutReservationStore, data: &StoreData) -> Result<(), PayoutError> {
    if let Some(parent) = store.path.parent() {
        fs::create_dir_all(parent).map_err(|_| PayoutError::Persistence)?;
    }
    let temporary = store.path.with_extension("tmp");
    fs::write(
        &temporary,
        canonical_json(data).map_err(|_| PayoutError::Canonicalization)?,
    )
    .map_err(|_| PayoutError::Persistence)?;
    fs::rename(temporary, &store.path).map_err(|_| PayoutError::Persistence)
}
store_impl!(PersistentPayoutReservationStore, persist);

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PayoutError {
    #[error("invalid Payout policy")]
    InvalidPolicy,
    #[error("invalid Payout configuration")]
    InvalidConfiguration,
    #[error("invalid Payout action")]
    InvalidAction,
    #[error("invalid Payout evidence")]
    InvalidEvidence,
    #[error("Payout canonicalization failed")]
    Canonicalization,
    #[error("Payout arithmetic failed")]
    Arithmetic,
    #[error("Payout record not found")]
    NotFound,
    #[error("Payout persistence failed")]
    Persistence,
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;
    use crate::canonical;

    fn intent() -> PayoutReservationIntent {
        PayoutReservationIntent {
            reservation_id: "balance:acct_concurrent:usd:bank_account".into(),
            currency: Currency::parse("usd").unwrap(),
            amount_minor: 500,
            limit_minor: 500,
        }
    }

    #[test]
    fn concurrent_last_balance_capacity_has_one_winner() {
        let store = Arc::new(InMemoryPayoutReservationStore::new());
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for suffix in ["one", "two"] {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                store
                    .reserve(
                        &format!("workflow-{suffix}"),
                        &canonical::sha256(suffix.as_bytes()),
                        &canonical::sha256(b"policy"),
                        &canonical::sha256(b"receipt"),
                        500,
                        &Currency::parse("usd").unwrap(),
                        &[intent()],
                        1,
                    )
                    .unwrap()
            }));
        }
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, ReservePayoutResult::Reserved(_)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, ReservePayoutResult::CapacityExceeded))
                .count(),
            1
        );
    }

    #[test]
    fn pending_unknown_and_failed_without_return_hold_capacity() {
        for state in [
            PayoutReservationState::ProviderAccepted,
            PayoutReservationState::OutcomeUnknown,
            PayoutReservationState::DeliveryFailedAwaitingReturn,
        ] {
            assert!(state.holds_capacity());
        }
        assert!(!PayoutReservationState::Released.holds_capacity());
    }

    #[test]
    fn persistent_unknown_replays_after_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("payout-state.json");
        let currency = Currency::parse("usd").unwrap();
        let digest = canonical::sha256(b"persistent-payout");
        {
            let store = PersistentPayoutReservationStore::new(&path).unwrap();
            store
                .reserve(
                    "workflow-persistent",
                    &digest,
                    &digest,
                    &digest,
                    500,
                    &currency,
                    &[intent()],
                    1,
                )
                .unwrap();
            store
                .set_state(
                    "workflow-persistent",
                    PayoutReservationState::OutcomeUnknown,
                    2,
                )
                .unwrap();
        }
        let reopened = PersistentPayoutReservationStore::new(&path).unwrap();
        assert_eq!(
            reopened
                .get("workflow-persistent")
                .unwrap()
                .unwrap()
                .state(),
            PayoutReservationState::OutcomeUnknown
        );
        assert!(matches!(
            reopened
                .reserve(
                    "workflow-persistent",
                    &digest,
                    &digest,
                    &digest,
                    500,
                    &currency,
                    &[intent()],
                    3,
                )
                .unwrap(),
            ReservePayoutResult::Replay(_)
        ));
    }
}
