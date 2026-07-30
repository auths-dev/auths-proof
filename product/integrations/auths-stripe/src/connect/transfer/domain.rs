//! Closed Connect Transfer policy, evidence, configuration, and durable state.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    reason = "Connect transfer commitments and atomic reservation dimensions remain explicit"
)]

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::{
        BalanceTransactionId, ChargeId, Currency, DigestHex, PaymentIntentId, StripeAccountId,
        TransferId,
    },
};

/// Exact action profile.
pub const CONNECT_TRANSFER_PROFILE: &str = "auths.stripe.exact-connect-transfer/1";
/// Closed policy identity.
pub const CONNECT_TRANSFER_POLICY_TYPE: &str = "auths.stripe.bounded-connect-transfer-policy/1";
/// Pure evaluator identity.
pub const CONNECT_TRANSFER_EVALUATOR_ID: &str = "auths.stripe.bounded-connect-transfer-evaluator/1";
/// Closed receipt family.
pub const CONNECT_TRANSFER_RECEIPT_SCHEMA: &str = "auths.stripe.connect-transfer-receipt/1";
/// Initial trusted policy provenance.
pub const CONNECT_TRANSFER_POLICY_PROVENANCE: &str = "executor-local-trusted-configuration";

const MAX_COLLECTION: usize = 64;
const MAX_MONEY_MINOR: u64 = 99_999_999;

pub(super) fn domain_valid_local(value: &str) -> bool {
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

/// Aggregate transfer budget scope.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ConnectTransferBudgetScope {
    Global,
    Destination(StripeAccountId),
    Source(ChargeId),
}

/// One exact fixed-window aggregate budget.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateConnectTransferBudget {
    pub budget_id: String,
    pub scope: ConnectTransferBudgetScope,
    pub currency: Currency,
    pub limit_minor: u64,
    pub starts_at: u64,
    pub ends_at: u64,
}

impl AggregateConnectTransferBudget {
    fn valid(&self) -> bool {
        domain_valid_local(&self.budget_id)
            && (1..=MAX_MONEY_MINOR).contains(&self.limit_minor)
            && self.starts_at < self.ends_at
    }
}

/// Immutable Connect-transfer policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeBoundedConnectTransferPolicyV1 {
    policy_type: String,
    canonicalization: String,
    evaluator_semantic_id: String,
    evaluator_semantic_version: u16,
    policy_id: String,
    valid_from: u64,
    expires_at: u64,
    allowed_test_platform_account_ids: Vec<StripeAccountId>,
    allowed_destination_connected_account_ids: Vec<StripeAccountId>,
    allowed_source_charge_ids: Vec<ChargeId>,
    allowed_transfer_groups: Vec<String>,
    allowed_currencies: Vec<Currency>,
    allowed_business_scopes: Vec<String>,
    per_transfer_minor_by_currency: BTreeMap<Currency, u64>,
    per_destination_minor_by_currency: BTreeMap<Currency, u64>,
    per_source_charge_basis_points: u16,
    aggregate_budgets: Vec<AggregateConnectTransferBudget>,
    maximum_source_evidence_age_seconds: u64,
    maximum_action_lifetime_seconds: u64,
    allowed_api_versions: Vec<String>,
    require_source_transaction: bool,
    require_livemode: bool,
}

/// Constructor carrier for the transfer policy.
pub struct StripeBoundedConnectTransferPolicyInput {
    pub policy_id: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub allowed_test_platform_account_ids: Vec<StripeAccountId>,
    pub allowed_destination_connected_account_ids: Vec<StripeAccountId>,
    pub allowed_source_charge_ids: Vec<ChargeId>,
    pub allowed_transfer_groups: Vec<String>,
    pub allowed_currencies: Vec<Currency>,
    pub allowed_business_scopes: Vec<String>,
    pub per_transfer_minor_by_currency: BTreeMap<Currency, u64>,
    pub per_destination_minor_by_currency: BTreeMap<Currency, u64>,
    pub per_source_charge_basis_points: u16,
    pub aggregate_budgets: Vec<AggregateConnectTransferBudget>,
    pub maximum_source_evidence_age_seconds: u64,
    pub maximum_action_lifetime_seconds: u64,
    pub allowed_api_versions: Vec<String>,
}

impl StripeBoundedConnectTransferPolicyV1 {
    pub fn new(
        mut input: StripeBoundedConnectTransferPolicyInput,
    ) -> Result<Self, ConnectTransferError> {
        input.allowed_test_platform_account_ids.sort();
        input.allowed_destination_connected_account_ids.sort();
        input.allowed_source_charge_ids.sort();
        input.allowed_transfer_groups.sort();
        input.allowed_currencies.sort();
        input.allowed_business_scopes.sort();
        input.aggregate_budgets.sort();
        input.allowed_api_versions.sort();
        let value = Self {
            policy_type: CONNECT_TRANSFER_POLICY_TYPE.into(),
            canonicalization: "rfc8785-sha256-v1".into(),
            evaluator_semantic_id: CONNECT_TRANSFER_EVALUATOR_ID.into(),
            evaluator_semantic_version: 1,
            policy_id: input.policy_id,
            valid_from: input.valid_from,
            expires_at: input.expires_at,
            allowed_test_platform_account_ids: input.allowed_test_platform_account_ids,
            allowed_destination_connected_account_ids: input
                .allowed_destination_connected_account_ids,
            allowed_source_charge_ids: input.allowed_source_charge_ids,
            allowed_transfer_groups: input.allowed_transfer_groups,
            allowed_currencies: input.allowed_currencies,
            allowed_business_scopes: input.allowed_business_scopes,
            per_transfer_minor_by_currency: input.per_transfer_minor_by_currency,
            per_destination_minor_by_currency: input.per_destination_minor_by_currency,
            per_source_charge_basis_points: input.per_source_charge_basis_points,
            aggregate_budgets: input.aggregate_budgets,
            maximum_source_evidence_age_seconds: input.maximum_source_evidence_age_seconds,
            maximum_action_lifetime_seconds: input.maximum_action_lifetime_seconds,
            allowed_api_versions: input.allowed_api_versions,
            require_source_transaction: true,
            require_livemode: false,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ConnectTransferError> {
        let maps = [
            &self.per_transfer_minor_by_currency,
            &self.per_destination_minor_by_currency,
        ];
        let valid = self.policy_type == CONNECT_TRANSFER_POLICY_TYPE
            && self.canonicalization == "rfc8785-sha256-v1"
            && self.evaluator_semantic_id == CONNECT_TRANSFER_EVALUATOR_ID
            && self.evaluator_semantic_version == 1
            && domain_valid_local(&self.policy_id)
            && self.valid_from < self.expires_at
            && sorted_unique(&self.allowed_test_platform_account_ids)
            && sorted_unique(&self.allowed_destination_connected_account_ids)
            && sorted_unique(&self.allowed_source_charge_ids)
            && sorted_unique(&self.allowed_transfer_groups)
            && self
                .allowed_transfer_groups
                .iter()
                .all(|value| domain_valid_local(value))
            && sorted_unique(&self.allowed_currencies)
            && sorted_unique(&self.allowed_business_scopes)
            && self
                .allowed_business_scopes
                .iter()
                .all(|value| domain_valid_local(value))
            && maps.iter().all(|map| {
                !map.is_empty()
                    && map.iter().all(|(currency, limit)| {
                        self.allowed_currencies.binary_search(currency).is_ok()
                            && (1..=MAX_MONEY_MINOR).contains(limit)
                    })
            })
            && (1..=10_000).contains(&self.per_source_charge_basis_points)
            && !self.aggregate_budgets.is_empty()
            && self.aggregate_budgets.len() <= MAX_COLLECTION
            && self
                .aggregate_budgets
                .iter()
                .all(AggregateConnectTransferBudget::valid)
            && self
                .aggregate_budgets
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && self
                .aggregate_budgets
                .iter()
                .map(|budget| budget.budget_id.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.aggregate_budgets.len()
            && (1..=300).contains(&self.maximum_source_evidence_age_seconds)
            && (1..=3_600).contains(&self.maximum_action_lifetime_seconds)
            && sorted_unique(&self.allowed_api_versions)
            && self
                .allowed_api_versions
                .iter()
                .all(|value| domain_valid_local(value))
            && self.require_source_transaction
            && !self.require_livemode;
        if valid {
            Ok(())
        } else {
            Err(ConnectTransferError::InvalidPolicy)
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
    pub const fn maximum_source_evidence_age_seconds(&self) -> u64 {
        self.maximum_source_evidence_age_seconds
    }
    pub const fn maximum_action_lifetime_seconds(&self) -> u64 {
        self.maximum_action_lifetime_seconds
    }
    pub const fn source_basis_points(&self) -> u16 {
        self.per_source_charge_basis_points
    }
    pub fn platforms(&self) -> &[StripeAccountId] {
        &self.allowed_test_platform_account_ids
    }
    pub fn destinations(&self) -> &[StripeAccountId] {
        &self.allowed_destination_connected_account_ids
    }
    pub fn sources(&self) -> &[ChargeId] {
        &self.allowed_source_charge_ids
    }
    pub fn groups(&self) -> &[String] {
        &self.allowed_transfer_groups
    }
    pub fn currencies(&self) -> &[Currency] {
        &self.allowed_currencies
    }
    pub fn scopes(&self) -> &[String] {
        &self.allowed_business_scopes
    }
    pub fn transfer_limits(&self) -> &BTreeMap<Currency, u64> {
        &self.per_transfer_minor_by_currency
    }
    pub fn destination_limits(&self) -> &BTreeMap<Currency, u64> {
        &self.per_destination_minor_by_currency
    }
    pub fn aggregate_budgets(&self) -> &[AggregateConnectTransferBudget] {
        &self.aggregate_budgets
    }
    pub fn api_versions(&self) -> &[String] {
        &self.allowed_api_versions
    }
}

/// Immutable executor configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeConnectTransferConfigurationV1 {
    profile: String,
    evaluator_id: String,
    implementation_id: String,
    policy_digest: DigestHex,
    platform_account_id: StripeAccountId,
    stripe_api_version: String,
    store_schema: String,
    receipt_schema: String,
    executor_audience: String,
    maximum_action_bytes: u64,
    maximum_evidence_objects: u32,
    maximum_reservations: u32,
    maximum_work_units: u32,
}

impl StripeConnectTransferConfigurationV1 {
    pub fn new(
        policy: &StripeBoundedConnectTransferPolicyV1,
        platform_account_id: StripeAccountId,
        stripe_api_version: String,
        executor_audience: String,
    ) -> Result<Self, ConnectTransferError> {
        let value = Self {
            profile: CONNECT_TRANSFER_PROFILE.into(),
            evaluator_id: CONNECT_TRANSFER_EVALUATOR_ID.into(),
            implementation_id: "auths-stripe-connect-transfer-rust/1".into(),
            policy_digest: policy
                .digest()
                .map_err(|_| ConnectTransferError::Canonicalization)?,
            platform_account_id,
            stripe_api_version,
            store_schema: "auths.stripe.connect-transfer-reservations/1".into(),
            receipt_schema: CONNECT_TRANSFER_RECEIPT_SCHEMA.into(),
            executor_audience,
            maximum_action_bytes: 65_536,
            maximum_evidence_objects: 64,
            maximum_reservations: 64,
            maximum_work_units: 4_096,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ConnectTransferError> {
        if self.profile == CONNECT_TRANSFER_PROFILE
            && self.evaluator_id == CONNECT_TRANSFER_EVALUATOR_ID
            && self.implementation_id == "auths-stripe-connect-transfer-rust/1"
            && domain_valid_local(&self.stripe_api_version)
            && self.store_schema == "auths.stripe.connect-transfer-reservations/1"
            && self.receipt_schema == CONNECT_TRANSFER_RECEIPT_SCHEMA
            && Audience::parse(&self.executor_audience).is_ok()
            && self.maximum_action_bytes == 65_536
            && self.maximum_evidence_objects == 64
            && self.maximum_reservations == 64
            && self.maximum_work_units == 4_096
        {
            Ok(())
        } else {
            Err(ConnectTransferError::InvalidConfiguration)
        }
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }
    pub const fn platform_account_id(&self) -> &StripeAccountId {
        &self.platform_account_id
    }
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
}

/// Fresh protected source, destination, and platform-balance evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectTransferEvidenceV1 {
    pub schema: String,
    pub platform_account_id: StripeAccountId,
    pub destination_account_id: StripeAccountId,
    pub destination_transfers_capability_active: bool,
    pub source_charge_id: ChargeId,
    pub source_payment_intent_id: PaymentIntentId,
    pub source_charge_amount_minor: u64,
    pub source_charge_captured: bool,
    pub source_charge_paid: bool,
    pub source_charge_status: String,
    pub source_currency: Currency,
    pub source_committed_transfer_minor: u64,
    pub source_reversed_transfer_minor: u64,
    pub platform_available_balance_minor: u64,
    pub transfer_group: String,
    pub livemode: bool,
    pub stripe_api_version: String,
    pub observed_at: u64,
    pub response_digest: DigestHex,
    pub source: String,
}

impl ConnectTransferEvidenceV1 {
    pub fn validate(&self) -> Result<(), ConnectTransferError> {
        let committed_after_reversal = self
            .source_committed_transfer_minor
            .checked_sub(self.source_reversed_transfer_minor);
        if self.schema == "auths.stripe.connect-transfer-evidence/1"
            && (1..=MAX_MONEY_MINOR).contains(&self.source_charge_amount_minor)
            && domain_valid_local(&self.source_charge_status)
            && committed_after_reversal.is_some()
            && domain_valid_local(&self.transfer_group)
            && !self.livemode
            && domain_valid_local(&self.stripe_api_version)
            && domain_valid_local(&self.source)
        {
            Ok(())
        } else {
            Err(ConnectTransferError::InvalidEvidence)
        }
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Held amount before one decision.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectTransferAggregateSnapshot {
    pub held_minor_by_reservation: BTreeMap<String, u64>,
}

/// One atomic reservation dimension.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectTransferReservationIntent {
    pub reservation_id: String,
    pub currency: Currency,
    pub amount_minor: u64,
    pub limit_minor: u64,
}

/// Sanitized provider Transfer observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectTransferProviderProjection {
    pub transfer_id: TransferId,
    pub destination_account_id: StripeAccountId,
    pub source_charge_id: ChargeId,
    pub amount_minor: u64,
    pub currency: Currency,
    pub transfer_group: String,
    pub reversed: bool,
    pub balance_transaction_id: Option<BalanceTransactionId>,
    pub request_id: Option<String>,
    pub observed_at: u64,
    pub response_digest: DigestHex,
}

/// Durable transfer lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectTransferReservationState {
    Reserved,
    ProviderAccepted,
    OutcomeUnknown,
    Released,
    ObservationOutsidePolicy,
}

impl ConnectTransferReservationState {
    pub const fn holds_capacity(self) -> bool {
        matches!(
            self,
            Self::Reserved
                | Self::ProviderAccepted
                | Self::OutcomeUnknown
                | Self::ObservationOutsidePolicy
        )
    }
}

/// Durable transfer reservation and replay record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectTransferReservationRecord {
    workflow_id: String,
    action_digest: DigestHex,
    policy_digest: DigestHex,
    decision_receipt_digest: DigestHex,
    amount_minor: u64,
    currency: Currency,
    reservations: Vec<ConnectTransferReservationIntent>,
    state: ConnectTransferReservationState,
    provider: Option<ConnectTransferProviderProjection>,
    updated_at: u64,
}

impl ConnectTransferReservationRecord {
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
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
    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }
    pub fn reservations(&self) -> &[ConnectTransferReservationIntent] {
        &self.reservations
    }
    pub const fn state(&self) -> ConnectTransferReservationState {
        self.state
    }
    pub fn provider(&self) -> Option<&ConnectTransferProviderProjection> {
        self.provider.as_ref()
    }
}

/// Atomic reserve result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReserveConnectTransferResult {
    Reserved(ConnectTransferReservationRecord),
    Replay(ConnectTransferReservationRecord),
    Conflict(ConnectTransferReservationRecord),
    CapacityExceeded,
}

/// Transfer-owned durable reservation boundary.
pub trait ConnectTransferReservationStore: Send + Sync {
    fn snapshot(&self) -> Result<ConnectTransferAggregateSnapshot, ConnectTransferError>;
    fn reserve(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        policy_digest: &DigestHex,
        decision_receipt_digest: &DigestHex,
        amount_minor: u64,
        currency: &Currency,
        reservations: &[ConnectTransferReservationIntent],
        now: u64,
    ) -> Result<ReserveConnectTransferResult, ConnectTransferError>;
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<ConnectTransferReservationRecord>, ConnectTransferError>;
    fn record_provider(
        &self,
        workflow_id: &str,
        provider: ConnectTransferProviderProjection,
        state: ConnectTransferReservationState,
        now: u64,
    ) -> Result<ConnectTransferReservationRecord, ConnectTransferError>;
    fn set_state(
        &self,
        workflow_id: &str,
        state: ConnectTransferReservationState,
        now: u64,
    ) -> Result<ConnectTransferReservationRecord, ConnectTransferError>;
}

impl<T: ConnectTransferReservationStore + ?Sized> ConnectTransferReservationStore for Arc<T> {
    fn snapshot(&self) -> Result<ConnectTransferAggregateSnapshot, ConnectTransferError> {
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
        reservations: &[ConnectTransferReservationIntent],
        now: u64,
    ) -> Result<ReserveConnectTransferResult, ConnectTransferError> {
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
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<ConnectTransferReservationRecord>, ConnectTransferError> {
        (**self).get(workflow_id)
    }
    fn record_provider(
        &self,
        workflow_id: &str,
        provider: ConnectTransferProviderProjection,
        state: ConnectTransferReservationState,
        now: u64,
    ) -> Result<ConnectTransferReservationRecord, ConnectTransferError> {
        (**self).record_provider(workflow_id, provider, state, now)
    }
    fn set_state(
        &self,
        workflow_id: &str,
        state: ConnectTransferReservationState,
        now: u64,
    ) -> Result<ConnectTransferReservationRecord, ConnectTransferError> {
        (**self).set_state(workflow_id, state, now)
    }
}

#[derive(Default, Deserialize, Serialize)]
struct StoreData {
    records: HashMap<String, ConnectTransferReservationRecord>,
}

fn snapshot(data: &StoreData) -> Result<ConnectTransferAggregateSnapshot, ConnectTransferError> {
    let mut held: BTreeMap<String, u64> = BTreeMap::new();
    for record in data
        .records
        .values()
        .filter(|record| record.state.holds_capacity())
    {
        for reservation in &record.reservations {
            let current = held
                .get(&reservation.reservation_id)
                .copied()
                .unwrap_or_default();
            held.insert(
                reservation.reservation_id.clone(),
                current
                    .checked_add(reservation.amount_minor)
                    .ok_or(ConnectTransferError::Arithmetic)?,
            );
        }
    }
    Ok(ConnectTransferAggregateSnapshot {
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
    reservations: &[ConnectTransferReservationIntent],
    now: u64,
) -> Result<ReserveConnectTransferResult, ConnectTransferError> {
    if let Some(existing) = data.records.get(workflow_id) {
        return Ok(if existing.action_digest == *action_digest {
            ReserveConnectTransferResult::Replay(existing.clone())
        } else {
            ReserveConnectTransferResult::Conflict(existing.clone())
        });
    }
    let current = snapshot(data)?;
    for reservation in reservations {
        let held = current
            .held_minor_by_reservation
            .get(&reservation.reservation_id)
            .copied()
            .unwrap_or_default();
        if held
            .checked_add(reservation.amount_minor)
            .is_none_or(|after| after > reservation.limit_minor)
        {
            return Ok(ReserveConnectTransferResult::CapacityExceeded);
        }
    }
    let record = ConnectTransferReservationRecord {
        workflow_id: workflow_id.into(),
        action_digest: action_digest.clone(),
        policy_digest: policy_digest.clone(),
        decision_receipt_digest: decision_receipt_digest.clone(),
        amount_minor,
        currency: currency.clone(),
        reservations: reservations.to_vec(),
        state: ConnectTransferReservationState::Reserved,
        provider: None,
        updated_at: now,
    };
    data.records.insert(workflow_id.into(), record.clone());
    Ok(ReserveConnectTransferResult::Reserved(record))
}

fn update(
    data: &mut StoreData,
    workflow_id: &str,
    provider: Option<ConnectTransferProviderProjection>,
    state: ConnectTransferReservationState,
    now: u64,
) -> Result<ConnectTransferReservationRecord, ConnectTransferError> {
    let record = data
        .records
        .get_mut(workflow_id)
        .ok_or(ConnectTransferError::NotFound)?;
    record.state = state;
    if let Some(value) = provider {
        record.provider = Some(value);
    }
    record.updated_at = now;
    Ok(record.clone())
}

/// In-memory atomic transfer store.
#[derive(Default)]
pub struct InMemoryConnectTransferReservationStore {
    data: Mutex<StoreData>,
}

impl InMemoryConnectTransferReservationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ConnectTransferReservationStore for InMemoryConnectTransferReservationStore {
    fn snapshot(&self) -> Result<ConnectTransferAggregateSnapshot, ConnectTransferError> {
        let data = self
            .data
            .lock()
            .map_err(|_| ConnectTransferError::Persistence)?;
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
        reservations: &[ConnectTransferReservationIntent],
        now: u64,
    ) -> Result<ReserveConnectTransferResult, ConnectTransferError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| ConnectTransferError::Persistence)?;
        reserve(
            &mut data,
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
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<ConnectTransferReservationRecord>, ConnectTransferError> {
        Ok(self
            .data
            .lock()
            .map_err(|_| ConnectTransferError::Persistence)?
            .records
            .get(workflow_id)
            .cloned())
    }
    fn record_provider(
        &self,
        workflow_id: &str,
        provider: ConnectTransferProviderProjection,
        state: ConnectTransferReservationState,
        now: u64,
    ) -> Result<ConnectTransferReservationRecord, ConnectTransferError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| ConnectTransferError::Persistence)?;
        update(&mut data, workflow_id, Some(provider), state, now)
    }
    fn set_state(
        &self,
        workflow_id: &str,
        state: ConnectTransferReservationState,
        now: u64,
    ) -> Result<ConnectTransferReservationRecord, ConnectTransferError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| ConnectTransferError::Persistence)?;
        update(&mut data, workflow_id, None, state, now)
    }
}

/// Durable JSON transfer store.
pub struct PersistentConnectTransferReservationStore {
    path: PathBuf,
    data: Mutex<StoreData>,
}

impl PersistentConnectTransferReservationStore {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, ConnectTransferError> {
        let path = path.as_ref().to_path_buf();
        let data = if path.exists() {
            serde_json::from_slice(&fs::read(&path).map_err(|_| ConnectTransferError::Persistence)?)
                .map_err(|_| ConnectTransferError::Persistence)?
        } else {
            StoreData::default()
        };
        Ok(Self {
            path,
            data: Mutex::new(data),
        })
    }

    fn persist(&self, data: &StoreData) -> Result<(), ConnectTransferError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|_| ConnectTransferError::Persistence)?;
        }
        let temporary = self.path.with_extension("tmp");
        fs::write(
            &temporary,
            canonical_json(data).map_err(|_| ConnectTransferError::Canonicalization)?,
        )
        .map_err(|_| ConnectTransferError::Persistence)?;
        fs::rename(temporary, &self.path).map_err(|_| ConnectTransferError::Persistence)
    }
}

impl ConnectTransferReservationStore for PersistentConnectTransferReservationStore {
    fn snapshot(&self) -> Result<ConnectTransferAggregateSnapshot, ConnectTransferError> {
        let data = self
            .data
            .lock()
            .map_err(|_| ConnectTransferError::Persistence)?;
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
        reservations: &[ConnectTransferReservationIntent],
        now: u64,
    ) -> Result<ReserveConnectTransferResult, ConnectTransferError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| ConnectTransferError::Persistence)?;
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
        if matches!(result, ReserveConnectTransferResult::Reserved(_)) {
            self.persist(&data)?;
        }
        Ok(result)
    }
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<ConnectTransferReservationRecord>, ConnectTransferError> {
        Ok(self
            .data
            .lock()
            .map_err(|_| ConnectTransferError::Persistence)?
            .records
            .get(workflow_id)
            .cloned())
    }
    fn record_provider(
        &self,
        workflow_id: &str,
        provider: ConnectTransferProviderProjection,
        state: ConnectTransferReservationState,
        now: u64,
    ) -> Result<ConnectTransferReservationRecord, ConnectTransferError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| ConnectTransferError::Persistence)?;
        let record = update(&mut data, workflow_id, Some(provider), state, now)?;
        self.persist(&data)?;
        Ok(record)
    }
    fn set_state(
        &self,
        workflow_id: &str,
        state: ConnectTransferReservationState,
        now: u64,
    ) -> Result<ConnectTransferReservationRecord, ConnectTransferError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| ConnectTransferError::Persistence)?;
        let record = update(&mut data, workflow_id, None, state, now)?;
        self.persist(&data)?;
        Ok(record)
    }
}

/// Closed transfer failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConnectTransferError {
    #[error("invalid Connect transfer policy")]
    InvalidPolicy,
    #[error("invalid Connect transfer configuration")]
    InvalidConfiguration,
    #[error("invalid Connect transfer action")]
    InvalidAction,
    #[error("invalid Connect transfer evidence")]
    InvalidEvidence,
    #[error("Connect transfer canonicalization failed")]
    Canonicalization,
    #[error("Connect transfer arithmetic failed")]
    Arithmetic,
    #[error("Connect transfer record not found")]
    NotFound,
    #[error("Connect transfer persistence failed")]
    Persistence,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;
    use crate::canonical;

    fn reservation(limit_minor: u64) -> ConnectTransferReservationIntent {
        ConnectTransferReservationIntent {
            reservation_id: "destination:acct_concurrent".into(),
            currency: Currency::parse("usd").unwrap(),
            amount_minor: limit_minor,
            limit_minor,
        }
    }

    #[test]
    fn atomic_reservation_allows_only_one_last_capacity_winner() {
        let store = Arc::new(InMemoryConnectTransferReservationStore::new());
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
                        &[reservation(500)],
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
                .filter(|result| matches!(result, ReserveConnectTransferResult::Reserved(_)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, ReserveConnectTransferResult::CapacityExceeded))
                .count(),
            1
        );
    }

    #[test]
    fn outcome_unknown_holds_capacity_and_release_returns_it() {
        let store = InMemoryConnectTransferReservationStore::new();
        let currency = Currency::parse("usd").unwrap();
        let intent = reservation(500);
        let digest = canonical::sha256(b"same");
        let reserved = store
            .reserve(
                "workflow-one",
                &digest,
                &digest,
                &digest,
                500,
                &currency,
                std::slice::from_ref(&intent),
                1,
            )
            .unwrap();
        assert!(matches!(
            reserved,
            ReserveConnectTransferResult::Reserved(_)
        ));
        store
            .set_state(
                "workflow-one",
                ConnectTransferReservationState::OutcomeUnknown,
                2,
            )
            .unwrap();
        assert_eq!(
            store
                .snapshot()
                .unwrap()
                .held_minor_by_reservation
                .get(&intent.reservation_id),
            Some(&500)
        );
        store
            .set_state("workflow-one", ConnectTransferReservationState::Released, 3)
            .unwrap();
        assert_eq!(
            store
                .snapshot()
                .unwrap()
                .held_minor_by_reservation
                .get(&intent.reservation_id),
            None
        );
    }

    #[test]
    fn persistent_restart_preserves_replay_and_unknown_capacity() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("connect-transfer-state.json");
        let currency = Currency::parse("usd").unwrap();
        let digest = canonical::sha256(b"persistent");
        {
            let store = PersistentConnectTransferReservationStore::new(&path).unwrap();
            store
                .reserve(
                    "workflow-persistent",
                    &digest,
                    &digest,
                    &digest,
                    500,
                    &currency,
                    &[reservation(500)],
                    1,
                )
                .unwrap();
            store
                .set_state(
                    "workflow-persistent",
                    ConnectTransferReservationState::OutcomeUnknown,
                    2,
                )
                .unwrap();
        }
        let reopened = PersistentConnectTransferReservationStore::new(&path).unwrap();
        assert_eq!(
            reopened
                .get("workflow-persistent")
                .unwrap()
                .unwrap()
                .state(),
            ConnectTransferReservationState::OutcomeUnknown
        );
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .held_minor_by_reservation
                .get("destination:acct_concurrent"),
            Some(&500)
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
                    &[reservation(500)],
                    3,
                )
                .unwrap(),
            ReserveConnectTransferResult::Replay(_)
        ));
    }

    #[test]
    fn duplicate_budget_ids_across_scopes_are_invalid() {
        let platform = StripeAccountId::parse("acct_platform").unwrap();
        let destination = StripeAccountId::parse("acct_destination").unwrap();
        let source = ChargeId::parse("ch_sourcefixture").unwrap();
        let currency = Currency::parse("usd").unwrap();
        let result =
            StripeBoundedConnectTransferPolicyV1::new(StripeBoundedConnectTransferPolicyInput {
                policy_id: "duplicate-budget-policy".into(),
                valid_from: 1,
                expires_at: 100,
                allowed_test_platform_account_ids: vec![platform],
                allowed_destination_connected_account_ids: vec![destination.clone()],
                allowed_source_charge_ids: vec![source],
                allowed_transfer_groups: vec!["group".into()],
                allowed_currencies: vec![currency.clone()],
                allowed_business_scopes: vec!["scope".into()],
                per_transfer_minor_by_currency: BTreeMap::from([(currency.clone(), 100)]),
                per_destination_minor_by_currency: BTreeMap::from([(currency.clone(), 100)]),
                per_source_charge_basis_points: 10_000,
                aggregate_budgets: vec![
                    AggregateConnectTransferBudget {
                        budget_id: "same-id".into(),
                        scope: ConnectTransferBudgetScope::Global,
                        currency: currency.clone(),
                        limit_minor: 100,
                        starts_at: 1,
                        ends_at: 100,
                    },
                    AggregateConnectTransferBudget {
                        budget_id: "same-id".into(),
                        scope: ConnectTransferBudgetScope::Destination(destination),
                        currency,
                        limit_minor: 100,
                        starts_at: 1,
                        ends_at: 100,
                    },
                ],
                maximum_source_evidence_age_seconds: 60,
                maximum_action_lifetime_seconds: 60,
                allowed_api_versions: vec!["2025-04-30.basil".into()],
            });
        assert!(matches!(result, Err(ConnectTransferError::InvalidPolicy)));
    }
}
