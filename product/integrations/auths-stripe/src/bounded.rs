//! Stripe-local immutable bounded-refund policy and pure evaluator.
//!
//! This module deliberately does not define a reusable policy language. Its
//! closed values and decisions are specific to Stripe refund semantics.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use crate::{
    canonical::{CanonicalError, canonical_digest},
    decision::{DecisionClass, EvaluationContext, evaluate},
    types::{
        ChargeId, Currency, DigestHex, ExactRefundActionV1, PaymentIntentId, RefundEvidenceV1,
        StripeAccountId, StripeVerifierConfiguration,
    },
};

/// Immutable configured-policy type.
pub const BOUNDED_POLICY_TYPE: &str = "auths.stripe.bounded-refund-policy";
/// Initial configured-policy version.
pub const BOUNDED_POLICY_VERSION: u16 = 1;
/// Canonical policy encoding and digest semantics.
pub const BOUNDED_CANONICALIZATION: &str = "rfc8785-sha256-v1";
/// Immutable evaluator semantic identifier.
pub const BOUNDED_EVALUATOR_ID: &str = "auths.stripe.bounded-refund-evaluator";
/// Immutable evaluator semantic version.
pub const BOUNDED_EVALUATOR_VERSION: u16 = 1;
/// Exact provider action evaluated by this policy.
pub const EXACT_REFUND_PROFILE: &str = "auths.stripe.exact-refund/1";
/// Provenance until the protocol carries a signer-authorized commitment.
pub const CONFIGURED_POLICY_PROVENANCE: &str = "executor-local-trusted-configuration";
const MAX_POLICY_ITEMS: u16 = 64;
const MAX_AGGREGATE_BUDGETS: usize = 8;
const MAX_POLICY_LIFETIME_SECONDS: u64 = 366 * 24 * 60 * 60;
const MAX_WINDOW_SECONDS: u64 = 31 * 24 * 60 * 60;

/// Explicit evidence denominator for a basis-point limit.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefundDenominator {
    /// Original Charge amount.
    OriginalChargeAmount,
    /// Amount Stripe reports as captured.
    CapturedAmount,
    /// Remaining amount refundable when evidence was observed.
    RemainingRefundableAmount,
}

/// Explicit integer rounding rule.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefundRounding {
    /// Integer division rounds toward zero, which is floor for positive money.
    FloorMinorUnit,
}

/// Evidence-relative refund ceiling.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelativeRefundLimit {
    basis_points: u16,
    denominator: RefundDenominator,
    rounding: RefundRounding,
}

impl RelativeRefundLimit {
    /// Builds one inclusive basis-point ceiling.
    ///
    /// # Errors
    ///
    /// Rejects zero or more than 100 percent.
    pub const fn new(
        basis_points: u16,
        denominator: RefundDenominator,
    ) -> Result<Self, BoundedValidationError> {
        if basis_points == 0 || basis_points > 10_000 {
            return Err(BoundedValidationError::InvalidPolicy);
        }
        Ok(Self {
            basis_points,
            denominator,
            rounding: RefundRounding::FloorMinorUnit,
        })
    }

    /// Integer basis points.
    #[must_use]
    pub const fn basis_points(&self) -> u16 {
        self.basis_points
    }

    /// Selected evidence denominator.
    #[must_use]
    pub const fn denominator(&self) -> RefundDenominator {
        self.denominator
    }

    /// Explicit rounding.
    #[must_use]
    pub const fn rounding(&self) -> RefundRounding {
        self.rounding
    }
}

/// Stripe Connect account restriction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ConnectScope {
    /// Only a direct/platform account with no connected-account context.
    PlatformOnly,
    /// Only the listed connected accounts.
    ConnectedAccounts {
        /// Sorted, unique connected accounts.
        account_ids: Vec<StripeAccountId>,
    },
}

impl ConnectScope {
    fn validate(&self) -> Result<(), BoundedValidationError> {
        match self {
            Self::PlatformOnly => Ok(()),
            Self::ConnectedAccounts { account_ids }
                if !account_ids.is_empty()
                    && account_ids.len() <= usize::from(MAX_POLICY_ITEMS)
                    && is_sorted_unique(account_ids) =>
            {
                Ok(())
            }
            Self::ConnectedAccounts { .. } => Err(BoundedValidationError::InvalidPolicy),
        }
    }

    fn allows(&self, account: Option<&StripeAccountId>) -> bool {
        match (self, account) {
            (Self::PlatformOnly, None) => true,
            (Self::ConnectedAccounts { account_ids }, Some(account)) => {
                account_ids.binary_search(account).is_ok()
            }
            _ => false,
        }
    }
}

/// Explicit aggregate-budget window.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RefundBudgetWindow {
    /// Fixed inclusive-start, exclusive-end window.
    Fixed {
        /// Window start.
        starts_at: u64,
        /// Window end.
        ends_at: u64,
    },
    /// Sliding window ending at the explicit evaluation time.
    Rolling {
        /// Window duration.
        duration_seconds: u64,
    },
}

impl RefundBudgetWindow {
    fn validate(&self) -> Result<(), BoundedValidationError> {
        match self {
            Self::Fixed { starts_at, ends_at }
                if *starts_at < *ends_at
                    && ends_at.saturating_sub(*starts_at) <= MAX_WINDOW_SECONDS =>
            {
                Ok(())
            }
            Self::Rolling { duration_seconds }
                if (1..=MAX_WINDOW_SECONDS).contains(duration_seconds) =>
            {
                Ok(())
            }
            _ => Err(BoundedValidationError::InvalidPolicy),
        }
    }

    /// Resolves the exact applicable window for explicit verifier time.
    ///
    /// # Errors
    ///
    /// Returns an expiry denial when a fixed window is inactive.
    pub fn identity(&self, now: u64) -> Result<RefundWindowIdentity, BoundedDecisionCode> {
        match self {
            Self::Fixed { starts_at, ends_at } if (*starts_at..*ends_at).contains(&now) => {
                Ok(RefundWindowIdentity {
                    starts_at: *starts_at,
                    ends_at: *ends_at,
                    kind: "fixed".into(),
                })
            }
            Self::Fixed { .. } => Err(BoundedDecisionCode::PolicyExpired),
            Self::Rolling { duration_seconds } if *duration_seconds > 0 => {
                // Timestamps are whole-second buckets. This half-open identity
                // contains exactly `duration_seconds` buckets ending at `now`.
                let starts_at = now.saturating_sub(duration_seconds.saturating_sub(1));
                let ends_at = now
                    .checked_add(1)
                    .ok_or(BoundedDecisionCode::ArithmeticOverflow)?;
                Ok(RefundWindowIdentity {
                    starts_at,
                    ends_at,
                    kind: "rolling".into(),
                })
            }
            Self::Rolling { .. } => Err(BoundedDecisionCode::PolicyInvalid),
        }
    }
}

/// One aggregate refund budget.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateRefundBudget {
    budget_id: String,
    currency: Currency,
    limit_minor: u64,
    window: RefundBudgetWindow,
}

impl AggregateRefundBudget {
    /// Builds one currency-specific budget.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers, money, or windows.
    pub fn new(
        budget_id: impl Into<String>,
        currency: Currency,
        limit_minor: u64,
        window: RefundBudgetWindow,
    ) -> Result<Self, BoundedValidationError> {
        let value = Self {
            budget_id: budget_id.into(),
            currency,
            limit_minor,
            window,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), BoundedValidationError> {
        if !valid_local_id(&self.budget_id)
            || self.limit_minor == 0
            || self.limit_minor > i64::MAX as u64
        {
            return Err(BoundedValidationError::InvalidPolicy);
        }
        self.window.validate()
    }

    /// Stable budget identifier.
    #[must_use]
    pub fn budget_id(&self) -> &str {
        &self.budget_id
    }

    /// Budget currency.
    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    /// Capacity in minor units.
    #[must_use]
    pub const fn limit_minor(&self) -> u64 {
        self.limit_minor
    }

    /// Explicit window rule.
    #[must_use]
    pub const fn window(&self) -> &RefundBudgetWindow {
        &self.window
    }
}

/// Closed immutable Stripe refund policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeBoundedRefundPolicyV1 {
    policy_type: String,
    policy_version: u16,
    canonicalization: String,
    evaluator_semantic_id: String,
    evaluator_semantic_version: u16,
    policy_id: String,
    valid_from: u64,
    expires_at: u64,
    allowed_test_account_ids: Vec<StripeAccountId>,
    allowed_currencies: Vec<Currency>,
    allowed_reasons: Vec<String>,
    allowed_charge_ids: Vec<ChargeId>,
    allowed_payment_intent_ids: Vec<PaymentIntentId>,
    allowed_api_versions: Vec<String>,
    connect_scope: ConnectScope,
    maximum_evidence_age_seconds: u64,
    per_refund_absolute_minor_by_currency: std::collections::BTreeMap<Currency, u64>,
    relative_limit: RelativeRefundLimit,
    aggregate_budgets: Vec<AggregateRefundBudget>,
}

/// Inputs whose fixed identity fields are supplied by the implementation.
pub struct StripeBoundedRefundPolicyInput {
    /// Stable local display identifier.
    pub policy_id: String,
    /// Inclusive validity start.
    pub valid_from: u64,
    /// Inclusive policy expiry.
    pub expires_at: u64,
    /// Allowed Stripe test accounts.
    pub allowed_test_account_ids: Vec<StripeAccountId>,
    /// Allowed currencies.
    pub allowed_currencies: Vec<Currency>,
    /// Allowed refund reasons.
    pub allowed_reasons: Vec<String>,
    /// Allowed Charges.
    pub allowed_charge_ids: Vec<ChargeId>,
    /// Allowed `PaymentIntents`.
    pub allowed_payment_intent_ids: Vec<PaymentIntentId>,
    /// Allowed pinned Stripe API versions.
    pub allowed_api_versions: Vec<String>,
    /// Exact Connect restriction.
    pub connect_scope: ConnectScope,
    /// Freshness ceiling.
    pub maximum_evidence_age_seconds: u64,
    /// Per-refund absolute limits.
    pub per_refund_absolute_minor_by_currency: std::collections::BTreeMap<Currency, u64>,
    /// Evidence-relative limit.
    pub relative_limit: RelativeRefundLimit,
    /// Aggregate budgets.
    pub aggregate_budgets: Vec<AggregateRefundBudget>,
}

impl StripeBoundedRefundPolicyV1 {
    /// Builds a canonical, immutable configured policy.
    ///
    /// # Errors
    ///
    /// Rejects missing, duplicate, unbounded, or contradictory constraints.
    pub fn new(mut input: StripeBoundedRefundPolicyInput) -> Result<Self, BoundedValidationError> {
        input.allowed_test_account_ids.sort();
        input.allowed_currencies.sort();
        input.allowed_reasons.sort();
        input.allowed_charge_ids.sort();
        input.allowed_payment_intent_ids.sort();
        input.allowed_api_versions.sort();
        input
            .aggregate_budgets
            .sort_by(|left, right| left.budget_id.cmp(&right.budget_id));
        let value = Self {
            policy_type: BOUNDED_POLICY_TYPE.into(),
            policy_version: BOUNDED_POLICY_VERSION,
            canonicalization: BOUNDED_CANONICALIZATION.into(),
            evaluator_semantic_id: BOUNDED_EVALUATOR_ID.into(),
            evaluator_semantic_version: BOUNDED_EVALUATOR_VERSION,
            policy_id: input.policy_id,
            valid_from: input.valid_from,
            expires_at: input.expires_at,
            allowed_test_account_ids: input.allowed_test_account_ids,
            allowed_currencies: input.allowed_currencies,
            allowed_reasons: input.allowed_reasons,
            allowed_charge_ids: input.allowed_charge_ids,
            allowed_payment_intent_ids: input.allowed_payment_intent_ids,
            allowed_api_versions: input.allowed_api_versions,
            connect_scope: input.connect_scope,
            maximum_evidence_age_seconds: input.maximum_evidence_age_seconds,
            per_refund_absolute_minor_by_currency: input.per_refund_absolute_minor_by_currency,
            relative_limit: input.relative_limit,
            aggregate_budgets: input.aggregate_budgets,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates a decoded policy without applying defaults.
    ///
    /// # Errors
    ///
    /// Rejects every value outside V1 semantics.
    pub fn validate(&self) -> Result<(), BoundedValidationError> {
        let sorted_budgets = self
            .aggregate_budgets
            .windows(2)
            .all(|pair| pair[0].budget_id < pair[1].budget_id);
        if self.policy_type != BOUNDED_POLICY_TYPE
            || self.policy_version != BOUNDED_POLICY_VERSION
            || self.canonicalization != BOUNDED_CANONICALIZATION
            || self.evaluator_semantic_id != BOUNDED_EVALUATOR_ID
            || self.evaluator_semantic_version != BOUNDED_EVALUATOR_VERSION
            || !valid_local_id(&self.policy_id)
            || self.valid_from >= self.expires_at
            || self.expires_at.saturating_sub(self.valid_from) > MAX_POLICY_LIFETIME_SECONDS
            || !valid_nonempty_sorted(&self.allowed_test_account_ids)
            || !valid_nonempty_sorted(&self.allowed_currencies)
            || !valid_nonempty_sorted(&self.allowed_reasons)
            || !valid_nonempty_sorted(&self.allowed_charge_ids)
            || !valid_nonempty_sorted(&self.allowed_payment_intent_ids)
            || !valid_nonempty_sorted(&self.allowed_api_versions)
            || self
                .allowed_reasons
                .iter()
                .any(|reason| !valid_reason(reason))
            || self
                .allowed_api_versions
                .iter()
                .any(|version| !valid_api_version(version))
            || self.maximum_evidence_age_seconds == 0
            || self.maximum_evidence_age_seconds > 15 * 60
            || self.per_refund_absolute_minor_by_currency.len() != self.allowed_currencies.len()
            || self.allowed_currencies.iter().any(|currency| {
                !matches!(
                    self.per_refund_absolute_minor_by_currency.get(currency),
                    Some(1..=9_999_999_999)
                )
            })
            || self.relative_limit.basis_points == 0
            || self.relative_limit.basis_points > 10_000
            || self.aggregate_budgets.is_empty()
            || self.aggregate_budgets.len() > MAX_AGGREGATE_BUDGETS
            || !sorted_budgets
            || self
                .aggregate_budgets
                .iter()
                .any(|budget| budget.validate().is_err())
        {
            return Err(BoundedValidationError::InvalidPolicy);
        }
        self.connect_scope.validate()
    }

    /// Canonical policy identity digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Stable display identifier.
    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Policy type.
    #[must_use]
    pub fn policy_type(&self) -> &str {
        &self.policy_type
    }

    /// Policy version.
    #[must_use]
    pub const fn policy_version(&self) -> u16 {
        self.policy_version
    }

    /// Canonicalization semantics.
    #[must_use]
    pub fn canonicalization(&self) -> &str {
        &self.canonicalization
    }

    /// Evaluator semantic identifier.
    #[must_use]
    pub fn evaluator_semantic_id(&self) -> &str {
        &self.evaluator_semantic_id
    }

    /// Evaluator semantic version.
    #[must_use]
    pub const fn evaluator_semantic_version(&self) -> u16 {
        self.evaluator_semantic_version
    }

    /// Inclusive start.
    #[must_use]
    pub const fn valid_from(&self) -> u64 {
        self.valid_from
    }

    /// Inclusive expiry.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Relative ceiling.
    #[must_use]
    pub const fn relative_limit(&self) -> &RelativeRefundLimit {
        &self.relative_limit
    }

    /// Aggregate budgets.
    #[must_use]
    pub fn aggregate_budgets(&self) -> &[AggregateRefundBudget] {
        &self.aggregate_budgets
    }

    /// Absolute ceiling for a currency.
    #[must_use]
    pub fn absolute_limit_minor(&self, currency: &Currency) -> Option<u64> {
        self.per_refund_absolute_minor_by_currency
            .get(currency)
            .copied()
    }

    /// Freshness ceiling.
    #[must_use]
    pub const fn maximum_evidence_age_seconds(&self) -> u64 {
        self.maximum_evidence_age_seconds
    }
}

/// Required/executed bounded evaluator configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeBoundedEvaluatorConfigurationV1 {
    schema: String,
    policy_digest: DigestHex,
    policy_type: String,
    policy_version: u16,
    canonicalization: String,
    evaluator_semantic_id: String,
    evaluator_semantic_version: u16,
    evaluator_implementation_id: String,
    exact_action_profile: String,
    reservation_schema: String,
    receipt_schema: String,
    executor_audience: String,
    maximum_policy_items: u16,
    maximum_evaluator_work: u32,
}

impl StripeBoundedEvaluatorConfigurationV1 {
    /// Builds the exact configuration for one immutable configured policy.
    ///
    /// # Errors
    ///
    /// Rejects malformed implementation or audience identifiers.
    pub fn for_policy(
        policy: &StripeBoundedRefundPolicyV1,
        evaluator_implementation_id: impl Into<String>,
        executor_audience: impl Into<String>,
    ) -> Result<Self, BoundedValidationError> {
        let value = Self {
            schema: "auths.stripe.bounded-evaluator-configuration/1".into(),
            policy_digest: policy
                .digest()
                .map_err(|_| BoundedValidationError::Canonicalization)?,
            policy_type: BOUNDED_POLICY_TYPE.into(),
            policy_version: BOUNDED_POLICY_VERSION,
            canonicalization: BOUNDED_CANONICALIZATION.into(),
            evaluator_semantic_id: BOUNDED_EVALUATOR_ID.into(),
            evaluator_semantic_version: BOUNDED_EVALUATOR_VERSION,
            evaluator_implementation_id: evaluator_implementation_id.into(),
            exact_action_profile: EXACT_REFUND_PROFILE.into(),
            reservation_schema: "auths.stripe.bounded-reservation/1".into(),
            receipt_schema: "auths.stripe.bounded-receipt/1".into(),
            executor_audience: executor_audience.into(),
            maximum_policy_items: MAX_POLICY_ITEMS,
            maximum_evaluator_work: 1_024,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates exact V1 semantics.
    ///
    /// # Errors
    ///
    /// Rejects unknown identities or unsafe limits.
    pub fn validate(&self) -> Result<(), BoundedValidationError> {
        if self.schema != "auths.stripe.bounded-evaluator-configuration/1"
            || self.policy_type != BOUNDED_POLICY_TYPE
            || self.policy_version != BOUNDED_POLICY_VERSION
            || self.canonicalization != BOUNDED_CANONICALIZATION
            || self.evaluator_semantic_id != BOUNDED_EVALUATOR_ID
            || self.evaluator_semantic_version != BOUNDED_EVALUATOR_VERSION
            || self.exact_action_profile != EXACT_REFUND_PROFILE
            || self.reservation_schema != "auths.stripe.bounded-reservation/1"
            || self.receipt_schema != "auths.stripe.bounded-receipt/1"
            || !valid_local_id(&self.evaluator_implementation_id)
            || auths_model::Audience::parse(&self.executor_audience).is_err()
            || self.maximum_policy_items != MAX_POLICY_ITEMS
            || self.maximum_evaluator_work != 1_024
        {
            return Err(BoundedValidationError::InvalidConfiguration);
        }
        Ok(())
    }

    /// Canonical configuration digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Configured policy commitment.
    #[must_use]
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }

    /// Evaluator semantic identifier.
    #[must_use]
    pub fn evaluator_semantic_id(&self) -> &str {
        &self.evaluator_semantic_id
    }

    /// Evaluator semantic version.
    #[must_use]
    pub const fn evaluator_semantic_version(&self) -> u16 {
        self.evaluator_semantic_version
    }

    /// Executed implementation/build identity.
    #[must_use]
    pub fn evaluator_implementation_id(&self) -> &str {
        &self.evaluator_implementation_id
    }

    /// Executor audience.
    #[must_use]
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
}

/// Exact resolved budget-window identity.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefundWindowIdentity {
    /// Inclusive start.
    pub starts_at: u64,
    /// Exclusive end.
    pub ends_at: u64,
    /// `fixed` or `rolling`.
    pub kind: String,
}

/// One aggregate state counter at an exact window.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateBudgetUsage {
    /// Policy budget ID.
    pub budget_id: String,
    /// Resolved window.
    pub window: RefundWindowIdentity,
    /// Already committed usage.
    pub committed_minor: u64,
    /// Live reserved usage.
    pub reserved_minor: u64,
    /// Usage held while provider outcome is unknown.
    pub outcome_unknown_minor: u64,
}

/// Explicit immutable view read by the pure evaluator.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateBudgetSnapshot {
    /// Exact counters, sorted by budget ID.
    pub usages: Vec<AggregateBudgetUsage>,
}

/// Reservation requested by an eligible decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefundReservationIntent {
    /// Budget identifier.
    pub budget_id: String,
    /// Currency.
    pub currency: Currency,
    /// Resolved window.
    pub window: RefundWindowIdentity,
    /// Capacity ceiling.
    pub limit_minor: u64,
    /// Exact requested capacity.
    pub amount_minor: u64,
    /// Available capacity in the evaluated snapshot.
    pub available_before_minor: u64,
}

/// Reproducible arithmetic and reservation result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedRefundEligibility {
    /// Absolute per-refund ceiling.
    pub absolute_ceiling_minor: u64,
    /// Selected evidence denominator.
    pub denominator: RefundDenominator,
    /// Exact denominator amount.
    pub denominator_minor: u64,
    /// Integer basis points.
    pub basis_points: u16,
    /// Explicit rounding.
    pub rounding: RefundRounding,
    /// Computed evidence-relative ceiling.
    pub relative_ceiling_minor: u64,
    /// Minimum of absolute, relative, and remaining refundable ceilings.
    pub effective_ceiling_minor: u64,
    /// Aggregate capacity intents.
    pub reservations: Vec<RefundReservationIntent>,
}

/// Stable decision class for the bounded layer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundedDecisionClass {
    /// Exact action is eligible for durable reservation.
    Eligible,
    /// Complete facts establish denial.
    Denied,
    /// Required trustworthy evidence is unavailable.
    Indeterminate,
}

/// Stable bounded-refund decision stage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundedDecisionStage {
    /// Policy/configuration identity.
    Configuration,
    /// Validity and freshness.
    Time,
    /// Stripe context and resources.
    StripeContext,
    /// Exact-action/evidence binding.
    Evidence,
    /// Checked per-refund arithmetic.
    PerRefundLimit,
    /// Aggregate state snapshot.
    AggregateBudget,
    /// All pure checks passed.
    Eligible,
}

/// Stable bounded-refund code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundedDecisionCode {
    /// Pure eligibility succeeded.
    Authorized,
    /// Policy bytes or invariants are invalid.
    PolicyInvalid,
    /// Policy digest differs from configured identity or action metadata.
    PolicyDigestMismatch,
    /// Evaluator semantic identity differs.
    EvaluatorMismatch,
    /// Required/executed bounded configurations differ.
    ConfigurationMismatch,
    /// Policy is not active yet.
    PolicyNotYetValid,
    /// Policy or fixed budget window expired.
    PolicyExpired,
    /// Stripe account is outside the configured policy.
    AccountDenied,
    /// API version is outside policy.
    ApiVersionDenied,
    /// Test mode is required.
    TestModeRequired,
    /// Connect context is outside policy.
    ConnectContextDenied,
    /// Charge is outside policy.
    ChargeDenied,
    /// `PaymentIntent` is outside policy.
    PaymentIntentDenied,
    /// Currency is outside policy.
    CurrencyDenied,
    /// Reason is outside policy.
    ReasonDenied,
    /// Evidence is stale or future-dated.
    EvidenceStale,
    /// Exact refund action does not match evidence or exact-refund policy.
    EvidenceMismatch,
    /// Absolute per-refund ceiling exceeded.
    AbsoluteLimitExceeded,
    /// Evidence-relative ceiling exceeded.
    RelativeLimitExceeded,
    /// Aggregate capacity is insufficient.
    AggregateBudgetExceeded,
    /// Checked integer arithmetic failed.
    ArithmeticOverflow,
}

/// Pure bounded evaluator result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedRefundDecision {
    /// Decision class.
    pub class: BoundedDecisionClass,
    /// Stable code.
    pub code: BoundedDecisionCode,
    /// Stable stage.
    pub stage: BoundedDecisionStage,
    /// Factual non-sensitive detail.
    pub detail: String,
    /// Reproducible calculation on eligibility.
    pub eligibility: Option<BoundedRefundEligibility>,
}

impl BoundedRefundDecision {
    fn denied(
        code: BoundedDecisionCode,
        stage: BoundedDecisionStage,
        detail: &'static str,
    ) -> Self {
        Self {
            class: BoundedDecisionClass::Denied,
            code,
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }

    fn indeterminate(
        code: BoundedDecisionCode,
        stage: BoundedDecisionStage,
        detail: &'static str,
    ) -> Self {
        Self {
            class: BoundedDecisionClass::Indeterminate,
            code,
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
}

/// Explicit inputs to the pure Stripe-local evaluator.
pub struct BoundedEvaluationContext<'a> {
    /// Immutable configured policy.
    pub policy: &'a StripeBoundedRefundPolicyV1,
    /// Agent-selected exact provider action.
    pub action: &'a ExactRefundActionV1,
    /// Fresh Stripe evidence.
    pub evidence: &'a RefundEvidenceV1,
    /// Advisory aggregate snapshot.
    pub aggregate_snapshot: &'a AggregateBudgetSnapshot,
    /// Exact-refund verifier configuration demanded by the action.
    pub required_exact_configuration: &'a StripeVerifierConfiguration,
    /// Exact-refund verifier configuration loaded by the executor.
    pub executed_exact_configuration: &'a StripeVerifierConfiguration,
    /// Required bounded evaluator configuration.
    pub required_bounded_configuration: &'a StripeBoundedEvaluatorConfigurationV1,
    /// Executed bounded evaluator configuration.
    pub executed_bounded_configuration: &'a StripeBoundedEvaluatorConfigurationV1,
    /// Exact executor audience.
    pub request_audience: &'a str,
    /// Explicit trusted time.
    pub now: u64,
}

/// Evaluates an exact refund inside an immutable configured Stripe policy.
#[must_use]
pub fn evaluate_bounded_refund(context: &BoundedEvaluationContext<'_>) -> BoundedRefundDecision {
    if let Err(decision) = check_bounded_configuration(context) {
        return decision;
    }
    if let Err(decision) = check_policy_time(context) {
        return decision;
    }
    if let Err(decision) = check_policy_context(context) {
        return decision;
    }
    if let Err(decision) = check_exact_and_evidence(context) {
        return decision;
    }
    let limits = match calculate_limits(context) {
        Ok(limits) => limits,
        Err(decision) => return decision,
    };
    let reservations = match calculate_reservations(context) {
        Ok(reservations) => reservations,
        Err(decision) => return decision,
    };
    BoundedRefundDecision {
        class: BoundedDecisionClass::Eligible,
        code: BoundedDecisionCode::Authorized,
        stage: BoundedDecisionStage::Eligible,
        detail: "the exact refund is eligible under the immutable configured Stripe policy".into(),
        eligibility: Some(BoundedRefundEligibility {
            reservations,
            ..limits
        }),
    }
}

fn check_bounded_configuration(
    context: &BoundedEvaluationContext<'_>,
) -> Result<(), BoundedRefundDecision> {
    if context.policy.validate().is_err()
        || context.required_bounded_configuration.validate().is_err()
        || context.executed_bounded_configuration.validate().is_err()
    {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::PolicyInvalid,
            BoundedDecisionStage::Configuration,
            "the configured policy or evaluator configuration is invalid",
        ));
    }
    if context.required_bounded_configuration != context.executed_bounded_configuration {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::ConfigurationMismatch,
            BoundedDecisionStage::Configuration,
            "required and executed bounded evaluator configurations differ",
        ));
    }
    if context
        .required_bounded_configuration
        .evaluator_semantic_id()
        != context.policy.evaluator_semantic_id()
        || context
            .required_bounded_configuration
            .evaluator_semantic_version()
            != context.policy.evaluator_semantic_version()
    {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::EvaluatorMismatch,
            BoundedDecisionStage::Configuration,
            "the configured evaluator semantic identity differs from policy",
        ));
    }
    let digest = context.policy.digest().map_err(|_| {
        BoundedRefundDecision::denied(
            BoundedDecisionCode::PolicyInvalid,
            BoundedDecisionStage::Configuration,
            "the configured policy is not canonical",
        )
    })?;
    if !digest_eq(
        context.required_bounded_configuration.policy_digest(),
        &digest,
    ) || context.action.metadata().get("auths_policy") != Some(&digest.to_string())
    {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::PolicyDigestMismatch,
            BoundedDecisionStage::Configuration,
            "the policy, configuration, and exact action policy commitments differ",
        ));
    }
    if context.request_audience != context.required_bounded_configuration.executor_audience()
        || context.request_audience != context.action.executor_audience()
    {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::ConfigurationMismatch,
            BoundedDecisionStage::Configuration,
            "the bounded policy addresses a different executor",
        ));
    }
    Ok(())
}

fn check_policy_time(context: &BoundedEvaluationContext<'_>) -> Result<(), BoundedRefundDecision> {
    if context.now < context.policy.valid_from {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::PolicyNotYetValid,
            BoundedDecisionStage::Time,
            "the immutable configured policy is not active yet",
        ));
    }
    if context.now > context.policy.expires_at {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::PolicyExpired,
            BoundedDecisionStage::Time,
            "the immutable configured policy expired",
        ));
    }
    let age = context
        .now
        .checked_sub(context.evidence.observed_at())
        .ok_or_else(|| {
            BoundedRefundDecision::indeterminate(
                BoundedDecisionCode::EvidenceStale,
                BoundedDecisionStage::Time,
                "Stripe evidence is from the future",
            )
        })?;
    if age > context.policy.maximum_evidence_age_seconds {
        return Err(BoundedRefundDecision::indeterminate(
            BoundedDecisionCode::EvidenceStale,
            BoundedDecisionStage::Time,
            "Stripe evidence is older than the configured policy permits",
        ));
    }
    Ok(())
}

fn check_policy_context(
    context: &BoundedEvaluationContext<'_>,
) -> Result<(), BoundedRefundDecision> {
    let policy = context.policy;
    let action = context.action;
    if action.livemode() || context.evidence.livemode() {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::TestModeRequired,
            BoundedDecisionStage::StripeContext,
            "bounded refunds are structurally restricted to Stripe test mode",
        ));
    }
    if policy
        .allowed_test_account_ids
        .binary_search(action.stripe_account_id())
        .is_err()
    {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::AccountDenied,
            BoundedDecisionStage::StripeContext,
            "the Stripe account is outside the configured policy",
        ));
    }
    if policy
        .allowed_api_versions
        .binary_search_by(|version| version.as_str().cmp(action.stripe_api_version()))
        .is_err()
    {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::ApiVersionDenied,
            BoundedDecisionStage::StripeContext,
            "the Stripe API version is outside the configured policy",
        ));
    }
    check_connect_context(context)?;
    if policy
        .allowed_charge_ids
        .binary_search(action.charge_id())
        .is_err()
    {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::ChargeDenied,
            BoundedDecisionStage::StripeContext,
            "the Charge is outside the configured policy",
        ));
    }
    let payment_intent_allowed = action.payment_intent_id().is_some_and(|payment_intent| {
        policy
            .allowed_payment_intent_ids
            .binary_search(payment_intent)
            .is_ok()
    });
    if !payment_intent_allowed {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::PaymentIntentDenied,
            BoundedDecisionStage::StripeContext,
            "the PaymentIntent is outside the configured policy",
        ));
    }
    if policy
        .allowed_currencies
        .binary_search(action.amount().currency())
        .is_err()
    {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::CurrencyDenied,
            BoundedDecisionStage::StripeContext,
            "the refund currency is outside the configured policy",
        ));
    }
    let reason_allowed = action.reason().is_some_and(|reason| {
        policy
            .allowed_reasons
            .binary_search_by(|allowed| allowed.as_str().cmp(reason))
            .is_ok()
    });
    if !reason_allowed {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::ReasonDenied,
            BoundedDecisionStage::StripeContext,
            "the refund reason is outside the configured policy",
        ));
    }
    Ok(())
}

fn check_connect_context(
    context: &BoundedEvaluationContext<'_>,
) -> Result<(), BoundedRefundDecision> {
    if !context
        .policy
        .connect_scope
        .allows(context.evidence.connect_account_id())
    {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::ConnectContextDenied,
            BoundedDecisionStage::StripeContext,
            "the Stripe Connect context is outside the configured policy",
        ));
    }
    let expected_connect_account = context
        .evidence
        .connect_account_id()
        .map_or_else(|| "platform".into(), ToString::to_string);
    if context.action.metadata().get("auths_connect_account") != Some(&expected_connect_account) {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::ConnectContextDenied,
            BoundedDecisionStage::StripeContext,
            "the exact action does not commit to the evidenced Stripe Connect context",
        ));
    }
    Ok(())
}

fn check_exact_and_evidence(
    context: &BoundedEvaluationContext<'_>,
) -> Result<(), BoundedRefundDecision> {
    let exact_decision = evaluate(&EvaluationContext {
        action: context.action,
        evidence: context.evidence,
        required_configuration: context.required_exact_configuration,
        executed_configuration: context.executed_exact_configuration,
        request_audience: context.request_audience,
        now: context.now,
    });
    if exact_decision.class == DecisionClass::Authorized {
        Ok(())
    } else {
        Err(BoundedRefundDecision {
            class: match exact_decision.class {
                DecisionClass::Indeterminate => BoundedDecisionClass::Indeterminate,
                DecisionClass::Authorized | DecisionClass::Denied => BoundedDecisionClass::Denied,
            },
            code: BoundedDecisionCode::EvidenceMismatch,
            stage: BoundedDecisionStage::Evidence,
            detail: exact_decision.detail,
            eligibility: None,
        })
    }
}

fn calculate_limits(
    context: &BoundedEvaluationContext<'_>,
) -> Result<BoundedRefundEligibility, BoundedRefundDecision> {
    let amount = context.action.amount().amount_minor();
    let absolute = context
        .policy
        .absolute_limit_minor(context.action.amount().currency())
        .ok_or_else(|| {
            BoundedRefundDecision::denied(
                BoundedDecisionCode::CurrencyDenied,
                BoundedDecisionStage::PerRefundLimit,
                "the currency has no absolute refund limit",
            )
        })?;
    if amount > absolute {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::AbsoluteLimitExceeded,
            BoundedDecisionStage::PerRefundLimit,
            "the exact refund exceeds the absolute per-refund ceiling",
        ));
    }
    let relative = context.policy.relative_limit();
    let denominator_minor = match relative.denominator() {
        RefundDenominator::OriginalChargeAmount => context.evidence.charge_amount_minor(),
        RefundDenominator::CapturedAmount => context.evidence.captured_amount_minor(),
        RefundDenominator::RemainingRefundableAmount => context.evidence.refundable_amount_minor(),
    };
    let numerator = denominator_minor
        .checked_mul(u64::from(relative.basis_points()))
        .ok_or_else(|| {
            BoundedRefundDecision::denied(
                BoundedDecisionCode::ArithmeticOverflow,
                BoundedDecisionStage::PerRefundLimit,
                "checked basis-point multiplication overflowed",
            )
        })?;
    let relative_ceiling_minor = numerator / 10_000;
    if amount > relative_ceiling_minor {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::RelativeLimitExceeded,
            BoundedDecisionStage::PerRefundLimit,
            "the exact refund exceeds the evidence-relative ceiling",
        ));
    }
    let effective_ceiling_minor = absolute
        .min(relative_ceiling_minor)
        .min(context.evidence.refundable_amount_minor());
    Ok(BoundedRefundEligibility {
        absolute_ceiling_minor: absolute,
        denominator: relative.denominator(),
        denominator_minor,
        basis_points: relative.basis_points(),
        rounding: relative.rounding(),
        relative_ceiling_minor,
        effective_ceiling_minor,
        reservations: Vec::new(),
    })
}

fn calculate_reservations(
    context: &BoundedEvaluationContext<'_>,
) -> Result<Vec<RefundReservationIntent>, BoundedRefundDecision> {
    let amount = context.action.amount().amount_minor();
    let currency = context.action.amount().currency();
    let mut output = Vec::new();
    for budget in context
        .policy
        .aggregate_budgets()
        .iter()
        .filter(|budget| budget.currency() == currency)
    {
        let window = budget.window().identity(context.now).map_err(|code| {
            BoundedRefundDecision::denied(
                code,
                BoundedDecisionStage::AggregateBudget,
                "the aggregate budget window is not active",
            )
        })?;
        let usage = context
            .aggregate_snapshot
            .usages
            .iter()
            .find(|usage| usage.budget_id == budget.budget_id() && usage.window == window);
        let (committed, reserved, unknown) = usage.map_or((0, 0, 0), |usage| {
            (
                usage.committed_minor,
                usage.reserved_minor,
                usage.outcome_unknown_minor,
            )
        });
        let used = committed
            .checked_add(reserved)
            .and_then(|value| value.checked_add(unknown))
            .ok_or_else(|| {
                BoundedRefundDecision::denied(
                    BoundedDecisionCode::ArithmeticOverflow,
                    BoundedDecisionStage::AggregateBudget,
                    "aggregate usage addition overflowed",
                )
            })?;
        let available = budget.limit_minor().checked_sub(used).ok_or_else(|| {
            BoundedRefundDecision::denied(
                BoundedDecisionCode::ArithmeticOverflow,
                BoundedDecisionStage::AggregateBudget,
                "aggregate usage exceeds its configured ceiling",
            )
        })?;
        if amount > available {
            return Err(BoundedRefundDecision::denied(
                BoundedDecisionCode::AggregateBudgetExceeded,
                BoundedDecisionStage::AggregateBudget,
                "the exact refund exceeds currently available aggregate capacity",
            ));
        }
        output.push(RefundReservationIntent {
            budget_id: budget.budget_id().into(),
            currency: currency.clone(),
            window,
            limit_minor: budget.limit_minor(),
            amount_minor: amount,
            available_before_minor: available,
        });
    }
    if output.is_empty() {
        return Err(BoundedRefundDecision::denied(
            BoundedDecisionCode::AggregateBudgetExceeded,
            BoundedDecisionStage::AggregateBudget,
            "no aggregate budget applies to the refund currency",
        ));
    }
    Ok(output)
}

fn digest_eq(left: &DigestHex, right: &DigestHex) -> bool {
    bool::from(left.as_str().as_bytes().ct_eq(right.as_str().as_bytes()))
}

fn valid_nonempty_sorted<T: Ord>(values: &[T]) -> bool {
    !values.is_empty()
        && values.len() <= usize::from(MAX_POLICY_ITEMS)
        && values.windows(2).all(|window| window[0] < window[1])
}

fn is_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn valid_local_id(value: &str) -> bool {
    (1..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}

fn valid_reason(value: &str) -> bool {
    matches!(value, "duplicate" | "fraudulent" | "requested_by_customer")
}

fn valid_api_version(value: &str) -> bool {
    (10..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

/// Closed bounded value validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BoundedValidationError {
    /// Policy violates V1 invariants.
    #[error("invalid Stripe bounded-refund policy")]
    InvalidPolicy,
    /// Evaluator configuration violates V1 invariants.
    #[error("invalid Stripe bounded-refund evaluator configuration")]
    InvalidConfiguration,
    /// Canonical identity could not be computed.
    #[error("could not canonicalize Stripe bounded-refund value")]
    Canonicalization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        NOW, bounded_action, bounded_configuration, bounded_policy, bounded_policy_input,
        configuration, evidence,
    };

    fn context<'a>(
        policy: &'a StripeBoundedRefundPolicyV1,
        action: &'a ExactRefundActionV1,
        evidence: &'a RefundEvidenceV1,
        exact: &'a StripeVerifierConfiguration,
        bounded: &'a StripeBoundedEvaluatorConfigurationV1,
        snapshot: &'a AggregateBudgetSnapshot,
    ) -> BoundedEvaluationContext<'a> {
        BoundedEvaluationContext {
            policy,
            action,
            evidence,
            aggregate_snapshot: snapshot,
            required_exact_configuration: exact,
            executed_exact_configuration: exact,
            required_bounded_configuration: bounded,
            executed_bounded_configuration: bounded,
            request_audience: exact.executor_audience(),
            now: NOW,
        }
    }

    #[test]
    fn configured_policy_authorizes_exact_refund_at_inclusive_boundary() {
        let evidence = evidence(2_000, 0);
        let exact = configuration(2_000);
        let policy = bounded_policy(
            &evidence,
            2_000,
            5_000,
            RefundDenominator::OriginalChargeAmount,
            5_000,
        );
        let bounded = bounded_configuration(&policy);
        let action = bounded_action(&exact, &policy, &evidence, 1_000, "bounded-workflow-01");
        let decision = evaluate_bounded_refund(&context(
            &policy,
            &action,
            &evidence,
            &exact,
            &bounded,
            &AggregateBudgetSnapshot::default(),
        ));

        assert_eq!(decision.class, BoundedDecisionClass::Eligible);
        let eligibility = decision.eligibility.unwrap();
        assert_eq!(eligibility.relative_ceiling_minor, 1_000);
        assert_eq!(eligibility.effective_ceiling_minor, 1_000);
        assert_eq!(eligibility.reservations[0].available_before_minor, 5_000);
    }

    #[test]
    fn percentage_rounds_down_and_boundary_plus_one_is_denied() {
        let evidence = evidence(10_001, 0);
        let exact = configuration(10_001);
        let policy = bounded_policy(
            &evidence,
            10_001,
            3_333,
            RefundDenominator::OriginalChargeAmount,
            20_000,
        );
        let bounded = bounded_configuration(&policy);
        let at_boundary = bounded_action(&exact, &policy, &evidence, 3_333, "bounded-workflow-02");
        let over = bounded_action(&exact, &policy, &evidence, 3_334, "bounded-workflow-03");
        let snapshot = AggregateBudgetSnapshot::default();

        assert_eq!(
            evaluate_bounded_refund(&context(
                &policy,
                &at_boundary,
                &evidence,
                &exact,
                &bounded,
                &snapshot,
            ))
            .class,
            BoundedDecisionClass::Eligible
        );
        assert_eq!(
            evaluate_bounded_refund(&context(
                &policy, &over, &evidence, &exact, &bounded, &snapshot,
            ))
            .code,
            BoundedDecisionCode::RelativeLimitExceeded
        );
    }

    #[test]
    fn required_and_executed_bounded_configuration_must_be_equal() {
        let evidence = evidence(2_000, 0);
        let exact = configuration(2_000);
        let policy = bounded_policy(
            &evidence,
            2_000,
            10_000,
            RefundDenominator::CapturedAmount,
            5_000,
        );
        let required = bounded_configuration(&policy);
        let executed = StripeBoundedEvaluatorConfigurationV1::for_policy(
            &policy,
            "different-build",
            exact.executor_audience(),
        )
        .unwrap();
        let action = bounded_action(&exact, &policy, &evidence, 1_000, "bounded-workflow-04");
        let decision = evaluate_bounded_refund(&BoundedEvaluationContext {
            policy: &policy,
            action: &action,
            evidence: &evidence,
            aggregate_snapshot: &AggregateBudgetSnapshot::default(),
            required_exact_configuration: &exact,
            executed_exact_configuration: &exact,
            required_bounded_configuration: &required,
            executed_bounded_configuration: &executed,
            request_audience: exact.executor_audience(),
            now: NOW,
        });

        assert_eq!(decision.code, BoundedDecisionCode::ConfigurationMismatch);
    }

    #[test]
    fn aggregate_snapshot_holds_reserved_and_unknown_capacity() {
        let evidence = evidence(2_000, 0);
        let exact = configuration(2_000);
        let policy = bounded_policy(
            &evidence,
            2_000,
            10_000,
            RefundDenominator::RemainingRefundableAmount,
            1_500,
        );
        let bounded = bounded_configuration(&policy);
        let action = bounded_action(&exact, &policy, &evidence, 501, "bounded-workflow-05");
        let window = policy.aggregate_budgets()[0]
            .window()
            .identity(NOW)
            .unwrap();
        let snapshot = AggregateBudgetSnapshot {
            usages: vec![AggregateBudgetUsage {
                budget_id: "support-daily".into(),
                window,
                committed_minor: 500,
                reserved_minor: 250,
                outcome_unknown_minor: 250,
            }],
        };
        let decision = evaluate_bounded_refund(&context(
            &policy, &action, &evidence, &exact, &bounded, &snapshot,
        ));

        assert_eq!(decision.code, BoundedDecisionCode::AggregateBudgetExceeded);
    }

    #[test]
    fn every_stripe_scope_dimension_denies_independently() {
        let evidence = evidence(2_000, 0);
        let exact = configuration(2_000);
        let snapshot = AggregateBudgetSnapshot::default();
        let mut cases = Vec::new();

        let mut account = bounded_policy_input(&evidence);
        account.allowed_test_account_ids =
            vec![StripeAccountId::parse("acct_otherdemo01").unwrap()];
        cases.push((
            StripeBoundedRefundPolicyV1::new(account).unwrap(),
            BoundedDecisionCode::AccountDenied,
        ));

        let mut api = bounded_policy_input(&evidence);
        api.allowed_api_versions = vec!["2026-01-01.clover".into()];
        cases.push((
            StripeBoundedRefundPolicyV1::new(api).unwrap(),
            BoundedDecisionCode::ApiVersionDenied,
        ));

        let mut connect = bounded_policy_input(&evidence);
        connect.connect_scope = ConnectScope::ConnectedAccounts {
            account_ids: vec![StripeAccountId::parse("acct_connectdemo01").unwrap()],
        };
        cases.push((
            StripeBoundedRefundPolicyV1::new(connect).unwrap(),
            BoundedDecisionCode::ConnectContextDenied,
        ));

        let mut charge = bounded_policy_input(&evidence);
        charge.allowed_charge_ids = vec![ChargeId::parse("ch_otherdemo00000001").unwrap()];
        cases.push((
            StripeBoundedRefundPolicyV1::new(charge).unwrap(),
            BoundedDecisionCode::ChargeDenied,
        ));

        let mut payment_intent = bounded_policy_input(&evidence);
        payment_intent.allowed_payment_intent_ids =
            vec![PaymentIntentId::parse("pi_otherdemo00000001").unwrap()];
        cases.push((
            StripeBoundedRefundPolicyV1::new(payment_intent).unwrap(),
            BoundedDecisionCode::PaymentIntentDenied,
        ));

        let mut currency = bounded_policy_input(&evidence);
        let eur = Currency::parse("eur").unwrap();
        currency.allowed_currencies = vec![eur.clone()];
        currency.per_refund_absolute_minor_by_currency =
            std::collections::BTreeMap::from([(eur.clone(), 2_000)]);
        currency.aggregate_budgets = vec![
            AggregateRefundBudget::new(
                "support-daily",
                eur,
                5_000,
                RefundBudgetWindow::Fixed {
                    starts_at: NOW - 3_600,
                    ends_at: NOW + 3_600,
                },
            )
            .unwrap(),
        ];
        cases.push((
            StripeBoundedRefundPolicyV1::new(currency).unwrap(),
            BoundedDecisionCode::CurrencyDenied,
        ));

        let mut reason = bounded_policy_input(&evidence);
        reason.allowed_reasons = vec!["fraudulent".into()];
        cases.push((
            StripeBoundedRefundPolicyV1::new(reason).unwrap(),
            BoundedDecisionCode::ReasonDenied,
        ));

        for (index, (policy, expected)) in cases.into_iter().enumerate() {
            let bounded = bounded_configuration(&policy);
            let action = bounded_action(
                &exact,
                &policy,
                &evidence,
                1_000,
                &format!("bounded-scope-{index:02}"),
            );
            let decision = evaluate_bounded_refund(&context(
                &policy, &action, &evidence, &exact, &bounded, &snapshot,
            ));
            assert_eq!(decision.code, expected);
        }
    }

    #[test]
    fn stale_evidence_and_expired_policy_fail_closed() {
        let evidence = evidence(2_000, 0);
        let exact = configuration(2_000);
        let policy = bounded_policy(
            &evidence,
            2_000,
            10_000,
            RefundDenominator::OriginalChargeAmount,
            5_000,
        );
        let bounded = bounded_configuration(&policy);
        let action = bounded_action(&exact, &policy, &evidence, 1_000, "bounded-stale-01");
        let snapshot = AggregateBudgetSnapshot::default();
        let mut stale = context(&policy, &action, &evidence, &exact, &bounded, &snapshot);
        stale.now = NOW + 120;
        assert_eq!(
            evaluate_bounded_refund(&stale).code,
            BoundedDecisionCode::EvidenceStale
        );

        let mut expired_input = bounded_policy_input(&evidence);
        expired_input.valid_from = NOW - 120;
        expired_input.expires_at = NOW - 1;
        let expired_policy = StripeBoundedRefundPolicyV1::new(expired_input).unwrap();
        let expired_configuration = bounded_configuration(&expired_policy);
        let expired_action = bounded_action(
            &exact,
            &expired_policy,
            &evidence,
            1_000,
            "bounded-expired-01",
        );
        assert_eq!(
            evaluate_bounded_refund(&context(
                &expired_policy,
                &expired_action,
                &evidence,
                &exact,
                &expired_configuration,
                &snapshot,
            ))
            .code,
            BoundedDecisionCode::PolicyExpired
        );
    }

    #[test]
    fn live_mode_evidence_and_checked_overflow_are_denied() {
        let base = evidence(2_000, 0);
        let live = RefundEvidenceV1::new(crate::types::RefundEvidenceInput {
            stripe_account_id: base.stripe_account_id().clone(),
            stripe_api_version: base.stripe_api_version().into(),
            livemode: true,
            charge_id: base.charge_id().clone(),
            payment_intent_id: base.payment_intent_id().cloned(),
            connect_account_id: None,
            currency: base.currency().clone(),
            charge_amount_minor: 2_000,
            captured_amount_minor: 2_000,
            amount_refunded_minor: 0,
            paid: true,
            captured: true,
            charge_refunded: false,
            disputed: false,
            observed_at: NOW - 5,
            response_commitment: crate::canonical::sha256(b"live evidence"),
        })
        .unwrap();
        let exact = configuration(2_000);
        let policy = bounded_policy(
            &live,
            2_000,
            10_000,
            RefundDenominator::OriginalChargeAmount,
            5_000,
        );
        let bounded = bounded_configuration(&policy);
        let action = bounded_action(&exact, &policy, &base, 1_000, "bounded-live-01");
        assert_eq!(
            evaluate_bounded_refund(&context(
                &policy,
                &action,
                &live,
                &exact,
                &bounded,
                &AggregateBudgetSnapshot::default(),
            ))
            .code,
            BoundedDecisionCode::TestModeRequired
        );

        let huge = RefundEvidenceV1::new(crate::types::RefundEvidenceInput {
            stripe_account_id: base.stripe_account_id().clone(),
            stripe_api_version: base.stripe_api_version().into(),
            livemode: false,
            charge_id: base.charge_id().clone(),
            payment_intent_id: base.payment_intent_id().cloned(),
            connect_account_id: None,
            currency: base.currency().clone(),
            charge_amount_minor: u64::MAX,
            captured_amount_minor: u64::MAX,
            amount_refunded_minor: 0,
            paid: true,
            captured: true,
            charge_refunded: false,
            disputed: false,
            observed_at: NOW - 5,
            response_commitment: crate::canonical::sha256(b"huge evidence"),
        })
        .unwrap();
        let overflow_policy = bounded_policy(
            &huge,
            2_000,
            10_000,
            RefundDenominator::CapturedAmount,
            5_000,
        );
        let overflow_configuration = bounded_configuration(&overflow_policy);
        let overflow_action =
            bounded_action(&exact, &overflow_policy, &huge, 1, "bounded-overflow-01");
        assert_eq!(
            evaluate_bounded_refund(&context(
                &overflow_policy,
                &overflow_action,
                &huge,
                &exact,
                &overflow_configuration,
                &AggregateBudgetSnapshot::default(),
            ))
            .code,
            BoundedDecisionCode::ArithmeticOverflow
        );
    }
}
