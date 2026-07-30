//! Pure bounded Connect Transfer evaluator.

#![allow(
    clippy::must_use_candidate,
    reason = "stable decision-code conversion is intentionally lightweight"
)]

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use super::{
    ConnectTransferAggregateSnapshot, ConnectTransferBudgetScope, ConnectTransferEvidenceV1,
    ConnectTransferReservationIntent, StripeBoundedConnectTransferPolicyV1,
    StripeConnectTransferConfigurationV1, StripeExactConnectTransferV1,
};
use crate::types::DigestHex;

/// Closed evaluator result class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectTransferDecisionClass {
    Eligible,
    Denied,
    Indeterminate,
}

/// Stable transfer decision stage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectTransferDecisionStage {
    Configuration,
    Policy,
    Action,
    Evidence,
    Destination,
    Source,
    Limits,
    PlatformBalance,
    Aggregate,
    Complete,
}

/// Stable transfer decision codes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectTransferDecisionCode {
    ConnectTransferAuthorized,
    ConnectDestinationDenied,
    ConnectSourceChargeDenied,
    ConnectSourceNotAvailable,
    ConnectTransferGroupMismatch,
    ConnectTransferLimitExceeded,
    ConnectSourceCapacityExceeded,
    ConnectPlatformBalanceInsufficient,
    ConnectTransferOutcomeUnknown,
    ConnectConfigurationMismatch,
    ConnectEvidenceInvalid,
    ConnectEvidenceStale,
    ConnectReplay,
    ConnectArithmeticFailure,
}

impl ConnectTransferDecisionCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectTransferAuthorized => "connect-transfer-authorized",
            Self::ConnectDestinationDenied => "connect-destination-denied",
            Self::ConnectSourceChargeDenied => "connect-source-charge-denied",
            Self::ConnectSourceNotAvailable => "connect-source-not-available",
            Self::ConnectTransferGroupMismatch => "connect-transfer-group-mismatch",
            Self::ConnectTransferLimitExceeded => "connect-transfer-limit-exceeded",
            Self::ConnectSourceCapacityExceeded => "connect-source-capacity-exceeded",
            Self::ConnectPlatformBalanceInsufficient => "connect-platform-balance-insufficient",
            Self::ConnectTransferOutcomeUnknown => "connect-transfer-outcome-unknown",
            Self::ConnectConfigurationMismatch => "connect-configuration-mismatch",
            Self::ConnectEvidenceInvalid => "connect-evidence-invalid",
            Self::ConnectEvidenceStale => "connect-evidence-stale",
            Self::ConnectReplay => "connect-replay",
            Self::ConnectArithmeticFailure => "connect-arithmetic-failure",
        }
    }
}

/// Exact successful transfer calculations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectTransferEligibility {
    pub source_ceiling_minor: u64,
    pub source_committed_net_minor: u64,
    pub source_available_before_minor: u64,
    pub platform_available_before_minor: u64,
    pub per_transfer_limit_minor: u64,
    pub per_destination_limit_minor: u64,
    pub reservations: Vec<ConnectTransferReservationIntent>,
}

/// Pure transfer decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectTransferDecision {
    pub class: ConnectTransferDecisionClass,
    pub code: ConnectTransferDecisionCode,
    pub stage: ConnectTransferDecisionStage,
    pub detail: String,
    pub eligibility: Option<ConnectTransferEligibility>,
}

impl ConnectTransferDecision {
    fn denied(
        code: ConnectTransferDecisionCode,
        stage: ConnectTransferDecisionStage,
        detail: &'static str,
    ) -> Self {
        Self {
            class: ConnectTransferDecisionClass::Denied,
            code,
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
}

/// Complete explicit evaluator inputs.
pub struct ConnectTransferEvaluationContext<'a> {
    pub policy: &'a StripeBoundedConnectTransferPolicyV1,
    pub action: &'a StripeExactConnectTransferV1,
    pub evidence: &'a ConnectTransferEvidenceV1,
    pub aggregate: &'a ConnectTransferAggregateSnapshot,
    pub required_configuration: &'a StripeConnectTransferConfigurationV1,
    pub executed_configuration: &'a StripeConnectTransferConfigurationV1,
    pub request_audience: &'a str,
    pub now: u64,
}

fn digest_equal(left: &DigestHex, right: &DigestHex) -> bool {
    left.as_str()
        .as_bytes()
        .ct_eq(right.as_str().as_bytes())
        .into()
}

fn held(snapshot: &ConnectTransferAggregateSnapshot, id: &str) -> u64 {
    snapshot
        .held_minor_by_reservation
        .get(id)
        .copied()
        .unwrap_or_default()
}

/// Evaluates an exact source-funded transfer with checked arithmetic.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "security precedence and every conservation dimension remain linear"
)]
pub fn evaluate_connect_transfer(
    context: &ConnectTransferEvaluationContext<'_>,
) -> ConnectTransferDecision {
    if context.required_configuration != context.executed_configuration {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectConfigurationMismatch,
            ConnectTransferDecisionStage::Configuration,
            "required and executed transfer configurations differ",
        );
    }
    if context.policy.validate().is_err()
        || context.action.validate().is_err()
        || context.evidence.validate().is_err()
        || context.required_configuration.validate().is_err()
    {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectEvidenceInvalid,
            ConnectTransferDecisionStage::Policy,
            "policy, action, evidence, or configuration is malformed",
        );
    }
    let (Ok(policy_digest), Ok(configuration_digest)) = (
        context.policy.digest(),
        context.required_configuration.digest(),
    ) else {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectArithmeticFailure,
            ConnectTransferDecisionStage::Configuration,
            "configuration commitments cannot be computed",
        );
    };
    if !digest_equal(context.action.required_policy_digest(), &policy_digest)
        || !digest_equal(
            context.action.required_configuration_digest(),
            &configuration_digest,
        )
        || context.required_configuration.policy_digest() != &policy_digest
        || context.required_configuration.platform_account_id()
            != context.action.platform_account_id()
        || context.required_configuration.stripe_api_version()
            != context.action.stripe_api_version()
        || context.required_configuration.executor_audience() != context.request_audience
        || context.action.executor_audience() != context.request_audience
    {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectConfigurationMismatch,
            ConnectTransferDecisionStage::Configuration,
            "a protected transfer configuration commitment differs",
        );
    }
    if context.now < context.policy.valid_from()
        || context.now > context.policy.expires_at()
        || context.now > context.action.expires_at()
        || context.action.expires_at().saturating_sub(context.now)
            > context.policy.maximum_action_lifetime_seconds()
    {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectEvidenceStale,
            ConnectTransferDecisionStage::Policy,
            "policy or exact action is inactive",
        );
    }
    if context.evidence.platform_account_id != *context.action.platform_account_id()
        || context.evidence.destination_account_id != *context.action.destination_account_id()
        || context.evidence.source_charge_id != *context.action.source_charge_id()
        || context.evidence.source_payment_intent_id != *context.action.source_payment_intent_id()
        || context.evidence.source_currency != *context.action.currency()
        || context.evidence.stripe_api_version != context.action.stripe_api_version()
        || context.evidence.livemode
    {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectEvidenceInvalid,
            ConnectTransferDecisionStage::Evidence,
            "protected source or account evidence differs from the action",
        );
    }
    if context.evidence.observed_at > context.now
        || context.now.saturating_sub(context.evidence.observed_at)
            > context.policy.maximum_source_evidence_age_seconds()
    {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectEvidenceStale,
            ConnectTransferDecisionStage::Evidence,
            "source or balance evidence is stale",
        );
    }
    if context
        .policy
        .platforms()
        .binary_search(context.action.platform_account_id())
        .is_err()
        || context
            .policy
            .destinations()
            .binary_search(context.action.destination_account_id())
            .is_err()
        || !context.evidence.destination_transfers_capability_active
    {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectDestinationDenied,
            ConnectTransferDecisionStage::Destination,
            "platform or connected destination is outside configured scope",
        );
    }
    if context
        .policy
        .sources()
        .binary_search(context.action.source_charge_id())
        .is_err()
    {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectSourceChargeDenied,
            ConnectTransferDecisionStage::Source,
            "source Charge is outside configured scope",
        );
    }
    if !context.evidence.source_charge_paid
        || !context.evidence.source_charge_captured
        || context.evidence.source_charge_status != "succeeded"
    {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectSourceNotAvailable,
            ConnectTransferDecisionStage::Source,
            "source Charge funds are not successful and available",
        );
    }
    if context.evidence.transfer_group != context.action.transfer_group()
        || context
            .policy
            .groups()
            .binary_search_by(|candidate| candidate.as_str().cmp(context.action.transfer_group()))
            .is_err()
        || context
            .policy
            .scopes()
            .binary_search_by(|candidate| candidate.as_str().cmp(context.action.business_scope()))
            .is_err()
    {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectTransferGroupMismatch,
            ConnectTransferDecisionStage::Action,
            "transfer group or business scope differs",
        );
    }
    if context
        .policy
        .currencies()
        .binary_search(context.action.currency())
        .is_err()
    {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectTransferLimitExceeded,
            ConnectTransferDecisionStage::Limits,
            "currency is outside configured scope",
        );
    }
    let (Some(per_transfer), Some(per_destination)) = (
        context
            .policy
            .transfer_limits()
            .get(context.action.currency()),
        context
            .policy
            .destination_limits()
            .get(context.action.currency()),
    ) else {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectTransferLimitExceeded,
            ConnectTransferDecisionStage::Limits,
            "currency-specific transfer limits are incomplete",
        );
    };
    if context.action.amount_minor() > *per_transfer {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectTransferLimitExceeded,
            ConnectTransferDecisionStage::Limits,
            "exact amount exceeds the inclusive per-transfer ceiling",
        );
    }
    let Some(source_product) = context
        .evidence
        .source_charge_amount_minor
        .checked_mul(u64::from(context.policy.source_basis_points()))
    else {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectArithmeticFailure,
            ConnectTransferDecisionStage::Source,
            "source-relative multiplication overflowed",
        );
    };
    let source_ceiling = source_product / 10_000;
    let Some(source_committed_net) = context
        .evidence
        .source_committed_transfer_minor
        .checked_sub(context.evidence.source_reversed_transfer_minor)
    else {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectArithmeticFailure,
            ConnectTransferDecisionStage::Source,
            "source committed amount underflowed",
        );
    };
    let source_id = format!("source:{}", context.action.source_charge_id());
    let destination_id = format!("destination:{}", context.action.destination_account_id());
    let platform_id = format!(
        "platform:{}:{}",
        context.action.platform_account_id(),
        context.action.currency()
    );
    let source_held = held(context.aggregate, &source_id);
    let destination_held = held(context.aggregate, &destination_id);
    let platform_held = held(context.aggregate, &platform_id);
    let Some(source_used) = source_committed_net.checked_add(source_held) else {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectArithmeticFailure,
            ConnectTransferDecisionStage::Source,
            "source capacity arithmetic overflowed",
        );
    };
    let Some(source_available) = source_ceiling.checked_sub(source_used) else {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectSourceCapacityExceeded,
            ConnectTransferDecisionStage::Source,
            "source-relative capacity is already exhausted",
        );
    };
    if context.action.amount_minor() > source_available {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectSourceCapacityExceeded,
            ConnectTransferDecisionStage::Source,
            "exact amount exceeds remaining source-relative capacity",
        );
    }
    if destination_held
        .checked_add(context.action.amount_minor())
        .is_none_or(|after| after > *per_destination)
    {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectTransferLimitExceeded,
            ConnectTransferDecisionStage::Limits,
            "destination capacity is exhausted",
        );
    }
    if platform_held
        .checked_add(context.action.amount_minor())
        .is_none_or(|after| after > context.evidence.platform_available_balance_minor)
    {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectPlatformBalanceInsufficient,
            ConnectTransferDecisionStage::PlatformBalance,
            "platform available balance cannot cover local held capacity and exact transfer",
        );
    }
    let mut reservations = vec![
        ConnectTransferReservationIntent {
            reservation_id: source_id,
            currency: context.action.currency().clone(),
            amount_minor: context.action.amount_minor(),
            limit_minor: source_ceiling.saturating_sub(source_committed_net),
        },
        ConnectTransferReservationIntent {
            reservation_id: destination_id,
            currency: context.action.currency().clone(),
            amount_minor: context.action.amount_minor(),
            limit_minor: *per_destination,
        },
        ConnectTransferReservationIntent {
            reservation_id: platform_id,
            currency: context.action.currency().clone(),
            amount_minor: context.action.amount_minor(),
            limit_minor: context.evidence.platform_available_balance_minor,
        },
    ];
    for budget in context.policy.aggregate_budgets() {
        if context.now < budget.starts_at || context.now > budget.ends_at {
            continue;
        }
        let applies = match &budget.scope {
            ConnectTransferBudgetScope::Global => true,
            ConnectTransferBudgetScope::Destination(account) => {
                account == context.action.destination_account_id()
            }
            ConnectTransferBudgetScope::Source(charge) => {
                charge == context.action.source_charge_id()
            }
        };
        if applies && budget.currency == *context.action.currency() {
            let id = format!("budget:{}", budget.budget_id);
            if held(context.aggregate, &id)
                .checked_add(context.action.amount_minor())
                .is_none_or(|after| after > budget.limit_minor)
            {
                return ConnectTransferDecision::denied(
                    ConnectTransferDecisionCode::ConnectTransferLimitExceeded,
                    ConnectTransferDecisionStage::Aggregate,
                    "an applicable aggregate transfer budget is exhausted",
                );
            }
            reservations.push(ConnectTransferReservationIntent {
                reservation_id: id,
                currency: budget.currency.clone(),
                amount_minor: context.action.amount_minor(),
                limit_minor: budget.limit_minor,
            });
        }
    }
    if reservations.len() == 3 {
        return ConnectTransferDecision::denied(
            ConnectTransferDecisionCode::ConnectTransferLimitExceeded,
            ConnectTransferDecisionStage::Aggregate,
            "no active aggregate budget covers the transfer",
        );
    }
    ConnectTransferDecision {
        class: ConnectTransferDecisionClass::Eligible,
        code: ConnectTransferDecisionCode::ConnectTransferAuthorized,
        stage: ConnectTransferDecisionStage::Complete,
        detail: "exact source-funded transfer is inside all configured bounds".into(),
        eligibility: Some(ConnectTransferEligibility {
            source_ceiling_minor: source_ceiling,
            source_committed_net_minor: source_committed_net,
            source_available_before_minor: source_available,
            platform_available_before_minor: context.evidence.platform_available_balance_minor,
            per_transfer_limit_minor: *per_transfer,
            per_destination_limit_minor: *per_destination,
            reservations,
        }),
    }
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn basis_points_floor_never_exceeds_denominator() {
        let amount: u64 = kani::any();
        let basis_points: u16 = kani::any();
        if basis_points <= 10_000
            && let Some(product) = amount.checked_mul(u64::from(basis_points))
        {
            assert!(product / 10_000 <= amount);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        canonical,
        connect::transfer::{
            AggregateConnectTransferBudget, ConnectTransferBudgetScope,
            StripeBoundedConnectTransferPolicyInput, StripeExactConnectTransferInput,
        },
        types::{ChargeId, Currency, PaymentIntentId, StripeAccountId},
    };

    const NOW: u64 = 2_100_500_000;
    const AUDIENCE: &str = "https://stripe-connect-transfer.auths.dev";
    const API_VERSION: &str = "2025-04-30.basil";

    struct Fixture {
        policy: StripeBoundedConnectTransferPolicyV1,
        configuration: StripeConnectTransferConfigurationV1,
        action: StripeExactConnectTransferV1,
        evidence: ConnectTransferEvidenceV1,
    }

    fn fixture(amount_minor: u64) -> Fixture {
        let platform = StripeAccountId::parse("acct_platformfixture").unwrap();
        let destination = StripeAccountId::parse("acct_destinationfixture").unwrap();
        let source = ChargeId::parse("ch_connectfixture").unwrap();
        let payment_intent = PaymentIntentId::parse("pi_connectfixture").unwrap();
        let currency = Currency::parse("usd").unwrap();
        let policy =
            StripeBoundedConnectTransferPolicyV1::new(StripeBoundedConnectTransferPolicyInput {
                policy_id: "connect-transfer-fixture".into(),
                valid_from: NOW - 60,
                expires_at: NOW + 3_600,
                allowed_test_platform_account_ids: vec![platform.clone()],
                allowed_destination_connected_account_ids: vec![destination.clone()],
                allowed_source_charge_ids: vec![source.clone()],
                allowed_transfer_groups: vec!["order-fixture".into()],
                allowed_currencies: vec![currency.clone()],
                allowed_business_scopes: vec!["supplier-payment".into()],
                per_transfer_minor_by_currency: BTreeMap::from([(currency.clone(), 500)]),
                per_destination_minor_by_currency: BTreeMap::from([(currency.clone(), 1_000)]),
                per_source_charge_basis_points: 2_500,
                aggregate_budgets: vec![AggregateConnectTransferBudget {
                    budget_id: "connect-global".into(),
                    scope: ConnectTransferBudgetScope::Global,
                    currency: currency.clone(),
                    limit_minor: 2_000,
                    starts_at: NOW - 60,
                    ends_at: NOW + 3_600,
                }],
                maximum_source_evidence_age_seconds: 60,
                maximum_action_lifetime_seconds: 300,
                allowed_api_versions: vec![API_VERSION.into()],
            })
            .unwrap();
        let configuration = StripeConnectTransferConfigurationV1::new(
            &policy,
            platform.clone(),
            API_VERSION.into(),
            AUDIENCE.into(),
        )
        .unwrap();
        let action = StripeExactConnectTransferV1::new(StripeExactConnectTransferInput {
            platform_account_id: platform.clone(),
            destination_connected_account_id: destination.clone(),
            source_charge_id: source.clone(),
            source_payment_intent_id: payment_intent.clone(),
            transfer_group: "order-fixture".into(),
            business_scope: "supplier-payment".into(),
            amount_minor,
            currency: currency.clone(),
            description_commitment: canonical::sha256(b"fixture transfer"),
            fixed_metadata_commitment: canonical::sha256(b"fixture metadata"),
            stripe_api_version: API_VERSION.into(),
            required_policy_digest: policy.digest().unwrap(),
            required_configuration_digest: configuration.digest().unwrap(),
            executor_audience: AUDIENCE.into(),
            expires_at: NOW + 120,
            nonce: canonical::sha256(b"connect-transfer-nonce"),
        })
        .unwrap();
        let evidence = ConnectTransferEvidenceV1 {
            schema: "auths.stripe.connect-transfer-evidence/1".into(),
            platform_account_id: platform,
            destination_account_id: destination,
            destination_transfers_capability_active: true,
            source_charge_id: source,
            source_payment_intent_id: payment_intent,
            source_charge_amount_minor: 4_000,
            source_charge_captured: true,
            source_charge_paid: true,
            source_charge_status: "succeeded".into(),
            source_currency: currency,
            source_committed_transfer_minor: 400,
            source_reversed_transfer_minor: 100,
            platform_available_balance_minor: 5_000,
            transfer_group: "order-fixture".into(),
            livemode: false,
            stripe_api_version: API_VERSION.into(),
            observed_at: NOW,
            response_digest: canonical::sha256(b"source-and-balance-response"),
            source: "stripe-api".into(),
        };
        Fixture {
            policy,
            configuration,
            action,
            evidence,
        }
    }

    fn evaluate(
        fixture: &Fixture,
        aggregate: &ConnectTransferAggregateSnapshot,
    ) -> ConnectTransferDecision {
        evaluate_connect_transfer(&ConnectTransferEvaluationContext {
            policy: &fixture.policy,
            action: &fixture.action,
            evidence: &fixture.evidence,
            aggregate,
            required_configuration: &fixture.configuration,
            executed_configuration: &fixture.configuration,
            request_audience: AUDIENCE,
            now: NOW,
        })
    }

    #[test]
    fn exact_inclusive_bound_and_basis_point_floor_are_eligible() {
        let fixture = fixture(500);
        let result = evaluate(&fixture, &ConnectTransferAggregateSnapshot::default());
        assert_eq!(
            result.code,
            ConnectTransferDecisionCode::ConnectTransferAuthorized
        );
        let eligibility = result.eligibility.unwrap();
        assert_eq!(eligibility.source_ceiling_minor, 1_000);
        assert_eq!(eligibility.source_committed_net_minor, 300);
        assert_eq!(eligibility.source_available_before_minor, 700);
        assert_eq!(eligibility.reservations.len(), 4);
    }

    #[test]
    fn one_minor_unit_above_each_conservation_boundary_is_denied() {
        let transfer = fixture(501);
        assert_eq!(
            evaluate(&transfer, &ConnectTransferAggregateSnapshot::default()).code,
            ConnectTransferDecisionCode::ConnectTransferLimitExceeded
        );

        let source = fixture(500);
        let source_held = BTreeMap::from([("source:ch_connectfixture".into(), 201)]);
        assert_eq!(
            evaluate(
                &source,
                &ConnectTransferAggregateSnapshot {
                    held_minor_by_reservation: source_held
                }
            )
            .code,
            ConnectTransferDecisionCode::ConnectSourceCapacityExceeded
        );

        let destination = fixture(500);
        let destination_held =
            BTreeMap::from([("destination:acct_destinationfixture".into(), 501)]);
        assert_eq!(
            evaluate(
                &destination,
                &ConnectTransferAggregateSnapshot {
                    held_minor_by_reservation: destination_held
                }
            )
            .code,
            ConnectTransferDecisionCode::ConnectTransferLimitExceeded
        );

        let platform = fixture(500);
        let platform_held = BTreeMap::from([("platform:acct_platformfixture:usd".into(), 4_501)]);
        assert_eq!(
            evaluate(
                &platform,
                &ConnectTransferAggregateSnapshot {
                    held_minor_by_reservation: platform_held
                }
            )
            .code,
            ConnectTransferDecisionCode::ConnectPlatformBalanceInsufficient
        );
    }

    #[test]
    fn source_destination_group_currency_and_staleness_mutations_fail_closed() {
        let mut destination = fixture(500);
        destination.evidence.destination_account_id =
            StripeAccountId::parse("acct_differentdestination").unwrap();
        assert_eq!(
            evaluate(&destination, &ConnectTransferAggregateSnapshot::default()).code,
            ConnectTransferDecisionCode::ConnectEvidenceInvalid
        );

        let mut source = fixture(500);
        source.evidence.source_charge_id = ChargeId::parse("ch_differentsource").unwrap();
        assert_eq!(
            evaluate(&source, &ConnectTransferAggregateSnapshot::default()).code,
            ConnectTransferDecisionCode::ConnectEvidenceInvalid
        );

        let mut group = fixture(500);
        group.evidence.transfer_group = "different-order".into();
        assert_eq!(
            evaluate(&group, &ConnectTransferAggregateSnapshot::default()).code,
            ConnectTransferDecisionCode::ConnectTransferGroupMismatch
        );

        let mut currency = fixture(500);
        currency.evidence.source_currency = Currency::parse("eur").unwrap();
        assert_eq!(
            evaluate(&currency, &ConnectTransferAggregateSnapshot::default()).code,
            ConnectTransferDecisionCode::ConnectEvidenceInvalid
        );

        let mut stale = fixture(500);
        stale.evidence.observed_at = NOW - 61;
        assert_eq!(
            evaluate(&stale, &ConnectTransferAggregateSnapshot::default()).code,
            ConnectTransferDecisionCode::ConnectEvidenceStale
        );
    }

    #[test]
    fn unavailable_source_and_aggregate_exhaustion_are_denied() {
        let mut source = fixture(500);
        source.evidence.source_charge_paid = false;
        assert_eq!(
            evaluate(&source, &ConnectTransferAggregateSnapshot::default()).code,
            ConnectTransferDecisionCode::ConnectSourceNotAvailable
        );

        let aggregate = fixture(500);
        let held = BTreeMap::from([("budget:connect-global".into(), 1_501)]);
        assert_eq!(
            evaluate(
                &aggregate,
                &ConnectTransferAggregateSnapshot {
                    held_minor_by_reservation: held
                }
            )
            .code,
            ConnectTransferDecisionCode::ConnectTransferLimitExceeded
        );
    }

    #[test]
    fn configuration_mismatch_has_highest_precedence() {
        let fixture = fixture(500);
        let other = StripeConnectTransferConfigurationV1::new(
            &fixture.policy,
            StripeAccountId::parse("acct_otherplatform").unwrap(),
            API_VERSION.into(),
            AUDIENCE.into(),
        )
        .unwrap();
        let result = evaluate_connect_transfer(&ConnectTransferEvaluationContext {
            policy: &fixture.policy,
            action: &fixture.action,
            evidence: &fixture.evidence,
            aggregate: &ConnectTransferAggregateSnapshot::default(),
            required_configuration: &fixture.configuration,
            executed_configuration: &other,
            request_audience: AUDIENCE,
            now: NOW,
        });
        assert_eq!(
            result.code,
            ConnectTransferDecisionCode::ConnectConfigurationMismatch
        );
    }
}
