//! Pure bounded Payout evaluator.

#![allow(
    clippy::must_use_candidate,
    clippy::too_many_lines,
    reason = "payout precedence and every conservation dimension remain linear"
)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use super::{
    PayoutAggregateSnapshot, PayoutBudgetScope, PayoutEvidenceV1, PayoutReservationIntent,
    StripeBoundedPayoutPolicyV1, StripeExactPayoutV1, StripePayoutConfigurationV1,
};
use crate::types::DigestHex;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PayoutDecisionClass {
    Eligible,
    Denied,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PayoutDecisionStage {
    Configuration,
    Policy,
    Evidence,
    Destination,
    Action,
    Approval,
    Balance,
    Aggregate,
    Complete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PayoutDecisionCode {
    PayoutAuthorized,
    PayoutDestinationDenied,
    PayoutDestinationUnavailable,
    PayoutMethodDenied,
    PayoutLimitExceeded,
    PayoutMinimumBalanceViolated,
    PayoutApprovalRequired,
    PayoutBalanceInsufficient,
    PayoutPending,
    PayoutFailed,
    PayoutOutcomeUnknown,
    PayoutConfigurationMismatch,
    PayoutEvidenceInvalid,
    PayoutEvidenceStale,
    PayoutReplay,
    PayoutArithmeticFailure,
}

impl PayoutDecisionCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PayoutAuthorized => "payout-authorized",
            Self::PayoutDestinationDenied => "payout-destination-denied",
            Self::PayoutDestinationUnavailable => "payout-destination-unavailable",
            Self::PayoutMethodDenied => "payout-method-denied",
            Self::PayoutLimitExceeded => "payout-limit-exceeded",
            Self::PayoutMinimumBalanceViolated => "payout-minimum-balance-violated",
            Self::PayoutApprovalRequired => "payout-approval-required",
            Self::PayoutBalanceInsufficient => "payout-balance-insufficient",
            Self::PayoutPending => "payout-pending",
            Self::PayoutFailed => "payout-failed",
            Self::PayoutOutcomeUnknown => "payout-outcome-unknown",
            Self::PayoutConfigurationMismatch => "payout-configuration-mismatch",
            Self::PayoutEvidenceInvalid => "payout-evidence-invalid",
            Self::PayoutEvidenceStale => "payout-evidence-stale",
            Self::PayoutReplay => "payout-replay",
            Self::PayoutArithmeticFailure => "payout-arithmetic-failure",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutEligibility {
    pub available_balance_before_minor: u64,
    pub local_balance_held_before_minor: u64,
    pub minimum_retained_minor: u64,
    pub available_after_minor: u64,
    pub per_payout_limit_minor: u64,
    pub per_destination_limit_minor: u64,
    pub approvals_consumed: Vec<DigestHex>,
    pub reservations: Vec<PayoutReservationIntent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutDecision {
    pub class: PayoutDecisionClass,
    pub code: PayoutDecisionCode,
    pub stage: PayoutDecisionStage,
    pub detail: String,
    pub eligibility: Option<PayoutEligibility>,
}

impl PayoutDecision {
    fn denied(code: PayoutDecisionCode, stage: PayoutDecisionStage, detail: &'static str) -> Self {
        Self {
            class: PayoutDecisionClass::Denied,
            code,
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
}

pub struct PayoutEvaluationContext<'a> {
    pub policy: &'a StripeBoundedPayoutPolicyV1,
    pub action: &'a StripeExactPayoutV1,
    pub evidence: &'a PayoutEvidenceV1,
    pub aggregate: &'a PayoutAggregateSnapshot,
    pub required_configuration: &'a StripePayoutConfigurationV1,
    pub executed_configuration: &'a StripePayoutConfigurationV1,
    pub request_audience: &'a str,
    pub now: u64,
}

fn digest_equal(left: &DigestHex, right: &DigestHex) -> bool {
    left.as_str()
        .as_bytes()
        .ct_eq(right.as_str().as_bytes())
        .into()
}

fn held(snapshot: &PayoutAggregateSnapshot, id: &str) -> u64 {
    snapshot
        .held_minor_by_reservation
        .get(id)
        .copied()
        .unwrap_or(0)
}

#[must_use]
pub fn evaluate_payout(context: &PayoutEvaluationContext<'_>) -> PayoutDecision {
    if context.required_configuration != context.executed_configuration {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutConfigurationMismatch,
            PayoutDecisionStage::Configuration,
            "required and executed payout configurations differ",
        );
    }
    if context.policy.validate().is_err()
        || context.action.validate().is_err()
        || context.evidence.validate().is_err()
        || context.required_configuration.validate().is_err()
    {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutEvidenceInvalid,
            PayoutDecisionStage::Policy,
            "policy, action, evidence, or configuration is malformed",
        );
    }
    let (Ok(policy_digest), Ok(configuration_digest)) = (
        context.policy.digest(),
        context.required_configuration.digest(),
    ) else {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutArithmeticFailure,
            PayoutDecisionStage::Configuration,
            "configuration commitments cannot be computed",
        );
    };
    if !digest_equal(context.action.required_policy_digest(), &policy_digest)
        || !digest_equal(
            context.action.required_configuration_digest(),
            &configuration_digest,
        )
        || context.required_configuration.policy_digest() != &policy_digest
        || context.required_configuration.stripe_account_id() != context.action.stripe_account_id()
        || context.required_configuration.source_type() != context.action.source_type()
        || context.required_configuration.stripe_api_version()
            != context.action.stripe_api_version()
        || context.required_configuration.executor_audience() != context.request_audience
        || context.action.executor_audience() != context.request_audience
    {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutConfigurationMismatch,
            PayoutDecisionStage::Configuration,
            "a protected payout configuration commitment differs",
        );
    }
    if context.now < context.policy.valid_from()
        || context.now > context.policy.expires_at()
        || context.now > context.action.expires_at()
        || context.action.expires_at().saturating_sub(context.now)
            > context.policy.maximum_action_lifetime()
    {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutEvidenceStale,
            PayoutDecisionStage::Policy,
            "policy or exact payout action is inactive",
        );
    }
    if context.evidence.stripe_account_id != *context.action.stripe_account_id()
        || context.evidence.destination_external_account_id
            != *context.action.destination_external_account_id()
        || context.evidence.destination_type_commitment
            != *context.action.destination_type_commitment()
        || context.evidence.currency != *context.action.currency()
        || context.evidence.source_type != context.action.source_type()
        || context.evidence.stripe_api_version != context.action.stripe_api_version()
        || context.evidence.livemode
    {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutEvidenceInvalid,
            PayoutDecisionStage::Evidence,
            "protected account, destination, balance, or API evidence differs",
        );
    }
    if context.evidence.balance_observed_at > context.now
        || context.evidence.destination_observed_at > context.now
        || context
            .now
            .saturating_sub(context.evidence.balance_observed_at)
            > context.policy.maximum_balance_age()
        || context
            .now
            .saturating_sub(context.evidence.destination_observed_at)
            > context.policy.maximum_destination_age()
    {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutEvidenceStale,
            PayoutDecisionStage::Evidence,
            "balance or destination evidence is stale",
        );
    }
    if context
        .policy
        .accounts()
        .binary_search(context.action.stripe_account_id())
        .is_err()
        || context
            .policy
            .destinations()
            .binary_search(context.action.destination_external_account_id())
            .is_err()
        || context
            .policy
            .destination_types()
            .binary_search(context.action.destination_type_commitment())
            .is_err()
    {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutDestinationDenied,
            PayoutDecisionStage::Destination,
            "account or external destination is outside configured scope",
        );
    }
    if context.evidence.destination_status != "verified" || !context.evidence.manual_payouts_enabled
    {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutDestinationUnavailable,
            PayoutDecisionStage::Destination,
            "destination or manual-payout capability is unavailable",
        );
    }
    if context.action.method() != super::PayoutMethod::Standard
        || context
            .policy
            .sources()
            .binary_search_by(|value| value.as_str().cmp(context.action.source_type()))
            .is_err()
        || context
            .policy
            .scopes()
            .binary_search_by(|value| value.as_str().cmp(context.action.business_scope()))
            .is_err()
        || context
            .policy
            .currencies()
            .binary_search(context.action.currency())
            .is_err()
    {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutMethodDenied,
            PayoutDecisionStage::Action,
            "method, source, business scope, or currency is outside policy",
        );
    }
    let (Some(per_payout), Some(per_destination), Some(minimum)) = (
        context
            .policy
            .payout_limits()
            .get(context.action.currency()),
        context
            .policy
            .destination_limits()
            .get(context.action.currency()),
        context
            .policy
            .minimum_balances()
            .get(context.action.currency()),
    ) else {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutLimitExceeded,
            PayoutDecisionStage::Action,
            "currency-specific payout limits are incomplete",
        );
    };
    if context.action.amount_minor() > *per_payout {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutLimitExceeded,
            PayoutDecisionStage::Action,
            "exact amount exceeds the inclusive per-payout limit",
        );
    }
    let approval_commitments: Vec<_> = context
        .evidence
        .approvals
        .iter()
        .map(|approval| approval.commitment.clone())
        .collect();
    if approval_commitments != context.action.required_approval_commitments() {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutApprovalRequired,
            PayoutDecisionStage::Approval,
            "approval evidence does not exactly match signed approval commitments",
        );
    }
    for threshold in context.policy.thresholds().iter().filter(|threshold| {
        threshold.currency == *context.action.currency()
            && context.action.amount_minor() >= threshold.amount_minor
    }) {
        let qualifying: Vec<_> = context
            .evidence
            .approvals
            .iter()
            .filter(|approval| {
                approval.approver_scope == threshold.required_approver_scope
                    && approval.assurance >= threshold.required_assurance
                    && approval.expires_at >= context.now
            })
            .collect();
        let distinct = qualifying
            .iter()
            .map(|approval| &approval.principal_commitment)
            .collect::<BTreeSet<_>>()
            .len();
        if distinct < usize::from(threshold.required_distinct_principals) {
            return PayoutDecision::denied(
                PayoutDecisionCode::PayoutApprovalRequired,
                PayoutDecisionStage::Approval,
                "the applicable threshold lacks distinct scoped approvers",
            );
        }
    }
    let account_id = format!(
        "balance:{}:{}:{}",
        context.action.stripe_account_id(),
        context.action.currency(),
        context.action.source_type()
    );
    let destination_id = format!(
        "destination:{}:{}",
        context.action.destination_external_account_id(),
        context.action.currency()
    );
    let account_held = held(context.aggregate, &account_id);
    let destination_held = held(context.aggregate, &destination_id);
    if destination_held
        .checked_add(context.action.amount_minor())
        .is_none_or(|after| after > *per_destination)
    {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutLimitExceeded,
            PayoutDecisionStage::Balance,
            "destination capacity is exhausted",
        );
    }
    let Some(after_holds) = context
        .evidence
        .available_balance_minor
        .checked_sub(account_held)
    else {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutBalanceInsufficient,
            PayoutDecisionStage::Balance,
            "local holds exceed fresh available balance",
        );
    };
    let Some(available_after) = after_holds.checked_sub(context.action.amount_minor()) else {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutBalanceInsufficient,
            PayoutDecisionStage::Balance,
            "fresh available balance cannot cover the exact payout",
        );
    };
    if available_after < *minimum {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutMinimumBalanceViolated,
            PayoutDecisionStage::Balance,
            "exact payout would breach the retained minimum balance",
        );
    }
    let balance_limit = context
        .evidence
        .available_balance_minor
        .saturating_sub(*minimum);
    let mut reservations = vec![
        PayoutReservationIntent {
            reservation_id: account_id,
            currency: context.action.currency().clone(),
            amount_minor: context.action.amount_minor(),
            limit_minor: balance_limit,
        },
        PayoutReservationIntent {
            reservation_id: destination_id,
            currency: context.action.currency().clone(),
            amount_minor: context.action.amount_minor(),
            limit_minor: *per_destination,
        },
    ];
    for budget in context.policy.budgets() {
        if context.now < budget.starts_at || context.now > budget.ends_at {
            continue;
        }
        let applies = match &budget.scope {
            PayoutBudgetScope::Global => true,
            PayoutBudgetScope::Destination(destination) => {
                destination == context.action.destination_external_account_id()
            }
        };
        if applies && budget.currency == *context.action.currency() {
            let id = format!("budget:{}", budget.budget_id);
            if held(context.aggregate, &id)
                .checked_add(context.action.amount_minor())
                .is_none_or(|after| after > budget.limit_minor)
            {
                return PayoutDecision::denied(
                    PayoutDecisionCode::PayoutLimitExceeded,
                    PayoutDecisionStage::Aggregate,
                    "an applicable aggregate payout budget is exhausted",
                );
            }
            reservations.push(PayoutReservationIntent {
                reservation_id: id,
                currency: budget.currency.clone(),
                amount_minor: context.action.amount_minor(),
                limit_minor: budget.limit_minor,
            });
        }
    }
    if reservations.len() == 2 {
        return PayoutDecision::denied(
            PayoutDecisionCode::PayoutLimitExceeded,
            PayoutDecisionStage::Aggregate,
            "no active aggregate payout budget covers the action",
        );
    }
    for commitment in &approval_commitments {
        reservations.push(PayoutReservationIntent {
            reservation_id: format!("approval:{commitment}"),
            currency: context.action.currency().clone(),
            amount_minor: 1,
            limit_minor: 1,
        });
    }
    PayoutDecision {
        class: PayoutDecisionClass::Eligible,
        code: PayoutDecisionCode::PayoutAuthorized,
        stage: PayoutDecisionStage::Complete,
        detail: "exact manual payout is inside every configured bound".into(),
        eligibility: Some(PayoutEligibility {
            available_balance_before_minor: context.evidence.available_balance_minor,
            local_balance_held_before_minor: account_held,
            minimum_retained_minor: *minimum,
            available_after_minor: available_after,
            per_payout_limit_minor: *per_payout,
            per_destination_limit_minor: *per_destination,
            approvals_consumed: approval_commitments,
            reservations,
        }),
    }
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn retained_balance_is_conservative() {
        let available: u64 = kani::any();
        let held: u64 = kani::any();
        let payout: u64 = kani::any();
        if let Some(after_holds) = available.checked_sub(held)
            && let Some(after) = after_holds.checked_sub(payout)
        {
            assert!(after <= available);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        canonical,
        treasury::payout::{
            AggregatePayoutBudget, PayoutApprovalEvidence, PayoutApprovalThreshold,
            PayoutBudgetScope, StripeBoundedPayoutPolicyInput, StripeExactPayoutInput,
        },
        types::{Currency, ExternalAccountId, StripeAccountId},
    };

    const NOW: u64 = 2_100_600_000;
    const AUDIENCE: &str = "https://stripe-payout.auths.dev";
    const API_VERSION: &str = "2025-04-30.basil";

    struct Fixture {
        policy: StripeBoundedPayoutPolicyV1,
        configuration: StripePayoutConfigurationV1,
        action: StripeExactPayoutV1,
        evidence: PayoutEvidenceV1,
    }

    fn fixture(amount_minor: u64) -> Fixture {
        let account = StripeAccountId::parse("acct_payoutfixture").unwrap();
        let destination = ExternalAccountId::parse("ba_payoutfixture").unwrap();
        let currency = Currency::parse("usd").unwrap();
        let destination_type = canonical::sha256(b"bank-account");
        let approval_one = PayoutApprovalEvidence {
            commitment: canonical::sha256(b"approval-one"),
            principal_commitment: canonical::sha256(b"principal-one"),
            approver_scope: "finance-payout".into(),
            assurance: 2,
            expires_at: NOW + 300,
        };
        let approval_two = PayoutApprovalEvidence {
            commitment: canonical::sha256(b"approval-two"),
            principal_commitment: canonical::sha256(b"principal-two"),
            approver_scope: "finance-payout".into(),
            assurance: 2,
            expires_at: NOW + 300,
        };
        let policy = StripeBoundedPayoutPolicyV1::new(StripeBoundedPayoutPolicyInput {
            policy_id: "payout-fixture".into(),
            valid_from: NOW - 60,
            expires_at: NOW + 3_600,
            allowed_test_account_ids: vec![account.clone()],
            allowed_external_destination_ids: vec![destination.clone()],
            allowed_destination_type_commitments: vec![destination_type.clone()],
            allowed_currencies: vec![currency.clone()],
            allowed_source_types: vec!["bank_account".into()],
            allowed_business_scopes: vec!["supplier-settlement".into()],
            per_payout_minor_by_currency: BTreeMap::from([(currency.clone(), 500)]),
            per_destination_minor_by_currency: BTreeMap::from([(currency.clone(), 1_000)]),
            aggregate_budgets: vec![AggregatePayoutBudget {
                budget_id: "payout-global".into(),
                scope: PayoutBudgetScope::Global,
                currency: currency.clone(),
                limit_minor: 2_000,
                starts_at: NOW - 60,
                ends_at: NOW + 3_600,
            }],
            approval_thresholds: vec![PayoutApprovalThreshold {
                currency: currency.clone(),
                amount_minor: 500,
                required_assurance: 2,
                required_approver_scope: "finance-payout".into(),
                required_distinct_principals: 2,
            }],
            minimum_available_balance_after_minor_by_currency: BTreeMap::from([(
                currency.clone(),
                500,
            )]),
            maximum_balance_evidence_age_seconds: 60,
            maximum_destination_evidence_age_seconds: 60,
            maximum_action_lifetime_seconds: 300,
            allowed_api_versions: vec![API_VERSION.into()],
        })
        .unwrap();
        let configuration = StripePayoutConfigurationV1::new(
            &policy,
            account.clone(),
            "bank_account".into(),
            API_VERSION.into(),
            AUDIENCE.into(),
        )
        .unwrap();
        let approvals = vec![approval_one, approval_two];
        let action = StripeExactPayoutV1::new(StripeExactPayoutInput {
            stripe_account_id: account.clone(),
            destination_external_account_id: destination.clone(),
            destination_type_commitment: destination_type.clone(),
            business_scope: "supplier-settlement".into(),
            amount_minor,
            currency: currency.clone(),
            source_type: "bank_account".into(),
            description_commitment: canonical::sha256(b"supplier payout"),
            statement_descriptor_commitment: canonical::sha256(b"AUTHS SUPPLIER"),
            required_approval_commitments: approvals
                .iter()
                .map(|approval| approval.commitment.clone())
                .collect(),
            stripe_api_version: API_VERSION.into(),
            required_policy_digest: policy.digest().unwrap(),
            required_configuration_digest: configuration.digest().unwrap(),
            executor_audience: AUDIENCE.into(),
            expires_at: NOW + 120,
            nonce: canonical::sha256(b"payout-nonce"),
        })
        .unwrap();
        let evidence = PayoutEvidenceV1 {
            schema: "auths.stripe.payout-evidence/1".into(),
            stripe_account_id: account,
            livemode: false,
            manual_payouts_enabled: true,
            available_balance_minor: 2_000,
            pending_balance_minor: 250,
            currency,
            source_type: "bank_account".into(),
            destination_external_account_id: destination,
            destination_type_commitment: destination_type,
            destination_fingerprint_commitment: canonical::sha256(b"redacted-fingerprint"),
            destination_status: "verified".into(),
            destination_observed_at: NOW,
            existing_pending_payout_minor: 0,
            approvals,
            stripe_api_version: API_VERSION.into(),
            balance_observed_at: NOW,
            response_digest: canonical::sha256(b"payout-evidence-response"),
            source: "stripe-api-and-approval-store".into(),
        };
        Fixture {
            policy,
            configuration,
            action,
            evidence,
        }
    }

    fn evaluate(fixture: &Fixture, aggregate: &PayoutAggregateSnapshot) -> PayoutDecision {
        evaluate_payout(&PayoutEvaluationContext {
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
    fn exact_payout_with_two_distinct_approvers_is_eligible() {
        let result = evaluate(&fixture(500), &PayoutAggregateSnapshot::default());
        assert_eq!(result.code, PayoutDecisionCode::PayoutAuthorized);
        let eligibility = result.eligibility.unwrap();
        assert_eq!(eligibility.available_after_minor, 1_500);
        assert_eq!(eligibility.approvals_consumed.len(), 2);
        assert_eq!(eligibility.reservations.len(), 5);
    }

    #[test]
    fn one_above_action_limit_and_one_below_retained_minimum_are_denied() {
        assert_eq!(
            evaluate(&fixture(501), &PayoutAggregateSnapshot::default()).code,
            PayoutDecisionCode::PayoutLimitExceeded
        );
        let fixture = fixture(500);
        let exact = PayoutAggregateSnapshot {
            held_minor_by_reservation: BTreeMap::from([(
                "balance:acct_payoutfixture:usd:bank_account".into(),
                1_000,
            )]),
        };
        assert_eq!(
            evaluate(&fixture, &exact).code,
            PayoutDecisionCode::PayoutAuthorized
        );
        let one_over = PayoutAggregateSnapshot {
            held_minor_by_reservation: BTreeMap::from([(
                "balance:acct_payoutfixture:usd:bank_account".into(),
                1_001,
            )]),
        };
        assert_eq!(
            evaluate(&fixture, &one_over).code,
            PayoutDecisionCode::PayoutMinimumBalanceViolated
        );
    }

    #[test]
    fn destination_substitution_and_disabled_destination_fail_closed() {
        let mut substituted = fixture(500);
        substituted.evidence.destination_external_account_id =
            ExternalAccountId::parse("ba_otherdestination").unwrap();
        assert_eq!(
            evaluate(&substituted, &PayoutAggregateSnapshot::default()).code,
            PayoutDecisionCode::PayoutEvidenceInvalid
        );
        let mut unavailable = fixture(500);
        unavailable.evidence.destination_status = "disabled".into();
        assert_eq!(
            evaluate(&unavailable, &PayoutAggregateSnapshot::default()).code,
            PayoutDecisionCode::PayoutDestinationUnavailable
        );
    }

    #[test]
    fn approvals_must_be_exact_distinct_scoped_and_fresh() {
        let mut missing = fixture(500);
        missing.evidence.approvals.pop();
        assert_eq!(
            evaluate(&missing, &PayoutAggregateSnapshot::default()).code,
            PayoutDecisionCode::PayoutApprovalRequired
        );
        let mut duplicate = fixture(500);
        duplicate.evidence.approvals[1].principal_commitment =
            duplicate.evidence.approvals[0].principal_commitment.clone();
        assert_eq!(
            evaluate(&duplicate, &PayoutAggregateSnapshot::default()).code,
            PayoutDecisionCode::PayoutApprovalRequired
        );
        let mut expired = fixture(500);
        expired.evidence.approvals[0].expires_at = NOW - 1;
        assert_eq!(
            evaluate(&expired, &PayoutAggregateSnapshot::default()).code,
            PayoutDecisionCode::PayoutApprovalRequired
        );
    }

    #[test]
    fn stale_balance_and_insufficient_balance_are_distinct() {
        let mut stale = fixture(500);
        stale.evidence.balance_observed_at = NOW - 61;
        assert_eq!(
            evaluate(&stale, &PayoutAggregateSnapshot::default()).code,
            PayoutDecisionCode::PayoutEvidenceStale
        );
        let mut insufficient = fixture(500);
        insufficient.evidence.available_balance_minor = 499;
        assert_eq!(
            evaluate(&insufficient, &PayoutAggregateSnapshot::default()).code,
            PayoutDecisionCode::PayoutBalanceInsufficient
        );
    }

    #[test]
    fn configuration_mismatch_precedes_destination_and_approval_checks() {
        let fixture = fixture(500);
        let other = StripePayoutConfigurationV1::new(
            &fixture.policy,
            StripeAccountId::parse("acct_otherpayout").unwrap(),
            "bank_account".into(),
            API_VERSION.into(),
            AUDIENCE.into(),
        )
        .unwrap();
        let result = evaluate_payout(&PayoutEvaluationContext {
            policy: &fixture.policy,
            action: &fixture.action,
            evidence: &fixture.evidence,
            aggregate: &PayoutAggregateSnapshot::default(),
            required_configuration: &fixture.configuration,
            executed_configuration: &other,
            request_audience: AUDIENCE,
            now: NOW,
        });
        assert_eq!(result.code, PayoutDecisionCode::PayoutConfigurationMismatch);
    }
}
