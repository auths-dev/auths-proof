//! Pure Stripe-specific containment checks.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use crate::types::{
    ExactRefundActionV1, RefundEvidenceV1, StripeVerifierConfiguration, ValidationError,
};

/// High-level product verdict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionClass {
    /// Every exact condition is satisfied.
    Authorized,
    /// Complete facts prove a mismatch.
    Denied,
    /// Fresh trustworthy evidence is unavailable.
    Indeterminate,
}

/// Stable Stripe-profile decision code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionCode {
    /// Every condition matched.
    Authorized,
    /// A closed value was invalid.
    InvalidInput,
    /// Required and executed configurations differ.
    VerifierConfigurationMismatch,
    /// Action does not commit to the required configuration.
    ActionConfigurationMismatch,
    /// Live-mode operation is forbidden.
    LiveModeDenied,
    /// Account or API version differs.
    StripeContextMismatch,
    /// Auths audience differs.
    AudienceMismatch,
    /// Evidence is stale or from the future.
    EvidenceStale,
    /// Action evidence commitment differs.
    EvidenceMismatch,
    /// Payment object identity differs.
    PaymentObjectMismatch,
    /// Charge is not safely refundable.
    ChargeNotRefundable,
    /// Currency differs.
    CurrencyMismatch,
    /// Amount exceeds evidence or policy.
    RefundAmountInvalid,
    /// Reason or metadata is outside policy.
    ParameterNotAuthorized,
    /// Connect side effects are forbidden.
    ConnectSideEffectDenied,
    /// Authorization expired.
    AuthorizationExpired,
}

/// Product decision with non-sensitive detail.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Decision {
    /// Broad result class.
    pub class: DecisionClass,
    /// Stable reason.
    pub code: DecisionCode,
    /// Concise factual explanation.
    pub detail: String,
}

impl Decision {
    fn authorized() -> Self {
        Self {
            class: DecisionClass::Authorized,
            code: DecisionCode::Authorized,
            detail: "the exact test-mode refund matches fresh Stripe evidence and policy".into(),
        }
    }

    fn denied(code: DecisionCode, detail: &'static str) -> Self {
        Self {
            class: DecisionClass::Denied,
            code,
            detail: detail.into(),
        }
    }

    fn indeterminate(code: DecisionCode, detail: &'static str) -> Self {
        Self {
            class: DecisionClass::Indeterminate,
            code,
            detail: detail.into(),
        }
    }
}

/// Borrowed inputs to the pure product decision.
pub struct EvaluationContext<'a> {
    /// Exact Auths action.
    pub action: &'a ExactRefundActionV1,
    /// Fresh normalized provider evidence.
    pub evidence: &'a RefundEvidenceV1,
    /// Configuration demanded by the caller/proof.
    pub required_configuration: &'a StripeVerifierConfiguration,
    /// Configuration actually loaded by the verifier/executor.
    pub executed_configuration: &'a StripeVerifierConfiguration,
    /// Exact request audience.
    pub request_audience: &'a str,
    /// Trusted Unix time.
    pub now: u64,
}

/// Evaluates exact-refund containment without side effects.
#[must_use]
pub fn evaluate(context: &EvaluationContext<'_>) -> Decision {
    for check in [
        check_configuration,
        check_time,
        check_stripe_context,
        check_evidence,
        check_money,
        check_parameters,
    ] {
        if let Err(decision) = check(context) {
            return decision;
        }
    }
    Decision::authorized()
}

fn check_configuration(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.action.validate().is_err()
        || context.required_configuration.validate().is_err()
        || context.executed_configuration.validate().is_err()
    {
        return Err(Decision::denied(
            DecisionCode::InvalidInput,
            "action or verifier configuration is invalid",
        ));
    }
    if context.required_configuration != context.executed_configuration {
        return Err(Decision::denied(
            DecisionCode::VerifierConfigurationMismatch,
            "required and executed verifier configurations differ",
        ));
    }
    let digest = context.required_configuration.digest().map_err(|_| {
        Decision::denied(DecisionCode::InvalidInput, "configuration is not canonical")
    })?;
    if !digest_eq(context.action.required_configuration_digest(), &digest) {
        return Err(Decision::denied(
            DecisionCode::ActionConfigurationMismatch,
            "the action commits to a different verifier configuration",
        ));
    }
    if context.request_audience != context.action.executor_audience()
        || context.request_audience != context.executed_configuration.executor_audience()
    {
        return Err(Decision::denied(
            DecisionCode::AudienceMismatch,
            "the request addresses a different executor",
        ));
    }
    Ok(())
}

fn check_time(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.now > context.action.expires_at() {
        return Err(Decision::denied(
            DecisionCode::AuthorizationExpired,
            "the exact refund authorization expired",
        ));
    }
    if context.action.expires_at() - context.action.observed_at()
        > context
            .executed_configuration
            .maximum_authorization_lifetime_seconds()
    {
        return Err(Decision::denied(
            DecisionCode::AuthorizationExpired,
            "the authorization lifetime exceeds verifier policy",
        ));
    }
    Ok(())
}

fn check_stripe_context(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.action.livemode() || context.evidence.livemode() {
        return Err(Decision::denied(
            DecisionCode::LiveModeDenied,
            "this profile is structurally restricted to Stripe test mode",
        ));
    }
    if context.action.stripe_account_id() != context.evidence.stripe_account_id()
        || context.action.stripe_api_version() != context.evidence.stripe_api_version()
        || !context
            .executed_configuration
            .allows_account(context.action.stripe_account_id())
        || !context
            .executed_configuration
            .allows_api_version(context.action.stripe_api_version())
    {
        return Err(Decision::denied(
            DecisionCode::StripeContextMismatch,
            "Stripe account or API version differs",
        ));
    }
    Ok(())
}

fn check_evidence(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    let age = context
        .now
        .checked_sub(context.evidence.observed_at())
        .ok_or_else(|| {
            Decision::indeterminate(
                DecisionCode::EvidenceStale,
                "Stripe evidence is from the future",
            )
        })?;
    if age
        > context
            .executed_configuration
            .maximum_evidence_age_seconds()
        || context.action.observed_at() != context.evidence.observed_at()
    {
        return Err(Decision::indeterminate(
            DecisionCode::EvidenceStale,
            "Stripe evidence is too old",
        ));
    }
    let digest = context.evidence.digest().map_err(|_| {
        Decision::indeterminate(DecisionCode::EvidenceMismatch, "evidence is not canonical")
    })?;
    if !digest_eq(context.action.evidence_digest(), &digest) {
        return Err(Decision::denied(
            DecisionCode::EvidenceMismatch,
            "the action commits to different Stripe evidence",
        ));
    }
    if context.action.charge_id() != context.evidence.charge_id()
        || context.action.payment_intent_id() != context.evidence.payment_intent_id()
    {
        return Err(Decision::denied(
            DecisionCode::PaymentObjectMismatch,
            "the Charge or PaymentIntent differs",
        ));
    }
    if !context.evidence.paid()
        || !context.evidence.captured()
        || context.evidence.charge_refunded()
        || context.evidence.disputed()
    {
        return Err(Decision::denied(
            DecisionCode::ChargeNotRefundable,
            "the fresh Charge state is not refundable under this profile",
        ));
    }
    Ok(())
}

fn check_money(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.action.amount().currency() != context.evidence.currency()
        || !context
            .executed_configuration
            .allows_currency(context.action.amount().currency())
    {
        return Err(Decision::denied(
            DecisionCode::CurrencyMismatch,
            "the refund currency differs from evidence or policy",
        ));
    }
    let expected_matches = context.action.expected_charge_amount_minor()
        == context.evidence.charge_amount_minor()
        && context.action.expected_amount_refunded_minor()
            == context.evidence.amount_refunded_minor()
        && context.action.expected_refundable_amount_minor()
            == context.evidence.refundable_amount_minor();
    let allowed_maximum = context
        .executed_configuration
        .maximum_refund_minor(context.action.amount().currency())
        .unwrap_or(0);
    if !expected_matches
        || context.action.amount().amount_minor() > context.evidence.refundable_amount_minor()
        || context.action.amount().amount_minor() > allowed_maximum
        || (!context.executed_configuration.allow_partial_refunds()
            && context.action.amount().amount_minor() != context.evidence.refundable_amount_minor())
    {
        return Err(Decision::denied(
            DecisionCode::RefundAmountInvalid,
            "the exact amount exceeds fresh evidence or verifier policy",
        ));
    }
    Ok(())
}

fn check_parameters(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.action.refund_application_fee()
        && !context
            .executed_configuration
            .allow_refund_application_fee()
        || context.action.reverse_transfer()
            && !context.executed_configuration.allow_reverse_transfer()
    {
        return Err(Decision::denied(
            DecisionCode::ConnectSideEffectDenied,
            "application-fee refund or transfer reversal is forbidden",
        ));
    }
    if !context
        .executed_configuration
        .allows_reason(context.action.reason())
        || context
            .action
            .metadata()
            .keys()
            .any(|key| !context.executed_configuration.allows_metadata_key(key))
    {
        return Err(Decision::denied(
            DecisionCode::ParameterNotAuthorized,
            "refund reason or metadata is outside verifier policy",
        ));
    }
    Ok(())
}

fn digest_eq(left: &crate::types::DigestHex, right: &crate::types::DigestHex) -> bool {
    bool::from(left.as_str().as_bytes().ct_eq(right.as_str().as_bytes()))
}

impl From<ValidationError> for Decision {
    fn from(_: ValidationError) -> Self {
        Self::denied(DecisionCode::InvalidInput, "invalid Stripe profile input")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{NOW, action, configuration, evidence};

    #[test]
    fn exact_refund_is_authorized() {
        let configuration = configuration(1_500);
        let evidence = evidence(2_000, 0);
        let action = action(&configuration, &evidence, 1_000);

        let decision = evaluate(&EvaluationContext {
            action: &action,
            evidence: &evidence,
            required_configuration: &configuration,
            executed_configuration: &configuration,
            request_audience: configuration.executor_audience(),
            now: NOW,
        });

        assert_eq!(decision.class, DecisionClass::Authorized);
        assert_eq!(decision.code, DecisionCode::Authorized);
    }

    #[test]
    fn one_minor_unit_over_policy_is_denied() {
        let configuration = configuration(1_000);
        let evidence = evidence(2_000, 0);
        let action = action(&configuration, &evidence, 1_001);

        let decision = evaluate(&EvaluationContext {
            action: &action,
            evidence: &evidence,
            required_configuration: &configuration,
            executed_configuration: &configuration,
            request_audience: configuration.executor_audience(),
            now: NOW,
        });

        assert_eq!(decision.code, DecisionCode::RefundAmountInvalid);
    }
}
