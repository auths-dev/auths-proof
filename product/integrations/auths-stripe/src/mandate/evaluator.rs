//! Pure bounded evaluator for future-payment capability creation.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use super::{
    PaymentConsentEvidenceV1, PaymentMandateEvidenceV1, StripeBoundedPaymentMandatePolicyV1,
    StripeExactPaymentMandateV1, StripePaymentMandateConfigurationV1,
};
use crate::{canonical::sha256, types::DigestHex};

/// Successful capability-slot calculation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentMandateEligibility {
    /// Active capabilities observed in protected Stripe evidence.
    pub provider_active_before: u32,
    /// Active or uncertain local capability slots.
    pub durable_active_before: u32,
    /// Inclusive configured capacity.
    pub active_capacity: u32,
    /// This reservation consumes exactly one capability slot.
    pub reserved_slots: u32,
}

/// Stable decision class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentMandateDecisionClass {
    Eligible,
    Denied,
    Indeterminate,
}

/// Stable evaluation stage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentMandateDecisionStage {
    Configuration,
    Policy,
    Action,
    Consent,
    Evidence,
    Scope,
    Capacity,
    Eligible,
}

/// Closed, stable V1 codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentMandateDecisionCode {
    Authorized,
    ConsentRequired,
    ConsentMismatch,
    ScopeExceeded,
    CapacityExceeded,
    ConfigurationMismatch,
    PolicyInactive,
    ActionExpired,
    ActionLifetimeExceeded,
    EvidenceStale,
    EvidenceMismatch,
    ProviderStateUnavailable,
    DuplicateSetup,
}

impl PaymentMandateDecisionCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "payment-mandate-authorized",
            Self::ConsentRequired => "payment-mandate-consent-required",
            Self::ConsentMismatch => "payment-mandate-consent-mismatch",
            Self::ScopeExceeded => "payment-mandate-scope-exceeded",
            Self::CapacityExceeded => "payment-mandate-capacity-exceeded",
            Self::ConfigurationMismatch => "bounded-configuration-mismatch",
            Self::PolicyInactive => "bounded-policy-inactive",
            Self::ActionExpired => "bounded-action-expired",
            Self::ActionLifetimeExceeded => "bounded-action-lifetime-exceeded",
            Self::EvidenceStale => "bounded-evidence-stale",
            Self::EvidenceMismatch => "bounded-evidence-mismatch",
            Self::ProviderStateUnavailable => "bounded-provider-state-unavailable",
            Self::DuplicateSetup => "payment-mandate-duplicate-setup",
        }
    }
}

/// Complete pure result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentMandateDecision {
    pub decision: PaymentMandateDecisionClass,
    pub code: String,
    pub stage: PaymentMandateDecisionStage,
    pub eligibility: Option<PaymentMandateEligibility>,
}

/// Explicit evaluator inputs.
pub struct PaymentMandateEvaluationContext<'a> {
    pub policy: &'a StripeBoundedPaymentMandatePolicyV1,
    pub action: &'a StripeExactPaymentMandateV1,
    pub consent: Option<&'a PaymentConsentEvidenceV1>,
    pub evidence: &'a PaymentMandateEvidenceV1,
    pub required_configuration: &'a StripePaymentMandateConfigurationV1,
    pub executed_configuration: &'a StripePaymentMandateConfigurationV1,
    pub durable_active_before: u32,
    pub now: u64,
}

/// Evaluates exact authority, trusted consent, Stripe evidence, and capacity.
#[must_use]
pub fn evaluate_payment_mandate(
    context: &PaymentMandateEvaluationContext<'_>,
) -> PaymentMandateDecision {
    let deny = |stage, code: PaymentMandateDecisionCode| PaymentMandateDecision {
        decision: PaymentMandateDecisionClass::Denied,
        code: code.as_str().into(),
        stage,
        eligibility: None,
    };
    let indeterminate = |stage, code: PaymentMandateDecisionCode| PaymentMandateDecision {
        decision: PaymentMandateDecisionClass::Indeterminate,
        code: code.as_str().into(),
        stage,
        eligibility: None,
    };

    if context.required_configuration != context.executed_configuration {
        return deny(
            PaymentMandateDecisionStage::Configuration,
            PaymentMandateDecisionCode::ConfigurationMismatch,
        );
    }
    if context.now < context.policy.valid_from() || context.now > context.policy.expires_at() {
        return deny(
            PaymentMandateDecisionStage::Policy,
            PaymentMandateDecisionCode::PolicyInactive,
        );
    }
    if context.action.expires_at() < context.now {
        return deny(
            PaymentMandateDecisionStage::Action,
            PaymentMandateDecisionCode::ActionExpired,
        );
    }
    if context.action.expires_at().saturating_sub(context.now)
        > context.policy.maximum_action_lifetime_seconds()
    {
        return deny(
            PaymentMandateDecisionStage::Action,
            PaymentMandateDecisionCode::ActionLifetimeExceeded,
        );
    }
    let Some(consent) = context.consent else {
        return deny(
            PaymentMandateDecisionStage::Consent,
            PaymentMandateDecisionCode::ConsentRequired,
        );
    };
    let Ok(consent_digest) = consent.digest() else {
        return indeterminate(
            PaymentMandateDecisionStage::Consent,
            PaymentMandateDecisionCode::ProviderStateUnavailable,
        );
    };
    let payment_method_commitment = sha256(context.action.payment_method_id().as_str().as_bytes());
    let consent_matches = digest_equal(context.action.consent_evidence_digest(), &consent_digest)
        && consent.customer_id() == context.action.customer_id()
        && digest_equal(
            consent.payment_method_commitment(),
            &payment_method_commitment,
        )
        && consent.stripe_account_id() == context.action.stripe_account_id()
        && consent.connect_account() == context.action.connect_account()
        && consent.usage() == context.action.usage()
        && consent.mandate_amount_type() == context.action.mandate_amount_type()
        && consent.mandate_amount_minor() == context.action.mandate_amount_minor()
        && consent.currency() == context.action.currency()
        && consent.interval() == context.action.interval()
        && consent.reference() == context.action.reference()
        && digest_equal(
            consent.displayed_terms_digest(),
            context.action.displayed_terms_digest(),
        )
        && consent.consent_assurance() >= context.policy.required_consent_assurance()
        && consent.accepted_at() <= context.now
        && consent.expires_at() >= context.now
        && context.now.saturating_sub(consent.accepted_at())
            <= context.policy.maximum_consent_age_seconds();
    if !consent_matches {
        return deny(
            PaymentMandateDecisionStage::Consent,
            PaymentMandateDecisionCode::ConsentMismatch,
        );
    }
    if context.evidence.observed_at() > context.now
        || context.now.saturating_sub(context.evidence.observed_at())
            > context.policy.maximum_evidence_age_seconds()
    {
        return deny(
            PaymentMandateDecisionStage::Evidence,
            PaymentMandateDecisionCode::EvidenceStale,
        );
    }
    if !context.evidence.customer_exists()
        || context.evidence.stripe_account_id() != context.action.stripe_account_id()
        || context.evidence.connect_account() != context.action.connect_account()
        || context.evidence.customer_id() != context.action.customer_id()
        || context.evidence.payment_method_id() != context.action.payment_method_id()
        || context.evidence.payment_method_customer_id() != context.action.customer_id()
        || context.evidence.payment_method_type() != context.action.payment_method_type()
        || context.evidence.stripe_api_version() != context.action.stripe_api_version()
        || context.evidence.livemode()
    {
        return deny(
            PaymentMandateDecisionStage::Evidence,
            PaymentMandateDecisionCode::EvidenceMismatch,
        );
    }
    if context.evidence.ambiguous_setup_exists() {
        return indeterminate(
            PaymentMandateDecisionStage::Evidence,
            PaymentMandateDecisionCode::ProviderStateUnavailable,
        );
    }
    if context.evidence.duplicate_scope_exists()
        || !context.evidence.existing_setup_intent_ids().is_empty()
    {
        return deny(
            PaymentMandateDecisionStage::Evidence,
            PaymentMandateDecisionCode::DuplicateSetup,
        );
    }
    let ceiling = context
        .policy
        .per_future_charge_minor_by_currency()
        .get(context.action.currency());
    let allowed = context
        .policy
        .allowed_test_account_ids()
        .binary_search(context.action.stripe_account_id())
        .is_ok()
        && context
            .policy
            .allowed_customer_ids()
            .binary_search(context.action.customer_id())
            .is_ok()
        && context
            .policy
            .allowed_payment_method_ids()
            .binary_search(context.action.payment_method_id())
            .is_ok()
        && context
            .policy
            .allowed_payment_method_types()
            .binary_search(&context.action.payment_method_type().to_owned())
            .is_ok()
        && context
            .policy
            .allowed_usage_modes()
            .binary_search(&context.action.usage())
            .is_ok()
        && context
            .policy
            .allowed_currencies()
            .binary_search(context.action.currency())
            .is_ok()
        && context
            .policy
            .allowed_intervals()
            .binary_search(&context.action.interval())
            .is_ok()
        && context
            .policy
            .allowed_api_versions()
            .binary_search(&context.action.stripe_api_version().to_owned())
            .is_ok()
        && ceiling.is_some_and(|value| context.action.mandate_amount_minor() <= *value)
        && context.action.required_policy_digest()
            == context.required_configuration.policy_digest()
        && context.action.required_configuration_digest()
            == &context
                .required_configuration
                .digest()
                .unwrap_or_else(|_| DigestHex::from_digest_bytes([0; 32]))
        && context.action.executor_audience() == context.required_configuration.executor_audience()
        && context.action.stripe_account_id() == context.required_configuration.stripe_account_id()
        && context.action.connect_account() == context.required_configuration.connect_account()
        && context.action.stripe_api_version()
            == context.required_configuration.stripe_api_version();
    if !allowed {
        return deny(
            PaymentMandateDecisionStage::Scope,
            PaymentMandateDecisionCode::ScopeExceeded,
        );
    }
    let active = context
        .evidence
        .active_mandate_count()
        .saturating_add(context.durable_active_before);
    if active >= context.policy.maximum_active_mandates_per_customer() {
        return deny(
            PaymentMandateDecisionStage::Capacity,
            PaymentMandateDecisionCode::CapacityExceeded,
        );
    }
    PaymentMandateDecision {
        decision: PaymentMandateDecisionClass::Eligible,
        code: PaymentMandateDecisionCode::Authorized.as_str().into(),
        stage: PaymentMandateDecisionStage::Eligible,
        eligibility: Some(PaymentMandateEligibility {
            provider_active_before: context.evidence.active_mandate_count(),
            durable_active_before: context.durable_active_before,
            active_capacity: context.policy.maximum_active_mandates_per_customer(),
            reserved_slots: 1,
        }),
    }
}

fn digest_equal(left: &DigestHex, right: &DigestHex) -> bool {
    left.as_str()
        .as_bytes()
        .ct_eq(right.as_str().as_bytes())
        .into()
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::{
        PaymentConsentEvidenceV1, PaymentMandateEvidenceV1, StripeBoundedPaymentMandatePolicyV1,
        StripeExactPaymentMandateV1, StripePaymentMandateConfigurationV1,
    };

    struct Fixture {
        policy: StripeBoundedPaymentMandatePolicyV1,
        action: StripeExactPaymentMandateV1,
        consent: PaymentConsentEvidenceV1,
        evidence: PaymentMandateEvidenceV1,
        configuration: StripePaymentMandateConfigurationV1,
    }

    impl Fixture {
        fn load() -> Self {
            let root =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/payment-mandate/v1");
            Self {
                policy: read(&root, "policy.json"),
                action: read(&root, "action.json"),
                consent: read(&root, "consent.json"),
                evidence: read(&root, "evidence.json"),
                configuration: read(&root, "configuration.json"),
            }
        }

        fn evaluate(
            &self,
            consent: Option<&PaymentConsentEvidenceV1>,
            durable_active_before: u32,
            executed: &StripePaymentMandateConfigurationV1,
        ) -> PaymentMandateDecision {
            evaluate_payment_mandate(&PaymentMandateEvaluationContext {
                policy: &self.policy,
                action: &self.action,
                consent,
                evidence: &self.evidence,
                required_configuration: &self.configuration,
                executed_configuration: executed,
                durable_active_before,
                now: 2_000_000_020,
            })
        }
    }

    #[test]
    fn exact_fixture_is_eligible() {
        let fixture = Fixture::load();
        assert_eq!(
            fixture
                .evaluate(Some(&fixture.consent), 0, &fixture.configuration)
                .code,
            "payment-mandate-authorized"
        );
    }

    #[test]
    fn missing_consent_and_capacity_fail_closed() {
        let fixture = Fixture::load();
        assert_eq!(
            fixture.evaluate(None, 0, &fixture.configuration).code,
            "payment-mandate-consent-required"
        );
        assert_eq!(
            fixture
                .evaluate(Some(&fixture.consent), 3, &fixture.configuration)
                .code,
            "payment-mandate-capacity-exceeded"
        );
    }

    #[test]
    fn terms_mutation_and_configuration_mismatch_are_distinct() {
        let fixture = Fixture::load();
        let mut consent_value = serde_json::to_value(&fixture.consent).unwrap();
        consent_value["displayed_terms_digest"] =
            serde_json::json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let changed_consent: PaymentConsentEvidenceV1 =
            serde_json::from_value(consent_value).unwrap();
        assert_eq!(
            fixture
                .evaluate(Some(&changed_consent), 0, &fixture.configuration)
                .code,
            "payment-mandate-consent-mismatch"
        );
        let mut config_value = serde_json::to_value(&fixture.configuration).unwrap();
        config_value["trusted_consent_context"] =
            serde_json::json!("changed-trusted-consent-context");
        let changed_config: StripePaymentMandateConfigurationV1 =
            serde_json::from_value(config_value).unwrap();
        assert_eq!(
            fixture
                .evaluate(Some(&fixture.consent), 0, &changed_config)
                .code,
            "bounded-configuration-mismatch"
        );
    }

    fn read<T: serde::de::DeserializeOwned>(root: &std::path::Path, name: &str) -> T {
        serde_json::from_slice(&fs::read(root.join(name)).unwrap()).unwrap()
    }
}
