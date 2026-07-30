//! Canonical receipts for bounded Stripe merchant authorizations.

use serde::{Deserialize, Serialize};

use super::{PaymentAuthorizeDecision, StripeExactPaymentAuthorizeV1};
use crate::{
    canonical::{CanonicalError, canonical_digest},
    merchant::{
        MERCHANT_POLICY_PROVENANCE, MerchantAggregateSnapshot, MerchantOperation,
        MerchantPaymentEvidenceV1, StripeBoundedMerchantPaymentPolicyV1,
        StripeMerchantEvaluatorConfigurationV1,
        state::{MerchantProviderProjection, MerchantReservationRecord, MerchantReservationState},
    },
    types::DigestHex,
};

/// Exact proof plus immutable-policy authorization decision.
#[allow(
    clippy::struct_excessive_bools,
    reason = "receipt trust-boundary facts remain independently explicit"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantAuthorizationDecisionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Durable workflow identity.
    pub workflow_id: String,
    /// Accurate V1 configured-policy provenance.
    pub policy_provenance: String,
    /// Complete immutable configured policy.
    pub policy: StripeBoundedMerchantPaymentPolicyV1,
    /// Canonical policy identity.
    pub policy_digest: DigestHex,
    /// Agent-selected exact manual-capture authorization hold.
    pub exact_action: StripeExactPaymentAuthorizeV1,
    /// Canonical exact-action identity.
    pub action_digest: DigestHex,
    /// Fresh protected Stripe and order evidence.
    pub evidence: MerchantPaymentEvidenceV1,
    /// Canonical evidence identity.
    pub evidence_digest: DigestHex,
    /// Aggregate availability used by the pure evaluator.
    pub aggregate_before: MerchantAggregateSnapshot,
    /// Required evaluator/runtime configuration.
    pub required_configuration: StripeMerchantEvaluatorConfigurationV1,
    /// Configuration actually executed.
    pub executed_configuration: StripeMerchantEvaluatorConfigurationV1,
    /// Literal canonical equality result.
    pub configuration_equal: bool,
    /// Exact Auths proof result.
    pub auths_decision: String,
    /// Stable Auths decision code.
    pub auths_code: String,
    /// Whether exact authority was established.
    pub authorization_established: bool,
    /// Pure Stripe-local bounded decision, when exact authority was established.
    pub bounded_decision: Option<PaymentAuthorizeDecision>,
    /// Credentials cannot have been requested at decision time.
    pub credential_requested: bool,
    /// Stripe cannot have been called at decision time.
    pub stripe_called: bool,
    /// Explicit trusted decision time.
    pub decided_at: u64,
}

impl MerchantAuthorizationDecisionReceipt {
    /// Returns the canonical decision commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Durable reservation, claim, attempt, or provider transition.
#[allow(
    clippy::struct_excessive_bools,
    reason = "receipt trust-boundary facts remain independently explicit"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantAuthorizationTransitionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Prior decision receipt commitment.
    pub decision_receipt_digest: DigestHex,
    /// Exact authorization profile.
    pub exact_action_profile: String,
    /// Exact authorization operation.
    pub operation: MerchantOperation,
    /// Exact action commitment.
    pub action_digest: DigestHex,
    /// Immutable configured-policy commitment.
    pub policy_digest: DigestHex,
    /// Required runtime configuration commitment.
    pub required_configuration_digest: DigestHex,
    /// Executed runtime configuration commitment.
    pub executed_configuration_digest: DigestHex,
    /// Literal transition name.
    pub semantic_event: String,
    /// Destination derived by the closed transition kernel.
    pub resulting_state: MerchantReservationState,
    /// Complete public durable record.
    pub reservation: MerchantReservationRecord,
    /// Exact Auths authority was established.
    pub authorization_established: bool,
    /// Protected execution has been attempted.
    pub execution_attempted: bool,
    /// Restricted credential was requested.
    pub credential_requested: bool,
    /// A Stripe provider call was attempted.
    pub stripe_called: bool,
    /// A normalized provider acceptance is durable.
    pub provider_accepted: bool,
    /// A later provider observation has reconciled the effect.
    pub reconciled_observation: bool,
    /// Explicit trusted transition time.
    pub recorded_at: u64,
}

impl MerchantAuthorizationTransitionReceipt {
    /// Returns the canonical transition commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Fresh retrieval or webhook observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantAuthorizationObservationReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Workflow identity.
    pub workflow_id: String,
    /// Exact authorization profile.
    pub exact_action_profile: String,
    /// Exact authorization operation.
    pub operation: MerchantOperation,
    /// Exact action commitment.
    pub action_digest: DigestHex,
    /// Prior decision receipt commitment.
    pub decision_receipt_digest: DigestHex,
    /// Immutable configured-policy commitment.
    pub policy_digest: DigestHex,
    /// Required runtime configuration commitment.
    pub required_configuration_digest: DigestHex,
    /// Executed runtime configuration commitment.
    pub executed_configuration_digest: DigestHex,
    /// Durable reservation identity.
    pub reservation_id: DigestHex,
    /// Sanitized Stripe observation.
    pub provider: MerchantProviderProjection,
    /// Whether exact action and amount equality were established.
    pub exact_provider_equality: bool,
    /// Observation reconciled durable state.
    pub reconciled: bool,
    /// Explicit residual assumptions.
    pub residual_assumptions: Vec<String>,
    /// Explicit trusted observation time.
    pub recorded_at: u64,
}

impl MerchantAuthorizationObservationReceipt {
    /// Returns the canonical observation commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Closed receipt family owned by the exact authorization profile.
///
/// Adding another Stripe profile does not add variants to this type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "receipt")]
pub enum MerchantAuthorizationReceipt {
    /// Exact proof and bounded authorization decision.
    #[serde(rename = "merchant-authorization-decision")]
    Decision(Box<MerchantAuthorizationDecisionReceipt>),
    /// Authorization reservation, claim, provider, or terminal transition.
    #[serde(rename = "merchant-authorization-transition")]
    Transition(Box<MerchantAuthorizationTransitionReceipt>),
    /// Fresh authorization provider observation.
    #[serde(rename = "merchant-authorization-observation")]
    Observation(Box<MerchantAuthorizationObservationReceipt>),
}

impl MerchantAuthorizationReceipt {
    /// Returns canonical receipt bytes.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        crate::canonical::canonical_json(self)
    }
}

/// Produces the accurately labeled configured-policy provenance.
#[must_use]
pub fn merchant_policy_provenance() -> String {
    MERCHANT_POLICY_PROVENANCE.into()
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use super::*;
    use crate::{
        canonical::{canonical_json, sha256},
        merchant::{
            MerchantPaymentEvidenceV1, MerchantReservationRecord, PaymentAuthorizeDecision,
            StripeBoundedMerchantPaymentPolicyV1, StripeExactPaymentAuthorizeV1,
            StripeMerchantEvaluatorConfigurationV1,
        },
    };

    #[test]
    fn canonical_authorization_fixture_corpus_is_exact_and_secret_free() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/merchant-authorize/v1");
        let manifest_bytes = fs::read(root.join("manifest.sha256.json")).unwrap();
        let manifest: BTreeMap<String, DigestHex> =
            serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(canonical_json(&manifest).unwrap(), manifest_bytes);
        let expected = [
            "action.json",
            "aggregate-before.json",
            "attempting.json",
            "authorized.json",
            "claimed.json",
            "configuration.json",
            "decision-receipt.json",
            "denial-codes.json",
            "eligibility.json",
            "evidence.json",
            "observation-receipt.json",
            "policy.json",
            "provider-accepted.json",
            "replay.json",
            "reservation.json",
            "transition-receipt.json",
        ];
        assert_eq!(
            manifest.keys().map(String::as_str).collect::<Vec<_>>(),
            expected
        );
        for (name, digest) in manifest {
            let bytes = fs::read(root.join(name)).unwrap();
            assert_eq!(sha256(&bytes), digest);
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(canonical_json(&value).unwrap(), bytes);
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(!text.contains("\"client_secret\":"));
            assert!(!text.contains("sk_live_"));
            assert!(!text.contains("sk_test_"));
            assert!(!text.contains("bounded-refund"));
            assert!(!text.contains("exact-refund"));
        }
    }

    #[test]
    fn canonical_authorization_types_and_stable_codes_round_trip_exactly() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/merchant-authorize/v1");
        round_trip::<StripeBoundedMerchantPaymentPolicyV1>(&root, "policy.json");
        round_trip::<StripeExactPaymentAuthorizeV1>(&root, "action.json");
        round_trip::<MerchantPaymentEvidenceV1>(&root, "evidence.json");
        round_trip::<StripeMerchantEvaluatorConfigurationV1>(&root, "configuration.json");
        round_trip::<PaymentAuthorizeDecision>(&root, "eligibility.json");
        round_trip::<MerchantAuthorizationDecisionReceipt>(&root, "decision-receipt.json");
        round_trip::<MerchantReservationRecord>(&root, "reservation.json");
        round_trip::<MerchantAuthorizationTransitionReceipt>(&root, "transition-receipt.json");
        round_trip::<MerchantAuthorizationObservationReceipt>(&root, "observation-receipt.json");

        let denials: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("denial-codes.json")).unwrap()).unwrap();
        let codes = denials["codes"].as_array().unwrap();
        assert_eq!(codes.len(), 20);
        assert!(
            codes
                .iter()
                .any(|code| code == "bounded-configuration-mismatch")
        );
        assert!(
            codes
                .iter()
                .any(|code| code == "payment-authorization-limit-exceeded")
        );
        assert!(
            codes
                .iter()
                .any(|code| code == "payment-authorization-already-exists")
        );
        assert!(
            codes
                .iter()
                .any(|code| code == "payment-method-capture-unsupported")
        );
    }

    fn round_trip<T>(root: &std::path::Path, name: &str)
    where
        T: serde::de::DeserializeOwned + serde::Serialize,
    {
        let bytes = fs::read(root.join(name)).unwrap();
        let value: T = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(canonical_json(&value).unwrap(), bytes);
    }
}
