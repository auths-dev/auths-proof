//! Canonical receipts owned only by the payment-mandate profile.

use serde::{Deserialize, Serialize};

use super::{
    PaymentConsentEvidenceV1, PaymentMandateCapabilityRecord, PaymentMandateDecision,
    PaymentMandateEvidenceV1, PaymentMandateProviderProjection,
    StripeBoundedPaymentMandatePolicyV1, StripeExactPaymentMandateV1,
    StripePaymentMandateConfigurationV1,
};
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::DigestHex,
};

/// Exact proof, consent, policy, evidence, and configuration decision.
#[allow(
    clippy::struct_excessive_bools,
    reason = "trust-boundary facts stay explicit"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentMandateDecisionReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub policy: StripeBoundedPaymentMandatePolicyV1,
    pub policy_digest: DigestHex,
    pub exact_action: StripeExactPaymentMandateV1,
    pub action_digest: DigestHex,
    pub consent: Option<PaymentConsentEvidenceV1>,
    pub consent_digest: Option<DigestHex>,
    pub evidence: PaymentMandateEvidenceV1,
    pub evidence_digest: DigestHex,
    pub durable_active_before: u32,
    pub required_configuration: StripePaymentMandateConfigurationV1,
    pub executed_configuration: StripePaymentMandateConfigurationV1,
    pub configuration_equal: bool,
    pub auths_decision: String,
    pub auths_code: String,
    pub authorization_established: bool,
    pub bounded_decision: Option<PaymentMandateDecision>,
    pub consent_consumed: bool,
    pub capability_reserved: bool,
    pub credential_requested: bool,
    pub stripe_called: bool,
    pub no_immediate_charge: bool,
    pub decided_at: u64,
}

impl PaymentMandateDecisionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Durable capability transition.
#[allow(
    clippy::struct_excessive_bools,
    reason = "trust-boundary facts stay explicit"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentMandateTransitionReceipt {
    pub schema: String,
    pub decision_receipt_digest: DigestHex,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub semantic_event: String,
    pub capability: PaymentMandateCapabilityRecord,
    pub authorization_established: bool,
    pub consent_consumed: bool,
    pub capability_reserved: bool,
    pub execution_attempted: bool,
    pub credential_requested: bool,
    pub stripe_called: bool,
    pub provider_accepted: bool,
    pub no_immediate_charge: bool,
    pub recorded_at: u64,
}

impl PaymentMandateTransitionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Fresh sanitized `SetupIntent` observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentMandateObservationReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub decision_receipt_digest: DigestHex,
    pub capability_id: DigestHex,
    pub provider: PaymentMandateProviderProjection,
    pub exact_provider_equality: bool,
    pub reconciled: bool,
    pub client_secret_exposed: bool,
    pub no_immediate_charge: bool,
    pub residual_assumptions: Vec<String>,
    pub recorded_at: u64,
}

impl PaymentMandateObservationReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Closed receipt family. Adding another Stripe profile cannot add variants here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "receipt")]
pub enum PaymentMandateReceipt {
    #[serde(rename = "payment-mandate-decision")]
    Decision(Box<PaymentMandateDecisionReceipt>),
    #[serde(rename = "payment-mandate-transition")]
    Transition(Box<PaymentMandateTransitionReceipt>),
    #[serde(rename = "payment-mandate-observation")]
    Observation(Box<PaymentMandateObservationReceipt>),
}

impl PaymentMandateReceipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use super::*;
    use crate::{
        PaymentConsentEvidenceV1, PaymentMandateEvidenceV1, StripeBoundedPaymentMandatePolicyV1,
        StripeExactPaymentMandateV1, StripePaymentMandateConfigurationV1,
        canonical::{canonical_json, sha256},
    };

    #[test]
    fn canonical_fixture_corpus_is_exact_and_secret_free() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/payment-mandate/v1");
        let manifest_bytes = fs::read(root.join("manifest.sha256.json")).unwrap();
        let manifest: BTreeMap<String, DigestHex> =
            serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(canonical_json(&manifest).unwrap(), manifest_bytes);
        assert_eq!(
            manifest.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "action.json",
                "configuration.json",
                "consent.json",
                "evidence.json",
                "policy.json",
                "stable-codes.json",
            ]
        );
        for (name, digest) in manifest {
            let bytes = fs::read(root.join(name)).unwrap();
            assert_eq!(sha256(&bytes), digest);
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(canonical_json(&value).unwrap(), bytes);
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(!text.contains("\"client_secret\":"));
            assert!(!text.contains("sk_test_"));
            assert!(!text.contains("sk_live_"));
        }
    }

    #[test]
    fn canonical_mandate_types_round_trip() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/payment-mandate/v1");
        round_trip::<StripeExactPaymentMandateV1>(&root, "action.json");
        round_trip::<StripePaymentMandateConfigurationV1>(&root, "configuration.json");
        round_trip::<PaymentConsentEvidenceV1>(&root, "consent.json");
        round_trip::<PaymentMandateEvidenceV1>(&root, "evidence.json");
        round_trip::<StripeBoundedPaymentMandatePolicyV1>(&root, "policy.json");
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
