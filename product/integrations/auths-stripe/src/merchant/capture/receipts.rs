//! Canonical receipts owned by the exact final-capture profile.

use serde::{Deserialize, Serialize};

use super::{
    PaymentCaptureDecision, PaymentCaptureEvidenceV1, PaymentCaptureProviderProjection,
    StripeExactPaymentCaptureV1,
};
use crate::{
    canonical::{CanonicalError, canonical_digest},
    merchant::{
        MERCHANT_POLICY_PROVENANCE, MerchantAggregateSnapshot, MerchantOperation,
        MerchantReservationRecord, MerchantReservationState, StripeBoundedMerchantPaymentPolicyV1,
        StripeMerchantEvaluatorConfigurationV1,
    },
    types::DigestHex,
};

/// Exact proof plus immutable-policy final-capture decision.
#[allow(
    clippy::struct_excessive_bools,
    reason = "receipt trust-boundary facts remain independently explicit"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantCaptureDecisionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Durable capture workflow identity.
    pub workflow_id: String,
    /// Accurately labeled configured-policy provenance.
    pub policy_provenance: String,
    /// Complete immutable configured policy.
    pub policy: StripeBoundedMerchantPaymentPolicyV1,
    /// Canonical policy identity.
    pub policy_digest: DigestHex,
    /// Agent-selected exact final capture.
    pub exact_action: StripeExactPaymentCaptureV1,
    /// Canonical exact-action identity.
    pub action_digest: DigestHex,
    /// Fresh protected Stripe and durable-authorization evidence.
    pub evidence: PaymentCaptureEvidenceV1,
    /// Canonical evidence identity.
    pub evidence_digest: DigestHex,
    /// Aggregate settlement availability used by the evaluator.
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
    /// Pure Stripe-local bounded decision, when authority was established.
    pub bounded_decision: Option<PaymentCaptureDecision>,
    /// Credentials cannot have been requested at decision time.
    pub credential_requested: bool,
    /// Stripe cannot have been called at decision time.
    pub stripe_called: bool,
    /// Explicit trusted decision time.
    pub decided_at: u64,
}

impl MerchantCaptureDecisionReceipt {
    /// Returns the canonical decision commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Durable settlement reservation, provider, or atomic hold-release transition.
#[allow(
    clippy::struct_excessive_bools,
    reason = "receipt trust-boundary facts remain independently explicit"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantCaptureTransitionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Prior decision receipt commitment.
    pub decision_receipt_digest: DigestHex,
    /// Exact final-capture profile.
    pub exact_action_profile: String,
    /// Exact capture operation.
    pub operation: MerchantOperation,
    /// Exact capture action commitment.
    pub action_digest: DigestHex,
    /// Linked authorization action commitment.
    pub authorization_action_digest: DigestHex,
    /// Linked authorization reservation identity.
    pub authorization_reservation_id: DigestHex,
    /// Immutable configured-policy commitment.
    pub policy_digest: DigestHex,
    /// Required runtime configuration commitment.
    pub required_configuration_digest: DigestHex,
    /// Executed runtime configuration commitment.
    pub executed_configuration_digest: DigestHex,
    /// Literal capture transition.
    pub semantic_event: String,
    /// Destination derived by the capture-owned transition kernel.
    pub resulting_state: MerchantReservationState,
    /// Complete public capture reservation.
    pub capture_reservation: MerchantReservationRecord,
    /// Linked authorization after an atomic commit, when applicable.
    pub linked_authorization: Option<MerchantReservationRecord>,
    /// Settlement amount reserved or committed.
    pub settlement_amount_minor: u64,
    /// Full hold amount released only on committed final capture.
    pub authorization_release_minor: u64,
    /// Whether settlement commit and hold release happened in one store transaction.
    pub atomic_cross_budget_transition: bool,
    /// Exact Auths authority was established.
    pub authorization_established: bool,
    /// Protected execution has been attempted.
    pub execution_attempted: bool,
    /// Capture-scoped credential was requested.
    pub credential_requested: bool,
    /// A Stripe capture or retrieval call was attempted.
    pub stripe_called: bool,
    /// A normalized provider capture is durable.
    pub provider_accepted: bool,
    /// A later provider observation reconciled the effect.
    pub reconciled_observation: bool,
    /// Explicit trusted transition time.
    pub recorded_at: u64,
}

impl MerchantCaptureTransitionReceipt {
    /// Returns the canonical transition commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Fresh post-capture `PaymentIntent`, Charge, and balance observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantCaptureObservationReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Capture workflow identity.
    pub workflow_id: String,
    /// Exact final-capture profile.
    pub exact_action_profile: String,
    /// Exact capture operation.
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
    /// Durable capture reservation identity.
    pub reservation_id: DigestHex,
    /// Linked authorization reservation identity.
    pub authorization_reservation_id: DigestHex,
    /// Sanitized capture-owned Stripe observation.
    pub provider: PaymentCaptureProviderProjection,
    /// Exact provider/action/link equality.
    pub exact_provider_equality: bool,
    /// Settlement committed and hold released atomically.
    pub atomic_cross_budget_transition: bool,
    /// Observation reconciled previously ambiguous state.
    pub reconciled: bool,
    /// Explicit residual assumptions.
    pub residual_assumptions: Vec<String>,
    /// Explicit trusted observation time.
    pub recorded_at: u64,
}

impl MerchantCaptureObservationReceipt {
    /// Returns the canonical observation commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Closed receipt family owned by the exact final-capture profile.
///
/// Adding another Stripe profile does not add variants to this type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "receipt")]
pub enum MerchantCaptureReceipt {
    /// Exact proof and bounded capture decision.
    #[serde(rename = "merchant-capture-decision")]
    Decision(Box<MerchantCaptureDecisionReceipt>),
    /// Capture settlement or atomic hold-release transition.
    #[serde(rename = "merchant-capture-transition")]
    Transition(Box<MerchantCaptureTransitionReceipt>),
    /// Fresh post-capture provider observation.
    #[serde(rename = "merchant-capture-observation")]
    Observation(Box<MerchantCaptureObservationReceipt>),
}

impl MerchantCaptureReceipt {
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
            MerchantReservationRecord, PaymentCaptureDecision,
            StripeBoundedMerchantPaymentPolicyV1, StripeMerchantEvaluatorConfigurationV1,
        },
    };

    #[test]
    fn canonical_capture_fixture_corpus_is_exact_and_secret_free() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/merchant-capture/v1");
        let manifest_bytes = fs::read(root.join("manifest.sha256.json")).unwrap();
        let manifest: BTreeMap<String, DigestHex> =
            serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(canonical_json(&manifest).unwrap(), manifest_bytes);
        let expected = [
            "action.json",
            "aggregate-before.json",
            "attempting.json",
            "claimed.json",
            "committed.json",
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
            assert!(!text.contains("exact-payment-cancel"));
        }
    }

    #[test]
    fn canonical_capture_types_and_stable_codes_round_trip_exactly() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/merchant-capture/v1");
        round_trip::<StripeBoundedMerchantPaymentPolicyV1>(&root, "policy.json");
        round_trip::<StripeExactPaymentCaptureV1>(&root, "action.json");
        round_trip::<PaymentCaptureEvidenceV1>(&root, "evidence.json");
        round_trip::<StripeMerchantEvaluatorConfigurationV1>(&root, "configuration.json");
        round_trip::<PaymentCaptureDecision>(&root, "eligibility.json");
        round_trip::<MerchantCaptureDecisionReceipt>(&root, "decision-receipt.json");
        round_trip::<MerchantReservationRecord>(&root, "reservation.json");
        round_trip::<MerchantCaptureTransitionReceipt>(&root, "transition-receipt.json");
        round_trip::<MerchantCaptureObservationReceipt>(&root, "observation-receipt.json");

        let denials: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("denial-codes.json")).unwrap()).unwrap();
        let codes = denials["codes"].as_array().unwrap();
        assert_eq!(codes.len(), 20);
        assert!(
            codes
                .iter()
                .any(|code| code == "payment-authorization-link-mismatch")
        );
        assert!(
            codes
                .iter()
                .any(|code| code == "payment-capture-already-executed")
        );
        assert!(
            codes
                .iter()
                .any(|code| code == "payment-capture-window-expired")
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
