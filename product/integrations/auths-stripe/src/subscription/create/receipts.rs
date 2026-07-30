//! Canonical receipts owned only by subscription creation.

use serde::{Deserialize, Serialize};

use super::{StripeExactSubscriptionCreateV1, SubscriptionCreateDecision};
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    subscription::{
        StripeBoundedSubscriptionPolicyV1, StripeSubscriptionConfigurationV1,
        SubscriptionCreateEvidenceV1, SubscriptionLiabilityRecord, SubscriptionProviderProjection,
    },
    types::DigestHex,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCreateDecisionReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub policy: StripeBoundedSubscriptionPolicyV1,
    pub policy_digest: DigestHex,
    pub exact_action: StripeExactSubscriptionCreateV1,
    pub action_digest: DigestHex,
    pub evidence: SubscriptionCreateEvidenceV1,
    pub evidence_digest: DigestHex,
    pub required_configuration: StripeSubscriptionConfigurationV1,
    pub executed_configuration: StripeSubscriptionConfigurationV1,
    pub configuration_equal: bool,
    pub auths_decision: String,
    pub auths_code: String,
    pub authorization_established: bool,
    pub bounded_decision: Option<SubscriptionCreateDecision>,
    pub recurring_reserved: bool,
    pub immediate_reserved: bool,
    pub active_slot_reserved: bool,
    pub credential_requested: bool,
    pub stripe_called: bool,
    pub decided_at: u64,
}

impl SubscriptionCreateDecisionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCreateTransitionReceipt {
    pub schema: String,
    pub decision_receipt_digest: DigestHex,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub semantic_event: String,
    pub liability: SubscriptionLiabilityRecord,
    pub authorization_established: bool,
    pub active_slot_reserved: bool,
    pub recurring_reserved: bool,
    pub immediate_reserved: bool,
    pub credential_requested: bool,
    pub stripe_called: bool,
    pub provider_accepted: bool,
    pub recorded_at: u64,
}

impl SubscriptionCreateTransitionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCreateObservationReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub decision_receipt_digest: DigestHex,
    pub liability_id: DigestHex,
    pub provider: SubscriptionProviderProjection,
    pub exact_provider_equality: bool,
    pub first_invoice_collected: bool,
    pub recurring_liability_committed: bool,
    pub remaining_term_liability_minor: u64,
    pub remaining_cycles: u32,
    pub reconciled: bool,
    pub residual_assumptions: Vec<String>,
    pub recorded_at: u64,
}

impl SubscriptionCreateObservationReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Closed receipt family. Future modify/cancel profiles cannot add variants.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "receipt")]
pub enum SubscriptionCreateReceipt {
    #[serde(rename = "subscription-create-decision")]
    Decision(Box<SubscriptionCreateDecisionReceipt>),
    #[serde(rename = "subscription-create-transition")]
    Transition(Box<SubscriptionCreateTransitionReceipt>),
    #[serde(rename = "subscription-create-observation")]
    Observation(Box<SubscriptionCreateObservationReceipt>),
}

impl SubscriptionCreateReceipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use super::*;
    use crate::canonical::sha256;

    #[test]
    fn canonical_fixture_corpus_is_exact_and_secret_free() {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/subscription-create/v1");
        let manifest_bytes = fs::read(root.join("manifest.sha256.json")).unwrap();
        let manifest: BTreeMap<String, DigestHex> =
            serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(canonical_json(&manifest).unwrap(), manifest_bytes);
        for (name, digest) in manifest {
            let bytes = fs::read(root.join(name)).unwrap();
            assert_eq!(sha256(&bytes), digest);
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(canonical_json(&value).unwrap(), bytes);
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(!text.contains("\"client_secret\":"));
            assert!(!text.contains("sk_test_"));
            assert!(!text.contains("rk_test_"));
        }
    }

    #[test]
    fn canonical_subscription_types_round_trip() {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/subscription-create/v1");
        round_trip::<StripeExactSubscriptionCreateV1>(&root, "action.json");
        round_trip::<StripeSubscriptionConfigurationV1>(&root, "configuration.json");
        round_trip::<SubscriptionCreateEvidenceV1>(&root, "evidence.json");
        round_trip::<StripeBoundedSubscriptionPolicyV1>(&root, "policy.json");
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
