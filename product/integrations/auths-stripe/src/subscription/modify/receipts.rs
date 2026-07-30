//! Canonical receipts owned only by Subscription modification.

use serde::{Deserialize, Serialize};

use super::{
    StripeExactSubscriptionModifyV1, SubscriptionModificationRecord, SubscriptionModifyDecision,
    SubscriptionModifyEvidenceV1, SubscriptionModifyProviderProjection,
};
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    subscription::{StripeBoundedSubscriptionPolicyV1, StripeSubscriptionConfigurationV1},
    types::DigestHex,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionModifyDecisionReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub policy: StripeBoundedSubscriptionPolicyV1,
    pub policy_digest: DigestHex,
    pub exact_action: StripeExactSubscriptionModifyV1,
    pub action_digest: DigestHex,
    pub evidence: SubscriptionModifyEvidenceV1,
    pub evidence_digest: DigestHex,
    pub required_configuration: StripeSubscriptionConfigurationV1,
    pub executed_configuration: StripeSubscriptionConfigurationV1,
    pub configuration_equal: bool,
    pub auths_decision: String,
    pub auths_code: String,
    pub authorization_established: bool,
    pub bounded_decision: Option<SubscriptionModifyDecision>,
    pub incremental_recurring_reserved: bool,
    pub proration_debit_reserved: bool,
    pub credit_counted_as_capacity: bool,
    pub credential_requested: bool,
    pub stripe_called: bool,
    pub decided_at: u64,
}

impl SubscriptionModifyDecisionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionModifyTransitionReceipt {
    pub schema: String,
    pub decision_receipt_digest: DigestHex,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub semantic_event: String,
    pub modification: SubscriptionModificationRecord,
    pub old_liability_retained: bool,
    pub incremental_recurring_held: bool,
    pub proration_debit_held: bool,
    pub superseded_liability_released: bool,
    pub credential_requested: bool,
    pub stripe_called: bool,
    pub provider_accepted: bool,
    pub recorded_at: u64,
}

impl SubscriptionModifyTransitionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionModifyObservationReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub decision_receipt_digest: DigestHex,
    pub transition_id: DigestHex,
    pub provider: SubscriptionModifyProviderProjection,
    pub exact_after_items_observed: bool,
    pub pending_update_only: bool,
    pub update_applied: bool,
    pub invoice_payment_succeeded: bool,
    pub old_liability_retained: bool,
    pub new_liability_committed: bool,
    pub superseded_liability_released: bool,
    pub proration_credit_is_observation_only: bool,
    pub reconciled: bool,
    pub residual_assumptions: Vec<String>,
    pub recorded_at: u64,
}

impl SubscriptionModifyObservationReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Closed receipt family. Create/cancel cannot add variants.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "receipt")]
pub enum SubscriptionModifyReceipt {
    #[serde(rename = "subscription-modify-decision")]
    Decision(Box<SubscriptionModifyDecisionReceipt>),
    #[serde(rename = "subscription-modify-transition")]
    Transition(Box<SubscriptionModifyTransitionReceipt>),
    #[serde(rename = "subscription-modify-observation")]
    Observation(Box<SubscriptionModifyObservationReceipt>),
}

impl SubscriptionModifyReceipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use super::*;
    use crate::canonical::sha256;

    fn receipt_kind(receipt: &SubscriptionModifyReceipt) -> &'static str {
        match receipt {
            SubscriptionModifyReceipt::Decision(_) => "decision",
            SubscriptionModifyReceipt::Transition(_) => "transition",
            SubscriptionModifyReceipt::Observation(_) => "observation",
        }
    }

    #[test]
    fn receipt_family_is_closed_at_compile_time() {
        let _ = receipt_kind;
    }

    #[test]
    fn canonical_fixture_corpus_is_exact_and_secret_free() {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/subscription-modify/v1");
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
    fn canonical_modify_types_round_trip() {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/subscription-modify/v1");
        round_trip::<StripeExactSubscriptionModifyV1>(&root, "action.json");
        round_trip::<StripeSubscriptionConfigurationV1>(&root, "configuration.json");
        round_trip::<SubscriptionModifyEvidenceV1>(&root, "evidence.json");
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
