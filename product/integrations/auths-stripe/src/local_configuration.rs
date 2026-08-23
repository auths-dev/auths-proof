//! Deployment-owned Stripe bounded-refund configuration.

#![forbid(unsafe_code)]
// Canonical configuration parsing uses one closed validation error family.
#![allow(clippy::missing_errors_doc)]

use crate::{
    ConnectScope, DigestHex, StripeBoundedEvaluatorConfigurationV1, StripeBoundedRefundPolicyV1,
    StripeVerifierConfiguration, canonical::canonical_json, types::ValidationError,
};
use auths_profile_runtime::ProfileConfigurationBinding;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

/// Exact protected evidence-broker contract. The broker owns the Stripe
/// runtime-read credential and signing key; the production agent receives
/// only signed bounded responses over an authenticated local socket.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StripeRefundEvidenceStoreV1 {
    schema: String,
    broker_socket_path: String,
    broker_uid: u32,
    agent_uid: u32,
    store_identity_sha256: DigestHex,
    reader_key_id: String,
    reader_public_key_base64url: String,
    maximum_snapshot_bytes: u32,
    maximum_age_seconds: u64,
    request_timeout_milliseconds: u32,
}

/// Exact deployment artifact shared by refund preparation and execution.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StripeRefundLocalAgentConfigurationV1 {
    schema: String,
    policy: StripeBoundedRefundPolicyV1,
    required_exact_configuration: StripeVerifierConfiguration,
    executed_exact_configuration: StripeVerifierConfiguration,
    required_bounded_configuration: StripeBoundedEvaluatorConfigurationV1,
    executed_bounded_configuration: StripeBoundedEvaluatorConfigurationV1,
    evidence_store: StripeRefundEvidenceStoreV1,
}

impl StripeRefundLocalAgentConfigurationV1 {
    /// Decodes canonical deployment bytes without permitting an implicit
    /// format or default. Protected helper processes use this path before a
    /// runtime binding exists.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| ValidationError::InvalidConfiguration)?;
        value.validate()?;
        if canonical_json(&value).map_err(|_| ValidationError::InvalidConfiguration)? != bytes {
            return Err(ValidationError::InvalidConfiguration);
        }
        Ok(value)
    }

    /// Decodes canonical deployment bytes and proves the whole AP-0012 policy,
    /// evaluator, exact-refund verifier, and protected evidence-store contract.
    pub fn from_binding(binding: &ProfileConfigurationBinding) -> Result<Self, ValidationError> {
        if binding.format() != "auths.stripe.refund-verifier-configuration/1" {
            return Err(ValidationError::InvalidConfiguration);
        }
        Self::from_canonical_bytes(binding.canonical_bytes())
    }

    /// Validates exact equality between required and executed configurations.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.policy
            .validate()
            .map_err(|_| ValidationError::InvalidConfiguration)?;
        self.required_exact_configuration.validate()?;
        self.executed_exact_configuration.validate()?;
        self.required_bounded_configuration
            .validate()
            .map_err(|_| ValidationError::InvalidConfiguration)?;
        self.executed_bounded_configuration
            .validate()
            .map_err(|_| ValidationError::InvalidConfiguration)?;
        let policy_digest = self
            .policy
            .digest()
            .map_err(|_| ValidationError::InvalidConfiguration)?;
        if self.schema != "auths.stripe.refund-verifier-configuration/1"
            || self.required_exact_configuration != self.executed_exact_configuration
            || self.required_bounded_configuration != self.executed_bounded_configuration
            || self.required_bounded_configuration.policy_digest() != &policy_digest
            || !matches!(self.policy.connect_scope(), ConnectScope::PlatformOnly)
            || self.required_exact_configuration.executor_audience()
                != self.required_bounded_configuration.executor_audience()
            || self.evidence_store.schema != "auths.stripe.refund-evidence-store/1"
            || !normalized_absolute_path(&self.evidence_store.broker_socket_path)
            || self.evidence_store.broker_uid == 0
            || self.evidence_store.agent_uid == 0
            || self.evidence_store.broker_uid == self.evidence_store.agent_uid
            || !registered_token(&self.evidence_store.reader_key_id, 128)
            || decode_public_key(&self.evidence_store.reader_public_key_base64url).is_err()
            || self.evidence_store.maximum_snapshot_bytes != 65_536
            || !(1_000..=30_000).contains(&self.evidence_store.request_timeout_milliseconds)
            || self.evidence_store.maximum_age_seconds != self.policy.maximum_evidence_age_seconds()
            || self.evidence_store.maximum_age_seconds
                != self
                    .required_exact_configuration
                    .maximum_evidence_age_seconds()
        {
            return Err(ValidationError::InvalidConfiguration);
        }
        Ok(())
    }

    #[must_use]
    pub const fn policy(&self) -> &StripeBoundedRefundPolicyV1 {
        &self.policy
    }

    #[must_use]
    pub const fn exact_configuration(&self) -> &StripeVerifierConfiguration {
        &self.executed_exact_configuration
    }

    #[must_use]
    pub const fn bounded_configuration(&self) -> &StripeBoundedEvaluatorConfigurationV1 {
        &self.executed_bounded_configuration
    }

    #[must_use]
    pub const fn evidence_store(&self) -> &StripeRefundEvidenceStoreV1 {
        &self.evidence_store
    }
}

impl StripeRefundEvidenceStoreV1 {
    /// Dedicated Unix socket owned by the separately credentialed reader.
    #[must_use]
    pub fn broker_socket_path(&self) -> &Path {
        Path::new(&self.broker_socket_path)
    }

    #[must_use]
    pub const fn broker_uid(&self) -> u32 {
        self.broker_uid
    }

    #[must_use]
    pub const fn agent_uid(&self) -> u32 {
        self.agent_uid
    }

    #[must_use]
    pub const fn store_identity_sha256(&self) -> &DigestHex {
        &self.store_identity_sha256
    }

    #[must_use]
    pub fn reader_key_id(&self) -> &str {
        &self.reader_key_id
    }

    pub fn reader_public_key(&self) -> Result<[u8; 32], ValidationError> {
        decode_public_key(&self.reader_public_key_base64url)
    }

    #[must_use]
    pub const fn maximum_snapshot_bytes(&self) -> usize {
        self.maximum_snapshot_bytes as usize
    }

    #[must_use]
    pub const fn maximum_age_seconds(&self) -> u64 {
        self.maximum_age_seconds
    }

    #[must_use]
    pub const fn request_timeout_milliseconds(&self) -> u32 {
        self.request_timeout_milliseconds
    }
}

fn decode_public_key(value: &str) -> Result<[u8; 32], ValidationError> {
    let mut bytes = [0_u8; 32];
    Base64UrlUnpadded::decode(value, &mut bytes)
        .map_err(|_| ValidationError::InvalidConfiguration)?;
    if bytes == [0; 32] || Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(ValidationError::InvalidConfiguration);
    }
    Ok(bytes)
}

fn registered_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn normalized_absolute_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= 1024
        && path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical::sha256, test_support};

    fn valid_configuration() -> StripeRefundLocalAgentConfigurationV1 {
        let evidence = test_support::evidence(10_000, 0);
        let exact = test_support::configuration(2_000);
        let policy = test_support::bounded_policy(
            &evidence,
            2_000,
            10_000,
            crate::RefundDenominator::OriginalChargeAmount,
            5_000,
        );
        let bounded = test_support::bounded_configuration(&policy);
        StripeRefundLocalAgentConfigurationV1 {
            schema: "auths.stripe.refund-verifier-configuration/1".into(),
            policy,
            required_exact_configuration: exact.clone(),
            executed_exact_configuration: exact,
            required_bounded_configuration: bounded.clone(),
            executed_bounded_configuration: bounded,
            evidence_store: StripeRefundEvidenceStoreV1 {
                schema: "auths.stripe.refund-evidence-store/1".into(),
                broker_socket_path: "/run/auths/stripe-refund-evidence.sock".into(),
                broker_uid: 1001,
                agent_uid: 1002,
                store_identity_sha256: sha256(b"protected Stripe evidence store"),
                reader_key_id: "stripe-runtime-reader-test-v1".into(),
                reader_public_key_base64url: Base64UrlUnpadded::encode_string(
                    &ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                maximum_snapshot_bytes: 65_536,
                maximum_age_seconds: 60,
                request_timeout_milliseconds: 30_000,
            },
        }
    }

    #[test]
    fn exact_deployment_configuration_is_valid() {
        valid_configuration().validate().unwrap();
    }

    #[test]
    fn required_and_executed_evaluators_cannot_drift() {
        let mut value = serde_json::to_value(valid_configuration()).unwrap();
        value["executedBoundedConfiguration"]["evaluator_implementation_id"] =
            serde_json::Value::String("different-reviewed-build".into());
        let changed: StripeRefundLocalAgentConfigurationV1 = serde_json::from_value(value).unwrap();
        assert_eq!(
            changed.validate(),
            Err(ValidationError::InvalidConfiguration)
        );
    }

    #[test]
    fn local_agent_rejects_connected_account_policy_without_a_header_path() {
        let mut value = serde_json::to_value(valid_configuration()).unwrap();
        value["policy"]["connect_scope"] = serde_json::json!({
            "kind": "connected-accounts",
            "account_ids": ["acct_connected_test"]
        });
        let changed: StripeRefundLocalAgentConfigurationV1 = serde_json::from_value(value).unwrap();
        assert_eq!(
            changed.validate(),
            Err(ValidationError::InvalidConfiguration)
        );
    }
}
