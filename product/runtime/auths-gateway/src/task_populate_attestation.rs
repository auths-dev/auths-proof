//! Operator-pinned evidence from a credential-bearing child preflight.
//!
//! A provider vertical owns its read-only checks and signing key. This
//! verifier only binds the resulting facts to the task, immutable effect
//! plan, child and connection; it does not interpret provider response JSON.

use crate::task_effect_plan::{PopulatePreflightFacts, VerifiedEffectPlan};
use base64ct::{Base64Unpadded, Encoding as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::BTreeMap;

const SCHEMA: &str = "auths.gateway-task-populate-preflight/2";
const DOMAIN: &[u8] = b"auths.gateway-task-populate-preflight/2\0";
const MAX_REPORT_BYTES: usize = 8_192;
const MAX_VALIDITY_SECONDS: u64 = 90;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PopulatePreflightStatement {
    schema: String,
    task_id: String,
    task_commitment: String,
    plan_commitment: String,
    create_operation_id: String,
    child_id: String,
    populate_recipe_digest: String,
    preflight_rule_digest: String,
    connection_id: String,
    connection_generation: u64,
    connection_subject: String,
    provider_values: BTreeMap<String, String>,
    evidence_digests: BTreeMap<String, String>,
    checked_at: u64,
    valid_until: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedPopulatePreflight {
    statement: PopulatePreflightStatement,
    signature_b64: String,
}

pub(crate) struct ExpectedPopulatePreflight<'a> {
    pub(crate) task_id: &'a str,
    pub(crate) task_commitment: &'a str,
    pub(crate) child_id: &'a str,
    pub(crate) rule_digest: &'a str,
    pub(crate) plan: &'a VerifiedEffectPlan,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifiedPopulatePreflight {
    statement: PopulatePreflightStatement,
    signature_sha256: String,
}

impl PopulatePreflightStatement {
    fn valid_at(&self, now: u64) -> bool {
        (self.checked_at..self.valid_until).contains(&now)
    }
}

impl VerifiedPopulatePreflight {
    /// Recheck this signed evidence at the journal's current transaction time.
    pub(crate) fn valid_at(&self, now: u64) -> bool {
        self.statement.valid_at(now)
    }

    pub(crate) fn facts(&self) -> PopulatePreflightFacts<'_> {
        PopulatePreflightFacts {
            child_id: &self.statement.child_id,
            provider_values: &self.statement.provider_values,
            connection_subject: &self.statement.connection_subject,
            connection_generation: self.statement.connection_generation,
            checked_at: self.statement.checked_at,
            valid_until: self.statement.valid_until,
        }
    }

    pub(crate) fn matches_expected(&self, expected: &ExpectedPopulatePreflight<'_>) -> bool {
        statement_matches(&self.statement, expected) && valid_digest(&self.signature_sha256)
    }

    pub(crate) fn checked_at(&self) -> u64 {
        self.statement.checked_at
    }

    pub(crate) fn signature_sha256(&self) -> &str {
        &self.signature_sha256
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_provider_value(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn statement_matches(
    statement: &PopulatePreflightStatement,
    expected: &ExpectedPopulatePreflight<'_>,
) -> bool {
    let plan = expected.plan;
    statement.schema == SCHEMA
        && statement.task_id == expected.task_id
        && statement.task_commitment == expected.task_commitment
        && statement.plan_commitment == plan.plan_commitment
        && statement.create_operation_id == plan.create.operation_id
        && statement.child_id == expected.child_id
        && statement.populate_recipe_digest == plan.populate_recipe_digest
        && statement.preflight_rule_digest == expected.rule_digest
        && plan.preflight_rule_digest.as_deref() == Some(expected.rule_digest)
        && statement.connection_id == plan.create.connection_id
        && statement.connection_generation == plan.create.connection_generation
        && statement.connection_subject == plan.create.connection_subject
        && valid_id(&statement.child_id)
        && statement.provider_values.len() <= 4
        && statement
            .provider_values
            .iter()
            .all(|(name, value)| valid_name(name) && valid_provider_value(value, 256))
        && (1..=8).contains(&statement.evidence_digests.len())
        && statement.evidence_digests.contains_key("metadata")
        && statement
            .evidence_digests
            .iter()
            .all(|(name, digest)| valid_name(name) && valid_digest(digest))
        && valid_digest(&statement.preflight_rule_digest)
        && statement.checked_at < statement.valid_until
        && statement.valid_until <= plan.expires_at
        && statement.valid_until - statement.checked_at <= MAX_VALIDITY_SECONDS
}

/// Verify an exact canonical report from the operator-pinned preflight key.
/// The report cannot be supplied as authority by the agent or the provider.
pub(crate) fn verify_populate_preflight(
    report: &[u8],
    public_key_hex: &str,
    expected: &ExpectedPopulatePreflight<'_>,
    now: u64,
) -> Option<VerifiedPopulatePreflight> {
    if report.len() > MAX_REPORT_BYTES || report.is_empty() {
        return None;
    }
    let envelope: SignedPopulatePreflight = serde_json::from_slice(report).ok()?;
    if serde_json_canonicalizer::to_vec(&envelope).ok()? != report
        || !statement_matches(&envelope.statement, expected)
        || !envelope.statement.valid_at(now)
    {
        return None;
    }
    let key_bytes = hex::decode(public_key_hex).ok()?;
    if expected.plan.preflight_key_sha256.as_deref()
        != Some(hex::encode(sha2::Sha256::digest(&key_bytes)).as_str())
    {
        return None;
    }
    let key = VerifyingKey::from_bytes(&<[u8; 32]>::try_from(key_bytes.as_slice()).ok()?).ok()?;
    let signature_bytes = Base64Unpadded::decode_vec(&envelope.signature_b64).ok()?;
    let signature = Signature::from_slice(&signature_bytes).ok()?;
    let mut preimage = DOMAIN.to_vec();
    preimage.extend(serde_json_canonicalizer::to_vec(&envelope.statement).ok()?);
    key.verify_strict(&preimage, &signature).ok()?;
    Some(VerifiedPopulatePreflight {
        statement: envelope.statement,
        signature_sha256: hex::encode(sha2::Sha256::digest(signature_bytes)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_activation::TaskWriteVerb;
    use crate::task_write::ExactWriteIntent;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::Value;

    fn assert_retained_validity(
        verified: &VerifiedPopulatePreflight,
        report: &[u8],
        public: &str,
        expected: &ExpectedPopulatePreflight<'_>,
    ) {
        for now in [0, 99, 100, 110, 159, 160, 200, u64::MAX] {
            assert_eq!(
                verified.valid_at(now),
                verify_populate_preflight(report, public, expected, now).is_some(),
                "retained signed evidence must use the same validity boundary at {now}"
            );
        }
    }

    #[test]
    fn pinned_preflight_signature_and_task_scope_are_required() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let create = ExactWriteIntent {
            writer: crate::participant_enrollment::EnrolledParticipant::for_test(
                "test-agent",
                &[0xaa; 32],
                1,
                1,
            ),
            task_id: "task-1".into(),
            task_commitment: "a".repeat(64),
            operation_id: "create-1".into(),
            action_commitment: "b".repeat(64),
            request_commitment: "c".repeat(64),
            recipe_digest: "d".repeat(64),
            resource_handle: "parent-1".into(),
            verb: TaskWriteVerb::Create,
            connection_id: "connection-1".into(),
            connection_generation: 3,
            connection_subject: "jules".into(),
        };
        let plan = VerifiedEffectPlan {
            plan_commitment: "e".repeat(64),
            create,
            populate_recipe_digest: "f".repeat(64),
            populate_operation_id: "populate-1".into(),
            content_commitment: "1".repeat(64),
            content_length: 10,
            expires_at: 200,
            preflight_rule_digest: Some("2".repeat(64)),
            preflight_key_sha256: Some(hex::encode(sha2::Sha256::digest(
                key.verifying_key().to_bytes(),
            ))),
        };
        let expected = ExpectedPopulatePreflight {
            task_id: "task-1",
            task_commitment: &plan.create.task_commitment,
            child_id: "child-1",
            rule_digest: &"2".repeat(64),
            plan: &plan,
        };
        let statement = PopulatePreflightStatement {
            schema: SCHEMA.into(),
            task_id: "task-1".into(),
            task_commitment: "a".repeat(64),
            plan_commitment: "e".repeat(64),
            create_operation_id: "create-1".into(),
            child_id: "child-1".into(),
            populate_recipe_digest: "f".repeat(64),
            preflight_rule_digest: "2".repeat(64),
            connection_id: "connection-1".into(),
            connection_generation: 3,
            connection_subject: "jules".into(),
            provider_values: BTreeMap::from([
                ("required_revision_id".into(), "revision-1".into()),
                ("tab_id".into(), "t.0".into()),
            ]),
            evidence_digests: BTreeMap::from([
                ("metadata".into(), "3".repeat(64)),
                ("capability".into(), "4".repeat(64)),
                ("document".into(), "5".repeat(64)),
            ]),
            checked_at: 100,
            valid_until: 160,
        };
        let mut preimage = DOMAIN.to_vec();
        preimage.extend(serde_json_canonicalizer::to_vec(&statement).expect("statement"));
        let envelope = SignedPopulatePreflight {
            statement,
            signature_b64: Base64Unpadded::encode_string(&key.sign(&preimage).to_bytes()),
        };
        let report = serde_json_canonicalizer::to_vec(&envelope).expect("canonical report");
        let public = hex::encode(key.verifying_key().to_bytes());
        let verified = verify_populate_preflight(&report, &public, &expected, 110)
            .expect("pinned signed fresh report");
        assert_eq!(verified.facts().provider_values["tab_id"], "t.0");
        let mut simple = verified.statement.clone();
        simple.provider_values.clear();
        simple.evidence_digests = BTreeMap::from([("metadata".into(), "3".repeat(64))]);
        let mut simple_preimage = DOMAIN.to_vec();
        simple_preimage.extend(serde_json_canonicalizer::to_vec(&simple).expect("statement"));
        let simple_report = serde_json_canonicalizer::to_vec(&SignedPopulatePreflight {
            statement: simple.clone(),
            signature_b64: Base64Unpadded::encode_string(&key.sign(&simple_preimage).to_bytes()),
        })
        .expect("simple preflight report");
        assert!(
            verify_populate_preflight(&simple_report, &public, &expected, 110).is_some(),
            "a provider with no late-bound fields still supplies signed child metadata"
        );
        simple.evidence_digests.clear();
        let mut missing_preimage = DOMAIN.to_vec();
        missing_preimage.extend(serde_json_canonicalizer::to_vec(&simple).expect("statement"));
        let missing_report = serde_json_canonicalizer::to_vec(&SignedPopulatePreflight {
            statement: simple,
            signature_b64: Base64Unpadded::encode_string(&key.sign(&missing_preimage).to_bytes()),
        })
        .expect("missing metadata report");
        assert!(verify_populate_preflight(&missing_report, &public, &expected, 110).is_none());
        assert!(verify_populate_preflight(&report, &"9".repeat(64), &expected, 110).is_none());
        assert!(verify_populate_preflight(&report, &public, &expected, 160).is_none());
        assert_retained_validity(&verified, &report, &public, &expected);
        let mut changed: Value = serde_json::from_slice(&report).expect("report");
        changed["statement"]["child_id"] = "other-child".into();
        let altered = serde_json_canonicalizer::to_vec(&changed).expect("altered");
        assert!(verify_populate_preflight(&altered, &public, &expected, 110).is_none());
    }
}
