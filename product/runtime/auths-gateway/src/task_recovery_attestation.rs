//! Operator-attested, independently checked evidence for a response-less create.
//!
//! This is evidence about one candidate, not a child binding. A separate
//! native human recovery action and a fresh credential-bearing metadata read
//! are required before the task journal can grant a populate scope.

use crate::task_activation::{TaskPendingChild, TaskWriteVerb};
use crate::task_effect_plan::VerifiedEffectPlan;
use base64ct::{Base64Unpadded, Encoding as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

const SCHEMA: &str = "auths.gateway-task-create-recovery-attestation/1";
const DOMAIN: &[u8] = b"auths.gateway-task-create-recovery-attestation/1\0";
const MAX_REPORT_BYTES: usize = 8_192;
const MAX_VALIDITY_SECONDS: u64 = 180;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryStatement {
    schema: String,
    task_id: String,
    task_commitment: String,
    plan_commitment: String,
    content_commitment: String,
    create_operation_id: String,
    create_recipe_digest: String,
    action_commitment: String,
    request_commitment: String,
    candidate_id: String,
    parent_id: String,
    title: String,
    marker: String,
    connection_id: String,
    connection_generation: u64,
    connection_subject: String,
    recovery_rule_digest: String,
    search_report_sha256: String,
    producer_observation_sha256: String,
    baseline_sha256: String,
    candidate_metadata_sha256: String,
    checked_at: u64,
    valid_until: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedRecoveryAttestation {
    statement: RecoveryStatement,
    signature_b64: String,
}

pub(crate) struct ExpectedRecoveryAttestation<'a> {
    pub(crate) task_id: &'a str,
    pub(crate) task_commitment: &'a str,
    pub(crate) pending: &'a TaskPendingChild,
    pub(crate) plan: &'a VerifiedEffectPlan,
    pub(crate) public_key_sha256: &'a str,
    pub(crate) rule_digest: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedRecoveryAttestation {
    statement: RecoveryStatement,
    commitment: String,
}

impl VerifiedRecoveryAttestation {
    pub(crate) fn candidate_id(&self) -> &str {
        &self.statement.candidate_id
    }

    pub(crate) fn commitment(&self) -> &str {
        &self.commitment
    }

    pub(crate) fn valid_until(&self) -> u64 {
        self.statement.valid_until
    }

    pub(crate) fn search_report_sha256(&self) -> &str {
        &self.statement.search_report_sha256
    }

    pub(crate) fn producer_observation_sha256(&self) -> &str {
        &self.statement.producer_observation_sha256
    }

    pub(crate) fn candidate_metadata_sha256(&self) -> &str {
        &self.statement.candidate_metadata_sha256
    }

    pub(crate) fn baseline_sha256(&self) -> &str {
        &self.statement.baseline_sha256
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn matches_expected(
    statement: &RecoveryStatement,
    expected: &ExpectedRecoveryAttestation<'_>,
) -> bool {
    let create = &expected.plan.create;
    statement.schema == SCHEMA
        && create.task_id == expected.task_id
        && create.task_commitment == expected.task_commitment
        && create.resource_handle == expected.pending.parent_handle
        && create.verb == TaskWriteVerb::Create
        && statement.task_id == expected.task_id
        && statement.task_commitment == expected.task_commitment
        && statement.plan_commitment == expected.plan.plan_commitment
        && statement.content_commitment == expected.plan.content_commitment
        && statement.create_operation_id == create.operation_id
        && statement.create_recipe_digest == create.recipe_digest
        && statement.action_commitment == create.action_commitment
        && statement.request_commitment == create.request_commitment
        && statement.parent_id == expected.pending.parent_handle
        && statement.title == expected.pending.title
        && statement.marker == expected.pending.marker
        && statement.connection_id == create.connection_id
        && statement.connection_generation == create.connection_generation
        && statement.connection_subject == create.connection_subject
        && statement.recovery_rule_digest == expected.rule_digest
        && expected.pending.create_operation_id == create.operation_id
        && expected.pending.create_recipe_digest == create.recipe_digest
        && expected.pending.populate_recipe_digest == expected.plan.populate_recipe_digest
        && bounded_id(&statement.candidate_id)
        && [
            &statement.task_commitment,
            &statement.plan_commitment,
            &statement.content_commitment,
            &statement.create_recipe_digest,
            &statement.action_commitment,
            &statement.request_commitment,
            &statement.recovery_rule_digest,
            &statement.search_report_sha256,
            &statement.producer_observation_sha256,
            &statement.baseline_sha256,
            &statement.candidate_metadata_sha256,
        ]
        .into_iter()
        .all(|value| digest(value))
        && statement.checked_at < statement.valid_until
        && statement.valid_until <= expected.plan.expires_at
        && statement.valid_until - statement.checked_at <= MAX_VALIDITY_SECONDS
}

/// Verify a canonical attestation from a pinned operator key. This deliberately
/// does not verify the provider reports themselves or grant child authority.
/// The signer must first validate both complete source reports and their join.
pub(crate) fn verify_recovery_attestation(
    report: &[u8],
    public_key_hex: &str,
    expected: &ExpectedRecoveryAttestation<'_>,
    now: u64,
) -> Option<VerifiedRecoveryAttestation> {
    if report.is_empty() || report.len() > MAX_REPORT_BYTES {
        return None;
    }
    let envelope: SignedRecoveryAttestation = serde_json::from_slice(report).ok()?;
    if serde_json_canonicalizer::to_vec(&envelope).ok()? != report
        || !matches_expected(&envelope.statement, expected)
        || !(envelope.statement.checked_at..envelope.statement.valid_until).contains(&now)
    {
        return None;
    }
    let key_bytes = hex::decode(public_key_hex).ok()?;
    if hex::encode(sha2::Sha256::digest(&key_bytes)) != expected.public_key_sha256 {
        return None;
    }
    let key = VerifyingKey::from_bytes(&<[u8; 32]>::try_from(key_bytes.as_slice()).ok()?).ok()?;
    let signature_bytes = Base64Unpadded::decode_vec(&envelope.signature_b64).ok()?;
    let signature = Signature::from_slice(&signature_bytes).ok()?;
    let mut preimage = DOMAIN.to_vec();
    preimage.extend(serde_json_canonicalizer::to_vec(&envelope.statement).ok()?);
    key.verify_strict(&preimage, &signature).ok()?;
    Some(VerifiedRecoveryAttestation {
        commitment: hex::encode(sha2::Sha256::digest(report)),
        statement: envelope.statement,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_activation::TaskWriteVerb;
    use crate::task_write::ExactWriteIntent;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::Value;

    fn recovery_plan() -> (TaskPendingChild, VerifiedEffectPlan) {
        let pending = TaskPendingChild {
            create_operation_id: "create-1".into(),
            create_recipe_digest: "d".repeat(64),
            populate_recipe_digest: "e".repeat(64),
            parent_handle: "project-a".into(),
            title: "Handoff".into(),
            marker: "ap071_marker".into(),
        };
        let plan = VerifiedEffectPlan {
            plan_commitment: "b".repeat(64),
            create: ExactWriteIntent {
                task_id: "task-1".into(),
                task_commitment: "a".repeat(64),
                operation_id: "create-1".into(),
                action_commitment: "c".repeat(64),
                request_commitment: "f".repeat(64),
                recipe_digest: "d".repeat(64),
                resource_handle: "project-a".into(),
                verb: TaskWriteVerb::Create,
                connection_id: "connection-1".into(),
                connection_generation: 3,
                connection_subject: "jules".into(),
            },
            populate_recipe_digest: "e".repeat(64),
            populate_operation_id: "populate-1".into(),
            content_commitment: "1".repeat(64),
            content_length: 10,
            expires_at: 200,
            preflight_rule_digest: None,
            preflight_key_sha256: None,
        };
        (pending, plan)
    }

    fn recovery_statement() -> RecoveryStatement {
        RecoveryStatement {
            schema: SCHEMA.into(),
            task_id: "task-1".into(),
            task_commitment: "a".repeat(64),
            plan_commitment: "b".repeat(64),
            content_commitment: "1".repeat(64),
            create_operation_id: "create-1".into(),
            create_recipe_digest: "d".repeat(64),
            action_commitment: "c".repeat(64),
            request_commitment: "f".repeat(64),
            candidate_id: "child-1".into(),
            parent_id: "project-a".into(),
            title: "Handoff".into(),
            marker: "ap071_marker".into(),
            connection_id: "connection-1".into(),
            connection_generation: 3,
            connection_subject: "jules".into(),
            recovery_rule_digest: "6".repeat(64),
            search_report_sha256: "2".repeat(64),
            producer_observation_sha256: "3".repeat(64),
            baseline_sha256: "4".repeat(64),
            candidate_metadata_sha256: "5".repeat(64),
            checked_at: 100,
            valid_until: 160,
        }
    }

    #[test]
    fn recovery_attestation_binds_candidate_and_both_observations_to_original_plan() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let public_sha256 = hex::encode(sha2::Sha256::digest(key.verifying_key().to_bytes()));
        let rule_digest = "6".repeat(64);
        let (pending, plan) = recovery_plan();
        let expected = ExpectedRecoveryAttestation {
            task_id: "task-1",
            task_commitment: &plan.create.task_commitment,
            pending: &pending,
            plan: &plan,
            public_key_sha256: &public_sha256,
            rule_digest: &rule_digest,
        };
        let statement = recovery_statement();
        let mut preimage = DOMAIN.to_vec();
        preimage.extend(serde_json_canonicalizer::to_vec(&statement).expect("statement"));
        let report = serde_json_canonicalizer::to_vec(&SignedRecoveryAttestation {
            statement,
            signature_b64: Base64Unpadded::encode_string(&key.sign(&preimage).to_bytes()),
        })
        .expect("canonical report");
        let verified = verify_recovery_attestation(&report, &public, &expected, 110)
            .expect("fresh pinned report");
        assert_eq!(verified.candidate_id(), "child-1");
        assert_eq!(verified.search_report_sha256(), "2".repeat(64));
        assert_eq!(verified.producer_observation_sha256(), "3".repeat(64));
        assert_eq!(verified.candidate_metadata_sha256(), "5".repeat(64));
        assert_eq!(
            verified.commitment(),
            hex::encode(sha2::Sha256::digest(&report))
        );
        assert!(verify_recovery_attestation(&report, &public, &expected, 160).is_none());
        assert!(verify_recovery_attestation(&report, &"9".repeat(64), &expected, 110).is_none());
        let mut wrong_subject: SignedRecoveryAttestation =
            serde_json::from_slice(&report).expect("report");
        wrong_subject.statement.connection_subject = "other-employee".into();
        let mut wrong_preimage = DOMAIN.to_vec();
        wrong_preimage
            .extend(serde_json_canonicalizer::to_vec(&wrong_subject.statement).expect("statement"));
        wrong_subject.signature_b64 =
            Base64Unpadded::encode_string(&key.sign(&wrong_preimage).to_bytes());
        assert!(
            verify_recovery_attestation(
                &serde_json_canonicalizer::to_vec(&wrong_subject).expect("signed report"),
                &public,
                &expected,
                110,
            )
            .is_none()
        );
        let mut other_candidate: Value = serde_json::from_slice(&report).expect("report");
        other_candidate["statement"]["candidate_id"] = "child-2".into();
        assert!(
            verify_recovery_attestation(
                &serde_json_canonicalizer::to_vec(&other_candidate).expect("altered"),
                &public,
                &expected,
                110
            )
            .is_none()
        );
        let mut mismatched_plan = plan.clone();
        mismatched_plan.content_commitment = "8".repeat(64);
        mismatched_plan.plan_commitment = "8".repeat(64);
        let wrong_expected = ExpectedRecoveryAttestation {
            plan: &mismatched_plan,
            ..expected
        };
        assert!(verify_recovery_attestation(&report, &public, &wrong_expected, 110).is_none());
        let mut unrecognized: Value = serde_json::from_slice(&report).expect("report");
        unrecognized["statement"]["unreviewed_authority"] = true.into();
        let original_expected = ExpectedRecoveryAttestation {
            plan: &plan,
            ..wrong_expected
        };
        assert!(
            verify_recovery_attestation(
                &serde_json_canonicalizer::to_vec(&unrecognized).expect("unknown field"),
                &public,
                &original_expected,
                110,
            )
            .is_none()
        );
    }
}
