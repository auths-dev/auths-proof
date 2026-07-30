//! Pure create and read policy evaluation.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use crate::{
    BoundedRecordApiPolicyV1, CREATE_OPERATION, CreateRecordV1, READ_OPERATION, ReadRecordV1,
    RecordsApiVerifierConfigurationV1, canonical::canonical_json,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionClass {
    Authorized,
    Denied,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordsDecision {
    pub class: DecisionClass,
    pub code: String,
    pub stage: String,
}

impl RecordsDecision {
    #[must_use]
    pub fn authorized() -> Self {
        Self {
            class: DecisionClass::Authorized,
            code: "authorized".into(),
            stage: "policy".into(),
        }
    }

    #[must_use]
    pub fn denied(code: &str, stage: &str) -> Self {
        Self {
            class: DecisionClass::Denied,
            code: code.into(),
            stage: stage.into(),
        }
    }

    #[must_use]
    pub fn is_authorized(&self) -> bool {
        self.class == DecisionClass::Authorized
    }
}

pub struct CreateEvaluation<'a> {
    pub action: &'a CreateRecordV1,
    pub policy: &'a BoundedRecordApiPolicyV1,
    pub required_configuration: &'a RecordsApiVerifierConfigurationV1,
    pub executed_configuration: &'a RecordsApiVerifierConfigurationV1,
    pub now: u64,
}

pub struct ReadEvaluation<'a> {
    pub action: &'a ReadRecordV1,
    pub policy: &'a BoundedRecordApiPolicyV1,
    pub required_configuration: &'a RecordsApiVerifierConfigurationV1,
    pub executed_configuration: &'a RecordsApiVerifierConfigurationV1,
    pub now: u64,
}

#[must_use]
pub fn evaluate_create(context: &CreateEvaluation<'_>) -> RecordsDecision {
    if context.required_configuration != context.executed_configuration {
        return RecordsDecision::denied(
            "verifier-configuration-mismatch",
            "verifier-configuration",
        );
    }
    if context.action.validate().is_err()
        || context.policy.validate().is_err()
        || context.required_configuration.validate().is_err()
    {
        return RecordsDecision::denied("malformed-action", "canonical-action");
    }
    let Ok(configuration_digest) = context.required_configuration.digest() else {
        return RecordsDecision::denied("malformed-configuration", "verifier-configuration");
    };
    if !digest_eq(
        &context.action.required_configuration_digest,
        &configuration_digest,
    ) {
        return RecordsDecision::denied(
            "verifier-configuration-mismatch",
            "verifier-configuration",
        );
    }
    let Ok(policy_digest) = context.policy.digest() else {
        return RecordsDecision::denied("malformed-policy", "policy");
    };
    if !digest_eq(&context.action.policy_digest, &policy_digest) {
        return RecordsDecision::denied("policy-mismatch", "policy");
    }
    if !context
        .policy
        .allowed_operations
        .iter()
        .any(|operation| operation == CREATE_OPERATION)
    {
        return RecordsDecision::denied("operation-not-authorized", "policy");
    }
    if context.action.namespace_id != context.policy.namespace_id
        || !context.policy.allows_record(&context.action.record_id)
    {
        return RecordsDecision::denied("record-not-authorized", "policy");
    }
    if canonical_json(&context.action.customer).map_or(usize::MAX, |bytes| bytes.len())
        > usize::try_from(context.policy.maximum_value_bytes).unwrap_or(0)
    {
        return RecordsDecision::denied("value-limit-exceeded", "policy");
    }
    common_freshness(
        context.action.expires_at,
        &context.action.executor_audience,
        context.policy,
        context.now,
    )
}

#[must_use]
pub fn evaluate_read(context: &ReadEvaluation<'_>) -> RecordsDecision {
    if context.required_configuration != context.executed_configuration {
        return RecordsDecision::denied(
            "verifier-configuration-mismatch",
            "verifier-configuration",
        );
    }
    if context.action.validate().is_err()
        || context.policy.validate().is_err()
        || context.required_configuration.validate().is_err()
    {
        return RecordsDecision::denied("malformed-action", "canonical-action");
    }
    let Ok(configuration_digest) = context.required_configuration.digest() else {
        return RecordsDecision::denied("malformed-configuration", "verifier-configuration");
    };
    let Ok(policy_digest) = context.policy.digest() else {
        return RecordsDecision::denied("malformed-policy", "policy");
    };
    if !digest_eq(
        &context.action.required_configuration_digest,
        &configuration_digest,
    ) {
        return RecordsDecision::denied(
            "verifier-configuration-mismatch",
            "verifier-configuration",
        );
    }
    if !digest_eq(&context.action.policy_digest, &policy_digest) {
        return RecordsDecision::denied("policy-mismatch", "policy");
    }
    if !context
        .policy
        .allowed_operations
        .iter()
        .any(|operation| operation == READ_OPERATION)
    {
        return RecordsDecision::denied("operation-not-authorized", "policy");
    }
    if context.action.namespace_id != context.policy.namespace_id
        || !context.policy.allows_record(&context.action.record_id)
    {
        return RecordsDecision::denied("record-not-authorized", "policy");
    }
    if context.action.maximum_response_bytes > context.policy.maximum_response_bytes
        || context.action.allowed_fields.iter().any(|field| {
            context
                .policy
                .allowed_read_fields
                .binary_search(field)
                .is_err()
        })
    {
        return RecordsDecision::denied("disclosure-not-authorized", "policy");
    }
    common_freshness(
        context.action.expires_at,
        &context.action.executor_audience,
        context.policy,
        context.now,
    )
}

fn common_freshness(
    action_expires_at: u64,
    audience: &str,
    policy: &BoundedRecordApiPolicyV1,
    now: u64,
) -> RecordsDecision {
    if now < policy.valid_from
        || now > policy.expires_at
        || action_expires_at < now
        || action_expires_at > policy.expires_at
        || action_expires_at.saturating_sub(now) > policy.maximum_action_lifetime_seconds
    {
        return RecordsDecision::denied("authorization-expired", "freshness");
    }
    if audience != policy.executor_audience {
        return RecordsDecision::denied("executor-audience-mismatch", "audience");
    }
    RecordsDecision::authorized()
}

fn digest_eq(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CustomerRecordV1, ReadField, RecordIdentifier, demo_configuration};

    fn fixture() -> (CreateRecordV1, BoundedRecordApiPolicyV1) {
        let config = demo_configuration("https://records.auths.dev");
        let policy = BoundedRecordApiPolicyV1 {
            policy_type: "auths.demo.bounded-record-api-policy".into(),
            policy_version: 1,
            policy_id: "policy-1".into(),
            namespace_id: RecordIdentifier::parse("visitor-1").unwrap(),
            presenter_principal: "key:demo".into(),
            allowed_operations: vec![CREATE_OPERATION.into(), READ_OPERATION.into()],
            allowed_record_ids: Vec::new(),
            allowed_record_id_prefixes: vec!["demo-".into()],
            maximum_value_bytes: 1024,
            maximum_response_bytes: 4096,
            allowed_read_fields: vec![ReadField::Customer, ReadField::RecordId],
            maximum_creates: 3,
            maximum_reads: 3,
            maximum_created_bytes: 3072,
            maximum_disclosed_bytes: 12_288,
            fixed_and_rolling_budgets: Vec::new(),
            valid_from: 100,
            expires_at: 1_000,
            maximum_action_lifetime_seconds: 300,
            maximum_presentation_lifetime_seconds: 120,
            maximum_evidence_age_seconds: 60,
            executor_audience: "https://records.auths.dev".into(),
        };
        let action = CreateRecordV1 {
            profile: "auths.demo.records.create/1".into(),
            namespace_id: policy.namespace_id.clone(),
            record_id: RecordIdentifier::parse("demo-1").unwrap(),
            customer: CustomerRecordV1 {
                age: 25,
                name: "Bob".into(),
                notes: "Demo customer".into(),
                occupation: "Sales".into(),
            },
            value_encoding: "auths.demo.customer-record/1".into(),
            expected_absent: true,
            policy_digest: policy.digest().unwrap(),
            required_evaluator: "auths.records.create-evaluator/1".into(),
            required_configuration_digest: config.digest().unwrap(),
            executor_audience: policy.executor_audience.clone(),
            expires_at: 500,
            nonce: "0123456789abcdef".into(),
        };
        (action, policy)
    }

    #[test]
    fn configuration_regression_4096_vs_4097_denies() {
        let (action, policy) = fixture();
        let required = demo_configuration("https://records.auths.dev");
        let mut executed = required.clone();
        executed.maximum_response_bytes = 4097;
        let decision = evaluate_create(&CreateEvaluation {
            action: &action,
            policy: &policy,
            required_configuration: &required,
            executed_configuration: &executed,
            now: 200,
        });
        assert_eq!(decision.code, "verifier-configuration-mismatch");
        assert_eq!(decision.stage, "verifier-configuration");
    }
}
