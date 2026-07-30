//! Fail-closed verification of an action against protected facts and policy.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use crate::{
    action::{PostgresBoundedUpdateV1, after_state_digest},
    canonical::canonical_digest,
    compiler::compile_statement,
    evidence::PostgresEvidenceV1,
    schema::{PostgresVerifierConfigurationV1, StableCode},
};

/// Public decision class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionClass {
    Authorized,
    Denied,
    Indeterminate,
}

/// Stable, stage-specific verifier outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub class: DecisionClass,
    pub code: String,
    pub stage: String,
}

impl Decision {
    fn deny(code: StableCode, stage: &str) -> Self {
        Self {
            class: DecisionClass::Denied,
            code: code.to_string(),
            stage: stage.into(),
        }
    }

    #[must_use]
    pub fn proof_denied() -> Self {
        Self::deny(StableCode::ProofInvalid, "proof")
    }

    #[must_use]
    pub fn proof_indeterminate() -> Self {
        Self {
            class: DecisionClass::Indeterminate,
            code: StableCode::ProofInvalid.to_string(),
            stage: "proof".into(),
        }
    }
}

/// Every input used by the verifier.
pub struct EvaluationContext<'a> {
    pub action: &'a PostgresBoundedUpdateV1,
    pub evidence: &'a PostgresEvidenceV1,
    pub required_configuration: &'a PostgresVerifierConfigurationV1,
    pub executed_configuration: &'a PostgresVerifierConfigurationV1,
    pub request_audience: &'a str,
    pub now: u64,
}

fn digest_eq(left: &crate::schema::DigestHex, right: &crate::schema::DigestHex) -> bool {
    bool::from(left.as_str().as_bytes().ct_eq(right.as_str().as_bytes()))
}

/// Evaluates cheap immutable policy before proof verification or claim.
#[must_use]
pub fn evaluate(context: &EvaluationContext<'_>) -> Decision {
    let action = context.action;
    let intent = &action.intent;
    let evidence = context.evidence;
    let required = context.required_configuration;
    let executed = context.executed_configuration;

    if action.validate().is_err() || evidence.validate().is_err() {
        return Decision::deny(StableCode::MalformedMutation, "canonical-action");
    }
    if required.validate().is_err() || executed.validate().is_err() || required != executed {
        return Decision::deny(
            StableCode::VerifierConfigurationMismatch,
            "verifier-configuration",
        );
    }
    let Ok(required_digest) = required.digest() else {
        return Decision::deny(StableCode::MalformedMutation, "configuration-digest");
    };
    if !digest_eq(&intent.required_configuration_digest, &required_digest) {
        return Decision::deny(
            StableCode::VerifierConfigurationMismatch,
            "verifier-configuration",
        );
    }
    if evidence.observed_at > context.now
        || action.observed_at != evidence.observed_at
        || intent.expires_at < context.now
        || intent.expires_at.saturating_sub(context.now)
            > executed.maximum_authorization_lifetime_seconds()
        || context.now.saturating_sub(evidence.observed_at)
            > executed.maximum_evidence_age_seconds()
    {
        return Decision::deny(StableCode::EvidenceStale, "freshness");
    }
    if intent.database_audience != context.request_audience
        || intent.database_audience != evidence.database_audience
        || !executed.allows_audience(&intent.database_audience)
    {
        return Decision::deny(StableCode::DatabaseAudienceMismatch, "database-audience");
    }
    if !executed.allows_database(&intent.database_name)
        || intent.database_name != evidence.database_name
    {
        return Decision::deny(StableCode::RelationMismatch, "database");
    }
    let Some(relation) = executed.relation(
        &intent.database_name,
        &intent.schema_name,
        &intent.table_name,
    ) else {
        return Decision::deny(StableCode::RelationMismatch, "relation-policy");
    };
    if intent.schema_name != evidence.schema_name
        || intent.table_name != evidence.table_name
        || intent.tenant_column != evidence.tenant_column
        || intent.tenant_column != relation.tenant_column
        || intent.primary_key_columns != evidence.primary_key_columns
        || intent.primary_key_columns != relation.primary_key_columns
        || action.relation_oid != evidence.relation_oid
        || action.executor_role != evidence.executor_role
        || action.database_server_identity != evidence.database_server_identity
    {
        return Decision::deny(StableCode::RelationMismatch, "relation-evidence");
    }
    if !digest_eq(&intent.schema_fingerprint, &evidence.schema_fingerprint) {
        return Decision::deny(StableCode::SchemaFingerprintMismatch, "schema");
    }
    if !digest_eq(&intent.policy_fingerprint, &evidence.policy_fingerprint) {
        return Decision::deny(StableCode::PolicyFingerprintMismatch, "row-security-policy");
    }
    if !digest_eq(&intent.trigger_fingerprint, &evidence.trigger_fingerprint)
        || relation
            .allowed_trigger_fingerprints
            .binary_search(&evidence.trigger_fingerprint)
            .is_err()
    {
        return Decision::deny(StableCode::TriggerFingerprintMismatch, "trigger-inventory");
    }
    if executed.required_row_security()
        && (!evidence.row_security_enabled
            || !evidence.row_security_forced
            || evidence.executor_owns_relation
            || evidence.executor_bypass_rls)
    {
        return Decision::deny(StableCode::PolicyFingerprintMismatch, "executor-role");
    }
    let Ok(tenant_commitment) = canonical_digest(&intent.tenant_value) else {
        return Decision::deny(StableCode::MalformedMutation, "tenant");
    };
    if !digest_eq(&tenant_commitment, &action.tenant_commitment)
        || !digest_eq(&tenant_commitment, &evidence.tenant_value_commitment)
    {
        return Decision::deny(StableCode::TenantMismatch, "tenant");
    }
    if intent.rows.len() > usize::try_from(executed.maximum_rows()).unwrap_or(0) {
        return Decision::deny(StableCode::RowLimitExceeded, "row-limit");
    }
    let Ok(row_set) = evidence.row_set_digest() else {
        return Decision::deny(StableCode::MalformedMutation, "row-set");
    };
    let intent_keys: Vec<_> = intent.rows.iter().map(|row| &row.primary_key).collect();
    let Ok(intent_row_set) = canonical_digest(&intent_keys) else {
        return Decision::deny(StableCode::MalformedMutation, "row-set");
    };
    if !digest_eq(&row_set, &action.row_set_digest)
        || !digest_eq(&intent_row_set, &action.row_set_digest)
    {
        return Decision::deny(StableCode::RowSetMismatch, "row-set");
    }
    for (precondition, observed) in intent.rows.iter().zip(&evidence.rows) {
        if precondition.primary_key != observed.primary_key
            || precondition.row_version != observed.row_version
            || precondition.before_value_commitments.len() != observed.before_values.len()
        {
            return Decision::deny(StableCode::BeforeStateMismatch, "before-state");
        }
        for (commitment, value) in precondition
            .before_value_commitments
            .iter()
            .zip(&observed.before_values)
        {
            let Ok(digest) = canonical_digest(value) else {
                return Decision::deny(StableCode::MalformedMutation, "before-state");
            };
            if commitment.column != value.column || !digest_eq(&commitment.digest, &digest) {
                return Decision::deny(StableCode::BeforeStateMismatch, "before-state");
            }
        }
    }
    let Ok(before_state) = evidence.before_state_digest() else {
        return Decision::deny(StableCode::MalformedMutation, "before-state");
    };
    if !digest_eq(&before_state, &action.before_state_digest) {
        return Decision::deny(StableCode::BeforeStateMismatch, "before-state");
    }
    for assignment in &intent.assignments {
        if assignment.column == intent.tenant_column
            || intent.primary_key_columns.contains(&assignment.column)
            || assignment.column == relation.row_version_column
        {
            return Decision::deny(StableCode::ColumnNotAuthorized, "assignment-column");
        }
        let Some(constraint) = relation
            .assignment_constraints
            .iter()
            .find(|(column, _)| column == &assignment.column)
            .map(|(_, constraint)| constraint)
        else {
            return Decision::deny(StableCode::ColumnNotAuthorized, "assignment-column");
        };
        let Some(column_evidence) = evidence
            .columns
            .iter()
            .find(|column| column.name == assignment.column)
        else {
            return Decision::deny(StableCode::ColumnNotAuthorized, "assignment-column");
        };
        if column_evidence.generated {
            return Decision::deny(StableCode::ColumnNotAuthorized, "assignment-column");
        }
        if assignment.value.validate(constraint).is_err() {
            return Decision::deny(StableCode::ValueConstraintFailed, "assignment-value");
        }
    }
    let Ok(derived_after_state) = after_state_digest(evidence, &intent.assignments) else {
        return Decision::deny(StableCode::MalformedMutation, "after-state");
    };
    if !digest_eq(&derived_after_state, &action.after_state_digest) {
        return Decision::deny(StableCode::AfterStateMismatch, "after-state");
    }
    let Ok(compiled) = compile_statement(intent, executed) else {
        return Decision::deny(StableCode::MalformedMutation, "statement-template");
    };
    if !digest_eq(
        &compiled.template_digest,
        &action.compiled_statement_template_digest,
    ) {
        return Decision::deny(
            StableCode::VerifierConfigurationMismatch,
            "statement-template",
        );
    }
    let Ok(evidence_digest) = evidence.digest() else {
        return Decision::deny(StableCode::MalformedMutation, "evidence");
    };
    if !digest_eq(&evidence_digest, &action.evidence_digest) {
        return Decision::deny(StableCode::BeforeStateMismatch, "evidence");
    }
    Decision {
        class: DecisionClass::Authorized,
        code: "authorized".into(),
        stage: "authorized".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fixture;

    #[test]
    fn exact_fixture_authorizes() {
        let fixture = fixture();
        assert_eq!(
            evaluate(&fixture.context()).class,
            DecisionClass::Authorized
        );
    }

    #[test]
    fn maximum_rows_mismatch_denies_before_effects() {
        let fixture = fixture();
        let executed = fixture.configuration_with_maximum_rows(4);
        let mut context = fixture.context();
        context.executed_configuration = &executed;
        let decision = evaluate(&context);
        assert_eq!(decision.class, DecisionClass::Denied);
        assert_eq!(decision.code, "verifier-configuration-mismatch");
        assert_eq!(decision.stage, "verifier-configuration");
    }

    #[test]
    fn changed_before_value_denies() {
        let mut fixture = fixture();
        fixture.evidence.rows[0].before_values[0].value =
            crate::value::TypedValueV1::text("tampered").unwrap();
        assert_eq!(evaluate(&fixture.context()).code, "before-state-mismatch");
    }

    #[test]
    fn changed_assignment_cannot_reuse_an_old_after_state_commitment() {
        let mut fixture = fixture();
        fixture.action.intent.assignments[0].value = crate::TypedValueV1::enum_text(
            crate::PgIdentifier::parse("review_status").expect("valid fixture identifier"),
            "pending",
        )
        .expect("valid fixture enum value");
        let decision = evaluate(&fixture.context());
        assert_eq!(decision.class, DecisionClass::Denied);
        assert_eq!(decision.code, "after-state-mismatch");
        assert_eq!(decision.stage, "after-state");
    }

    #[test]
    fn generated_assignment_target_denies() {
        let mut fixture = fixture();
        fixture
            .evidence
            .columns
            .iter_mut()
            .find(|column| column.name.as_str() == "review_status")
            .unwrap()
            .generated = true;
        let decision = evaluate(&fixture.context());
        assert_eq!(decision.code, "column-not-authorized");
        assert_eq!(decision.stage, "assignment-column");
    }

    #[test]
    fn powerful_executor_role_is_malformed_protected_evidence() {
        let mut fixture = fixture();
        fixture.evidence.executor_superuser = true;
        let decision = evaluate(&fixture.context());
        assert_eq!(decision.code, "malformed-mutation");
        assert_eq!(decision.stage, "canonical-action");
    }
}
