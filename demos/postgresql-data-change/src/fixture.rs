//! Deterministic scenarios and real Auths proof material.

use auths_apps_testkit::{ExactActionFixture, exact_action_fixture};
use auths_postgresql::{
    Decision, DigestHex, EvaluationContext, PgIdentifier, PostgresBoundedUpdateProfile,
    PostgresBoundedUpdateV1, PostgresEvidenceV1, PostgresVerifierConfigurationInput,
    PostgresVerifierConfigurationV1, RelationPolicyV1, TypedValueV1, ValueConstraintV1,
    ValueKindV1,
    canonical::{canonical_json, sha256},
    evaluate,
    test_support::{Fixture, fixture},
};
use auths_profile_api::ActionProfile as _;
use serde::Serialize;
use serde_json::Value;

/// Exact product fixture, real proof, and adversarial variants.
pub struct DemoFixture {
    pub product: Fixture,
    pub auths: ExactActionFixture,
    pub variants: Vec<DemoVariant>,
}

/// One visible experiment.
#[derive(Clone, Serialize)]
pub struct DemoVariant {
    pub id: String,
    pub label: String,
    pub description: String,
    pub action: PostgresBoundedUpdateV1,
    pub evidence: PostgresEvidenceV1,
    pub required_configuration: PostgresVerifierConfigurationV1,
    pub executed_configuration: PostgresVerifierConfigurationV1,
    pub required_configuration_digest: DigestHex,
    pub executed_configuration_digest: DigestHex,
    pub decision: Decision,
}

#[must_use]
pub fn demo_fixture(now: u64, challenge: [u8; 32]) -> DemoFixture {
    demo_fixture_from_product(fixture_at(now), now, challenge)
}

#[must_use]
pub fn demo_fixture_from_product(product: Fixture, now: u64, challenge: [u8; 32]) -> DemoFixture {
    let canonical = PostgresBoundedUpdateProfile
        .canonicalize(&product.action.canonical_bytes().unwrap())
        .unwrap();
    let auths = exact_action_fixture(
        &canonical,
        product.configuration.executor_audience(),
        now,
        challenge,
    );
    let variants = variants(&product, now);
    DemoFixture {
        product,
        auths,
        variants,
    }
}

#[must_use]
pub fn fixture_at(now: u64) -> Fixture {
    let mut product = fixture();
    product.evidence.observed_at = now;
    product.intent.expires_at = now.saturating_add(300);
    product.intent.nonce = format!("postgresql-demo-{now:020}");
    product.action = PostgresBoundedUpdateV1::build(
        product.intent.clone(),
        &product.evidence,
        &product.configuration,
    )
    .unwrap();
    product
}

pub fn fixture_from_evidence(
    evidence: PostgresEvidenceV1,
    now: u64,
) -> Result<Fixture, auths_postgresql::ValidationError> {
    let configuration = configuration_from_evidence(&evidence, 3)?;
    let reviewed = TypedValueV1::enum_text(identifier("review_status"), "reviewed")?;
    let rows = evidence
        .rows
        .iter()
        .map(|row| auths_postgresql::RowPreconditionV1 {
            primary_key: row.primary_key.clone(),
            before_value_commitments: row
                .before_values
                .iter()
                .map(|value| auths_postgresql::NamedCommitmentV1 {
                    column: value.column.clone(),
                    digest: auths_postgresql::canonical::canonical_digest(value)
                        .expect("serializable row value"),
                })
                .collect(),
            row_version: row.row_version,
        })
        .collect();
    let intent = auths_postgresql::PostgresBoundedUpdateIntentV1::new(
        auths_postgresql::PostgresBoundedUpdateIntentV1 {
            profile: String::new(),
            database_audience: evidence.database_audience.clone(),
            database_name: evidence.database_name.clone(),
            schema_name: evidence.schema_name.clone(),
            table_name: evidence.table_name.clone(),
            tenant_column: evidence.tenant_column.clone(),
            tenant_value: TypedValueV1::text("tenant-demo")?,
            primary_key_columns: evidence.primary_key_columns.clone(),
            rows,
            assignments: vec![auths_postgresql::AssignmentV1 {
                column: identifier("review_status"),
                value: reviewed,
            }],
            expected_row_count: 3,
            schema_fingerprint: evidence.schema_fingerprint.clone(),
            policy_fingerprint: evidence.policy_fingerprint.clone(),
            trigger_fingerprint: evidence.trigger_fingerprint.clone(),
            required_configuration_digest: DigestHex::from_bytes([0; 32]),
            expires_at: now.saturating_add(300),
            nonce: format!("postgresql-live-{now:020}"),
        },
        &configuration,
    )?;
    let action = PostgresBoundedUpdateV1::build(intent.clone(), &evidence, &configuration)?;
    Ok(Fixture {
        action,
        intent,
        evidence,
        configuration,
    })
}

pub fn configuration_from_evidence(
    evidence: &PostgresEvidenceV1,
    maximum_rows: u32,
) -> Result<PostgresVerifierConfigurationV1, auths_postgresql::ValidationError> {
    PostgresVerifierConfigurationV1::new(PostgresVerifierConfigurationInput {
        allowed_database_audiences: vec![evidence.database_audience.clone()],
        allowed_databases: vec![evidence.database_name.clone()],
        allowed_relations: vec![RelationPolicyV1 {
            database: evidence.database_name.clone(),
            schema: evidence.schema_name.clone(),
            table: evidence.table_name.clone(),
            tenant_column: evidence.tenant_column.clone(),
            primary_key_columns: evidence.primary_key_columns.clone(),
            row_version_column: evidence.row_version_column.clone(),
            assignment_constraints: vec![(
                identifier("review_status"),
                ValueConstraintV1 {
                    kind: ValueKindV1::EnumText,
                    nullable: false,
                    maximum_text_bytes: None,
                    decimal_precision: None,
                    decimal_scale: None,
                    timestamp_precision: None,
                    enum_name: Some(identifier("review_status")),
                    allowed_enum_values: vec!["pending".into(), "reviewed".into()],
                },
            )],
            allowed_trigger_fingerprints: vec![evidence.trigger_fingerprint.clone()],
        }],
        maximum_rows,
        maximum_evidence_age_seconds: 300,
        maximum_authorization_lifetime_seconds: 300,
        required_row_security: true,
        statement_timeout_ms: 5_000,
        lock_timeout_ms: 1_000,
        receipt_schema_version: "auths.postgresql.decision-receipt/1".into(),
        executor_audience: evidence.database_audience.clone(),
    })
}

fn variants(fixture: &Fixture, now: u64) -> Vec<DemoVariant> {
    let exact = variant(
        "exact",
        "Exact three-row transition",
        "Exactly three committed accounts move from pending to reviewed.",
        fixture.action.clone(),
        fixture.evidence.clone(),
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let mut extra_evidence = fixture.evidence.clone();
    let mut extra = extra_evidence.rows[2].clone();
    extra.primary_key[0].value =
        TypedValueV1::uuid("00000000-0000-0000-0000-000000000004").unwrap();
    extra.row_version = 4;
    extra_evidence.rows.push(extra);
    let extra_row = variant(
        "extra-row",
        "An extra row appears",
        "Protected discovery sees a fourth candidate outside the authorized row set.",
        fixture.action.clone(),
        extra_evidence,
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let mut tenant_evidence = fixture.evidence.clone();
    tenant_evidence.tenant_value_commitment =
        auths_postgresql::canonical::canonical_digest(&TypedValueV1::text("tenant-other").unwrap())
            .unwrap();
    let tenant = variant(
        "tenant-changed",
        "Tenant changed",
        "The observed tenant commitment differs from the exact action.",
        fixture.action.clone(),
        tenant_evidence,
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let mut before_evidence = fixture.evidence.clone();
    before_evidence.rows[0].before_values[0].value =
        TypedValueV1::enum_text(identifier("review_status"), "reviewed").unwrap();
    let before = variant(
        "before-changed",
        "A before value changed",
        "One row no longer has its committed pending state.",
        fixture.action.clone(),
        before_evidence,
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let forbidden_action = mutate_action(&fixture.action, |value| {
        value["intent"]["assignments"][0]["column"] = Value::from("email");
    });
    let forbidden = variant(
        "forbidden-column",
        "Forbidden column added",
        "The action attempts to change a column absent from the allowlist.",
        forbidden_action,
        fixture.evidence.clone(),
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let outside_action = mutate_action(&fixture.action, |value| {
        value["intent"]["assignments"][0]["value"]["value"]["value"] = Value::from("escalated");
    });
    let outside = variant(
        "value-outside-enum",
        "Value outside enum",
        "The proposed review state is not in the configured enum domain.",
        outside_action,
        fixture.evidence.clone(),
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let mut policy_evidence = fixture.evidence.clone();
    policy_evidence.policy_fingerprint = sha256(b"changed-policy");
    let policy = variant(
        "schema-policy-changed",
        "RLS policy changed",
        "The protected policy fingerprint differs from authorization.",
        fixture.action.clone(),
        policy_evidence,
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let configuration = variant(
        "configuration-changed",
        "Verifier ceiling changed",
        "The executor loads maximum_rows = 4 while the action requires 3.",
        fixture.action.clone(),
        fixture.evidence.clone(),
        fixture.configuration.clone(),
        configuration_from_evidence(&fixture.evidence, 4).unwrap(),
        now,
    );
    vec![
        exact,
        extra_row,
        tenant,
        before,
        forbidden,
        outside,
        policy,
        configuration,
    ]
}

#[allow(
    clippy::too_many_arguments,
    reason = "variant construction keeps every changed verifier input visible"
)]
fn variant(
    id: &str,
    label: &str,
    description: &str,
    action: PostgresBoundedUpdateV1,
    evidence: PostgresEvidenceV1,
    required_configuration: PostgresVerifierConfigurationV1,
    executed_configuration: PostgresVerifierConfigurationV1,
    now: u64,
) -> DemoVariant {
    let required_configuration_digest = required_configuration.digest().unwrap();
    let executed_configuration_digest = executed_configuration.digest().unwrap();
    let decision = evaluate(&EvaluationContext {
        action: &action,
        evidence: &evidence,
        required_configuration: &required_configuration,
        executed_configuration: &executed_configuration,
        request_audience: required_configuration.executor_audience(),
        now,
    });
    DemoVariant {
        id: id.into(),
        label: label.into(),
        description: description.into(),
        action,
        evidence,
        required_configuration,
        executed_configuration,
        required_configuration_digest,
        executed_configuration_digest,
        decision,
    }
}

fn mutate_action(
    action: &PostgresBoundedUpdateV1,
    mutate: impl FnOnce(&mut Value),
) -> PostgresBoundedUpdateV1 {
    let mut value = serde_json::to_value(action).unwrap();
    mutate(&mut value);
    PostgresBoundedUpdateV1::from_canonical_bytes(&canonical_json(&value).unwrap()).unwrap()
}

fn identifier(value: &str) -> PgIdentifier {
    PgIdentifier::parse(value).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_material_denials_are_visible() {
        let fixture = demo_fixture(auths_postgresql::test_support::NOW, [7; 32]);
        assert_eq!(fixture.variants[0].decision.code, "authorized");
        let codes = fixture
            .variants
            .iter()
            .skip(1)
            .map(|variant| variant.decision.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"row-set-mismatch"));
        assert!(codes.contains(&"tenant-mismatch"));
        assert!(codes.contains(&"before-state-mismatch"));
        assert!(codes.contains(&"column-not-authorized"));
        assert!(codes.contains(&"value-constraint-failed"));
        assert!(codes.contains(&"policy-fingerprint-mismatch"));
        assert!(codes.contains(&"verifier-configuration-mismatch"));
    }
}
