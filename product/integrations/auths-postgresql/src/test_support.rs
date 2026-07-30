//! Deterministic bounded-update fixtures.

use crate::{
    action::{PostgresBoundedUpdateIntentV1, PostgresBoundedUpdateV1, RowPreconditionV1},
    canonical::{canonical_digest, sha256},
    decision::EvaluationContext,
    evidence::{ColumnEvidenceV1, ObservedRowV1, PostgresEvidenceV1},
    schema::{
        DigestHex, PgIdentifier, PostgresVerifierConfigurationInput,
        PostgresVerifierConfigurationV1, RelationPolicyV1, ValueConstraintV1, ValueKindV1,
    },
    value::{AssignmentV1, NamedCommitmentV1, NamedValueV1, TypedValueV1},
};

pub const NOW: u64 = 1_800_000_000;
pub const AUDIENCE: &str = "https://postgresql.demo.auths.dev";

fn identifier(value: &str) -> PgIdentifier {
    PgIdentifier::parse(value).unwrap()
}

/// Complete exact three-row fixture.
pub struct Fixture {
    pub action: PostgresBoundedUpdateV1,
    pub intent: PostgresBoundedUpdateIntentV1,
    pub evidence: PostgresEvidenceV1,
    pub configuration: PostgresVerifierConfigurationV1,
}

impl Fixture {
    #[must_use]
    pub fn context(&self) -> EvaluationContext<'_> {
        EvaluationContext {
            action: &self.action,
            evidence: &self.evidence,
            required_configuration: &self.configuration,
            executed_configuration: &self.configuration,
            request_audience: AUDIENCE,
            now: NOW,
        }
    }

    #[must_use]
    pub fn configuration_with_maximum_rows(
        &self,
        maximum_rows: u32,
    ) -> PostgresVerifierConfigurationV1 {
        configuration_with_maximum_rows(maximum_rows)
    }
}

#[must_use]
pub fn configuration() -> PostgresVerifierConfigurationV1 {
    configuration_with_maximum_rows(3)
}

#[must_use]
pub fn configuration_with_maximum_rows(maximum_rows: u32) -> PostgresVerifierConfigurationV1 {
    PostgresVerifierConfigurationV1::new(PostgresVerifierConfigurationInput {
        allowed_database_audiences: vec![AUDIENCE.into()],
        allowed_databases: vec![identifier("auths_demo")],
        allowed_relations: vec![RelationPolicyV1 {
            database: identifier("auths_demo"),
            schema: identifier("app"),
            table: identifier("demo_accounts"),
            tenant_column: identifier("tenant_id"),
            primary_key_columns: vec![identifier("account_id")],
            row_version_column: identifier("row_version"),
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
            allowed_trigger_fingerprints: vec![sha256(b"no-user-triggers-v1")],
        }],
        maximum_rows,
        maximum_evidence_age_seconds: 300,
        maximum_authorization_lifetime_seconds: 300,
        required_row_security: true,
        statement_timeout_ms: 5_000,
        lock_timeout_ms: 1_000,
        receipt_schema_version: "auths.postgresql.decision-receipt/1".into(),
        executor_audience: AUDIENCE.into(),
    })
    .unwrap()
}

#[must_use]
pub fn fixture() -> Fixture {
    let configuration = configuration();
    let schema_fingerprint = sha256(b"demo_accounts-schema-v1");
    let policy_fingerprint = sha256(b"tenant-isolation-policy-v1");
    let trigger_fingerprint = sha256(b"no-user-triggers-v1");
    let tenant_value = TypedValueV1::text("tenant-demo").unwrap();
    let tenant_commitment = canonical_digest(&tenant_value).unwrap();
    let pending = TypedValueV1::enum_text(identifier("review_status"), "pending").unwrap();
    let rows = (1_i64..=3)
        .map(|index| ObservedRowV1 {
            primary_key: vec![NamedValueV1 {
                column: identifier("account_id"),
                value: TypedValueV1::Uuid(format!("00000000-0000-0000-0000-{index:012}")),
            }],
            before_values: vec![NamedValueV1 {
                column: identifier("review_status"),
                value: pending.clone(),
            }],
            row_version: index,
        })
        .collect::<Vec<_>>();
    let evidence = PostgresEvidenceV1 {
        database_server_identity: "spiffe://auths.demo/postgresql/synthetic".into(),
        database_audience: AUDIENCE.into(),
        database_name: identifier("auths_demo"),
        schema_name: identifier("app"),
        table_name: identifier("demo_accounts"),
        relation_oid: 16_384,
        schema_fingerprint: schema_fingerprint.clone(),
        policy_fingerprint: policy_fingerprint.clone(),
        trigger_fingerprint: trigger_fingerprint.clone(),
        privilege_fingerprint: sha256(b"auths_executor-minimal-privileges-v1"),
        row_security_enabled: true,
        row_security_forced: true,
        executor_role: identifier("auths_executor"),
        executor_owns_relation: false,
        executor_bypass_rls: false,
        executor_superuser: false,
        executor_create_role: false,
        executor_create_database: false,
        executor_replication: false,
        executor_database_create: false,
        executor_schema_create: false,
        executor_table_truncate: false,
        has_rewrite_rules: false,
        is_foreign_table: false,
        has_partition_routing: false,
        columns: vec![
            ColumnEvidenceV1 {
                name: identifier("account_id"),
                database_type: "uuid".into(),
                nullable: false,
                generated: false,
                has_default: false,
            },
            ColumnEvidenceV1 {
                name: identifier("review_status"),
                database_type: "app.review_status".into(),
                nullable: false,
                generated: false,
                has_default: true,
            },
            ColumnEvidenceV1 {
                name: identifier("row_version"),
                database_type: "bigint".into(),
                nullable: false,
                generated: false,
                has_default: true,
            },
            ColumnEvidenceV1 {
                name: identifier("tenant_id"),
                database_type: "text".into(),
                nullable: false,
                generated: false,
                has_default: false,
            },
        ],
        tenant_column: identifier("tenant_id"),
        tenant_value_commitment: tenant_commitment,
        primary_key_columns: vec![identifier("account_id")],
        row_version_column: identifier("row_version"),
        rows,
        server_version: "17.5".into(),
        evidence_source: "protected-catalog-discovery-v1".into(),
        observed_at: NOW,
    };
    let row_preconditions = evidence
        .rows
        .iter()
        .map(|row| RowPreconditionV1 {
            primary_key: row.primary_key.clone(),
            before_value_commitments: row
                .before_values
                .iter()
                .map(|value| NamedCommitmentV1 {
                    column: value.column.clone(),
                    digest: canonical_digest(value).unwrap(),
                })
                .collect(),
            row_version: row.row_version,
        })
        .collect();
    let intent = PostgresBoundedUpdateIntentV1::new(
        PostgresBoundedUpdateIntentV1 {
            profile: String::new(),
            database_audience: AUDIENCE.into(),
            database_name: identifier("auths_demo"),
            schema_name: identifier("app"),
            table_name: identifier("demo_accounts"),
            tenant_column: identifier("tenant_id"),
            tenant_value,
            primary_key_columns: vec![identifier("account_id")],
            rows: row_preconditions,
            assignments: vec![AssignmentV1 {
                column: identifier("review_status"),
                value: TypedValueV1::enum_text(identifier("review_status"), "reviewed").unwrap(),
            }],
            expected_row_count: 3,
            schema_fingerprint,
            policy_fingerprint,
            trigger_fingerprint,
            required_configuration_digest: DigestHex::from_bytes([0; 32]),
            expires_at: NOW + 300,
            nonce: "postgresql-demo-nonce-00000001".into(),
        },
        &configuration,
    )
    .unwrap();
    let action = PostgresBoundedUpdateV1::build(intent.clone(), &evidence, &configuration).unwrap();
    Fixture {
        action,
        intent,
        evidence,
        configuration,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_uses_serializable_and_exact_three_rows() {
        let fixture = fixture();
        assert_eq!(fixture.intent.rows.len(), 3);
        assert_eq!(
            crate::compile_statement(&fixture.intent, &fixture.configuration)
                .unwrap()
                .isolation,
            crate::IsolationLevelV1::Serializable
        );
    }
}
