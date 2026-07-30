//! Protected PostgreSQL catalog and row observations.

use serde::{Deserialize, Serialize};

use crate::{
    canonical::canonical_digest,
    schema::{DigestHex, HARD_MAX_ROWS, PgIdentifier, ValidationError},
    value::NamedValueV1,
};

/// Catalog column facts committed by discovery.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnEvidenceV1 {
    pub name: PgIdentifier,
    pub database_type: String,
    pub nullable: bool,
    pub generated: bool,
    pub has_default: bool,
}

/// One observed candidate row.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRowV1 {
    pub primary_key: Vec<NamedValueV1>,
    pub before_values: Vec<NamedValueV1>,
    pub row_version: i64,
}

impl ObservedRowV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.primary_key.is_empty()
            || self
                .primary_key
                .windows(2)
                .any(|pair| pair[0].column >= pair[1].column)
            || self.before_values.is_empty()
            || self
                .before_values
                .windows(2)
                .any(|pair| pair[0].column >= pair[1].column)
        {
            return Err(ValidationError::InvalidEvidence);
        }
        Ok(())
    }
}

/// Complete catalog, role, RLS, and candidate-row evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresEvidenceV1 {
    pub database_server_identity: String,
    pub database_audience: String,
    pub database_name: PgIdentifier,
    pub schema_name: PgIdentifier,
    pub table_name: PgIdentifier,
    pub relation_oid: u32,
    pub schema_fingerprint: DigestHex,
    pub policy_fingerprint: DigestHex,
    pub trigger_fingerprint: DigestHex,
    pub privilege_fingerprint: DigestHex,
    pub row_security_enabled: bool,
    pub row_security_forced: bool,
    pub executor_role: PgIdentifier,
    pub executor_owns_relation: bool,
    pub executor_bypass_rls: bool,
    pub executor_superuser: bool,
    pub executor_create_role: bool,
    pub executor_create_database: bool,
    pub executor_replication: bool,
    pub executor_database_create: bool,
    pub executor_schema_create: bool,
    pub executor_table_truncate: bool,
    pub has_rewrite_rules: bool,
    pub is_foreign_table: bool,
    pub has_partition_routing: bool,
    pub columns: Vec<ColumnEvidenceV1>,
    pub tenant_column: PgIdentifier,
    pub tenant_value_commitment: DigestHex,
    pub primary_key_columns: Vec<PgIdentifier>,
    pub row_version_column: PgIdentifier,
    pub rows: Vec<ObservedRowV1>,
    pub server_version: String,
    pub evidence_source: String,
    pub observed_at: u64,
}

impl PostgresEvidenceV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.database_server_identity.is_empty()
            || self.database_server_identity.len() > 512
            || self.database_audience.is_empty()
            || self.relation_oid == 0
            || self.columns.is_empty()
            || self
                .columns
                .windows(2)
                .any(|pair| pair[0].name >= pair[1].name)
            || self.primary_key_columns.is_empty()
            || self
                .primary_key_columns
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.rows.is_empty()
            || self.rows.len() > HARD_MAX_ROWS
            || self.rows.windows(2).any(|pair| pair[0] >= pair[1])
            || self.server_version.is_empty()
            || self.evidence_source.is_empty()
            || self.executor_owns_relation
            || self.executor_bypass_rls
            || self.executor_superuser
            || self.executor_create_role
            || self.executor_create_database
            || self.executor_replication
            || self.executor_database_create
            || self.executor_schema_create
            || self.executor_table_truncate
            || self.has_rewrite_rules
            || self.is_foreign_table
            || self.has_partition_routing
        {
            return Err(ValidationError::InvalidEvidence);
        }
        for row in &self.rows {
            row.validate()?;
            if row
                .primary_key
                .iter()
                .chain(&row.before_values)
                .any(|value| value.value.validate_canonical().is_err())
            {
                return Err(ValidationError::InvalidEvidence);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<DigestHex, ValidationError> {
        canonical_digest(self)
    }

    pub fn row_set_digest(&self) -> Result<DigestHex, ValidationError> {
        let keys: Vec<_> = self.rows.iter().map(|row| &row.primary_key).collect();
        canonical_digest(&keys)
    }

    pub fn before_state_digest(&self) -> Result<DigestHex, ValidationError> {
        let state: Vec<_> = self
            .rows
            .iter()
            .map(|row| (&row.primary_key, &row.before_values, row.row_version))
            .collect();
        canonical_digest(&state)
    }
}
