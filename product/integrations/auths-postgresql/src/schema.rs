//! Closed identifiers, configuration, and error vocabulary.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};

use crate::canonical::canonical_digest;

/// Profile identifier.
pub const PROFILE_ID: &str = "auths.postgresql.bounded-update";
/// Profile version.
pub const PROFILE_VERSION: u16 = 1;
/// Canonical media type.
pub const MEDIA_TYPE: &str = "application/vnd.auths.postgresql.bounded-update.v1+json";
/// Exact capability.
pub const UPDATE_CAPABILITY: &str = "postgresql.bounded-update/execute";
/// Hard action size.
pub const MAX_ACTION_BYTES: usize = 512 * 1024;
/// Hard row count.
pub const HARD_MAX_ROWS: usize = 256;
/// Hard assignment count.
pub const HARD_MAX_ASSIGNMENTS: usize = 32;
/// Hard evidence age.
pub const HARD_MAX_EVIDENCE_AGE_SECONDS: u64 = 60 * 60;
/// Hard authorization lifetime.
pub const HARD_MAX_AUTHORIZATION_LIFETIME_SECONDS: u64 = 15 * 60;

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

macro_rules! validated_string {
    ($name:ident, $validator:ident, $message:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                if !$validator(&value) {
                    return Err(ValidationError::MalformedMutation);
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ValidationError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(|_| serde::de::Error::custom($message))
            }
        }
    };
}

validated_string!(DigestHex, valid_digest, "invalid lowercase SHA-256 digest");
validated_string!(
    PgIdentifier,
    valid_identifier,
    "invalid canonical PostgreSQL identifier"
);

impl DigestHex {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(hex::encode(bytes))
    }
}

impl PgIdentifier {
    /// Quotes an already validated identifier. The constructor's restricted
    /// alphabet makes this operation non-ambiguous and non-injectable.
    #[must_use]
    pub fn quoted(&self) -> String {
        format!("\"{}\"", self.0)
    }
}

/// Stable public status code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "kebab-case")]
pub enum StableCode {
    #[error("malformed-mutation")]
    MalformedMutation,
    #[error("unsupported-profile")]
    UnsupportedProfile,
    #[error("unsupported-value-type")]
    UnsupportedValueType,
    #[error("proof-invalid")]
    ProofInvalid,
    #[error("verifier-configuration-mismatch")]
    VerifierConfigurationMismatch,
    #[error("evidence-stale")]
    EvidenceStale,
    #[error("database-audience-mismatch")]
    DatabaseAudienceMismatch,
    #[error("schema-fingerprint-mismatch")]
    SchemaFingerprintMismatch,
    #[error("policy-fingerprint-mismatch")]
    PolicyFingerprintMismatch,
    #[error("trigger-fingerprint-mismatch")]
    TriggerFingerprintMismatch,
    #[error("relation-mismatch")]
    RelationMismatch,
    #[error("tenant-mismatch")]
    TenantMismatch,
    #[error("row-set-mismatch")]
    RowSetMismatch,
    #[error("before-state-mismatch")]
    BeforeStateMismatch,
    #[error("row-limit-exceeded")]
    RowLimitExceeded,
    #[error("column-not-authorized")]
    ColumnNotAuthorized,
    #[error("value-constraint-failed")]
    ValueConstraintFailed,
    #[error("already-claimed")]
    AlreadyClaimed,
    #[error("credential-unavailable")]
    CredentialUnavailable,
    #[error("transaction-conflict")]
    TransactionConflict,
    #[error("cardinality-mismatch")]
    CardinalityMismatch,
    #[error("after-state-mismatch")]
    AfterStateMismatch,
    #[error("database-execution-failed")]
    DatabaseExecutionFailed,
    #[error("execution-outcome-unknown")]
    ExecutionOutcomeUnknown,
}

/// Validation failure before an effect is possible.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValidationError {
    #[error("malformed mutation")]
    MalformedMutation,
    #[error("unsupported value")]
    UnsupportedValue,
    #[error("unsupported profile")]
    UnsupportedProfile,
    #[error("input is not canonical")]
    NonCanonical,
    #[error("invalid configuration")]
    InvalidConfiguration,
    #[error("invalid evidence")]
    InvalidEvidence,
    #[error("canonicalization failed")]
    Canonicalization,
    #[error("action exceeds hard size limit")]
    LimitExceeded,
}

/// Supported mutation value kind.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValueKindV1 {
    Boolean,
    Int64,
    Text,
    Uuid,
    Decimal,
    TimestampUtc,
    EnumText,
}

/// Closed constraint for one assignable column.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueConstraintV1 {
    pub kind: ValueKindV1,
    pub nullable: bool,
    pub maximum_text_bytes: Option<u32>,
    pub decimal_precision: Option<u8>,
    pub decimal_scale: Option<u8>,
    pub timestamp_precision: Option<u8>,
    pub enum_name: Option<PgIdentifier>,
    pub allowed_enum_values: Vec<String>,
}

impl ValueConstraintV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        let text_ok = match self.kind {
            ValueKindV1::Text => self.maximum_text_bytes.is_some_and(|value| value > 0),
            _ => self.maximum_text_bytes.is_none(),
        };
        let decimal_ok =
            match self.kind {
                ValueKindV1::Decimal => self.decimal_precision.zip(self.decimal_scale).is_some_and(
                    |(precision, scale)| precision > 0 && precision <= 38 && scale <= precision,
                ),
                _ => self.decimal_precision.is_none() && self.decimal_scale.is_none(),
            };
        let timestamp_ok = match self.kind {
            ValueKindV1::TimestampUtc => self.timestamp_precision.is_some_and(|value| value <= 6),
            _ => self.timestamp_precision.is_none(),
        };
        let enum_ok = match self.kind {
            ValueKindV1::EnumText => {
                self.enum_name.is_some()
                    && !self.allowed_enum_values.is_empty()
                    && self
                        .allowed_enum_values
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
            }
            _ => self.enum_name.is_none() && self.allowed_enum_values.is_empty(),
        };
        if text_ok && decimal_ok && timestamp_ok && enum_ok {
            Ok(())
        } else {
            Err(ValidationError::InvalidConfiguration)
        }
    }
}

/// One fully resolved relation allowlist entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationPolicyV1 {
    pub database: PgIdentifier,
    pub schema: PgIdentifier,
    pub table: PgIdentifier,
    pub tenant_column: PgIdentifier,
    pub primary_key_columns: Vec<PgIdentifier>,
    pub row_version_column: PgIdentifier,
    pub assignment_constraints: Vec<(PgIdentifier, ValueConstraintV1)>,
    pub allowed_trigger_fingerprints: Vec<DigestHex>,
}

impl RelationPolicyV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.primary_key_columns.is_empty()
            || self
                .primary_key_columns
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self
                .assignment_constraints
                .windows(2)
                .any(|pair| pair[0].0 >= pair[1].0)
            || self.allowed_trigger_fingerprints.is_empty()
            || self
                .allowed_trigger_fingerprints
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.assignment_constraints.is_empty()
        {
            return Err(ValidationError::InvalidConfiguration);
        }
        self.assignment_constraints
            .iter()
            .try_for_each(|(_, constraint)| constraint.validate())
    }
}

/// Required transaction isolation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationLevelV1 {
    Serializable,
}

/// Immutable verifier policy, included in decision receipts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresVerifierConfigurationV1 {
    profile: String,
    canonicalization_version: String,
    allowed_database_audiences: Vec<String>,
    allowed_databases: Vec<PgIdentifier>,
    allowed_relations: Vec<RelationPolicyV1>,
    maximum_rows: u32,
    maximum_evidence_age_seconds: u64,
    maximum_authorization_lifetime_seconds: u64,
    required_isolation_level: IsolationLevelV1,
    required_row_security: bool,
    statement_timeout_ms: u32,
    lock_timeout_ms: u32,
    receipt_schema_version: String,
    executor_audience: String,
}

/// Input normalized into canonical verifier policy.
pub struct PostgresVerifierConfigurationInput {
    pub allowed_database_audiences: Vec<String>,
    pub allowed_databases: Vec<PgIdentifier>,
    pub allowed_relations: Vec<RelationPolicyV1>,
    pub maximum_rows: u32,
    pub maximum_evidence_age_seconds: u64,
    pub maximum_authorization_lifetime_seconds: u64,
    pub required_row_security: bool,
    pub statement_timeout_ms: u32,
    pub lock_timeout_ms: u32,
    pub receipt_schema_version: String,
    pub executor_audience: String,
}

impl PostgresVerifierConfigurationV1 {
    pub fn new(mut input: PostgresVerifierConfigurationInput) -> Result<Self, ValidationError> {
        input.allowed_database_audiences.sort();
        input.allowed_database_audiences.dedup();
        input.allowed_databases.sort();
        input.allowed_databases.dedup();
        input.allowed_relations.sort_by(|left, right| {
            (&left.database, &left.schema, &left.table).cmp(&(
                &right.database,
                &right.schema,
                &right.table,
            ))
        });
        input.allowed_relations.dedup_by(|left, right| {
            left.database == right.database
                && left.schema == right.schema
                && left.table == right.table
        });
        for relation in &mut input.allowed_relations {
            relation.primary_key_columns.sort();
            relation.primary_key_columns.dedup();
            relation
                .assignment_constraints
                .sort_by(|left, right| left.0.cmp(&right.0));
            relation
                .assignment_constraints
                .dedup_by(|left, right| left.0 == right.0);
            relation.allowed_trigger_fingerprints.sort();
            relation.allowed_trigger_fingerprints.dedup();
        }
        let configuration = Self {
            profile: format!("{PROFILE_ID}/{PROFILE_VERSION}"),
            canonicalization_version: "rfc8785-sha256-v1".into(),
            allowed_database_audiences: input.allowed_database_audiences,
            allowed_databases: input.allowed_databases,
            allowed_relations: input.allowed_relations,
            maximum_rows: input.maximum_rows,
            maximum_evidence_age_seconds: input.maximum_evidence_age_seconds,
            maximum_authorization_lifetime_seconds: input.maximum_authorization_lifetime_seconds,
            required_isolation_level: IsolationLevelV1::Serializable,
            required_row_security: input.required_row_security,
            statement_timeout_ms: input.statement_timeout_ms,
            lock_timeout_ms: input.lock_timeout_ms,
            receipt_schema_version: input.receipt_schema_version,
            executor_audience: input.executor_audience,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.profile != format!("{PROFILE_ID}/{PROFILE_VERSION}")
            || self.canonicalization_version != "rfc8785-sha256-v1"
            || self.allowed_database_audiences.is_empty()
            || self.allowed_database_audiences.iter().any(String::is_empty)
            || self
                .allowed_database_audiences
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.allowed_databases.is_empty()
            || self
                .allowed_databases
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.allowed_relations.is_empty()
            || self.maximum_rows == 0
            || usize::try_from(self.maximum_rows).map_or(true, |value| value > HARD_MAX_ROWS)
            || self.maximum_evidence_age_seconds == 0
            || self.maximum_evidence_age_seconds > HARD_MAX_EVIDENCE_AGE_SECONDS
            || self.maximum_authorization_lifetime_seconds == 0
            || self.maximum_authorization_lifetime_seconds > HARD_MAX_AUTHORIZATION_LIFETIME_SECONDS
            || !self.required_row_security
            || self.statement_timeout_ms == 0
            || self.lock_timeout_ms == 0
            || self.receipt_schema_version.is_empty()
            || self.executor_audience.is_empty()
        {
            return Err(ValidationError::InvalidConfiguration);
        }
        self.allowed_relations
            .iter()
            .try_for_each(RelationPolicyV1::validate)
    }

    pub fn digest(&self) -> Result<DigestHex, ValidationError> {
        canonical_digest(self)
    }

    #[must_use]
    pub fn maximum_rows(&self) -> u32 {
        self.maximum_rows
    }

    #[must_use]
    pub fn maximum_evidence_age_seconds(&self) -> u64 {
        self.maximum_evidence_age_seconds
    }

    #[must_use]
    pub fn maximum_authorization_lifetime_seconds(&self) -> u64 {
        self.maximum_authorization_lifetime_seconds
    }

    #[must_use]
    pub fn required_row_security(&self) -> bool {
        self.required_row_security
    }

    #[must_use]
    pub fn statement_timeout_ms(&self) -> u32 {
        self.statement_timeout_ms
    }

    #[must_use]
    pub fn lock_timeout_ms(&self) -> u32 {
        self.lock_timeout_ms
    }

    #[must_use]
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }

    #[must_use]
    pub fn receipt_schema_version(&self) -> &str {
        &self.receipt_schema_version
    }

    #[must_use]
    pub fn allows_audience(&self, audience: &str) -> bool {
        self.allowed_database_audiences
            .binary_search_by(|value| value.as_str().cmp(audience))
            .is_ok()
    }

    #[must_use]
    pub fn allows_database(&self, database: &PgIdentifier) -> bool {
        self.allowed_databases.binary_search(database).is_ok()
    }

    #[must_use]
    pub fn relation(
        &self,
        database: &PgIdentifier,
        schema: &PgIdentifier,
        table: &PgIdentifier,
    ) -> Option<&RelationPolicyV1> {
        self.allowed_relations.iter().find(|relation| {
            relation.database == *database && relation.schema == *schema && relation.table == *table
        })
    }
}
