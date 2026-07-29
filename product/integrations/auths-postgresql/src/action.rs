//! Hostile typed intent and evidence-resolved canonical action.

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{canonical_digest, canonical_json},
    compiler::compile_statement,
    evidence::PostgresEvidenceV1,
    schema::{
        DigestHex, HARD_MAX_ASSIGNMENTS, HARD_MAX_ROWS, MAX_ACTION_BYTES, PROFILE_ID,
        PROFILE_VERSION, PgIdentifier, PostgresVerifierConfigurationV1, ValidationError,
    },
    value::{AssignmentV1, NamedCommitmentV1, NamedValueV1, TypedValueV1},
};

/// One exact row precondition; no predicate language is exposed.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowPreconditionV1 {
    pub primary_key: Vec<NamedValueV1>,
    pub before_value_commitments: Vec<NamedCommitmentV1>,
    pub row_version: i64,
}

impl RowPreconditionV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.primary_key.is_empty()
            || self
                .primary_key
                .windows(2)
                .any(|pair| pair[0].column >= pair[1].column)
            || self.before_value_commitments.is_empty()
            || self
                .before_value_commitments
                .windows(2)
                .any(|pair| pair[0].column >= pair[1].column)
        {
            return Err(ValidationError::MalformedMutation);
        }
        Ok(())
    }
}

/// Agent-visible bounded mutation language. It deliberately contains no SQL.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresBoundedUpdateIntentV1 {
    pub profile: String,
    pub database_audience: String,
    pub database_name: PgIdentifier,
    pub schema_name: PgIdentifier,
    pub table_name: PgIdentifier,
    pub tenant_column: PgIdentifier,
    pub tenant_value: TypedValueV1,
    pub primary_key_columns: Vec<PgIdentifier>,
    pub rows: Vec<RowPreconditionV1>,
    pub assignments: Vec<AssignmentV1>,
    pub expected_row_count: u32,
    pub schema_fingerprint: DigestHex,
    pub policy_fingerprint: DigestHex,
    pub trigger_fingerprint: DigestHex,
    pub required_configuration_digest: DigestHex,
    pub expires_at: u64,
    pub nonce: String,
}

impl PostgresBoundedUpdateIntentV1 {
    pub fn new(
        mut value: Self,
        configuration: &PostgresVerifierConfigurationV1,
    ) -> Result<Self, ValidationError> {
        value.profile = format!("{PROFILE_ID}/{PROFILE_VERSION}");
        value.primary_key_columns.sort();
        for row in &mut value.rows {
            row.primary_key.sort();
            row.before_value_commitments.sort();
        }
        value.rows.sort();
        value.assignments.sort();
        value.required_configuration_digest = configuration.digest()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.profile != format!("{PROFILE_ID}/{PROFILE_VERSION}")
            || self.database_audience.is_empty()
            || self.primary_key_columns.is_empty()
            || self
                .primary_key_columns
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.rows.is_empty()
            || self.rows.len() > HARD_MAX_ROWS
            || self.rows.windows(2).any(|pair| pair[0] >= pair[1])
            || self.assignments.is_empty()
            || self.assignments.len() > HARD_MAX_ASSIGNMENTS
            || self
                .assignments
                .windows(2)
                .any(|pair| pair[0].column >= pair[1].column)
            || usize::try_from(self.expected_row_count).ok() != Some(self.rows.len())
            || !(16..=256).contains(&self.nonce.len())
            || !self
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || matches!(self.tenant_value, TypedValueV1::Null(_))
            || self.tenant_value.validate_canonical().is_err()
        {
            return Err(ValidationError::MalformedMutation);
        }
        for row in &self.rows {
            row.validate()?;
            let row_columns: Vec<_> = row.primary_key.iter().map(|value| &value.column).collect();
            let expected_columns: Vec<_> = self.primary_key_columns.iter().collect();
            if row_columns != expected_columns
                || row.primary_key.iter().any(|value| {
                    matches!(value.value, TypedValueV1::Null(_))
                        || value.value.validate_canonical().is_err()
                })
            {
                return Err(ValidationError::MalformedMutation);
            }
        }
        if self
            .assignments
            .iter()
            .any(|assignment| assignment.value.validate_canonical().is_err())
        {
            return Err(ValidationError::MalformedMutation);
        }
        Ok(())
    }
}

/// Final action bound to protected discovery and trusted SQL compilation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresBoundedUpdateV1 {
    pub intent: PostgresBoundedUpdateIntentV1,
    pub database_server_identity: String,
    pub relation_oid: u32,
    pub executor_role: PgIdentifier,
    pub tenant_commitment: DigestHex,
    pub row_set_digest: DigestHex,
    pub before_state_digest: DigestHex,
    pub after_state_digest: DigestHex,
    pub compiled_statement_template_digest: DigestHex,
    pub evidence_digest: DigestHex,
    pub observed_at: u64,
}

impl PostgresBoundedUpdateV1 {
    pub fn build(
        intent: PostgresBoundedUpdateIntentV1,
        evidence: &PostgresEvidenceV1,
        configuration: &PostgresVerifierConfigurationV1,
    ) -> Result<Self, ValidationError> {
        intent.validate()?;
        evidence.validate()?;
        let tenant_commitment = canonical_digest(&intent.tenant_value)?;
        let row_set_digest = evidence.row_set_digest()?;
        let before_state_digest = evidence.before_state_digest()?;
        let after_state_digest = after_state_digest(evidence, &intent.assignments)?;
        let template_digest = compile_statement(&intent, configuration)?.template_digest;
        let action = Self {
            intent,
            database_server_identity: evidence.database_server_identity.clone(),
            relation_oid: evidence.relation_oid,
            executor_role: evidence.executor_role.clone(),
            tenant_commitment,
            row_set_digest,
            before_state_digest,
            after_state_digest,
            compiled_statement_template_digest: template_digest,
            evidence_digest: evidence.digest()?,
            observed_at: evidence.observed_at,
        };
        action.validate()?;
        Ok(action)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        self.intent.validate()?;
        if self.database_server_identity.is_empty() || self.relation_oid == 0 {
            return Err(ValidationError::MalformedMutation);
        }
        if self.canonical_bytes()?.len() > MAX_ACTION_BYTES {
            return Err(ValidationError::LimitExceeded);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ValidationError> {
        canonical_json(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        if bytes.is_empty() || bytes.len() > MAX_ACTION_BYTES {
            return Err(ValidationError::LimitExceeded);
        }
        let action: Self =
            serde_json::from_slice(bytes).map_err(|_| ValidationError::MalformedMutation)?;
        action.validate()?;
        if action.canonical_bytes()? != bytes {
            return Err(ValidationError::NonCanonical);
        }
        Ok(action)
    }

    pub fn digest(&self) -> Result<DigestHex, ValidationError> {
        canonical_digest(self)
    }
}

/// Computes committed post-state without exposing it in receipts.
pub fn after_state_digest(
    evidence: &PostgresEvidenceV1,
    assignments: &[AssignmentV1],
) -> Result<DigestHex, ValidationError> {
    let mut state = Vec::with_capacity(evidence.rows.len());
    for row in &evidence.rows {
        let mut values = row.before_values.clone();
        for assignment in assignments {
            match values.binary_search_by(|value| value.column.cmp(&assignment.column)) {
                Ok(index) => values[index].value = assignment.value.clone(),
                Err(index) => values.insert(
                    index,
                    NamedValueV1 {
                        column: assignment.column.clone(),
                        value: assignment.value.clone(),
                    },
                ),
            }
        }
        state.push((&row.primary_key, values, row.row_version.saturating_add(1)));
    }
    canonical_digest(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fixture;

    #[test]
    fn duplicate_assignment_is_malformed_not_normalized() {
        let fixture = fixture();
        let mut intent = fixture.intent.clone();
        intent.assignments.push(intent.assignments[0].clone());
        assert!(PostgresBoundedUpdateIntentV1::new(intent, &fixture.configuration).is_err());
    }

    #[test]
    fn primary_key_shape_must_match_declared_columns() {
        let fixture = fixture();
        let mut intent = fixture.intent.clone();
        intent.rows[0].primary_key[0].column = PgIdentifier::parse("other_id").unwrap();
        assert!(PostgresBoundedUpdateIntentV1::new(intent, &fixture.configuration).is_err());
    }
}
