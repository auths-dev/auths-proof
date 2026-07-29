//! Linked privacy-aware decision, claim, transaction, and observation receipts.

use serde::{Deserialize, Serialize};

use crate::{
    action::PostgresBoundedUpdateV1,
    canonical::{canonical_digest, sha256},
    claim::ClaimRecord,
    decision::{Decision, EvaluationContext, evaluate},
    evidence::PostgresEvidenceV1,
    ports::TransactionResult,
    schema::{DigestHex, PostgresVerifierConfigurationV1, ValidationError},
};

/// Policy and proof decision, excluding keys and values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    pub schema: String,
    pub action_digest: DigestHex,
    pub evidence_digest: DigestHex,
    pub database_audience_commitment: DigestHex,
    pub relation_oid: u32,
    pub tenant_commitment: DigestHex,
    pub row_set_digest: DigestHex,
    pub before_state_digest: DigestHex,
    pub after_state_digest: DigestHex,
    pub expected_row_count: u32,
    pub required_configuration: PostgresVerifierConfigurationV1,
    pub executed_configuration: PostgresVerifierConfigurationV1,
    pub decision: Decision,
    pub auths_decision: Option<String>,
    pub auths_code: Option<String>,
    pub evidence_age_seconds: u64,
    pub decided_at: u64,
}

impl DecisionReceipt {
    pub fn digest(&self) -> Result<DigestHex, ValidationError> {
        canonical_digest(self)
    }
}

/// Atomic database effect and ledger evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionReceipt {
    pub schema: String,
    pub decision_digest: DigestHex,
    pub action_digest: DigestHex,
    pub claim_id_commitment: DigestHex,
    pub database_audience_commitment: DigestHex,
    pub relation_oid: u32,
    pub tenant_commitment: DigestHex,
    pub row_set_digest: DigestHex,
    pub before_state_digest: DigestHex,
    pub after_state_digest: DigestHex,
    pub affected_rows: u32,
    pub outcome: String,
    pub ledger_commitment: DigestHex,
    pub server_version: String,
    pub transaction_started_at: u64,
    pub committed_at: u64,
    pub reconciled: bool,
}

/// Fresh post-commit read-back commitment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationReceipt {
    pub schema: String,
    pub action_digest: DigestHex,
    pub readback_commitment: DigestHex,
    pub authorized_after_state_digest: DigestHex,
    pub after_state_matches: bool,
    pub observed_at: u64,
}

/// Receipt variants suitable for an append-only sink.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PostgresReceipt {
    Decision(Box<DecisionReceipt>),
    Claim(ClaimRecord),
    Transaction(Box<TransactionReceipt>),
    Observation(ObservationReceipt),
}

#[allow(
    clippy::too_many_arguments,
    reason = "receipt construction exposes every policy input explicitly"
)]
pub fn decision_receipt(
    action: &PostgresBoundedUpdateV1,
    evidence: &PostgresEvidenceV1,
    required_configuration: &PostgresVerifierConfigurationV1,
    executed_configuration: &PostgresVerifierConfigurationV1,
    request_audience: &str,
    now: u64,
) -> Result<DecisionReceipt, ValidationError> {
    Ok(DecisionReceipt {
        schema: executed_configuration.receipt_schema_version().into(),
        action_digest: action.digest()?,
        evidence_digest: evidence.digest()?,
        database_audience_commitment: sha256(action.intent.database_audience.as_bytes()),
        relation_oid: action.relation_oid,
        tenant_commitment: action.tenant_commitment.clone(),
        row_set_digest: action.row_set_digest.clone(),
        before_state_digest: action.before_state_digest.clone(),
        after_state_digest: action.after_state_digest.clone(),
        expected_row_count: action.intent.expected_row_count,
        required_configuration: required_configuration.clone(),
        executed_configuration: executed_configuration.clone(),
        decision: evaluate(&EvaluationContext {
            action,
            evidence,
            required_configuration,
            executed_configuration,
            request_audience,
            now,
        }),
        auths_decision: None,
        auths_code: None,
        evidence_age_seconds: now.saturating_sub(evidence.observed_at),
        decided_at: now,
    })
}

pub fn transaction_receipt(
    decision_digest: DigestHex,
    action: &PostgresBoundedUpdateV1,
    claim_id: &str,
    result: &TransactionResult,
) -> Result<TransactionReceipt, ValidationError> {
    Ok(TransactionReceipt {
        schema: "auths.postgresql.transaction-receipt/1".into(),
        decision_digest,
        action_digest: action.digest()?,
        claim_id_commitment: sha256(claim_id.as_bytes()),
        database_audience_commitment: sha256(action.intent.database_audience.as_bytes()),
        relation_oid: action.relation_oid,
        tenant_commitment: action.tenant_commitment.clone(),
        row_set_digest: action.row_set_digest.clone(),
        before_state_digest: action.before_state_digest.clone(),
        after_state_digest: action.after_state_digest.clone(),
        affected_rows: result.affected_rows,
        outcome: if result.reconciled {
            "reconciled-committed".into()
        } else {
            "committed".into()
        },
        ledger_commitment: result.ledger_commitment.clone(),
        server_version: result.server_version.clone(),
        transaction_started_at: result.transaction_started_at,
        committed_at: result.committed_at,
        reconciled: result.reconciled,
    })
}

#[must_use]
pub fn observation_receipt(
    action: &PostgresBoundedUpdateV1,
    result: &TransactionResult,
) -> ObservationReceipt {
    ObservationReceipt {
        schema: "auths.postgresql.observation-receipt/1".into(),
        action_digest: action.digest().expect("previously validated action"),
        readback_commitment: result.readback_commitment.clone(),
        authorized_after_state_digest: action.after_state_digest.clone(),
        after_state_matches: result.readback_commitment == action.after_state_digest,
        observed_at: result.committed_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fixture;

    #[test]
    fn decision_receipt_contains_no_private_values() {
        let fixture = fixture();
        let receipt = decision_receipt(
            &fixture.action,
            &fixture.evidence,
            &fixture.configuration,
            &fixture.configuration,
            &fixture.evidence.database_audience,
            crate::test_support::NOW,
        )
        .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("tenant-demo"));
        assert!(!json.contains("account-001"));
        assert!(!json.contains("\"value\":\"pending\""));
        assert!(!json.contains("\"value\":\"reviewed\""));
    }
}
