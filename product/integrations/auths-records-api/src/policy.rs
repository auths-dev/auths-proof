//! Immutable records policy and verifier configuration.

use serde::{Deserialize, Serialize};

use crate::{
    CREATE_OPERATION, READ_OPERATION, ReadField, RecordIdentifier, RecordsError,
    canonical::canonical_digest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetWindowV1 {
    pub window_seconds: u64,
    pub maximum_creates: u32,
    pub maximum_reads: u32,
    pub maximum_created_bytes: u64,
    pub maximum_disclosed_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedRecordApiPolicyV1 {
    pub policy_type: String,
    pub policy_version: u32,
    pub policy_id: String,
    pub namespace_id: RecordIdentifier,
    pub presenter_principal: String,
    pub allowed_operations: Vec<String>,
    pub allowed_record_ids: Vec<RecordIdentifier>,
    pub allowed_record_id_prefixes: Vec<String>,
    pub maximum_value_bytes: u32,
    pub maximum_response_bytes: u32,
    pub allowed_read_fields: Vec<ReadField>,
    pub maximum_creates: u32,
    pub maximum_reads: u32,
    pub maximum_created_bytes: u64,
    pub maximum_disclosed_bytes: u64,
    pub fixed_and_rolling_budgets: Vec<BudgetWindowV1>,
    pub valid_from: u64,
    pub expires_at: u64,
    pub maximum_action_lifetime_seconds: u64,
    pub maximum_presentation_lifetime_seconds: u64,
    pub maximum_evidence_age_seconds: u64,
    pub executor_audience: String,
}

impl BoundedRecordApiPolicyV1 {
    pub fn validate(&self) -> Result<(), RecordsError> {
        let mut operations = self.allowed_operations.clone();
        operations.sort();
        operations.dedup();
        let valid_operations = operations
            .iter()
            .all(|operation| matches!(operation.as_str(), CREATE_OPERATION | READ_OPERATION));
        let mut fields = self.allowed_read_fields.clone();
        fields.sort();
        fields.dedup();
        let identifiers_valid = self
            .allowed_record_id_prefixes
            .iter()
            .all(|prefix| RecordIdentifier::parse(format!("{prefix}x")).is_ok());
        if self.policy_type != "auths.demo.bounded-record-api-policy"
            || self.policy_version != 1
            || self.policy_id.is_empty()
            || self.presenter_principal.is_empty()
            || self.allowed_operations != operations
            || !valid_operations
            || self.allowed_read_fields != fields
            || !identifiers_valid
            || self.maximum_value_bytes == 0
            || self.maximum_response_bytes == 0
            || self.expires_at <= self.valid_from
            || self.maximum_action_lifetime_seconds == 0
            || self.maximum_presentation_lifetime_seconds == 0
            || self.executor_audience.is_empty()
        {
            return Err(RecordsError::MeaningMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, RecordsError> {
        self.validate()?;
        canonical_digest(self)
    }

    #[must_use]
    pub fn allows_record(&self, record: &RecordIdentifier) -> bool {
        self.allowed_record_ids.binary_search(record).is_ok()
            || self
                .allowed_record_id_prefixes
                .iter()
                .any(|prefix| record.as_str().starts_with(prefix))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordsApiVerifierConfigurationV1 {
    pub create_profile: String,
    pub read_profile: String,
    pub policy_type_and_version: String,
    pub evaluator_semantic_id_and_version: String,
    pub canonicalization_version: String,
    pub presentation_version: String,
    pub configured_executor_audience: String,
    pub trusted_operation_ids: Vec<String>,
    pub trusted_https_origin_mappings: Vec<String>,
    pub trusted_iroh_endpoint_mappings: Vec<String>,
    pub iroh_protocol_version: String,
    pub identifier_grammar_version: String,
    pub value_encoding: String,
    pub maximum_http_header_bytes: u32,
    pub maximum_proof_bytes: u32,
    pub maximum_presentation_bytes: u32,
    pub maximum_request_body_bytes: u32,
    pub maximum_value_bytes: u32,
    pub maximum_response_bytes: u32,
    pub maximum_policy_items: u32,
    pub maximum_evaluator_work: u32,
    pub maximum_active_reservations: u32,
    pub maximum_action_lifetime_seconds: u64,
    pub maximum_presentation_lifetime_seconds: u64,
    pub challenge_schema: String,
    pub claim_and_replay_schema: String,
    pub records_store_schema: String,
    pub receipt_schema: String,
}

impl RecordsApiVerifierConfigurationV1 {
    pub fn validate(&self) -> Result<(), RecordsError> {
        if self.create_profile != "auths.demo.records.create/1"
            || self.read_profile != "auths.demo.records.read/1"
            || self.policy_type_and_version != "auths.demo.bounded-record-api-policy/1"
            || self.evaluator_semantic_id_and_version != "auths.records-evaluator/1"
            || self.canonicalization_version != "rfc8785-sha256-v1"
            || self.presentation_version != "auths.records-presentation/1"
            || self.iroh_protocol_version != "auths.records-api/1"
            || self.identifier_grammar_version != "auths.records-identifier/1"
            || self.value_encoding != "auths.demo.customer-record/1"
            || self.trusted_operation_ids
                != [CREATE_OPERATION.to_string(), READ_OPERATION.to_string()]
            || self.maximum_http_header_bytes == 0
            || self.maximum_proof_bytes == 0
            || self.maximum_presentation_bytes == 0
            || self.maximum_request_body_bytes == 0
            || self.maximum_value_bytes == 0
            || self.maximum_response_bytes == 0
            || self.maximum_evaluator_work == 0
            || self.maximum_active_reservations == 0
            || self.configured_executor_audience.is_empty()
        {
            return Err(RecordsError::MeaningMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, RecordsError> {
        self.validate()?;
        canonical_digest(self)
    }
}

#[must_use]
pub fn demo_configuration(executor_audience: &str) -> RecordsApiVerifierConfigurationV1 {
    RecordsApiVerifierConfigurationV1 {
        create_profile: "auths.demo.records.create/1".into(),
        read_profile: "auths.demo.records.read/1".into(),
        policy_type_and_version: "auths.demo.bounded-record-api-policy/1".into(),
        evaluator_semantic_id_and_version: "auths.records-evaluator/1".into(),
        canonicalization_version: "rfc8785-sha256-v1".into(),
        presentation_version: "auths.records-presentation/1".into(),
        configured_executor_audience: executor_audience.into(),
        trusted_operation_ids: vec![CREATE_OPERATION.into(), READ_OPERATION.into()],
        trusted_https_origin_mappings: vec!["http://localhost:4180".into()],
        trusted_iroh_endpoint_mappings: vec!["configured-at-startup".into()],
        iroh_protocol_version: "auths.records-api/1".into(),
        identifier_grammar_version: "auths.records-identifier/1".into(),
        value_encoding: "auths.demo.customer-record/1".into(),
        maximum_http_header_bytes: 32 * 1024,
        maximum_proof_bytes: 256 * 1024,
        maximum_presentation_bytes: 16 * 1024,
        maximum_request_body_bytes: 16 * 1024,
        maximum_value_bytes: 4 * 1024,
        maximum_response_bytes: 4096,
        maximum_policy_items: 128,
        maximum_evaluator_work: 4096,
        maximum_active_reservations: 128,
        maximum_action_lifetime_seconds: 300,
        maximum_presentation_lifetime_seconds: 120,
        challenge_schema: "auths.records-challenge/1".into(),
        claim_and_replay_schema: "auths.records-ledger/1".into(),
        records_store_schema: "auths.records-store/1".into(),
        receipt_schema: "auths.records-receipt/1".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_byte_configuration_difference_changes_digest() {
        let left = demo_configuration("https://records.auths.dev");
        let mut right = left.clone();
        right.maximum_response_bytes = 4097;
        assert_ne!(left.digest().unwrap(), right.digest().unwrap());
    }
}
