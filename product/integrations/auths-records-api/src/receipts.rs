//! Linked delivery, decision, execution/disclosure, and observation receipts.

use serde::{Deserialize, Serialize};

use crate::{
    RecordsApiVerifierConfigurationV1, RecordsDecision, RecordsError, canonical::canonical_digest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryAdapter {
    File,
    Https,
    Iroh,
    Memory,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReceipt {
    pub schema: String,
    pub delivery_id: String,
    pub adapter: DeliveryAdapter,
    pub adapter_identity: String,
    pub protocol: String,
    pub received_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub action_digest: String,
    pub policy_digest: String,
    pub proof_digest: String,
    pub presenter_principal: String,
    pub operation_id: String,
    pub executor_audience: String,
    pub required_configuration: RecordsApiVerifierConfigurationV1,
    pub executed_configuration: RecordsApiVerifierConfigurationV1,
    pub decision: RecordsDecision,
    pub auths_decision: String,
    pub auths_code: String,
    pub protected_storage_accessed: bool,
    pub decided_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "effect", rename_all = "kebab-case")]
pub enum EffectReceipt {
    Create {
        receipt_id: String,
        decision_digest: String,
        action_digest: String,
        namespace_commitment: String,
        record_commitment: String,
        value_commitment: String,
        record_version: u64,
        create_units_before: u32,
        create_units_after: u32,
        created_bytes_before: u64,
        created_bytes_after: u64,
        executed_at: u64,
    },
    Read {
        receipt_id: String,
        decision_digest: String,
        action_digest: String,
        namespace_commitment: String,
        record_commitment: String,
        fields_commitment: String,
        response_commitment: String,
        response_bytes: u64,
        read_units_before: u32,
        read_units_after: u32,
        disclosed_bytes_before: u64,
        disclosed_bytes_after: u64,
        disclosed_at: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub action_digest: String,
    pub effect_digest: String,
    pub state_commitment: String,
    pub outcome: String,
    pub observed_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBundle {
    pub schema: String,
    pub delivery: DeliveryReceipt,
    pub decision: DecisionReceipt,
    pub effect: Option<EffectReceipt>,
    pub observation: Option<ObservationReceipt>,
}

impl ReceiptBundle {
    pub fn digest(&self) -> Result<String, RecordsError> {
        canonical_digest(self)
    }
}
