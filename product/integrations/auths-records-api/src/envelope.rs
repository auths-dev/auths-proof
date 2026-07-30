//! Transport-neutral request envelope.

use serde::{Deserialize, Serialize};

use crate::{
    CREATE_OPERATION, READ_OPERATION, RecordsActionV1, RecordsError, RecordsPresentationV1,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordsRequestEnvelopeV1 {
    pub envelope_version: String,
    pub operation_id: String,
    pub canonical_action: RecordsActionV1,
    pub proof_hex: String,
    pub presentation: RecordsPresentationV1,
}

impl RecordsRequestEnvelopeV1 {
    pub fn validate(&self, maximum_proof_bytes: usize) -> Result<(), RecordsError> {
        if self.envelope_version != "auths.records-envelope/1"
            || self.operation_id != self.canonical_action.operation_id()
            || !matches!(
                self.operation_id.as_str(),
                CREATE_OPERATION | READ_OPERATION
            )
        {
            return Err(RecordsError::MeaningMismatch);
        }
        let proof = self.proof()?;
        if proof.is_empty() || proof.len() > maximum_proof_bytes {
            return Err(RecordsError::LimitExceeded);
        }
        self.canonical_action.canonical_bytes()?;
        Ok(())
    }

    pub fn proof(&self) -> Result<Vec<u8>, RecordsError> {
        hex::decode(&self.proof_hex).map_err(|_| RecordsError::Malformed)
    }
}
