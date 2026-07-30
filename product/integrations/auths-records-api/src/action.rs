//! Closed create and read actions for the records vertical.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_digest, canonical_json};

pub const CREATE_PROFILE_ID: &str = "auths.demo.records.create";
pub const READ_PROFILE_ID: &str = "auths.demo.records.read";
pub const PROFILE_VERSION: u16 = 1;
pub const CREATE_OPERATION: &str = "records.create.v1";
pub const READ_OPERATION: &str = "records.read.v1";
pub const MEDIA_TYPE: &str = "application/vnd.auths.records-action+json;version=1";
pub const MAX_ACTION_BYTES: usize = 16 * 1024;
pub const MAX_IDENTIFIER_BYTES: usize = 64;
pub const MAX_VALUE_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecordsError {
    #[error("input exceeds a hard limit")]
    LimitExceeded,
    #[error("input is malformed")]
    Malformed,
    #[error("input is not canonical")]
    NonCanonical,
    #[error("canonical encoding failed")]
    Canonicalization,
    #[error("action or policy meaning is invalid")]
    MeaningMismatch,
    #[error("state is unavailable or corrupt")]
    StateUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecordIdentifier(String);

impl RecordIdentifier {
    pub fn parse(value: impl Into<String>) -> Result<Self, RecordsError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_IDENTIFIER_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(RecordsError::MeaningMismatch);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadField {
    CreatedAt,
    RecordId,
    UpdatedAt,
    Value,
    Version,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRecordV1 {
    pub profile: String,
    pub namespace_id: RecordIdentifier,
    pub record_id: RecordIdentifier,
    pub value: String,
    pub value_encoding: String,
    pub expected_absent: bool,
    pub policy_digest: String,
    pub required_evaluator: String,
    pub required_configuration_digest: String,
    pub executor_audience: String,
    pub expires_at: u64,
    pub nonce: String,
}

impl CreateRecordV1 {
    pub fn validate(&self) -> Result<(), RecordsError> {
        if self.profile != format!("{CREATE_PROFILE_ID}/{PROFILE_VERSION}")
            || self.value_encoding != "utf8-text/1"
            || !self.expected_absent
            || self.value.len() > MAX_VALUE_BYTES
            || self.value.contains('\0')
            || self.required_evaluator != "auths.records.create-evaluator/1"
            || self.executor_audience.is_empty()
            || !is_digest(&self.policy_digest)
            || !is_digest(&self.required_configuration_digest)
            || !is_nonce(&self.nonce)
        {
            return Err(RecordsError::MeaningMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RecordsError> {
        self.validate()?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RecordsError> {
        if bytes.is_empty() || bytes.len() > MAX_ACTION_BYTES {
            return Err(RecordsError::LimitExceeded);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| RecordsError::Malformed)?;
        value.validate()?;
        if value.canonical_bytes()? != bytes {
            return Err(RecordsError::NonCanonical);
        }
        Ok(value)
    }

    pub fn digest(&self) -> Result<String, RecordsError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRecordV1 {
    pub profile: String,
    pub namespace_id: RecordIdentifier,
    pub record_id: RecordIdentifier,
    pub allowed_fields: Vec<ReadField>,
    pub maximum_response_bytes: u32,
    pub expected_record_version: u64,
    pub policy_digest: String,
    pub required_evaluator: String,
    pub required_configuration_digest: String,
    pub executor_audience: String,
    pub expires_at: u64,
    pub nonce: String,
}

impl ReadRecordV1 {
    pub fn validate(&self) -> Result<(), RecordsError> {
        let canonical_fields: BTreeSet<_> = self.allowed_fields.iter().copied().collect();
        if self.profile != format!("{READ_PROFILE_ID}/{PROFILE_VERSION}")
            || self.allowed_fields.is_empty()
            || canonical_fields.len() != self.allowed_fields.len()
            || canonical_fields.iter().copied().collect::<Vec<_>>() != self.allowed_fields
            || self.maximum_response_bytes == 0
            || self.required_evaluator != "auths.records.read-evaluator/1"
            || self.executor_audience.is_empty()
            || !is_digest(&self.policy_digest)
            || !is_digest(&self.required_configuration_digest)
            || !is_nonce(&self.nonce)
        {
            return Err(RecordsError::MeaningMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RecordsError> {
        self.validate()?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RecordsError> {
        if bytes.is_empty() || bytes.len() > MAX_ACTION_BYTES {
            return Err(RecordsError::LimitExceeded);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| RecordsError::Malformed)?;
        value.validate()?;
        if value.canonical_bytes()? != bytes {
            return Err(RecordsError::NonCanonical);
        }
        Ok(value)
    }

    pub fn digest(&self) -> Result<String, RecordsError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation_id", content = "action")]
pub enum RecordsActionV1 {
    #[serde(rename = "records.create.v1")]
    Create(CreateRecordV1),
    #[serde(rename = "records.read.v1")]
    Read(ReadRecordV1),
}

impl RecordsActionV1 {
    #[must_use]
    pub const fn operation_id(&self) -> &'static str {
        match self {
            Self::Create(_) => CREATE_OPERATION,
            Self::Read(_) => READ_OPERATION,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RecordsError> {
        match self {
            Self::Create(action) => action.canonical_bytes(),
            Self::Read(action) => action.canonical_bytes(),
        }
    }

    pub fn digest(&self) -> Result<String, RecordsError> {
        match self {
            Self::Create(action) => action.digest(),
            Self::Read(action) => action.digest(),
        }
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_nonce(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_grammar_is_closed() {
        assert!(RecordIdentifier::parse("demo-1").is_ok());
        assert!(RecordIdentifier::parse("../other").is_err());
        assert!(RecordIdentifier::parse("space here").is_err());
    }

    #[test]
    fn canonical_decoder_rejects_unknown_fields() {
        let bytes = br#"{"expected_absent":true,"executor_audience":"https://records.auths.dev","expires_at":1,"nonce":"0123456789abcdef","policy_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile":"auths.demo.records.create/1","required_configuration_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","required_evaluator":"auths.records.create-evaluator/1","namespace_id":"demo","record_id":"demo-1","unexpected":true,"value":"hello","value_encoding":"utf8-text/1"}"#;
        assert_eq!(
            CreateRecordV1::from_canonical_bytes(bytes),
            Err(RecordsError::Malformed)
        );
    }
}
