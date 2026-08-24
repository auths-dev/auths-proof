// Qualification-only canonical codecs intentionally expose one opaque invalid-
// input result. Callers must fail closed and must not branch on parser details.
#![allow(clippy::result_unit_err)]

use minicbor::{Decoder, Encoder, data::Type};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, Zeroizing};

const VERSION: u8 = 1;
const FIELD_COUNT: u64 = 15;
const MAX_REQUEST_BYTES: usize = 16_384;
const PROVIDER_CALL_FIELD_COUNT: u64 = 14;
const MAX_PROVIDER_REQUEST_BYTES: usize = 52 * 1_024 * 1_024;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 260 * 1_024 * 1_024;
const MAX_PROVIDER_COMPONENT_BYTES: usize = 25 * 1_024 * 1_024;
const MAX_PROVIDER_RESULT_BYTES: usize = 258 * 1_024 * 1_024;

/// Capability-free request sent only by the qualification agent to the
/// protected credential broker. Secret bytes never enter this record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationCredentialLeaseRequest {
    source_context_sha256: [u8; 32],
    operation_id: String,
    workload_id: String,
    profile_id: String,
    profile_version: u16,
    provider_kind: String,
    connection_alias: String,
    connection_id: String,
    connection_generation: u64,
    descriptor_sha256: [u8; 32],
    account_sha256: [u8; 32],
    contract: String,
    descriptor_schema: String,
    credential_scope: String,
}

/// Exact one-call handoff from the qualification agent to the protected
/// `ProviderProxy`. The opaque capability is redeemable only by the protected
/// proxy at the `CredentialBroker`; mutation credential bytes never cross the
/// candidate process.
pub struct QualificationProviderCallRequest {
    source_context_sha256: [u8; 32],
    operation_id: String,
    profile_id: String,
    profile_version: u16,
    connection_generation: u64,
    kind: QualificationProviderCallKind,
    credential_lease_sha256: [u8; 32],
    command: Vec<u8>,
    profile_state: Vec<u8>,
    credential_capability: Zeroizing<[u8; 32]>,
    configuration_format: Option<String>,
    configuration: Option<Vec<u8>>,
    now_unix_seconds: u64,
}

/// Closed internal `ProviderProxy` transport operation. This is not an SDK
/// route: the generated client continues to own execute/recover semantics,
/// while the protected proxy owns both kinds of provider I/O.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum QualificationProviderCallKind {
    Execute,
    Reconcile,
}

impl QualificationProviderCallKind {
    const fn code(self) -> u8 {
        match self {
            Self::Execute => 0,
            Self::Reconcile => 1,
        }
    }

    const fn from_code(code: u8) -> Result<Self, ()> {
        match code {
            0 => Ok(Self::Execute),
            1 => Ok(Self::Reconcile),
            _ => Err(()),
        }
    }
}

impl QualificationProviderCallRequest {
    /// Constructs one bounded, capability-bearing protected provider call.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when any field is outside the closed wire grammar.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_context_sha256: [u8; 32],
        operation_id: impl Into<String>,
        profile_id: impl Into<String>,
        profile_version: u16,
        connection_generation: u64,
        kind: QualificationProviderCallKind,
        credential_lease_sha256: [u8; 32],
        command: Vec<u8>,
        profile_state: Vec<u8>,
        credential_capability: Zeroizing<[u8; 32]>,
        configuration_format: Option<String>,
        configuration: Option<Vec<u8>>,
        now_unix_seconds: u64,
    ) -> Result<Self, ()> {
        let value = Self {
            source_context_sha256,
            operation_id: operation_id.into(),
            profile_id: profile_id.into(),
            profile_version,
            connection_generation,
            kind,
            credential_lease_sha256,
            command,
            profile_state,
            credential_capability,
            configuration_format,
            configuration,
            now_unix_seconds,
        };
        value.validate().then_some(value).ok_or(())
    }

    /// Encodes the exact canonical request while keeping secret-bearing bytes
    /// in zeroizing storage.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when the value is invalid, oversized, or cannot be encoded.
    pub fn to_cbor(&self) -> Result<Zeroizing<Vec<u8>>, ()> {
        if !self.validate() {
            return Err(());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        let mut encoder = Encoder::new(&mut *bytes);
        encoder.array(PROVIDER_CALL_FIELD_COUNT).map_err(|_| ())?;
        encoder.u8(VERSION).map_err(|_| ())?;
        encoder.bytes(&self.source_context_sha256).map_err(|_| ())?;
        encoder.str(&self.operation_id).map_err(|_| ())?;
        encoder.str(&self.profile_id).map_err(|_| ())?;
        encoder.u16(self.profile_version).map_err(|_| ())?;
        encoder.u64(self.connection_generation).map_err(|_| ())?;
        encoder.u8(self.kind.code()).map_err(|_| ())?;
        encoder
            .bytes(&self.credential_lease_sha256)
            .map_err(|_| ())?;
        encoder.bytes(&self.command).map_err(|_| ())?;
        encoder.bytes(&self.profile_state).map_err(|_| ())?;
        encoder
            .bytes(self.credential_capability.as_slice())
            .map_err(|_| ())?;
        encode_optional_text(&mut encoder, self.configuration_format.as_deref())?;
        encode_optional_bytes(&mut encoder, self.configuration.as_deref())?;
        encoder.u64(self.now_unix_seconds).map_err(|_| ())?;
        (bytes.len() <= MAX_PROVIDER_REQUEST_BYTES)
            .then_some(bytes)
            .ok_or(())
    }

    /// Decodes one exact canonical request and clears the input on success.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` for malformed, noncanonical, or oversized input.
    pub fn from_cbor(bytes: &mut Zeroizing<Vec<u8>>) -> Result<Self, ()> {
        if bytes.is_empty() || bytes.len() > MAX_PROVIDER_REQUEST_BYTES {
            return Err(());
        }
        let mut decoder = Decoder::new(bytes.as_slice());
        if decoder.array().map_err(|_| ())? != Some(PROVIDER_CALL_FIELD_COUNT)
            || decoder.u8().map_err(|_| ())? != VERSION
        {
            return Err(());
        }
        let digest = |bytes: &[u8]| bytes.try_into().map_err(|_| ());
        let value = Self::new(
            digest(decoder.bytes().map_err(|_| ())?)?,
            decoder.str().map_err(|_| ())?,
            decoder.str().map_err(|_| ())?,
            decoder.u16().map_err(|_| ())?,
            decoder.u64().map_err(|_| ())?,
            QualificationProviderCallKind::from_code(decoder.u8().map_err(|_| ())?)?,
            digest(decoder.bytes().map_err(|_| ())?)?,
            decoder.bytes().map_err(|_| ())?.to_vec(),
            decoder.bytes().map_err(|_| ())?.to_vec(),
            Zeroizing::new(digest(decoder.bytes().map_err(|_| ())?)?),
            decode_optional_text(&mut decoder)?,
            decode_optional_bytes(&mut decoder)?,
            decoder.u64().map_err(|_| ())?,
        )?;
        if decoder.position() != bytes.len() || value.to_cbor()?.as_slice() != bytes.as_slice() {
            return Err(());
        }
        bytes.zeroize();
        Ok(value)
    }

    fn validate(&self) -> bool {
        self.profile_version != 0
            && self.connection_generation != 0
            && self.now_unix_seconds != 0
            && registered(&self.operation_id, 160)
            && semantic(&self.profile_id)
            && !self.command.is_empty()
            && self.command.len() <= MAX_PROVIDER_COMPONENT_BYTES
            && !self.profile_state.is_empty()
            && self.profile_state.len() <= MAX_PROVIDER_COMPONENT_BYTES
            && self.configuration_format.is_some() == self.configuration.is_some()
            && self.configuration_format.as_deref().is_none_or(semantic)
            && self.configuration.as_ref().is_none_or(|bytes| {
                !bytes.is_empty() && bytes.len() <= MAX_PROVIDER_COMPONENT_BYTES
            })
    }

    #[must_use]
    pub const fn source_context_sha256(&self) -> &[u8; 32] {
        &self.source_context_sha256
    }
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    #[must_use]
    pub const fn profile_version(&self) -> u16 {
        self.profile_version
    }
    #[must_use]
    pub const fn connection_generation(&self) -> u64 {
        self.connection_generation
    }
    #[must_use]
    pub const fn kind(&self) -> QualificationProviderCallKind {
        self.kind
    }
    #[must_use]
    pub const fn credential_lease_sha256(&self) -> &[u8; 32] {
        &self.credential_lease_sha256
    }
    #[must_use]
    pub fn command(&self) -> &[u8] {
        &self.command
    }
    #[must_use]
    pub fn profile_state(&self) -> &[u8] {
        &self.profile_state
    }
    #[must_use]
    pub fn credential_capability(&self) -> &[u8; 32] {
        &self.credential_capability
    }
    #[must_use]
    pub fn configuration_format(&self) -> Option<&str> {
        self.configuration_format.as_deref()
    }
    #[must_use]
    pub fn configuration(&self) -> Option<&[u8]> {
        self.configuration.as_deref()
    }
    #[must_use]
    pub const fn now_unix_seconds(&self) -> u64 {
        self.now_unix_seconds
    }
}

impl std::fmt::Debug for QualificationProviderCallRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QualificationProviderCallRequest")
            .field("operation_id", &self.operation_id)
            .field("profile_id", &self.profile_id)
            .field("profile_version", &self.profile_version)
            .field("connection_generation", &self.connection_generation)
            .field("kind", &self.kind)
            .field("credential_lease_sha256", &"[COMMITMENT]")
            .field("command", &"[REDACTED]")
            .field("profile_state", &"[REDACTED]")
            .field("credential_capability", &"[REDACTED]")
            .field("source_context_sha256", &"[COMMITMENT]")
            .field("configuration_format", &self.configuration_format)
            .field("configuration", &"[REDACTED]")
            .field("now_unix_seconds", &self.now_unix_seconds)
            .finish()
    }
}

/// Closed `ProviderProxy` result. It preserves the production runtime's exact
/// uncertainty classes without exposing credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualificationProviderCallResponse {
    Success(Vec<u8>),
    PreEntry(Vec<u8>),
    PreEntryPending,
    Possible(Vec<u8>),
    PossibleWithProfileState {
        issue: Vec<u8>,
        profile_state: Vec<u8>,
    },
    /// The protected provider transport exceeded its immutable post-entry
    /// deadline, so the agent must persist outcome-unknown and reconcile.
    PostEntryTimeout,
    NotApplied,
    Invalid,
}

impl QualificationProviderCallResponse {
    /// Encodes the exact canonical response.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when a response component is empty, oversized, or
    /// cannot be encoded.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ()> {
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        match self {
            Self::Success(value) => encode_response_one(&mut encoder, 0, value)?,
            Self::PreEntry(value) => encode_response_one(&mut encoder, 1, value)?,
            Self::PreEntryPending => {
                encoder.array(2).map_err(|_| ())?;
                encoder.u8(VERSION).map_err(|_| ())?;
                encoder.u8(2).map_err(|_| ())?;
            }
            Self::Possible(value) => encode_response_one(&mut encoder, 3, value)?,
            Self::PossibleWithProfileState {
                issue,
                profile_state,
            } => {
                encoder.array(4).map_err(|_| ())?;
                encoder.u8(VERSION).map_err(|_| ())?;
                encoder.u8(4).map_err(|_| ())?;
                encoder.bytes(issue).map_err(|_| ())?;
                encoder.bytes(profile_state).map_err(|_| ())?;
            }
            Self::PostEntryTimeout => {
                encoder.array(2).map_err(|_| ())?;
                encoder.u8(VERSION).map_err(|_| ())?;
                encoder.u8(5).map_err(|_| ())?;
            }
            Self::NotApplied => {
                encoder.array(2).map_err(|_| ())?;
                encoder.u8(VERSION).map_err(|_| ())?;
                encoder.u8(6).map_err(|_| ())?;
            }
            Self::Invalid => {
                encoder.array(2).map_err(|_| ())?;
                encoder.u8(VERSION).map_err(|_| ())?;
                encoder.u8(7).map_err(|_| ())?;
            }
        }
        (bytes.len() <= MAX_PROVIDER_RESPONSE_BYTES)
            .then_some(bytes)
            .ok_or(())
    }

    /// Decodes one exact canonical response.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` for malformed, noncanonical, or oversized input.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.is_empty() || bytes.len() > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(());
        }
        let mut decoder = Decoder::new(bytes);
        let fields = decoder.array().map_err(|_| ())?.ok_or(())?;
        if decoder.u8().map_err(|_| ())? != VERSION {
            return Err(());
        }
        let kind = decoder.u8().map_err(|_| ())?;
        let value = match (kind, fields) {
            (0, 3) => Self::Success(decoder.bytes().map_err(|_| ())?.to_vec()),
            (1, 3) => Self::PreEntry(decoder.bytes().map_err(|_| ())?.to_vec()),
            (2, 2) => Self::PreEntryPending,
            (3, 3) => Self::Possible(decoder.bytes().map_err(|_| ())?.to_vec()),
            (4, 4) => Self::PossibleWithProfileState {
                issue: decoder.bytes().map_err(|_| ())?.to_vec(),
                profile_state: decoder.bytes().map_err(|_| ())?.to_vec(),
            },
            (5, 2) => Self::PostEntryTimeout,
            (6, 2) => Self::NotApplied,
            (7, 2) => Self::Invalid,
            _ => return Err(()),
        };
        if decoder.position() != bytes.len() || value.to_cbor()? != bytes {
            return Err(());
        }
        Ok(value)
    }
}

fn encode_response_one(
    encoder: &mut Encoder<&mut Vec<u8>>,
    kind: u8,
    value: &[u8],
) -> Result<(), ()> {
    if value.is_empty() || value.len() > MAX_PROVIDER_RESULT_BYTES {
        return Err(());
    }
    encoder.array(3).map_err(|_| ())?;
    encoder.u8(VERSION).map_err(|_| ())?;
    encoder.u8(kind).map_err(|_| ())?;
    encoder.bytes(value).map_err(|_| ())?;
    Ok(())
}

fn encode_optional_text(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: Option<&str>,
) -> Result<(), ()> {
    match value {
        Some(value) => encoder.str(value).map_err(|_| ())?,
        None => encoder.null().map_err(|_| ())?,
    };
    Ok(())
}

fn encode_optional_bytes(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: Option<&[u8]>,
) -> Result<(), ()> {
    match value {
        Some(value) => encoder.bytes(value).map_err(|_| ())?,
        None => encoder.null().map_err(|_| ())?,
    };
    Ok(())
}

fn decode_optional_text(decoder: &mut Decoder<'_>) -> Result<Option<String>, ()> {
    if decoder.datatype().map_err(|_| ())? == Type::Null {
        decoder.null().map_err(|_| ())?;
        Ok(None)
    } else {
        Ok(Some(decoder.str().map_err(|_| ())?.to_owned()))
    }
}

fn decode_optional_bytes(decoder: &mut Decoder<'_>) -> Result<Option<Vec<u8>>, ()> {
    if decoder.datatype().map_err(|_| ())? == Type::Null {
        decoder.null().map_err(|_| ())?;
        Ok(None)
    } else {
        Ok(Some(decoder.bytes().map_err(|_| ())?.to_vec()))
    }
}

impl QualificationCredentialLeaseRequest {
    /// Constructs one bounded, capability-free credential-lease request.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when any field is outside the closed wire grammar.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_context_sha256: [u8; 32],
        operation_id: impl Into<String>,
        workload_id: impl Into<String>,
        profile_id: impl Into<String>,
        profile_version: u16,
        provider_kind: impl Into<String>,
        connection_alias: impl Into<String>,
        connection_id: impl Into<String>,
        connection_generation: u64,
        descriptor_sha256: [u8; 32],
        account_sha256: [u8; 32],
        contract: impl Into<String>,
        descriptor_schema: impl Into<String>,
        credential_scope: impl Into<String>,
    ) -> Result<Self, ()> {
        let value = Self {
            source_context_sha256,
            operation_id: operation_id.into(),
            workload_id: workload_id.into(),
            profile_id: profile_id.into(),
            profile_version,
            provider_kind: provider_kind.into(),
            connection_alias: connection_alias.into(),
            connection_id: connection_id.into(),
            connection_generation,
            descriptor_sha256,
            account_sha256,
            contract: contract.into(),
            descriptor_schema: descriptor_schema.into(),
            credential_scope: credential_scope.into(),
        };
        value.validate().then_some(value).ok_or(())
    }

    /// Encodes the exact canonical lease request.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when the value is invalid, oversized, or cannot be encoded.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ()> {
        if !self.validate() {
            return Err(());
        }
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        encoder.array(FIELD_COUNT).map_err(|_| ())?;
        encoder.u8(VERSION).map_err(|_| ())?;
        encoder.bytes(&self.source_context_sha256).map_err(|_| ())?;
        encoder.str(&self.operation_id).map_err(|_| ())?;
        encoder.str(&self.workload_id).map_err(|_| ())?;
        encoder.str(&self.profile_id).map_err(|_| ())?;
        encoder.u16(self.profile_version).map_err(|_| ())?;
        encoder.str(&self.provider_kind).map_err(|_| ())?;
        encoder.str(&self.connection_alias).map_err(|_| ())?;
        encoder.str(&self.connection_id).map_err(|_| ())?;
        encoder.u64(self.connection_generation).map_err(|_| ())?;
        encoder.bytes(&self.descriptor_sha256).map_err(|_| ())?;
        encoder.bytes(&self.account_sha256).map_err(|_| ())?;
        encoder.str(&self.contract).map_err(|_| ())?;
        encoder.str(&self.descriptor_schema).map_err(|_| ())?;
        encoder.str(&self.credential_scope).map_err(|_| ())?;
        (bytes.len() <= MAX_REQUEST_BYTES)
            .then_some(bytes)
            .ok_or(())
    }

    /// Returns the capability-free commitment used to bind the broker lease,
    /// `ProviderProxy` handoff, and the signed `CredentialBroker` observations.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` if the request cannot be canonically encoded.
    pub fn lease_sha256(&self) -> Result<[u8; 32], ()> {
        let mut digest = Sha256::new();
        digest.update(b"AUTHS-QUALIFICATION-CREDENTIAL-LEASE\0\x01");
        digest.update(self.to_cbor()?);
        Ok(digest.finalize().into())
    }

    /// Decodes one exact canonical lease request.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` for malformed, noncanonical, or oversized input.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
            return Err(());
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| ())? != Some(FIELD_COUNT)
            || decoder.u8().map_err(|_| ())? != VERSION
        {
            return Err(());
        }
        let digest = |bytes: &[u8]| bytes.try_into().map_err(|_| ());
        let value = Self::new(
            digest(decoder.bytes().map_err(|_| ())?)?,
            decoder.str().map_err(|_| ())?,
            decoder.str().map_err(|_| ())?,
            decoder.str().map_err(|_| ())?,
            decoder.u16().map_err(|_| ())?,
            decoder.str().map_err(|_| ())?,
            decoder.str().map_err(|_| ())?,
            decoder.str().map_err(|_| ())?,
            decoder.u64().map_err(|_| ())?,
            digest(decoder.bytes().map_err(|_| ())?)?,
            digest(decoder.bytes().map_err(|_| ())?)?,
            decoder.str().map_err(|_| ())?,
            decoder.str().map_err(|_| ())?,
            decoder.str().map_err(|_| ())?,
        )?;
        if decoder.position() != bytes.len() || value.to_cbor()? != bytes {
            return Err(());
        }
        Ok(value)
    }

    fn validate(&self) -> bool {
        self.profile_version != 0
            && self.connection_generation != 0
            && registered(&self.operation_id, 160)
            && graphic(&self.workload_id, 512)
            && semantic(&self.profile_id)
            && lower_token(&self.provider_kind)
            && lower_token(&self.connection_alias)
            && graphic(&self.connection_id, 160)
            && semantic(&self.contract)
            && semantic(&self.descriptor_schema)
            && semantic(&self.credential_scope)
    }

    #[must_use]
    pub const fn source_context_sha256(&self) -> &[u8; 32] {
        &self.source_context_sha256
    }
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    #[must_use]
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    #[must_use]
    pub const fn profile_version(&self) -> u16 {
        self.profile_version
    }
    #[must_use]
    pub fn provider_kind(&self) -> &str {
        &self.provider_kind
    }
    #[must_use]
    pub fn connection_alias(&self) -> &str {
        &self.connection_alias
    }
    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }
    #[must_use]
    pub const fn connection_generation(&self) -> u64 {
        self.connection_generation
    }
    #[must_use]
    pub const fn descriptor_sha256(&self) -> &[u8; 32] {
        &self.descriptor_sha256
    }
    #[must_use]
    pub const fn account_sha256(&self) -> &[u8; 32] {
        &self.account_sha256
    }
    #[must_use]
    pub fn contract(&self) -> &str {
        &self.contract
    }
    #[must_use]
    pub fn descriptor_schema(&self) -> &str {
        &self.descriptor_schema
    }
    #[must_use]
    pub fn credential_scope(&self) -> &str {
        &self.credential_scope
    }
}

fn graphic(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn registered(value: &str, maximum: usize) -> bool {
    graphic(value, maximum)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn lower_token(value: &str) -> bool {
    graphic(value, 128)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn semantic(value: &str) -> bool {
    graphic(value, 160)
        && value.contains('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}

#[cfg(test)]
mod tests {
    use super::{
        QualificationCredentialLeaseRequest, QualificationProviderCallKind,
        QualificationProviderCallRequest, QualificationProviderCallResponse,
    };
    use zeroize::Zeroizing;

    #[test]
    fn credential_request_is_exact_canonical_and_secret_free() {
        let request = QualificationCredentialLeaseRequest::new(
            [1; 32],
            "operation-1",
            "did:key:workload",
            "auths.stripe.refund",
            1,
            "stripe",
            "primary",
            "connection-1",
            1,
            [2; 32],
            [3; 32],
            "auths.stripe.connection/1",
            "auths.stripe.connection-descriptor/1",
            "stripe.refunds.write/1",
        )
        .unwrap();
        let bytes = request.to_cbor().unwrap();
        assert_eq!(
            QualificationCredentialLeaseRequest::from_cbor(&bytes).unwrap(),
            request
        );
        let mut too_short = bytes.clone();
        too_short[0] = 0x8e;
        assert!(QualificationCredentialLeaseRequest::from_cbor(&too_short).is_err());
        let mut too_long = bytes.clone();
        too_long[0] = 0x90;
        assert!(QualificationCredentialLeaseRequest::from_cbor(&too_long).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(QualificationCredentialLeaseRequest::from_cbor(&trailing).is_err());
    }

    fn provider_request(
        kind: QualificationProviderCallKind,
        credential_lease_sha256: [u8; 32],
        credential_capability: [u8; 32],
    ) -> QualificationProviderCallRequest {
        QualificationProviderCallRequest::new(
            [7; 32],
            "operation-1",
            "auths.stripe.refund",
            1,
            4,
            kind,
            credential_lease_sha256,
            vec![0xa1, 0x01, 0x02],
            vec![0xa0],
            Zeroizing::new(credential_capability),
            Some("auths.stripe.refund-verifier-configuration/1".into()),
            Some(vec![0xa0]),
            1_735_689_600,
        )
        .unwrap()
    }

    #[test]
    fn provider_request_is_exact_canonical_and_redacted() {
        let request = provider_request(QualificationProviderCallKind::Execute, [8; 32], [9; 32]);
        let mut bytes = request.to_cbor().unwrap();
        let decoded = QualificationProviderCallRequest::from_cbor(&mut bytes).unwrap();
        assert!(bytes.iter().all(|byte| *byte == 0));
        assert_eq!(decoded.operation_id(), "operation-1");
        assert_eq!(decoded.kind(), QualificationProviderCallKind::Execute);
        assert_eq!(decoded.credential_lease_sha256(), &[8; 32]);
        assert_eq!(decoded.credential_capability(), &[9; 32]);
        let debug = format!("{decoded:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("090909"));

        let mut malformed = decoded.to_cbor().unwrap();
        malformed[0] = 0x8d;
        assert!(QualificationProviderCallRequest::from_cbor(&mut malformed).is_err());
        let mut trailing = decoded.to_cbor().unwrap();
        trailing.push(0);
        assert!(QualificationProviderCallRequest::from_cbor(&mut trailing).is_err());

        let execute = decoded.to_cbor().unwrap();
        let reconcile =
            provider_request(QualificationProviderCallKind::Reconcile, [8; 32], [9; 32])
                .to_cbor()
                .unwrap();
        let changed_lease =
            provider_request(QualificationProviderCallKind::Execute, [9; 32], [9; 32])
                .to_cbor()
                .unwrap();
        assert_ne!(execute, reconcile);
        assert_ne!(execute, changed_lease);
    }

    #[test]
    fn provider_response_roster_round_trips_canonically() {
        for response in [
            QualificationProviderCallResponse::Success(vec![1]),
            QualificationProviderCallResponse::PreEntry(vec![2]),
            QualificationProviderCallResponse::PreEntryPending,
            QualificationProviderCallResponse::Possible(vec![3]),
            QualificationProviderCallResponse::PossibleWithProfileState {
                issue: vec![4],
                profile_state: vec![5],
            },
            QualificationProviderCallResponse::PostEntryTimeout,
            QualificationProviderCallResponse::NotApplied,
            QualificationProviderCallResponse::Invalid,
        ] {
            let bytes = response.to_cbor().unwrap();
            assert_eq!(
                QualificationProviderCallResponse::from_cbor(&bytes).unwrap(),
                response
            );
            let mut trailing = bytes;
            trailing.push(0);
            assert!(QualificationProviderCallResponse::from_cbor(&trailing).is_err());
        }
        assert!(
            QualificationProviderCallResponse::Success(Vec::new())
                .to_cbor()
                .is_err()
        );
    }
}
