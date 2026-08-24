use crate::credential::CredentialReferenceCommitment;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use minicbor::{Decoder, Encoder};
use sha2::{Digest as _, Sha256};
use std::{fmt, num::NonZeroU64};
use thiserror::Error;

const RECORD_SCHEMA_VERSION: u8 = 1;
const RECORD_FIELD_COUNT: u64 = 17;
const MAX_RECORD_BYTES: usize = 262_144;
const MAX_DESCRIPTOR_BYTES: usize = 65_536;
const MAX_WORKLOADS: usize = 256;
const MAX_PROFILES: usize = 32;

/// Lowercase provider kind.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProviderKind(String);

impl ProviderKind {
    /// Parses `[a-z][a-z0-9-]{0,63}`.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRecordError::InvalidProviderKind`] for an invalid value.
    pub fn parse(value: impl Into<String>) -> Result<Self, ConnectionRecordError> {
        let value = value.into();
        if !is_lower_token(&value, 64) {
            return Err(ConnectionRecordError::InvalidProviderKind);
        }
        Ok(Self(value))
    }

    /// Returns the canonical token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Human-selected connection alias.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConnectionAlias(String);

impl ConnectionAlias {
    /// Parses `[a-z][a-z0-9-]{0,63}`.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRecordError::InvalidAlias`] for an invalid value.
    pub fn parse(value: impl Into<String>) -> Result<Self, ConnectionRecordError> {
        let value = value.into();
        if !is_lower_token(&value, 64) {
            return Err(ConnectionRecordError::InvalidAlias);
        }
        Ok(Self(value))
    }

    /// Returns the canonical token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Versioned semantic identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SemanticId(String);

impl SemanticId {
    /// Parses `[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}`.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRecordError::InvalidSemanticId`] for an invalid value.
    pub fn parse(value: impl Into<String>) -> Result<Self, ConnectionRecordError> {
        let value = value.into();
        let valid = (1..=128).contains(&value.len())
            && value.is_ascii()
            && value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric()
                    || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'-'))
            });
        if !valid {
            return Err(ConnectionRecordError::InvalidSemanticId);
        }
        Ok(Self(value))
    }

    /// Returns the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Unpredictable internal connection identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(String);

impl ConnectionId {
    /// Generates `conn_` plus base64url for 16 operating-system random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRecordError::Randomness`] if the operating system
    /// random source is unavailable.
    pub fn generate() -> Result<Self, ConnectionRecordError> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| ConnectionRecordError::Randomness)?;
        Ok(Self(format!(
            "conn_{}",
            Base64UrlUnpadded::encode_string(&random)
        )))
    }

    /// Parses the exact internal identifier shape.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRecordError::InvalidConnectionId`] if the value is malformed.
    pub fn parse(value: impl Into<String>) -> Result<Self, ConnectionRecordError> {
        let value = value.into();
        let encoded = value
            .strip_prefix("conn_")
            .ok_or(ConnectionRecordError::InvalidConnectionId)?;
        let mut decoded = [0_u8; 16];
        let bytes = Base64UrlUnpadded::decode(encoded, &mut decoded)
            .map_err(|_| ConnectionRecordError::InvalidConnectionId)?;
        if bytes.len() != 16 || Base64UrlUnpadded::encode_string(bytes) != encoded {
            return Err(ConnectionRecordError::InvalidConnectionId);
        }
        Ok(Self(value))
    }

    /// Returns the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ConnectionId")
            .field(&self.0)
            .finish()
    }
}

/// One profile/version authorization in a connection record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConnectionProfile {
    id: SemanticId,
    version: u16,
}

impl ConnectionProfile {
    /// Constructs an allowed profile.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRecordError::InvalidProfile`] when the version is zero.
    pub fn new(id: SemanticId, version: u16) -> Result<Self, ConnectionRecordError> {
        if version == 0 {
            return Err(ConnectionRecordError::InvalidProfile);
        }
        Ok(Self { id, version })
    }

    /// Returns the profile identifier.
    #[must_use]
    pub const fn id(&self) -> &SemanticId {
        &self.id
    }

    /// Returns the profile version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }
}

/// Administrative connection state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    /// New operations and recovery are allowed.
    Active,
    /// New operations are refused; recovery remains available.
    Disabled,
    /// New credential leases are refused and the record is retained as a tombstone.
    Revoked,
}

impl ConnectionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
        }
    }

    fn parse(value: &str) -> Result<Self, ConnectionRecordError> {
        match value {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            "revoked" => Ok(Self::Revoked),
            _ => Err(ConnectionRecordError::InvalidState),
        }
    }
}

/// Exact durable provider-connection record (`auths.provider-connection/1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionRecord {
    provider_kind: ProviderKind,
    alias: ConnectionAlias,
    connection_id: ConnectionId,
    contract: SemanticId,
    descriptor_schema: SemanticId,
    descriptor: Vec<u8>,
    descriptor_commitment: [u8; 32],
    account_commitment: [u8; 32],
    credential_reference_commitment: [u8; 32],
    generation: NonZeroU64,
    state: ConnectionState,
    allowed_workloads: Vec<String>,
    allowed_profiles: Vec<ConnectionProfile>,
    created_at_unix_seconds: u64,
    updated_at_unix_seconds: u64,
    revoked_at_unix_seconds: Option<u64>,
}

impl ConnectionRecord {
    /// Constructs and validates one exact durable connection record.
    #[allow(clippy::too_many_arguments)]
    ///
    /// # Errors
    ///
    /// Returns a closed validation error for malformed, unsorted, duplicate,
    /// contradictory, or oversized data.
    pub fn new(
        provider_kind: ProviderKind,
        alias: ConnectionAlias,
        connection_id: ConnectionId,
        contract: SemanticId,
        descriptor_schema: SemanticId,
        descriptor: Vec<u8>,
        account_commitment: [u8; 32],
        credential_reference_commitment: [u8; 32],
        generation: NonZeroU64,
        state: ConnectionState,
        allowed_workloads: Vec<String>,
        allowed_profiles: Vec<ConnectionProfile>,
        created_at_unix_seconds: u64,
        updated_at_unix_seconds: u64,
        revoked_at_unix_seconds: Option<u64>,
    ) -> Result<Self, ConnectionRecordError> {
        if !(1..=MAX_DESCRIPTOR_BYTES).contains(&descriptor.len()) {
            return Err(ConnectionRecordError::InvalidDescriptor);
        }
        let descriptor_commitment = Sha256::digest(&descriptor).into();
        let record = Self {
            provider_kind,
            alias,
            connection_id,
            contract,
            descriptor_schema,
            descriptor,
            descriptor_commitment,
            account_commitment,
            credential_reference_commitment,
            generation,
            state,
            allowed_workloads,
            allowed_profiles,
            created_at_unix_seconds,
            updated_at_unix_seconds,
            revoked_at_unix_seconds,
        };
        record.validate()?;
        if record.to_canonical_cbor()?.len() > MAX_RECORD_BYTES {
            return Err(ConnectionRecordError::RecordTooLarge);
        }
        Ok(record)
    }

    /// Encodes the exact integer-keyed canonical CBOR record.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRecordError::Encoding`] on an unexpected encoder failure.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ConnectionRecordError> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(RECORD_FIELD_COUNT).map_err(encoding)?;
        encoder
            .u8(1)
            .and_then(|value| value.u8(RECORD_SCHEMA_VERSION))
            .map_err(encoding)?;
        encode_text(&mut encoder, 2, self.provider_kind.as_str())?;
        encode_text(&mut encoder, 3, self.alias.as_str())?;
        encode_text(&mut encoder, 4, self.connection_id.as_str())?;
        encode_text(&mut encoder, 5, self.contract.as_str())?;
        encode_text(&mut encoder, 6, self.descriptor_schema.as_str())?;
        encoder
            .u8(7)
            .and_then(|value| value.bytes(&self.descriptor))
            .map_err(encoding)?;
        encoder
            .u8(8)
            .and_then(|value| value.bytes(&self.descriptor_commitment))
            .map_err(encoding)?;
        encoder
            .u8(9)
            .and_then(|value| value.bytes(&self.account_commitment))
            .map_err(encoding)?;
        encoder
            .u8(10)
            .and_then(|value| value.bytes(&self.credential_reference_commitment))
            .map_err(encoding)?;
        encoder
            .u8(11)
            .and_then(|value| value.u64(self.generation.get()))
            .map_err(encoding)?;
        encode_text(&mut encoder, 12, self.state.as_str())?;
        encoder
            .u8(13)
            .and_then(|value| value.array(self.allowed_workloads.len() as u64))
            .map_err(encoding)?;
        for workload in &self.allowed_workloads {
            encoder.str(workload).map_err(encoding)?;
        }
        encoder
            .u8(14)
            .and_then(|value| value.array(self.allowed_profiles.len() as u64))
            .map_err(encoding)?;
        for profile in &self.allowed_profiles {
            encoder.array(2).map_err(encoding)?;
            encoder.str(profile.id.as_str()).map_err(encoding)?;
            encoder.u16(profile.version).map_err(encoding)?;
        }
        encoder
            .u8(15)
            .and_then(|value| value.u64(self.created_at_unix_seconds))
            .map_err(encoding)?;
        encoder
            .u8(16)
            .and_then(|value| value.u64(self.updated_at_unix_seconds))
            .map_err(encoding)?;
        encoder.u8(17).map_err(encoding)?;
        match self.revoked_at_unix_seconds {
            Some(value) => {
                encoder.u64(value).map_err(encoding)?;
            }
            None => {
                encoder.null().map_err(encoding)?;
            }
        }
        Ok(encoder.into_writer())
    }

    /// Decodes and revalidates one exact canonical CBOR record.
    ///
    /// # Errors
    ///
    /// Rejects indefinite/unknown maps, noncanonical values, unknown fields,
    /// trailing bytes, and any invalid invariant.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ConnectionRecordError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ConnectionRecordError::RecordTooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.map().map_err(decoding)? != Some(RECORD_FIELD_COUNT) {
            return Err(ConnectionRecordError::InvalidShape);
        }
        expect_key(&mut decoder, 1)?;
        if decoder.u8().map_err(decoding)? != RECORD_SCHEMA_VERSION {
            return Err(ConnectionRecordError::InvalidSchema);
        }
        expect_key(&mut decoder, 2)?;
        let provider_kind = ProviderKind::parse(decoder.str().map_err(decoding)?)?;
        expect_key(&mut decoder, 3)?;
        let alias = ConnectionAlias::parse(decoder.str().map_err(decoding)?)?;
        expect_key(&mut decoder, 4)?;
        let connection_id = ConnectionId::parse(decoder.str().map_err(decoding)?)?;
        expect_key(&mut decoder, 5)?;
        let contract = SemanticId::parse(decoder.str().map_err(decoding)?)?;
        expect_key(&mut decoder, 6)?;
        let descriptor_schema = SemanticId::parse(decoder.str().map_err(decoding)?)?;
        expect_key(&mut decoder, 7)?;
        let descriptor = decoder.bytes().map_err(decoding)?.to_vec();
        expect_key(&mut decoder, 8)?;
        let descriptor_commitment = decode_commitment(&mut decoder)?;
        expect_key(&mut decoder, 9)?;
        let account_commitment = decode_commitment(&mut decoder)?;
        expect_key(&mut decoder, 10)?;
        let credential_reference_commitment = decode_commitment(&mut decoder)?;
        expect_key(&mut decoder, 11)?;
        let generation = NonZeroU64::new(decoder.u64().map_err(decoding)?)
            .ok_or(ConnectionRecordError::InvalidGeneration)?;
        expect_key(&mut decoder, 12)?;
        let state = ConnectionState::parse(decoder.str().map_err(decoding)?)?;
        expect_key(&mut decoder, 13)?;
        let allowed_workloads = decode_workloads(&mut decoder)?;
        expect_key(&mut decoder, 14)?;
        let allowed_profiles = decode_profiles(&mut decoder)?;
        expect_key(&mut decoder, 15)?;
        let created_at_unix_seconds = decoder.u64().map_err(decoding)?;
        expect_key(&mut decoder, 16)?;
        let updated_at_unix_seconds = decoder.u64().map_err(decoding)?;
        expect_key(&mut decoder, 17)?;
        let revoked_at_unix_seconds =
            if decoder.datatype().map_err(decoding)? == minicbor::data::Type::Null {
                decoder.null().map_err(decoding)?;
                None
            } else {
                Some(decoder.u64().map_err(decoding)?)
            };
        if decoder.position() != bytes.len() {
            return Err(ConnectionRecordError::TrailingBytes);
        }
        let record = Self::new(
            provider_kind,
            alias,
            connection_id,
            contract,
            descriptor_schema,
            descriptor,
            account_commitment,
            credential_reference_commitment,
            generation,
            state,
            allowed_workloads,
            allowed_profiles,
            created_at_unix_seconds,
            updated_at_unix_seconds,
            revoked_at_unix_seconds,
        )?;
        if record.descriptor_commitment != descriptor_commitment
            || record.to_canonical_cbor()?.as_slice() != bytes
        {
            return Err(ConnectionRecordError::Noncanonical);
        }
        Ok(record)
    }

    fn validate(&self) -> Result<(), ConnectionRecordError> {
        if !(1..=MAX_WORKLOADS).contains(&self.allowed_workloads.len())
            || !strictly_sorted_unique(&self.allowed_workloads)
            || self
                .allowed_workloads
                .iter()
                .any(|value| !is_ascii_graphic(value, 128))
        {
            return Err(ConnectionRecordError::InvalidWorkloads);
        }
        if !(1..=MAX_PROFILES).contains(&self.allowed_profiles.len())
            || !strictly_sorted_unique(&self.allowed_profiles)
        {
            return Err(ConnectionRecordError::InvalidProfiles);
        }
        if self.created_at_unix_seconds > self.updated_at_unix_seconds {
            return Err(ConnectionRecordError::InvalidTimestamps);
        }
        match (self.state, self.revoked_at_unix_seconds) {
            (ConnectionState::Revoked, Some(value))
                if (self.created_at_unix_seconds..=self.updated_at_unix_seconds)
                    .contains(&value) => {}
            (ConnectionState::Revoked, _) | (_, Some(_)) => {
                return Err(ConnectionRecordError::InvalidTimestamps);
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns the provider kind.
    #[must_use]
    pub const fn provider_kind(&self) -> &ProviderKind {
        &self.provider_kind
    }
    /// Returns the human-selected alias.
    #[must_use]
    pub const fn alias(&self) -> &ConnectionAlias {
        &self.alias
    }
    /// Returns the immutable internal connection ID.
    #[must_use]
    pub const fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }
    /// Returns the provider connection contract.
    #[must_use]
    pub const fn contract(&self) -> &SemanticId {
        &self.contract
    }
    /// Returns the descriptor schema.
    #[must_use]
    pub const fn descriptor_schema(&self) -> &SemanticId {
        &self.descriptor_schema
    }
    /// Returns the opaque provider descriptor.
    #[must_use]
    pub fn descriptor(&self) -> &[u8] {
        &self.descriptor
    }
    /// Returns the descriptor commitment.
    #[must_use]
    pub const fn descriptor_commitment(&self) -> &[u8; 32] {
        &self.descriptor_commitment
    }
    /// Returns the provider-account commitment.
    #[must_use]
    pub const fn account_commitment(&self) -> &[u8; 32] {
        &self.account_commitment
    }
    /// Returns the credential-reference commitment.
    #[must_use]
    pub const fn credential_reference_commitment(&self) -> &[u8; 32] {
        &self.credential_reference_commitment
    }
    /// Returns the security-relevant generation.
    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.generation
    }
    /// Returns the administrative state.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.state
    }
    /// Returns allowed workload identifiers.
    #[must_use]
    pub fn allowed_workloads(&self) -> &[String] {
        &self.allowed_workloads
    }
    /// Returns allowed profile/version pairs.
    #[must_use]
    pub fn allowed_profiles(&self) -> &[ConnectionProfile] {
        &self.allowed_profiles
    }
    /// Returns the creation time.
    #[must_use]
    pub const fn created_at_unix_seconds(&self) -> u64 {
        self.created_at_unix_seconds
    }
    /// Returns the last update time.
    #[must_use]
    pub const fn updated_at_unix_seconds(&self) -> u64 {
        self.updated_at_unix_seconds
    }
    /// Returns the revocation time for a revoked tombstone.
    #[must_use]
    pub const fn revoked_at_unix_seconds(&self) -> Option<u64> {
        self.revoked_at_unix_seconds
    }

    /// Reconstructs the exact sealed binding for an unresolved older
    /// generation after the caller has authenticated the operation and loaded
    /// that generation's retained credential commitment.
    ///
    /// This recovery-only projection deliberately does not require the current
    /// record to be active. Disablement and rotation reject new operations but
    /// cannot erase the connection identity of an operation that may already
    /// have entered its provider. The caller must still compare the recorded
    /// descriptor and account commitments before invoking this method.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRecordError::InvalidGeneration`] when recovery asks
    /// for a generation newer than the durable connection record.
    pub fn binding_for_recovery(
        &self,
        generation: NonZeroU64,
        credential_reference_commitment: CredentialReferenceCommitment,
    ) -> Result<ConnectionBinding, ConnectionRecordError> {
        if generation > self.generation {
            return Err(ConnectionRecordError::InvalidGeneration);
        }
        Ok(ConnectionBinding {
            provider_kind: self.provider_kind.clone(),
            alias: self.alias.clone(),
            connection_id: self.connection_id.clone(),
            contract: self.contract.clone(),
            descriptor_schema: self.descriptor_schema.clone(),
            descriptor: self.descriptor.clone(),
            generation,
            descriptor_commitment: self.descriptor_commitment,
            account_commitment: self.account_commitment,
            credential_reference_commitment: *credential_reference_commitment.as_bytes(),
        })
    }

    /// Creates one generation-incrementing administrative state transition.
    ///
    /// Revoked records are terminal tombstones. Active and disabled records
    /// may transition between those states or to revoked. The original
    /// connection identity, descriptor, commitments, and allowlists remain
    /// byte-identical.
    ///
    /// # Errors
    ///
    /// Rejects time regression, generation overflow, a no-op transition, or
    /// any attempt to leave the revoked state.
    pub fn transition_state(
        &self,
        state: ConnectionState,
        credential_reference_commitment: [u8; 32],
        updated_at_unix_seconds: u64,
    ) -> Result<Self, ConnectionRecordError> {
        if state == self.state
            || self.state == ConnectionState::Revoked
            || updated_at_unix_seconds < self.updated_at_unix_seconds
        {
            return Err(ConnectionRecordError::InvalidState);
        }
        let generation = NonZeroU64::new(
            self.generation
                .get()
                .checked_add(1)
                .ok_or(ConnectionRecordError::InvalidGeneration)?,
        )
        .ok_or(ConnectionRecordError::InvalidGeneration)?;
        Self::new(
            self.provider_kind.clone(),
            self.alias.clone(),
            self.connection_id.clone(),
            self.contract.clone(),
            self.descriptor_schema.clone(),
            self.descriptor.clone(),
            self.account_commitment,
            credential_reference_commitment,
            generation,
            state,
            self.allowed_workloads.clone(),
            self.allowed_profiles.clone(),
            self.created_at_unix_seconds,
            updated_at_unix_seconds,
            (state == ConnectionState::Revoked).then_some(updated_at_unix_seconds),
        )
    }

    /// Creates a generation-incrementing credential/descriptor rotation.
    ///
    /// # Errors
    ///
    /// Revoked records, invalid descriptors, time regression, and generation
    /// overflow fail without modifying the current record.
    pub fn rotated(
        &self,
        descriptor: Vec<u8>,
        account_commitment: [u8; 32],
        credential_reference_commitment: [u8; 32],
        updated_at_unix_seconds: u64,
    ) -> Result<Self, ConnectionRecordError> {
        if self.state == ConnectionState::Revoked
            || updated_at_unix_seconds < self.updated_at_unix_seconds
        {
            return Err(ConnectionRecordError::InvalidState);
        }
        let generation = NonZeroU64::new(
            self.generation
                .get()
                .checked_add(1)
                .ok_or(ConnectionRecordError::InvalidGeneration)?,
        )
        .ok_or(ConnectionRecordError::InvalidGeneration)?;
        Self::new(
            self.provider_kind.clone(),
            self.alias.clone(),
            self.connection_id.clone(),
            self.contract.clone(),
            self.descriptor_schema.clone(),
            descriptor,
            account_commitment,
            credential_reference_commitment,
            generation,
            self.state,
            self.allowed_workloads.clone(),
            self.allowed_profiles.clone(),
            self.created_at_unix_seconds,
            updated_at_unix_seconds,
            None,
        )
    }

    /// Creates a generation-incrementing authorization replacement.
    ///
    /// # Errors
    ///
    /// The ordinary record bounds, revoked-state finality, time monotonicity,
    /// and generation overflow are enforced atomically.
    pub fn with_authorization(
        &self,
        allowed_workloads: Vec<String>,
        allowed_profiles: Vec<ConnectionProfile>,
        credential_reference_commitment: [u8; 32],
        updated_at_unix_seconds: u64,
    ) -> Result<Self, ConnectionRecordError> {
        if self.state == ConnectionState::Revoked
            || updated_at_unix_seconds < self.updated_at_unix_seconds
        {
            return Err(ConnectionRecordError::InvalidState);
        }
        let generation = NonZeroU64::new(
            self.generation
                .get()
                .checked_add(1)
                .ok_or(ConnectionRecordError::InvalidGeneration)?,
        )
        .ok_or(ConnectionRecordError::InvalidGeneration)?;
        Self::new(
            self.provider_kind.clone(),
            self.alias.clone(),
            self.connection_id.clone(),
            self.contract.clone(),
            self.descriptor_schema.clone(),
            self.descriptor.clone(),
            self.account_commitment,
            credential_reference_commitment,
            generation,
            self.state,
            allowed_workloads,
            allowed_profiles,
            self.created_at_unix_seconds,
            updated_at_unix_seconds,
            None,
        )
    }
}

/// Internal operation binding produced only by an authorized registry lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionBinding {
    pub(crate) provider_kind: ProviderKind,
    pub(crate) alias: ConnectionAlias,
    pub(crate) connection_id: ConnectionId,
    pub(crate) contract: SemanticId,
    pub(crate) descriptor_schema: SemanticId,
    pub(crate) descriptor: Vec<u8>,
    pub(crate) generation: NonZeroU64,
    pub(crate) descriptor_commitment: [u8; 32],
    pub(crate) account_commitment: [u8; 32],
    pub(crate) credential_reference_commitment: [u8; 32],
}

impl ConnectionBinding {
    /// Returns the provider kind.
    #[must_use]
    pub const fn provider_kind(&self) -> &ProviderKind {
        &self.provider_kind
    }
    /// Returns the selected alias.
    #[must_use]
    pub const fn alias(&self) -> &ConnectionAlias {
        &self.alias
    }
    /// Returns the immutable connection ID bound into the operation.
    #[must_use]
    pub const fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }
    /// Returns the connection contract.
    #[must_use]
    pub const fn contract(&self) -> &SemanticId {
        &self.contract
    }
    /// Returns the descriptor schema.
    #[must_use]
    pub const fn descriptor_schema(&self) -> &SemanticId {
        &self.descriptor_schema
    }
    /// Returns the provider-owned, non-secret descriptor snapshot sealed into
    /// this operation binding.
    #[must_use]
    pub fn descriptor(&self) -> &[u8] {
        &self.descriptor
    }
    /// Returns the bound connection generation.
    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.generation
    }
    /// Returns the bound descriptor commitment.
    #[must_use]
    pub const fn descriptor_commitment(&self) -> &[u8; 32] {
        &self.descriptor_commitment
    }
    /// Returns the bound provider-account commitment.
    #[must_use]
    pub const fn account_commitment(&self) -> &[u8; 32] {
        &self.account_commitment
    }
    /// Returns the commitment to the retained credential reference and generation.
    ///
    /// Domain-owned durable prepared records bind this non-secret value so a
    /// credential rotation cannot be substituted between preflight and effect.
    #[must_use]
    pub const fn credential_reference_commitment(&self) -> &[u8; 32] {
        &self.credential_reference_commitment
    }
}

/// Closed durable-record validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ConnectionRecordError {
    /// Provider kind token is invalid.
    #[error("invalid provider kind")]
    InvalidProviderKind,
    /// Alias token is invalid.
    #[error("invalid connection alias")]
    InvalidAlias,
    /// Semantic identifier is invalid.
    #[error("invalid semantic identifier")]
    InvalidSemanticId,
    /// Internal connection identifier is invalid.
    #[error("invalid connection identifier")]
    InvalidConnectionId,
    /// Operating-system randomness failed.
    #[error("operating-system randomness unavailable")]
    Randomness,
    /// Profile pair is invalid.
    #[error("invalid profile authorization")]
    InvalidProfile,
    /// Opaque descriptor is empty or oversized.
    #[error("invalid connection descriptor")]
    InvalidDescriptor,
    /// Generation is zero.
    #[error("invalid connection generation")]
    InvalidGeneration,
    /// State token is unknown.
    #[error("invalid connection state")]
    InvalidState,
    /// Workload list is unbounded, malformed, duplicate, or unsorted.
    #[error("invalid workload authorization list")]
    InvalidWorkloads,
    /// Profile list is unbounded, duplicate, or unsorted.
    #[error("invalid profile authorization list")]
    InvalidProfiles,
    /// Timestamps contradict the connection state.
    #[error("invalid connection timestamps")]
    InvalidTimestamps,
    /// Encoded record exceeds its hard ceiling.
    #[error("connection record exceeds maximum size")]
    RecordTooLarge,
    /// CBOR map shape is not the exact record shape.
    #[error("invalid connection record shape")]
    InvalidShape,
    /// CBOR schema version is unknown.
    #[error("unknown connection record schema")]
    InvalidSchema,
    /// Encoded record is not byte-canonical or a commitment changed.
    #[error("noncanonical connection record")]
    Noncanonical,
    /// Encoded record contains trailing bytes.
    #[error("connection record contains trailing bytes")]
    TrailingBytes,
    /// Canonical encoding failed.
    #[error("connection record encoding failed")]
    Encoding,
    /// Canonical decoding failed.
    #[error("connection record decoding failed")]
    Decoding,
}

fn is_lower_token(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len())
        && value.is_ascii()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || (index > 0 && (byte.is_ascii_digit() || byte == b'-'))
        })
}

fn is_ascii_graphic(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len()) && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn encode_text(
    encoder: &mut Encoder<Vec<u8>>,
    key: u8,
    value: &str,
) -> Result<(), ConnectionRecordError> {
    encoder
        .u8(key)
        .and_then(|item| item.str(value))
        .map_err(encoding)?;
    Ok(())
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), ConnectionRecordError> {
    if decoder.u8().map_err(decoding)? != expected {
        return Err(ConnectionRecordError::InvalidShape);
    }
    Ok(())
}

fn decode_commitment(decoder: &mut Decoder<'_>) -> Result<[u8; 32], ConnectionRecordError> {
    decoder
        .bytes()
        .map_err(decoding)?
        .try_into()
        .map_err(|_| ConnectionRecordError::InvalidShape)
}

fn decode_workloads(decoder: &mut Decoder<'_>) -> Result<Vec<String>, ConnectionRecordError> {
    let count = decoder
        .array()
        .map_err(decoding)?
        .ok_or(ConnectionRecordError::InvalidShape)?;
    let count = usize::try_from(count).map_err(|_| ConnectionRecordError::InvalidWorkloads)?;
    if !(1..=MAX_WORKLOADS).contains(&count) {
        return Err(ConnectionRecordError::InvalidWorkloads);
    }
    (0..count)
        .map(|_| decoder.str().map(str::to_owned).map_err(decoding))
        .collect()
}

fn decode_profiles(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<ConnectionProfile>, ConnectionRecordError> {
    let count = decoder
        .array()
        .map_err(decoding)?
        .ok_or(ConnectionRecordError::InvalidShape)?;
    let count = usize::try_from(count).map_err(|_| ConnectionRecordError::InvalidProfiles)?;
    if !(1..=MAX_PROFILES).contains(&count) {
        return Err(ConnectionRecordError::InvalidProfiles);
    }
    (0..count)
        .map(|_| {
            if decoder.array().map_err(decoding)? != Some(2) {
                return Err(ConnectionRecordError::InvalidShape);
            }
            ConnectionProfile::new(
                SemanticId::parse(decoder.str().map_err(decoding)?)?,
                decoder.u16().map_err(decoding)?,
            )
        })
        .collect()
}

fn encoding<E>(_error: minicbor::encode::Error<E>) -> ConnectionRecordError {
    ConnectionRecordError::Encoding
}

fn decoding(_error: minicbor::decode::Error) -> ConnectionRecordError {
    ConnectionRecordError::Decoding
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn record() -> ConnectionRecord {
        ConnectionRecord::new(
            ProviderKind::parse("stripe").unwrap(),
            ConnectionAlias::parse("billing").unwrap(),
            ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            SemanticId::parse("auths.stripe.connection/1").unwrap(),
            SemanticId::parse("auths.stripe.connection-descriptor/1").unwrap(),
            b"descriptor".to_vec(),
            [2; 32],
            [3; 32],
            NonZeroU64::new(1).unwrap(),
            ConnectionState::Active,
            vec!["workload-a".to_owned()],
            vec![
                ConnectionProfile::new(SemanticId::parse("auths.stripe.refund").unwrap(), 1)
                    .unwrap(),
            ],
            10,
            10,
            None,
        )
        .unwrap()
    }

    #[test]
    fn canonical_record_round_trip_is_byte_exact() {
        let record = record();
        let bytes = record.to_canonical_cbor().unwrap();
        assert_eq!(
            ConnectionRecord::from_canonical_cbor(&bytes).unwrap(),
            record
        );
    }

    #[test]
    fn unknown_and_trailing_fields_fail_closed() {
        let mut bytes = record().to_canonical_cbor().unwrap();
        bytes.push(0);
        assert_eq!(
            ConnectionRecord::from_canonical_cbor(&bytes).unwrap_err(),
            ConnectionRecordError::TrailingBytes
        );
    }

    #[test]
    fn descriptor_commitment_substitution_is_rejected() {
        let mut bytes = record().to_canonical_cbor().unwrap();
        let offset = bytes
            .windows(32)
            .position(|window| window == record().descriptor_commitment())
            .unwrap();
        bytes[offset] ^= 1;
        assert_eq!(
            ConnectionRecord::from_canonical_cbor(&bytes).unwrap_err(),
            ConnectionRecordError::Noncanonical
        );
    }
}
