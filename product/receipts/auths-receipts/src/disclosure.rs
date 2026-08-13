use super::{
    DecisionClass, ExecutionOutcome, ReceiptError, ReceiptSignatureVerifier, ReceiptSigner,
    decision_receipt_id, raw_digest, verify_decision_attestation, verify_execution_attestation,
};
use auths_model::{
    ContextDigest, Digest, PROTOCOL_V1, PrincipalId, ProfileId, ProfileRef, ReceiptId,
    StatusSnapshotId, Timestamp,
};
use minicbor::{Decoder, Encoder, data::Type};
use std::fmt;

const DISCLOSURE_KIND: u8 = 0;
const MAX_DISCLOSURE_COMMAND_BYTES: usize = 1024 * 1024;
const MAX_DISCLOSURE_RESULT_BYTES: usize = 1024 * 1024;
const MAX_PROJECTION_FIELDS: usize = 32;
const MAX_PROJECTION_TITLE_BYTES: usize = 256;
const MAX_PROJECTION_LABEL_BYTES: usize = 128;
const MAX_PROJECTION_VALUE_BYTES: usize = 2048;
const MAX_TENANT_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptDisclosure {
    receipt_id: ReceiptId,
    profile: ProfileRef,
    command: Vec<u8>,
    result: Option<Vec<u8>>,
}

impl ReceiptDisclosure {
    /// # Errors
    ///
    /// Returns [`ReceiptInspectionError::DisclosureLimitExceeded`] when the
    /// command is empty or either payload exceeds its disclosure bound.
    pub fn new(
        receipt_id: ReceiptId,
        profile: ProfileRef,
        command: Vec<u8>,
        result: Option<Vec<u8>>,
    ) -> Result<Self, ReceiptInspectionError> {
        if command.is_empty() || command.len() > MAX_DISCLOSURE_COMMAND_BYTES {
            return Err(ReceiptInspectionError::DisclosureLimitExceeded);
        }
        if result
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_DISCLOSURE_RESULT_BYTES)
        {
            return Err(ReceiptInspectionError::DisclosureLimitExceeded);
        }
        Ok(Self {
            receipt_id,
            profile,
            command,
            result,
        })
    }

    #[must_use]
    pub const fn receipt_id(&self) -> ReceiptId {
        self.receipt_id
    }

    #[must_use]
    pub const fn profile(&self) -> &ProfileRef {
        &self.profile
    }

    #[must_use]
    pub fn command(&self) -> &[u8] {
        &self.command
    }

    #[must_use]
    pub fn result(&self) -> Option<&[u8]> {
        self.result.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptProjection {
    title: String,
    fields: Vec<(String, String)>,
}

impl ReceiptProjection {
    /// # Errors
    ///
    /// Returns [`ReceiptInspectionError::ProjectionLimitExceeded`] when the
    /// title or fields are empty, oversized, too numerous, or contain control
    /// characters.
    pub fn new(
        title: impl Into<String>,
        fields: Vec<(String, String)>,
    ) -> Result<Self, ReceiptInspectionError> {
        let title = title.into();
        if title.is_empty()
            || title.len() > MAX_PROJECTION_TITLE_BYTES
            || fields.is_empty()
            || fields.len() > MAX_PROJECTION_FIELDS
            || fields.iter().any(|(label, value)| {
                label.is_empty()
                    || label.len() > MAX_PROJECTION_LABEL_BYTES
                    || value.is_empty()
                    || value.len() > MAX_PROJECTION_VALUE_BYTES
                    || label.bytes().any(|byte| byte.is_ascii_control())
                    || value.bytes().any(|byte| byte.is_ascii_control())
            })
        {
            return Err(ReceiptInspectionError::ProjectionLimitExceeded);
        }
        Ok(Self { title, fields })
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    #[must_use]
    pub fn fields(&self) -> &[(String, String)] {
        &self.fields
    }
}

pub trait ReceiptProfileInspector {
    /// # Errors
    ///
    /// Returns a receipt inspection error when the profile or its material is
    /// unsupported, malformed, or cannot be projected within the output bounds.
    fn project(
        &self,
        profile: &ProfileRef,
        command: &[u8],
        result: Option<&[u8]>,
    ) -> Result<ReceiptProjection, ReceiptInspectionError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptViewMode {
    Opaque,
    Summary,
    Full,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReceiptMetadata {
    decision_id: ReceiptId,
    execution_id: ReceiptId,
    profile: ProfileRef,
    decision: DecisionClass,
    reasons: Vec<String>,
    outcome: ExecutionOutcome,
    decided_at: Timestamp,
    completed_at: Timestamp,
    decision_signer: ReceiptSigner,
    execution_signer: ReceiptSigner,
    proof_digest: Digest,
    action_digest: Digest,
    context_digest: ContextDigest,
    principal_status: StatusSnapshotId,
    grant_status: StatusSnapshotId,
    execution_lease: Digest,
    command_digest: Digest,
    result_digest: Option<Digest>,
}

impl VerifiedReceiptMetadata {
    #[must_use]
    pub const fn decision_id(&self) -> ReceiptId {
        self.decision_id
    }

    #[must_use]
    pub const fn execution_id(&self) -> ReceiptId {
        self.execution_id
    }

    #[must_use]
    pub const fn profile(&self) -> &ProfileRef {
        &self.profile
    }

    #[must_use]
    pub const fn decision(&self) -> DecisionClass {
        self.decision
    }

    #[must_use]
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }

    #[must_use]
    pub const fn outcome(&self) -> ExecutionOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn decided_at(&self) -> Timestamp {
        self.decided_at
    }

    #[must_use]
    pub const fn completed_at(&self) -> Timestamp {
        self.completed_at
    }

    #[must_use]
    pub const fn decision_signer(&self) -> &ReceiptSigner {
        &self.decision_signer
    }

    #[must_use]
    pub const fn execution_signer(&self) -> &ReceiptSigner {
        &self.execution_signer
    }

    #[must_use]
    pub const fn proof_digest(&self) -> Digest {
        self.proof_digest
    }

    #[must_use]
    pub const fn action_digest(&self) -> Digest {
        self.action_digest
    }

    #[must_use]
    pub const fn context_digest(&self) -> ContextDigest {
        self.context_digest
    }

    #[must_use]
    pub const fn principal_status(&self) -> StatusSnapshotId {
        self.principal_status
    }

    #[must_use]
    pub const fn grant_status(&self) -> StatusSnapshotId {
        self.grant_status
    }

    #[must_use]
    pub const fn execution_lease(&self) -> Digest {
        self.execution_lease
    }

    #[must_use]
    pub const fn command_digest(&self) -> Digest {
        self.command_digest
    }

    #[must_use]
    pub const fn result_digest(&self) -> Option<Digest> {
        self.result_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiptInspection {
    VerifiedOpaque {
        metadata: VerifiedReceiptMetadata,
    },
    VerifiedDisclosed {
        metadata: VerifiedReceiptMetadata,
        mode: ReceiptViewMode,
        projection: ReceiptProjection,
        disclosure: Option<ReceiptDisclosure>,
    },
}

impl ReceiptInspection {
    #[must_use]
    pub const fn metadata(&self) -> &VerifiedReceiptMetadata {
        match self {
            Self::VerifiedOpaque { metadata } | Self::VerifiedDisclosed { metadata, .. } => {
                metadata
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// # Errors
///
/// Returns a receipt inspection error when either attestation is invalid, the
/// receipts are not linked, the requested disclosure is absent or inconsistent
/// with the receipt commitments, or the profile projection fails.
pub fn inspect_attested_execution_receipt(
    decision_bytes: &[u8],
    decision_id: ReceiptId,
    decision_verifier: &PrincipalId,
    decision_policy: &dyn ReceiptSignatureVerifier,
    execution_bytes: &[u8],
    execution_id: ReceiptId,
    execution_verifier: &PrincipalId,
    execution_policy: &dyn ReceiptSignatureVerifier,
    mode: ReceiptViewMode,
    disclosure_bytes: Option<&[u8]>,
    profile_inspector: Option<&dyn ReceiptProfileInspector>,
) -> Result<ReceiptInspection, ReceiptInspectionError> {
    let decision = verify_decision_attestation(
        decision_bytes,
        decision_id,
        decision_verifier,
        decision_policy,
    )
    .map_err(ReceiptInspectionError::from_receipt)?;
    let execution = verify_execution_attestation(
        execution_bytes,
        execution_id,
        execution_verifier,
        execution_policy,
    )
    .map_err(ReceiptInspectionError::from_receipt)?;
    if execution.receipt().decision_receipt() != decision_id
        || decision_receipt_id(decision.receipt()).map_err(ReceiptInspectionError::from_receipt)?
            != decision_id
    {
        return Err(ReceiptInspectionError::ReceiptLinkageMismatch);
    }
    let metadata = VerifiedReceiptMetadata {
        decision_id,
        execution_id,
        profile: decision.receipt().profile().clone(),
        decision: decision.receipt().decision(),
        reasons: decision.receipt().reasons().to_vec(),
        outcome: execution.receipt().outcome(),
        decided_at: decision.receipt().decided_at(),
        completed_at: execution.receipt().completed_at(),
        decision_signer: decision.signer().clone(),
        execution_signer: execution.signer().clone(),
        proof_digest: decision.receipt().proof_digest(),
        action_digest: decision.receipt().action_digest(),
        context_digest: decision.receipt().context_digest(),
        principal_status: decision.receipt().principal_status(),
        grant_status: decision.receipt().grant_status(),
        execution_lease: execution.receipt().execution_lease(),
        command_digest: execution.receipt().command_digest(),
        result_digest: execution.receipt().result_digest(),
    };
    if mode == ReceiptViewMode::Opaque {
        return Ok(ReceiptInspection::VerifiedOpaque { metadata });
    }
    let disclosure = decode_receipt_disclosure(
        disclosure_bytes.ok_or(ReceiptInspectionError::DisclosureRequired)?,
    )?;
    if disclosure.receipt_id != execution_id {
        return Err(ReceiptInspectionError::DisclosureReceiptMismatch);
    }
    if disclosure.profile != *decision.receipt().profile() {
        return Err(ReceiptInspectionError::DisclosureProfileMismatch);
    }
    if raw_digest(&disclosure.command) != execution.receipt().command_digest() {
        return Err(ReceiptInspectionError::DisclosureCommandMismatch);
    }
    match (
        disclosure.result.as_deref(),
        execution.receipt().result_digest(),
    ) {
        (Some(result), Some(expected)) if raw_digest(result) == expected => {}
        (None, None) => {}
        _ => return Err(ReceiptInspectionError::DisclosureResultMismatch),
    }
    let projection = profile_inspector
        .ok_or(ReceiptInspectionError::UnsupportedProfile)?
        .project(
            decision.receipt().profile(),
            &disclosure.command,
            disclosure.result.as_deref(),
        )?;
    Ok(ReceiptInspection::VerifiedDisclosed {
        metadata,
        mode,
        projection,
        disclosure: (mode == ReceiptViewMode::Full).then_some(disclosure),
    })
}

/// # Errors
///
/// Returns [`ReceiptInspectionError::DisclosureMalformed`] when the disclosure
/// cannot be encoded as canonical CBOR.
pub fn encode_receipt_disclosure(
    disclosure: &ReceiptDisclosure,
) -> Result<Vec<u8>, ReceiptInspectionError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(7)
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?;
    disclosure_key(&mut encoder, 0)?;
    encoder
        .u16(PROTOCOL_V1)
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?;
    disclosure_key(&mut encoder, 1)?;
    encoder
        .u8(DISCLOSURE_KIND)
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?;
    disclosure_key(&mut encoder, 2)?;
    disclosure_bytes(&mut encoder, disclosure.receipt_id.as_bytes())?;
    disclosure_key(&mut encoder, 3)?;
    encoder
        .str(disclosure.profile.id().as_str())
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?;
    disclosure_key(&mut encoder, 4)?;
    encoder
        .u16(disclosure.profile.version())
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?;
    disclosure_key(&mut encoder, 5)?;
    disclosure_bytes(&mut encoder, &disclosure.command)?;
    disclosure_key(&mut encoder, 6)?;
    if let Some(result) = &disclosure.result {
        disclosure_bytes(&mut encoder, result)?;
    } else {
        encoder
            .null()
            .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?;
    }
    Ok(encoder.into_writer())
}

/// # Errors
///
/// Returns a receipt inspection error when the input exceeds disclosure bounds,
/// is malformed or non-canonical, uses an unsupported version or kind, or
/// contains an invalid profile or payload.
pub fn decode_receipt_disclosure(
    input: &[u8],
) -> Result<ReceiptDisclosure, ReceiptInspectionError> {
    if input.len() > MAX_DISCLOSURE_COMMAND_BYTES + MAX_DISCLOSURE_RESULT_BYTES + 1024 {
        return Err(ReceiptInspectionError::DisclosureLimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    if decoder
        .map()
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?
        != Some(7)
    {
        return Err(ReceiptInspectionError::DisclosureMalformed);
    }
    disclosure_key_decode(&mut decoder, 0)?;
    if decoder
        .u16()
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?
        != PROTOCOL_V1
    {
        return Err(ReceiptInspectionError::UnsupportedDisclosure);
    }
    disclosure_key_decode(&mut decoder, 1)?;
    if decoder
        .u8()
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?
        != DISCLOSURE_KIND
    {
        return Err(ReceiptInspectionError::UnsupportedDisclosure);
    }
    disclosure_key_decode(&mut decoder, 2)?;
    let receipt_id = ReceiptId::new(disclosure_digest(&mut decoder)?);
    disclosure_key_decode(&mut decoder, 3)?;
    let profile_id = ProfileId::parse(
        decoder
            .str()
            .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?,
    )
    .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?;
    disclosure_key_decode(&mut decoder, 4)?;
    let profile = ProfileRef::new(
        profile_id,
        decoder
            .u16()
            .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?,
    )
    .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?;
    disclosure_key_decode(&mut decoder, 5)?;
    let command = decoder
        .bytes()
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?
        .to_vec();
    disclosure_key_decode(&mut decoder, 6)?;
    let result = if decoder
        .datatype()
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?
        == Type::Null
    {
        decoder
            .null()
            .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?;
        None
    } else {
        Some(
            decoder
                .bytes()
                .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?
                .to_vec(),
        )
    };
    if decoder.position() != input.len() {
        return Err(ReceiptInspectionError::DisclosureMalformed);
    }
    let disclosure = ReceiptDisclosure::new(receipt_id, profile, command, result)?;
    if encode_receipt_disclosure(&disclosure)?.as_slice() != input {
        return Err(ReceiptInspectionError::DisclosureNonCanonical);
    }
    Ok(disclosure)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptDisclosureLocator {
    tenant: String,
    receipt_id: ReceiptId,
}

impl ReceiptDisclosureLocator {
    /// # Errors
    ///
    /// Returns [`ReceiptInspectionError::TenantOutsideBounds`] when the tenant
    /// is empty, oversized, or contains control characters.
    pub fn new(
        tenant: impl Into<String>,
        receipt_id: ReceiptId,
    ) -> Result<Self, ReceiptInspectionError> {
        let tenant = tenant.into();
        if tenant.is_empty()
            || tenant.len() > MAX_TENANT_BYTES
            || tenant.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ReceiptInspectionError::TenantOutsideBounds);
        }
        Ok(Self { tenant, receipt_id })
    }

    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    #[must_use]
    pub const fn receipt_id(&self) -> ReceiptId {
        self.receipt_id
    }
}

pub trait ReceiptDisclosureProtector {
    type Error;

    /// # Errors
    ///
    /// Returns the protector's error when the plaintext cannot be protected for
    /// the supplied locator.
    fn protect(
        &self,
        locator: &ReceiptDisclosureLocator,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// # Errors
    ///
    /// Returns the protector's error when the protected bytes cannot be
    /// authenticated or revealed for the supplied locator.
    fn reveal(
        &self,
        locator: &ReceiptDisclosureLocator,
        protected: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

pub trait ReceiptDisclosureStore {
    type Error;

    /// # Errors
    ///
    /// Returns the store's error when the protected disclosure cannot be saved.
    fn put(&self, locator: &ReceiptDisclosureLocator, protected: &[u8]) -> Result<(), Self::Error>;

    /// # Errors
    ///
    /// Returns the store's error when the disclosure cannot be read.
    fn get(&self, locator: &ReceiptDisclosureLocator) -> Result<Option<Vec<u8>>, Self::Error>;

    /// # Errors
    ///
    /// Returns the store's error when the disclosure cannot be deleted.
    fn delete(&self, locator: &ReceiptDisclosureLocator) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptInspectionError {
    ReceiptMalformed,
    ReceiptNonCanonical,
    ReceiptUnsupported,
    ReceiptLimitExceeded,
    ReceiptIdMismatch,
    ReceiptLinkageMismatch,
    UnexpectedSigner,
    InvalidSignature,
    DisclosureRequired,
    DisclosureMalformed,
    DisclosureNonCanonical,
    UnsupportedDisclosure,
    DisclosureLimitExceeded,
    DisclosureReceiptMismatch,
    DisclosureProfileMismatch,
    DisclosureCommandMismatch,
    DisclosureResultMismatch,
    UnsupportedProfile,
    InvalidProfileMaterial,
    ProjectionLimitExceeded,
    TenantOutsideBounds,
}

impl ReceiptInspectionError {
    fn from_receipt(error: ReceiptError) -> Self {
        match error {
            ReceiptError::Malformed | ReceiptError::InvalidReason => Self::ReceiptMalformed,
            ReceiptError::NonCanonical => Self::ReceiptNonCanonical,
            ReceiptError::UnsupportedProtocol => Self::ReceiptUnsupported,
            ReceiptError::LimitExceeded => Self::ReceiptLimitExceeded,
            ReceiptError::DigestMismatch => Self::ReceiptIdMismatch,
            ReceiptError::LinkageMismatch | ReceiptError::Duplicate => Self::ReceiptLinkageMismatch,
            ReceiptError::UnexpectedSigner => Self::UnexpectedSigner,
            ReceiptError::InvalidSignature | ReceiptError::SigningUnavailable => {
                Self::InvalidSignature
            }
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ReceiptMalformed => "receipt-malformed",
            Self::ReceiptNonCanonical => "receipt-non-canonical",
            Self::ReceiptUnsupported => "receipt-unsupported",
            Self::ReceiptLimitExceeded => "receipt-limit-exceeded",
            Self::ReceiptIdMismatch => "receipt-id-mismatch",
            Self::ReceiptLinkageMismatch => "receipt-linkage-mismatch",
            Self::UnexpectedSigner => "receipt-unexpected-signer",
            Self::InvalidSignature => "receipt-invalid-signature",
            Self::DisclosureRequired => "disclosure-required",
            Self::DisclosureMalformed => "disclosure-malformed",
            Self::DisclosureNonCanonical => "disclosure-non-canonical",
            Self::UnsupportedDisclosure => "disclosure-unsupported",
            Self::DisclosureLimitExceeded => "disclosure-limit-exceeded",
            Self::DisclosureReceiptMismatch => "disclosure-receipt-mismatch",
            Self::DisclosureProfileMismatch => "disclosure-profile-mismatch",
            Self::DisclosureCommandMismatch => "disclosure-command-mismatch",
            Self::DisclosureResultMismatch => "disclosure-result-mismatch",
            Self::UnsupportedProfile => "disclosure-profile-unsupported",
            Self::InvalidProfileMaterial => "disclosure-profile-material-invalid",
            Self::ProjectionLimitExceeded => "disclosure-projection-limit-exceeded",
            Self::TenantOutsideBounds => "disclosure-tenant-outside-bounds",
        }
    }
}

impl fmt::Display for ReceiptInspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ReceiptInspectionError {}

fn disclosure_key(encoder: &mut Encoder<Vec<u8>>, value: u8) -> Result<(), ReceiptInspectionError> {
    encoder
        .u8(value)
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?;
    Ok(())
}

fn disclosure_bytes(
    encoder: &mut Encoder<Vec<u8>>,
    value: &[u8],
) -> Result<(), ReceiptInspectionError> {
    encoder
        .bytes(value)
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?;
    Ok(())
}

fn disclosure_key_decode(
    decoder: &mut Decoder<'_>,
    expected: u8,
) -> Result<(), ReceiptInspectionError> {
    if decoder
        .u8()
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?
        == expected
    {
        Ok(())
    } else {
        Err(ReceiptInspectionError::DisclosureNonCanonical)
    }
}

fn disclosure_digest(decoder: &mut Decoder<'_>) -> Result<[u8; 32], ReceiptInspectionError> {
    decoder
        .bytes()
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)?
        .try_into()
        .map_err(|_| ReceiptInspectionError::DisclosureMalformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ProfileRef {
        ProfileRef::new(ProfileId::parse("auths.edge").unwrap(), 1).unwrap()
    }

    #[test]
    fn disclosure_round_trips_canonically() {
        let disclosure = ReceiptDisclosure::new(
            ReceiptId::new([7; 32]),
            profile(),
            b"command".to_vec(),
            Some(b"result".to_vec()),
        )
        .unwrap();

        let encoded = encode_receipt_disclosure(&disclosure).unwrap();

        assert_eq!(decode_receipt_disclosure(&encoded).unwrap(), disclosure);
    }

    #[test]
    fn disclosure_and_locator_reject_unbounded_inputs() {
        assert_eq!(
            ReceiptDisclosure::new(
                ReceiptId::new([0; 32]),
                profile(),
                vec![0; MAX_DISCLOSURE_COMMAND_BYTES + 1],
                None,
            ),
            Err(ReceiptInspectionError::DisclosureLimitExceeded)
        );
        assert_eq!(
            ReceiptDisclosureLocator::new("tenant\nother", ReceiptId::new([0; 32])),
            Err(ReceiptInspectionError::TenantOutsideBounds)
        );
    }
}
