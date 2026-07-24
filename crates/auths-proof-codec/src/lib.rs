//! Deterministic CBOR codec and domain-separated hashing for `auths-proof` V1.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use auths_proof_model::{
    ActionId, ActionStatement, AdapterId, AlgorithmId, Audience, AuthorityStateEvidenceEntry,
    AuthorityStateMethod, BodyDigest, CapabilityId, Challenge, DelegationDepth, EvidenceBytes,
    EvidenceId, EvidenceMediaType, GrantId, GrantPayload, ModelError, Permission, PermissionSet,
    PrincipalEvidenceBinding, PrincipalEvidenceEntry, PrincipalRef, ProofBundle, ProtocolVersion,
    ResourceId, RevocationRequirement, SignatureBytes, SignatureDescriptor, SignatureEnvelope,
    SignedAction, SignedGrant, StatementId, Timestamp, ValidityWindow, VerificationMethodRef,
    MAX_EVIDENCE_BYTES, MAX_EVIDENCE_ENTRIES, MAX_GRANTS, MAX_PERMISSIONS,
};
use core::{fmt, str};
use sha2::{Digest, Sha256};

pub const GRANT_DOMAIN_V1: &[u8] = b"auths-proof/grant/v1\0";
pub const ACTION_DOMAIN_V1: &[u8] = b"auths-proof/action/v1\0";
pub const GRANT_ID_DOMAIN_V1: &[u8] = b"auths-proof/grant-id/v1\0";
pub const ACTION_ID_DOMAIN_V1: &[u8] = b"auths-proof/action-id/v1\0";
pub const EVIDENCE_ID_DOMAIN_V1: &[u8] = b"auths-proof/evidence-id/v1\0";

pub const DEFAULT_MAX_BUNDLE_BYTES: usize = 2 * 1024 * 1024;
pub const HARD_MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeLimits {
    pub max_bundle_bytes: usize,
    pub max_evidence_bytes: usize,
    pub max_grants: usize,
    pub max_permissions: usize,
    pub max_evidence_entries: usize,
}

impl DecodeLimits {
    pub const fn standard() -> Self {
        Self {
            max_bundle_bytes: DEFAULT_MAX_BUNDLE_BYTES,
            max_evidence_bytes: 1024 * 1024,
            max_grants: 16,
            max_permissions: 256,
            max_evidence_entries: 64,
        }
    }

    pub fn validate(self) -> Result<Self, CodecError> {
        if self.max_bundle_bytes > HARD_MAX_BUNDLE_BYTES
            || self.max_evidence_bytes > MAX_EVIDENCE_BYTES
            || self.max_grants > MAX_GRANTS
            || self.max_permissions > MAX_PERMISSIONS
            || self.max_evidence_entries > MAX_EVIDENCE_ENTRIES
        {
            return Err(CodecError::LimitExceeded);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodecError {
    UnexpectedEof,
    InvalidType,
    InvalidUtf8,
    NonCanonical,
    TrailingData,
    LimitExceeded,
    DigestMismatch,
    Model(ModelError),
}

impl From<ModelError> for CodecError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnexpectedEof => "unexpected end of CBOR input",
            Self::InvalidType => "unexpected CBOR type or field",
            Self::InvalidUtf8 => "invalid UTF-8 text",
            Self::NonCanonical => "non-canonical CBOR encoding or collection order",
            Self::TrailingData => "trailing bytes after CBOR object",
            Self::LimitExceeded => "decode resource limit exceeded",
            Self::DigestMismatch => "content-addressed identifier mismatch",
            Self::Model(error) => return write!(formatter, "invalid protocol model: {error}"),
        };
        formatter.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CodecError {}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn head(&mut self, major: u8, value: u64) {
        let prefix = major << 5;
        match value {
            0..=23 => self.bytes.push(prefix | value as u8),
            24..=0xff => {
                self.bytes.push(prefix | 24);
                self.bytes.push(value as u8);
            }
            0x100..=0xffff => {
                self.bytes.push(prefix | 25);
                self.bytes.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.bytes.push(prefix | 26);
                self.bytes.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.bytes.push(prefix | 27);
                self.bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
    }

    fn uint(&mut self, value: u64) {
        self.head(0, value);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.head(2, value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    fn text(&mut self, value: &str) {
        self.head(3, value.len() as u64);
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn array(&mut self, len: usize) {
        self.head(4, len as u64);
    }

    fn map(&mut self, len: usize) {
        self.head(5, len as u64);
    }

    fn null(&mut self) {
        self.bytes.push(0xf6);
    }
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn finish(self) -> Result<(), CodecError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingData)
        }
    }

    fn byte(&mut self) -> Result<u8, CodecError> {
        let value = self
            .input
            .get(self.position)
            .copied()
            .ok_or(CodecError::UnexpectedEof)?;
        self.position += 1;
        Ok(value)
    }

    fn exact<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(CodecError::LimitExceeded)?;
        let slice = self
            .input
            .get(self.position..end)
            .ok_or(CodecError::UnexpectedEof)?;
        let mut bytes = [0_u8; N];
        bytes.copy_from_slice(slice);
        self.position = end;
        Ok(bytes)
    }

    fn head(&mut self, expected_major: u8) -> Result<u64, CodecError> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        if major != expected_major {
            return Err(CodecError::InvalidType);
        }
        let value = match additional {
            0..=23 => additional as u64,
            24 => {
                let value = self.byte()? as u64;
                if value < 24 {
                    return Err(CodecError::NonCanonical);
                }
                value
            }
            25 => {
                let value = u16::from_be_bytes(self.exact::<2>()?) as u64;
                if value <= 0xff {
                    return Err(CodecError::NonCanonical);
                }
                value
            }
            26 => {
                let value = u32::from_be_bytes(self.exact::<4>()?) as u64;
                if value <= 0xffff {
                    return Err(CodecError::NonCanonical);
                }
                value
            }
            27 => {
                let value = u64::from_be_bytes(self.exact::<8>()?);
                if value <= 0xffff_ffff {
                    return Err(CodecError::NonCanonical);
                }
                value
            }
            _ => return Err(CodecError::NonCanonical),
        };
        Ok(value)
    }

    fn uint(&mut self) -> Result<u64, CodecError> {
        self.head(0)
    }

    fn usize(&mut self, expected_major: u8, max: usize) -> Result<usize, CodecError> {
        let value = self.head(expected_major)?;
        let value = usize::try_from(value).map_err(|_| CodecError::LimitExceeded)?;
        if value > max {
            return Err(CodecError::LimitExceeded);
        }
        Ok(value)
    }

    fn map_exact(&mut self, len: usize) -> Result<(), CodecError> {
        if self.usize(5, len)? == len {
            Ok(())
        } else {
            Err(CodecError::InvalidType)
        }
    }

    fn key(&mut self, expected: u64) -> Result<(), CodecError> {
        if self.uint()? == expected {
            Ok(())
        } else {
            Err(CodecError::NonCanonical)
        }
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, CodecError> {
        let len = self.usize(2, max)?;
        let end = self
            .position
            .checked_add(len)
            .ok_or(CodecError::LimitExceeded)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(CodecError::UnexpectedEof)?;
        self.position = end;
        Ok(bytes.to_vec())
    }

    fn digest(&mut self) -> Result<[u8; 32], CodecError> {
        let bytes = self.bytes(32)?;
        if bytes.len() != 32 {
            return Err(CodecError::InvalidType);
        }
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&bytes);
        Ok(digest)
    }

    fn text(&mut self, max: usize) -> Result<String, CodecError> {
        let bytes = self.bytes_like_text(max)?;
        str::from_utf8(bytes)
            .map(String::from)
            .map_err(|_| CodecError::InvalidUtf8)
    }

    fn bytes_like_text(&mut self, max: usize) -> Result<&'a [u8], CodecError> {
        let len = self.usize(3, max)?;
        let end = self
            .position
            .checked_add(len)
            .ok_or(CodecError::LimitExceeded)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(CodecError::UnexpectedEof)?;
        self.position = end;
        Ok(bytes)
    }

    fn array_len(&mut self, max: usize) -> Result<usize, CodecError> {
        self.usize(4, max)
    }

    fn null_or_digest(&mut self) -> Result<Option<[u8; 32]>, CodecError> {
        if self.input.get(self.position) == Some(&0xf6) {
            self.position += 1;
            Ok(None)
        } else {
            self.digest().map(Some)
        }
    }
}

fn write_permission(writer: &mut Writer, permission: &Permission) {
    writer.map(2);
    writer.uint(0);
    writer.text(permission.capability().as_str());
    writer.uint(1);
    writer.text(permission.resource().as_str());
}

fn read_permission(reader: &mut Reader<'_>) -> Result<Permission, CodecError> {
    reader.map_exact(2)?;
    reader.key(0)?;
    let capability = CapabilityId::parse(&reader.text(128)?)?;
    reader.key(1)?;
    let resource = ResourceId::parse(&reader.text(1_024)?)?;
    Ok(Permission::new(capability, resource))
}

fn write_permissions(writer: &mut Writer, permissions: &PermissionSet) {
    writer.array(permissions.as_slice().len());
    for permission in permissions.as_slice() {
        write_permission(writer, permission);
    }
}

fn read_permissions(
    reader: &mut Reader<'_>,
    limits: &DecodeLimits,
) -> Result<PermissionSet, CodecError> {
    let len = reader.array_len(limits.max_permissions)?;
    let mut permissions = Vec::with_capacity(len);
    for _ in 0..len {
        permissions.push(read_permission(reader)?);
    }
    PermissionSet::from_canonical(permissions).map_err(CodecError::from)
}

fn write_descriptor(writer: &mut Writer, descriptor: &SignatureDescriptor) {
    writer.map(3);
    writer.uint(0);
    writer.text(descriptor.adapter().as_str());
    writer.uint(1);
    writer.text(descriptor.verification_method().as_str());
    writer.uint(2);
    writer.text(descriptor.algorithm().as_str());
}

fn read_descriptor(reader: &mut Reader<'_>) -> Result<SignatureDescriptor, CodecError> {
    reader.map_exact(3)?;
    reader.key(0)?;
    let adapter = AdapterId::parse(&reader.text(64)?)?;
    reader.key(1)?;
    let method = VerificationMethodRef::parse(&reader.text(512)?)?;
    reader.key(2)?;
    let algorithm = AlgorithmId::parse(&reader.text(64)?)?;
    Ok(SignatureDescriptor::new(adapter, method, algorithm))
}

fn write_signature(writer: &mut Writer, signature: &SignatureEnvelope) {
    writer.map(2);
    writer.uint(0);
    write_descriptor(writer, signature.descriptor());
    writer.uint(1);
    writer.bytes(signature.signature().as_slice());
}

fn read_signature(reader: &mut Reader<'_>) -> Result<SignatureEnvelope, CodecError> {
    reader.map_exact(2)?;
    reader.key(0)?;
    let descriptor = read_descriptor(reader)?;
    reader.key(1)?;
    let signature = SignatureBytes::new(reader.bytes(4_096)?)?;
    Ok(SignatureEnvelope::new(descriptor, signature))
}

fn write_revocation(writer: &mut Writer, revocation: &RevocationRequirement) {
    match revocation {
        RevocationRequirement::ExpiryOnly => {
            writer.map(1);
            writer.uint(0);
            writer.uint(0);
        }
        RevocationRequirement::StatusProofRequired { method } => {
            writer.map(2);
            writer.uint(0);
            writer.uint(1);
            writer.uint(1);
            writer.text(method.as_str());
        }
    }
}

fn read_revocation(reader: &mut Reader<'_>) -> Result<RevocationRequirement, CodecError> {
    let len = reader.usize(5, 2)?;
    if len == 0 {
        return Err(CodecError::InvalidType);
    }
    reader.key(0)?;
    match reader.uint()? {
        0 if len == 1 => Ok(RevocationRequirement::ExpiryOnly),
        1 if len == 2 => {
            reader.key(1)?;
            Ok(RevocationRequirement::StatusProofRequired {
                method: AuthorityStateMethod::parse(&reader.text(64)?)?,
            })
        }
        _ => Err(CodecError::InvalidType),
    }
}

fn write_grant_payload(writer: &mut Writer, grant: &GrantPayload) {
    writer.map(10);
    writer.uint(0);
    writer.uint(grant.version().get() as u64);
    writer.uint(1);
    writer.text(grant.issuer().as_str());
    writer.uint(2);
    writer.text(grant.subject().as_str());
    writer.uint(3);
    write_permissions(writer, grant.permissions());
    writer.uint(4);
    writer.uint(grant.issued_at().as_secs());
    writer.uint(5);
    writer.uint(grant.validity().from().as_secs());
    writer.uint(6);
    writer.uint(grant.validity().until().as_secs());
    writer.uint(7);
    writer.uint(grant.remaining_delegation_depth().get() as u64);
    writer.uint(8);
    write_revocation(writer, grant.revocation());
    writer.uint(9);
    match grant.parent() {
        Some(parent) => writer.bytes(parent.as_bytes()),
        None => writer.null(),
    }
}

fn read_grant_payload(
    reader: &mut Reader<'_>,
    limits: &DecodeLimits,
) -> Result<GrantPayload, CodecError> {
    reader.map_exact(10)?;
    reader.key(0)?;
    ProtocolVersion::new(read_u8(reader)?)?;
    reader.key(1)?;
    let issuer = PrincipalRef::parse(&reader.text(512)?)?;
    reader.key(2)?;
    let subject = PrincipalRef::parse(&reader.text(512)?)?;
    reader.key(3)?;
    let permissions = read_permissions(reader, limits)?;
    reader.key(4)?;
    let issued_at = Timestamp::new(reader.uint()?);
    reader.key(5)?;
    let valid_from = Timestamp::new(reader.uint()?);
    reader.key(6)?;
    let valid_until = Timestamp::new(reader.uint()?);
    reader.key(7)?;
    let depth = DelegationDepth::new(read_u8(reader)?);
    reader.key(8)?;
    let revocation = read_revocation(reader)?;
    reader.key(9)?;
    let parent = reader.null_or_digest()?.map(GrantId::new);
    GrantPayload::new(
        issuer,
        subject,
        permissions,
        issued_at,
        ValidityWindow::new(valid_from, valid_until)?,
        depth,
        revocation,
        parent,
    )
    .map_err(CodecError::from)
}

fn write_action_payload(writer: &mut Writer, action: &ActionStatement) {
    writer.map(8);
    writer.uint(0);
    writer.uint(action.version().get() as u64);
    writer.uint(1);
    writer.text(action.actor().as_str());
    writer.uint(2);
    write_permission(writer, action.permission());
    writer.uint(3);
    writer.bytes(action.body_digest().as_bytes());
    writer.uint(4);
    writer.text(action.audience().as_str());
    writer.uint(5);
    writer.uint(action.issued_at().as_secs());
    writer.uint(6);
    writer.uint(action.expires_at().as_secs());
    writer.uint(7);
    writer.bytes(action.challenge().as_bytes());
}

fn read_action_payload(reader: &mut Reader<'_>) -> Result<ActionStatement, CodecError> {
    reader.map_exact(8)?;
    reader.key(0)?;
    ProtocolVersion::new(read_u8(reader)?)?;
    reader.key(1)?;
    let actor = PrincipalRef::parse(&reader.text(512)?)?;
    reader.key(2)?;
    let permission = read_permission(reader)?;
    reader.key(3)?;
    let body_digest = BodyDigest::new(reader.digest()?);
    reader.key(4)?;
    let audience = Audience::parse(&reader.text(512)?)?;
    reader.key(5)?;
    let issued_at = Timestamp::new(reader.uint()?);
    reader.key(6)?;
    let expires_at = Timestamp::new(reader.uint()?);
    reader.key(7)?;
    let challenge = Challenge::new(reader.digest()?);
    ActionStatement::new(
        actor,
        permission,
        body_digest,
        audience,
        issued_at,
        expires_at,
        challenge,
    )
    .map_err(CodecError::from)
}

fn write_signed_grant(writer: &mut Writer, grant: &SignedGrant) {
    writer.map(2);
    writer.uint(0);
    write_grant_payload(writer, grant.payload());
    writer.uint(1);
    write_signature(writer, grant.signature());
}

fn read_signed_grant(
    reader: &mut Reader<'_>,
    limits: &DecodeLimits,
) -> Result<SignedGrant, CodecError> {
    reader.map_exact(2)?;
    reader.key(0)?;
    let payload = read_grant_payload(reader, limits)?;
    reader.key(1)?;
    let signature = read_signature(reader)?;
    Ok(SignedGrant::new(payload, signature))
}

fn write_signed_action(writer: &mut Writer, action: &SignedAction) {
    writer.map(2);
    writer.uint(0);
    write_action_payload(writer, action.payload());
    writer.uint(1);
    write_signature(writer, action.signature());
}

fn read_signed_action(reader: &mut Reader<'_>) -> Result<SignedAction, CodecError> {
    reader.map_exact(2)?;
    reader.key(0)?;
    let payload = read_action_payload(reader)?;
    reader.key(1)?;
    let signature = read_signature(reader)?;
    Ok(SignedAction::new(payload, signature))
}

fn write_principal_evidence(writer: &mut Writer, evidence: &PrincipalEvidenceEntry) {
    writer.map(4);
    writer.uint(0);
    writer.bytes(evidence.id().as_bytes());
    writer.uint(1);
    writer.text(evidence.method().as_str());
    writer.uint(2);
    writer.text(evidence.media_type().as_str());
    writer.uint(3);
    writer.bytes(evidence.bytes().as_slice());
}

fn read_principal_evidence(
    reader: &mut Reader<'_>,
    limits: &DecodeLimits,
) -> Result<PrincipalEvidenceEntry, CodecError> {
    reader.map_exact(4)?;
    reader.key(0)?;
    let id = EvidenceId::new(reader.digest()?);
    reader.key(1)?;
    let method = AdapterId::parse(&reader.text(64)?)?;
    reader.key(2)?;
    let media_type = EvidenceMediaType::parse(&reader.text(128)?)?;
    reader.key(3)?;
    let bytes = EvidenceBytes::new(reader.bytes(limits.max_evidence_bytes)?)?;
    let evidence = PrincipalEvidenceEntry::new(id, method, media_type, bytes);
    if evidence_id(
        evidence.method(),
        evidence.media_type(),
        evidence.bytes().as_slice(),
    ) != id
    {
        return Err(CodecError::DigestMismatch);
    }
    Ok(evidence)
}

fn write_binding(writer: &mut Writer, binding: &PrincipalEvidenceBinding) {
    writer.map(3);
    writer.uint(0);
    match binding.statement() {
        StatementId::Grant(_) => writer.uint(0),
        StatementId::Action(_) => writer.uint(1),
    }
    writer.uint(1);
    match binding.statement() {
        StatementId::Grant(id) => writer.bytes(id.as_bytes()),
        StatementId::Action(id) => writer.bytes(id.as_bytes()),
    }
    writer.uint(2);
    writer.bytes(binding.evidence().as_bytes());
}

fn read_binding(reader: &mut Reader<'_>) -> Result<PrincipalEvidenceBinding, CodecError> {
    reader.map_exact(3)?;
    reader.key(0)?;
    let kind = reader.uint()?;
    reader.key(1)?;
    let statement_digest = reader.digest()?;
    reader.key(2)?;
    let evidence = EvidenceId::new(reader.digest()?);
    let statement = match kind {
        0 => StatementId::Grant(GrantId::new(statement_digest)),
        1 => StatementId::Action(ActionId::new(statement_digest)),
        _ => return Err(CodecError::InvalidType),
    };
    Ok(PrincipalEvidenceBinding::new(statement, evidence))
}

fn write_authority_state(writer: &mut Writer, evidence: &AuthorityStateEvidenceEntry) {
    writer.map(4);
    writer.uint(0);
    writer.bytes(evidence.id().as_bytes());
    writer.uint(1);
    writer.text(evidence.method().as_str());
    writer.uint(2);
    writer.text(evidence.media_type().as_str());
    writer.uint(3);
    writer.bytes(evidence.bytes().as_slice());
}

fn read_authority_state(
    reader: &mut Reader<'_>,
    limits: &DecodeLimits,
) -> Result<AuthorityStateEvidenceEntry, CodecError> {
    reader.map_exact(4)?;
    reader.key(0)?;
    let id = EvidenceId::new(reader.digest()?);
    reader.key(1)?;
    let method = AuthorityStateMethod::parse(&reader.text(64)?)?;
    reader.key(2)?;
    let media_type = EvidenceMediaType::parse(&reader.text(128)?)?;
    reader.key(3)?;
    let bytes = EvidenceBytes::new(reader.bytes(limits.max_evidence_bytes)?)?;
    let evidence = AuthorityStateEvidenceEntry::new(id, method, media_type, bytes);
    if authority_state_evidence_id(
        evidence.method(),
        evidence.media_type(),
        evidence.bytes().as_slice(),
    ) != id
    {
        return Err(CodecError::DigestMismatch);
    }
    Ok(evidence)
}

fn read_u8(reader: &mut Reader<'_>) -> Result<u8, CodecError> {
    u8::try_from(reader.uint()?).map_err(|_| CodecError::InvalidType)
}

fn ensure_sorted_unique<T: Ord>(values: &[T]) -> Result<(), CodecError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(CodecError::NonCanonical)
    } else {
        Ok(())
    }
}

fn validate_bundle_canonical(bundle: &ProofBundle) -> Result<(), CodecError> {
    ensure_sorted_unique(bundle.principal_evidence())?;
    ensure_sorted_unique(bundle.principal_evidence_bindings())?;
    ensure_sorted_unique(bundle.authority_state_evidence())?;
    if bundle
        .principal_evidence()
        .windows(2)
        .any(|pair| pair[0].id() == pair[1].id())
        || bundle
            .authority_state_evidence()
            .windows(2)
            .any(|pair| pair[0].id() == pair[1].id())
    {
        return Err(CodecError::NonCanonical);
    }
    for evidence in bundle.principal_evidence() {
        if evidence_id(
            evidence.method(),
            evidence.media_type(),
            evidence.bytes().as_slice(),
        ) != evidence.id()
        {
            return Err(CodecError::DigestMismatch);
        }
    }
    for evidence in bundle.authority_state_evidence() {
        if authority_state_evidence_id(
            evidence.method(),
            evidence.media_type(),
            evidence.bytes().as_slice(),
        ) != evidence.id()
        {
            return Err(CodecError::DigestMismatch);
        }
    }
    Ok(())
}

pub fn encode_bundle(bundle: &ProofBundle) -> Result<Vec<u8>, CodecError> {
    validate_bundle_canonical(bundle)?;
    let mut writer = Writer::default();
    writer.map(6);
    writer.uint(0);
    writer.uint(bundle.version().get() as u64);
    writer.uint(1);
    write_signed_action(&mut writer, bundle.action());
    writer.uint(2);
    writer.array(bundle.grants().len());
    for grant in bundle.grants() {
        write_signed_grant(&mut writer, grant);
    }
    writer.uint(3);
    writer.array(bundle.principal_evidence().len());
    for evidence in bundle.principal_evidence() {
        write_principal_evidence(&mut writer, evidence);
    }
    writer.uint(4);
    writer.array(bundle.principal_evidence_bindings().len());
    for binding in bundle.principal_evidence_bindings() {
        write_binding(&mut writer, binding);
    }
    writer.uint(5);
    writer.array(bundle.authority_state_evidence().len());
    for evidence in bundle.authority_state_evidence() {
        write_authority_state(&mut writer, evidence);
    }
    Ok(writer.finish())
}

pub fn decode_bundle(input: &[u8], limits: DecodeLimits) -> Result<ProofBundle, CodecError> {
    let limits = limits.validate()?;
    if input.len() > limits.max_bundle_bytes {
        return Err(CodecError::LimitExceeded);
    }
    let mut reader = Reader::new(input);
    reader.map_exact(6)?;
    reader.key(0)?;
    ProtocolVersion::new(read_u8(&mut reader)?)?;
    reader.key(1)?;
    let action = read_signed_action(&mut reader)?;
    reader.key(2)?;
    let grant_len = reader.array_len(limits.max_grants)?;
    let mut grants = Vec::with_capacity(grant_len);
    for _ in 0..grant_len {
        grants.push(read_signed_grant(&mut reader, &limits)?);
    }
    reader.key(3)?;
    let evidence_len = reader.array_len(limits.max_evidence_entries)?;
    let mut principal_evidence = Vec::with_capacity(evidence_len);
    for _ in 0..evidence_len {
        principal_evidence.push(read_principal_evidence(&mut reader, &limits)?);
    }
    ensure_sorted_unique(&principal_evidence)?;
    if principal_evidence
        .windows(2)
        .any(|pair| pair[0].id() == pair[1].id())
    {
        return Err(CodecError::NonCanonical);
    }
    reader.key(4)?;
    let binding_len = reader.array_len(limits.max_evidence_entries)?;
    let mut bindings = Vec::with_capacity(binding_len);
    for _ in 0..binding_len {
        bindings.push(read_binding(&mut reader)?);
    }
    ensure_sorted_unique(&bindings)?;
    reader.key(5)?;
    let state_len = reader.array_len(limits.max_evidence_entries)?;
    let mut authority_state = Vec::with_capacity(state_len);
    for _ in 0..state_len {
        authority_state.push(read_authority_state(&mut reader, &limits)?);
    }
    ensure_sorted_unique(&authority_state)?;
    if authority_state
        .windows(2)
        .any(|pair| pair[0].id() == pair[1].id())
    {
        return Err(CodecError::NonCanonical);
    }
    reader.finish()?;
    ProofBundle::new(
        action,
        grants,
        principal_evidence,
        bindings,
        authority_state,
    )
    .map_err(CodecError::from)
}

pub fn encode_signed_grant(grant: &SignedGrant) -> Vec<u8> {
    let mut writer = Writer::default();
    write_signed_grant(&mut writer, grant);
    writer.finish()
}

pub fn decode_signed_grant(input: &[u8]) -> Result<SignedGrant, CodecError> {
    let mut reader = Reader::new(input);
    let grant = read_signed_grant(&mut reader, &DecodeLimits::standard())?;
    reader.finish()?;
    Ok(grant)
}

pub fn encode_signed_action(action: &SignedAction) -> Vec<u8> {
    let mut writer = Writer::default();
    write_signed_action(&mut writer, action);
    writer.finish()
}

pub fn decode_signed_action(input: &[u8]) -> Result<SignedAction, CodecError> {
    let mut reader = Reader::new(input);
    let action = read_signed_action(&mut reader)?;
    reader.finish()?;
    Ok(action)
}

pub fn encode_principal_evidence(evidence: &PrincipalEvidenceEntry) -> Vec<u8> {
    let mut writer = Writer::default();
    write_principal_evidence(&mut writer, evidence);
    writer.finish()
}

pub fn decode_principal_evidence(
    input: &[u8],
    max_evidence_bytes: usize,
) -> Result<PrincipalEvidenceEntry, CodecError> {
    let limits = DecodeLimits {
        max_evidence_bytes,
        ..DecodeLimits::standard()
    }
    .validate()?;
    let mut reader = Reader::new(input);
    let evidence = read_principal_evidence(&mut reader, &limits)?;
    reader.finish()?;
    Ok(evidence)
}

pub fn encode_grant_signing_input(
    grant: &GrantPayload,
    descriptor: &SignatureDescriptor,
) -> Vec<u8> {
    let mut writer = Writer::default();
    writer.map(2);
    writer.uint(0);
    write_grant_payload(&mut writer, grant);
    writer.uint(1);
    write_descriptor(&mut writer, descriptor);
    writer.finish()
}

pub fn decode_grant_signing_input(
    input: &[u8],
) -> Result<(GrantPayload, SignatureDescriptor), CodecError> {
    let mut reader = Reader::new(input);
    reader.map_exact(2)?;
    reader.key(0)?;
    let grant = read_grant_payload(&mut reader, &DecodeLimits::standard())?;
    reader.key(1)?;
    let descriptor = read_descriptor(&mut reader)?;
    reader.finish()?;
    Ok((grant, descriptor))
}

pub fn encode_action_signing_input(
    action: &ActionStatement,
    descriptor: &SignatureDescriptor,
) -> Vec<u8> {
    let mut writer = Writer::default();
    writer.map(2);
    writer.uint(0);
    write_action_payload(&mut writer, action);
    writer.uint(1);
    write_descriptor(&mut writer, descriptor);
    writer.finish()
}

pub fn decode_action_signing_input(
    input: &[u8],
) -> Result<(ActionStatement, SignatureDescriptor), CodecError> {
    let mut reader = Reader::new(input);
    reader.map_exact(2)?;
    reader.key(0)?;
    let action = read_action_payload(&mut reader)?;
    reader.key(1)?;
    let descriptor = read_descriptor(&mut reader)?;
    reader.finish()?;
    Ok((action, descriptor))
}

pub fn grant_signing_bytes(grant: &GrantPayload, descriptor: &SignatureDescriptor) -> Vec<u8> {
    let encoded = encode_grant_signing_input(grant, descriptor);
    let mut bytes = Vec::with_capacity(GRANT_DOMAIN_V1.len() + encoded.len());
    bytes.extend_from_slice(GRANT_DOMAIN_V1);
    bytes.extend_from_slice(&encoded);
    bytes
}

pub fn action_signing_bytes(action: &ActionStatement, descriptor: &SignatureDescriptor) -> Vec<u8> {
    let encoded = encode_action_signing_input(action, descriptor);
    let mut bytes = Vec::with_capacity(ACTION_DOMAIN_V1.len() + encoded.len());
    bytes.extend_from_slice(ACTION_DOMAIN_V1);
    bytes.extend_from_slice(&encoded);
    bytes
}

fn domain_hash(domain: &[u8], encoded: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    hasher.finalize().into()
}

pub fn grant_id(grant: &SignedGrant) -> GrantId {
    GrantId::new(domain_hash(GRANT_ID_DOMAIN_V1, &encode_signed_grant(grant)))
}

pub fn action_id(action: &SignedAction) -> ActionId {
    ActionId::new(domain_hash(
        ACTION_ID_DOMAIN_V1,
        &encode_signed_action(action),
    ))
}

fn evidence_id_for(method: &str, media_type: &EvidenceMediaType, bytes: &[u8]) -> EvidenceId {
    let mut writer = Writer::default();
    writer.map(3);
    writer.uint(0);
    writer.text(method);
    writer.uint(1);
    writer.text(media_type.as_str());
    writer.uint(2);
    writer.bytes(bytes);
    EvidenceId::new(domain_hash(EVIDENCE_ID_DOMAIN_V1, &writer.finish()))
}

pub fn evidence_id(method: &AdapterId, media_type: &EvidenceMediaType, bytes: &[u8]) -> EvidenceId {
    evidence_id_for(method.as_str(), media_type, bytes)
}

pub fn authority_state_evidence_id(
    method: &AuthorityStateMethod,
    media_type: &EvidenceMediaType,
    bytes: &[u8],
) -> EvidenceId {
    evidence_id_for(method.as_str(), media_type, bytes)
}

pub fn body_digest(body: &[u8]) -> BodyDigest {
    BodyDigest::new(Sha256::digest(body).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn descriptor() -> SignatureDescriptor {
        SignatureDescriptor::new(
            AdapterId::parse("raw-key-v1").expect("adapter"),
            VerificationMethodRef::parse("key:sha256:abc").expect("method"),
            AlgorithmId::parse("ed25519").expect("algorithm"),
        )
    }

    fn action() -> ActionStatement {
        ActionStatement::new(
            PrincipalRef::parse("key:sha256:abc").expect("principal"),
            Permission::new(
                CapabilityId::parse("mcp.tools.call").expect("capability"),
                ResourceId::parse("mcp://filesystem/read").expect("resource"),
            ),
            body_digest(b"hello"),
            Audience::parse("mcp://filesystem").expect("audience"),
            Timestamp::new(10),
            Timestamp::new(20),
            Challenge::new([7; 32]),
        )
        .expect("action")
    }

    #[test]
    fn unsigned_action_encoding_is_stable() {
        let encoded = encode_action_signing_input(&action(), &descriptor());
        assert_eq!(
            hex_for_test(&encoded),
            "a200a80001016e6b65793a7368613235363a61626302a2006e6d63702e746f6f6c732e63616c6c01756d63703a2f2f66696c6573797374656d2f72656164035820"
                .to_owned()
                + "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                + "04706d63703a2f2f66696c6573797374656d050a0614075820"
                + &"07".repeat(32)
                + "01a3006a7261772d6b65792d7631016e6b65793a7368613235363a616263026765643235353139"
        );
    }

    #[test]
    fn signed_action_round_trips_canonically() {
        let signature = SignatureEnvelope::new(
            descriptor(),
            SignatureBytes::new(vec![9; 64]).expect("signature"),
        );
        let signed = SignedAction::new(action(), signature);
        let encoded = encode_signed_action(&signed);
        let decoded = decode_signed_action(&encoded).expect("decode");
        assert_eq!(decoded, signed);
        assert_eq!(encode_signed_action(&decoded), encoded);
    }

    #[test]
    fn non_minimal_integer_is_rejected() {
        let mut encoded = encode_action_signing_input(&action(), &descriptor());
        let version_position = encoded
            .windows(3)
            .position(|window| window == [0, 0xa8, 0])
            .expect("version prefix")
            + 3;
        encoded.splice(version_position..version_position + 1, [0x18, 0x01]);
        assert_eq!(
            decode_action_signing_input(&encoded),
            Err(CodecError::NonCanonical)
        );
    }

    fn hex_for_test(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }
}
