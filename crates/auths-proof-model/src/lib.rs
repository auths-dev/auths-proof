//! Protocol-domain types for `auths-proof`.
//!
//! This crate deliberately contains no wire codec, cryptography, I/O, clock,
//! randomness, or concrete identity method.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{string::String, vec, vec::Vec};
use core::{fmt, str::FromStr};

pub const PROTOCOL_V1: u8 = 1;
pub const MAX_PRINCIPAL_LEN: usize = 512;
pub const MAX_CAPABILITY_LEN: usize = 128;
pub const MAX_RESOURCE_LEN: usize = 1_024;
pub const MAX_AUDIENCE_LEN: usize = 512;
pub const MAX_ADAPTER_ID_LEN: usize = 64;
pub const MAX_METHOD_REF_LEN: usize = 512;
pub const MAX_ALGORITHM_ID_LEN: usize = 64;
pub const MAX_MEDIA_TYPE_LEN: usize = 128;
pub const MAX_PERMISSIONS: usize = 1_024;
pub const MAX_GRANTS: usize = 32;
pub const MAX_EVIDENCE_ENTRIES: usize = 256;
pub const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SIGNATURE_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ProtocolVersion(u8);

impl ProtocolVersion {
    pub const V1: Self = Self(PROTOCOL_V1);

    pub fn new(value: u8) -> Result<Self, ModelError> {
        if value == PROTOCOL_V1 {
            Ok(Self(value))
        } else {
            Err(ModelError::UnsupportedProtocolVersion)
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

fn validate_no_space_control(value: &str, max: usize) -> Result<(), ModelError> {
    if value.is_empty() || value.len() > max {
        return Err(ModelError::InvalidLength);
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ModelError::InvalidSyntax);
    }
    Ok(())
}

fn validate_token(value: &str, max: usize) -> Result<(), ModelError> {
    validate_no_space_control(value, max)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
    }) {
        return Err(ModelError::InvalidSyntax);
    }
    Ok(())
}

macro_rules! string_newtype {
    ($name:ident, $max:expr, $validator:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: &str) -> Result<Self, ModelError> {
                $validator(value, $max)?;
                Ok(Self(String::from(value)))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
    };
}

fn validate_principal(value: &str, max: usize) -> Result<(), ModelError> {
    validate_no_space_control(value, max)?;
    let (scheme, remainder) = value.split_once(':').ok_or(ModelError::MissingScheme)?;
    let mut bytes = scheme.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')
        })
        || remainder.is_empty()
    {
        return Err(ModelError::InvalidSyntax);
    }
    Ok(())
}

string_newtype!(PrincipalRef, MAX_PRINCIPAL_LEN, validate_principal);
string_newtype!(CapabilityId, MAX_CAPABILITY_LEN, validate_token);
string_newtype!(ResourceId, MAX_RESOURCE_LEN, validate_no_space_control);
string_newtype!(Audience, MAX_AUDIENCE_LEN, validate_no_space_control);
string_newtype!(AdapterId, MAX_ADAPTER_ID_LEN, validate_token);
string_newtype!(
    VerificationMethodRef,
    MAX_METHOD_REF_LEN,
    validate_no_space_control
);
string_newtype!(AlgorithmId, MAX_ALGORITHM_ID_LEN, validate_token);
string_newtype!(
    EvidenceMediaType,
    MAX_MEDIA_TYPE_LEN,
    validate_no_space_control
);
string_newtype!(AuthorityStateMethod, MAX_ADAPTER_ID_LEN, validate_token);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

macro_rules! digest_newtype {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(Digest32);

        impl $name {
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(Digest32::new(bytes))
            }

            pub const fn digest(self) -> Digest32 {
                self.0
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }
    };
}

digest_newtype!(BodyDigest);
digest_newtype!(EvidenceId);
digest_newtype!(GrantId);
digest_newtype!(ActionId);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Challenge([u8; 32]);

impl Challenge {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const fn new(seconds_since_epoch: u64) -> Self {
        Self(seconds_since_epoch)
    }

    pub const fn as_secs(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DurationSeconds(u64);

impl DurationSeconds {
    pub const fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    pub const fn minutes(minutes: u64) -> Self {
        Self(minutes.saturating_mul(60))
    }

    pub const fn as_secs(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DelegationDepth(u8);

impl DelegationDepth {
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValidityWindow {
    from: Timestamp,
    until: Timestamp,
}

impl ValidityWindow {
    pub fn new(from: Timestamp, until: Timestamp) -> Result<Self, ModelError> {
        if from > until {
            return Err(ModelError::InvalidValidityWindow);
        }
        Ok(Self { from, until })
    }

    pub const fn from(&self) -> Timestamp {
        self.from
    }

    pub const fn until(&self) -> Timestamp {
        self.until
    }

    pub fn contains(&self, time: Timestamp) -> bool {
        self.from <= time && time <= self.until
    }

    pub fn contains_window(&self, child: &Self) -> bool {
        self.from <= child.from && child.until <= self.until
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Permission {
    capability: CapabilityId,
    resource: ResourceId,
}

impl Permission {
    pub const fn new(capability: CapabilityId, resource: ResourceId) -> Self {
        Self {
            capability,
            resource,
        }
    }

    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    pub const fn resource(&self) -> &ResourceId {
        &self.resource
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionSet(Vec<Permission>);

impl PermissionSet {
    pub fn new(mut permissions: Vec<Permission>) -> Result<Self, ModelError> {
        permissions.sort();
        permissions.dedup();
        if permissions.is_empty() || permissions.len() > MAX_PERMISSIONS {
            return Err(ModelError::InvalidPermissionSet);
        }
        Ok(Self(permissions))
    }

    pub fn from_canonical(permissions: Vec<Permission>) -> Result<Self, ModelError> {
        if permissions.is_empty()
            || permissions.len() > MAX_PERMISSIONS
            || permissions.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ModelError::NonCanonicalPermissionSet);
        }
        Ok(Self(permissions))
    }

    pub fn as_slice(&self) -> &[Permission] {
        &self.0
    }

    pub fn contains(&self, permission: &Permission) -> bool {
        self.0.binary_search(permission).is_ok()
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.0.iter().all(|permission| parent.contains(permission))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityScope {
    permissions: PermissionSet,
}

impl AuthorityScope {
    pub const fn new(permissions: PermissionSet) -> Self {
        Self { permissions }
    }

    pub const fn permissions(&self) -> &PermissionSet {
        &self.permissions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureDescriptor {
    adapter: AdapterId,
    verification_method: VerificationMethodRef,
    algorithm: AlgorithmId,
}

impl SignatureDescriptor {
    pub const fn new(
        adapter: AdapterId,
        verification_method: VerificationMethodRef,
        algorithm: AlgorithmId,
    ) -> Self {
        Self {
            adapter,
            verification_method,
            algorithm,
        }
    }

    pub const fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    pub const fn verification_method(&self) -> &VerificationMethodRef {
        &self.verification_method
    }

    pub const fn algorithm(&self) -> &AlgorithmId {
        &self.algorithm
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureBytes(Vec<u8>);

impl SignatureBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ModelError> {
        if bytes.is_empty() || bytes.len() > MAX_SIGNATURE_BYTES {
            return Err(ModelError::InvalidSignatureLength);
        }
        Ok(Self(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureEnvelope {
    descriptor: SignatureDescriptor,
    signature: SignatureBytes,
}

impl SignatureEnvelope {
    pub const fn new(descriptor: SignatureDescriptor, signature: SignatureBytes) -> Self {
        Self {
            descriptor,
            signature,
        }
    }

    pub const fn descriptor(&self) -> &SignatureDescriptor {
        &self.descriptor
    }

    pub const fn signature(&self) -> &SignatureBytes {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationRequirement {
    ExpiryOnly,
    StatusProofRequired { method: AuthorityStateMethod },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantPayload {
    version: ProtocolVersion,
    issuer: PrincipalRef,
    subject: PrincipalRef,
    permissions: PermissionSet,
    issued_at: Timestamp,
    validity: ValidityWindow,
    remaining_delegation_depth: DelegationDepth,
    revocation: RevocationRequirement,
    parent: Option<GrantId>,
}

impl GrantPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: PrincipalRef,
        subject: PrincipalRef,
        permissions: PermissionSet,
        issued_at: Timestamp,
        validity: ValidityWindow,
        remaining_delegation_depth: DelegationDepth,
        revocation: RevocationRequirement,
        parent: Option<GrantId>,
    ) -> Result<Self, ModelError> {
        if issued_at > validity.until() {
            return Err(ModelError::IssueTimeAfterValidity);
        }
        Ok(Self {
            version: ProtocolVersion::V1,
            issuer,
            subject,
            permissions,
            issued_at,
            validity,
            remaining_delegation_depth,
            revocation,
            parent,
        })
    }

    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }
    pub const fn issuer(&self) -> &PrincipalRef {
        &self.issuer
    }
    pub const fn subject(&self) -> &PrincipalRef {
        &self.subject
    }
    pub const fn permissions(&self) -> &PermissionSet {
        &self.permissions
    }
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }
    pub const fn validity(&self) -> ValidityWindow {
        self.validity
    }
    pub const fn remaining_delegation_depth(&self) -> DelegationDepth {
        self.remaining_delegation_depth
    }
    pub const fn revocation(&self) -> &RevocationRequirement {
        &self.revocation
    }
    pub const fn parent(&self) -> Option<GrantId> {
        self.parent
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedGrant {
    payload: GrantPayload,
    signature: SignatureEnvelope,
}

impl SignedGrant {
    pub const fn new(payload: GrantPayload, signature: SignatureEnvelope) -> Self {
        Self { payload, signature }
    }

    pub const fn payload(&self) -> &GrantPayload {
        &self.payload
    }

    pub const fn signature(&self) -> &SignatureEnvelope {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionStatement {
    version: ProtocolVersion,
    actor: PrincipalRef,
    permission: Permission,
    body_digest: BodyDigest,
    audience: Audience,
    issued_at: Timestamp,
    expires_at: Timestamp,
    challenge: Challenge,
}

impl ActionStatement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actor: PrincipalRef,
        permission: Permission,
        body_digest: BodyDigest,
        audience: Audience,
        issued_at: Timestamp,
        expires_at: Timestamp,
        challenge: Challenge,
    ) -> Result<Self, ModelError> {
        if issued_at > expires_at {
            return Err(ModelError::InvalidValidityWindow);
        }
        Ok(Self {
            version: ProtocolVersion::V1,
            actor,
            permission,
            body_digest,
            audience,
            issued_at,
            expires_at,
            challenge,
        })
    }

    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }
    pub const fn actor(&self) -> &PrincipalRef {
        &self.actor
    }
    pub const fn permission(&self) -> &Permission {
        &self.permission
    }
    pub const fn body_digest(&self) -> BodyDigest {
        self.body_digest
    }
    pub const fn audience(&self) -> &Audience {
        &self.audience
    }
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
    pub const fn challenge(&self) -> Challenge {
        self.challenge
    }
    pub fn validity(&self) -> ValidityWindow {
        ValidityWindow {
            from: self.issued_at,
            until: self.expires_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAction {
    payload: ActionStatement,
    signature: SignatureEnvelope,
}

impl SignedAction {
    pub const fn new(payload: ActionStatement, signature: SignatureEnvelope) -> Self {
        Self { payload, signature }
    }

    pub const fn payload(&self) -> &ActionStatement {
        &self.payload
    }

    pub const fn signature(&self) -> &SignatureEnvelope {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct EvidenceBytes(Vec<u8>);

impl EvidenceBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ModelError> {
        if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(ModelError::InvalidEvidenceLength);
        }
        Ok(Self(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PrincipalEvidenceEntry {
    id: EvidenceId,
    method: AdapterId,
    media_type: EvidenceMediaType,
    bytes: EvidenceBytes,
}

impl PrincipalEvidenceEntry {
    pub const fn new(
        id: EvidenceId,
        method: AdapterId,
        media_type: EvidenceMediaType,
        bytes: EvidenceBytes,
    ) -> Self {
        Self {
            id,
            method,
            media_type,
            bytes,
        }
    }

    pub const fn id(&self) -> EvidenceId {
        self.id
    }
    pub const fn method(&self) -> &AdapterId {
        &self.method
    }
    pub const fn media_type(&self) -> &EvidenceMediaType {
        &self.media_type
    }
    pub const fn bytes(&self) -> &EvidenceBytes {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum StatementId {
    Grant(GrantId),
    Action(ActionId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PrincipalEvidenceBinding {
    statement: StatementId,
    evidence: EvidenceId,
}

impl PrincipalEvidenceBinding {
    pub const fn new(statement: StatementId, evidence: EvidenceId) -> Self {
        Self {
            statement,
            evidence,
        }
    }

    pub const fn statement(&self) -> StatementId {
        self.statement
    }

    pub const fn evidence(&self) -> EvidenceId {
        self.evidence
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthorityStateEvidenceEntry {
    id: EvidenceId,
    method: AuthorityStateMethod,
    media_type: EvidenceMediaType,
    bytes: EvidenceBytes,
}

impl AuthorityStateEvidenceEntry {
    pub const fn new(
        id: EvidenceId,
        method: AuthorityStateMethod,
        media_type: EvidenceMediaType,
        bytes: EvidenceBytes,
    ) -> Self {
        Self {
            id,
            method,
            media_type,
            bytes,
        }
    }

    pub const fn id(&self) -> EvidenceId {
        self.id
    }
    pub const fn method(&self) -> &AuthorityStateMethod {
        &self.method
    }
    pub const fn media_type(&self) -> &EvidenceMediaType {
        &self.media_type
    }
    pub const fn bytes(&self) -> &EvidenceBytes {
        &self.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofBundle {
    version: ProtocolVersion,
    action: SignedAction,
    grants: Vec<SignedGrant>,
    principal_evidence: Vec<PrincipalEvidenceEntry>,
    principal_evidence_bindings: Vec<PrincipalEvidenceBinding>,
    authority_state_evidence: Vec<AuthorityStateEvidenceEntry>,
}

impl ProofBundle {
    pub fn new(
        action: SignedAction,
        grants: Vec<SignedGrant>,
        principal_evidence: Vec<PrincipalEvidenceEntry>,
        principal_evidence_bindings: Vec<PrincipalEvidenceBinding>,
        authority_state_evidence: Vec<AuthorityStateEvidenceEntry>,
    ) -> Result<Self, ModelError> {
        if grants.len() > MAX_GRANTS
            || principal_evidence.len() > MAX_EVIDENCE_ENTRIES
            || principal_evidence_bindings.len() > MAX_EVIDENCE_ENTRIES
            || authority_state_evidence.len() > MAX_EVIDENCE_ENTRIES
        {
            return Err(ModelError::CollectionLimitExceeded);
        }
        Ok(Self {
            version: ProtocolVersion::V1,
            action,
            grants,
            principal_evidence,
            principal_evidence_bindings,
            authority_state_evidence,
        })
    }

    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }
    pub const fn action(&self) -> &SignedAction {
        &self.action
    }
    pub fn grants(&self) -> &[SignedGrant] {
        &self.grants
    }
    pub fn principal_evidence(&self) -> &[PrincipalEvidenceEntry] {
        &self.principal_evidence
    }
    pub fn principal_evidence_bindings(&self) -> &[PrincipalEvidenceBinding] {
        &self.principal_evidence_bindings
    }
    pub fn authority_state_evidence(&self) -> &[AuthorityStateEvidenceEntry] {
        &self.authority_state_evidence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum AssuranceClaim {
    SelfCertifyingIdentifier,
    OfflineVerifiable,
    ControllerStateCurrentAt(Timestamp),
    ControllerStateHistoricalAt(Timestamp),
    StatementExistenceProvenAt(Timestamp),
    RotationAware,
    RevocationCheckedAt(Timestamp),
    WitnessThresholdMet(u16),
    PkiChainValidated,
    HardwareAttested,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssuranceClaims(Vec<AssuranceClaim>);

impl AssuranceClaims {
    pub fn new(mut claims: Vec<AssuranceClaim>) -> Self {
        claims.sort();
        claims.dedup();
        Self(claims)
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn as_slice(&self) -> &[AssuranceClaim] {
        &self.0
    }

    pub fn contains(&self, claim: &AssuranceClaim) -> bool {
        self.0.binary_search(claim).is_ok()
    }

    pub fn contains_all(&self, required: &Self) -> bool {
        required.0.iter().all(|claim| self.contains(claim))
    }

    pub fn union_assign(&mut self, other: &Self) {
        self.0.extend_from_slice(&other.0);
        self.0.sort();
        self.0.dedup();
    }

    pub fn intersect_assign(&mut self, other: &Self) {
        self.0.retain(|claim| other.contains(claim));
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssuranceRequirements {
    required_claims: AssuranceClaims,
    max_controller_status_age: Option<DurationSeconds>,
    allow_irrevocable_principals: bool,
    require_statement_time_for_historical_keys: bool,
}

impl AssuranceRequirements {
    pub const fn new(
        required_claims: AssuranceClaims,
        max_controller_status_age: Option<DurationSeconds>,
        allow_irrevocable_principals: bool,
        require_statement_time_for_historical_keys: bool,
    ) -> Self {
        Self {
            required_claims,
            max_controller_status_age,
            allow_irrevocable_principals,
            require_statement_time_for_historical_keys,
        }
    }

    pub const fn required_claims(&self) -> &AssuranceClaims {
        &self.required_claims
    }
    pub const fn max_controller_status_age(&self) -> Option<DurationSeconds> {
        self.max_controller_status_age
    }
    pub const fn allow_irrevocable_principals(&self) -> bool {
        self.allow_irrevocable_principals
    }
    pub const fn require_statement_time_for_historical_keys(&self) -> bool {
        self.require_statement_time_for_historical_keys
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustAnchor {
    principal: PrincipalRef,
    authority: AuthorityScope,
    validity: ValidityWindow,
    max_delegation_depth: DelegationDepth,
    required_assurance: AssuranceRequirements,
}

impl TrustAnchor {
    pub const fn new(
        principal: PrincipalRef,
        authority: AuthorityScope,
        validity: ValidityWindow,
        max_delegation_depth: DelegationDepth,
        required_assurance: AssuranceRequirements,
    ) -> Self {
        Self {
            principal,
            authority,
            validity,
            max_delegation_depth,
            required_assurance,
        }
    }

    pub const fn principal(&self) -> &PrincipalRef {
        &self.principal
    }
    pub const fn authority(&self) -> &AuthorityScope {
        &self.authority
    }
    pub const fn validity(&self) -> ValidityWindow {
        self.validity
    }
    pub const fn max_delegation_depth(&self) -> DelegationDepth {
        self.max_delegation_depth
    }
    pub const fn required_assurance(&self) -> &AssuranceRequirements {
        &self.required_assurance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationPolicy {
    required_assurance: AssuranceClaims,
    max_controller_status_age: Option<DurationSeconds>,
    allow_expiry_only_grants: bool,
    allow_irrevocable_principals: bool,
    require_statement_time_for_historical_keys: bool,
}

impl VerificationPolicy {
    pub fn live_action() -> Self {
        Self {
            required_assurance: AssuranceClaims::new(vec![AssuranceClaim::OfflineVerifiable]),
            max_controller_status_age: None,
            allow_expiry_only_grants: true,
            allow_irrevocable_principals: true,
            require_statement_time_for_historical_keys: true,
        }
    }

    pub fn offline_audit() -> Self {
        Self {
            required_assurance: AssuranceClaims::empty(),
            max_controller_status_age: None,
            allow_expiry_only_grants: true,
            allow_irrevocable_principals: true,
            require_statement_time_for_historical_keys: true,
        }
    }

    pub fn require_claim(mut self, claim: AssuranceClaim) -> Self {
        let mut claims = self.required_assurance.0;
        claims.push(claim);
        self.required_assurance = AssuranceClaims::new(claims);
        self
    }

    pub const fn max_controller_status_age(mut self, age: DurationSeconds) -> Self {
        self.max_controller_status_age = Some(age);
        self
    }

    pub const fn required_assurance(&self) -> &AssuranceClaims {
        &self.required_assurance
    }
    pub const fn controller_status_max_age(&self) -> Option<DurationSeconds> {
        self.max_controller_status_age
    }
    pub const fn allow_expiry_only_grants(&self) -> bool {
        self.allow_expiry_only_grants
    }
    pub const fn allow_irrevocable_principals(&self) -> bool {
        self.allow_irrevocable_principals
    }
    pub const fn require_statement_time_for_historical_keys(&self) -> bool {
        self.require_statement_time_for_historical_keys
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Authorized,
    Denied,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum VerdictReason {
    AuthorizedByGrantChain,
    MalformedProof,
    NonCanonicalProof,
    InvalidEvidenceDigest,
    DuplicateEvidence,
    DuplicateEvidenceBinding,
    UnusedEvidence,
    InvalidSignature,
    PrincipalAdapterMismatch,
    VerificationMethodMismatch,
    AlgorithmMismatch,
    ActionBodyMismatch,
    AudienceMismatch,
    ChallengeMismatch,
    ActionOutsideValidity,
    PermissionNotGranted,
    DelegationExpanded,
    BrokenGrantChain,
    GrantOutsideValidity,
    GrantExpired,
    GrantRevoked,
    UntrustedRoot,
    AssuranceRequirementNotMet,
    UnsupportedAdapter,
    MissingPrincipalEvidence,
    MissingAuthorityStateEvidence,
    StaleAuthorityStateEvidence,
    HistoricalStateUnavailable,
    ExpiryOnlyGrantDisallowed,
    IrrevocablePrincipalDisallowed,
    ResourceLimitExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Limitation {
    ExpiryOnlyGrant(GrantId),
    IrrevocablePrincipal(PrincipalRef),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustVerdict {
    decision: Decision,
    reasons: Vec<VerdictReason>,
    root: Option<PrincipalRef>,
    actor: Option<PrincipalRef>,
    grant_count: usize,
    assurance: AssuranceClaims,
    limitations: Vec<Limitation>,
}

impl TrustVerdict {
    pub fn new(
        decision: Decision,
        reasons: Vec<VerdictReason>,
        root: Option<PrincipalRef>,
        actor: Option<PrincipalRef>,
        grant_count: usize,
        assurance: AssuranceClaims,
        limitations: Vec<Limitation>,
    ) -> Self {
        Self {
            decision,
            reasons,
            root,
            actor,
            grant_count,
            assurance,
            limitations,
        }
    }

    pub const fn decision(&self) -> Decision {
        self.decision
    }
    pub fn reasons(&self) -> &[VerdictReason] {
        &self.reasons
    }
    pub const fn root(&self) -> Option<&PrincipalRef> {
        self.root.as_ref()
    }
    pub const fn actor(&self) -> Option<&PrincipalRef> {
        self.actor.as_ref()
    }
    pub const fn grant_count(&self) -> usize {
        self.grant_count
    }
    pub const fn assurance(&self) -> &AssuranceClaims {
        &self.assurance
    }
    pub fn limitations(&self) -> &[Limitation] {
        &self.limitations
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofPurpose {
    CapabilityDelegation,
    CapabilityInvocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    InvalidLength,
    InvalidSyntax,
    MissingScheme,
    UnsupportedProtocolVersion,
    InvalidValidityWindow,
    IssueTimeAfterValidity,
    InvalidPermissionSet,
    NonCanonicalPermissionSet,
    InvalidSignatureLength,
    InvalidEvidenceLength,
    CollectionLimitExceeded,
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidLength => "value length is outside the allowed range",
            Self::InvalidSyntax => "value has invalid syntax",
            Self::MissingScheme => "principal identifier has no scheme",
            Self::UnsupportedProtocolVersion => "unsupported protocol version",
            Self::InvalidValidityWindow => "validity window is inverted",
            Self::IssueTimeAfterValidity => "issue time is after the validity window",
            Self::InvalidPermissionSet => "permission set is empty or too large",
            Self::NonCanonicalPermissionSet => "permission set is not sorted and unique",
            Self::InvalidSignatureLength => "signature length is outside the allowed range",
            Self::InvalidEvidenceLength => "evidence length is outside the allowed range",
            Self::CollectionLimitExceeded => "protocol collection limit exceeded",
        };
        formatter.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ModelError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn principal_requires_lowercase_uri_scheme() {
        assert!(PrincipalRef::parse("did:key:z6Mk").is_ok());
        assert!(PrincipalRef::parse("DID:key:z6Mk").is_err());
        assert!(PrincipalRef::parse("1did:key:z6Mk").is_err());
        assert!(PrincipalRef::parse("did key").is_err());
    }

    #[test]
    fn permission_sets_are_sorted_and_deduplicated_when_authored() {
        let capability = CapabilityId::parse("mcp.tools.call").expect("valid capability");
        let first = Permission::new(
            capability.clone(),
            ResourceId::parse("mcp://b").expect("valid resource"),
        );
        let second = Permission::new(
            capability,
            ResourceId::parse("mcp://a").expect("valid resource"),
        );
        let set = PermissionSet::new(vec![first.clone(), second.clone(), first.clone()])
            .expect("valid permission set");
        assert_eq!(set.as_slice(), &[second, first]);
    }

    #[test]
    fn child_window_must_be_contained() {
        let parent =
            ValidityWindow::new(Timestamp::new(10), Timestamp::new(20)).expect("valid window");
        let child =
            ValidityWindow::new(Timestamp::new(11), Timestamp::new(19)).expect("valid window");
        assert!(parent.contains_window(&child));
    }
}
