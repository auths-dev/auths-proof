//! Validated, effect-free Auths Proof Protocol V1 vocabulary.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, num::NonZeroU64};
use subtle::ConstantTimeEq;

pub const PROTOCOL_V1: u16 = 1;
pub const HARD_MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_BUNDLE_BYTES: usize = 256 * 1024;
pub const HARD_MAX_GRANTS: usize = 256;
pub const DEFAULT_MAX_GRANTS: usize = 16;
pub const HARD_MAX_ACTIONS: usize = 128;
pub const DEFAULT_MAX_ACTIONS: usize = 16;
pub const HARD_MAX_PLAN_LEAVES: usize = 128;
pub const DEFAULT_MAX_PLAN_LEAVES: usize = 16;
pub const HARD_MAX_PLAN_DEPTH: usize = 16;
pub const DEFAULT_MAX_PLAN_DEPTH: usize = 8;
pub const HARD_MAX_PLAN_BRANCHING: usize = 128;
pub const DEFAULT_MAX_PLAN_BRANCHING: usize = 16;
pub const HARD_MAX_EVIDENCE: usize = 512;
pub const DEFAULT_MAX_EVIDENCE: usize = 32;
pub const HARD_MAX_EVIDENCE_BYTES: usize = 2 * 1024 * 1024;
pub const DEFAULT_MAX_EVIDENCE_BYTES: usize = 64 * 1024;
pub const HARD_MAX_BINDINGS: usize = 512;
pub const DEFAULT_MAX_BINDINGS: usize = 32;
pub const HARD_MAX_PRINCIPAL_STATUS: usize = 512;
pub const DEFAULT_MAX_PRINCIPAL_STATUS: usize = 32;
pub const HARD_MAX_GRANT_STATUS: usize = 512;
pub const DEFAULT_MAX_GRANT_STATUS: usize = 32;
pub const HARD_MAX_ATTACHMENTS: usize = 512;
pub const DEFAULT_MAX_ATTACHMENTS: usize = 32;
pub const HARD_MAX_SIGNATURES: usize = 1_024;
pub const DEFAULT_MAX_SIGNATURES: usize = 64;
pub const HARD_MAX_SIGNATURE_BYTES: usize = 4_096;
pub const DEFAULT_MAX_SIGNATURE_BYTES: usize = 512;
pub const HARD_MAX_PERMISSIONS: usize = 1_024;
pub const DEFAULT_MAX_PERMISSIONS: usize = 64;
pub const HARD_MAX_AUDIENCES: usize = 256;
pub const DEFAULT_MAX_AUDIENCES: usize = 32;
pub const HARD_MAX_EXTENSIONS: usize = 32;
pub const DEFAULT_MAX_EXTENSIONS: usize = 8;
pub const HARD_MAX_EXTENSION_BYTES: usize = 65_536;
pub const DEFAULT_MAX_EXTENSION_BYTES: usize = 16_384;
pub const HARD_MAX_BODY_DIGESTS: usize = 256;
pub const DEFAULT_MAX_BODY_DIGESTS: usize = 32;
pub const HARD_MAX_BINDING_EVIDENCE: usize = 32;
pub const DEFAULT_MAX_BINDING_EVIDENCE: usize = 8;
pub const HARD_MAX_CANONICAL_BODY_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_CANONICAL_BODY_BYTES: usize = 1024 * 1024;
pub const HARD_MAX_WORK_UNITS: u64 = 1_000_000;
pub const DEFAULT_MAX_WORK_UNITS: u64 = 50_000;
pub const HARD_MAX_REGISTRY_ENTRIES: usize = 1_024;
pub const DEFAULT_MAX_REGISTRY_ENTRIES: usize = 64;
pub const HARD_MAX_TRUST_ANCHORS: usize = 1_024;
pub const DEFAULT_MAX_TRUST_ANCHORS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ProtocolVersion(u16);

impl ProtocolVersion {
    pub const V1: Self = Self(PROTOCOL_V1);

    /// Parses a supported protocol-major identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::UnsupportedProtocol`] unless `value` identifies
    /// Auths Proof Protocol V1.
    pub const fn new(value: u16) -> Result<Self, ModelError> {
        if value == PROTOCOL_V1 {
            Ok(Self(value))
        } else {
            Err(ModelError::UnsupportedProtocol)
        }
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

fn parse_bounded(value: &str, maximum: usize, error: ModelError) -> Result<String, ModelError> {
    if value.is_empty()
        || value.len() > maximum
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(error);
    }
    Ok(value.to_string())
}

macro_rules! bounded_string {
    ($name:ident, $maximum:expr, $error:expr) => {
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(String);

        impl $name {
            /// Parses a non-empty, bounded identifier without whitespace or
            /// control characters.
            ///
            /// # Errors
            ///
            /// Returns the identifier-specific [`ModelError`] when `value` is
            /// empty, exceeds its protocol bound, or contains whitespace or a
            /// control character.
            pub fn parse(value: &str) -> Result<Self, ModelError> {
                parse_bounded(value, $maximum, $error).map(Self)
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

/// Opaque, bounded principal identifier with a canonical lowercase URI scheme.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Parses a principal identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidPrincipal`] when the identifier violates
    /// its byte bound, contains whitespace/control characters, lacks a URI
    /// scheme, or uses a non-canonical scheme.
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        let parsed = parse_bounded(value, 512, ModelError::InvalidPrincipal)?;
        let (scheme, remainder) = parsed.split_once(':').ok_or(ModelError::InvalidPrincipal)?;
        let mut characters = scheme.chars();
        if remainder.is_empty()
            || !characters
                .next()
                .is_some_and(|character| character.is_ascii_lowercase())
            || !characters.all(|character| {
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || matches!(character, '+' | '-' | '.')
            })
        {
            return Err(ModelError::InvalidPrincipal);
        }
        Ok(Self(parsed))
    }

    /// Returns the canonical principal identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

bounded_string!(
    VerificationMethod,
    512,
    ModelError::InvalidVerificationMethod
);
bounded_string!(ProfileId, 128, ModelError::InvalidProfile);
bounded_string!(CapabilityId, 128, ModelError::InvalidCapability);
bounded_string!(ResourceId, 1_024, ModelError::InvalidResource);
bounded_string!(Audience, 512, ModelError::InvalidAudience);
bounded_string!(MediaType, 128, ModelError::InvalidMediaType);
bounded_string!(PrincipalMethodId, 128, ModelError::InvalidRegistryId);
bounded_string!(SignatureSuiteId, 128, ModelError::InvalidRegistryId);
bounded_string!(EvidenceTypeId, 128, ModelError::InvalidRegistryId);
bounded_string!(StatusMethodId, 128, ModelError::InvalidRegistryId);
bounded_string!(AssuranceClaimId, 128, ModelError::InvalidRegistryId);
bounded_string!(AssurancePolicyId, 128, ModelError::InvalidRegistryId);
bounded_string!(BudgetAlgebraId, 128, ModelError::InvalidRegistryId);
bounded_string!(ResourceMatcherId, 128, ModelError::InvalidRegistryId);
bounded_string!(ChannelBindingId, 128, ModelError::InvalidRegistryId);
bounded_string!(ProfilePolicyId, 128, ModelError::InvalidRegistryId);
bounded_string!(AssuranceImplicationId, 128, ModelError::InvalidRegistryId);
bounded_string!(PurposeId, 128, ModelError::InvalidRegistryId);
bounded_string!(AdapterId, 128, ModelError::InvalidRegistryId);
bounded_string!(EvidenceSourceId, 128, ModelError::InvalidRegistryId);
bounded_string!(ClaimParameterId, 128, ModelError::InvalidRegistryId);
bounded_string!(DispositionId, 128, ModelError::InvalidRegistryId);
bounded_string!(TrustAnchorId, 128, ModelError::InvalidRegistryId);
bounded_string!(ExtensionId, 128, ModelError::InvalidExtensionId);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const ZERO: Self = Self([0; 32]);

    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

macro_rules! digest_identifier {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(Digest);

        impl $name {
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(Digest::new(bytes))
            }

            #[must_use]
            pub const fn from_digest(digest: Digest) -> Self {
                Self(digest)
            }

            #[must_use]
            pub const fn digest(self) -> Digest {
                self.0
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl From<Digest> for $name {
            fn from(digest: Digest) -> Self {
                Self::from_digest(digest)
            }
        }

        impl From<$name> for Digest {
            fn from(identifier: $name) -> Self {
                identifier.digest()
            }
        }
    };
}

digest_identifier!(GrantId);
digest_identifier!(ActionId);
digest_identifier!(PlanId);
digest_identifier!(EvidenceId);
digest_identifier!(AttachmentDigest);
digest_identifier!(PrincipalStatusId);
digest_identifier!(GrantStatusId);
digest_identifier!(ReceiptId);
digest_identifier!(ContextDigest);
digest_identifier!(ProofRef);
digest_identifier!(StatusSnapshotId);
digest_identifier!(RegistryManifestId);
digest_identifier!(VerificationResultDigest);

/// Unpredictable 32-byte verifier challenge compared in constant time.
#[derive(Clone, Copy, Debug)]
pub struct Challenge([u8; 32]);

impl Challenge {
    /// Constructs a challenge from exact bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact challenge bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for Challenge {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for Challenge {}

impl core::hash::Hash for Challenge {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::hash::Hash::hash(&self.0, state);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    #[must_use]
    pub const fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidityWindow {
    not_before: Timestamp,
    expires_at: Timestamp,
}

impl ValidityWindow {
    /// Constructs an inclusive validity window.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValidity`] when `not_before` is later than
    /// `expires_at`.
    pub const fn new(not_before: Timestamp, expires_at: Timestamp) -> Result<Self, ModelError> {
        if not_before.0 > expires_at.0 {
            return Err(ModelError::InvalidValidity);
        }
        Ok(Self {
            not_before,
            expires_at,
        })
    }

    #[must_use]
    pub const fn not_before(self) -> Timestamp {
        self.not_before
    }

    #[must_use]
    pub const fn expires_at(self) -> Timestamp {
        self.expires_at
    }

    #[must_use]
    pub const fn contains(self, timestamp: Timestamp) -> bool {
        timestamp.0 >= self.not_before.0 && timestamp.0 <= self.expires_at.0
    }

    #[must_use]
    pub const fn contains_window(self, child: Self) -> bool {
        child.not_before.0 >= self.not_before.0 && child.expires_at.0 <= self.expires_at.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ProfileRef {
    id: ProfileId,
    version: u16,
}

impl ProfileRef {
    /// Constructs a versioned application profile reference.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidProfile`] when `version` is zero. Version
    /// zero is reserved for profile-independent domain-separated objects.
    pub fn new(id: ProfileId, version: u16) -> Result<Self, ModelError> {
        if version == 0 {
            return Err(ModelError::InvalidProfile);
        }
        Ok(Self { id, version })
    }

    #[must_use]
    pub const fn id(&self) -> &ProfileId {
        &self.id
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Permission {
    capability: CapabilityId,
    resource: ResourceId,
}

impl Permission {
    #[must_use]
    pub const fn new(capability: CapabilityId, resource: ResourceId) -> Self {
        Self {
            capability,
            resource,
        }
    }

    #[must_use]
    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    #[must_use]
    pub const fn resource(&self) -> &ResourceId {
        &self.resource
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionSet(Vec<Permission>);

impl PermissionSet {
    /// Constructs a sorted, duplicate-free, non-empty permission set.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidPermissionSet`] when the set is empty or
    /// exceeds [`HARD_MAX_PERMISSIONS`].
    pub fn new(mut permissions: Vec<Permission>) -> Result<Self, ModelError> {
        if permissions.is_empty() || permissions.len() > HARD_MAX_PERMISSIONS {
            return Err(ModelError::InvalidPermissionSet);
        }
        permissions.sort();
        permissions.dedup();
        Ok(Self(permissions))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Permission] {
        &self.0
    }

    #[must_use]
    pub fn contains(&self, permission: &Permission) -> bool {
        self.0.binary_search(permission).is_ok()
    }

    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.0.iter().all(|permission| parent.contains(permission))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AudienceSet(Vec<Audience>);

impl AudienceSet {
    /// Constructs a sorted, duplicate-free, non-empty audience set.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidAudienceSet`] when the set is empty or
    /// exceeds [`HARD_MAX_AUDIENCES`].
    pub fn new(mut audiences: Vec<Audience>) -> Result<Self, ModelError> {
        if audiences.is_empty() || audiences.len() > HARD_MAX_AUDIENCES {
            return Err(ModelError::InvalidAudienceSet);
        }
        audiences.sort();
        audiences.dedup();
        Ok(Self(audiences))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Audience] {
        &self.0
    }

    #[must_use]
    pub fn contains(&self, audience: &Audience) -> bool {
        self.0.binary_search(audience).is_ok()
    }

    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.0.iter().all(|audience| parent.contains(audience))
    }
}

/// Canonically ordered, non-empty set of action body digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyDigestSet(Vec<Digest>);

impl BodyDigestSet {
    /// Constructs a bounded body-digest set.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidActionConstraint`] when `digests` is
    /// empty or exceeds [`HARD_MAX_BODY_DIGESTS`].
    pub fn new(mut digests: Vec<Digest>) -> Result<Self, ModelError> {
        if digests.is_empty() || digests.len() > HARD_MAX_BODY_DIGESTS {
            return Err(ModelError::InvalidActionConstraint);
        }
        digests.sort();
        digests.dedup();
        Ok(Self(digests))
    }

    /// Returns canonical digests in ascending byte order.
    #[must_use]
    pub fn as_slice(&self) -> &[Digest] {
        &self.0
    }

    /// Reports whether the set contains `digest`.
    #[must_use]
    pub fn contains(&self, digest: &Digest) -> bool {
        self.0.binary_search(digest).is_ok()
    }

    /// Reports whether this set is a subset of `parent`.
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.0.iter().all(|digest| parent.contains(digest))
    }
}

/// Closed V1 action-body attenuation algebra.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionConstraint {
    /// Delegated discretion over any canonical body.
    AnyBody,
    /// Approval of exactly one canonical body digest.
    ExactBodyDigest(Digest),
    /// Approval of a bounded set of canonical body digests.
    AllowedBodyDigests(BodyDigestSet),
}

impl ActionConstraint {
    /// Constructs an allowed-body set in canonical digest order.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidActionConstraint`] when `digests` is
    /// empty or exceeds [`HARD_MAX_BODY_DIGESTS`].
    pub fn allowed_body_digests(digests: Vec<Digest>) -> Result<Self, ModelError> {
        Ok(Self::AllowedBodyDigests(BodyDigestSet::new(digests)?))
    }

    #[must_use]
    pub fn allows(&self, digest: Digest) -> bool {
        match self {
            Self::AnyBody => true,
            Self::ExactBodyDigest(expected) => expected == &digest,
            Self::AllowedBodyDigests(allowed) => allowed.contains(&digest),
        }
    }

    #[must_use]
    pub fn attenuates(&self, parent: &Self) -> bool {
        match (self, parent) {
            (_, Self::AnyBody) => true,
            (Self::ExactBodyDigest(child), Self::ExactBodyDigest(parent)) => child == parent,
            (Self::ExactBodyDigest(child), Self::AllowedBodyDigests(parent)) => {
                parent.contains(child)
            }
            (Self::AllowedBodyDigests(child), Self::AllowedBodyDigests(parent)) => {
                child.is_subset_of(parent)
            }
            _ => false,
        }
    }

    #[must_use]
    pub fn allowed_digests(&self) -> Option<&[Digest]> {
        if let Self::AllowedBodyDigests(digests) = self {
            Some(digests.as_slice())
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetCeiling {
    algebra: BudgetAlgebraId,
    value: u64,
}

impl BudgetCeiling {
    #[must_use]
    pub const fn new(algebra: BudgetAlgebraId, value: u64) -> Self {
        Self { algebra, value }
    }

    #[must_use]
    pub const fn algebra(&self) -> &BudgetAlgebraId {
        &self.algebra
    }

    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    #[must_use]
    pub fn attenuates(&self, parent: &Self) -> bool {
        self.algebra == parent.algebra && self.value <= parent.value
    }

    /// Reports whether this ceiling covers an action's requested budget.
    #[must_use]
    pub fn covers(&self, requested: &Self) -> bool {
        requested.attenuates(self)
    }
}

/// Non-zero maximum age for a required status observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FreshnessLimit(NonZeroU64);

impl FreshnessLimit {
    /// Constructs a non-zero freshness limit in seconds.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidStatus`] when `seconds` is zero.
    pub const fn new(seconds: u64) -> Result<Self, ModelError> {
        match NonZeroU64::new(seconds) {
            Some(value) => Ok(Self(value)),
            None => Err(ModelError::InvalidStatus),
        }
    }

    /// Returns the freshness window in seconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Grant or trust-anchor status requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatusPolicy {
    /// Expiration is sufficient; no external status snapshot is required.
    ExpiryOnly,
    /// A registered immutable status snapshot must be fresh enough.
    SnapshotRequired {
        /// Exact status-method registry identifier.
        method: StatusMethodId,
        /// Maximum accepted observation age.
        max_age: FreshnessLimit,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CriticalExtension {
    id: ExtensionId,
    bytes: Vec<u8>,
}

impl CriticalExtension {
    /// Constructs one bounded critical extension.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidExtension`] when `bytes` exceeds
    /// [`HARD_MAX_EXTENSION_BYTES`].
    pub fn new(id: ExtensionId, bytes: Vec<u8>) -> Result<Self, ModelError> {
        if bytes.len() > HARD_MAX_EXTENSION_BYTES {
            return Err(ModelError::InvalidExtension);
        }
        Ok(Self { id, bytes })
    }

    #[must_use]
    pub const fn id(&self) -> &ExtensionId {
        &self.id
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriticalExtensions(Vec<CriticalExtension>);

impl CriticalExtensions {
    /// Constructs a canonical critical-extension set.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidExtension`] when the collection exceeds
    /// [`HARD_MAX_EXTENSIONS`] and [`ModelError::DuplicateExtension`] when an
    /// identifier occurs more than once.
    pub fn new(mut extensions: Vec<CriticalExtension>) -> Result<Self, ModelError> {
        if extensions.len() > HARD_MAX_EXTENSIONS {
            return Err(ModelError::InvalidExtension);
        }
        extensions.sort();
        if extensions
            .windows(2)
            .any(|window| window[0].id == window[1].id)
        {
            return Err(ModelError::DuplicateExtension);
        }
        Ok(Self(extensions))
    }

    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn as_slice(&self) -> &[CriticalExtension] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureDescriptor {
    principal_method: PrincipalMethodId,
    verification_method: VerificationMethod,
    suite: SignatureSuiteId,
}

impl SignatureDescriptor {
    #[must_use]
    pub const fn new(
        principal_method: PrincipalMethodId,
        verification_method: VerificationMethod,
        suite: SignatureSuiteId,
    ) -> Self {
        Self {
            principal_method,
            verification_method,
            suite,
        }
    }

    #[must_use]
    pub const fn principal_method(&self) -> &PrincipalMethodId {
        &self.principal_method
    }

    #[must_use]
    pub const fn verification_method(&self) -> &VerificationMethod {
        &self.verification_method
    }

    #[must_use]
    pub const fn suite(&self) -> &SignatureSuiteId {
        &self.suite
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureBytes(Vec<u8>);

impl SignatureBytes {
    /// Constructs bounded, non-empty signature bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidSignature`] when `bytes` is empty or
    /// exceeds [`HARD_MAX_SIGNATURE_BYTES`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, ModelError> {
        if bytes.is_empty() || bytes.len() > HARD_MAX_SIGNATURE_BYTES {
            return Err(ModelError::InvalidSignature);
        }
        Ok(Self(bytes))
    }

    #[must_use]
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
    #[must_use]
    pub const fn new(descriptor: SignatureDescriptor, signature: SignatureBytes) -> Self {
        Self {
            descriptor,
            signature,
        }
    }

    #[must_use]
    pub const fn descriptor(&self) -> &SignatureDescriptor {
        &self.descriptor
    }

    #[must_use]
    pub const fn signature(&self) -> &SignatureBytes {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantStatement {
    version: ProtocolVersion,
    issuer: PrincipalId,
    subject: PrincipalId,
    profile: ProfileRef,
    permissions: PermissionSet,
    validity: ValidityWindow,
    audiences: AudienceSet,
    action_constraint: ActionConstraint,
    budget_ceiling: Option<BudgetCeiling>,
    remaining_depth: u16,
    parent: Option<GrantId>,
    status_policy: StatusPolicy,
    assurance_floor: AssurancePolicyId,
    extensions: CriticalExtensions,
}

impl GrantStatement {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        issuer: PrincipalId,
        subject: PrincipalId,
        profile: ProfileRef,
        permissions: PermissionSet,
        validity: ValidityWindow,
        audiences: AudienceSet,
        action_constraint: ActionConstraint,
        budget_ceiling: Option<BudgetCeiling>,
        remaining_depth: u16,
        parent: Option<GrantId>,
        status_policy: StatusPolicy,
        assurance_floor: AssurancePolicyId,
        extensions: CriticalExtensions,
    ) -> Self {
        Self {
            version: ProtocolVersion::V1,
            issuer,
            subject,
            profile,
            permissions,
            validity,
            audiences,
            action_constraint,
            budget_ceiling,
            remaining_depth,
            parent,
            status_policy,
            assurance_floor,
            extensions,
        }
    }

    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }
    #[must_use]
    pub const fn issuer(&self) -> &PrincipalId {
        &self.issuer
    }
    #[must_use]
    pub const fn subject(&self) -> &PrincipalId {
        &self.subject
    }
    #[must_use]
    pub const fn profile(&self) -> &ProfileRef {
        &self.profile
    }
    #[must_use]
    pub const fn permissions(&self) -> &PermissionSet {
        &self.permissions
    }
    #[must_use]
    pub const fn validity(&self) -> ValidityWindow {
        self.validity
    }
    #[must_use]
    pub const fn audiences(&self) -> &AudienceSet {
        &self.audiences
    }
    #[must_use]
    pub const fn action_constraint(&self) -> &ActionConstraint {
        &self.action_constraint
    }
    #[must_use]
    pub const fn budget_ceiling(&self) -> Option<&BudgetCeiling> {
        self.budget_ceiling.as_ref()
    }
    #[must_use]
    pub const fn remaining_depth(&self) -> u16 {
        self.remaining_depth
    }
    #[must_use]
    pub const fn parent(&self) -> Option<GrantId> {
        self.parent
    }
    #[must_use]
    pub const fn status_policy(&self) -> &StatusPolicy {
        &self.status_policy
    }
    #[must_use]
    pub const fn assurance_floor(&self) -> &AssurancePolicyId {
        &self.assurance_floor
    }
    #[must_use]
    pub const fn extensions(&self) -> &CriticalExtensions {
        &self.extensions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedGrant {
    statement: GrantStatement,
    signature: SignatureEnvelope,
}

impl SignedGrant {
    #[must_use]
    pub const fn new(statement: GrantStatement, signature: SignatureEnvelope) -> Self {
        Self {
            statement,
            signature,
        }
    }

    #[must_use]
    pub const fn statement(&self) -> &GrantStatement {
        &self.statement
    }

    #[must_use]
    pub const fn signature(&self) -> &SignatureEnvelope {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionEnvelope {
    version: ProtocolVersion,
    profile: ProfileRef,
    body_media_type: MediaType,
    canonical_body_digest: Digest,
    permission: Permission,
    requested_budget: Option<BudgetCeiling>,
    audience: Audience,
    challenge: Challenge,
    validity: ValidityWindow,
    actor: PrincipalId,
    terminal_grant: Option<GrantId>,
    authorization_plan: PlanId,
    channel_binding: ChannelBindingId,
    proof_ref: ProofRef,
    attachments: Vec<AttachmentDescriptor>,
    extensions: CriticalExtensions,
}

impl ActionEnvelope {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        profile: ProfileRef,
        body_media_type: MediaType,
        canonical_body_digest: Digest,
        permission: Permission,
        requested_budget: Option<BudgetCeiling>,
        audience: Audience,
        challenge: Challenge,
        validity: ValidityWindow,
        actor: PrincipalId,
        terminal_grant: Option<GrantId>,
        authorization_plan: PlanId,
        channel_binding: ChannelBindingId,
        proof_ref: ProofRef,
        attachments: Vec<AttachmentDescriptor>,
        extensions: CriticalExtensions,
    ) -> Self {
        Self {
            version: ProtocolVersion::V1,
            profile,
            body_media_type,
            canonical_body_digest,
            permission,
            requested_budget,
            audience,
            challenge,
            validity,
            actor,
            terminal_grant,
            authorization_plan,
            channel_binding,
            proof_ref,
            attachments,
            extensions,
        }
    }

    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }
    #[must_use]
    pub const fn profile(&self) -> &ProfileRef {
        &self.profile
    }
    #[must_use]
    pub const fn body_media_type(&self) -> &MediaType {
        &self.body_media_type
    }
    #[must_use]
    pub const fn canonical_body_digest(&self) -> Digest {
        self.canonical_body_digest
    }
    #[must_use]
    pub const fn permission(&self) -> &Permission {
        &self.permission
    }
    #[must_use]
    pub const fn requested_budget(&self) -> Option<&BudgetCeiling> {
        self.requested_budget.as_ref()
    }
    #[must_use]
    pub const fn audience(&self) -> &Audience {
        &self.audience
    }
    #[must_use]
    pub const fn challenge(&self) -> Challenge {
        self.challenge
    }
    #[must_use]
    pub const fn validity(&self) -> ValidityWindow {
        self.validity
    }
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
    #[must_use]
    pub const fn terminal_grant(&self) -> Option<GrantId> {
        self.terminal_grant
    }
    #[must_use]
    pub const fn authorization_plan(&self) -> PlanId {
        self.authorization_plan
    }
    #[must_use]
    pub const fn channel_binding(&self) -> &ChannelBindingId {
        &self.channel_binding
    }
    #[must_use]
    pub const fn proof_ref(&self) -> ProofRef {
        self.proof_ref
    }
    /// Returns attachment descriptors whose use is covered by this signature.
    #[must_use]
    pub fn attachments(&self) -> &[AttachmentDescriptor] {
        &self.attachments
    }
    #[must_use]
    pub const fn extensions(&self) -> &CriticalExtensions {
        &self.extensions
    }
}

/// Profile-canonical application action supplied explicitly to the pure
/// verifier.
///
/// Profiles construct this value after canonicalizing untrusted application
/// input and deriving its exact permission and optional budget request. The
/// proof kernel treats the body bytes as opaque.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalAction {
    profile: ProfileRef,
    media_type: MediaType,
    body: Vec<u8>,
    permission: Permission,
    requested_budget: Option<BudgetCeiling>,
    detached_attachments: Vec<DetachedAttachment>,
}

impl CanonicalAction {
    /// Constructs a bounded profile-canonical action.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidCanonicalAction`] when `body` is empty or
    /// exceeds [`HARD_MAX_CANONICAL_BODY_BYTES`].
    pub fn new(
        profile: ProfileRef,
        media_type: MediaType,
        body: Vec<u8>,
        permission: Permission,
        requested_budget: Option<BudgetCeiling>,
    ) -> Result<Self, ModelError> {
        if body.is_empty() || body.len() > HARD_MAX_CANONICAL_BODY_BYTES {
            return Err(ModelError::InvalidCanonicalAction);
        }
        Ok(Self {
            profile,
            media_type,
            body,
            permission,
            requested_budget,
            detached_attachments: Vec::new(),
        })
    }

    /// Adds a canonical, duplicate-free detached-attachment input map.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidAttachment`] when the collection exceeds
    /// protocol bounds, contains duplicate identifiers, or the accumulated
    /// detached bytes exceed the bundle byte hard limit.
    pub fn with_detached_attachments(
        mut self,
        mut attachments: Vec<DetachedAttachment>,
    ) -> Result<Self, ModelError> {
        attachments.sort_by_key(DetachedAttachment::digest);
        if attachments.len() > HARD_MAX_ATTACHMENTS
            || attachments
                .windows(2)
                .any(|window| window[0].digest() == window[1].digest())
            || attachments
                .iter()
                .try_fold(0usize, |total, attachment| {
                    total.checked_add(attachment.bytes().len())
                })
                .is_none_or(|total| total > HARD_MAX_BUNDLE_BYTES)
        {
            return Err(ModelError::InvalidAttachment);
        }
        self.detached_attachments = attachments;
        Ok(self)
    }

    /// Returns the exact profile and semantic version.
    #[must_use]
    pub const fn profile(&self) -> &ProfileRef {
        &self.profile
    }

    /// Returns the registered canonical-body media type.
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }

    /// Returns the exact profile-canonical body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the exact permission derived by the application profile.
    #[must_use]
    pub const fn permission(&self) -> &Permission {
        &self.permission
    }

    /// Returns the stateful budget request bound by the action, when present.
    #[must_use]
    pub const fn requested_budget(&self) -> Option<&BudgetCeiling> {
        self.requested_budget.as_ref()
    }

    /// Returns detached bytes in canonical content-identifier order.
    #[must_use]
    pub fn detached_attachments(&self) -> &[DetachedAttachment] {
        &self.detached_attachments
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAction {
    envelope: ActionEnvelope,
    signature: SignatureEnvelope,
}

impl SignedAction {
    #[must_use]
    pub const fn new(envelope: ActionEnvelope, signature: SignatureEnvelope) -> Self {
        Self {
            envelope,
            signature,
        }
    }

    #[must_use]
    pub const fn envelope(&self) -> &ActionEnvelope {
        &self.envelope
    }

    #[must_use]
    pub const fn signature(&self) -> &SignatureEnvelope {
        &self.signature
    }
}

/// Bounded V1 authorization plan whose internal node shape is validated at
/// construction.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuthorizationPlan(AuthorizationPlanNode);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum AuthorizationPlanNode {
    Proof(ProofRef),
    AllOf(Vec<AuthorizationPlan>),
    AnyOf(Vec<AuthorizationPlan>),
    KOfN {
        k: u16,
        members: Vec<AuthorizationPlan>,
    },
}

/// Borrowed view of one validated authorization-plan node.
#[derive(Clone, Copy, Debug)]
pub enum AuthorizationPlanRef<'a> {
    /// One authority branch identified by its signed proof reference.
    Proof(ProofRef),
    /// Every member must authorize the shared action.
    AllOf(&'a [AuthorizationPlan]),
    /// At least one member must authorize the shared action.
    AnyOf(&'a [AuthorizationPlan]),
    /// At least `k` members must authorize the shared action.
    KOfN {
        /// Required number of successful members.
        k: u16,
        /// Canonically encoded child plans.
        members: &'a [AuthorizationPlan],
    },
}

impl AuthorizationPlan {
    /// Constructs a leaf plan for `proof_ref`.
    #[must_use]
    pub const fn proof(proof_ref: ProofRef) -> Self {
        Self(AuthorizationPlanNode::Proof(proof_ref))
    }

    /// Constructs a bounded conjunction.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidPlan`] for an empty member set and
    /// [`ModelError::PlanLimitExceeded`] when the hard plan bounds or unique
    /// leaf invariant would be exceeded.
    pub fn all_of(members: Vec<Self>) -> Result<Self, ModelError> {
        Self::compound(AuthorizationPlanNode::AllOf(members))
    }

    /// Constructs a bounded disjunction.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidPlan`] for an empty member set and
    /// [`ModelError::PlanLimitExceeded`] when the hard plan bounds or unique
    /// leaf invariant would be exceeded.
    pub fn any_of(members: Vec<Self>) -> Result<Self, ModelError> {
        Self::compound(AuthorizationPlanNode::AnyOf(members))
    }

    /// Constructs a bounded threshold plan.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidPlan`] when `k` is zero, exceeds the
    /// member count, or the member set is empty. Returns
    /// [`ModelError::PlanLimitExceeded`] when hard plan bounds or unique leaf
    /// invariants would be exceeded.
    pub fn k_of_n(k: u16, members: Vec<Self>) -> Result<Self, ModelError> {
        Self::compound(AuthorizationPlanNode::KOfN { k, members })
    }

    fn compound(mut node: AuthorizationPlanNode) -> Result<Self, ModelError> {
        match &mut node {
            AuthorizationPlanNode::Proof(_) => {}
            AuthorizationPlanNode::AllOf(members)
            | AuthorizationPlanNode::AnyOf(members)
            | AuthorizationPlanNode::KOfN { members, .. } => members.sort(),
        }
        let plan = Self(node);
        plan.validate(&VerifierLimits::hard())?;
        Ok(plan)
    }

    /// Returns a borrowed view of the plan node.
    #[must_use]
    pub fn as_ref(&self) -> AuthorizationPlanRef<'_> {
        match &self.0 {
            AuthorizationPlanNode::Proof(reference) => AuthorizationPlanRef::Proof(*reference),
            AuthorizationPlanNode::AllOf(members) => AuthorizationPlanRef::AllOf(members),
            AuthorizationPlanNode::AnyOf(members) => AuthorizationPlanRef::AnyOf(members),
            AuthorizationPlanNode::KOfN { k, members } => {
                AuthorizationPlanRef::KOfN { k: *k, members }
            }
        }
    }

    /// Validates the plan shape against deployment limits.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidPlan`] for structurally invalid operators
    /// and [`ModelError::PlanLimitExceeded`] for excessive depth, excessive
    /// leaves, or repeated proof references.
    pub fn validate(&self, limits: &VerifierLimits) -> Result<PlanShape, ModelError> {
        fn walk(
            plan: &AuthorizationPlan,
            depth: usize,
            limits: &VerifierLimits,
            refs: &mut BTreeSet<ProofRef>,
            maximum_depth: &mut usize,
        ) -> Result<(), ModelError> {
            if depth > limits.plan_depth {
                return Err(ModelError::PlanLimitExceeded);
            }
            *maximum_depth = (*maximum_depth).max(depth);
            match &plan.0 {
                AuthorizationPlanNode::Proof(reference) => {
                    if !refs.insert(*reference) || refs.len() > limits.plan_leaves {
                        return Err(ModelError::PlanLimitExceeded);
                    }
                }
                AuthorizationPlanNode::AllOf(members) | AuthorizationPlanNode::AnyOf(members) => {
                    if members.is_empty() {
                        return Err(ModelError::InvalidPlan);
                    }
                    if members.len() > limits.plan_branching {
                        return Err(ModelError::PlanLimitExceeded);
                    }
                    for member in members {
                        walk(member, depth + 1, limits, refs, maximum_depth)?;
                    }
                }
                AuthorizationPlanNode::KOfN { k, members } => {
                    if *k == 0 || usize::from(*k) > members.len() || members.is_empty() {
                        return Err(ModelError::InvalidPlan);
                    }
                    if members.len() > limits.plan_branching {
                        return Err(ModelError::PlanLimitExceeded);
                    }
                    for member in members {
                        walk(member, depth + 1, limits, refs, maximum_depth)?;
                    }
                }
            }
            Ok(())
        }

        let mut refs = BTreeSet::new();
        let mut maximum_depth = 0;
        walk(self, 1, limits, &mut refs, &mut maximum_depth)?;
        Ok(PlanShape {
            leaves: refs.into_iter().collect(),
            maximum_depth,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanShape {
    leaves: Vec<ProofRef>,
    maximum_depth: usize,
}

impl PlanShape {
    #[must_use]
    pub fn leaves(&self) -> &[ProofRef] {
        &self.leaves
    }

    /// Returns the deepest one-indexed plan level.
    #[must_use]
    pub const fn maximum_depth(&self) -> usize {
        self.maximum_depth
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceObject {
    id: EvidenceId,
    evidence_type: EvidenceTypeId,
    media_type: MediaType,
    bytes: Vec<u8>,
}

impl EvidenceObject {
    /// Constructs one bounded, non-empty evidence object.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidEvidence`] when `bytes` is empty or
    /// exceeds [`HARD_MAX_EVIDENCE_BYTES`].
    pub fn new(
        id: EvidenceId,
        evidence_type: EvidenceTypeId,
        media_type: MediaType,
        bytes: Vec<u8>,
    ) -> Result<Self, ModelError> {
        if bytes.is_empty() || bytes.len() > HARD_MAX_EVIDENCE_BYTES {
            return Err(ModelError::InvalidEvidence);
        }
        Ok(Self {
            id,
            evidence_type,
            media_type,
            bytes,
        })
    }

    #[must_use]
    pub const fn id(&self) -> EvidenceId {
        self.id
    }
    #[must_use]
    pub const fn evidence_type(&self) -> &EvidenceTypeId {
        &self.evidence_type
    }
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum StatementRef {
    Grant(GrantId),
    Action(ActionId),
    PrincipalStatus(PrincipalStatusId),
    GrantStatus(GrantStatusId),
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ControlBinding {
    statement: StatementRef,
    evidence: Vec<EvidenceId>,
}

impl ControlBinding {
    /// Constructs a canonical statement-to-evidence binding.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidEvidenceBinding`] when `evidence` is
    /// empty, exceeds [`HARD_MAX_BINDING_EVIDENCE`], or contains duplicates.
    pub fn new(statement: StatementRef, mut evidence: Vec<EvidenceId>) -> Result<Self, ModelError> {
        if evidence.is_empty() || evidence.len() > HARD_MAX_BINDING_EVIDENCE {
            return Err(ModelError::InvalidEvidenceBinding);
        }
        evidence.sort();
        if evidence.windows(2).any(|window| window[0] == window[1]) {
            return Err(ModelError::InvalidEvidenceBinding);
        }
        Ok(Self {
            statement,
            evidence,
        })
    }

    #[must_use]
    pub const fn statement(&self) -> StatementRef {
        self.statement
    }
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceId] {
        &self.evidence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalState {
    Active,
    Revoked,
    Superseded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantState {
    Active,
    Revoked,
    Superseded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalStatusStatement {
    version: ProtocolVersion,
    method: StatusMethodId,
    principal: PrincipalId,
    purpose: PurposeId,
    state: PrincipalState,
    sequence: u64,
    observed_at: Timestamp,
    valid_until: Timestamp,
    issuer: PrincipalId,
    extensions: CriticalExtensions,
}

impl PrincipalStatusStatement {
    #[allow(clippy::too_many_arguments)]
    /// Constructs a principal-status statement.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidStatus`] when `observed_at` is later than
    /// `valid_until`.
    pub fn new(
        method: StatusMethodId,
        principal: PrincipalId,
        purpose: PurposeId,
        state: PrincipalState,
        sequence: u64,
        observed_at: Timestamp,
        valid_until: Timestamp,
        issuer: PrincipalId,
        extensions: CriticalExtensions,
    ) -> Result<Self, ModelError> {
        if observed_at > valid_until {
            return Err(ModelError::InvalidStatus);
        }
        Ok(Self {
            version: ProtocolVersion::V1,
            method,
            principal,
            purpose,
            state,
            sequence,
            observed_at,
            valid_until,
            issuer,
            extensions,
        })
    }

    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }
    /// Returns the exact registered status method.
    #[must_use]
    pub const fn method(&self) -> &StatusMethodId {
        &self.method
    }
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }
    #[must_use]
    pub const fn purpose(&self) -> &PurposeId {
        &self.purpose
    }
    #[must_use]
    pub const fn state(&self) -> PrincipalState {
        self.state
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }
    #[must_use]
    pub const fn valid_until(&self) -> Timestamp {
        self.valid_until
    }
    #[must_use]
    pub const fn issuer(&self) -> &PrincipalId {
        &self.issuer
    }
    #[must_use]
    pub const fn extensions(&self) -> &CriticalExtensions {
        &self.extensions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPrincipalStatus {
    statement: PrincipalStatusStatement,
    signature: SignatureEnvelope,
}

impl SignedPrincipalStatus {
    #[must_use]
    pub const fn new(statement: PrincipalStatusStatement, signature: SignatureEnvelope) -> Self {
        Self {
            statement,
            signature,
        }
    }
    #[must_use]
    pub const fn statement(&self) -> &PrincipalStatusStatement {
        &self.statement
    }
    #[must_use]
    pub const fn signature(&self) -> &SignatureEnvelope {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantStatusStatement {
    version: ProtocolVersion,
    method: StatusMethodId,
    grant_id: GrantId,
    state: GrantState,
    sequence: u64,
    observed_at: Timestamp,
    valid_until: Timestamp,
    issuer: PrincipalId,
    extensions: CriticalExtensions,
}

impl GrantStatusStatement {
    #[allow(clippy::too_many_arguments)]
    /// Constructs a grant-status statement.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidStatus`] when `observed_at` is later than
    /// `valid_until`.
    pub fn new(
        method: StatusMethodId,
        grant_id: GrantId,
        state: GrantState,
        sequence: u64,
        observed_at: Timestamp,
        valid_until: Timestamp,
        issuer: PrincipalId,
        extensions: CriticalExtensions,
    ) -> Result<Self, ModelError> {
        if observed_at > valid_until {
            return Err(ModelError::InvalidStatus);
        }
        Ok(Self {
            version: ProtocolVersion::V1,
            method,
            grant_id,
            state,
            sequence,
            observed_at,
            valid_until,
            issuer,
            extensions,
        })
    }

    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }
    /// Returns the exact registered status method.
    #[must_use]
    pub const fn method(&self) -> &StatusMethodId {
        &self.method
    }
    #[must_use]
    pub const fn grant_id(&self) -> GrantId {
        self.grant_id
    }
    #[must_use]
    pub const fn state(&self) -> GrantState {
        self.state
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }
    #[must_use]
    pub const fn valid_until(&self) -> Timestamp {
        self.valid_until
    }
    #[must_use]
    pub const fn issuer(&self) -> &PrincipalId {
        &self.issuer
    }
    #[must_use]
    pub const fn extensions(&self) -> &CriticalExtensions {
        &self.extensions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedGrantStatus {
    statement: GrantStatusStatement,
    signature: SignatureEnvelope,
}

impl SignedGrantStatus {
    #[must_use]
    pub const fn new(statement: GrantStatusStatement, signature: SignatureEnvelope) -> Self {
        Self {
            statement,
            signature,
        }
    }
    #[must_use]
    pub const fn statement(&self) -> &GrantStatusStatement {
        &self.statement
    }
    #[must_use]
    pub const fn signature(&self) -> &SignatureEnvelope {
        &self.signature
    }
}

/// Context-pinned authorization for one status issuer and exact method.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct StatusTrustRule {
    method: StatusMethodId,
    issuer: PrincipalId,
    sequence_floor: u64,
}

impl StatusTrustRule {
    /// Constructs a status trust rule.
    #[must_use]
    pub const fn new(method: StatusMethodId, issuer: PrincipalId, sequence_floor: u64) -> Self {
        Self {
            method,
            issuer,
            sequence_floor,
        }
    }

    /// Returns the exact status method.
    #[must_use]
    pub const fn method(&self) -> &StatusMethodId {
        &self.method
    }

    /// Returns the only issuer trusted by this rule.
    #[must_use]
    pub const fn issuer(&self) -> &PrincipalId {
        &self.issuer
    }

    /// Returns the minimum accepted sequence.
    #[must_use]
    pub const fn sequence_floor(&self) -> u64 {
        self.sequence_floor
    }
}

/// Immutable verifier-supplied snapshot of principal lifecycle facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalStatusSnapshot {
    id: StatusSnapshotId,
    observed_at: Timestamp,
    valid_until: Timestamp,
    statements: Vec<SignedPrincipalStatus>,
    checkpoints: Vec<EvidenceId>,
    trust: Vec<StatusTrustRule>,
}

impl PrincipalStatusSnapshot {
    /// Constructs a canonical principal-status snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidStatusSnapshot`] when the snapshot window
    /// is inverted, exceeds protocol collection bounds, contains more than one
    /// statement for a principal/purpose pair, or includes a statement that
    /// does not cover the snapshot's complete validity window.
    pub fn new(
        id: StatusSnapshotId,
        observed_at: Timestamp,
        valid_until: Timestamp,
        statements: Vec<SignedPrincipalStatus>,
        checkpoints: Vec<EvidenceId>,
    ) -> Result<Self, ModelError> {
        Self::with_trust(
            id,
            observed_at,
            valid_until,
            statements,
            checkpoints,
            Vec::new(),
        )
    }

    /// Constructs a canonical snapshot with explicit trusted issuer rules.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidStatusSnapshot`] for invalid windows,
    /// duplicate subjects, duplicate trust rules, or excessive collections.
    pub fn with_trust(
        id: StatusSnapshotId,
        observed_at: Timestamp,
        valid_until: Timestamp,
        mut statements: Vec<SignedPrincipalStatus>,
        mut checkpoints: Vec<EvidenceId>,
        mut trust: Vec<StatusTrustRule>,
    ) -> Result<Self, ModelError> {
        if observed_at > valid_until
            || statements.len() > HARD_MAX_PRINCIPAL_STATUS
            || checkpoints.len() > HARD_MAX_EVIDENCE
            || trust.len() > HARD_MAX_REGISTRY_ENTRIES
        {
            return Err(ModelError::InvalidStatusSnapshot);
        }
        statements.sort_by(|left, right| {
            left.statement()
                .principal()
                .cmp(right.statement().principal())
                .then_with(|| left.statement().purpose().cmp(right.statement().purpose()))
                .then_with(|| left.statement().method().cmp(right.statement().method()))
                .then_with(|| {
                    left.statement()
                        .sequence()
                        .cmp(&right.statement().sequence())
                })
                .then_with(|| left.statement().issuer().cmp(right.statement().issuer()))
        });
        if statements
            .windows(2)
            .any(|window| window[0].statement() == window[1].statement())
            || statements.iter().any(|signed| {
                signed.statement().observed_at() > observed_at
                    || signed.statement().valid_until() < valid_until
            })
        {
            return Err(ModelError::InvalidStatusSnapshot);
        }
        checkpoints.sort();
        checkpoints.dedup();
        trust.sort();
        if trust.windows(2).any(|window| {
            window[0].method() == window[1].method() && window[0].issuer() == window[1].issuer()
        }) {
            return Err(ModelError::InvalidStatusSnapshot);
        }
        Ok(Self {
            id,
            observed_at,
            valid_until,
            statements,
            checkpoints,
            trust,
        })
    }

    /// Returns the content identifier supplied for receipt and cache binding.
    #[must_use]
    pub const fn id(&self) -> StatusSnapshotId {
        self.id
    }

    /// Returns the observation time.
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Returns the latest evaluation time covered by the snapshot.
    #[must_use]
    pub const fn valid_until(&self) -> Timestamp {
        self.valid_until
    }

    /// Returns canonical principal-status statements.
    #[must_use]
    pub fn statements(&self) -> &[SignedPrincipalStatus] {
        &self.statements
    }

    /// Returns canonical checkpoint evidence identifiers.
    #[must_use]
    pub fn checkpoints(&self) -> &[EvidenceId] {
        &self.checkpoints
    }

    /// Returns context-pinned status issuer and sequence rules.
    #[must_use]
    pub fn trust(&self) -> &[StatusTrustRule] {
        &self.trust
    }
}

/// Immutable verifier-supplied snapshot of grant lifecycle facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantStatusSnapshot {
    id: StatusSnapshotId,
    observed_at: Timestamp,
    valid_until: Timestamp,
    statements: Vec<SignedGrantStatus>,
    checkpoints: Vec<EvidenceId>,
    trust: Vec<StatusTrustRule>,
}

impl GrantStatusSnapshot {
    /// Constructs a canonical grant-status snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidStatusSnapshot`] when the snapshot window
    /// is inverted, exceeds protocol collection bounds, contains more than one
    /// statement for a grant, or includes a statement that does not cover the
    /// snapshot's complete validity window.
    pub fn new(
        id: StatusSnapshotId,
        observed_at: Timestamp,
        valid_until: Timestamp,
        statements: Vec<SignedGrantStatus>,
        checkpoints: Vec<EvidenceId>,
    ) -> Result<Self, ModelError> {
        Self::with_trust(
            id,
            observed_at,
            valid_until,
            statements,
            checkpoints,
            Vec::new(),
        )
    }

    /// Constructs a canonical snapshot with explicit trusted issuer rules.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidStatusSnapshot`] for invalid windows,
    /// duplicate subjects, duplicate trust rules, or excessive collections.
    pub fn with_trust(
        id: StatusSnapshotId,
        observed_at: Timestamp,
        valid_until: Timestamp,
        mut statements: Vec<SignedGrantStatus>,
        mut checkpoints: Vec<EvidenceId>,
        mut trust: Vec<StatusTrustRule>,
    ) -> Result<Self, ModelError> {
        if observed_at > valid_until
            || statements.len() > HARD_MAX_GRANT_STATUS
            || checkpoints.len() > HARD_MAX_EVIDENCE
            || trust.len() > HARD_MAX_REGISTRY_ENTRIES
        {
            return Err(ModelError::InvalidStatusSnapshot);
        }
        statements.sort_by(|left, right| {
            left.statement()
                .grant_id()
                .cmp(&right.statement().grant_id())
                .then_with(|| left.statement().method().cmp(right.statement().method()))
                .then_with(|| {
                    left.statement()
                        .sequence()
                        .cmp(&right.statement().sequence())
                })
                .then_with(|| left.statement().issuer().cmp(right.statement().issuer()))
        });
        if statements
            .windows(2)
            .any(|window| window[0].statement() == window[1].statement())
            || statements.iter().any(|signed| {
                signed.statement().observed_at() > observed_at
                    || signed.statement().valid_until() < valid_until
            })
        {
            return Err(ModelError::InvalidStatusSnapshot);
        }
        checkpoints.sort();
        checkpoints.dedup();
        trust.sort();
        if trust.windows(2).any(|window| {
            window[0].method() == window[1].method() && window[0].issuer() == window[1].issuer()
        }) {
            return Err(ModelError::InvalidStatusSnapshot);
        }
        Ok(Self {
            id,
            observed_at,
            valid_until,
            statements,
            checkpoints,
            trust,
        })
    }

    /// Returns the content identifier supplied for receipt and cache binding.
    #[must_use]
    pub const fn id(&self) -> StatusSnapshotId {
        self.id
    }

    /// Returns the observation time.
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Returns the latest evaluation time covered by the snapshot.
    #[must_use]
    pub const fn valid_until(&self) -> Timestamp {
        self.valid_until
    }

    /// Returns canonical grant-status statements.
    #[must_use]
    pub fn statements(&self) -> &[SignedGrantStatus] {
        &self.statements
    }

    /// Returns canonical checkpoint evidence identifiers.
    #[must_use]
    pub fn checkpoints(&self) -> &[EvidenceId] {
        &self.checkpoints
    }

    /// Returns context-pinned status issuer and sequence rules.
    #[must_use]
    pub fn trust(&self) -> &[StatusTrustRule] {
        &self.trust
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AttachmentDescriptor {
    digest: AttachmentDigest,
    media_type: MediaType,
    byte_length: u64,
    disposition: DispositionId,
    encrypted: bool,
    required: bool,
    opaque_allowed: bool,
}

impl AttachmentDescriptor {
    #[must_use]
    pub const fn new(
        digest: AttachmentDigest,
        media_type: MediaType,
        byte_length: u64,
        disposition: DispositionId,
        encrypted: bool,
        required: bool,
        opaque_allowed: bool,
    ) -> Self {
        Self {
            digest,
            media_type,
            byte_length,
            disposition,
            encrypted,
            required,
            opaque_allowed,
        }
    }
    #[must_use]
    pub const fn digest(&self) -> AttachmentDigest {
        self.digest
    }
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
    #[must_use]
    pub const fn disposition(&self) -> &DispositionId {
        &self.disposition
    }
    #[must_use]
    pub const fn encrypted(&self) -> bool {
        self.encrypted
    }
    /// Reports whether missing detached bytes are an authorization failure.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
    /// Reports whether encrypted content may remain semantically opaque.
    #[must_use]
    pub const fn opaque_allowed(&self) -> bool {
        self.opaque_allowed
    }
}

/// One bounded detached attachment supplied as part of the verifier input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetachedAttachment {
    digest: AttachmentDigest,
    bytes: Vec<u8>,
}

impl DetachedAttachment {
    /// Constructs detached bytes under their content-addressed identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidAttachment`] when bytes are empty or
    /// exceed the hard bundle byte limit.
    pub fn new(digest: AttachmentDigest, bytes: Vec<u8>) -> Result<Self, ModelError> {
        if bytes.is_empty() || bytes.len() > HARD_MAX_BUNDLE_BYTES {
            return Err(ModelError::InvalidAttachment);
        }
        Ok(Self { digest, bytes })
    }

    /// Returns the content-addressed identifier.
    #[must_use]
    pub const fn digest(&self) -> AttachmentDigest {
        self.digest
    }

    /// Returns the exact detached bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Target V1 proof-bundle header.
pub struct BundleHeader {
    version: ProtocolVersion,
    flags: u64,
}

impl BundleHeader {
    /// Constructs a V1 bundle header.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidBundleHeader`] when any unregistered flag
    /// bit is set. V1 currently registers no flag bits.
    pub const fn new(version: ProtocolVersion, flags: u64) -> Result<Self, ModelError> {
        if flags != 0 {
            return Err(ModelError::InvalidBundleHeader);
        }
        Ok(Self { version, flags })
    }

    /// Returns the target V1 header with no flags.
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            version: ProtocolVersion::V1,
            flags: 0,
        }
    }

    /// Returns the protocol major.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the registered flag bits.
    #[must_use]
    pub const fn flags(&self) -> u64 {
        self.flags
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofBundle {
    header: BundleHeader,
    grants: Vec<SignedGrant>,
    actions: Vec<SignedAction>,
    plan: AuthorizationPlan,
    evidence: Vec<EvidenceObject>,
    bindings: Vec<ControlBinding>,
    principal_status: Vec<SignedPrincipalStatus>,
    grant_status: Vec<SignedGrantStatus>,
    attachments: Vec<AttachmentDescriptor>,
    canonical_body: Option<Vec<u8>>,
}

impl ProofBundle {
    #[allow(clippy::too_many_arguments)]
    /// Constructs a target V1 proof bundle and validates hard collection
    /// limits and authorization-plan shape.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::CollectionLimitExceeded`] when any collection or
    /// inline body exceeds its hard protocol maximum. Plan errors from
    /// [`AuthorizationPlan::validate`] are propagated unchanged.
    pub fn new(
        header: BundleHeader,
        grants: Vec<SignedGrant>,
        mut actions: Vec<SignedAction>,
        plan: AuthorizationPlan,
        mut evidence: Vec<EvidenceObject>,
        mut bindings: Vec<ControlBinding>,
        principal_status: Vec<SignedPrincipalStatus>,
        grant_status: Vec<SignedGrantStatus>,
        mut attachments: Vec<AttachmentDescriptor>,
        canonical_body: Option<Vec<u8>>,
    ) -> Result<Self, ModelError> {
        let signature_count = grants
            .len()
            .checked_add(actions.len())
            .and_then(|count| count.checked_add(principal_status.len()))
            .and_then(|count| count.checked_add(grant_status.len()))
            .ok_or(ModelError::CollectionLimitExceeded)?;
        if grants.len() > HARD_MAX_GRANTS
            || actions.is_empty()
            || actions.len() > HARD_MAX_ACTIONS
            || evidence.len() > HARD_MAX_EVIDENCE
            || bindings.len() > HARD_MAX_BINDINGS
            || principal_status.len() > HARD_MAX_PRINCIPAL_STATUS
            || grant_status.len() > HARD_MAX_GRANT_STATUS
            || attachments.len() > HARD_MAX_ATTACHMENTS
            || signature_count > HARD_MAX_SIGNATURES
            || canonical_body
                .as_ref()
                .is_some_and(|body| body.len() > HARD_MAX_CANONICAL_BODY_BYTES)
        {
            return Err(ModelError::CollectionLimitExceeded);
        }
        actions.sort_by_key(|action| action.envelope().proof_ref());
        evidence.sort_by_key(EvidenceObject::id);
        bindings.sort();
        attachments.sort_by_key(AttachmentDescriptor::digest);
        plan.validate(&VerifierLimits::hard())?;
        Ok(Self {
            header,
            grants,
            actions,
            plan,
            evidence,
            bindings,
            principal_status,
            grant_status,
            attachments,
            canonical_body,
        })
    }

    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.header.version()
    }
    #[must_use]
    pub const fn header(&self) -> &BundleHeader {
        &self.header
    }
    #[must_use]
    pub fn grants(&self) -> &[SignedGrant] {
        &self.grants
    }
    #[must_use]
    pub fn actions(&self) -> &[SignedAction] {
        &self.actions
    }
    #[must_use]
    pub const fn plan(&self) -> &AuthorizationPlan {
        &self.plan
    }
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceObject] {
        &self.evidence
    }
    #[must_use]
    pub fn bindings(&self) -> &[ControlBinding] {
        &self.bindings
    }
    #[must_use]
    pub fn principal_status(&self) -> &[SignedPrincipalStatus] {
        &self.principal_status
    }
    #[must_use]
    pub fn grant_status(&self) -> &[SignedGrantStatus] {
        &self.grant_status
    }
    #[must_use]
    pub fn attachments(&self) -> &[AttachmentDescriptor] {
        &self.attachments
    }
    #[must_use]
    pub fn canonical_body(&self) -> Option<&[u8]> {
        self.canonical_body.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ParticipantRole {
    Root,
    Intermediate,
    Actor,
    ExternalIssuer,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AssuranceClaim {
    kind: AssuranceClaimId,
    parameters: Vec<(ClaimParameterId, ClaimParameterId)>,
    observed_at: Option<Timestamp>,
    source: EvidenceSourceId,
}

impl AssuranceClaim {
    /// Constructs a canonical parameterized assurance claim.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidAssurance`] when the parameter count
    /// exceeds [`HARD_MAX_EXTENSIONS`] or a parameter key occurs more than
    /// once.
    pub fn new(
        kind: AssuranceClaimId,
        mut parameters: Vec<(ClaimParameterId, ClaimParameterId)>,
        observed_at: Option<Timestamp>,
        source: EvidenceSourceId,
    ) -> Result<Self, ModelError> {
        if parameters.len() > HARD_MAX_EXTENSIONS {
            return Err(ModelError::InvalidAssurance);
        }
        parameters.sort();
        if parameters
            .windows(2)
            .any(|window| window[0].0 == window[1].0)
        {
            return Err(ModelError::InvalidAssurance);
        }
        Ok(Self {
            kind,
            parameters,
            observed_at,
            source,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> &AssuranceClaimId {
        &self.kind
    }
    #[must_use]
    pub fn parameters(&self) -> &[(ClaimParameterId, ClaimParameterId)] {
        &self.parameters
    }
    #[must_use]
    pub const fn observed_at(&self) -> Option<Timestamp> {
        self.observed_at
    }
    #[must_use]
    pub const fn source(&self) -> &EvidenceSourceId {
        &self.source
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantAssurance {
    principal: PrincipalId,
    role: ParticipantRole,
    claims: Vec<AssuranceClaim>,
    evidence: Vec<EvidenceId>,
    adapter: AdapterId,
    adapter_version: u16,
}

impl ParticipantAssurance {
    /// Constructs assurance evidence for one principal in one chain role.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidAssurance`] when the canonical claim or
    /// evidence collection exceeds [`HARD_MAX_EVIDENCE`].
    pub fn new(
        principal: PrincipalId,
        role: ParticipantRole,
        mut claims: Vec<AssuranceClaim>,
        mut evidence: Vec<EvidenceId>,
        adapter: AdapterId,
        adapter_version: u16,
    ) -> Result<Self, ModelError> {
        claims.sort();
        claims.dedup();
        evidence.sort();
        evidence.dedup();
        if claims.len() > HARD_MAX_EVIDENCE || evidence.len() > HARD_MAX_EVIDENCE {
            return Err(ModelError::InvalidAssurance);
        }
        Ok(Self {
            principal,
            role,
            claims,
            evidence,
            adapter,
            adapter_version,
        })
    }

    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }
    #[must_use]
    pub const fn role(&self) -> ParticipantRole {
        self.role
    }
    #[must_use]
    pub fn claims(&self) -> &[AssuranceClaim] {
        &self.claims
    }
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceId] {
        &self.evidence
    }
    #[must_use]
    pub const fn adapter(&self) -> &AdapterId {
        &self.adapter
    }
    #[must_use]
    pub const fn adapter_version(&self) -> u16 {
        self.adapter_version
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AssuranceRequirement {
    role: ParticipantRole,
    claim_kind: AssuranceClaimId,
    parameters: Vec<(ClaimParameterId, ClaimParameterId)>,
    source: Option<EvidenceSourceId>,
    adapter: Option<AdapterId>,
    adapter_version: Option<u16>,
    maximum_age: Option<FreshnessLimit>,
}

impl AssuranceRequirement {
    #[must_use]
    pub const fn new(
        role: ParticipantRole,
        claim_kind: AssuranceClaimId,
        maximum_age: Option<FreshnessLimit>,
    ) -> Self {
        Self {
            role,
            claim_kind,
            parameters: Vec::new(),
            source: None,
            adapter: None,
            adapter_version: None,
            maximum_age,
        }
    }

    /// Constructs an exact typed assurance constraint.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidAssurance`] for duplicate parameters, an
    /// excessive parameter collection, zero adapter versions, or a version
    /// constraint without an exact adapter identifier.
    #[allow(clippy::too_many_arguments)]
    pub fn constrained(
        role: ParticipantRole,
        claim_kind: AssuranceClaimId,
        mut parameters: Vec<(ClaimParameterId, ClaimParameterId)>,
        source: Option<EvidenceSourceId>,
        adapter: Option<AdapterId>,
        adapter_version: Option<u16>,
        maximum_age: Option<FreshnessLimit>,
    ) -> Result<Self, ModelError> {
        parameters.sort();
        if parameters.len() > HARD_MAX_EXTENSIONS
            || parameters
                .windows(2)
                .any(|window| window[0].0 == window[1].0)
            || adapter_version == Some(0)
            || (adapter_version.is_some() && adapter.is_none())
        {
            return Err(ModelError::InvalidAssurance);
        }
        Ok(Self {
            role,
            claim_kind,
            parameters,
            source,
            adapter,
            adapter_version,
            maximum_age,
        })
    }
    #[must_use]
    pub const fn role(&self) -> ParticipantRole {
        self.role
    }
    #[must_use]
    pub const fn claim_kind(&self) -> &AssuranceClaimId {
        &self.claim_kind
    }
    /// Returns exact required claim parameters.
    #[must_use]
    pub fn parameters(&self) -> &[(ClaimParameterId, ClaimParameterId)] {
        &self.parameters
    }
    /// Returns the required evidence source, when constrained.
    #[must_use]
    pub const fn source(&self) -> Option<&EvidenceSourceId> {
        self.source.as_ref()
    }
    /// Returns the required adapter identifier, when constrained.
    #[must_use]
    pub const fn adapter(&self) -> Option<&AdapterId> {
        self.adapter.as_ref()
    }
    /// Returns the required adapter version, when constrained.
    #[must_use]
    pub const fn adapter_version(&self) -> Option<u16> {
        self.adapter_version
    }
    #[must_use]
    pub const fn maximum_age(&self) -> Option<FreshnessLimit> {
        self.maximum_age
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssurancePolicy {
    id: AssurancePolicyId,
    requirements: Vec<AssuranceRequirement>,
}

impl AssurancePolicy {
    /// Constructs a bounded role-indexed assurance policy.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidAssurance`] when the requirement count
    /// exceeds [`HARD_MAX_EVIDENCE`].
    pub fn new(
        id: AssurancePolicyId,
        mut requirements: Vec<AssuranceRequirement>,
    ) -> Result<Self, ModelError> {
        if requirements.len() > HARD_MAX_EVIDENCE {
            return Err(ModelError::InvalidAssurance);
        }
        requirements.sort();
        requirements.dedup();
        Ok(Self { id, requirements })
    }
    #[must_use]
    pub const fn id(&self) -> &AssurancePolicyId {
        &self.id
    }
    #[must_use]
    pub fn requirements(&self) -> &[AssuranceRequirement] {
        &self.requirements
    }
}

/// Canonical evidence explaining how one assurance requirement was satisfied.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AssuranceSatisfaction {
    requirement_index: u16,
    principal: PrincipalId,
    claim: AssuranceClaim,
    evidence: Vec<EvidenceId>,
}

impl AssuranceSatisfaction {
    /// Constructs one canonical assurance satisfaction record.
    #[must_use]
    pub const fn new(
        requirement_index: u16,
        principal: PrincipalId,
        claim: AssuranceClaim,
        evidence: Vec<EvidenceId>,
    ) -> Self {
        Self {
            requirement_index,
            principal,
            claim,
            evidence,
        }
    }

    /// Returns the canonical policy requirement index.
    #[must_use]
    pub const fn requirement_index(&self) -> u16 {
        self.requirement_index
    }

    /// Returns the evidence subject.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the exact claim selected for this requirement.
    #[must_use]
    pub const fn claim(&self) -> &AssuranceClaim {
        &self.claim
    }

    /// Returns exact evidence objects supporting the selected claim.
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceId] {
        &self.evidence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustAnchor {
    id: TrustAnchorId,
    principal: PrincipalId,
    accepted_methods: Vec<PrincipalMethodId>,
    profiles: Vec<ProfileRef>,
    permissions: PermissionSet,
    resource_namespaces: Vec<ResourceId>,
    audiences: AudienceSet,
    validity: ValidityWindow,
    budget_ceiling: Option<BudgetCeiling>,
    max_delegation_depth: u16,
    assurance_policy: AssurancePolicyId,
    status_policy: StatusPolicy,
}

impl TrustAnchor {
    #[allow(clippy::too_many_arguments)]
    /// Constructs an authority-scoped local trust anchor.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidTrustAnchor`] when no control method or no
    /// application profile is accepted.
    pub fn new(
        id: TrustAnchorId,
        principal: PrincipalId,
        mut accepted_methods: Vec<PrincipalMethodId>,
        mut profiles: Vec<ProfileRef>,
        permissions: PermissionSet,
        mut resource_namespaces: Vec<ResourceId>,
        audiences: AudienceSet,
        validity: ValidityWindow,
        budget_ceiling: Option<BudgetCeiling>,
        max_delegation_depth: u16,
        assurance_policy: AssurancePolicyId,
        status_policy: StatusPolicy,
    ) -> Result<Self, ModelError> {
        accepted_methods.sort();
        accepted_methods.dedup();
        profiles.sort();
        profiles.dedup();
        resource_namespaces.sort();
        resource_namespaces.dedup();
        if accepted_methods.is_empty()
            || accepted_methods.len() > HARD_MAX_REGISTRY_ENTRIES
            || profiles.is_empty()
            || profiles.len() > HARD_MAX_REGISTRY_ENTRIES
            || resource_namespaces.len() > HARD_MAX_PERMISSIONS
        {
            return Err(ModelError::InvalidTrustAnchor);
        }
        Ok(Self {
            id,
            principal,
            accepted_methods,
            profiles,
            permissions,
            resource_namespaces,
            audiences,
            validity,
            budget_ceiling,
            max_delegation_depth,
            assurance_policy,
            status_policy,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &TrustAnchorId {
        &self.id
    }
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }
    #[must_use]
    pub fn accepted_methods(&self) -> &[PrincipalMethodId] {
        &self.accepted_methods
    }
    #[must_use]
    pub fn profiles(&self) -> &[ProfileRef] {
        &self.profiles
    }
    #[must_use]
    pub const fn permissions(&self) -> &PermissionSet {
        &self.permissions
    }
    #[must_use]
    pub fn resource_namespaces(&self) -> &[ResourceId] {
        &self.resource_namespaces
    }
    #[must_use]
    pub const fn audiences(&self) -> &AudienceSet {
        &self.audiences
    }
    #[must_use]
    pub const fn validity(&self) -> ValidityWindow {
        self.validity
    }
    /// Returns the maximum stateful budget this root can delegate.
    #[must_use]
    pub const fn budget_ceiling(&self) -> Option<&BudgetCeiling> {
        self.budget_ceiling.as_ref()
    }
    #[must_use]
    pub const fn max_delegation_depth(&self) -> u16 {
        self.max_delegation_depth
    }
    #[must_use]
    pub const fn assurance_policy(&self) -> &AssurancePolicyId {
        &self.assurance_policy
    }
    #[must_use]
    pub const fn status_policy(&self) -> &StatusPolicy {
        &self.status_policy
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierLimits {
    bundle_bytes: usize,
    grants: usize,
    actions: usize,
    plan_leaves: usize,
    plan_depth: usize,
    plan_branching: usize,
    evidence: usize,
    evidence_bytes: usize,
    bindings: usize,
    principal_status: usize,
    grant_status: usize,
    attachments: usize,
    signatures: usize,
    signature_bytes: usize,
    permissions: usize,
    audiences: usize,
    extensions: usize,
    extension_bytes: usize,
    body_digests: usize,
    binding_evidence: usize,
    canonical_body_bytes: usize,
    registry_entries: usize,
    trust_anchors: usize,
    work_units: u64,
}

/// Configurable count or byte limit in [`VerifierLimits`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitKind {
    BundleBytes,
    Grants,
    Actions,
    PlanLeaves,
    PlanDepth,
    PlanBranching,
    EvidenceObjects,
    EvidenceBytes,
    ControlBindings,
    PrincipalStatusStatements,
    GrantStatusStatements,
    Attachments,
    Signatures,
    SignatureBytes,
    Permissions,
    Audiences,
    CriticalExtensions,
    CriticalExtensionBytes,
    AllowedBodyDigests,
    BindingEvidence,
    CanonicalBodyBytes,
    RegistryEntries,
    TrustAnchors,
}

impl VerifierLimits {
    #[must_use]
    pub const fn default_deployment() -> Self {
        Self {
            bundle_bytes: DEFAULT_MAX_BUNDLE_BYTES,
            grants: DEFAULT_MAX_GRANTS,
            actions: DEFAULT_MAX_ACTIONS,
            plan_leaves: DEFAULT_MAX_PLAN_LEAVES,
            plan_depth: DEFAULT_MAX_PLAN_DEPTH,
            plan_branching: DEFAULT_MAX_PLAN_BRANCHING,
            evidence: DEFAULT_MAX_EVIDENCE,
            evidence_bytes: DEFAULT_MAX_EVIDENCE_BYTES,
            bindings: DEFAULT_MAX_BINDINGS,
            principal_status: DEFAULT_MAX_PRINCIPAL_STATUS,
            grant_status: DEFAULT_MAX_GRANT_STATUS,
            attachments: DEFAULT_MAX_ATTACHMENTS,
            signatures: DEFAULT_MAX_SIGNATURES,
            signature_bytes: DEFAULT_MAX_SIGNATURE_BYTES,
            permissions: DEFAULT_MAX_PERMISSIONS,
            audiences: DEFAULT_MAX_AUDIENCES,
            extensions: DEFAULT_MAX_EXTENSIONS,
            extension_bytes: DEFAULT_MAX_EXTENSION_BYTES,
            body_digests: DEFAULT_MAX_BODY_DIGESTS,
            binding_evidence: DEFAULT_MAX_BINDING_EVIDENCE,
            canonical_body_bytes: DEFAULT_MAX_CANONICAL_BODY_BYTES,
            registry_entries: DEFAULT_MAX_REGISTRY_ENTRIES,
            trust_anchors: DEFAULT_MAX_TRUST_ANCHORS,
            work_units: DEFAULT_MAX_WORK_UNITS,
        }
    }

    #[must_use]
    pub const fn hard() -> Self {
        Self {
            bundle_bytes: HARD_MAX_BUNDLE_BYTES,
            grants: HARD_MAX_GRANTS,
            actions: HARD_MAX_ACTIONS,
            plan_leaves: HARD_MAX_PLAN_LEAVES,
            plan_depth: HARD_MAX_PLAN_DEPTH,
            plan_branching: HARD_MAX_PLAN_BRANCHING,
            evidence: HARD_MAX_EVIDENCE,
            evidence_bytes: HARD_MAX_EVIDENCE_BYTES,
            bindings: HARD_MAX_BINDINGS,
            principal_status: HARD_MAX_PRINCIPAL_STATUS,
            grant_status: HARD_MAX_GRANT_STATUS,
            attachments: HARD_MAX_ATTACHMENTS,
            signatures: HARD_MAX_SIGNATURES,
            signature_bytes: HARD_MAX_SIGNATURE_BYTES,
            permissions: HARD_MAX_PERMISSIONS,
            audiences: HARD_MAX_AUDIENCES,
            extensions: HARD_MAX_EXTENSIONS,
            extension_bytes: HARD_MAX_EXTENSION_BYTES,
            body_digests: HARD_MAX_BODY_DIGESTS,
            binding_evidence: HARD_MAX_BINDING_EVIDENCE,
            canonical_body_bytes: HARD_MAX_CANONICAL_BODY_BYTES,
            registry_entries: HARD_MAX_REGISTRY_ENTRIES,
            trust_anchors: HARD_MAX_TRUST_ANCHORS,
            work_units: HARD_MAX_WORK_UNITS,
        }
    }

    /// Lowers one deployment limit while preserving protocol hard maxima.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::CollectionLimitExceeded`] when `value` exceeds
    /// the hard maximum for `kind`.
    pub fn with_limit(mut self, kind: LimitKind, value: usize) -> Result<Self, ModelError> {
        match kind {
            LimitKind::BundleBytes => self.bundle_bytes = value,
            LimitKind::Grants => self.grants = value,
            LimitKind::Actions => self.actions = value,
            LimitKind::PlanLeaves => self.plan_leaves = value,
            LimitKind::PlanDepth => self.plan_depth = value,
            LimitKind::PlanBranching => self.plan_branching = value,
            LimitKind::EvidenceObjects => self.evidence = value,
            LimitKind::EvidenceBytes => self.evidence_bytes = value,
            LimitKind::ControlBindings => self.bindings = value,
            LimitKind::PrincipalStatusStatements => self.principal_status = value,
            LimitKind::GrantStatusStatements => self.grant_status = value,
            LimitKind::Attachments => self.attachments = value,
            LimitKind::Signatures => self.signatures = value,
            LimitKind::SignatureBytes => self.signature_bytes = value,
            LimitKind::Permissions => self.permissions = value,
            LimitKind::Audiences => self.audiences = value,
            LimitKind::CriticalExtensions => self.extensions = value,
            LimitKind::CriticalExtensionBytes => self.extension_bytes = value,
            LimitKind::AllowedBodyDigests => self.body_digests = value,
            LimitKind::BindingEvidence => self.binding_evidence = value,
            LimitKind::CanonicalBodyBytes => self.canonical_body_bytes = value,
            LimitKind::RegistryEntries => self.registry_entries = value,
            LimitKind::TrustAnchors => self.trust_anchors = value,
        }
        self.validate()?;
        Ok(self)
    }

    /// Lowers the total adapter/cryptographic work budget.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::CollectionLimitExceeded`] when `work_units`
    /// exceeds [`HARD_MAX_WORK_UNITS`].
    pub fn with_work_units(mut self, work_units: u64) -> Result<Self, ModelError> {
        self.work_units = work_units;
        self.validate()?;
        Ok(self)
    }

    /// Returns the configured value for one count or byte limit.
    #[must_use]
    pub const fn get(&self, kind: LimitKind) -> usize {
        match kind {
            LimitKind::BundleBytes => self.bundle_bytes,
            LimitKind::Grants => self.grants,
            LimitKind::Actions => self.actions,
            LimitKind::PlanLeaves => self.plan_leaves,
            LimitKind::PlanDepth => self.plan_depth,
            LimitKind::PlanBranching => self.plan_branching,
            LimitKind::EvidenceObjects => self.evidence,
            LimitKind::EvidenceBytes => self.evidence_bytes,
            LimitKind::ControlBindings => self.bindings,
            LimitKind::PrincipalStatusStatements => self.principal_status,
            LimitKind::GrantStatusStatements => self.grant_status,
            LimitKind::Attachments => self.attachments,
            LimitKind::Signatures => self.signatures,
            LimitKind::SignatureBytes => self.signature_bytes,
            LimitKind::Permissions => self.permissions,
            LimitKind::Audiences => self.audiences,
            LimitKind::CriticalExtensions => self.extensions,
            LimitKind::CriticalExtensionBytes => self.extension_bytes,
            LimitKind::AllowedBodyDigests => self.body_digests,
            LimitKind::BindingEvidence => self.binding_evidence,
            LimitKind::CanonicalBodyBytes => self.canonical_body_bytes,
            LimitKind::RegistryEntries => self.registry_entries,
            LimitKind::TrustAnchors => self.trust_anchors,
        }
    }

    /// Returns the configured total adapter/cryptographic work budget.
    #[must_use]
    pub const fn max_work_units(&self) -> u64 {
        self.work_units
    }

    /// Validates that every deployment limit is within the protocol hard
    /// maximum.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::CollectionLimitExceeded`] when any configured
    /// limit exceeds the corresponding hard maximum.
    pub fn validate(&self) -> Result<(), ModelError> {
        let hard = Self::hard();
        if self.bundle_bytes > hard.bundle_bytes
            || self.grants > hard.grants
            || self.actions > hard.actions
            || self.plan_leaves > hard.plan_leaves
            || self.plan_depth > hard.plan_depth
            || self.plan_branching > hard.plan_branching
            || self.evidence > hard.evidence
            || self.evidence_bytes > hard.evidence_bytes
            || self.bindings > hard.bindings
            || self.principal_status > hard.principal_status
            || self.grant_status > hard.grant_status
            || self.attachments > hard.attachments
            || self.signatures > hard.signatures
            || self.signature_bytes > hard.signature_bytes
            || self.permissions > hard.permissions
            || self.audiences > hard.audiences
            || self.extensions > hard.extensions
            || self.extension_bytes > hard.extension_bytes
            || self.body_digests > hard.body_digests
            || self.binding_evidence > hard.binding_evidence
            || self.canonical_body_bytes > hard.canonical_body_bytes
            || self.registry_entries > hard.registry_entries
            || self.trust_anchors > hard.trust_anchors
            || self.work_units > hard.work_units
        {
            return Err(ModelError::CollectionLimitExceeded);
        }
        Ok(())
    }
}

impl Default for VerifierLimits {
    fn default() -> Self {
        Self::default_deployment()
    }
}

fn canonical_registry_ids<T: Ord>(
    mut identifiers: Vec<T>,
    required: bool,
) -> Result<Vec<T>, ModelError> {
    if identifiers.len() > HARD_MAX_REGISTRY_ENTRIES || (required && identifiers.is_empty()) {
        return Err(ModelError::InvalidRegistrySelection);
    }
    identifiers.sort();
    identifiers.dedup();
    Ok(identifiers)
}

/// Exact immutable registry selection accepted by one verifier context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedRegistries {
    manifest_id: RegistryManifestId,
    principal_methods: Vec<PrincipalMethodId>,
    signature_suites: Vec<SignatureSuiteId>,
    evidence_types: Vec<EvidenceTypeId>,
    principal_status_methods: Vec<StatusMethodId>,
    grant_status_methods: Vec<StatusMethodId>,
    assurance_claims: Vec<AssuranceClaimId>,
    assurance_implications: Vec<AssuranceImplicationId>,
    resource_matchers: Vec<ResourceMatcherId>,
    budget_algebras: Vec<BudgetAlgebraId>,
    critical_extensions: Vec<ExtensionId>,
    profiles: Vec<ProfileRef>,
    profile_policies: Vec<ProfilePolicyId>,
}

impl AcceptedRegistries {
    /// Constructs an exact, canonical registry selection.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidRegistrySelection`] when a registry
    /// collection exceeds [`HARD_MAX_REGISTRY_ENTRIES`] or when the mandatory
    /// principal-method, signature-suite, or profile set is empty.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest_id: RegistryManifestId,
        principal_methods: Vec<PrincipalMethodId>,
        signature_suites: Vec<SignatureSuiteId>,
        evidence_types: Vec<EvidenceTypeId>,
        principal_status_methods: Vec<StatusMethodId>,
        grant_status_methods: Vec<StatusMethodId>,
        assurance_claims: Vec<AssuranceClaimId>,
        assurance_implications: Vec<AssuranceImplicationId>,
        resource_matchers: Vec<ResourceMatcherId>,
        budget_algebras: Vec<BudgetAlgebraId>,
        mut critical_extensions: Vec<ExtensionId>,
        mut profiles: Vec<ProfileRef>,
        profile_policies: Vec<ProfilePolicyId>,
    ) -> Result<Self, ModelError> {
        if critical_extensions.len() > HARD_MAX_REGISTRY_ENTRIES
            || profiles.is_empty()
            || profiles.len() > HARD_MAX_REGISTRY_ENTRIES
        {
            return Err(ModelError::InvalidRegistrySelection);
        }
        critical_extensions.sort();
        critical_extensions.dedup();
        profiles.sort();
        profiles.dedup();
        Ok(Self {
            manifest_id,
            principal_methods: canonical_registry_ids(principal_methods, true)?,
            signature_suites: canonical_registry_ids(signature_suites, true)?,
            evidence_types: canonical_registry_ids(evidence_types, false)?,
            principal_status_methods: canonical_registry_ids(principal_status_methods, false)?,
            grant_status_methods: canonical_registry_ids(grant_status_methods, false)?,
            assurance_claims: canonical_registry_ids(assurance_claims, false)?,
            assurance_implications: canonical_registry_ids(assurance_implications, false)?,
            resource_matchers: canonical_registry_ids(resource_matchers, true)?,
            budget_algebras: canonical_registry_ids(budget_algebras, false)?,
            critical_extensions,
            profiles,
            profile_policies: canonical_registry_ids(profile_policies, true)?,
        })
    }

    /// Returns the pinned registry-manifest identifier.
    #[must_use]
    pub const fn manifest_id(&self) -> RegistryManifestId {
        self.manifest_id
    }

    /// Returns accepted principal-method identifiers.
    #[must_use]
    pub fn principal_methods(&self) -> &[PrincipalMethodId] {
        &self.principal_methods
    }

    /// Returns accepted signature-suite identifiers.
    #[must_use]
    pub fn signature_suites(&self) -> &[SignatureSuiteId] {
        &self.signature_suites
    }

    /// Returns accepted evidence-type identifiers.
    #[must_use]
    pub fn evidence_types(&self) -> &[EvidenceTypeId] {
        &self.evidence_types
    }

    /// Returns accepted principal-status method identifiers.
    #[must_use]
    pub fn principal_status_methods(&self) -> &[StatusMethodId] {
        &self.principal_status_methods
    }

    /// Returns accepted grant-status method identifiers.
    #[must_use]
    pub fn grant_status_methods(&self) -> &[StatusMethodId] {
        &self.grant_status_methods
    }

    /// Returns accepted assurance-claim identifiers.
    #[must_use]
    pub fn assurance_claims(&self) -> &[AssuranceClaimId] {
        &self.assurance_claims
    }

    /// Returns accepted assurance implication-rule identifiers.
    #[must_use]
    pub fn assurance_implications(&self) -> &[AssuranceImplicationId] {
        &self.assurance_implications
    }

    /// Returns accepted resource-matching algebra identifiers.
    #[must_use]
    pub fn resource_matchers(&self) -> &[ResourceMatcherId] {
        &self.resource_matchers
    }

    /// Returns accepted budget-algebra identifiers.
    #[must_use]
    pub fn budget_algebras(&self) -> &[BudgetAlgebraId] {
        &self.budget_algebras
    }

    /// Returns registered critical extension identifiers.
    #[must_use]
    pub fn critical_extensions(&self) -> &[ExtensionId] {
        &self.critical_extensions
    }

    /// Returns accepted application profiles.
    #[must_use]
    pub fn profiles(&self) -> &[ProfileRef] {
        &self.profiles
    }

    /// Returns accepted effect-free profile-policy identifiers.
    #[must_use]
    pub fn profile_policies(&self) -> &[ProfilePolicyId] {
        &self.profile_policies
    }

    /// Performs an exact principal-method lookup.
    #[must_use]
    pub fn accepts_principal_method(&self, identifier: &PrincipalMethodId) -> bool {
        self.principal_methods.binary_search(identifier).is_ok()
    }

    /// Performs an exact signature-suite lookup.
    #[must_use]
    pub fn accepts_signature_suite(&self, identifier: &SignatureSuiteId) -> bool {
        self.signature_suites.binary_search(identifier).is_ok()
    }

    /// Performs an exact evidence-type lookup.
    #[must_use]
    pub fn accepts_evidence_type(&self, identifier: &EvidenceTypeId) -> bool {
        self.evidence_types.binary_search(identifier).is_ok()
    }

    /// Performs an exact principal-status method lookup.
    #[must_use]
    pub fn accepts_principal_status_method(&self, identifier: &StatusMethodId) -> bool {
        self.principal_status_methods
            .binary_search(identifier)
            .is_ok()
    }

    /// Performs an exact grant-status method lookup.
    #[must_use]
    pub fn accepts_grant_status_method(&self, identifier: &StatusMethodId) -> bool {
        self.grant_status_methods.binary_search(identifier).is_ok()
    }

    /// Performs an exact assurance-claim lookup.
    #[must_use]
    pub fn accepts_assurance_claim(&self, identifier: &AssuranceClaimId) -> bool {
        self.assurance_claims.binary_search(identifier).is_ok()
    }

    /// Performs an exact assurance implication-rule lookup.
    #[must_use]
    pub fn accepts_assurance_implication(&self, identifier: &AssuranceImplicationId) -> bool {
        self.assurance_implications
            .binary_search(identifier)
            .is_ok()
    }

    /// Performs an exact resource-matching algebra lookup.
    #[must_use]
    pub fn accepts_resource_matcher(&self, identifier: &ResourceMatcherId) -> bool {
        self.resource_matchers.binary_search(identifier).is_ok()
    }

    /// Performs an exact budget-algebra lookup.
    #[must_use]
    pub fn accepts_budget_algebra(&self, identifier: &BudgetAlgebraId) -> bool {
        self.budget_algebras.binary_search(identifier).is_ok()
    }

    /// Performs an exact critical-extension lookup.
    #[must_use]
    pub fn accepts_critical_extension(&self, identifier: &ExtensionId) -> bool {
        self.critical_extensions.binary_search(identifier).is_ok()
    }

    /// Performs an exact profile-and-version lookup.
    #[must_use]
    pub fn accepts_profile(&self, profile: &ProfileRef) -> bool {
        self.profiles.binary_search(profile).is_ok()
    }

    /// Performs an exact effect-free profile-policy lookup.
    #[must_use]
    pub fn accepts_profile_policy(&self, policy: &ProfilePolicyId) -> bool {
        self.profile_policies.binary_search(policy).is_ok()
    }

    /// Returns the largest accepted registry collection.
    #[must_use]
    pub fn maximum_entry_count(&self) -> usize {
        [
            self.principal_methods.len(),
            self.signature_suites.len(),
            self.evidence_types.len(),
            self.principal_status_methods.len(),
            self.grant_status_methods.len(),
            self.assurance_claims.len(),
            self.assurance_implications.len(),
            self.resource_matchers.len(),
            self.budget_algebras.len(),
            self.critical_extensions.len(),
            self.profiles.len(),
            self.profile_policies.len(),
        ]
        .into_iter()
        .max()
        .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierContext {
    trust_anchors: Vec<TrustAnchor>,
    accepted_registries: AcceptedRegistries,
    expected_audience: Audience,
    expected_challenge: Challenge,
    evaluation_time: Timestamp,
    assurance_policy: AssurancePolicy,
    principal_status_snapshot: PrincipalStatusSnapshot,
    grant_status_snapshot: GrantStatusSnapshot,
    resource_matcher: ResourceMatcherId,
    profile_policy: ProfilePolicyId,
    channel_policy: ChannelBindingId,
    limits: VerifierLimits,
}

impl VerifierContext {
    #[allow(clippy::too_many_arguments)]
    /// Constructs an explicit, immutable verifier context.
    ///
    /// # Errors
    ///
    /// Returns an error when `limits` exceed protocol maxima or when trust
    /// anchors or accepted profiles are empty.
    pub fn new(
        mut trust_anchors: Vec<TrustAnchor>,
        accepted_registries: AcceptedRegistries,
        expected_audience: Audience,
        expected_challenge: Challenge,
        evaluation_time: Timestamp,
        assurance_policy: AssurancePolicy,
        principal_status_snapshot: PrincipalStatusSnapshot,
        grant_status_snapshot: GrantStatusSnapshot,
        resource_matcher: ResourceMatcherId,
        profile_policy: ProfilePolicyId,
        channel_policy: ChannelBindingId,
        limits: VerifierLimits,
    ) -> Result<Self, ModelError> {
        limits.validate()?;
        trust_anchors.sort_by(|left, right| left.id().cmp(right.id()));
        if trust_anchors.is_empty()
            || trust_anchors.len() > limits.get(LimitKind::TrustAnchors)
            || trust_anchors
                .windows(2)
                .any(|window| window[0].id() == window[1].id())
            || trust_anchors.iter().any(|anchor| {
                anchor
                    .accepted_methods()
                    .iter()
                    .any(|method| !accepted_registries.accepts_principal_method(method))
                    || anchor
                        .profiles()
                        .iter()
                        .any(|profile| !accepted_registries.accepts_profile(profile))
                    || matches!(
                        anchor.status_policy(),
                        StatusPolicy::SnapshotRequired { method, .. }
                            if !accepted_registries.accepts_principal_status_method(method)
                    )
            })
            || assurance_policy.requirements().iter().any(|requirement| {
                !accepted_registries.accepts_assurance_claim(requirement.claim_kind())
            })
            || !accepted_registries.accepts_resource_matcher(&resource_matcher)
            || !accepted_registries.accepts_profile_policy(&profile_policy)
            || accepted_registries.maximum_entry_count() > limits.get(LimitKind::RegistryEntries)
        {
            return Err(ModelError::InvalidVerifierContext);
        }
        Ok(Self {
            trust_anchors,
            accepted_registries,
            expected_audience,
            expected_challenge,
            evaluation_time,
            assurance_policy,
            principal_status_snapshot,
            grant_status_snapshot,
            resource_matcher,
            profile_policy,
            channel_policy,
            limits,
        })
    }

    /// Derives a per-request context without changing trust, registries,
    /// status, policies, or resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error only if the existing context no longer satisfies its
    /// own invariants.
    pub fn for_request(
        &self,
        expected_audience: Audience,
        expected_challenge: Challenge,
        evaluation_time: Timestamp,
    ) -> Result<Self, ModelError> {
        Self::new(
            self.trust_anchors.clone(),
            self.accepted_registries.clone(),
            expected_audience,
            expected_challenge,
            evaluation_time,
            self.assurance_policy.clone(),
            self.principal_status_snapshot.clone(),
            self.grant_status_snapshot.clone(),
            self.resource_matcher.clone(),
            self.profile_policy.clone(),
            self.channel_policy.clone(),
            self.limits.clone(),
        )
    }

    #[must_use]
    pub fn trust_anchors(&self) -> &[TrustAnchor] {
        &self.trust_anchors
    }
    #[must_use]
    pub const fn accepted_registries(&self) -> &AcceptedRegistries {
        &self.accepted_registries
    }
    #[must_use]
    pub const fn expected_audience(&self) -> &Audience {
        &self.expected_audience
    }
    #[must_use]
    pub const fn expected_challenge(&self) -> Challenge {
        self.expected_challenge
    }
    #[must_use]
    pub const fn evaluation_time(&self) -> Timestamp {
        self.evaluation_time
    }
    #[must_use]
    pub const fn assurance_policy(&self) -> &AssurancePolicy {
        &self.assurance_policy
    }
    #[must_use]
    pub const fn principal_status_snapshot(&self) -> &PrincipalStatusSnapshot {
        &self.principal_status_snapshot
    }
    #[must_use]
    pub const fn grant_status_snapshot(&self) -> &GrantStatusSnapshot {
        &self.grant_status_snapshot
    }
    #[must_use]
    pub const fn resource_matcher(&self) -> &ResourceMatcherId {
        &self.resource_matcher
    }
    #[must_use]
    pub const fn profile_policy(&self) -> &ProfilePolicyId {
        &self.profile_policy
    }
    #[must_use]
    pub const fn channel_policy(&self) -> &ChannelBindingId {
        &self.channel_policy
    }
    #[must_use]
    pub const fn limits(&self) -> &VerifierLimits {
        &self.limits
    }
}

/// Stable stage at which a portable verifier result became final.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum VerificationStage {
    Decode,
    Resolve,
    PrincipalControl,
    Authority,
    Complete,
}

/// Stable three-way portable verifier decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum VerificationDecision {
    Authorized,
    Denied,
    Indeterminate,
}

/// Stable language-neutral result code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationCode {
    Authorized,
    Denied(DenialReason),
    Indeterminate(Requirement),
}

impl VerificationCode {
    /// Returns the stable language-neutral code string.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Denied(reason) => reason.code(),
            Self::Indeterminate(requirement) => requirement.code(),
        }
    }
}

/// Deterministic resource totals reported by the portable verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationResources {
    proof_bytes: u64,
    action_bytes: u64,
    context_bytes: u64,
    object_count: u64,
    plan_leaves: u64,
    plan_depth: u64,
    work_units: u64,
}

impl VerificationResources {
    /// Constructs exact bounded verifier resource totals.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        proof_bytes: u64,
        action_bytes: u64,
        context_bytes: u64,
        object_count: u64,
        plan_leaves: u64,
        plan_depth: u64,
        work_units: u64,
    ) -> Self {
        Self {
            proof_bytes,
            action_bytes,
            context_bytes,
            object_count,
            plan_leaves,
            plan_depth,
            work_units,
        }
    }

    #[must_use]
    pub const fn proof_bytes(self) -> u64 {
        self.proof_bytes
    }
    #[must_use]
    pub const fn action_bytes(self) -> u64 {
        self.action_bytes
    }
    #[must_use]
    pub const fn context_bytes(self) -> u64 {
        self.context_bytes
    }
    #[must_use]
    pub const fn object_count(self) -> u64 {
        self.object_count
    }
    #[must_use]
    pub const fn plan_leaves(self) -> u64 {
        self.plan_leaves
    }
    #[must_use]
    pub const fn plan_depth(self) -> u64 {
        self.plan_depth
    }
    #[must_use]
    pub const fn work_units(self) -> u64 {
        self.work_units
    }
}

/// Complete language-neutral output of `verify_v1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableVerificationResult {
    decision: VerificationDecision,
    stage: VerificationStage,
    code: VerificationCode,
    proof_digest: Digest,
    action_digest: Digest,
    context_digest: ContextDigest,
    plan_id: Option<PlanId>,
    result_digest: VerificationResultDigest,
    authorized_branches: Vec<ProofRef>,
    assurance: Vec<ParticipantAssurance>,
    assurance_satisfactions: Vec<AssuranceSatisfaction>,
    resources: VerificationResources,
    registry_manifest: RegistryManifestId,
}

impl PortableVerificationResult {
    /// Constructs a complete portable result before its canonical result
    /// digest is bound.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        decision: VerificationDecision,
        stage: VerificationStage,
        code: VerificationCode,
        proof_digest: Digest,
        action_digest: Digest,
        context_digest: ContextDigest,
        plan_id: Option<PlanId>,
        authorized_branches: Vec<ProofRef>,
        assurance: Vec<ParticipantAssurance>,
        assurance_satisfactions: Vec<AssuranceSatisfaction>,
        resources: VerificationResources,
        registry_manifest: RegistryManifestId,
    ) -> Self {
        Self {
            decision,
            stage,
            code,
            proof_digest,
            action_digest,
            context_digest,
            plan_id,
            result_digest: VerificationResultDigest::new([0; 32]),
            authorized_branches,
            assurance,
            assurance_satisfactions,
            resources,
            registry_manifest,
        }
    }

    /// Binds the digest of the canonical result projection.
    #[must_use]
    pub const fn with_result_digest(mut self, digest: VerificationResultDigest) -> Self {
        self.result_digest = digest;
        self
    }

    #[must_use]
    pub const fn decision(&self) -> VerificationDecision {
        self.decision
    }
    #[must_use]
    pub const fn stage(&self) -> VerificationStage {
        self.stage
    }
    #[must_use]
    pub const fn code(&self) -> VerificationCode {
        self.code
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
    pub const fn plan_id(&self) -> Option<PlanId> {
        self.plan_id
    }
    #[must_use]
    pub const fn result_digest(&self) -> VerificationResultDigest {
        self.result_digest
    }
    #[must_use]
    pub fn authorized_branches(&self) -> &[ProofRef] {
        &self.authorized_branches
    }
    #[must_use]
    pub fn assurance(&self) -> &[ParticipantAssurance] {
        &self.assurance
    }
    #[must_use]
    pub fn assurance_satisfactions(&self) -> &[AssuranceSatisfaction] {
        &self.assurance_satisfactions
    }
    #[must_use]
    pub const fn resources(&self) -> VerificationResources {
        self.resources
    }
    #[must_use]
    pub const fn registry_manifest(&self) -> RegistryManifestId {
        self.registry_manifest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialReason {
    MalformedProof,
    NonCanonicalProof,
    ResourceLimitExceeded,
    DigestMismatch,
    DuplicateObject,
    MissingReference,
    ReferenceCycle,
    AmbiguousTerminalGrant,
    UnusedCriticalEvidence,
    InvalidSignature,
    PrincipalMethodMismatch,
    VerificationMethodMismatch,
    SignatureSuiteMismatch,
    UntrustedRoot,
    BrokenGrantChain,
    DelegationExpanded,
    PermissionNotGranted,
    ActionConstraintMismatch,
    BudgetCeilingExceeded,
    AuthorizationPlanInvalid,
    PlanActionMismatch,
    ActionBodyMismatch,
    AudienceMismatch,
    ChallengeMismatch,
    ActionOutsideValidity,
    PrincipalRevoked,
    GrantRevoked,
    StatusSequenceRollback,
    StatusMethodMismatch,
    StatusIssuerUntrusted,
    RegistryManifestMismatch,
    ResourceNamespaceMismatch,
    CriticalExtensionUnknown,
    AttachmentMissing,
    AttachmentDigestMismatch,
    AttachmentLengthMismatch,
    DuplicateAttachment,
    UnusedCriticalAttachment,
    OpaqueAttachmentNotAllowed,
    LocalPolicyDenied,
}

impl DenialReason {
    /// Returns the stable language-neutral V1 reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MalformedProof => "malformed-proof",
            Self::NonCanonicalProof => "non-canonical-proof",
            Self::ResourceLimitExceeded => "resource-limit-exceeded",
            Self::DigestMismatch => "digest-mismatch",
            Self::DuplicateObject => "duplicate-object",
            Self::MissingReference => "missing-reference",
            Self::ReferenceCycle => "reference-cycle",
            Self::AmbiguousTerminalGrant => "ambiguous-terminal-grant",
            Self::UnusedCriticalEvidence => "unused-critical-evidence",
            Self::InvalidSignature => "invalid-signature",
            Self::PrincipalMethodMismatch => "principal-method-mismatch",
            Self::VerificationMethodMismatch => "verification-method-mismatch",
            Self::SignatureSuiteMismatch => "signature-suite-mismatch",
            Self::UntrustedRoot => "untrusted-root",
            Self::BrokenGrantChain => "broken-grant-chain",
            Self::DelegationExpanded => "delegation-expanded",
            Self::PermissionNotGranted => "permission-not-granted",
            Self::ActionConstraintMismatch => "action-constraint-mismatch",
            Self::BudgetCeilingExceeded => "budget-ceiling-exceeded",
            Self::AuthorizationPlanInvalid => "authorization-plan-invalid",
            Self::PlanActionMismatch => "plan-action-mismatch",
            Self::ActionBodyMismatch => "action-body-mismatch",
            Self::AudienceMismatch => "audience-mismatch",
            Self::ChallengeMismatch => "challenge-mismatch",
            Self::ActionOutsideValidity => "action-outside-validity",
            Self::PrincipalRevoked => "principal-revoked",
            Self::GrantRevoked => "grant-revoked",
            Self::StatusSequenceRollback => "status-sequence-rollback",
            Self::StatusMethodMismatch => "status-method-mismatch",
            Self::StatusIssuerUntrusted => "status-issuer-untrusted",
            Self::RegistryManifestMismatch => "registry-manifest-mismatch",
            Self::ResourceNamespaceMismatch => "resource-namespace-mismatch",
            Self::CriticalExtensionUnknown => "critical-extension-unknown",
            Self::AttachmentMissing => "attachment-missing",
            Self::AttachmentDigestMismatch => "attachment-digest-mismatch",
            Self::AttachmentLengthMismatch => "attachment-length-mismatch",
            Self::DuplicateAttachment => "duplicate-attachment",
            Self::UnusedCriticalAttachment => "unused-critical-attachment",
            Self::OpaqueAttachmentNotAllowed => "opaque-attachment-not-allowed",
            Self::LocalPolicyDenied => "local-policy-denied",
        }
    }

    /// Parses one exact stable V1 denial code.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        [
            Self::MalformedProof,
            Self::NonCanonicalProof,
            Self::ResourceLimitExceeded,
            Self::DigestMismatch,
            Self::DuplicateObject,
            Self::MissingReference,
            Self::ReferenceCycle,
            Self::AmbiguousTerminalGrant,
            Self::UnusedCriticalEvidence,
            Self::InvalidSignature,
            Self::PrincipalMethodMismatch,
            Self::VerificationMethodMismatch,
            Self::SignatureSuiteMismatch,
            Self::UntrustedRoot,
            Self::BrokenGrantChain,
            Self::DelegationExpanded,
            Self::PermissionNotGranted,
            Self::ActionConstraintMismatch,
            Self::BudgetCeilingExceeded,
            Self::AuthorizationPlanInvalid,
            Self::PlanActionMismatch,
            Self::ActionBodyMismatch,
            Self::AudienceMismatch,
            Self::ChallengeMismatch,
            Self::ActionOutsideValidity,
            Self::PrincipalRevoked,
            Self::GrantRevoked,
            Self::StatusSequenceRollback,
            Self::StatusMethodMismatch,
            Self::StatusIssuerUntrusted,
            Self::RegistryManifestMismatch,
            Self::ResourceNamespaceMismatch,
            Self::CriticalExtensionUnknown,
            Self::AttachmentMissing,
            Self::AttachmentDigestMismatch,
            Self::AttachmentLengthMismatch,
            Self::DuplicateAttachment,
            Self::UnusedCriticalAttachment,
            Self::OpaqueAttachmentNotAllowed,
            Self::LocalPolicyDenied,
        ]
        .into_iter()
        .find(|reason| reason.code() == code)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Requirement {
    UnsupportedProtocol,
    UnsupportedPrincipalMethod,
    UnsupportedSignatureSuite,
    UnsupportedEvidenceType,
    UnsupportedStatusMethod,
    UnsupportedProfile,
    UnsupportedProfilePolicy,
    UnsupportedResourceMatcher,
    UnsupportedBudgetAlgebra,
    UnsupportedCriticalExtension,
    UnsupportedAssuranceClaim,
    MissingPrincipalEvidence,
    MissingPrincipalStatus,
    MissingGrantStatus,
    StaleStatus,
    HistoricalStateUnavailable,
    AssuranceRequirementNotMet,
    ExternalFactUnavailable,
}

impl Requirement {
    /// Returns the stable language-neutral V1 requirement code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedProtocol => "unsupported-protocol",
            Self::UnsupportedPrincipalMethod => "unsupported-principal-method",
            Self::UnsupportedSignatureSuite => "unsupported-signature-suite",
            Self::UnsupportedEvidenceType => "unsupported-evidence-type",
            Self::UnsupportedStatusMethod => "unsupported-status-method",
            Self::UnsupportedProfile => "unsupported-profile",
            Self::UnsupportedProfilePolicy => "unsupported-profile-policy",
            Self::UnsupportedResourceMatcher => "unsupported-resource-matcher",
            Self::UnsupportedBudgetAlgebra => "unsupported-budget-algebra",
            Self::UnsupportedCriticalExtension => "unsupported-critical-extension",
            Self::UnsupportedAssuranceClaim => "unsupported-assurance-claim",
            Self::MissingPrincipalEvidence => "missing-principal-evidence",
            Self::MissingPrincipalStatus => "missing-principal-status",
            Self::MissingGrantStatus => "missing-grant-status",
            Self::StaleStatus => "stale-status",
            Self::HistoricalStateUnavailable => "historical-state-unavailable",
            Self::AssuranceRequirementNotMet => "assurance-requirement-not-met",
            Self::ExternalFactUnavailable => "external-fact-unavailable",
        }
    }

    /// Parses one exact stable V1 indeterminate requirement code.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        [
            Self::UnsupportedProtocol,
            Self::UnsupportedPrincipalMethod,
            Self::UnsupportedSignatureSuite,
            Self::UnsupportedEvidenceType,
            Self::UnsupportedStatusMethod,
            Self::UnsupportedProfile,
            Self::UnsupportedProfilePolicy,
            Self::UnsupportedResourceMatcher,
            Self::UnsupportedBudgetAlgebra,
            Self::UnsupportedCriticalExtension,
            Self::UnsupportedAssuranceClaim,
            Self::MissingPrincipalEvidence,
            Self::MissingPrincipalStatus,
            Self::MissingGrantStatus,
            Self::StaleStatus,
            Self::HistoricalStateUnavailable,
            Self::AssuranceRequirementNotMet,
            Self::ExternalFactUnavailable,
        ]
        .into_iter()
        .find(|requirement| requirement.code() == code)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    UnsupportedProtocol,
    InvalidBundleHeader,
    InvalidPrincipal,
    InvalidVerificationMethod,
    InvalidProfile,
    InvalidCapability,
    InvalidResource,
    InvalidAudience,
    InvalidAudienceSet,
    InvalidMediaType,
    InvalidRegistryId,
    InvalidExtensionId,
    InvalidValidity,
    InvalidPermissionSet,
    InvalidActionConstraint,
    InvalidCanonicalAction,
    InvalidExtension,
    DuplicateExtension,
    InvalidSignature,
    InvalidEvidence,
    InvalidEvidenceBinding,
    InvalidStatus,
    InvalidStatusSnapshot,
    InvalidAttachment,
    InvalidPlan,
    PlanLimitExceeded,
    InvalidAssurance,
    InvalidTrustAnchor,
    InvalidRegistrySelection,
    InvalidVerifierContext,
    DuplicateObject,
    CollectionLimitExceeded,
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedProtocol => "unsupported protocol",
            Self::InvalidBundleHeader => "invalid bundle header",
            Self::InvalidPrincipal => "invalid principal",
            Self::InvalidVerificationMethod => "invalid verification method",
            Self::InvalidProfile => "invalid profile",
            Self::InvalidCapability => "invalid capability",
            Self::InvalidResource => "invalid resource",
            Self::InvalidAudience => "invalid audience",
            Self::InvalidAudienceSet => "invalid audience set",
            Self::InvalidMediaType => "invalid media type",
            Self::InvalidRegistryId => "invalid registry identifier",
            Self::InvalidExtensionId => "invalid extension identifier",
            Self::InvalidValidity => "invalid validity window",
            Self::InvalidPermissionSet => "invalid permission set",
            Self::InvalidActionConstraint => "invalid action constraint",
            Self::InvalidCanonicalAction => "invalid canonical action",
            Self::InvalidExtension => "invalid critical extension",
            Self::DuplicateExtension => "duplicate critical extension",
            Self::InvalidSignature => "invalid signature bytes",
            Self::InvalidEvidence => "invalid evidence",
            Self::InvalidEvidenceBinding => "invalid evidence binding",
            Self::InvalidStatus => "invalid status statement",
            Self::InvalidStatusSnapshot => "invalid status snapshot",
            Self::InvalidAttachment => "invalid attachment input",
            Self::InvalidPlan => "invalid authorization plan",
            Self::PlanLimitExceeded => "authorization plan limit exceeded",
            Self::InvalidAssurance => "invalid assurance",
            Self::InvalidTrustAnchor => "invalid trust anchor",
            Self::InvalidRegistrySelection => "invalid accepted registry selection",
            Self::InvalidVerifierContext => "invalid verifier context",
            Self::DuplicateObject => "duplicate object",
            Self::CollectionLimitExceeded => "collection limit exceeded",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ModelError {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn digest(byte: u8) -> Digest {
        Digest::new([byte; 32])
    }

    #[test]
    fn action_constraint_is_monotonic() {
        let any = ActionConstraint::AnyBody;
        let set = ActionConstraint::allowed_body_digests(vec![digest(1), digest(2)]).expect("set");
        let exact = ActionConstraint::ExactBodyDigest(digest(1));
        assert!(set.attenuates(&any));
        assert!(exact.attenuates(&set));
        assert!(!set.attenuates(&exact));
    }

    #[test]
    fn plan_rejects_duplicate_leaf() {
        let leaf = AuthorizationPlan::proof(digest(1).into());
        assert_eq!(
            AuthorizationPlan::all_of(vec![leaf.clone(), leaf]),
            Err(ModelError::PlanLimitExceeded)
        );
    }

    #[test]
    fn child_window_must_be_contained() {
        let parent = ValidityWindow::new(Timestamp::new(10), Timestamp::new(20)).expect("parent");
        let child = ValidityWindow::new(Timestamp::new(11), Timestamp::new(19)).expect("child");
        assert!(parent.contains_window(child));
        assert!(!child.contains_window(parent));
    }

    #[test]
    fn principal_scheme_is_canonical() {
        assert!(PrincipalId::parse("did:key:z6Mk").is_ok());
        assert_eq!(
            PrincipalId::parse("DID:key:z6Mk"),
            Err(ModelError::InvalidPrincipal)
        );
        assert_eq!(
            PrincipalId::parse("did:"),
            Err(ModelError::InvalidPrincipal)
        );
    }

    proptest! {
        #[test]
        fn validity_containment_is_transitive(
            parent_start in 0_u64..1_000_000,
            left in 0_u64..10_000,
            right in 0_u64..10_000,
        ) {
            let parent_end = parent_start.saturating_add(left).saturating_add(right);
            let parent = ValidityWindow::new(
                Timestamp::new(parent_start),
                Timestamp::new(parent_end),
            ).expect("generated parent is ordered");
            let child = ValidityWindow::new(
                Timestamp::new(parent_start.saturating_add(left)),
                Timestamp::new(parent_end),
            ).expect("generated child is ordered");
            prop_assert!(parent.contains_window(child));
        }

        #[test]
        fn body_digest_sets_are_canonical(bytes in prop::collection::vec(any::<u8>(), 1..257)) {
            let digests: Vec<_> = bytes.iter().map(|byte| digest(*byte)).collect();
            let set = BodyDigestSet::new(digests).expect("generated set is bounded");
            prop_assert!(set.as_slice().windows(2).all(|window| window[0] < window[1]));
            for byte in bytes {
                prop_assert!(set.contains(&digest(byte)));
            }
        }

        #[test]
        fn principal_parser_never_accepts_uppercase_scheme(
            scheme in "[A-Z][A-Za-z0-9+.-]{0,15}",
            remainder in "[a-z0-9:._/-]{1,64}",
        ) {
            let candidate = format!("{scheme}:{remainder}");
            prop_assert_eq!(
                PrincipalId::parse(&candidate),
                Err(ModelError::InvalidPrincipal)
            );
        }

        #[test]
        fn deployment_limits_never_exceed_hard_maximum(extra in 1_usize..1_000_000) {
            let value = HARD_MAX_BUNDLE_BYTES.saturating_add(extra);
            prop_assert_eq!(
                VerifierLimits::default_deployment()
                    .with_limit(LimitKind::BundleBytes, value),
                Err(ModelError::CollectionLimitExceeded)
            );
        }
    }
}
