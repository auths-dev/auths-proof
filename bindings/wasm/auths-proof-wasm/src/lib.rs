//! WebAssembly export of the bounded three-input Auths V1 engine boundary.

#![forbid(unsafe_code)]

use auths_author::{
    ApprovalPolicyCommitment, ExternalSigningRequest, GrantPlan, GrantRequest, OverGrantingWarning,
    ProfilePlanCommitment, ProfilePlanMember, commit_plan_approval, plan_child_grant,
    prepare_action, prepare_grant, prepare_grant_status, prepare_principal_status,
};
use auths_identity::{IdentityPacket, PublicIdentity, SignedIdentityMessage};
use auths_identity_raw_key::RawKeyIdentityMethod;
use auths_model::{
    ActionConstraint, ActionEnvelope, AssurancePolicyId, Audience, AudienceSet, AuthorizationPlan,
    BodyDigestSet, BudgetAlgebraId, BudgetCeiling, BundleHeader, CapabilityId, Challenge,
    ChannelBindingId, CompositionRequirement, ControlBinding, CriticalExtensions, Digest,
    EvidenceId, EvidenceObject, EvidenceTypeId, FreshnessLimit, MediaType, Permission,
    PermissionSet, PrincipalId, PrincipalMethodId, ProfileId, ProofBundle, ProofRef, ResourceId,
    SignatureBytes, SignatureDescriptor, SignatureSuiteId, SignedGrant, StatementRef,
    StatusMethodId, StatusPolicy, Timestamp, ValidityWindow, VerificationMethod,
    VerifierConfigurationId, VerifierLimits,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::{McpProfile, McpToolCall};
use auths_registries::ImmutableRegistries;
use serde_json::{Map, Value};
use std::fmt;
use wasm_bindgen::prelude::*;

/// Version of the repository-owned authoring ABI exposed by this WASM module.
pub const AUTHORING_ABI_V1: u16 = 1;
/// Version of the neutral identity ABI exposed independently of authority authoring.
pub const IDENTITY_ABI_V1: u16 = 1;

const WARNING_ANY_BODY: u32 = 1 << 0;
const WARNING_MULTIPLE_PERMISSIONS: u32 = 1 << 1;
const WARNING_MULTIPLE_AUDIENCES: u32 = 1 << 2;
const WARNING_DELEGATION_ALLOWED: u32 = 1 << 3;
const WARNING_NO_BUDGET_CEILING: u32 = 1 << 4;
const WARNING_LONG_VALIDITY: u32 = 1 << 5;

/// Returns the exact authoring ABI version compiled into this distribution.
#[must_use]
#[wasm_bindgen(js_name = authoringAbiVersionV1)]
pub fn authoring_abi_version_v1() -> u16 {
    AUTHORING_ABI_V1
}

/// Returns the exact neutral identity ABI version compiled into this distribution.
#[must_use]
#[wasm_bindgen(js_name = identityAbiVersionV1)]
pub fn identity_abi_version_v1() -> u16 {
    IDENTITY_ABI_V1
}

/// Validates and returns one canonical principal identifier.
///
/// # Errors
///
/// Returns a JavaScript error when the identifier violates the target V1
/// grammar or bound.
#[wasm_bindgen(js_name = canonicalPrincipalV1)]
pub fn canonical_principal_v1(principal: &str) -> Result<String, JsValue> {
    PrincipalId::parse(principal)
        .map(|value| value.as_str().to_owned())
        .map_err(js_error)
}

/// Structurally decoded fields from the neutral compact identity protocol.
///
/// Receiving this value does not claim that the identity relationship was validated. Call the
/// explicitly named raw-key validation export before trusting a self-certifying raw-key identity.
#[wasm_bindgen]
pub struct IdentityFieldsV2 {
    method_id: String,
    identity_id: String,
    suite_id: String,
    public_key: Vec<u8>,
}

impl From<&PublicIdentity> for IdentityFieldsV2 {
    fn from(identity: &PublicIdentity) -> Self {
        Self {
            method_id: identity.method_id().to_owned(),
            identity_id: identity.identity_id().to_owned(),
            suite_id: identity.suite_id().to_owned(),
            public_key: identity.public_key().to_vec(),
        }
    }
}

#[wasm_bindgen]
impl IdentityFieldsV2 {
    #[must_use]
    #[wasm_bindgen(getter, js_name = methodId)]
    pub fn method_id(&self) -> String {
        self.method_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = identityId)]
    pub fn identity_id(&self) -> String {
        self.identity_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = suiteId)]
    pub fn suite_id(&self) -> String {
        self.suite_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

/// An Ed25519-authenticated message from the neutral identity protocol.
#[wasm_bindgen]
pub struct AuthenticatedIdentityMessageV2 {
    identity: IdentityFieldsV2,
    message: Vec<u8>,
}

#[wasm_bindgen]
impl AuthenticatedIdentityMessageV2 {
    #[must_use]
    #[wasm_bindgen(getter, js_name = methodId)]
    pub fn method_id(&self) -> String {
        self.identity.method_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = identityId)]
    pub fn identity_id(&self) -> String {
        self.identity.identity_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = suiteId)]
    pub fn suite_id(&self) -> String {
        self.identity.suite_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.identity.public_key.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }
}

/// Encodes canonical public-identity packet bytes without selecting an identity adapter.
///
/// The caller supplies a method-derived stable identifier. Decoding the resulting bytes remains
/// structural; a matching method adapter must validate the relationship separately.
///
/// # Errors
///
/// Rejects malformed identifiers, empty or oversized keys, and encoding failures.
#[wasm_bindgen(js_name = encodePublicIdentityV2)]
pub fn encode_public_identity_v2(
    method_id: &str,
    identity_id: &str,
    suite_id: &str,
    public_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let identity = PublicIdentity::new(method_id, identity_id, suite_id, public_key.to_vec())
        .map_err(js_error)?;
    IdentityPacket::PublicIdentity(identity)
        .encode()
        .map_err(js_error)
}

/// Creates canonical public-identity packet bytes for the suite-labelled raw-key adapter.
///
/// This is identity only: it creates no grant, capability, approval, policy, or authority.
///
/// # Errors
///
/// Rejects malformed suite identifiers, empty or oversized keys, and encoding failures.
#[wasm_bindgen(js_name = createRawKeyPublicIdentityV2)]
pub fn create_raw_key_public_identity_v2(
    suite_id: &str,
    public_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let validated =
        RawKeyIdentityMethod::identity(suite_id, public_key.to_vec()).map_err(js_error)?;
    IdentityPacket::PublicIdentity(validated.into_public_identity())
        .encode()
        .map_err(js_error)
}

/// Decodes one canonical public-identity packet without claiming method validation.
///
/// # Errors
///
/// Rejects non-canonical, signed-message, unknown-version, trailing, or oversized packets.
#[wasm_bindgen(js_name = decodePublicIdentityV2)]
pub fn decode_public_identity_v2(packet: &[u8]) -> Result<IdentityFieldsV2, JsValue> {
    match IdentityPacket::decode(packet).map_err(js_error)? {
        IdentityPacket::PublicIdentity(identity) => Ok(IdentityFieldsV2::from(&identity)),
        IdentityPacket::SignedMessage(_) => Err(js_error("expected a public-identity packet")),
    }
}

/// Validates a decoded public identity with the self-certifying raw-key method.
///
/// # Errors
///
/// Rejects any non-public packet or invalid method/key/identifier relationship.
#[wasm_bindgen(js_name = validateRawKeyPublicIdentityV2)]
pub fn validate_raw_key_public_identity_v2(packet: &[u8]) -> Result<IdentityFieldsV2, JsValue> {
    match IdentityPacket::decode(packet).map_err(js_error)? {
        IdentityPacket::PublicIdentity(identity) => identity
            .validate(&RawKeyIdentityMethod)
            .map(|validated| IdentityFieldsV2::from(validated.as_public_identity()))
            .map_err(js_error),
        IdentityPacket::SignedMessage(_) => Err(js_error("expected a public-identity packet")),
    }
}

/// Returns exact domain-separated bytes for caller-owned signing custody.
///
/// # Errors
///
/// Rejects a non-public identity packet or invalid message bounds.
#[wasm_bindgen(js_name = identityMessageSigningPreimageV2)]
pub fn identity_message_signing_preimage_v2(
    public_identity_packet: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, JsValue> {
    match IdentityPacket::decode(public_identity_packet).map_err(js_error)? {
        IdentityPacket::PublicIdentity(identity) => {
            SignedIdentityMessage::signing_preimage(&identity, message).map_err(js_error)
        }
        IdentityPacket::SignedMessage(_) => Err(js_error("expected a public-identity packet")),
    }
}

/// Encodes a signed identity message after external custody returns signature bytes.
///
/// This performs structural checks only. Use the suite-specific verification export before
/// treating the application bytes as authenticated.
///
/// # Errors
///
/// Rejects invalid packet, message, signature, or resource bounds.
#[wasm_bindgen(js_name = encodeSignedIdentityMessageV2)]
pub fn encode_signed_identity_message_v2(
    public_identity_packet: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let identity = match IdentityPacket::decode(public_identity_packet).map_err(js_error)? {
        IdentityPacket::PublicIdentity(identity) => identity,
        IdentityPacket::SignedMessage(_) => {
            return Err(js_error("expected a public-identity packet"));
        }
    };
    IdentityPacket::SignedMessage(
        SignedIdentityMessage::new(identity, message.to_vec(), signature.to_vec())
            .map_err(js_error)?,
    )
    .encode()
    .map_err(js_error)
}

/// Verifies a signed identity message with the raw-key method and Ed25519 suite adapter.
///
/// Success authenticates the exact message bytes. It grants no capability or authority.
///
/// # Errors
///
/// Rejects public-only packets, invalid identity relationships, suite mismatches, and signatures.
#[wasm_bindgen(js_name = verifyEd25519IdentityMessageV2)]
pub fn verify_ed25519_identity_message_v2(
    packet: &[u8],
) -> Result<AuthenticatedIdentityMessageV2, JsValue> {
    match IdentityPacket::decode(packet).map_err(js_error)? {
        IdentityPacket::PublicIdentity(_) => Err(js_error("expected a signed identity message")),
        IdentityPacket::SignedMessage(signed) => signed
            .verify(
                &RawKeyIdentityMethod,
                &auths_signature_ed25519::Ed25519Verifier,
            )
            .map(|authenticated| AuthenticatedIdentityMessageV2 {
                identity: IdentityFieldsV2::from(authenticated.identity().as_public_identity()),
                message: authenticated.message().to_vec(),
            })
            .map_err(js_error),
    }
}

/// Lossless bounded authority projection for one canonical signed grant.
#[wasm_bindgen]
pub struct SignedGrantAuthorityV1 {
    statement_cbor: Vec<u8>,
    grant_id: Vec<u8>,
    issuer: String,
    subject: String,
    profile_id: String,
    profile_version: u16,
    permission_capabilities: Vec<String>,
    permission_resources: Vec<String>,
    not_before: u64,
    expires_at: u64,
    audiences: Vec<String>,
    action_constraint: &'static str,
    action_digest_count: u32,
    has_budget: bool,
    budget_algebra: String,
    budget_value: u64,
    remaining_depth: u16,
    has_parent: bool,
    parent_id: Vec<u8>,
    status_policy: &'static str,
    status_method: String,
    status_max_age: u64,
    assurance_floor: String,
    critical_extensions: Vec<String>,
    signature_principal_method: String,
    signature_verification_method: String,
    signature_suite: String,
}

#[wasm_bindgen]
impl SignedGrantAuthorityV1 {
    /// Returns the canonical unsigned statement owned by this signed grant.
    #[must_use]
    #[wasm_bindgen(getter, js_name = statementCbor)]
    pub fn statement_cbor(&self) -> Vec<u8> {
        self.statement_cbor.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = grantId)]
    pub fn grant_id(&self) -> Vec<u8> {
        self.grant_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn issuer(&self) -> String {
        self.issuer.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn subject(&self) -> String {
        self.subject.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = profileId)]
    pub fn profile_id(&self) -> String {
        self.profile_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = profileVersion)]
    pub fn profile_version(&self) -> u16 {
        self.profile_version
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = permissionCapabilities)]
    pub fn permission_capabilities(&self) -> Vec<String> {
        self.permission_capabilities.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = permissionResources)]
    pub fn permission_resources(&self) -> Vec<String> {
        self.permission_resources.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = notBefore)]
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = expiresAt)]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn audiences(&self) -> Vec<String> {
        self.audiences.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = actionConstraint)]
    pub fn action_constraint(&self) -> String {
        self.action_constraint.to_owned()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = actionDigestCount)]
    pub fn action_digest_count(&self) -> u32 {
        self.action_digest_count
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = hasBudget)]
    pub fn has_budget(&self) -> bool {
        self.has_budget
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = budgetAlgebra)]
    pub fn budget_algebra(&self) -> String {
        self.budget_algebra.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = budgetValue)]
    pub fn budget_value(&self) -> u64 {
        self.budget_value
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = remainingDepth)]
    pub fn remaining_depth(&self) -> u16 {
        self.remaining_depth
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = hasParent)]
    pub fn has_parent(&self) -> bool {
        self.has_parent
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = parentId)]
    pub fn parent_id(&self) -> Vec<u8> {
        self.parent_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = statusPolicy)]
    pub fn status_policy(&self) -> String {
        self.status_policy.to_owned()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = statusMethod)]
    pub fn status_method(&self) -> String {
        self.status_method.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = statusMaxAge)]
    pub fn status_max_age(&self) -> u64 {
        self.status_max_age
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = assuranceFloor)]
    pub fn assurance_floor(&self) -> String {
        self.assurance_floor.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = criticalExtensions)]
    pub fn critical_extensions(&self) -> Vec<String> {
        self.critical_extensions.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = signaturePrincipalMethod)]
    pub fn signature_principal_method(&self) -> String {
        self.signature_principal_method.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = signatureVerificationMethod)]
    pub fn signature_verification_method(&self) -> String {
        self.signature_verification_method.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = signatureSuite)]
    pub fn signature_suite(&self) -> String {
        self.signature_suite.clone()
    }
}

/// Decodes one exact canonical signed grant into a bounded authority view.
///
/// This operation validates canonical structure and identifiers. Signature,
/// status, assurance, and chain verification remain part of authorization.
///
/// # Errors
///
/// Returns a JavaScript error for malformed, non-canonical, or over-limit
/// signed-grant input.
#[wasm_bindgen(js_name = inspectSignedGrantV1)]
pub fn inspect_signed_grant_v1(
    signed_grant_cbor: &[u8],
) -> Result<SignedGrantAuthorityV1, JsValue> {
    inspect_signed_grant_native(signed_grant_cbor).map_err(js_error)
}

/// Validates the structural root-authority bindings of one signed grant.
///
/// This operation requires a parentless grant whose issuer, subject, and
/// profile equal the caller's already-canonical trust and agent inputs. It
/// does not claim that the signature, status, assurance, or chain has passed
/// authorization verification.
///
/// # Errors
///
/// Returns a JavaScript error for malformed, non-canonical, over-limit, or
/// mismatched signed-grant input.
#[wasm_bindgen(js_name = validateRootAuthorityV1)]
pub fn validate_root_authority_v1(
    signed_grant_cbor: &[u8],
    root_principal: &str,
    subject_principal: &str,
    profile_id: &str,
    profile_version: u16,
) -> Result<SignedGrantAuthorityV1, JsValue> {
    validate_root_authority_native(
        signed_grant_cbor,
        root_principal,
        subject_principal,
        profile_id,
        profile_version,
    )
    .map_err(js_error)
}

fn validate_root_authority_native(
    signed_grant_cbor: &[u8],
    root_principal: &str,
    subject_principal: &str,
    profile_id: &str,
    profile_version: u16,
) -> Result<SignedGrantAuthorityV1, EngineError> {
    let authority = inspect_signed_grant_native(signed_grant_cbor)?;
    let root_principal = PrincipalId::parse(root_principal)?;
    let subject_principal = PrincipalId::parse(subject_principal)?;
    let profile_id = ProfileId::parse(profile_id)?;
    if authority.has_parent {
        return Err(EngineError::Abi(
            "root authority grant must not name a parent",
        ));
    }
    if authority.issuer != root_principal.as_str() {
        return Err(EngineError::Abi(
            "root authority grant issuer does not match the trusted root",
        ));
    }
    if authority.subject != subject_principal.as_str() {
        return Err(EngineError::Abi(
            "root authority grant subject does not match the attached agent",
        ));
    }
    if authority.profile_id != profile_id.as_str() || authority.profile_version != profile_version {
        return Err(EngineError::Abi(
            "root authority grant profile does not match the attached profile",
        ));
    }
    Ok(authority)
}

fn inspect_signed_grant_native(
    signed_grant_cbor: &[u8],
) -> Result<SignedGrantAuthorityV1, EngineError> {
    let grant =
        auths_codec::decode_signed_grant(signed_grant_cbor, &VerifierLimits::default_deployment())?;
    let statement = grant.statement();
    let grant_id = auths_codec::grant_id(statement)?.as_bytes().to_vec();
    let permission_capabilities = statement
        .permissions()
        .as_slice()
        .iter()
        .map(|permission| permission.capability().as_str().to_owned())
        .collect();
    let permission_resources = statement
        .permissions()
        .as_slice()
        .iter()
        .map(|permission| permission.resource().as_str().to_owned())
        .collect();
    let audiences = statement
        .audiences()
        .as_slice()
        .iter()
        .map(|audience| audience.as_str().to_owned())
        .collect();
    let (action_constraint, action_digest_count) = match statement.action_constraint() {
        ActionConstraint::AnyBody => ("any-body", 0),
        ActionConstraint::ExactBodyDigest(_) => ("exact-body", 1),
        ActionConstraint::AllowedBodyDigests(digests) => (
            "allowed-bodies",
            u32::try_from(digests.as_slice().len())
                .map_err(|_| EngineError::Abi("action digest count exceeds ABI"))?,
        ),
    };
    let (has_budget, budget_algebra, budget_value) = statement.budget_ceiling().map_or_else(
        || (false, String::new(), 0),
        |budget| (true, budget.algebra().as_str().to_owned(), budget.value()),
    );
    let (has_parent, parent_id) = statement.parent().map_or_else(
        || (false, Vec::new()),
        |parent| (true, parent.as_bytes().to_vec()),
    );
    let (status_policy, status_method, status_max_age) = match statement.status_policy() {
        StatusPolicy::ExpiryOnly => ("expiry-only", String::new(), 0),
        StatusPolicy::SnapshotRequired { method, max_age } => (
            "snapshot-required",
            method.as_str().to_owned(),
            max_age.get(),
        ),
    };
    let critical_extensions = statement
        .extensions()
        .as_slice()
        .iter()
        .map(|extension| extension.id().as_str().to_owned())
        .collect();
    let descriptor = grant.signature().descriptor();
    Ok(SignedGrantAuthorityV1 {
        statement_cbor: auths_codec::encode_grant_statement(statement)?,
        grant_id,
        issuer: statement.issuer().as_str().to_owned(),
        subject: statement.subject().as_str().to_owned(),
        profile_id: statement.profile().id().as_str().to_owned(),
        profile_version: statement.profile().version(),
        permission_capabilities,
        permission_resources,
        not_before: statement.validity().not_before().get(),
        expires_at: statement.validity().expires_at().get(),
        audiences,
        action_constraint,
        action_digest_count,
        has_budget,
        budget_algebra,
        budget_value,
        remaining_depth: statement.remaining_depth(),
        has_parent,
        parent_id,
        status_policy,
        status_method,
        status_max_age,
        assurance_floor: statement.assurance_floor().as_str().to_owned(),
        critical_extensions,
        signature_principal_method: descriptor.principal_method().as_str().to_owned(),
        signature_verification_method: descriptor.verification_method().as_str().to_owned(),
        signature_suite: descriptor.suite().as_str().to_owned(),
    })
}

/// Bounded output of native child-grant planning.
#[allow(clippy::struct_excessive_bools)]
#[wasm_bindgen]
pub struct GrantPlanV1 {
    statement_cbor: Vec<u8>,
    removed_permissions: u32,
    removed_audiences: u32,
    validity_shortened: bool,
    action_narrowed: bool,
    budget_narrowed: bool,
    status_narrowed: bool,
    parent_depth: u16,
    child_depth: u16,
    warning_mask: u32,
}

#[wasm_bindgen]
impl GrantPlanV1 {
    /// Returns the canonical, native-planned child statement.
    #[must_use]
    #[wasm_bindgen(getter, js_name = statementCbor)]
    pub fn statement_cbor(&self) -> Vec<u8> {
        self.statement_cbor.clone()
    }

    /// Returns how many parent permissions were removed.
    #[must_use]
    #[wasm_bindgen(getter, js_name = removedPermissions)]
    pub fn removed_permissions(&self) -> u32 {
        self.removed_permissions
    }

    /// Returns how many parent audiences were removed.
    #[must_use]
    #[wasm_bindgen(getter, js_name = removedAudiences)]
    pub fn removed_audiences(&self) -> u32 {
        self.removed_audiences
    }

    /// Reports whether the validity window was narrowed.
    #[must_use]
    #[wasm_bindgen(getter, js_name = validityShortened)]
    pub fn validity_shortened(&self) -> bool {
        self.validity_shortened
    }

    /// Reports whether the action-body constraint was narrowed.
    #[must_use]
    #[wasm_bindgen(getter, js_name = actionNarrowed)]
    pub fn action_narrowed(&self) -> bool {
        self.action_narrowed
    }

    /// Reports whether the budget ceiling was narrowed.
    #[must_use]
    #[wasm_bindgen(getter, js_name = budgetNarrowed)]
    pub fn budget_narrowed(&self) -> bool {
        self.budget_narrowed
    }

    /// Reports whether the status policy was narrowed.
    #[must_use]
    #[wasm_bindgen(getter, js_name = statusNarrowed)]
    pub fn status_narrowed(&self) -> bool {
        self.status_narrowed
    }

    /// Returns the parent delegation depth.
    #[must_use]
    #[wasm_bindgen(getter, js_name = parentDepth)]
    pub fn parent_depth(&self) -> u16 {
        self.parent_depth
    }

    /// Returns the planned child delegation depth.
    #[must_use]
    #[wasm_bindgen(getter, js_name = childDepth)]
    pub fn child_depth(&self) -> u16 {
        self.child_depth
    }

    /// Returns the stable V1 warning bit-set.
    #[must_use]
    #[wasm_bindgen(getter, js_name = warningMask)]
    pub fn warning_mask(&self) -> u32 {
        self.warning_mask
    }
}

/// Plans one strictly non-widening child grant from canonical V1 statements.
///
/// The proposal's issuer and parent fields are ignored. Native authoring
/// derives them from `parent_grant_cbor`.
///
/// # Errors
///
/// Returns a JavaScript error for malformed, non-canonical, over-limit, or
/// widening input.
#[wasm_bindgen(js_name = planChildGrantV1)]
pub fn plan_child_grant_v1(
    parent_grant_cbor: &[u8],
    proposed_child_cbor: &[u8],
) -> Result<GrantPlanV1, JsValue> {
    plan_child_grant_native(parent_grant_cbor, proposed_child_cbor).map_err(js_error)
}

/// Plans a child grant from bounded workflow fields without caller-authored CBOR.
///
/// Profile and critical extensions are inherited exactly from the parent.
/// Issuer and parent linkage are derived by native authoring. Optional fields
/// use the closed modes documented by the authoring ABI manifest.
///
/// # Errors
///
/// Returns a JavaScript error for malformed identifiers, inconsistent field
/// arrays, invalid modes, over-limit input, or any widened authority.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = planChildGrantFieldsV1)]
pub fn plan_child_grant_fields_v1(
    parent_grant_cbor: &[u8],
    subject: &str,
    permission_capabilities: Vec<String>,
    permission_resources: Vec<String>,
    not_before: u64,
    expires_at: u64,
    audiences: Vec<String>,
    action_mode: &str,
    action_digests: &[u8],
    budget_mode: &str,
    budget_algebra: &str,
    budget_value: u64,
    remaining_depth: u16,
    status_mode: &str,
    status_method: &str,
    status_max_age: u64,
    assurance_floor: &str,
) -> Result<GrantPlanV1, JsValue> {
    plan_child_grant_fields_native(
        parent_grant_cbor,
        subject,
        permission_capabilities,
        permission_resources,
        not_before,
        expires_at,
        audiences,
        action_mode,
        action_digests,
        budget_mode,
        budget_algebra,
        budget_value,
        remaining_depth,
        status_mode,
        status_method,
        status_max_age,
        assurance_floor,
    )
    .map_err(js_error)
}

/// Commits to already-canonical bytes under an explicit application domain.
///
/// # Errors
///
/// Returns a JavaScript error when the domain or payload exceeds limits.
#[wasm_bindgen(js_name = commitCanonicalV1)]
pub fn commit_canonical_v1(domain: &str, canonical: &[u8]) -> Result<Vec<u8>, JsValue> {
    auths_codec::domain_commitment(domain, canonical)
        .map(|digest| digest.as_bytes().to_vec())
        .map_err(js_error)
}

/// Commits to one exact executable approval configuration.
///
/// # Errors
///
/// Returns a JavaScript error for an out-of-limit or repeated requirement set.
// wasm-bindgen marshals a JavaScript string array as an owned Vec<String>.
#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen(js_name = commitApprovalPolicyV1)]
pub fn commit_approval_policy_v1(
    mode: &str,
    max_uses: u32,
    expires_in_seconds: u32,
    requirements: Vec<String>,
) -> Result<Vec<u8>, JsValue> {
    let borrowed: Vec<&str> = requirements.iter().map(String::as_str).collect();
    ApprovalPolicyCommitment::commit(mode, max_uses, expires_in_seconds, &borrowed)
        .map(|digest| digest.as_bytes().to_vec())
        .map_err(js_error)
}

/// Binds one plan approval to the plan, policy, and expiry it covered.
///
/// # Errors
///
/// Returns a JavaScript error for out-of-limit or wrong-width inputs.
#[wasm_bindgen(js_name = commitPlanApprovalV1)]
pub fn commit_plan_approval_v1(
    plan_commitment: &[u8],
    configuration_digest: &[u8],
    max_uses: u32,
    expires_at: u64,
) -> Result<Vec<u8>, JsValue> {
    let plan: [u8; 32] = plan_commitment
        .try_into()
        .map_err(|_| js_error(EngineError::Abi("plan commitment must be 32 bytes")))?;
    let configuration: [u8; 32] = configuration_digest
        .try_into()
        .map_err(|_| js_error(EngineError::Abi("configuration digest must be 32 bytes")))?;
    commit_plan_approval(&plan, &configuration, max_uses, expires_at)
        .map(|digest| digest.as_bytes().to_vec())
        .map_err(js_error)
}

/// Ordered plan and per-member commitments for one profile.
#[wasm_bindgen]
pub struct ProfilePlanCommitmentV1 {
    plan: Vec<u8>,
    members: Vec<u8>,
    member_count: usize,
}

#[wasm_bindgen]
impl ProfilePlanCommitmentV1 {
    /// Returns the commitment over the whole ordered plan.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn plan(&self) -> Vec<u8> {
        self.plan.clone()
    }

    /// Returns every member commitment concatenated in plan order.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn members(&self) -> Vec<u8> {
        self.members.clone()
    }

    /// Returns how many members the plan commits to.
    #[must_use]
    #[wasm_bindgen(getter, js_name = memberCount)]
    pub fn member_count(&self) -> usize {
        self.member_count
    }
}

/// Commits to an ordered profile-plan membership.
///
/// Members arrive concatenated with their exact lengths, so the boundary
/// carries no per-member JavaScript object.
///
/// # Errors
///
/// Returns a JavaScript error when the profile or membership exceeds limits,
/// or when the declared lengths do not consume the buffer exactly.
#[wasm_bindgen(js_name = commitProfilePlanV1)]
pub fn commit_profile_plan_v1(
    profile_id: &str,
    profile_version: u16,
    members: &[u8],
    member_lengths: &[u32],
) -> Result<ProfilePlanCommitmentV1, JsValue> {
    let mut borrowed: Vec<&[u8]> = Vec::with_capacity(member_lengths.len());
    let mut offset = 0_usize;
    for length in member_lengths {
        let length = *length as usize;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| js_error(EngineError::Abi("plan member lengths overflow")))?;
        if end > members.len() {
            return Err(js_error(EngineError::Abi(
                "plan member lengths exceed the supplied buffer",
            )));
        }
        borrowed.push(&members[offset..end]);
        offset = end;
    }
    if offset != members.len() {
        return Err(js_error(EngineError::Abi(
            "plan member lengths do not consume the supplied buffer",
        )));
    }
    let commitment =
        ProfilePlanCommitment::commit(profile_id, profile_version, &borrowed).map_err(js_error)?;
    let mut flattened = Vec::with_capacity(commitment.members().len() * 32);
    for member in commitment.members() {
        flattened.extend_from_slice(member.as_bytes());
    }
    Ok(ProfilePlanCommitmentV1 {
        plan: commitment.plan().as_bytes().to_vec(),
        members: flattened,
        member_count: commitment.members().len(),
    })
}

/// Canonicalizes one MCP plan member from typed JavaScript argument values.
///
/// # Errors
///
/// Returns a JavaScript error when the arguments are not a bounded JSON
/// object or any profile field is invalid.
#[wasm_bindgen(js_name = canonicalizeMcpPlanMemberV1)]
pub fn canonicalize_mcp_plan_member_v1(
    service: &str,
    name: &str,
    arguments: &JsValue,
) -> Result<Vec<u8>, JsValue> {
    canonicalize_mcp_plan_member_native(service, name, arguments).map_err(js_error)
}

/// Canonicalizes one application-profile plan member from typed fields.
///
/// # Errors
///
/// Returns a JavaScript error for invalid or out-of-limit profile fields.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = canonicalizeProfilePlanMemberV1)]
pub fn canonicalize_profile_plan_member_v1(
    profile_id: &str,
    profile_version: u16,
    media_type: &str,
    body: &[u8],
    capability: &str,
    resource: &str,
    has_budget: bool,
    budget_algebra: &str,
    budget_value: u64,
    resource_namespace: &str,
    audience: &str,
) -> Result<Vec<u8>, JsValue> {
    canonicalize_profile_plan_member_native(
        profile_id,
        profile_version,
        media_type,
        body,
        capability,
        resource,
        has_budget,
        budget_algebra,
        budget_value,
        resource_namespace,
        audience,
    )
    .map_err(js_error)
}

/// Exact native signing request returned to an external custody port.
#[wasm_bindgen]
pub struct AuthoringSigningRequestV1 {
    object_kind: &'static str,
    request_id: String,
    object_id: Vec<u8>,
    signing_preimage: Vec<u8>,
    transaction_digest: Vec<u8>,
}

#[wasm_bindgen]
impl AuthoringSigningRequestV1 {
    /// Returns the closed signed-object kind.
    #[must_use]
    #[wasm_bindgen(getter, js_name = objectKind)]
    pub fn object_kind(&self) -> String {
        self.object_kind.to_owned()
    }

    /// Returns the exact identifier custody and approval ports echo back.
    ///
    /// The format belongs to `auths-author`; bindings carry it unchanged.
    #[must_use]
    #[wasm_bindgen(getter, js_name = requestId)]
    pub fn request_id(&self) -> String {
        self.request_id.clone()
    }

    /// Returns the exact unsigned object identifier.
    #[must_use]
    #[wasm_bindgen(getter, js_name = objectId)]
    pub fn object_id(&self) -> Vec<u8> {
        self.object_id.clone()
    }

    /// Returns the exact domain-separated bytes supplied to custody.
    #[must_use]
    #[wasm_bindgen(getter, js_name = signingPreimage)]
    pub fn signing_preimage(&self) -> Vec<u8> {
        self.signing_preimage.clone()
    }

    /// Returns the transaction binding a custody port must echo back.
    ///
    /// Bindings commit to this value instead of restating the rule, so no
    /// language recomputes what the preimage binds to.
    #[must_use]
    #[wasm_bindgen(getter, js_name = transactionDigest)]
    pub fn transaction_digest(&self) -> Vec<u8> {
        self.transaction_digest.clone()
    }
}

/// Prepares exact grant signing bytes from canonical unsigned CBOR.
///
/// # Errors
///
/// Returns a JavaScript error for invalid input or descriptor identifiers.
#[wasm_bindgen(js_name = prepareGrantSigningV1)]
pub fn prepare_grant_signing_v1(
    statement_cbor: &[u8],
    principal_method: &str,
    verification_method: &str,
    suite: &str,
) -> Result<AuthoringSigningRequestV1, JsValue> {
    let limits = VerifierLimits::default_deployment();
    let statement =
        auths_codec::decode_grant_statement(statement_cbor, &limits).map_err(js_error)?;
    let request = prepare_grant(
        statement,
        signing_descriptor(principal_method, verification_method, suite).map_err(js_error)?,
    )
    .map_err(js_error)?;
    Ok(signing_request(&request))
}

/// Prepares exact action signing bytes from canonical unsigned CBOR.
///
/// # Errors
///
/// Returns a JavaScript error for invalid input or descriptor identifiers.
#[wasm_bindgen(js_name = prepareActionSigningV1)]
pub fn prepare_action_signing_v1(
    envelope_cbor: &[u8],
    principal_method: &str,
    verification_method: &str,
    suite: &str,
) -> Result<AuthoringSigningRequestV1, JsValue> {
    let limits = VerifierLimits::default_deployment();
    let envelope = auths_codec::decode_action_envelope(envelope_cbor, &limits).map_err(js_error)?;
    let request = prepare_action(
        envelope,
        signing_descriptor(principal_method, verification_method, suite).map_err(js_error)?,
    )
    .map_err(js_error)?;
    Ok(signing_request(&request))
}

/// Prepares exact principal-status signing bytes from canonical unsigned CBOR.
///
/// # Errors
///
/// Returns a JavaScript error for invalid input or descriptor identifiers.
#[wasm_bindgen(js_name = preparePrincipalStatusSigningV1)]
pub fn prepare_principal_status_signing_v1(
    statement_cbor: &[u8],
    principal_method: &str,
    verification_method: &str,
    suite: &str,
) -> Result<AuthoringSigningRequestV1, JsValue> {
    let limits = VerifierLimits::default_deployment();
    let statement = auths_codec::decode_principal_status_statement(statement_cbor, &limits)
        .map_err(js_error)?;
    let request = prepare_principal_status(
        statement,
        signing_descriptor(principal_method, verification_method, suite).map_err(js_error)?,
    )
    .map_err(js_error)?;
    Ok(signing_request(&request))
}

/// Prepares exact grant-status signing bytes from canonical unsigned CBOR.
///
/// # Errors
///
/// Returns a JavaScript error for invalid input or descriptor identifiers.
#[wasm_bindgen(js_name = prepareGrantStatusSigningV1)]
pub fn prepare_grant_status_signing_v1(
    statement_cbor: &[u8],
    principal_method: &str,
    verification_method: &str,
    suite: &str,
) -> Result<AuthoringSigningRequestV1, JsValue> {
    let limits = VerifierLimits::default_deployment();
    let statement =
        auths_codec::decode_grant_status_statement(statement_cbor, &limits).map_err(js_error)?;
    let request = prepare_grant_status(
        statement,
        signing_descriptor(principal_method, verification_method, suite).map_err(js_error)?,
    )
    .map_err(js_error)?;
    Ok(signing_request(&request))
}

/// Completes one grant with a signature over the exact prepared preimage.
///
/// # Errors
///
/// Returns a JavaScript error for invalid canonical input, descriptor, or
/// bounded signature bytes.
#[wasm_bindgen(js_name = completeGrantSigningV1)]
pub fn complete_grant_signing_v1(
    statement_cbor: &[u8],
    principal_method: &str,
    verification_method: &str,
    suite: &str,
    signature: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let limits = VerifierLimits::default_deployment();
    let statement =
        auths_codec::decode_grant_statement(statement_cbor, &limits).map_err(js_error)?;
    let request = prepare_grant(
        statement,
        signing_descriptor(principal_method, verification_method, suite).map_err(js_error)?,
    )
    .map_err(js_error)?;
    let signed = request.complete(SignatureBytes::new(signature.to_vec()).map_err(js_error)?);
    auths_codec::encode_signed_grant(&signed).map_err(js_error)
}

/// Completes one action with a signature over the exact prepared preimage.
///
/// # Errors
///
/// Returns a JavaScript error for invalid canonical input, descriptor, or
/// bounded signature bytes.
#[wasm_bindgen(js_name = completeActionSigningV1)]
pub fn complete_action_signing_v1(
    envelope_cbor: &[u8],
    principal_method: &str,
    verification_method: &str,
    suite: &str,
    signature: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let limits = VerifierLimits::default_deployment();
    let envelope = auths_codec::decode_action_envelope(envelope_cbor, &limits).map_err(js_error)?;
    let request = prepare_action(
        envelope,
        signing_descriptor(principal_method, verification_method, suite).map_err(js_error)?,
    )
    .map_err(js_error)?;
    let signed = request.complete(SignatureBytes::new(signature.to_vec()).map_err(js_error)?);
    auths_codec::encode_signed_action(&signed).map_err(js_error)
}

/// Completes one principal-status statement with an exact signature.
///
/// # Errors
///
/// Returns a JavaScript error for invalid canonical input, descriptor, or
/// bounded signature bytes.
#[wasm_bindgen(js_name = completePrincipalStatusSigningV1)]
pub fn complete_principal_status_signing_v1(
    statement_cbor: &[u8],
    principal_method: &str,
    verification_method: &str,
    suite: &str,
    signature: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let limits = VerifierLimits::default_deployment();
    let statement = auths_codec::decode_principal_status_statement(statement_cbor, &limits)
        .map_err(js_error)?;
    let request = prepare_principal_status(
        statement,
        signing_descriptor(principal_method, verification_method, suite).map_err(js_error)?,
    )
    .map_err(js_error)?;
    let signed = request.complete(SignatureBytes::new(signature.to_vec()).map_err(js_error)?);
    auths_codec::encode_signed_principal_status(&signed).map_err(js_error)
}

/// Completes one grant-status statement with an exact signature.
///
/// # Errors
///
/// Returns a JavaScript error for invalid canonical input, descriptor, or
/// bounded signature bytes.
#[wasm_bindgen(js_name = completeGrantStatusSigningV1)]
pub fn complete_grant_status_signing_v1(
    statement_cbor: &[u8],
    principal_method: &str,
    verification_method: &str,
    suite: &str,
    signature: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let limits = VerifierLimits::default_deployment();
    let statement =
        auths_codec::decode_grant_status_statement(statement_cbor, &limits).map_err(js_error)?;
    let request = prepare_grant_status(
        statement,
        signing_descriptor(principal_method, verification_method, suite).map_err(js_error)?,
    )
    .map_err(js_error)?;
    let signed = request.complete(SignatureBytes::new(signature.to_vec()).map_err(js_error)?);
    auths_codec::encode_signed_grant_status(&signed).map_err(js_error)
}

/// Binds one exact request to a canonical trusted-context template.
///
/// # Errors
///
/// Returns a JavaScript error for malformed context, audience, or challenge.
#[wasm_bindgen(js_name = bindTrustedContextRequestV1)]
pub fn bind_trusted_context_request_v1(
    trusted_context_cbor: &[u8],
    audience: &str,
    challenge: &[u8],
    evaluation_time: u64,
) -> Result<Vec<u8>, JsValue> {
    bind_trusted_context_request_native(trusted_context_cbor, audience, challenge, evaluation_time)
        .map_err(js_error)
}

/// Native MCP action preparation retained across exact external signing.
#[wasm_bindgen]
pub struct McpActionPreparationV1 {
    canonical_action_cbor: Vec<u8>,
    action_envelope_cbor: Vec<u8>,
    arguments_json: Vec<u8>,
    audience: String,
    resource: String,
    display_digest_hex: String,
}

#[wasm_bindgen]
impl McpActionPreparationV1 {
    /// Returns the exact canonical action consumed by verification.
    #[must_use]
    #[wasm_bindgen(getter, js_name = canonicalActionCbor)]
    pub fn canonical_action_cbor(&self) -> Vec<u8> {
        self.canonical_action_cbor.clone()
    }

    /// Returns the exact unsigned action envelope consumed by signing.
    #[must_use]
    #[wasm_bindgen(getter, js_name = actionEnvelopeCbor)]
    pub fn action_envelope_cbor(&self) -> Vec<u8> {
        self.action_envelope_cbor.clone()
    }

    /// Returns the exact canonical argument JSON accepted by the profile.
    #[must_use]
    #[wasm_bindgen(getter, js_name = argumentsJson)]
    pub fn arguments_json(&self) -> Vec<u8> {
        self.arguments_json.clone()
    }

    /// Returns the profile-derived verifier audience.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn audience(&self) -> String {
        self.audience.clone()
    }

    /// Returns the profile-derived resource.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn resource(&self) -> String {
        self.resource.clone()
    }

    /// Returns the digest represented by the profile review display.
    #[must_use]
    #[wasm_bindgen(getter, js_name = displayDigestHex)]
    pub fn display_digest_hex(&self) -> String {
        self.display_digest_hex.clone()
    }
}

/// Canonicalizes one closed MCP call and prepares its exact action envelope.
///
/// # Errors
///
/// Returns a JavaScript error for malformed arguments, invalid profile
/// identifiers, an invalid actor/challenge, or a malformed terminal grant.
#[wasm_bindgen(js_name = prepareMcpActionV1)]
pub fn prepare_mcp_action_v1(
    service: &str,
    name: &str,
    arguments: &JsValue,
    actor: &str,
    terminal_grant_cbor: &[u8],
    challenge: &[u8],
    evaluation_time: u64,
) -> Result<McpActionPreparationV1, JsValue> {
    let arguments = mcp_arguments_from_js(arguments).map_err(js_error)?;
    prepare_mcp_action_native(
        service,
        name,
        arguments,
        actor,
        terminal_grant_cbor,
        challenge,
        evaluation_time,
    )
    .map_err(js_error)
}

/// Native action preparation for an application-owned closed profile.
#[wasm_bindgen]
pub struct ProfileActionPreparationV1 {
    canonical_action_cbor: Vec<u8>,
    action_envelope_cbor: Vec<u8>,
    audience: String,
    resource: String,
}

/// Unsigned root grant and matching self-contained raw-key trust context.
#[wasm_bindgen]
pub struct RawKeyAuthorityPreparationV1 {
    statement_cbor: Vec<u8>,
    trusted_context_cbor: Vec<u8>,
    verifier_configuration: Vec<u8>,
}

/// Native raw-key identity fields derived from one Ed25519 public key.
#[wasm_bindgen]
pub struct RawKeyIdentityV1 {
    principal: String,
    evidence: Vec<u8>,
    principal_method: String,
    media_type: String,
    suite: String,
}

#[wasm_bindgen]
impl RawKeyIdentityV1 {
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn principal(&self) -> String {
        self.principal.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn evidence(&self) -> Vec<u8> {
        self.evidence.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = principalMethod)]
    pub fn principal_method(&self) -> String {
        self.principal_method.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = verificationMethod)]
    pub fn verification_method(&self) -> String {
        self.principal.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = mediaType)]
    pub fn media_type(&self) -> String {
        self.media_type.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn suite(&self) -> String {
        self.suite.clone()
    }
}

/// Derives the canonical raw-key descriptor and self-certifying identity.
///
/// # Errors
///
/// Returns a JavaScript error unless the public key is exactly one Ed25519
/// verification key.
#[wasm_bindgen(js_name = deriveEd25519RawKeyIdentityV1)]
pub fn derive_ed25519_raw_key_identity_v1(public_key: &[u8]) -> Result<RawKeyIdentityV1, JsValue> {
    let descriptor = auths_raw_key::RawKeyDescriptor::new(
        auths_raw_key::RawKeyType::Ed25519,
        public_key.to_vec(),
    )
    .map_err(|_| js_error("invalid Ed25519 raw-key descriptor"))?;
    let principal = descriptor
        .principal()
        .map_err(|_| js_error("raw-key principal derivation failed"))?
        .to_string();
    Ok(RawKeyIdentityV1 {
        principal,
        evidence: descriptor.encode(),
        principal_method: auths_raw_key::RAW_KEY_V1.to_owned(),
        media_type: auths_raw_key::RAW_KEY_MEDIA_TYPE.to_owned(),
        suite: descriptor.suite().to_owned(),
    })
}

#[wasm_bindgen]
impl RawKeyAuthorityPreparationV1 {
    /// Returns the unsigned canonical root-grant statement.
    #[must_use]
    #[wasm_bindgen(getter, js_name = statementCbor)]
    pub fn statement_cbor(&self) -> Vec<u8> {
        self.statement_cbor.clone()
    }

    /// Returns the matching immutable trusted-context template.
    #[must_use]
    #[wasm_bindgen(getter, js_name = trustedContextCbor)]
    pub fn trusted_context_cbor(&self) -> Vec<u8> {
        self.trusted_context_cbor.clone()
    }

    /// Returns the exact packaged-verifier configuration commitment.
    #[must_use]
    #[wasm_bindgen(getter, js_name = verifierConfiguration)]
    pub fn verifier_configuration(&self) -> Vec<u8> {
        self.verifier_configuration.clone()
    }
}

/// Plans a root grant and matching local raw-key verifier context.
///
/// This is an explicit self-contained bootstrap profile for local and
/// headless deployments. It does not generate, import, or retain private key
/// material; the returned statement must still pass through an external
/// signer and approval provider.
///
/// # Errors
///
/// Returns a JavaScript error for invalid or unbounded authority fields.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = prepareRawKeyAuthorityV1)]
pub fn prepare_raw_key_authority_v1(
    root: &str,
    subject: &str,
    profile_id: &str,
    profile_version: u16,
    permission_capabilities: Vec<String>,
    permission_resources: Vec<String>,
    resource_namespaces: Vec<String>,
    not_before: u64,
    expires_at: u64,
    audiences: Vec<String>,
    has_budget: bool,
    budget_algebra: &str,
    budget_value: u64,
    remaining_depth: u16,
) -> Result<RawKeyAuthorityPreparationV1, JsValue> {
    prepare_raw_key_authority_native(
        root,
        subject,
        profile_id,
        profile_version,
        permission_capabilities,
        permission_resources,
        resource_namespaces,
        not_before,
        expires_at,
        audiences,
        has_budget,
        budget_algebra,
        budget_value,
        remaining_depth,
    )
    .map_err(js_error)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn prepare_raw_key_authority_native(
    root: &str,
    subject: &str,
    profile_id: &str,
    profile_version: u16,
    permission_capabilities: Vec<String>,
    permission_resources: Vec<String>,
    resource_namespaces: Vec<String>,
    not_before: u64,
    expires_at: u64,
    audiences: Vec<String>,
    has_budget: bool,
    budget_algebra: &str,
    budget_value: u64,
    remaining_depth: u16,
) -> Result<RawKeyAuthorityPreparationV1, EngineError> {
    let root = PrincipalId::parse(root)?;
    let subject = PrincipalId::parse(subject)?;
    let profile = auths_model::ProfileRef::new(ProfileId::parse(profile_id)?, profile_version)?;
    let permissions = permission_set(permission_capabilities, permission_resources)?;
    let audiences = AudienceSet::new(
        audiences
            .into_iter()
            .map(|value| Audience::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let expected_audience = audiences
        .as_slice()
        .first()
        .ok_or(EngineError::Abi("authority must contain an audience"))?
        .clone();
    let validity = ValidityWindow::new(Timestamp::new(not_before), Timestamp::new(expires_at))?;
    let budget = if has_budget {
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse(budget_algebra)?,
            budget_value,
        ))
    } else {
        None
    };
    let assurance_id = AssurancePolicyId::parse("raw-key-baseline")?;
    let statement = auths_model::GrantStatement::new(
        root.clone(),
        subject,
        profile.clone(),
        permissions.clone(),
        validity,
        audiences.clone(),
        ActionConstraint::AnyBody,
        budget.clone(),
        remaining_depth,
        None,
        StatusPolicy::ExpiryOnly,
        assurance_id.clone(),
        CriticalExtensions::empty(),
    );
    let namespaces = resource_namespaces
        .into_iter()
        .map(|value| ResourceId::parse(&value))
        .collect::<Result<Vec<_>, _>>()?;
    let anchor = auths_model::TrustAnchor::new(
        auths_model::TrustAnchorId::parse(root.as_str())?,
        root,
        vec![PrincipalMethodId::parse(auths_raw_key::RAW_KEY_V1)?],
        vec![profile.clone()],
        permissions,
        namespaces,
        audiences,
        validity,
        budget.clone(),
        remaining_depth
            .checked_add(1)
            .ok_or(EngineError::Abi("root delegation depth exceeds bounds"))?,
        assurance_id.clone(),
        StatusPolicy::ExpiryOnly,
    )?;
    let claim = auths_model::AssuranceClaimId::parse("self-certifying-identifier")?;
    let assurance = auths_model::AssurancePolicy::new(
        assurance_id,
        vec![
            auths_model::AssuranceRequirement::new(
                auths_model::ParticipantRole::Root,
                auths_model::AssuranceQuantifier::Every,
                claim.clone(),
                None,
            ),
            auths_model::AssuranceRequirement::new(
                auths_model::ParticipantRole::Actor,
                auths_model::AssuranceQuantifier::Every,
                claim.clone(),
                None,
            ),
        ],
    )?;
    let registries = auths_model::AcceptedRegistries::new(
        auths_registries::TARGET_V1_REGISTRY_MANIFEST,
        vec![PrincipalMethodId::parse(auths_raw_key::RAW_KEY_V1)?],
        vec![SignatureSuiteId::parse("ed25519-v1")?],
        vec![EvidenceTypeId::parse(auths_raw_key::RAW_KEY_V1)?],
        Vec::new(),
        Vec::new(),
        vec![
            claim,
            auths_model::AssuranceClaimId::parse("offline-verifiable")?,
        ],
        Vec::new(),
        vec![auths_model::ResourceMatcherId::parse(
            auths_registries::URI_NAMESPACE_V1,
        )?],
        budget
            .as_ref()
            .map(|value| vec![value.algebra().clone()])
            .unwrap_or_default(),
        Vec::new(),
        vec![profile],
        vec![auths_model::ProfilePolicyId::parse(
            auths_registries::EXACT_PROFILE_V1,
        )?],
    )?;
    let context = auths_model::VerifierContext::new(
        VerifierConfigurationId::new(self_contained_v1_configuration()?),
        CompositionRequirement::new(None, 1, 1, 1)?,
        vec![anchor],
        registries,
        expected_audience,
        Challenge::new([0; 32]),
        Timestamp::new(not_before),
        assurance,
        auths_model::PrincipalStatusSnapshot::new(
            auths_model::StatusSnapshotId::new([0x44; 32]),
            Timestamp::new(not_before),
            Timestamp::new(expires_at),
            Vec::new(),
            Vec::new(),
        )?,
        auths_model::GrantStatusSnapshot::new(
            auths_model::StatusSnapshotId::new([0x55; 32]),
            Timestamp::new(not_before),
            Timestamp::new(expires_at),
            Vec::new(),
            Vec::new(),
        )?,
        auths_model::ResourceMatcherId::parse(auths_registries::URI_NAMESPACE_V1)?,
        auths_model::ProfilePolicyId::parse(auths_registries::EXACT_PROFILE_V1)?,
        ChannelBindingId::parse("none-v1")?,
        VerifierLimits::default_deployment(),
    )?;
    Ok(RawKeyAuthorityPreparationV1 {
        statement_cbor: auths_codec::encode_grant_statement(&statement)?,
        trusted_context_cbor: auths_codec::encode_verifier_context(&context)?,
        verifier_configuration: self_contained_v1_configuration()?.to_vec(),
    })
}

fn permission_set(
    capabilities: Vec<String>,
    resources: Vec<String>,
) -> Result<PermissionSet, EngineError> {
    if capabilities.len() != resources.len() {
        return Err(EngineError::Abi(
            "permission capability and resource counts differ",
        ));
    }
    PermissionSet::new(
        capabilities
            .into_iter()
            .zip(resources)
            .map(|(capability, resource)| {
                Ok(Permission::new(
                    CapabilityId::parse(&capability)?,
                    ResourceId::parse(&resource)?,
                ))
            })
            .collect::<Result<Vec<_>, auths_model::ModelError>>()?,
    )
    .map_err(EngineError::from)
}

#[wasm_bindgen]
impl ProfileActionPreparationV1 {
    /// Returns the exact canonical action consumed by verification.
    #[must_use]
    #[wasm_bindgen(getter, js_name = canonicalActionCbor)]
    pub fn canonical_action_cbor(&self) -> Vec<u8> {
        self.canonical_action_cbor.clone()
    }

    /// Returns the exact unsigned action envelope consumed by signing.
    #[must_use]
    #[wasm_bindgen(getter, js_name = actionEnvelopeCbor)]
    pub fn action_envelope_cbor(&self) -> Vec<u8> {
        self.action_envelope_cbor.clone()
    }

    /// Returns the profile-selected verifier audience after validation.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn audience(&self) -> String {
        self.audience.clone()
    }

    /// Returns the profile-derived resource after validation.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn resource(&self) -> String {
        self.resource.clone()
    }
}

/// Prepares one action whose semantics were canonicalized by an
/// application-owned closed profile.
///
/// This boundary constructs protocol objects only. It does not interpret an
/// operation tag, select an executor, or turn an authorized result into an
/// effect-capable command.
///
/// # Errors
///
/// Returns a JavaScript error for an invalid profile, media type, permission,
/// budget, audience, actor, challenge, or terminal grant.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = prepareProfileActionV1)]
pub fn prepare_profile_action_v1(
    profile_id: &str,
    profile_version: u16,
    media_type: &str,
    body: &[u8],
    capability: &str,
    resource: &str,
    has_budget: bool,
    budget_algebra: &str,
    budget_value: u64,
    audience: &str,
    actor: &str,
    terminal_grant_cbor: &[u8],
    challenge: &[u8],
    evaluation_time: u64,
) -> Result<ProfileActionPreparationV1, JsValue> {
    prepare_profile_action_native(
        profile_id,
        profile_version,
        media_type,
        body,
        capability,
        resource,
        has_budget,
        budget_algebra,
        budget_value,
        audience,
        actor,
        terminal_grant_cbor,
        challenge,
        evaluation_time,
    )
    .map_err(js_error)
}

#[allow(clippy::too_many_arguments)]
fn prepare_profile_action_native(
    profile_id: &str,
    profile_version: u16,
    media_type: &str,
    body: &[u8],
    capability: &str,
    resource: &str,
    has_budget: bool,
    budget_algebra: &str,
    budget_value: u64,
    audience: &str,
    actor: &str,
    terminal_grant_cbor: &[u8],
    challenge: &[u8],
    evaluation_time: u64,
) -> Result<ProfileActionPreparationV1, EngineError> {
    let canonical = canonical_profile_action_native(
        profile_id,
        profile_version,
        media_type,
        body,
        capability,
        resource,
        has_budget,
        budget_algebra,
        budget_value,
    )?;
    let profile = canonical.profile().clone();
    let permission = canonical.permission().clone();
    let requested_budget = canonical.requested_budget().cloned();
    let terminal_grant = auths_codec::decode_signed_grant(
        terminal_grant_cbor,
        &VerifierLimits::default_deployment(),
    )?;
    let challenge: [u8; 32] = challenge
        .try_into()
        .map_err(|_| EngineError::Abi("challenge must contain exactly 32 bytes"))?;
    let proof_ref = ProofRef::new(challenge);
    let plan = AuthorizationPlan::proof(proof_ref);
    let audience = Audience::parse(audience)?;
    let envelope = ActionEnvelope::new(
        profile,
        MediaType::parse(media_type)?,
        auths_codec::body_digest(body),
        permission,
        requested_budget,
        audience.clone(),
        Challenge::new(challenge),
        ValidityWindow::new(
            Timestamp::new(evaluation_time),
            Timestamp::new(evaluation_time),
        )?,
        PrincipalId::parse(actor)?,
        Some(auths_codec::grant_id(terminal_grant.statement())?),
        auths_codec::plan_id(&plan)?,
        ChannelBindingId::parse("none-v1")?,
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    Ok(ProfileActionPreparationV1 {
        canonical_action_cbor: auths_codec::encode_canonical_action(&canonical)?,
        action_envelope_cbor: auths_codec::encode_action_envelope(&envelope)?,
        audience: audience.to_string(),
        resource: canonical.permission().resource().to_string(),
    })
}

fn prepare_mcp_action_native(
    service: &str,
    name: &str,
    arguments: Map<String, Value>,
    actor: &str,
    terminal_grant_cbor: &[u8],
    challenge: &[u8],
    evaluation_time: u64,
) -> Result<McpActionPreparationV1, EngineError> {
    let call = McpToolCall::new(service, name, arguments)?;
    let untrusted = call.canonical_bytes()?;
    let profile = McpProfile;
    let canonical = profile.canonicalize(&untrusted)?;
    let display = profile.review_display(&canonical)?;
    let limits = VerifierLimits::default_deployment();
    let terminal_grant = auths_codec::decode_signed_grant(terminal_grant_cbor, &limits)?;
    let challenge: [u8; 32] = challenge
        .try_into()
        .map_err(|_| EngineError::Abi("challenge must contain exactly 32 bytes"))?;
    let proof_ref = ProofRef::new(challenge);
    let plan = AuthorizationPlan::proof(proof_ref);
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        auths_codec::body_digest(canonical.body()),
        canonical.permission().clone(),
        canonical.requested_budget().cloned(),
        call.audience()?,
        Challenge::new(challenge),
        ValidityWindow::new(
            Timestamp::new(evaluation_time),
            Timestamp::new(evaluation_time),
        )?,
        PrincipalId::parse(actor)?,
        Some(auths_codec::grant_id(terminal_grant.statement())?),
        auths_codec::plan_id(&plan)?,
        ChannelBindingId::parse("none-v1")?,
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    Ok(McpActionPreparationV1 {
        canonical_action_cbor: auths_codec::encode_canonical_action(&canonical)?,
        action_envelope_cbor: auths_codec::encode_action_envelope(&envelope)?,
        arguments_json: serde_json_canonicalizer::to_vec(call.arguments())
            .map_err(|_| EngineError::Abi("MCP arguments could not be canonicalized"))?,
        audience: call.audience()?.to_string(),
        resource: canonical.permission().resource().to_string(),
        display_digest_hex: display.canonical_digest_hex().to_owned(),
    })
}

fn mcp_arguments_from_js(arguments: &JsValue) -> Result<Map<String, Value>, EngineError> {
    let Value::Object(arguments) = serde_wasm_bindgen::from_value(arguments.clone())
        .map_err(|_| EngineError::Abi("MCP arguments must contain JSON values"))?
    else {
        return Err(EngineError::Abi("MCP arguments must be a JSON object"));
    };
    Ok(arguments)
}

fn canonicalize_mcp_plan_member_native(
    service: &str,
    name: &str,
    arguments: &JsValue,
) -> Result<Vec<u8>, EngineError> {
    let call = McpToolCall::new(service, name, mcp_arguments_from_js(arguments)?)?;
    let profile = McpProfile;
    let canonical = profile.canonicalize(&call.canonical_bytes()?)?;
    ProfilePlanMember::encode(
        &canonical,
        &ResourceId::parse(&format!("mcp://{service}"))?,
        &call.audience()?,
    )
    .map_err(EngineError::from)
}

#[allow(clippy::too_many_arguments)]
fn canonicalize_profile_plan_member_native(
    profile_id: &str,
    profile_version: u16,
    media_type: &str,
    body: &[u8],
    capability: &str,
    resource: &str,
    has_budget: bool,
    budget_algebra: &str,
    budget_value: u64,
    resource_namespace: &str,
    audience: &str,
) -> Result<Vec<u8>, EngineError> {
    let canonical = canonical_profile_action_native(
        profile_id,
        profile_version,
        media_type,
        body,
        capability,
        resource,
        has_budget,
        budget_algebra,
        budget_value,
    )?;
    ProfilePlanMember::encode(
        &canonical,
        &ResourceId::parse(resource_namespace)?,
        &Audience::parse(audience)?,
    )
    .map_err(EngineError::from)
}

#[allow(clippy::too_many_arguments)]
fn canonical_profile_action_native(
    profile_id: &str,
    profile_version: u16,
    media_type: &str,
    body: &[u8],
    capability: &str,
    resource: &str,
    has_budget: bool,
    budget_algebra: &str,
    budget_value: u64,
) -> Result<auths_model::CanonicalAction, EngineError> {
    let profile = auths_model::ProfileRef::new(ProfileId::parse(profile_id)?, profile_version)?;
    let permission = Permission::new(
        CapabilityId::parse(capability)?,
        ResourceId::parse(resource)?,
    );
    let requested_budget = if has_budget {
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse(budget_algebra)?,
            budget_value,
        ))
    } else {
        None
    };
    auths_model::CanonicalAction::new(
        profile,
        MediaType::parse(media_type)?,
        body.to_vec(),
        permission,
        requested_budget,
    )
    .map_err(EngineError::from)
}

#[derive(Clone)]
struct GrantProofMaterial {
    grant: SignedGrant,
    evidence: Vec<EvidenceObject>,
}

/// Native, bounded proof-material collector used only by the workflow facade.
#[wasm_bindgen]
pub struct WorkflowProofBuilderV1 {
    grants: Vec<GrantProofMaterial>,
    action_evidence: Vec<EvidenceObject>,
}

#[wasm_bindgen]
impl WorkflowProofBuilderV1 {
    /// Creates an empty bounded proof collector.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            grants: Vec::new(),
            action_evidence: Vec::new(),
        }
    }

    /// Appends one canonical signed grant in root-to-leaf order.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for malformed grants or collection overflow.
    #[wasm_bindgen(js_name = pushGrant)]
    pub fn push_grant(&mut self, signed_grant_cbor: &[u8]) -> Result<u32, JsValue> {
        if self.grants.len()
            >= VerifierLimits::default_deployment().get(auths_model::LimitKind::Grants)
        {
            return Err(js_error(EngineError::Abi(
                "grant chain exceeds deployment limit",
            )));
        }
        let grant = auths_codec::decode_signed_grant(
            signed_grant_cbor,
            &VerifierLimits::default_deployment(),
        )
        .map_err(js_error)?;
        self.grants.push(GrantProofMaterial {
            grant,
            evidence: Vec::new(),
        });
        u32::try_from(self.grants.len() - 1)
            .map_err(|_| js_error(EngineError::Abi("grant index exceeds ABI")))
    }

    /// Binds one typed public evidence object to a previously added grant.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for an invalid index, identifier, media type,
    /// evidence body, or collection limit.
    #[wasm_bindgen(js_name = bindGrantEvidence)]
    pub fn bind_grant_evidence(
        &mut self,
        grant_index: u32,
        evidence_type: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<(), JsValue> {
        let material = self
            .grants
            .get_mut(usize::try_from(grant_index).map_err(js_error)?)
            .ok_or_else(|| js_error(EngineError::Abi("grant evidence index is invalid")))?;
        material
            .evidence
            .push(addressed_evidence(evidence_type, media_type, bytes).map_err(js_error)?);
        Ok(())
    }

    /// Binds one typed public evidence object to the signed action.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for an invalid identifier, media type,
    /// evidence body, or collection limit.
    #[wasm_bindgen(js_name = bindActionEvidence)]
    pub fn bind_action_evidence(
        &mut self,
        evidence_type: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<(), JsValue> {
        self.action_evidence
            .push(addressed_evidence(evidence_type, media_type, bytes).map_err(js_error)?);
        Ok(())
    }

    /// Assembles the canonical proof and exact request-bound trusted context.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for malformed signed data, inconsistent plan
    /// binding, invalid evidence, or an invalid trusted-context template.
    pub fn finish(
        &self,
        signed_action_cbor: &[u8],
        canonical_action_cbor: &[u8],
        trusted_context_cbor: &[u8],
    ) -> Result<WorkflowAuthorizationArtifactsV1, JsValue> {
        self.finish_native(
            signed_action_cbor,
            canonical_action_cbor,
            trusted_context_cbor,
        )
        .map_err(js_error)
    }
}

impl Default for WorkflowProofBuilderV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkflowProofBuilderV1 {
    fn finish_native(
        &self,
        signed_action_cbor: &[u8],
        canonical_action_cbor: &[u8],
        trusted_context_cbor: &[u8],
    ) -> Result<WorkflowAuthorizationArtifactsV1, EngineError> {
        let limits = VerifierLimits::default_deployment();
        let action = auths_codec::decode_signed_action(signed_action_cbor, &limits)?;
        let canonical = auths_codec::decode_canonical_action(canonical_action_cbor, &limits)?;
        let plan = AuthorizationPlan::proof(action.envelope().proof_ref());
        if auths_codec::plan_id(&plan)? != action.envelope().authorization_plan() {
            return Err(EngineError::Abi(
                "signed action does not bind its authorization plan",
            ));
        }
        let mut evidence = Vec::new();
        let mut bindings = Vec::new();
        for material in &self.grants {
            let ids = unique_evidence(&mut evidence, &material.evidence);
            if !ids.is_empty() {
                bindings.push(ControlBinding::new(
                    StatementRef::Grant(auths_codec::grant_id(material.grant.statement())?),
                    ids,
                )?);
            }
        }
        let action_ids = unique_evidence(&mut evidence, &self.action_evidence);
        if !action_ids.is_empty() {
            bindings.push(ControlBinding::new(
                StatementRef::Action(auths_codec::action_id(action.envelope())?),
                action_ids,
            )?);
        }
        let proof = ProofBundle::new(
            BundleHeader::v1(),
            self.grants
                .iter()
                .map(|material| material.grant.clone())
                .collect(),
            vec![action.clone()],
            plan.clone(),
            evidence,
            bindings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(canonical.body().to_vec()),
        )?;
        let context = auths_codec::decode_verifier_context(trusted_context_cbor)?
            .for_request(
                action.envelope().audience().clone(),
                action.envelope().challenge(),
                action.envelope().validity().not_before(),
            )?
            .with_composition(CompositionRequirement::exact(auths_codec::plan_id(&plan)?))?;
        Ok(WorkflowAuthorizationArtifactsV1 {
            proof_cbor: auths_codec::encode_bundle(&proof)?,
            trusted_context_cbor: auths_codec::encode_verifier_context(&context)?,
        })
    }
}

/// Canonical inputs assembled by native profile and proof owners.
#[wasm_bindgen]
pub struct WorkflowAuthorizationArtifactsV1 {
    proof_cbor: Vec<u8>,
    trusted_context_cbor: Vec<u8>,
}

#[wasm_bindgen]
impl WorkflowAuthorizationArtifactsV1 {
    /// Returns the canonical proof bundle.
    #[must_use]
    #[wasm_bindgen(getter, js_name = proofCbor)]
    pub fn proof_cbor(&self) -> Vec<u8> {
        self.proof_cbor.clone()
    }

    /// Returns the exact request-bound trusted context.
    #[must_use]
    #[wasm_bindgen(getter, js_name = trustedContextCbor)]
    pub fn trusted_context_cbor(&self) -> Vec<u8> {
        self.trusted_context_cbor.clone()
    }
}

/// Validates a canonical trusted-context template against its configured root
/// and packaged verifier commitment.
///
/// # Errors
///
/// Returns a JavaScript error for malformed context, configuration mismatch,
/// or a missing root trust anchor.
#[wasm_bindgen(js_name = validateTrustedContextV1)]
pub fn validate_trusted_context_v1(
    trusted_context_cbor: &[u8],
    root_principal: &str,
    verifier_configuration: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let result = (|| -> Result<Vec<u8>, EngineError> {
        let expected: [u8; 32] = verifier_configuration
            .try_into()
            .map_err(|_| EngineError::Abi("verifier configuration must contain 32 bytes"))?;
        let root = PrincipalId::parse(root_principal)?;
        let context = auths_codec::decode_verifier_context(trusted_context_cbor)?;
        if context.configuration() != VerifierConfigurationId::new(expected) {
            return Err(EngineError::Abi(
                "trusted context configuration does not match",
            ));
        }
        if !context
            .trust_anchors()
            .iter()
            .any(|anchor| anchor.principal() == &root)
        {
            return Err(EngineError::Abi(
                "trusted context omits the configured root",
            ));
        }
        Ok(auths_codec::encode_verifier_context(&context)?)
    })();
    result.map_err(js_error)
}

fn addressed_evidence(
    evidence_type: &str,
    media_type: &str,
    bytes: &[u8],
) -> Result<EvidenceObject, EngineError> {
    let evidence_type = EvidenceTypeId::parse(evidence_type)?;
    let media_type = MediaType::parse(media_type)?;
    let unaddressed = EvidenceObject::new(
        EvidenceId::new([0; 32]),
        evidence_type.clone(),
        media_type.clone(),
        bytes.to_vec(),
    )?;
    Ok(EvidenceObject::new(
        auths_codec::evidence_id(&unaddressed)?,
        evidence_type,
        media_type,
        bytes.to_vec(),
    )?)
}

fn unique_evidence(all: &mut Vec<EvidenceObject>, additions: &[EvidenceObject]) -> Vec<EvidenceId> {
    let mut ids = Vec::with_capacity(additions.len());
    for object in additions {
        if !all.iter().any(|candidate| candidate.id() == object.id()) {
            all.push(object.clone());
        }
        if !ids.contains(&object.id()) {
            ids.push(object.id());
        }
    }
    ids
}

fn plan_child_grant_native(
    parent_grant_cbor: &[u8],
    proposed_child_cbor: &[u8],
) -> Result<GrantPlanV1, EngineError> {
    let limits = VerifierLimits::default_deployment();
    let parent = auths_codec::decode_grant_statement(parent_grant_cbor, &limits)?;
    let proposed = auths_codec::decode_grant_statement(proposed_child_cbor, &limits)?;
    let plan = plan_child_grant(&parent, GrantRequest::from_proposed_statement(&proposed))?;
    grant_plan_output(&plan)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn plan_child_grant_fields_native(
    parent_grant_cbor: &[u8],
    subject: &str,
    permission_capabilities: Vec<String>,
    permission_resources: Vec<String>,
    not_before: u64,
    expires_at: u64,
    audiences: Vec<String>,
    action_mode: &str,
    action_digests: &[u8],
    budget_mode: &str,
    budget_algebra: &str,
    budget_value: u64,
    remaining_depth: u16,
    status_mode: &str,
    status_method: &str,
    status_max_age: u64,
    assurance_floor: &str,
) -> Result<GrantPlanV1, EngineError> {
    let limits = VerifierLimits::default_deployment();
    let parent = auths_codec::decode_grant_statement(parent_grant_cbor, &limits)?;
    if permission_capabilities.len() != permission_resources.len() {
        return Err(EngineError::Abi(
            "permission capability and resource counts differ",
        ));
    }
    let permissions = permission_capabilities
        .into_iter()
        .zip(permission_resources)
        .map(|(capability, resource)| {
            Ok(Permission::new(
                CapabilityId::parse(&capability)?,
                ResourceId::parse(&resource)?,
            ))
        })
        .collect::<Result<Vec<_>, auths_model::ModelError>>()?;
    let permissions = PermissionSet::new(permissions)?;
    let audiences = AudienceSet::new(
        audiences
            .into_iter()
            .map(|audience| Audience::parse(&audience))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let action_constraint = match action_mode {
        "inherit" => {
            if !action_digests.is_empty() {
                return Err(EngineError::Abi(
                    "inherited action constraint must not include digests",
                ));
            }
            parent.action_constraint().clone()
        }
        "any-body" => {
            if !action_digests.is_empty() {
                return Err(EngineError::Abi(
                    "any-body action constraint must not include digests",
                ));
            }
            ActionConstraint::AnyBody
        }
        "exact-body" => ActionConstraint::ExactBodyDigest(Digest::new(
            action_digests
                .try_into()
                .map_err(|_| EngineError::Abi("exact-body requires one 32-byte digest"))?,
        )),
        "allowed-bodies" => {
            if action_digests.is_empty() || !action_digests.len().is_multiple_of(32) {
                return Err(EngineError::Abi(
                    "allowed-bodies requires complete 32-byte digests",
                ));
            }
            let digests = action_digests
                .chunks_exact(32)
                .map(|bytes| {
                    Ok(Digest::new(bytes.try_into().map_err(|_| {
                        EngineError::Abi("allowed-body digest has invalid length")
                    })?))
                })
                .collect::<Result<Vec<_>, EngineError>>()?;
            ActionConstraint::AllowedBodyDigests(BodyDigestSet::new(digests)?)
        }
        _ => return Err(EngineError::Abi("unsupported action constraint mode")),
    };
    let budget_ceiling = match budget_mode {
        "inherit" => {
            if !budget_algebra.is_empty() || budget_value != 0 {
                return Err(EngineError::Abi(
                    "inherited budget must not include budget fields",
                ));
            }
            parent.budget_ceiling().cloned()
        }
        "none" => {
            if !budget_algebra.is_empty() || budget_value != 0 {
                return Err(EngineError::Abi(
                    "absent budget must not include budget fields",
                ));
            }
            None
        }
        "ceiling" => Some(BudgetCeiling::new(
            BudgetAlgebraId::parse(budget_algebra)?,
            budget_value,
        )),
        _ => return Err(EngineError::Abi("unsupported budget mode")),
    };
    let status_policy = match status_mode {
        "inherit" => {
            if !status_method.is_empty() || status_max_age != 0 {
                return Err(EngineError::Abi(
                    "inherited status must not include status fields",
                ));
            }
            parent.status_policy().clone()
        }
        "expiry-only" => {
            if !status_method.is_empty() || status_max_age != 0 {
                return Err(EngineError::Abi(
                    "expiry-only status must not include status fields",
                ));
            }
            StatusPolicy::ExpiryOnly
        }
        "snapshot-required" => StatusPolicy::SnapshotRequired {
            method: StatusMethodId::parse(status_method)?,
            max_age: FreshnessLimit::new(status_max_age)?,
        },
        _ => return Err(EngineError::Abi("unsupported status mode")),
    };
    let assurance_floor = if assurance_floor.is_empty() {
        parent.assurance_floor().clone()
    } else {
        AssurancePolicyId::parse(assurance_floor)?
    };
    let request = GrantRequest::new(
        PrincipalId::parse(subject)?,
        parent.profile().clone(),
        permissions,
        ValidityWindow::new(Timestamp::new(not_before), Timestamp::new(expires_at))?,
        audiences,
        action_constraint,
        budget_ceiling,
        remaining_depth,
        status_policy,
        assurance_floor,
        parent.extensions().clone(),
    );
    grant_plan_output(&plan_child_grant(&parent, request)?)
}

fn grant_plan_output(plan: &GrantPlan) -> Result<GrantPlanV1, EngineError> {
    let diff = plan.diff();
    let (parent_depth, child_depth) = diff.delegation_depth();
    let removed_permissions = u32::try_from(diff.removed_permissions())
        .map_err(|_| EngineError::Abi("permission diff exceeds ABI"))?;
    let removed_audiences = u32::try_from(diff.removed_audiences())
        .map_err(|_| EngineError::Abi("audience diff exceeds ABI"))?;
    let warning_mask = plan.warnings().iter().fold(0, |mask, warning| {
        mask | match warning {
            OverGrantingWarning::AnyBody => WARNING_ANY_BODY,
            OverGrantingWarning::MultiplePermissions => WARNING_MULTIPLE_PERMISSIONS,
            OverGrantingWarning::MultipleAudiences => WARNING_MULTIPLE_AUDIENCES,
            OverGrantingWarning::DelegationAllowed => WARNING_DELEGATION_ALLOWED,
            OverGrantingWarning::NoBudgetCeiling => WARNING_NO_BUDGET_CEILING,
            OverGrantingWarning::LongValidity => WARNING_LONG_VALIDITY,
        }
    });
    Ok(GrantPlanV1 {
        statement_cbor: auths_codec::encode_grant_statement(plan.statement())?,
        removed_permissions,
        removed_audiences,
        validity_shortened: diff.validity_shortened(),
        action_narrowed: diff.action_narrowed(),
        budget_narrowed: diff.budget_narrowed(),
        status_narrowed: diff.status_narrowed(),
        parent_depth,
        child_depth,
        warning_mask,
    })
}

fn signing_descriptor(
    principal_method: &str,
    verification_method: &str,
    suite: &str,
) -> Result<SignatureDescriptor, auths_model::ModelError> {
    Ok(SignatureDescriptor::new(
        PrincipalMethodId::parse(principal_method)?,
        VerificationMethod::parse(verification_method)?,
        SignatureSuiteId::parse(suite)?,
    ))
}

fn signing_request<T>(request: &ExternalSigningRequest<T>) -> AuthoringSigningRequestV1 {
    AuthoringSigningRequestV1 {
        object_kind: request.object_id().label(),
        request_id: request.request_id(),
        object_id: request.object_id().as_bytes().to_vec(),
        signing_preimage: request.signing_preimage().to_vec(),
        transaction_digest: request.transaction_digest().as_bytes().to_vec(),
    }
}

fn bind_trusted_context_request_native(
    trusted_context_cbor: &[u8],
    audience: &str,
    challenge: &[u8],
    evaluation_time: u64,
) -> Result<Vec<u8>, EngineError> {
    let challenge: [u8; 32] = challenge
        .try_into()
        .map_err(|_| EngineError::Abi("challenge must contain exactly 32 bytes"))?;
    let context = auths_codec::decode_verifier_context(trusted_context_cbor)?;
    let context = context.for_request(
        Audience::parse(audience)?,
        Challenge::new(challenge),
        Timestamp::new(evaluation_time),
    )?;
    Ok(auths_codec::encode_verifier_context(&context)?)
}

fn js_error(error: impl fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}

/// Verifies with the self-contained target V1 principal methods.
///
/// This distribution includes raw-key, `did:key`, and `did:keri` control plus
/// Ed25519 and P-256 signatures. Deployments that accept trust-configured
/// methods such as `did:web`, `WebAuthn`, `HSM`, or `SPIFFE` construct the same
/// portable engine with their explicit immutable implementations.
///
/// # Errors
///
/// Returns a typed error only when a compiled registry identifier is invalid
/// or the canonical result cannot be encoded.
pub fn verify_self_contained_v1(
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
) -> Result<Vec<u8>, EngineError> {
    let raw_key = auths_raw_key::RawKeyMethod::new()?;
    let did_key = auths_did_key::DidKeyMethod::new()?;
    let did_keri = auths_did_keri::DidKeriMethod::new()?;
    let ed25519 = auths_signature::Ed25519Suite::new()?;
    let p256 = auths_signature::P256Sha256Suite::new()?;
    let methods: [&dyn PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
    let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
    let registries = ImmutableRegistries::new(&methods, &suites)?;
    Ok(auths_verifier::verify_v1(
        proof_cbor,
        canonical_action_cbor,
        trusted_context_cbor,
        &registries,
    )?)
}

/// Returns the exact configuration commitment for this fixed WASM
/// distribution.
///
/// # Errors
///
/// Returns an error if a compiled adapter or registry cannot initialize.
pub fn self_contained_v1_configuration() -> Result<[u8; 32], EngineError> {
    let raw_key = auths_raw_key::RawKeyMethod::new()?;
    let did_key = auths_did_key::DidKeyMethod::new()?;
    let did_keri = auths_did_keri::DidKeriMethod::new()?;
    let ed25519 = auths_signature::Ed25519Suite::new()?;
    let p256 = auths_signature::P256Sha256Suite::new()?;
    let methods: [&dyn PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
    let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
    let registries = ImmutableRegistries::new(&methods, &suites)?;
    Ok(*registries.configuration_id().as_bytes())
}

/// JavaScript-facing exact configuration commitment for this distribution.
///
/// # Errors
///
/// Returns a JavaScript error only if compiled engine initialization fails.
#[wasm_bindgen(js_name = configurationV1)]
pub fn configuration_v1() -> Result<Vec<u8>, JsValue> {
    self_contained_v1_configuration()
        .map(|bytes| bytes.to_vec())
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

/// JavaScript-facing three-input portable V1 verifier.
///
/// Protocol failures are canonical result bytes, not JavaScript exceptions.
/// Exceptions are reserved for an internal compiled-registry or result-codec
/// failure.
///
/// # Errors
///
/// Returns a JavaScript error only for an internal engine initialization or
/// result encoding failure.
#[wasm_bindgen(js_name = verifyV1)]
pub fn verify_v1(
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
) -> Result<Vec<u8>, JsValue> {
    verify_self_contained_v1(proof_cbor, canonical_action_cbor, trusted_context_cbor)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

/// Internal portable verification or authoring failure.
#[derive(Debug)]
pub enum EngineError {
    /// A model value violated the target V1 grammar or bounds.
    Model(auths_model::ModelError),
    /// The compiled KERI implementation could not initialize.
    Keri(auths_did_keri::KeriError),
    /// Executable registry implementations collided or were invalid.
    Registry(auths_registries::RegistryError),
    /// Canonical result encoding failed.
    Codec(auths_codec::CodecError),
    /// Native child-authority planning rejected the proposal.
    Planning(auths_author::PlanningError),
    /// Exact signing-input construction failed.
    Author(auths_author::AuthorError),
    /// MCP profile construction or canonicalization failed.
    Mcp(auths_profile_mcp::ProfileError),
    /// Profile contract construction or projection failed.
    Profile(auths_profile_api::ProfileContractError),
    /// A binding-level invariant could not be represented.
    Abi(&'static str),
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(formatter, "invalid target V1 model value: {error}"),
            Self::Keri(error) => write!(formatter, "could not initialize did:keri: {error}"),
            Self::Registry(error) => {
                write!(
                    formatter,
                    "could not construct target V1 registries: {error}"
                )
            }
            Self::Codec(error) => {
                write!(
                    formatter,
                    "could not process canonical target V1 data: {error}"
                )
            }
            Self::Planning(error) => write!(formatter, "could not plan child authority: {error}"),
            Self::Author(error) => write!(formatter, "could not prepare signing request: {error}"),
            Self::Mcp(error) => write!(formatter, "could not construct MCP action: {error}"),
            Self::Profile(error) => write!(formatter, "MCP profile contract failed: {error}"),
            Self::Abi(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<auths_model::ModelError> for EngineError {
    fn from(error: auths_model::ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<auths_did_keri::KeriError> for EngineError {
    fn from(error: auths_did_keri::KeriError) -> Self {
        Self::Keri(error)
    }
}

impl From<auths_registries::RegistryError> for EngineError {
    fn from(error: auths_registries::RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<auths_codec::CodecError> for EngineError {
    fn from(error: auths_codec::CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<auths_author::PlanningError> for EngineError {
    fn from(error: auths_author::PlanningError) -> Self {
        Self::Planning(error)
    }
}

impl From<auths_author::AuthorError> for EngineError {
    fn from(error: auths_author::AuthorError) -> Self {
        Self::Author(error)
    }
}

impl From<auths_profile_mcp::ProfileError> for EngineError {
    fn from(error: auths_profile_mcp::ProfileError) -> Self {
        Self::Mcp(error)
    }
}

impl From<auths_profile_api::ProfileContractError> for EngineError {
    fn from(error: auths_profile_api::ProfileContractError) -> Self {
        Self::Profile(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_key_bundle() -> auths_model::ProofBundle {
        let fixture = auths_testkit::raw_key_chain();
        auths_codec::decode_bundle(fixture.proof_bytes(), &VerifierLimits::default_deployment())
            .unwrap()
    }

    #[test]
    fn native_wasm_boundary_matches_the_portable_contract() {
        let fixture = auths_testkit::raw_key_chain();
        let action = auths_codec::encode_canonical_action(fixture.canonical_action()).unwrap();
        let context = auths_codec::decode_verifier_context(fixture.context_bytes())
            .unwrap()
            .with_configuration(auths_model::VerifierConfigurationId::new(
                self_contained_v1_configuration().unwrap(),
            ))
            .unwrap();
        let context = auths_codec::encode_verifier_context(&context).unwrap();
        let result = verify_self_contained_v1(fixture.proof_bytes(), &action, &context).unwrap();
        assert_eq!(
            auths_codec::decode_verification_result(&result)
                .unwrap()
                .code()
                .code(),
            "authorized"
        );
        assert_eq!(
            auths_codec::decode_verification_result(&result)
                .unwrap()
                .required_configuration(),
            Some(auths_model::VerifierConfigurationId::new(
                self_contained_v1_configuration().unwrap()
            ))
        );
        assert_eq!(
            auths_codec::decode_verification_result(&result)
                .unwrap()
                .local_configuration(),
            auths_model::VerifierConfigurationId::new(self_contained_v1_configuration().unwrap())
        );
    }

    #[test]
    fn native_mcp_authorization_assembly_matches_profile_and_core_owners() {
        let fixture = auths_testkit::raw_key_chain();
        let bundle = auths_codec::decode_bundle(
            fixture.proof_bytes(),
            &VerifierLimits::default_deployment(),
        )
        .unwrap();
        let mut builder = WorkflowProofBuilderV1::new();
        for grant in bundle.grants() {
            let index = builder.grants.len();
            let grant_identifier = auths_codec::grant_id(grant.statement()).unwrap();
            let ids = bundle
                .bindings()
                .iter()
                .find(|binding| binding.statement() == StatementRef::Grant(grant_identifier))
                .unwrap()
                .evidence();
            builder.grants.push(GrantProofMaterial {
                grant: grant.clone(),
                evidence: bundle
                    .evidence()
                    .iter()
                    .filter(|evidence| ids.contains(&evidence.id()))
                    .cloned()
                    .collect(),
            });
            assert_eq!(builder.grants.len(), index + 1);
        }
        let action = bundle.actions().first().unwrap();
        let action_identifier = auths_codec::action_id(action.envelope()).unwrap();
        let ids = bundle
            .bindings()
            .iter()
            .find(|binding| binding.statement() == StatementRef::Action(action_identifier))
            .unwrap()
            .evidence();
        builder.action_evidence = bundle
            .evidence()
            .iter()
            .filter(|evidence| ids.contains(&evidence.id()))
            .cloned()
            .collect();
        let artifacts = builder
            .finish_native(
                &auths_codec::encode_signed_action(action).unwrap(),
                &auths_codec::encode_canonical_action(fixture.canonical_action()).unwrap(),
                fixture.context_bytes(),
            )
            .unwrap();
        assert_eq!(artifacts.proof_cbor, fixture.proof_bytes());

        let terminal = auths_codec::encode_signed_grant(bundle.grants().first().unwrap()).unwrap();
        let actor = action.envelope().actor().as_str();
        let prepared = prepare_mcp_action_native(
            "reports",
            "update_demo_record",
            serde_json::from_value(serde_json::json!({"value": "reviewed"})).unwrap(),
            actor,
            &terminal,
            &[0x22; 32],
            50,
        )
        .unwrap();
        let call = McpToolCall::new(
            "reports",
            "update_demo_record",
            serde_json::from_value(serde_json::json!({"value": "reviewed"})).unwrap(),
        )
        .unwrap();
        let expected = McpProfile
            .canonicalize(&call.canonical_bytes().unwrap())
            .unwrap();
        assert_eq!(
            prepared.canonical_action_cbor,
            auths_codec::encode_canonical_action(&expected).unwrap()
        );
    }

    #[test]
    fn authoring_abi_planning_matches_the_native_owner() {
        let bundle = raw_key_bundle();
        let proposed = bundle.grants()[0].statement();
        let parent = auths_model::GrantStatement::new(
            proposed.issuer().clone(),
            proposed.issuer().clone(),
            proposed.profile().clone(),
            proposed.permissions().clone(),
            auths_model::ValidityWindow::new(Timestamp::new(0), Timestamp::new(100)).unwrap(),
            proposed.audiences().clone(),
            auths_model::ActionConstraint::AnyBody,
            Some(auths_model::BudgetCeiling::new(
                proposed.budget_ceiling().unwrap().algebra().clone(),
                20,
            )),
            1,
            None,
            proposed.status_policy().clone(),
            proposed.assurance_floor().clone(),
            auths_model::CriticalExtensions::empty(),
        );
        let parent_cbor = auths_codec::encode_grant_statement(&parent).unwrap();
        let proposed_cbor = auths_codec::encode_grant_statement(proposed).unwrap();

        let wasm_plan = plan_child_grant_native(&parent_cbor, &proposed_cbor).unwrap();
        let native_plan =
            plan_child_grant(&parent, GrantRequest::from_proposed_statement(proposed)).unwrap();

        assert_eq!(
            wasm_plan.statement_cbor,
            auths_codec::encode_grant_statement(native_plan.statement()).unwrap()
        );
        assert_eq!(wasm_plan.child_depth, proposed.remaining_depth());
        assert_eq!(
            auths_codec::decode_grant_statement(
                &wasm_plan.statement_cbor,
                &VerifierLimits::default_deployment(),
            )
            .unwrap()
            .parent(),
            Some(auths_codec::grant_id(&parent).unwrap())
        );
    }

    #[test]
    fn authoring_abi_signing_request_matches_the_native_owner() {
        let bundle = raw_key_bundle();
        let envelope = bundle.actions()[0].envelope().clone();
        let descriptor = bundle.actions()[0].signature().descriptor().clone();
        let native = prepare_action(envelope.clone(), descriptor).unwrap();
        let projected = signing_request(&native);

        assert_eq!(projected.object_kind, "action");
        assert_eq!(projected.request_id, native.request_id());
        assert!(projected.request_id.starts_with("action:"));
        assert_eq!(projected.signing_preimage, native.signing_preimage());
        assert_eq!(
            projected.transaction_digest,
            native.transaction_digest().as_bytes()
        );
        assert_eq!(
            projected.transaction_digest,
            auths_codec::transaction_binding(native.signing_preimage()).as_bytes()
        );
        assert_eq!(
            projected.object_id,
            auths_codec::action_id(&envelope).unwrap().as_bytes()
        );
    }

    #[test]
    fn authoring_abi_signed_action_matches_canonical_rust_bytes() {
        let bundle = raw_key_bundle();
        let action = &bundle.actions()[0];
        let descriptor = action.signature().descriptor();
        let envelope_cbor = auths_codec::encode_action_envelope(action.envelope()).unwrap();
        let completed = complete_action_signing_v1(
            &envelope_cbor,
            descriptor.principal_method().as_str(),
            descriptor.verification_method().as_str(),
            descriptor.suite().as_str(),
            action.signature().signature().as_slice(),
        )
        .unwrap();
        assert_eq!(
            completed,
            auths_codec::encode_signed_action(action).unwrap()
        );
    }

    #[test]
    fn signed_grant_authority_projection_matches_the_native_model() {
        let bundle = raw_key_bundle();
        let grant = &bundle.grants()[0];
        let statement = grant.statement();
        let bytes = auths_codec::encode_signed_grant(grant).unwrap();
        let projected = inspect_signed_grant_native(&bytes).unwrap();

        assert_eq!(
            projected.statement_cbor,
            auths_codec::encode_grant_statement(statement).unwrap()
        );
        assert_eq!(
            projected.grant_id,
            auths_codec::grant_id(statement).unwrap().as_bytes()
        );
        assert_eq!(projected.issuer, statement.issuer().as_str());
        assert_eq!(projected.subject, statement.subject().as_str());
        assert_eq!(projected.profile_id, statement.profile().id().as_str());
        assert_eq!(projected.profile_version, statement.profile().version());
        assert_eq!(projected.permission_capabilities, vec!["tools/call"]);
        assert_eq!(projected.permission_resources, vec!["mcp://reports/read"]);
        assert!(!projected.has_parent);
        assert_eq!(projected.action_constraint, "exact-body");
        assert_eq!(projected.action_digest_count, 1);
        assert_eq!(projected.status_policy, "expiry-only");
    }

    #[test]
    fn root_authority_validation_binds_every_attach_identity() {
        let bundle = raw_key_bundle();
        let grant = &bundle.grants()[0];
        let statement = grant.statement();
        let bytes = auths_codec::encode_signed_grant(grant).unwrap();

        assert!(
            validate_root_authority_native(
                &bytes,
                statement.issuer().as_str(),
                statement.subject().as_str(),
                statement.profile().id().as_str(),
                statement.profile().version(),
            )
            .is_ok()
        );
        assert!(
            validate_root_authority_native(
                &bytes,
                statement.subject().as_str(),
                statement.subject().as_str(),
                statement.profile().id().as_str(),
                statement.profile().version(),
            )
            .is_err()
        );
        assert!(
            validate_root_authority_native(
                &bytes,
                statement.issuer().as_str(),
                statement.issuer().as_str(),
                statement.profile().id().as_str(),
                statement.profile().version(),
            )
            .is_err()
        );
        assert!(
            validate_root_authority_native(
                &bytes,
                statement.issuer().as_str(),
                statement.subject().as_str(),
                statement.profile().id().as_str(),
                statement.profile().version() + 1,
            )
            .is_err()
        );
    }

    #[test]
    fn structured_child_planning_inherits_closed_parent_fields() {
        let bundle = raw_key_bundle();
        let proposed = bundle.grants()[0].statement();
        let extensions = auths_model::CriticalExtensions::new(vec![
            auths_model::CriticalExtension::new(
                auths_model::ExtensionId::parse("extension.test-v1").unwrap(),
                vec![1, 2, 3],
            )
            .unwrap(),
        ])
        .unwrap();
        let parent = auths_model::GrantStatement::new(
            proposed.issuer().clone(),
            proposed.subject().clone(),
            proposed.profile().clone(),
            proposed.permissions().clone(),
            ValidityWindow::new(Timestamp::new(0), Timestamp::new(100)).unwrap(),
            proposed.audiences().clone(),
            ActionConstraint::AnyBody,
            Some(BudgetCeiling::new(
                proposed.budget_ceiling().unwrap().algebra().clone(),
                20,
            )),
            2,
            None,
            StatusPolicy::SnapshotRequired {
                method: StatusMethodId::parse("status.test-v1").unwrap(),
                max_age: FreshnessLimit::new(60).unwrap(),
            },
            proposed.assurance_floor().clone(),
            extensions.clone(),
        );
        let parent_cbor = auths_codec::encode_grant_statement(&parent).unwrap();
        let plan = plan_child_grant_fields_native(
            &parent_cbor,
            "did:web:child.workflow.auths.example",
            vec!["tools/call".to_owned()],
            vec!["mcp://reports/read".to_owned()],
            20,
            80,
            vec!["mcp://reports".to_owned()],
            "inherit",
            &[],
            "ceiling",
            "numeric-ceiling-v1",
            10,
            1,
            "inherit",
            "",
            0,
            "",
        )
        .unwrap();
        let child = auths_codec::decode_grant_statement(
            &plan.statement_cbor,
            &VerifierLimits::default_deployment(),
        )
        .unwrap();

        assert_eq!(child.issuer(), parent.subject());
        assert_eq!(child.profile(), parent.profile());
        assert_eq!(
            child.parent(),
            Some(auths_codec::grant_id(&parent).unwrap())
        );
        assert_eq!(child.extensions(), &extensions);
        assert_eq!(child.status_policy(), parent.status_policy());
    }

    #[test]
    fn authoring_abi_request_context_matches_native_model() {
        let fixture = auths_testkit::raw_key_chain();
        let context = auths_codec::decode_verifier_context(fixture.context_bytes()).unwrap();
        let audience = context.expected_audience().as_str();
        let challenge = [42; 32];
        let expected = context
            .for_request(
                Audience::parse(audience).unwrap(),
                Challenge::new(challenge),
                Timestamp::new(1234),
            )
            .unwrap();
        let actual = bind_trusted_context_request_native(
            fixture.context_bytes(),
            audience,
            &challenge,
            1234,
        )
        .unwrap();
        assert_eq!(
            actual,
            auths_codec::encode_verifier_context(&expected).unwrap()
        );
    }

    #[test]
    fn authoring_abi_rejects_non_exact_challenges() {
        let fixture = auths_testkit::raw_key_chain();
        assert!(
            bind_trusted_context_request_native(
                fixture.context_bytes(),
                "auths://verifier",
                &[0; 31],
                0,
            )
            .is_err()
        );
    }
}
