//! WebAssembly export of the bounded three-input Auths V1 engine boundary.

#![forbid(unsafe_code)]

use auths_author::{
    ExternalSigningRequest, GrantPlan, GrantRequest, OverGrantingWarning, SigningObjectId,
    plan_child_grant, prepare_action, prepare_grant, prepare_grant_status,
    prepare_principal_status,
};
use auths_model::{
    Audience, Challenge, PrincipalId, PrincipalMethodId, SignatureDescriptor, SignatureSuiteId,
    SignatureBytes, Timestamp, VerificationMethod, VerifierLimits,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_registries::ImmutableRegistries;
use std::fmt;
use wasm_bindgen::prelude::*;

/// Version of the repository-owned authoring ABI exposed by this WASM module.
pub const AUTHORING_ABI_V1: u16 = 1;

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

/// Bounded output of native child-grant planning.
#[wasm_bindgen]
pub struct GrantPlanV1 {
    statement_cbor: Vec<u8>,
    removed_permissions: u32,
    removed_audiences: u32,
    validity_shortened: bool,
    action_narrowed: bool,
    budget_narrowed: bool,
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

/// Exact native signing request returned to an external custody port.
#[wasm_bindgen]
pub struct AuthoringSigningRequestV1 {
    object_kind: &'static str,
    object_id: Vec<u8>,
    signing_preimage: Vec<u8>,
}

#[wasm_bindgen]
impl AuthoringSigningRequestV1 {
    /// Returns the closed signed-object kind.
    #[must_use]
    #[wasm_bindgen(getter, js_name = objectKind)]
    pub fn object_kind(&self) -> String {
        self.object_kind.to_owned()
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
    let statement = auths_codec::decode_grant_statement(statement_cbor, &limits)
        .map_err(js_error)?;
    let request = prepare_grant(
        statement,
        signing_descriptor(principal_method, verification_method, suite).map_err(js_error)?,
    )
    .map_err(js_error)?;
    Ok(signing_request("grant", &request))
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
    Ok(signing_request("action", &request))
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
    Ok(signing_request("principal-status", &request))
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
    let statement = auths_codec::decode_grant_status_statement(statement_cbor, &limits)
        .map_err(js_error)?;
    let request = prepare_grant_status(
        statement,
        signing_descriptor(principal_method, verification_method, suite).map_err(js_error)?,
    )
    .map_err(js_error)?;
    Ok(signing_request("grant-status", &request))
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
    let statement = auths_codec::decode_grant_statement(statement_cbor, &limits)
        .map_err(js_error)?;
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
    let statement = auths_codec::decode_grant_status_statement(statement_cbor, &limits)
        .map_err(js_error)?;
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
    bind_trusted_context_request_native(
        trusted_context_cbor,
        audience,
        challenge,
        evaluation_time,
    )
    .map_err(js_error)
}

fn plan_child_grant_native(
    parent_grant_cbor: &[u8],
    proposed_child_cbor: &[u8],
) -> Result<GrantPlanV1, EngineError> {
    let limits = VerifierLimits::default_deployment();
    let parent = auths_codec::decode_grant_statement(parent_grant_cbor, &limits)?;
    let proposed = auths_codec::decode_grant_statement(proposed_child_cbor, &limits)?;
    let plan = plan_child_grant(&parent, GrantRequest::from_proposed_statement(&proposed))?;
    grant_plan_output(plan)
}

fn grant_plan_output(plan: GrantPlan) -> Result<GrantPlanV1, EngineError> {
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

fn signing_request<T>(
    object_kind: &'static str,
    request: &ExternalSigningRequest<T>,
) -> AuthoringSigningRequestV1 {
    let object_id = match request.object_id() {
        SigningObjectId::Grant(identifier) => identifier.as_bytes().to_vec(),
        SigningObjectId::Action(identifier) => identifier.as_bytes().to_vec(),
        SigningObjectId::PrincipalStatus(identifier) => identifier.as_bytes().to_vec(),
        SigningObjectId::GrantStatus(identifier) => identifier.as_bytes().to_vec(),
    };
    AuthoringSigningRequestV1 {
        object_kind,
        object_id,
        signing_preimage: request.signing_preimage().to_vec(),
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
                write!(formatter, "could not process canonical target V1 data: {error}")
            }
            Self::Planning(error) => write!(formatter, "could not plan child authority: {error}"),
            Self::Author(error) => write!(formatter, "could not prepare signing request: {error}"),
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
        let native_plan = plan_child_grant(
            &parent,
            GrantRequest::from_proposed_statement(proposed),
        )
        .unwrap();

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
        let projected = signing_request("action", &native);

        assert_eq!(projected.object_kind, "action");
        assert_eq!(projected.signing_preimage, native.signing_preimage());
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
        assert_eq!(completed, auths_codec::encode_signed_action(action).unwrap());
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
        assert_eq!(actual, auths_codec::encode_verifier_context(&expected).unwrap());
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
