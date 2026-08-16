//! WebAssembly export of the bounded three-input Auths V1 engine boundary.

#![forbid(unsafe_code)]

use auths_author::{
    ApprovalPolicyCommitment, ExternalSigningRequest, GrantPlan, GrantRequest, OverGrantingWarning,
    ProfilePlanCommitment, ProfilePlanMember, WorkflowAssemblyError, WorkflowProofBuilder,
    address_evidence, commit_plan_approval, plan_child_grant, prepare_action, prepare_grant,
    prepare_grant_status, prepare_principal_status, prepare_profile_action,
};
use auths_identity::{
    IdentityDescriptor, IdentityPacket, PublicIdentity, SignedIdentityMessage,
    VerificationMaterial, VerificationRelationship,
};
use auths_identity_raw_key::RawKeyIdentityMethod;
use auths_model::{
    AcceptedRegistries, ActionConstraint, ActionEnvelope, AssuranceClaimId, AssuranceImplicationId,
    AssurancePolicy, AssurancePolicyId, AssuranceQuantifier, AssuranceRequirement, Audience,
    AudienceSet, AuthorizationPlan, BodyDigestSet, BudgetAlgebraId, BudgetCeiling, CapabilityId,
    Challenge, ChannelBindingId, CompositionRequirement, CriticalExtension, CriticalExtensions,
    Digest, EvidenceId, EvidenceObject, EvidenceTypeId, ExtensionId, FreshnessLimit, GrantId,
    GrantState, GrantStatusSnapshot, GrantStatusStatement, LimitKind, MediaType, ParticipantRole,
    Permission, PermissionSet, PrincipalId, PrincipalMethodId, PrincipalState,
    PrincipalStatusSnapshot, PrincipalStatusStatement, ProfileBudgetExpression, ProfileId,
    ProfilePolicyId, ProfileRef, ProofRef, PurposeId, ResourceId, ResourceMatcherId,
    SignatureBytes, SignatureDescriptor, SignatureSuiteId, StatusMethodId, StatusPolicy,
    StatusSnapshotId, StatusTrustRule, Timestamp, TrustAnchor, TrustAnchorId, TrustedContext,
    ValidityWindow, VerificationMethod, VerifierConfigurationId, VerifierLimits,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_production_client::{
    PRODUCTION_CLIENT_CONTRACT_VERSION, ProductVerb, ProductionRequest, QualifiedProfile,
    RecoveryReference, TransportFailure, decode_request, decode_response, encode_delegation_body,
    encode_request, project_sdk_event_v2, transport_failure_response,
};
use auths_profile_api::ActionProfile;
// The generic reference domain profiles (HTTP, Git, deployment, supply-chain,
// edge) are no longer projected to JavaScript: this consumer package exposes
// no generic domain parser, canonicalizer, or action-field carrier. The one
// remaining use is the receipt projector below, which the checked-in
// `product/fixtures/v1/receipt-disclosure/inspection-v1.json` corpus still
// keys to the unqualified `auths.edge` profile. Removing it needs a
// qualified-profile receipt projector in Rust and a re-keyed corpus, and the
// pyo3 binding carries the identical coupling at
// `bindings/python/src/receipts.rs:411`.
use auths_profile_domains::DomainReceiptInspector;
use auths_profile_mcp::{
    McpCause, McpExecutionSession, McpHandlerEffect, McpHandlerResult, McpProfile,
    McpReservationResult, McpSessionKey, McpSessionStep, McpTerminal, McpToolCall,
    mcp_authority_commitment,
};
use auths_receipts::{
    AttestedDecisionReceipt, AttestedExecutionReceipt, ConfiguredReceiptVerifier, DecisionClass,
    ExecutionOutcome, ReceiptDisclosure, ReceiptInspection, ReceiptSigner, ReceiptViewMode,
    VerifiedReceiptMetadata, application_execution_lease_digest, decode_attested_decision,
    decode_attested_execution, decode_decision, decode_execution, encode_attested_decision,
    encode_attested_execution, encode_receipt_disclosure, inspect_attested_execution_receipt,
    prepare_decision_receipt, prepare_execution_receipt, verify_attested_decision_bytes,
    verify_attested_execution_bytes, verify_decision_attestation, verify_execution_attestation,
};
use auths_registries::ImmutableRegistries;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::BTreeSet, fmt};
use wasm_bindgen::prelude::*;

/// Version of the repository-owned authoring ABI exposed by this WASM module.
pub const AUTHORING_ABI_V1: u16 = 1;
/// Version of the neutral identity ABI exposed independently of authority authoring.
pub const IDENTITY_ABI_V1: u16 = 1;

/// Version of the Rust-owned production client contract.
#[must_use]
#[wasm_bindgen(js_name = productionClientContractVersionV1)]
pub fn production_client_contract_version_v1() -> u16 {
    PRODUCTION_CLIENT_CONTRACT_VERSION
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionRequestInput {
    verb: String,
    profile: String,
    identity: Vec<u8>,
    authority: Option<Vec<u8>>,
    body: Option<Vec<u8>>,
    recovery_reference: Option<String>,
}

/// Encodes one bounded canonical production-client request.
///
/// # Errors
///
/// Returns a JavaScript error for an unsupported verb, profile, malformed
/// recovery reference, invalid request shape, or over-limit value.
#[wasm_bindgen(js_name = encodeProductionRequestV1)]
pub fn encode_production_request_v1(input: JsValue) -> Result<Vec<u8>, JsValue> {
    let input: ProductionRequestInput =
        serde_wasm_bindgen::from_value(input).map_err(|_| js_error("client.malformed"))?;
    let request = ProductionRequest::new(
        ProductVerb::parse(&input.verb).map_err(js_error)?,
        QualifiedProfile::parse(&input.profile).map_err(js_error)?,
        input.identity,
        input.authority,
        input.body,
        input
            .recovery_reference
            .as_deref()
            .map(RecoveryReference::parse)
            .transpose()
            .map_err(js_error)?,
    )
    .map_err(js_error)?;
    encode_request(&request).map_err(js_error)
}

/// Parses one canonical production response and returns its inert projection.
///
/// # Errors
///
/// Returns a JavaScript error when the response is malformed, non-canonical,
/// unsupported, or over the contract limit.
#[wasm_bindgen(js_name = decodeProductionResponseV1)]
pub fn decode_production_response_v1(input: &[u8]) -> Result<String, JsValue> {
    decode_response(input)
        .and_then(|response| response.projection_json())
        .map_err(js_error)
}

/// Parses one canonical production request and returns its inert projection.
///
/// # Errors
///
/// Returns a JavaScript error when the request is malformed, non-canonical,
/// unsupported, or over the contract limit.
#[wasm_bindgen(js_name = decodeProductionRequestV1)]
pub fn decode_production_request_v1(input: &[u8]) -> Result<String, JsValue> {
    decode_request(input)
        .and_then(|request| request.projection_json())
        .map_err(js_error)
}

/// Projects one client-side transport failure under the Rust-owned contract.
///
/// The caller reports only what its transport can PROVE about the failure --
/// whether any request byte was written -- and Rust decides the registry code
/// and next call. A failure that is not provably before transmission, on a verb
/// that applies an effect, is `core.outcome-unknown` with `reconcile`, never a
/// code whose registered effect is `not-applied`. A language binding that chose
/// this itself would be telling a caller that a possibly-applied PostgreSQL
/// update is safe to blindly retry.
///
/// # Errors
///
/// Returns a JavaScript error for an unknown verb or an unknown failure kind.
#[wasm_bindgen(js_name = productionTransportFailureV1)]
pub fn production_transport_failure_v1(verb: &str, failure: &str) -> Result<String, JsValue> {
    let verb = ProductVerb::parse(verb).map_err(js_error)?;
    let failure = match failure {
        "endpoint-unresolvable" => TransportFailure::EndpointUnresolvable,
        "connection-refused" => TransportFailure::ConnectionRefused,
        "connection-failed" => TransportFailure::ConnectionFailed,
        "connection-lost" => TransportFailure::ConnectionLost,
        "response-timeout" => TransportFailure::ResponseTimeout,
        "cancelled" => TransportFailure::Cancelled,
        "unusable-response" => TransportFailure::UnusableResponse,
        _ => {
            return Err(js_error(EngineError::Abi(
                "unknown production transport failure",
            )));
        }
    };
    transport_failure_response(verb, failure)
        .projection_json()
        .map_err(js_error)
}

/// Encodes exact delegate subject and attenuation bytes under the Rust-owned contract.
///
/// # Errors
///
/// Returns a JavaScript error for empty or over-limit values.
#[wasm_bindgen(js_name = encodeProductionDelegationV1)]
pub fn encode_production_delegation_v1(
    subject: &[u8],
    attenuation: &[u8],
) -> Result<Vec<u8>, JsValue> {
    encode_delegation_body(subject, attenuation).map_err(js_error)
}

/// Parses and projects one privacy-safe SDK telemetry event in Rust.
///
/// # Errors
///
/// Returns a JavaScript error for unknown fields, unsafe attributes, or an
/// unsupported stage or outcome.
#[wasm_bindgen(js_name = projectSdkEventV2)]
pub fn project_sdk_event(input: JsValue) -> Result<String, JsValue> {
    let value: Value =
        serde_wasm_bindgen::from_value(input).map_err(|_| js_error("client.malformed"))?;
    project_sdk_event_v2(&value.to_string()).map_err(js_error)
}

const MAX_VERIFICATION_BATCH_ITEMS: usize = 256;
const MAX_VERIFICATION_BATCH_BYTES: usize = 16 * 1024 * 1024;

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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CriticalExtensionInput {
    id: String,
    bytes: Vec<u8>,
}

fn critical_extensions(value: JsValue) -> Result<CriticalExtensions, EngineError> {
    let inputs: Vec<CriticalExtensionInput> = serde_wasm_bindgen::from_value(value)
        .map_err(|_| EngineError::Abi("invalid critical extensions"))?;
    CriticalExtensions::new(
        inputs
            .into_iter()
            .map(|input| {
                Ok(CriticalExtension::new(
                    ExtensionId::parse(&input.id)?,
                    input.bytes,
                )?)
            })
            .collect::<Result<Vec<_>, EngineError>>()?,
    )
    .map_err(EngineError::from)
}

fn principal_state(value: &str) -> Result<PrincipalState, EngineError> {
    match value {
        "active" => Ok(PrincipalState::Active),
        "revoked" => Ok(PrincipalState::Revoked),
        "superseded" => Ok(PrincipalState::Superseded),
        _ => Err(EngineError::Abi("invalid principal status state")),
    }
}

fn grant_state(value: &str) -> Result<GrantState, EngineError> {
    match value {
        "active" => Ok(GrantState::Active),
        "revoked" => Ok(GrantState::Revoked),
        "superseded" => Ok(GrantState::Superseded),
        _ => Err(EngineError::Abi("invalid grant status state")),
    }
}

/// Constructs canonical unsigned principal-status bytes from typed fields.
///
/// # Errors
///
/// Returns a JavaScript error when an identifier, state, window, or extension is invalid.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = encodePrincipalStatusStatementV1)]
pub fn encode_principal_status_statement_v1(
    method: &str,
    principal: &str,
    purpose: &str,
    state: &str,
    sequence: u64,
    observed_at: u64,
    valid_until: u64,
    issuer: &str,
    extensions: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let statement = PrincipalStatusStatement::new(
        StatusMethodId::parse(method).map_err(js_error)?,
        PrincipalId::parse(principal).map_err(js_error)?,
        PurposeId::parse(purpose).map_err(js_error)?,
        principal_state(state).map_err(js_error)?,
        sequence,
        Timestamp::new(observed_at),
        Timestamp::new(valid_until),
        PrincipalId::parse(issuer).map_err(js_error)?,
        critical_extensions(extensions).map_err(js_error)?,
    )
    .map_err(js_error)?;
    auths_codec::encode_principal_status_statement(&statement).map_err(js_error)
}

/// Constructs canonical unsigned grant-status bytes from typed fields.
///
/// # Errors
///
/// Returns a JavaScript error when an identifier, state, window, or extension is invalid.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = encodeGrantStatusStatementV1)]
pub fn encode_grant_status_statement_v1(
    method: &str,
    grant_id: &[u8],
    state: &str,
    sequence: u64,
    observed_at: u64,
    valid_until: u64,
    issuer: &str,
    extensions: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let grant_id = <[u8; 32]>::try_from(grant_id)
        .map(GrantId::new)
        .map_err(|_| js_error(EngineError::Abi("grant id must contain 32 bytes")))?;
    let statement = GrantStatusStatement::new(
        StatusMethodId::parse(method).map_err(js_error)?,
        grant_id,
        grant_state(state).map_err(js_error)?,
        sequence,
        Timestamp::new(observed_at),
        Timestamp::new(valid_until),
        PrincipalId::parse(issuer).map_err(js_error)?,
        critical_extensions(extensions).map_err(js_error)?,
    )
    .map_err(js_error)?;
    auths_codec::encode_grant_status_statement(&statement).map_err(js_error)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusTrustInput {
    method: String,
    issuer: String,
    sequence_floor: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusSnapshotInput {
    id: Vec<u8>,
    observed_at: u64,
    valid_until: u64,
    statements: Vec<Vec<u8>>,
    checkpoints: Vec<Vec<u8>>,
    trust: Vec<StatusTrustInput>,
}

fn snapshot_id(bytes: &[u8]) -> Result<StatusSnapshotId, EngineError> {
    <[u8; 32]>::try_from(bytes)
        .map(StatusSnapshotId::new)
        .map_err(|_| EngineError::Abi("status snapshot id must contain 32 bytes"))
}

fn checkpoints(values: Vec<Vec<u8>>) -> Result<Vec<EvidenceId>, EngineError> {
    values
        .into_iter()
        .map(|value| {
            <[u8; 32]>::try_from(value.as_slice())
                .map(EvidenceId::new)
                .map_err(|_| EngineError::Abi("status checkpoint must contain 32 bytes"))
        })
        .collect()
}

fn status_trust(values: Vec<StatusTrustInput>) -> Result<Vec<StatusTrustRule>, EngineError> {
    values
        .into_iter()
        .map(|value| {
            Ok(StatusTrustRule::new(
                StatusMethodId::parse(&value.method)?,
                PrincipalId::parse(&value.issuer)?,
                value.sequence_floor,
            ))
        })
        .collect()
}

fn principal_status_snapshot(value: JsValue) -> Result<PrincipalStatusSnapshot, EngineError> {
    let input: StatusSnapshotInput = serde_wasm_bindgen::from_value(value)
        .map_err(|_| EngineError::Abi("invalid principal status snapshot"))?;
    let limits = VerifierLimits::default_deployment();
    PrincipalStatusSnapshot::with_trust(
        snapshot_id(&input.id)?,
        Timestamp::new(input.observed_at),
        Timestamp::new(input.valid_until),
        input
            .statements
            .into_iter()
            .map(|statement| auths_codec::decode_signed_principal_status(&statement, &limits))
            .collect::<Result<Vec<_>, _>>()?,
        checkpoints(input.checkpoints)?,
        status_trust(input.trust)?,
    )
    .map_err(EngineError::from)
}

fn grant_status_snapshot(value: JsValue) -> Result<GrantStatusSnapshot, EngineError> {
    let input: StatusSnapshotInput = serde_wasm_bindgen::from_value(value)
        .map_err(|_| EngineError::Abi("invalid grant status snapshot"))?;
    let limits = VerifierLimits::default_deployment();
    GrantStatusSnapshot::with_trust(
        snapshot_id(&input.id)?,
        Timestamp::new(input.observed_at),
        Timestamp::new(input.valid_until),
        input
            .statements
            .into_iter()
            .map(|statement| auths_codec::decode_signed_grant_status(&statement, &limits))
            .collect::<Result<Vec<_>, _>>()?,
        checkpoints(input.checkpoints)?,
        status_trust(input.trust)?,
    )
    .map_err(EngineError::from)
}

/// Canonical status snapshot accepted by trusted-context composition.
#[wasm_bindgen]
pub struct StatusSnapshotV1 {
    cbor: Vec<u8>,
    id: Vec<u8>,
    statement_count: usize,
}

#[wasm_bindgen]
impl StatusSnapshotV1 {
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn cbor(&self) -> Vec<u8> {
        self.cbor.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Vec<u8> {
        self.id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = statementCount)]
    pub fn statement_count(&self) -> usize {
        self.statement_count
    }
}

/// Parses, canonicalizes, and bounds a principal-status snapshot.
///
/// # Errors
///
/// Returns a JavaScript error for malformed, duplicate, stale, or reordered input.
#[wasm_bindgen(js_name = parsePrincipalStatusSnapshotV1)]
pub fn parse_principal_status_snapshot_v1(value: JsValue) -> Result<StatusSnapshotV1, JsValue> {
    let snapshot = principal_status_snapshot(value).map_err(js_error)?;
    Ok(StatusSnapshotV1 {
        cbor: auths_codec::encode_principal_status_snapshot(&snapshot).map_err(js_error)?,
        id: snapshot.id().as_bytes().to_vec(),
        statement_count: snapshot.statements().len(),
    })
}

/// Parses, canonicalizes, and bounds a grant-status snapshot.
///
/// # Errors
///
/// Returns a JavaScript error for malformed, duplicate, stale, or reordered input.
#[wasm_bindgen(js_name = parseGrantStatusSnapshotV1)]
pub fn parse_grant_status_snapshot_v1(value: JsValue) -> Result<StatusSnapshotV1, JsValue> {
    let snapshot = grant_status_snapshot(value).map_err(js_error)?;
    Ok(StatusSnapshotV1 {
        cbor: auths_codec::encode_grant_status_snapshot(&snapshot).map_err(js_error)?,
        id: snapshot.id().as_bytes().to_vec(),
        statement_count: snapshot.statements().len(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompositionInput {
    expected_plan: Option<Vec<u8>>,
    minimum_authorized_branches: u16,
    minimum_distinct_actors: u16,
    minimum_distinct_roots: u16,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileInput {
    id: String,
    version: u16,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PermissionInput {
    capability: String,
    resource: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BudgetInput {
    algebra: String,
    value: u64,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
enum StatusPolicyInput {
    ExpiryOnly,
    SnapshotRequired {
        method: String,
        #[serde(rename = "maxAge")]
        max_age: u64,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustAnchorInput {
    id: String,
    principal: String,
    accepted_methods: Vec<String>,
    profiles: Vec<ProfileInput>,
    permissions: Vec<PermissionInput>,
    resource_namespaces: Vec<String>,
    audiences: Vec<String>,
    not_before: u64,
    expires_at: u64,
    budget: Option<BudgetInput>,
    max_delegation_depth: u16,
    assurance_policy: String,
    status_policy: StatusPolicyInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AssuranceRequirementInput {
    role: String,
    quantifier: String,
    claim_kind: String,
    maximum_age: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AssuranceInput {
    id: String,
    requirements: Vec<AssuranceRequirementInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryInput {
    principal_methods: Vec<String>,
    signature_suites: Vec<String>,
    evidence_types: Vec<String>,
    principal_status_methods: Vec<String>,
    grant_status_methods: Vec<String>,
    assurance_claims: Vec<String>,
    assurance_implications: Vec<String>,
    resource_matchers: Vec<String>,
    budget_algebras: Vec<String>,
    critical_extensions: Vec<String>,
    profiles: Vec<ProfileInput>,
    profile_policies: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LimitInput {
    kind: String,
    value: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustedContextInput {
    composition: CompositionInput,
    trust_anchors: Vec<TrustAnchorInput>,
    registries: RegistryInput,
    expected_audience: String,
    evaluation_time: u64,
    assurance: AssuranceInput,
    resource_matcher: String,
    profile_policy: String,
    channel_policy: String,
    limits: Vec<LimitInput>,
    work_units: u64,
}

fn profile_ref(input: &ProfileInput) -> Result<ProfileRef, EngineError> {
    ProfileRef::new(ProfileId::parse(&input.id)?, input.version).map_err(EngineError::from)
}

fn status_policy(input: StatusPolicyInput) -> Result<StatusPolicy, EngineError> {
    match input {
        StatusPolicyInput::ExpiryOnly => Ok(StatusPolicy::ExpiryOnly),
        StatusPolicyInput::SnapshotRequired { method, max_age } => {
            Ok(StatusPolicy::SnapshotRequired {
                method: StatusMethodId::parse(&method)?,
                max_age: FreshnessLimit::new(max_age)?,
            })
        }
    }
}

fn trust_anchor(input: TrustAnchorInput) -> Result<TrustAnchor, EngineError> {
    if contains_duplicates(&input.accepted_methods)
        || contains_duplicates(&input.profiles)
        || contains_duplicates(&input.permissions)
        || contains_duplicates(&input.resource_namespaces)
        || contains_duplicates(&input.audiences)
    {
        return Err(EngineError::Abi("trust anchor contains duplicate entries"));
    }
    TrustAnchor::new(
        TrustAnchorId::parse(&input.id)?,
        PrincipalId::parse(&input.principal)?,
        input
            .accepted_methods
            .into_iter()
            .map(|value| PrincipalMethodId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
        input
            .profiles
            .into_iter()
            .map(|input| profile_ref(&input))
            .collect::<Result<Vec<_>, _>>()?,
        PermissionSet::new(
            input
                .permissions
                .into_iter()
                .map(|value| {
                    Ok(Permission::new(
                        CapabilityId::parse(&value.capability)?,
                        ResourceId::parse(&value.resource)?,
                    ))
                })
                .collect::<Result<Vec<_>, EngineError>>()?,
        )?,
        input
            .resource_namespaces
            .into_iter()
            .map(|value| ResourceId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
        AudienceSet::new(
            input
                .audiences
                .into_iter()
                .map(|value| Audience::parse(&value))
                .collect::<Result<Vec<_>, _>>()?,
        )?,
        ValidityWindow::new(
            Timestamp::new(input.not_before),
            Timestamp::new(input.expires_at),
        )?,
        match input.budget {
            Some(value) => Some(BudgetCeiling::new(
                BudgetAlgebraId::parse(&value.algebra)?,
                value.value,
            )),
            None => None,
        },
        input.max_delegation_depth,
        AssurancePolicyId::parse(&input.assurance_policy)?,
        status_policy(input.status_policy)?,
    )
    .map_err(EngineError::from)
}

fn participant_role(value: &str) -> Result<ParticipantRole, EngineError> {
    match value {
        "root" => Ok(ParticipantRole::Root),
        "intermediate" => Ok(ParticipantRole::Intermediate),
        "actor" => Ok(ParticipantRole::Actor),
        "external-issuer" => Ok(ParticipantRole::ExternalIssuer),
        _ => Err(EngineError::Abi("invalid assurance participant role")),
    }
}

fn assurance_quantifier(value: &str) -> Result<AssuranceQuantifier, EngineError> {
    match value {
        "any" => Ok(AssuranceQuantifier::Any),
        "every" => Ok(AssuranceQuantifier::Every),
        _ => Err(EngineError::Abi("invalid assurance quantifier")),
    }
}

fn assurance_policy(input: AssuranceInput) -> Result<AssurancePolicy, EngineError> {
    AssurancePolicy::new(
        AssurancePolicyId::parse(&input.id)?,
        input
            .requirements
            .into_iter()
            .map(|value| {
                Ok(AssuranceRequirement::new(
                    participant_role(&value.role)?,
                    assurance_quantifier(&value.quantifier)?,
                    AssuranceClaimId::parse(&value.claim_kind)?,
                    value.maximum_age.map(FreshnessLimit::new).transpose()?,
                ))
            })
            .collect::<Result<Vec<_>, EngineError>>()?,
    )
    .map_err(EngineError::from)
}

fn accepted_registries(input: RegistryInput) -> Result<AcceptedRegistries, EngineError> {
    if contains_duplicates(&input.principal_methods)
        || contains_duplicates(&input.signature_suites)
        || contains_duplicates(&input.evidence_types)
        || contains_duplicates(&input.principal_status_methods)
        || contains_duplicates(&input.grant_status_methods)
        || contains_duplicates(&input.assurance_claims)
        || contains_duplicates(&input.assurance_implications)
        || contains_duplicates(&input.resource_matchers)
        || contains_duplicates(&input.budget_algebras)
        || contains_duplicates(&input.critical_extensions)
        || contains_duplicates(&input.profiles)
        || contains_duplicates(&input.profile_policies)
    {
        return Err(EngineError::Abi(
            "trusted context registries contain duplicate entries",
        ));
    }
    if input.principal_methods.iter().any(|value| {
        ![
            auths_raw_key::RAW_KEY_V1,
            auths_did_key::DID_KEY_V1,
            auths_did_keri::ADAPTER_ID,
        ]
        .contains(&value.as_str())
    }) || input.signature_suites.iter().any(|value| {
        ![auths_signature::ED25519_V1, auths_signature::P256_SHA256_V1].contains(&value.as_str())
    }) {
        return Err(EngineError::Abi(
            "trusted context selected an adapter not installed in this SDK",
        ));
    }
    let profiles = input
        .profiles
        .into_iter()
        .map(|input| profile_ref(&input))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AcceptedRegistries::new(
        auths_registries::TARGET_V1_REGISTRY_MANIFEST,
        input
            .principal_methods
            .into_iter()
            .map(|value| PrincipalMethodId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
        input
            .signature_suites
            .into_iter()
            .map(|value| SignatureSuiteId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
        input
            .evidence_types
            .into_iter()
            .map(|value| EvidenceTypeId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
        input
            .principal_status_methods
            .into_iter()
            .map(|value| StatusMethodId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
        input
            .grant_status_methods
            .into_iter()
            .map(|value| StatusMethodId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
        input
            .assurance_claims
            .into_iter()
            .map(|value| AssuranceClaimId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
        input
            .assurance_implications
            .into_iter()
            .map(|value| AssuranceImplicationId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
        input
            .resource_matchers
            .into_iter()
            .map(|value| ResourceMatcherId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
        input
            .budget_algebras
            .into_iter()
            .map(|value| BudgetAlgebraId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
        input
            .critical_extensions
            .into_iter()
            .map(|value| ExtensionId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
        profiles.clone(),
        input
            .profile_policies
            .into_iter()
            .map(|value| ProfilePolicyId::parse(&value))
            .collect::<Result<Vec<_>, _>>()?,
    )?
    .with_budget_free_profiles(
        profiles
            .into_iter()
            .filter(|profile| {
                shipped_budget_expression(profile) == ProfileBudgetExpression::Inexpressible
            })
            .collect(),
    )?)
}

/// Resolves an accepted profile's budget-expression capability from the Rust
/// profile implementations this SDK ships.
///
/// The capability is a structural fact about a profile's canonical body, so it
/// is read from Rust rather than accepted from the caller: a JavaScript or
/// Python embedder cannot assert that a profile spends nothing. A profile this
/// SDK does not implement resolves to the default, `Expressible`, which keeps
/// an absent requested budget uncovered by a bounded ceiling.
fn shipped_budget_expression(profile: &ProfileRef) -> ProfileBudgetExpression {
    auths_profile_mcp::budget_expression(profile)
        .or_else(|| auths_profile_domains::budget_expression(profile))
        .unwrap_or_default()
}

fn limit_kind(value: &str) -> Result<LimitKind, EngineError> {
    match value {
        "bundle-bytes" => Ok(LimitKind::BundleBytes),
        "action-bytes" => Ok(LimitKind::ActionBytes),
        "context-bytes" => Ok(LimitKind::ContextBytes),
        "grants" => Ok(LimitKind::Grants),
        "actions" => Ok(LimitKind::Actions),
        "plan-leaves" => Ok(LimitKind::PlanLeaves),
        "plan-depth" => Ok(LimitKind::PlanDepth),
        "plan-branching" => Ok(LimitKind::PlanBranching),
        "evidence-objects" => Ok(LimitKind::EvidenceObjects),
        "evidence-bytes" => Ok(LimitKind::EvidenceBytes),
        "control-bindings" => Ok(LimitKind::ControlBindings),
        "principal-status-statements" => Ok(LimitKind::PrincipalStatusStatements),
        "grant-status-statements" => Ok(LimitKind::GrantStatusStatements),
        "attachments" => Ok(LimitKind::Attachments),
        "attachment-bytes" => Ok(LimitKind::AttachmentBytes),
        "signatures" => Ok(LimitKind::Signatures),
        "signature-bytes" => Ok(LimitKind::SignatureBytes),
        "permissions" => Ok(LimitKind::Permissions),
        "audiences" => Ok(LimitKind::Audiences),
        "critical-extensions" => Ok(LimitKind::CriticalExtensions),
        "critical-extension-bytes" => Ok(LimitKind::CriticalExtensionBytes),
        "allowed-body-digests" => Ok(LimitKind::AllowedBodyDigests),
        "binding-evidence" => Ok(LimitKind::BindingEvidence),
        "canonical-body-bytes" => Ok(LimitKind::CanonicalBodyBytes),
        "registry-entries" => Ok(LimitKind::RegistryEntries),
        "trust-anchors" => Ok(LimitKind::TrustAnchors),
        _ => Err(EngineError::Abi("invalid verifier limit kind")),
    }
}

fn verifier_limits(
    inputs: Vec<LimitInput>,
    work_units: u64,
) -> Result<VerifierLimits, EngineError> {
    if contains_duplicates(
        &inputs
            .iter()
            .map(|input| input.kind.as_str())
            .collect::<Vec<_>>(),
    ) {
        return Err(EngineError::Abi(
            "verifier limits contain duplicate entries",
        ));
    }
    let mut limits = VerifierLimits::default_deployment();
    for input in inputs {
        limits = limits.with_limit(limit_kind(&input.kind)?, input.value)?;
    }
    limits
        .with_work_units(work_units)
        .map_err(EngineError::from)
}

fn contains_duplicates<T: Ord>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}

fn composition(input: CompositionInput) -> Result<CompositionRequirement, EngineError> {
    let expected_plan = input
        .expected_plan
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes.as_slice())
                .map(auths_model::PlanId::new)
                .map_err(|_| EngineError::Abi("expected plan id must contain 32 bytes"))
        })
        .transpose()?;
    CompositionRequirement::new(
        expected_plan,
        input.minimum_authorized_branches,
        input.minimum_distinct_actors,
        input.minimum_distinct_roots,
    )
    .map_err(EngineError::from)
}

/// Rust-compiled immutable trusted context and executable registry configuration.
#[wasm_bindgen]
pub struct TrustedContextCompilationV1 {
    cbor: Vec<u8>,
    verifier_configuration: Vec<u8>,
}

#[wasm_bindgen]
impl TrustedContextCompilationV1 {
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn cbor(&self) -> Vec<u8> {
        self.cbor.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = verifierConfiguration)]
    pub fn verifier_configuration(&self) -> Vec<u8> {
        self.verifier_configuration.clone()
    }
}

/// Compiles typed roots, registries, lifecycle, assurance, and limits into a verifier context.
///
/// # Errors
///
/// Returns a JavaScript error for any malformed or mutually inconsistent field.
#[wasm_bindgen(js_name = compileTrustedContextV1)]
pub fn compile_trusted_context_v1(
    value: JsValue,
    principal_status_cbor: &[u8],
    grant_status_cbor: &[u8],
) -> Result<TrustedContextCompilationV1, JsValue> {
    let input: TrustedContextInput = serde_wasm_bindgen::from_value(value)
        .map_err(|_| js_error(EngineError::Abi("invalid trusted context configuration")))?;
    let limits = verifier_limits(input.limits, input.work_units).map_err(js_error)?;
    let principal_status =
        auths_codec::decode_principal_status_snapshot(principal_status_cbor, &limits)
            .map_err(js_error)?;
    let grant_status =
        auths_codec::decode_grant_status_snapshot(grant_status_cbor, &limits).map_err(js_error)?;
    let configuration = self_contained_v1_configuration().map_err(js_error)?;
    let context = TrustedContext::new(
        VerifierConfigurationId::new(configuration),
        composition(input.composition).map_err(js_error)?,
        input
            .trust_anchors
            .into_iter()
            .map(trust_anchor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(js_error)?,
        accepted_registries(input.registries).map_err(js_error)?,
        Audience::parse(&input.expected_audience).map_err(js_error)?,
        Challenge::new([0; 32]),
        Timestamp::new(input.evaluation_time),
        assurance_policy(input.assurance).map_err(js_error)?,
        principal_status,
        grant_status,
        ResourceMatcherId::parse(&input.resource_matcher).map_err(js_error)?,
        ProfilePolicyId::parse(&input.profile_policy).map_err(js_error)?,
        ChannelBindingId::parse(&input.channel_policy).map_err(js_error)?,
        limits,
    )
    .map_err(js_error)?;
    Ok(TrustedContextCompilationV1 {
        cbor: auths_codec::encode_verifier_context(&context).map_err(js_error)?,
        verifier_configuration: configuration.to_vec(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentityDescriptorInput {
    method_id: String,
    identity_id: String,
    method_material: Vec<u8>,
    relationships: Vec<VerificationRelationshipInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerificationRelationshipInput {
    relationship_id: String,
    purpose: String,
    suite_id: String,
    verification_material: Vec<VerificationMaterialInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerificationMaterialInput {
    material_id: String,
    bytes: Vec<u8>,
}

fn identity_descriptor(input: IdentityDescriptorInput) -> Result<IdentityDescriptor, EngineError> {
    IdentityDescriptor::new(
        &input.method_id,
        &input.identity_id,
        input.method_material,
        input
            .relationships
            .into_iter()
            .map(|relationship| {
                VerificationRelationship::new(
                    &relationship.relationship_id,
                    &relationship.purpose,
                    &relationship.suite_id,
                    relationship
                        .verification_material
                        .into_iter()
                        .map(|material| {
                            VerificationMaterial::new(&material.material_id, material.bytes)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(EngineError::from)
}

fn identity_descriptor_value(descriptor: &IdentityDescriptor) -> Value {
    let relationships = descriptor
        .relationships()
        .iter()
        .map(|relationship| {
            serde_json::json!({
                "relationshipId": relationship.relationship_id(),
                "purpose": relationship.purpose(),
                "suiteId": relationship.suite_id(),
                "verificationMaterial": relationship.verification_material().iter().map(|material| {
                    serde_json::json!({
                        "materialId": material.material_id(),
                        "bytes": material.bytes(),
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "methodId": descriptor.method_id(),
        "identityId": descriptor.identity_id(),
        "methodMaterial": descriptor.method_material(),
        "relationships": relationships,
    })
}

/// Encodes one credential-shape-agnostic identity descriptor into canonical bytes.
///
/// # Errors
///
/// Rejects malformed, duplicate, excessive, or unsupported descriptor fields.
#[wasm_bindgen(js_name = encodeIdentityDescriptorV1)]
pub fn encode_identity_descriptor_v1(value: JsValue) -> Result<Vec<u8>, JsValue> {
    let input: IdentityDescriptorInput = serde_wasm_bindgen::from_value(value)
        .map_err(|_| js_error(EngineError::Abi("invalid identity descriptor")))?;
    identity_descriptor(input)
        .and_then(|descriptor| descriptor.encode().map_err(EngineError::from))
        .map_err(js_error)
}

/// Decodes one complete canonical credential-shape-agnostic descriptor.
///
/// # Errors
///
/// Rejects malformed, non-canonical, trailing, or excessive input.
#[wasm_bindgen(js_name = decodeIdentityDescriptorV1)]
pub fn decode_identity_descriptor_v1(packet: &[u8]) -> Result<JsValue, JsValue> {
    let descriptor = IdentityDescriptor::decode(packet).map_err(js_error)?;
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    identity_descriptor_value(&descriptor)
        .serialize(&serializer)
        .map_err(|_| js_error(EngineError::Abi("identity descriptor cannot cross the ABI")))
}

/// Returns the exact relationship-bound application-message signing bytes.
///
/// # Errors
///
/// Rejects malformed descriptors, unknown relationships, and excessive messages.
#[wasm_bindgen(js_name = identityDescriptorSigningPreimageV1)]
pub fn identity_descriptor_signing_preimage_v1(
    packet: &[u8],
    relationship_id: &str,
    message: &[u8],
) -> Result<Vec<u8>, JsValue> {
    IdentityDescriptor::decode(packet)
        .and_then(|descriptor| descriptor.signing_preimage(relationship_id, message))
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

#[wasm_bindgen]
pub struct SignedIdentityMessageFieldsV2 {
    identity: IdentityFieldsV2,
    message: Vec<u8>,
    signature: Vec<u8>,
}

#[wasm_bindgen]
impl SignedIdentityMessageFieldsV2 {
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

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
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

#[wasm_bindgen(js_name = decodeSignedIdentityMessageV2)]
/// Decodes one canonical signed identity message without authenticating it.
///
/// # Errors
///
/// Rejects malformed, non-canonical, public-identity, trailing, or oversized packets.
pub fn decode_signed_identity_message_v2(
    packet: &[u8],
) -> Result<SignedIdentityMessageFieldsV2, JsValue> {
    match IdentityPacket::decode(packet).map_err(js_error)? {
        IdentityPacket::PublicIdentity(_) => Err(js_error("expected a signed identity message")),
        IdentityPacket::SignedMessage(signed) => Ok(SignedIdentityMessageFieldsV2 {
            identity: IdentityFieldsV2::from(signed.identity()),
            message: signed.message().to_vec(),
            signature: signed.signature().to_vec(),
        }),
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
pub struct AuthorizationPlanBuilderV1 {
    plans: Vec<AuthorizationPlan>,
}

#[wasm_bindgen]
impl AuthorizationPlanBuilderV1 {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self { plans: Vec::new() }
    }

    /// Adds one exact proof reference.
    ///
    /// # Errors
    ///
    /// Rejects a reference with any width other than 32 bytes.
    pub fn proof(&mut self, reference: &[u8]) -> Result<u32, JsValue> {
        let reference: [u8; 32] = reference
            .try_into()
            .map_err(|_| js_error("proof reference must contain exactly 32 bytes"))?;
        self.push(AuthorizationPlan::proof(ProofRef::new(reference)))
    }

    #[wasm_bindgen(js_name = allOf)]
    /// Composes plans that must all authorize.
    ///
    /// # Errors
    ///
    /// Rejects unknown, empty, duplicate, or over-limit membership.
    pub fn all_of(&mut self, members: &[u32]) -> Result<u32, JsValue> {
        let members = self.members(members)?;
        let plan = AuthorizationPlan::all_of(members)
            .map_err(EngineError::from)
            .map_err(js_error)?;
        self.push(plan)
    }

    #[wasm_bindgen(js_name = anyOf)]
    /// Composes plans where any member may authorize.
    ///
    /// # Errors
    ///
    /// Rejects unknown, empty, duplicate, or over-limit membership.
    pub fn any_of(&mut self, members: &[u32]) -> Result<u32, JsValue> {
        let members = self.members(members)?;
        let plan = AuthorizationPlan::any_of(members)
            .map_err(EngineError::from)
            .map_err(js_error)?;
        self.push(plan)
    }

    #[wasm_bindgen(js_name = threshold)]
    /// Composes a bounded threshold over exact members.
    ///
    /// # Errors
    ///
    /// Rejects unknown, duplicate, impossible, or over-limit membership.
    pub fn threshold(&mut self, required: u16, members: &[u32]) -> Result<u32, JsValue> {
        let members = self.members(members)?;
        let plan = AuthorizationPlan::k_of_n(required, members)
            .map_err(EngineError::from)
            .map_err(js_error)?;
        self.push(plan)
    }

    /// Returns the canonical plan and bounded shape summary.
    ///
    /// # Errors
    ///
    /// Rejects unknown or over-limit plans.
    pub fn summarize(&self, handle: u32) -> Result<AuthorizationPlanSummaryV1, JsValue> {
        let plan = self.plan(handle)?;
        let shape = plan
            .validate(&VerifierLimits::default_deployment())
            .map_err(EngineError::from)
            .map_err(js_error)?;
        Ok(AuthorizationPlanSummaryV1 {
            plan_cbor: auths_codec::encode_authorization_plan(plan)
                .map_err(EngineError::from)
                .map_err(js_error)?,
            plan_id: auths_codec::plan_id(plan)
                .map_err(EngineError::from)
                .map_err(js_error)?
                .as_bytes()
                .to_vec(),
            proof_references: shape
                .leaves()
                .iter()
                .flat_map(auths_model::ProofRef::as_bytes)
                .copied()
                .collect(),
            leaf_count: u32::try_from(shape.leaves().len())
                .map_err(|_| js_error("authorization plan leaf count exceeds the ABI"))?,
            maximum_depth: u32::try_from(shape.maximum_depth())
                .map_err(|_| js_error("authorization plan depth exceeds the ABI"))?,
        })
    }

    fn push(&mut self, plan: AuthorizationPlan) -> Result<u32, JsValue> {
        plan.validate(&VerifierLimits::default_deployment())
            .map_err(EngineError::from)
            .map_err(js_error)?;
        let handle = u32::try_from(self.plans.len())
            .map_err(|_| js_error("authorization plan builder is full"))?;
        self.plans.push(plan);
        Ok(handle)
    }

    fn plan(&self, handle: u32) -> Result<&AuthorizationPlan, JsValue> {
        self.plans
            .get(handle as usize)
            .ok_or_else(|| js_error("authorization plan handle is unknown"))
    }

    fn members(&self, handles: &[u32]) -> Result<Vec<AuthorizationPlan>, JsValue> {
        handles
            .iter()
            .map(|handle| self.plan(*handle).cloned())
            .collect()
    }
}

impl Default for AuthorizationPlanBuilderV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub struct AuthorizationPlanSummaryV1 {
    plan_cbor: Vec<u8>,
    plan_id: Vec<u8>,
    proof_references: Vec<u8>,
    leaf_count: u32,
    maximum_depth: u32,
}

#[wasm_bindgen]
impl AuthorizationPlanSummaryV1 {
    #[must_use]
    #[wasm_bindgen(getter, js_name = planCbor)]
    pub fn plan_cbor(&self) -> Vec<u8> {
        self.plan_cbor.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = planId)]
    pub fn plan_id(&self) -> Vec<u8> {
        self.plan_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = proofReferences)]
    pub fn proof_references(&self) -> Vec<u8> {
        self.proof_references.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = leafCount)]
    pub fn leaf_count(&self) -> u32 {
        self.leaf_count
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = maximumDepth)]
    pub fn maximum_depth(&self) -> u32 {
        self.maximum_depth
    }
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

/// Receipt commitments derived from the exact artifacts consumed by verification.
#[wasm_bindgen]
pub struct ProfileReceiptBindingsV1 {
    action: Vec<u8>,
    authority: Vec<u8>,
    context: Vec<u8>,
}

/// Canonical native receipt bytes and their exact attestation preimage.
#[wasm_bindgen]
pub struct ReceiptPreparationV1 {
    id: Vec<u8>,
    canonical: Vec<u8>,
    signing_preimage: Vec<u8>,
}

#[wasm_bindgen]
impl ReceiptPreparationV1 {
    #[must_use]
    #[wasm_bindgen(getter, js_name = receiptId)]
    pub fn receipt_id(&self) -> Vec<u8> {
        self.id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn canonical(&self) -> Vec<u8> {
        self.canonical.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = signingPreimage)]
    pub fn signing_preimage(&self) -> Vec<u8> {
        self.signing_preimage.clone()
    }
}

#[wasm_bindgen]
impl ProfileReceiptBindingsV1 {
    #[must_use]
    #[wasm_bindgen(getter, js_name = actionCommitment)]
    pub fn action_commitment(&self) -> Vec<u8> {
        self.action.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = authorityCommitment)]
    pub fn authority_commitment(&self) -> Vec<u8> {
        self.authority.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = contextCommitment)]
    pub fn context_commitment(&self) -> Vec<u8> {
        self.context.clone()
    }
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

/// Derives the Ed25519 public key for a deterministic development seed.
///
/// # Errors
///
/// Returns a JavaScript error unless the seed is exactly 32 bytes.
#[wasm_bindgen(js_name = developmentEd25519PublicKeyV1)]
pub fn development_ed25519_public_key_v1(seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| js_error("development Ed25519 seed must contain 32 bytes"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
        .to_vec())
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
        vec![profile.clone()],
        vec![auths_model::ProfilePolicyId::parse(
            auths_registries::EXACT_PROFILE_V1,
        )?],
    )?
    .with_budget_free_profiles(
        // Read from the Rust profile implementation, never asserted here: a
        // profile with no budget field in its canonical body spends zero, and a
        // profile this SDK does not ship keeps the denying default.
        (shipped_budget_expression(&profile) == ProfileBudgetExpression::Inexpressible)
            .then_some(profile)
            .into_iter()
            .collect(),
    )?;
    let context = auths_model::TrustedContext::new(
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

/// Derives receipt commitments from the exact canonical verification inputs.
///
/// # Errors
///
/// Returns a JavaScript error when any input is malformed or non-canonical.
#[wasm_bindgen(js_name = profileReceiptBindingsV1)]
pub fn profile_receipt_bindings_v1(
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
) -> Result<ProfileReceiptBindingsV1, JsValue> {
    let limits = VerifierLimits::default_deployment();
    let proof = auths_codec::decode_bundle(proof_cbor, &limits).map_err(js_error)?;
    let action =
        auths_codec::decode_canonical_action(canonical_action_cbor, &limits).map_err(js_error)?;
    let context = auths_codec::decode_verifier_context(trusted_context_cbor).map_err(js_error)?;
    let canonical_action = auths_codec::encode_canonical_action(&action).map_err(js_error)?;
    Ok(ProfileReceiptBindingsV1 {
        action: auths_codec::domain_commitment("auths.canonical-action.v1", &canonical_action)
            .map_err(js_error)?
            .as_bytes()
            .to_vec(),
        authority: auths_codec::proof_digest(&proof)
            .map_err(js_error)?
            .as_bytes()
            .to_vec(),
        context: auths_codec::context_digest(&context)
            .map_err(js_error)?
            .as_bytes()
            .to_vec(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpSessionStepProjection {
    kind: &'static str,
    execution_id: String,
    service: Option<String>,
    tool: Option<String>,
    bytes: Option<Vec<u8>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpSessionTerminalProjection {
    kind: &'static str,
    execution_id: String,
    output_json: Option<Vec<u8>>,
    receipt_json: Option<Vec<u8>>,
    reference: Option<String>,
    record_json: Option<Vec<u8>>,
    /// The stable registry code this outcome carries, named by the profile.
    /// `None` only for a completed execution, which is not a failure.
    code: Option<&'static str>,
}

#[wasm_bindgen(js_name = McpExecutionSessionV1)]
pub struct McpExecutionSessionV1 {
    inner: McpExecutionSession,
}

#[wasm_bindgen(js_class = McpExecutionSessionV1)]
impl McpExecutionSessionV1 {
    #[must_use]
    #[wasm_bindgen(getter, js_name = executionId)]
    pub fn execution_id(&self) -> String {
        self.inner.execution_id().to_owned()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = canonicalAction)]
    pub fn canonical_action(&self) -> Vec<u8> {
        self.inner.canonical_action().to_vec()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = decisionReceiptId)]
    pub fn decision_receipt_id(&self) -> Vec<u8> {
        self.inner.decision_receipt_id().to_vec()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = decisionReceipt)]
    pub fn decision_receipt(&self) -> Vec<u8> {
        self.inner.decision_receipt().to_vec()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = planCommitment)]
    pub fn plan_commitment(&self) -> Option<Vec<u8>> {
        self.inner.plan_commitment().map(|value| value.to_vec())
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = memberIndex)]
    pub fn member_index(&self) -> Option<u16> {
        self.inner.member_index()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = memberCount)]
    pub fn member_count(&self) -> Option<u16> {
        self.inner.member_count()
    }

    /// Projects authenticated recovery material for the pending durable step.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error when the current state has no crash-safe checkpoint.
    pub fn checkpoint(&self) -> Result<JsValue, JsValue> {
        let checkpoint = self.inner.checkpoint().map_err(js_error)?;
        serde_wasm_bindgen::to_value(&mcp_session_terminal(&checkpoint)).map_err(js_error)
    }

    /// Releases the next bounded I/O step.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error until the prior result arrives or after termination.
    #[wasm_bindgen(js_name = nextStep)]
    pub fn next_step(&mut self) -> Result<JsValue, JsValue> {
        let step = self.inner.next_step().map_err(js_error)?;
        serde_wasm_bindgen::to_value(&mcp_session_step(step)).map_err(js_error)
    }

    /// Accepts the atomic reservation observation.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for an unknown result or invalid transition.
    #[wasm_bindgen(js_name = acceptReservation)]
    pub fn accept_reservation(&mut self, result: &str) -> Result<(), JsValue> {
        let result = match result {
            "acquired" => McpReservationResult::Acquired,
            "exact-replay" => McpReservationResult::ExactReplay,
            "conflict" => McpReservationResult::Conflict,
            _ => return Err(js_error(EngineError::Abi("invalid MCP reservation result"))),
        };
        self.inner.accept_reservation(result).map_err(js_error)
    }

    /// Accepts durable provider-entry evidence.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error unless provider entry is the pending step.
    #[wasm_bindgen(js_name = acceptProviderEntry)]
    pub fn accept_provider_entry(&mut self) -> Result<(), JsValue> {
        self.inner.accept_provider_entry().map_err(js_error)
    }

    /// Terminates safely when cancellation arrives before provider entry.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error after provider entry or outside that step.
    #[wasm_bindgen(js_name = cancelBeforeProvider)]
    pub fn cancel_before_provider(&mut self) -> Result<(), JsValue> {
        self.inner.cancel_before_provider().map_err(js_error)
    }

    /// Accepts one bounded handler or reconciliation result.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for invalid classifications, bounds, or transitions.
    #[allow(clippy::needless_pass_by_value)]
    #[wasm_bindgen(js_name = acceptHandler)]
    pub fn accept_handler(
        &mut self,
        effect: &str,
        output_json: Option<Vec<u8>>,
        cause: Option<String>,
    ) -> Result<(), JsValue> {
        let effect = match effect {
            "not-applied" => McpHandlerEffect::NotApplied,
            "applied" => McpHandlerEffect::Applied,
            "possible" => McpHandlerEffect::Possible,
            _ => return Err(js_error(EngineError::Abi("invalid MCP handler effect"))),
        };
        let cause = cause
            .as_deref()
            .map(parse_mcp_cause)
            .transpose()
            .map_err(js_error)?;
        let result =
            McpHandlerResult::parse(effect, output_json.as_deref(), cause).map_err(js_error)?;
        self.inner.accept_handler(result).map_err(js_error)
    }

    /// Accepts receipt persistence evidence.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for an invalid transition or persistence failure.
    #[wasm_bindgen(js_name = acceptReceipt)]
    pub fn accept_receipt(&mut self, persisted: bool) -> Result<(), JsValue> {
        self.inner.accept_receipt(persisted).map_err(js_error)
    }

    /// Projects the terminal result without exposing the session capability.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error only if the bounded projection cannot be encoded.
    pub fn terminal(&self) -> Result<JsValue, JsValue> {
        match self.inner.terminal() {
            Some(value) => {
                serde_wasm_bindgen::to_value(&mcp_session_terminal(value)).map_err(js_error)
            }
            None => Ok(JsValue::NULL),
        }
    }
}

/// Verifies exact artifacts and opens one closed MCP execution session.
///
/// # Errors
///
/// Returns a JavaScript error for incompatible artifacts, a denied action, or
/// invalid bounded session configuration.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
#[wasm_bindgen(js_name = beginMcpExecutionV1)]
pub fn begin_mcp_execution_v1(
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
    decision_receipt_id: &[u8],
    decision_receipt: &[u8],
    has_plan: bool,
    plan_commitment: &[u8],
    member_index: u16,
    member_count: u16,
    request_id: Option<String>,
    session_key: &[u8],
) -> Result<McpExecutionSessionV1, JsValue> {
    let key: [u8; 32] = session_key
        .try_into()
        .map_err(|_| js_error(EngineError::Abi("MCP session key must contain 32 bytes")))?;
    let decision_receipt_id: [u8; 32] = decision_receipt_id.try_into().map_err(|_| {
        js_error(EngineError::Abi(
            "MCP decision receipt ID must contain 32 bytes",
        ))
    })?;
    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(js_error)?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(js_error)?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(js_error)?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(js_error)?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(js_error)?;
    let methods: [&dyn PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
    let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
    let registries = ImmutableRegistries::new(&methods, &suites).map_err(js_error)?;
    let sealed = auths_verifier::verify_v1_sealed(
        proof_cbor,
        canonical_action_cbor,
        trusted_context_cbor,
        &registries,
    )
    .map_err(js_error)?;
    let (_, _, action) = sealed.into_parts();
    let action =
        action.ok_or_else(|| js_error(EngineError::Abi("MCP action is not authorized")))?;
    let command = McpProfile.decode_verified(&action).map_err(js_error)?;
    let action_commitment =
        *auths_codec::domain_commitment("auths.canonical-action.v1", canonical_action_cbor)
            .map_err(js_error)?
            .as_bytes();
    let proof = auths_codec::decode_bundle(proof_cbor, &VerifierLimits::default_deployment())
        .map_err(js_error)?;
    let context = auths_codec::decode_verifier_context(trusted_context_cbor).map_err(js_error)?;
    let authority_commitment = mcp_authority_commitment(proof.grants()).map_err(js_error)?;
    let context_commitment = *auths_codec::context_digest(&context)
        .map_err(js_error)?
        .as_bytes();
    let inner = if has_plan {
        let plan_commitment: [u8; 32] = plan_commitment.try_into().map_err(|_| {
            js_error(EngineError::Abi(
                "MCP plan commitment must contain 32 bytes",
            ))
        })?;
        McpExecutionSession::begin_plan_member(
            command,
            action_commitment,
            authority_commitment,
            context_commitment,
            canonical_action_cbor.to_vec(),
            decision_receipt_id,
            decision_receipt.to_vec(),
            plan_commitment,
            member_index,
            member_count,
            request_id.as_deref(),
            McpSessionKey::new(key),
        )
    } else {
        if !plan_commitment.is_empty() || member_index != 0 || member_count != 0 {
            return Err(js_error(EngineError::Abi("unexpected MCP plan binding")));
        }
        McpExecutionSession::begin(
            command,
            action_commitment,
            authority_commitment,
            context_commitment,
            canonical_action_cbor.to_vec(),
            decision_receipt_id,
            decision_receipt.to_vec(),
            request_id.as_deref(),
            McpSessionKey::new(key),
        )
    }
    .map_err(js_error)?;
    Ok(McpExecutionSessionV1 { inner })
}

/// Authenticates and resumes one stored MCP execution.
///
/// # Errors
///
/// Returns a JavaScript error for a forged, corrupt, or mismatched record.
#[wasm_bindgen(js_name = resumeMcpExecutionV1)]
pub fn resume_mcp_execution_v1(
    session_key: &[u8],
    reference: &str,
    record_json: &[u8],
) -> Result<McpExecutionSessionV1, JsValue> {
    let key: [u8; 32] = session_key
        .try_into()
        .map_err(|_| js_error(EngineError::Abi("MCP session key must contain 32 bytes")))?;
    let inner = McpExecutionSession::resume(McpSessionKey::new(key), reference, record_json)
        .map_err(js_error)?;
    Ok(McpExecutionSessionV1 { inner })
}

fn mcp_session_step(step: McpSessionStep) -> McpSessionStepProjection {
    match step {
        McpSessionStep::Reserve { execution_id } => McpSessionStepProjection {
            kind: "reserve",
            execution_id,
            service: None,
            tool: None,
            bytes: None,
        },
        McpSessionStep::MarkProviderEntry { execution_id } => McpSessionStepProjection {
            kind: "mark-provider-entry",
            execution_id,
            service: None,
            tool: None,
            bytes: None,
        },
        McpSessionStep::Invoke {
            execution_id,
            service,
            tool,
            arguments_json,
        } => McpSessionStepProjection {
            kind: "invoke",
            execution_id,
            service: Some(service),
            tool: Some(tool),
            bytes: Some(arguments_json),
        },
        McpSessionStep::PersistReceipt {
            execution_id,
            receipt_json,
        } => McpSessionStepProjection {
            kind: "persist-receipt",
            execution_id,
            service: None,
            tool: None,
            bytes: Some(receipt_json),
        },
        McpSessionStep::Reconcile {
            execution_id,
            service,
        } => McpSessionStepProjection {
            kind: "reconcile",
            execution_id,
            service: Some(service),
            tool: None,
            bytes: None,
        },
    }
}

fn mcp_session_terminal(value: &McpTerminal) -> McpSessionTerminalProjection {
    // The code is read from the profile, never chosen here. WASM is a
    // transport: it may not name an outcome the profile did not name.
    let code = value.registry_code();
    match value {
        McpTerminal::Completed {
            execution_id,
            output_json,
            receipt_json,
        } => McpSessionTerminalProjection {
            kind: "completed",
            execution_id: execution_id.clone(),
            output_json: Some(output_json.clone()),
            receipt_json: Some(receipt_json.clone()),
            reference: None,
            record_json: None,
            code,
        },
        McpTerminal::NotApplied { execution_id } => {
            terminal_without_data("not-applied", execution_id, code)
        }
        McpTerminal::ExactReplay { execution_id } => {
            terminal_without_data("exact-replay", execution_id, code)
        }
        McpTerminal::Conflict { execution_id } => {
            terminal_without_data("conflict", execution_id, code)
        }
        McpTerminal::Recoverable {
            execution_id,
            reference,
            record_json,
            ..
        } => McpSessionTerminalProjection {
            kind: "recoverable",
            execution_id: execution_id.clone(),
            output_json: None,
            receipt_json: None,
            reference: Some(reference.as_str().to_owned()),
            record_json: Some(record_json.clone()),
            code,
        },
    }
}

fn terminal_without_data(
    kind: &'static str,
    execution_id: &str,
    code: Option<&'static str>,
) -> McpSessionTerminalProjection {
    McpSessionTerminalProjection {
        kind,
        execution_id: execution_id.to_owned(),
        output_json: None,
        receipt_json: None,
        reference: None,
        record_json: None,
        code,
    }
}

fn parse_mcp_cause(value: &str) -> Result<McpCause, EngineError> {
    match value {
        "cancelled" => Ok(McpCause::Cancelled),
        "invalid-output" => Ok(McpCause::InvalidOutput),
        "limit-exceeded" => Ok(McpCause::LimitExceeded),
        "timeout" => Ok(McpCause::Timeout),
        "unavailable" => Ok(McpCause::Unavailable),
        "unknown" => Ok(McpCause::Unknown),
        _ => Err(EngineError::Abi("invalid MCP cause category")),
    }
}

/// Prepares one canonical authorized decision receipt from exact verified
/// artifacts.
///
/// # Errors
///
/// Returns a JavaScript error for malformed, non-canonical, or out-of-limit
/// inputs.
#[wasm_bindgen(js_name = prepareAuthorizedDecisionReceiptV1)]
pub fn prepare_authorized_decision_receipt_v1(
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
    decided_at: u64,
    verifier: &str,
    verification_method: &str,
    suite: &str,
) -> Result<ReceiptPreparationV1, JsValue> {
    let limits = VerifierLimits::default_deployment();
    let proof = auths_codec::decode_bundle(proof_cbor, &limits).map_err(js_error)?;
    if auths_codec::encode_bundle(&proof)
        .map_err(js_error)?
        .as_slice()
        != proof_cbor
    {
        return Err(js_error(EngineError::Abi("proof is not canonical")));
    }
    let action =
        auths_codec::decode_canonical_action(canonical_action_cbor, &limits).map_err(js_error)?;
    if auths_codec::encode_canonical_action(&action)
        .map_err(js_error)?
        .as_slice()
        != canonical_action_cbor
    {
        return Err(js_error(EngineError::Abi("action is not canonical")));
    }
    let context = auths_codec::decode_verifier_context(trusted_context_cbor).map_err(js_error)?;
    if auths_codec::encode_verifier_context(&context)
        .map_err(js_error)?
        .as_slice()
        != trusted_context_cbor
    {
        return Err(js_error(EngineError::Abi(
            "trusted context is not canonical",
        )));
    }
    let signer = receipt_signer(verifier, verification_method, suite).map_err(js_error)?;
    let authority_commitment = auths_codec::proof_digest(&proof).map_err(js_error)?;
    let prepared = prepare_decision_receipt(
        authority_commitment,
        &action,
        &context,
        DecisionClass::Authorized,
        vec!["authorized".to_owned()],
        Timestamp::new(decided_at),
        &signer,
    )
    .map_err(js_error)?;
    Ok(receipt_preparation(prepared))
}

/// Prepares one canonical application execution receipt.
///
/// # Errors
///
/// Returns a JavaScript error for an invalid decision, lease, command,
/// result, outcome, or signer.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = prepareApplicationExecutionReceiptV1)]
pub fn prepare_application_execution_receipt_v1(
    decision_receipt_id: &[u8],
    idempotency_key: &str,
    has_plan: bool,
    plan_commitment: &[u8],
    member_index: u16,
    member_count: u16,
    command_bytes: &[u8],
    outcome: &str,
    has_result: bool,
    result: &[u8],
    completed_at: u64,
    verifier: &str,
    verification_method: &str,
    suite: &str,
) -> Result<ReceiptPreparationV1, JsValue> {
    if command_bytes.is_empty() || command_bytes.len() > auths_model::HARD_MAX_ACTION_BYTES {
        return Err(js_error(EngineError::Abi(
            "command bytes are outside bounds",
        )));
    }
    let decision =
        auths_model::ReceiptId::new(receipt_array32(decision_receipt_id, "decision receipt id")?);
    let plan = has_plan
        .then(|| receipt_array32(plan_commitment, "plan commitment").map(Digest::new))
        .transpose()?;
    if !has_plan && !plan_commitment.is_empty() {
        return Err(js_error(EngineError::Abi("unexpected plan commitment")));
    }
    let member = has_plan.then_some((member_index, member_count));
    application_execution_lease_digest(idempotency_key, plan, member).map_err(js_error)?;
    if !has_result && !result.is_empty() {
        return Err(js_error(EngineError::Abi("unexpected execution result")));
    }
    let signer = receipt_signer(verifier, verification_method, suite).map_err(js_error)?;
    let prepared = prepare_execution_receipt(
        decision,
        idempotency_key,
        plan,
        member,
        command_bytes,
        match outcome {
            "succeeded" => ExecutionOutcome::Succeeded,
            "failed" => ExecutionOutcome::Failed,
            "indeterminate" => ExecutionOutcome::Indeterminate,
            _ => {
                return Err(js_error(EngineError::Abi(
                    "execution outcome cannot be attested",
                )));
            }
        },
        has_result.then_some(result),
        Timestamp::new(completed_at),
        &signer,
    )
    .map_err(js_error)?;
    Ok(receipt_preparation(prepared))
}

/// Attaches an exact verifier signature to canonical decision receipt bytes.
///
/// # Errors
///
/// Returns a JavaScript error for malformed receipt, signer, or signature
/// inputs.
#[wasm_bindgen(js_name = attestDecisionReceiptV1)]
pub fn attest_decision_receipt_v1(
    canonical: &[u8],
    verifier: &str,
    verification_method: &str,
    suite: &str,
    signature: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let receipt = decode_decision(canonical).map_err(js_error)?;
    let signer = receipt_signer(verifier, verification_method, suite).map_err(js_error)?;
    encode_attested_decision(&AttestedDecisionReceipt::new(
        receipt,
        signer,
        SignatureBytes::new(signature.to_vec()).map_err(js_error)?,
    ))
    .map_err(js_error)
}

/// Attaches an exact verifier signature to canonical execution receipt bytes.
///
/// # Errors
///
/// Returns a JavaScript error for malformed receipt, signer, or signature
/// inputs.
#[wasm_bindgen(js_name = attestExecutionReceiptV1)]
pub fn attest_execution_receipt_v1(
    canonical: &[u8],
    verifier: &str,
    verification_method: &str,
    suite: &str,
    signature: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let receipt = decode_execution(canonical).map_err(js_error)?;
    let signer = receipt_signer(verifier, verification_method, suite).map_err(js_error)?;
    encode_attested_execution(&AttestedExecutionReceipt::new(
        receipt,
        signer,
        SignatureBytes::new(signature.to_vec()).map_err(js_error)?,
    ))
    .map_err(js_error)
}

/// Verifies a canonical receipt attestation under one exact raw Ed25519 key.
///
/// # Errors
///
/// Returns a JavaScript error for any structural, identity, suite, or
/// signature mismatch.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = verifyRawKeyReceiptV1)]
pub fn verify_raw_key_receipt_v1(
    kind: &str,
    attested: &[u8],
    expected_id: &[u8],
    verifier: &str,
    verification_method: &str,
    suite: &str,
    raw_key_evidence: &[u8],
) -> Result<(), JsValue> {
    let expected_verifier = PrincipalId::parse(verifier).map_err(js_error)?;
    let signer = ReceiptSigner::new(
        expected_verifier.clone(),
        VerificationMethod::parse(verification_method).map_err(js_error)?,
        SignatureSuiteId::parse(suite).map_err(js_error)?,
    );
    let descriptor = auths_raw_key::RawKeyDescriptor::decode(raw_key_evidence)
        .map_err(|_| js_error(EngineError::Abi("invalid raw-key receipt evidence")))?;
    if descriptor.principal().map_err(js_error)? != expected_verifier || descriptor.suite() != suite
    {
        return Err(js_error(EngineError::Abi(
            "receipt key does not match signer",
        )));
    }
    let expected = auths_model::ReceiptId::new(receipt_array32(expected_id, "receipt id")?);
    let suite = auths_signature::Ed25519Suite::new().map_err(js_error)?;
    let configured = ConfiguredReceiptVerifier::new(signer, descriptor.public_key(), &suite);
    match kind {
        "decision" => {
            verify_decision_attestation(attested, expected, &expected_verifier, &configured)
                .map_err(js_error)?;
        }
        "execution" => {
            verify_execution_attestation(attested, expected, &expected_verifier, &configured)
                .map_err(js_error)?;
        }
        _ => return Err(js_error(EngineError::Abi("unsupported receipt kind"))),
    }
    Ok(())
}

/// Verifies the structural link between one decision and execution receipt.
///
/// # Errors
///
/// Returns a JavaScript error for malformed receipts, mismatched identifiers,
/// or an execution linked to another decision.
#[wasm_bindgen(js_name = verifyReceiptLinkV1)]
pub fn verify_receipt_link_v1(
    decision: &[u8],
    decision_id: &[u8],
    execution: &[u8],
    execution_id: &[u8],
) -> Result<(), JsValue> {
    let decision_id = auths_model::ReceiptId::new(receipt_array32(
        decision_id,
        "decision receipt id must contain 32 bytes",
    )?);
    verify_attested_decision_bytes(decision, decision_id).map_err(js_error)?;
    let execution_id = auths_model::ReceiptId::new(receipt_array32(
        execution_id,
        "execution receipt id must contain 32 bytes",
    )?);
    let execution = verify_attested_execution_bytes(execution, execution_id).map_err(js_error)?;
    if execution.receipt().decision_receipt() != decision_id {
        return Err(js_error(EngineError::Abi("receipt linkage mismatch")));
    }
    Ok(())
}

/// Encodes one bounded disclosure for an execution receipt.
///
/// # Errors
///
/// Rejects invalid identifiers, profiles, and over-limit material.
#[wasm_bindgen(js_name = prepareReceiptDisclosureV1)]
pub fn prepare_receipt_disclosure_v1(
    execution_id: &[u8],
    profile_id: &str,
    profile_version: u16,
    command: &[u8],
    has_result: bool,
    result: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let disclosure = ReceiptDisclosure::new(
        auths_model::ReceiptId::new(receipt_array32(execution_id, "execution receipt id")?),
        ProfileRef::new(
            ProfileId::parse(profile_id).map_err(js_error)?,
            profile_version,
        )
        .map_err(js_error)?,
        command.to_vec(),
        has_result.then(|| result.to_vec()),
    )
    .map_err(js_error)?;
    encode_receipt_disclosure(&disclosure).map_err(js_error)
}

/// Verifies linked receipts and returns an inert bounded view.
#[must_use]
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = inspectRawKeyReceiptV1)]
pub fn inspect_raw_key_receipt_v1(
    decision_id: &[u8],
    decision_bytes: &[u8],
    decision_evidence: &[u8],
    execution_id: &[u8],
    execution_bytes: &[u8],
    execution_evidence: &[u8],
    mode: &str,
    has_disclosure: bool,
    disclosure: &[u8],
) -> Vec<u8> {
    let output = inspect_raw_key_receipt(
        decision_id,
        decision_bytes,
        decision_evidence,
        execution_id,
        execution_bytes,
        execution_evidence,
        mode,
        has_disclosure.then_some(disclosure),
    )
    .unwrap_or_else(|code| serde_json::json!({ "kind": "invalid", "mode": mode, "code": code }));
    serde_json::to_vec(&output).unwrap_or_else(|_| {
        br#"{"kind":"invalid","mode":"opaque","code":"inspection-output-failed"}"#.to_vec()
    })
}

#[allow(clippy::too_many_arguments)]
fn inspect_raw_key_receipt(
    decision_id: &[u8],
    decision_bytes: &[u8],
    decision_evidence: &[u8],
    execution_id: &[u8],
    execution_bytes: &[u8],
    execution_evidence: &[u8],
    mode: &str,
    disclosure: Option<&[u8]>,
) -> Result<Value, String> {
    let mode = match mode {
        "opaque" => ReceiptViewMode::Opaque,
        "summary" => ReceiptViewMode::Summary,
        "full" => ReceiptViewMode::Full,
        _ => return Err("inspection-mode-unsupported".into()),
    };
    let decision_id = auths_model::ReceiptId::new(
        decision_id
            .try_into()
            .map_err(|_| "receipt-id-outside-bounds")?,
    );
    let execution_id = auths_model::ReceiptId::new(
        execution_id
            .try_into()
            .map_err(|_| "receipt-id-outside-bounds")?,
    );
    let decision_attested = decode_attested_decision(decision_bytes)
        .map_err(|error| inspection_receipt_error(error).to_owned())?;
    let execution_attested = decode_attested_execution(execution_bytes)
        .map_err(|error| inspection_receipt_error(error).to_owned())?;
    let decision_descriptor = auths_raw_key::RawKeyDescriptor::decode(decision_evidence)
        .map_err(|_| "receipt-invalid-evidence".to_owned())?;
    let execution_descriptor = auths_raw_key::RawKeyDescriptor::decode(execution_evidence)
        .map_err(|_| "receipt-invalid-evidence".to_owned())?;
    let decision_principal = decision_descriptor
        .principal()
        .map_err(|_| "receipt-invalid-evidence".to_owned())?;
    let execution_principal = execution_descriptor
        .principal()
        .map_err(|_| "receipt-invalid-evidence".to_owned())?;
    if decision_attested.signer().verifier() != &decision_principal
        || decision_attested.signer().suite().as_str() != decision_descriptor.suite()
        || execution_attested.signer().verifier() != &execution_principal
        || execution_attested.signer().suite().as_str() != execution_descriptor.suite()
    {
        return Err("receipt-key-does-not-match-signer".into());
    }
    let decision_suite =
        auths_signature::Ed25519Suite::new().map_err(|_| "receipt-suite-unavailable".to_owned())?;
    let execution_suite =
        auths_signature::Ed25519Suite::new().map_err(|_| "receipt-suite-unavailable".to_owned())?;
    let decision_policy = ConfiguredReceiptVerifier::new(
        decision_attested.signer().clone(),
        decision_descriptor.public_key(),
        &decision_suite,
    );
    let execution_policy = ConfiguredReceiptVerifier::new(
        execution_attested.signer().clone(),
        execution_descriptor.public_key(),
        &execution_suite,
    );
    let inspection = inspect_attested_execution_receipt(
        decision_bytes,
        decision_id,
        &decision_principal,
        &decision_policy,
        execution_bytes,
        execution_id,
        &execution_principal,
        &execution_policy,
        mode,
        disclosure,
        (mode != ReceiptViewMode::Opaque)
            .then_some(&DomainReceiptInspector as &dyn auths_receipts::ReceiptProfileInspector),
    )
    .map_err(|error| error.code().to_owned())?;
    Ok(inspection_json(&inspection))
}

fn inspection_json(inspection: &ReceiptInspection) -> Value {
    match inspection {
        ReceiptInspection::VerifiedOpaque { metadata } => serde_json::json!({
            "kind": "verified-opaque",
            "mode": "opaque",
            "receipt": inspection_metadata_json(metadata),
        }),
        ReceiptInspection::VerifiedDisclosed {
            metadata,
            mode,
            projection,
            disclosure,
        } => serde_json::json!({
            "kind": "verified-disclosed",
            "mode": match mode { ReceiptViewMode::Summary => "summary", ReceiptViewMode::Full => "full", ReceiptViewMode::Opaque => "opaque" },
            "receipt": inspection_metadata_json(metadata),
            "summary": {
                "title": projection.title(),
                "fields": projection.fields().iter().map(|(label, value)| serde_json::json!({ "label": label, "value": value })).collect::<Vec<_>>(),
            },
            "disclosure": disclosure.as_ref().map(|value| serde_json::json!({
                "commandHex": hex::encode(value.command()),
                "resultHex": value.result().map(hex::encode),
            })),
        }),
    }
}

fn inspection_metadata_json(metadata: &VerifiedReceiptMetadata) -> Value {
    serde_json::json!({
        "decisionReceiptId": hex::encode(metadata.decision_id().as_bytes()),
        "executionReceiptId": hex::encode(metadata.execution_id().as_bytes()),
        "profile": { "id": metadata.profile().id().as_str(), "version": metadata.profile().version() },
        "decision": match metadata.decision() { DecisionClass::Authorized => "authorized", DecisionClass::Denied => "denied", DecisionClass::Indeterminate => "indeterminate" },
        "reasons": metadata.reasons(),
        "outcome": match metadata.outcome() { ExecutionOutcome::Succeeded => "succeeded", ExecutionOutcome::Failed => "failed", ExecutionOutcome::Indeterminate => "indeterminate" },
        "decidedAt": metadata.decided_at().get().to_string(),
        "completedAt": metadata.completed_at().get().to_string(),
        "decisionSigner": inspection_signer_json(metadata.decision_signer()),
        "executionSigner": inspection_signer_json(metadata.execution_signer()),
        "commitments": {
            "proof": hex::encode(metadata.proof_digest().as_bytes()),
            "action": hex::encode(metadata.action_digest().as_bytes()),
            "context": hex::encode(metadata.context_digest().as_bytes()),
            "principalStatus": hex::encode(metadata.principal_status().as_bytes()),
            "grantStatus": hex::encode(metadata.grant_status().as_bytes()),
            "executionLease": hex::encode(metadata.execution_lease().as_bytes()),
            "command": hex::encode(metadata.command_digest().as_bytes()),
            "result": metadata.result_digest().map(|value| hex::encode(value.as_bytes())),
        },
    })
}

fn inspection_signer_json(signer: &ReceiptSigner) -> Value {
    serde_json::json!({
        "principal": signer.verifier().as_str(),
        "verificationMethod": signer.verification_method().as_str(),
        "suite": signer.suite().as_str(),
    })
}

fn inspection_receipt_error(error: auths_receipts::ReceiptError) -> &'static str {
    match error {
        auths_receipts::ReceiptError::Malformed | auths_receipts::ReceiptError::InvalidReason => {
            "receipt-malformed"
        }
        auths_receipts::ReceiptError::NonCanonical => "receipt-non-canonical",
        auths_receipts::ReceiptError::UnsupportedProtocol => "receipt-unsupported",
        auths_receipts::ReceiptError::LimitExceeded => "receipt-limit-exceeded",
        auths_receipts::ReceiptError::DigestMismatch => "receipt-id-mismatch",
        auths_receipts::ReceiptError::LinkageMismatch | auths_receipts::ReceiptError::Duplicate => {
            "receipt-linkage-mismatch"
        }
        auths_receipts::ReceiptError::UnexpectedSigner => "receipt-unexpected-signer",
        auths_receipts::ReceiptError::InvalidSignature
        | auths_receipts::ReceiptError::SigningUnavailable => "receipt-invalid-signature",
    }
}

fn receipt_signer(
    verifier: &str,
    verification_method: &str,
    suite: &str,
) -> Result<ReceiptSigner, EngineError> {
    Ok(ReceiptSigner::new(
        PrincipalId::parse(verifier)?,
        VerificationMethod::parse(verification_method)?,
        SignatureSuiteId::parse(suite)?,
    ))
}

#[allow(clippy::needless_pass_by_value)]
fn receipt_preparation(value: auths_receipts::PreparedReceipt) -> ReceiptPreparationV1 {
    ReceiptPreparationV1 {
        id: value.id().as_bytes().to_vec(),
        canonical: value.canonical().to_vec(),
        signing_preimage: value.signing_preimage().to_vec(),
    }
}

fn receipt_array32(value: &[u8], label: &'static str) -> Result<[u8; 32], JsValue> {
    value
        .try_into()
        .map_err(|_| js_error(EngineError::Abi(label)))
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
    let resource = canonical.permission().resource().to_string();
    let prepared = prepare_profile_action(
        canonical,
        call.audience()?,
        PrincipalId::parse(actor)?,
        &terminal_grant,
        challenge,
        evaluation_time,
    )?;
    Ok(McpActionPreparationV1 {
        canonical_action_cbor: auths_codec::encode_canonical_action(prepared.canonical())?,
        action_envelope_cbor: auths_codec::encode_action_envelope(prepared.envelope())?,
        arguments_json: serde_json_canonicalizer::to_vec(call.arguments())
            .map_err(|_| EngineError::Abi("MCP arguments could not be canonicalized"))?,
        audience: call.audience()?.to_string(),
        resource,
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

/// Native, bounded proof-material collector used only by the workflow facade.
#[wasm_bindgen]
pub struct WorkflowProofBuilderV1 {
    inner: WorkflowProofBuilder,
}

#[wasm_bindgen]
impl WorkflowProofBuilderV1 {
    /// Creates an empty bounded proof collector.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: WorkflowProofBuilder::new(),
        }
    }

    /// Appends one canonical signed grant in root-to-leaf order.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for malformed grants or collection overflow.
    #[wasm_bindgen(js_name = pushGrant)]
    pub fn push_grant(&mut self, signed_grant_cbor: &[u8]) -> Result<u32, JsValue> {
        let grant = auths_codec::decode_signed_grant(
            signed_grant_cbor,
            &VerifierLimits::default_deployment(),
        )
        .map_err(js_error)?;
        let index = self.inner.push_grant(grant).map_err(js_error)?;
        u32::try_from(index).map_err(|_| js_error(EngineError::Abi("grant index exceeds ABI")))
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
        self.inner
            .bind_grant_evidence(
                usize::try_from(grant_index).map_err(js_error)?,
                addressed_evidence(evidence_type, media_type, bytes).map_err(js_error)?,
            )
            .map_err(js_error)
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
        self.inner
            .bind_action_evidence(
                addressed_evidence(evidence_type, media_type, bytes).map_err(js_error)?,
            )
            .map_err(js_error)
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
        let context = auths_codec::decode_verifier_context(trusted_context_cbor)?;
        let artifacts = self.inner.finish(&action, &canonical, &context)?;
        Ok(WorkflowAuthorizationArtifactsV1 {
            proof_cbor: auths_codec::encode_bundle(artifacts.proof())?,
            trusted_context_cbor: auths_codec::encode_verifier_context(artifacts.context())?,
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
    Ok(address_evidence(
        EvidenceTypeId::parse(evidence_type)?,
        MediaType::parse(media_type)?,
        bytes.to_vec(),
    )?)
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

/// Correlation identifier carried by every failure minted at this boundary.
///
/// The WASM module has no clock, no randomness, and no request scope, so it
/// reports the boundary itself rather than inventing a per-call identifier.
const BOUNDARY_CORRELATION_ID: &str = "wasm-boundary";

/// Projects one bounded boundary failure as a structured JavaScript `Error`.
///
/// The returned value is a real `Error` instance whose own properties are the
/// camelCase serialization of [`auths_errors::ErrorEnvelope`]: `schema`,
/// `family`, `code`, `operation`, `stage`, `summary`, `correlationId`,
/// `retry`, `effect`, `entered`, `recommendedAction`, and `causes`.
///
/// This module decides none of that meaning. It names the failure with a
/// stable registry code; [`auths_errors::classify`] decides the effect state,
/// the retry class, and the recommended action, and an unrecognized code fails
/// closed to `effect: "possible"` there rather than here.
fn js_error(error: impl Into<EngineError>) -> JsValue {
    boundary_error(&error.into())
}

fn boundary_error(error: &EngineError) -> JsValue {
    let code = error.registry_code();
    let classification = auths_errors::classify(code);
    let summary = bounded_summary(&error.to_string());
    let envelope = auths_errors::ErrorEnvelope {
        schema: auths_errors::ENVELOPE_SCHEMA.to_owned(),
        family: classification.family,
        code: code.to_owned(),
        operation: classification.operation.to_owned(),
        stage: classification.stage().to_owned(),
        summary: summary.clone(),
        correlation_id: BOUNDARY_CORRELATION_ID.to_owned(),
        retry: classification.retry,
        effect: classification.effect,
        entered: auths_errors::EnteredBoundaries::default(),
        recommended_action: classification.recommended_action,
        execution_reference: None,
        decision_reference: None,
        receipt_reference: None,
        causes: Vec::new(),
    };
    let failure = js_sys::Error::new(&summary);
    failure.set_name("AuthsError");
    let value = JsValue::from(failure);
    if let Ok(fields) = serde_wasm_bindgen::to_value(&envelope)
        && let Some(fields) = fields.dyn_ref::<js_sys::Object>()
    {
        for entry in js_sys::Object::entries(fields).iter() {
            let pair = js_sys::Array::from(&entry);
            let _ = js_sys::Reflect::set(&value, &pair.get(0), &pair.get(1));
        }
    }
    value
}

/// Truncates a human summary onto a character boundary within the registry's
/// bound without ever producing the empty summary the contract forbids.
fn bounded_summary(message: &str) -> String {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return "bounded Auths boundary failure".to_owned();
    }
    if trimmed.len() <= auths_errors::MAX_SUMMARY_BYTES {
        return trimmed.to_owned();
    }
    let mut end = auths_errors::MAX_SUMMARY_BYTES;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    trimmed[..end].to_owned()
}

/// Classification of one stable code, projected for a JavaScript caller.
///
/// A caller that receives a code from a newer Auths build asks this function
/// what the code means. It never fails: an unrecognized code is reported with
/// `known: false` and `effect: "possible"`, so a newer code is never swallowed
/// and never downgraded to `not-applied`.
/// # Errors
///
/// Returns a structured Auths error only when the classification cannot cross
/// the ABI.
#[wasm_bindgen(js_name = classifyErrorCodeV1)]
pub fn classify_error_code_v1(code: &str) -> Result<JsValue, JsValue> {
    let classification = auths_errors::classify(code);
    serde_wasm_bindgen::to_value(&classification).map_err(|_| {
        js_error(EngineError::Abi(
            "error classification cannot cross the ABI",
        ))
    })
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
        .map_err(js_error)
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
        .map_err(js_error)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationBatchInput {
    #[serde(rename = "proofCbor")]
    proof: Vec<u8>,
    #[serde(rename = "canonicalActionCbor")]
    action: Vec<u8>,
    #[serde(rename = "trustedContextCbor")]
    context: Vec<u8>,
}

/// JavaScript-facing bounded batch verifier with exactly the single-item semantics.
///
/// # Errors
///
/// Rejects empty, excessive, or over-budget batches and internal engine failures.
#[wasm_bindgen(js_name = verifyBatchV1)]
pub fn verify_batch_v1(input: JsValue) -> Result<JsValue, JsValue> {
    let items: Vec<VerificationBatchInput> = serde_wasm_bindgen::from_value(input)
        .map_err(|_| js_error(EngineError::Abi("invalid verification batch")))?;
    if items.is_empty() || items.len() > MAX_VERIFICATION_BATCH_ITEMS {
        return Err(js_error(EngineError::Abi(
            "verification batch is outside item bounds",
        )));
    }
    let total_bytes = items.iter().try_fold(0_usize, |total, item| {
        total
            .checked_add(item.proof.len())
            .and_then(|value| value.checked_add(item.action.len()))
            .and_then(|value| value.checked_add(item.context.len()))
    });
    if total_bytes.is_none_or(|value| value > MAX_VERIFICATION_BATCH_BYTES) {
        return Err(js_error(EngineError::Abi(
            "verification batch is outside byte bounds",
        )));
    }
    let results = items
        .iter()
        .map(|item| verify_self_contained_v1(&item.proof, &item.action, &item.context))
        .collect::<Result<Vec<_>, _>>()
        .map_err(js_error)?;
    results
        .serialize(&serde_wasm_bindgen::Serializer::new())
        .map_err(|_| js_error(EngineError::Abi("verification batch cannot cross the ABI")))
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
    /// Exact action or authorization-artifact assembly failed.
    Workflow(WorkflowAssemblyError),
    /// MCP profile construction or canonicalization failed.
    Mcp(auths_profile_mcp::ProfileError),
    /// Profile contract construction or projection failed.
    Profile(auths_profile_api::ProfileContractError),
    /// General identity encoding or validation failed.
    Identity(auths_identity::IdentityError),
    /// A bounded production-client request or response was invalid.
    Client(auths_production_client::ProductionClientError),
    /// An MCP execution session rejected a transition or a bounded input.
    Session(auths_profile_mcp::McpSessionError),
    /// Receipt preparation, encoding, or attestation failed.
    Receipt(auths_receipts::ReceiptError),
    /// Receipt inspection or disclosure projection failed.
    Inspection(auths_receipts::ReceiptInspectionError),
    /// A binding-level invariant could not be represented.
    Abi(&'static str),
}

impl EngineError {
    /// Names the stable registry code for one boundary failure.
    ///
    /// This module names the failure; `auths_errors` decides what the name
    /// means. No effect state, retry class, or recommended action is chosen
    /// here — see [`boundary_error`].
    ///
    /// Every code named here is a pre-effect failure. The WASM module encodes,
    /// decodes, plans, and prepares signing inputs; it opens no connection,
    /// invokes no provider, and holds no durable state, so no failure it can
    /// produce could have applied a real-world effect. `wasm_boundary_codes_
    /// are_registered_and_pre_effect` proves that against the registry.
    const fn registry_code(&self) -> &'static str {
        match self {
            Self::Keri(_) => "core.native-runtime-unavailable",
            Self::Registry(_) => "core.invalid-configuration",
            Self::Model(_)
            | Self::Codec(_)
            | Self::Planning(_)
            | Self::Author(_)
            | Self::Workflow(_)
            | Self::Mcp(_)
            | Self::Profile(_)
            | Self::Identity(_)
            | Self::Client(_)
            | Self::Session(_)
            | Self::Receipt(_)
            | Self::Inspection(_)
            | Self::Abi(_) => "core.malformed-input",
        }
    }

    /// Every stable code this boundary can name.
    #[cfg(test)]
    const CODES: &'static [&'static str] = &[
        "core.native-runtime-unavailable",
        "core.invalid-configuration",
        "core.malformed-input",
    ];
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
            Self::Workflow(error) => write!(formatter, "could not assemble workflow: {error}"),
            Self::Mcp(error) => write!(formatter, "could not construct MCP action: {error}"),
            Self::Profile(error) => write!(formatter, "MCP profile contract failed: {error}"),
            Self::Identity(error) => write!(formatter, "identity descriptor failed: {error}"),
            // These four variants exist only so the boundary can name a
            // registry code for an error that previously reached JavaScript
            // as its own bare `Display`. They add no prefix, because callers
            // and tests match on the owning crate's stable code text.
            Self::Client(error) => fmt::Display::fmt(error, formatter),
            Self::Session(error) => fmt::Display::fmt(error, formatter),
            Self::Receipt(error) => fmt::Display::fmt(error, formatter),
            Self::Inspection(error) => fmt::Display::fmt(error, formatter),
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

impl From<WorkflowAssemblyError> for EngineError {
    fn from(error: WorkflowAssemblyError) -> Self {
        Self::Workflow(error)
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

impl From<auths_identity::IdentityError> for EngineError {
    fn from(error: auths_identity::IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<auths_production_client::ProductionClientError> for EngineError {
    fn from(error: auths_production_client::ProductionClientError) -> Self {
        Self::Client(error)
    }
}

impl From<auths_profile_mcp::McpSessionError> for EngineError {
    fn from(error: auths_profile_mcp::McpSessionError) -> Self {
        Self::Session(error)
    }
}

impl From<auths_receipts::ReceiptError> for EngineError {
    fn from(error: auths_receipts::ReceiptError) -> Self {
        Self::Receipt(error)
    }
}

impl From<auths_receipts::ReceiptInspectionError> for EngineError {
    fn from(error: auths_receipts::ReceiptInspectionError) -> Self {
        Self::Inspection(error)
    }
}

impl From<serde_wasm_bindgen::Error> for EngineError {
    fn from(_: serde_wasm_bindgen::Error) -> Self {
        Self::Abi("bounded value cannot cross the ABI")
    }
}

impl From<core::num::TryFromIntError> for EngineError {
    fn from(_: core::num::TryFromIntError) -> Self {
        Self::Abi("bounded value is outside its integer range")
    }
}

impl From<&'static str> for EngineError {
    fn from(message: &'static str) -> Self {
        Self::Abi(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_boundary_codes_are_registered_and_pre_effect() {
        for code in EngineError::CODES {
            let classification = auths_errors::classify(code);
            assert!(
                classification.known,
                "{code} is not in product/errors/v1/registry.json; this boundary mints no codes"
            );
            assert_eq!(
                classification.effect,
                auths_errors::EffectState::NotApplied,
                "{code} claims an effect this module cannot cause: it opens no connection, \
                 invokes no provider, and holds no durable state"
            );
        }
    }

    #[test]
    fn every_engine_error_variant_names_a_registered_code() {
        let variants: [EngineError; 5] = [
            EngineError::Abi("bounded"),
            EngineError::Keri(auths_did_keri::KeriError::UnsupportedKey),
            EngineError::Model(auths_model::ModelError::InvalidPrincipal),
            EngineError::Codec(auths_codec::CodecError::Malformed),
            EngineError::Profile(auths_profile_api::ProfileContractError::Malformed),
        ];
        for variant in &variants {
            let code = variant.registry_code();
            assert!(
                EngineError::CODES.contains(&code),
                "{code} escaped the declared boundary code set"
            );
            assert!(auths_errors::classify(code).known, "{code} is unregistered");
        }
    }

    /// The boundary must project the registry's classification, never compute
    /// one. A literal effect state, retry class, or recommended action in this
    /// module would be a second definition of meaning.
    #[test]
    fn the_boundary_names_codes_and_decides_no_classification() {
        // Only the shipping half of the module is under test; the assertions
        // below necessarily name the vocabulary they forbid.
        let source = include_str!("lib.rs");
        let shipping = source
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("the test module marks the end of the shipping surface")
            .0;
        for banned in [
            "EffectState::",
            "RetryClass::",
            "RecommendedAction::",
            "ErrorFamily::",
        ] {
            assert!(
                !shipping.contains(banned),
                "{banned} appears in the shipping WASM boundary; effect, retry, family, and \
                 recommended action are decided by auths_errors::classify, not here"
            );
        }
    }

    #[test]
    fn an_unrecognized_code_reaches_the_caller_as_possible() {
        let classification = auths_errors::classify("future.minted-by-a-newer-build");
        assert!(!classification.known);
        assert_eq!(classification.effect, auths_errors::EffectState::Possible);
    }

    #[test]
    fn a_summary_is_bounded_and_never_empty() {
        assert_eq!(bounded_summary("  "), "bounded Auths boundary failure");
        let long = "é".repeat(auths_errors::MAX_SUMMARY_BYTES);
        let bounded = bounded_summary(&long);
        assert!(bounded.len() <= auths_errors::MAX_SUMMARY_BYTES);
        assert!(!bounded.is_empty());
        assert!(long.starts_with(&bounded));
    }

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
        for (position, grant) in bundle.grants().iter().enumerate() {
            let grant_identifier = auths_codec::grant_id(grant.statement()).unwrap();
            let ids = bundle
                .bindings()
                .iter()
                .find(|binding| {
                    binding.statement() == auths_model::StatementRef::Grant(grant_identifier)
                })
                .unwrap()
                .evidence();
            let index = builder.inner.push_grant(grant.clone()).unwrap();
            assert_eq!(index, position);
            for evidence in bundle
                .evidence()
                .iter()
                .filter(|evidence| ids.contains(&evidence.id()))
            {
                builder
                    .inner
                    .bind_grant_evidence(index, evidence.clone())
                    .unwrap();
            }
        }
        let action = bundle.actions().first().unwrap();
        let action_identifier = auths_codec::action_id(action.envelope()).unwrap();
        let ids = bundle
            .bindings()
            .iter()
            .find(|binding| {
                binding.statement() == auths_model::StatementRef::Action(action_identifier)
            })
            .unwrap()
            .evidence();
        for evidence in bundle
            .evidence()
            .iter()
            .filter(|evidence| ids.contains(&evidence.id()))
        {
            builder
                .inner
                .bind_action_evidence(evidence.clone())
                .unwrap();
        }
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
