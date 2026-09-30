//! Thin projection of `auths-approval-quorum` for one exact MCP action.
//!
//! The actor signs one action envelope; each listed approver signs one
//! approval statement bound to the action and the approval requirement. Any
//! `required` distinct listed approvers suffice. Every check is native.

use super::{
    AuthoringSigningRequestV1, EngineError, addressed_evidence, js_error, mcp_arguments_from_js,
    signing_descriptor, signing_request,
};
use auths_approval_quorum::{
    MAX_ACTOR_GRANTS, MAX_APPROVER_EVIDENCE, MAX_APPROVERS, MAX_STATEMENT_EVIDENCE, QuorumAction,
    QuorumActor, QuorumError, QuorumProposal,
};
use auths_model::{
    EvidenceObject, PrincipalId, SignatureBytes, SignatureDescriptor, SignatureEnvelope,
    SignedAction, SignedApproval, SignedGrant, VerifierLimits,
};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::{McpProfile, McpToolCall};
use wasm_bindgen::prelude::*;

/// Prepares the actor's envelope and one approval statement per listed
/// approver for a `required`-of-N requirement, valid from `evaluation_time`
/// for `validity_seconds` (the native default when omitted), cut to the
/// actor's terminal-grant expiry. Omit the grant when the actor is itself a
/// trust anchor of the verifier's installation.
///
/// # Errors
///
/// Rejects malformed arguments, an impossible threshold, a repeated
/// approver, the actor listed as an approver, or a validity outside the
/// native bounds.
#[allow(
    clippy::too_many_arguments,
    clippy::needless_pass_by_value,
    reason = "wasm-bindgen passes string arrays and optional byte arrays only by value"
)]
#[wasm_bindgen(js_name = prepareMcpQuorumV1)]
pub fn prepare_mcp_quorum_v1(
    service: &str,
    name: &str,
    arguments: &JsValue,
    required: u16,
    approvers: Vec<String>,
    actor: &str,
    actor_terminal_grant_cbor: Option<Vec<u8>>,
    challenge: &[u8],
    evaluation_time: u64,
    validity_seconds: Option<u32>,
) -> Result<McpQuorumV1, JsValue> {
    prepare_native(
        service,
        name,
        arguments,
        required,
        &approvers,
        actor,
        actor_terminal_grant_cbor.as_deref(),
        challenge,
        evaluation_time,
        validity_seconds.map(u64::from),
    )
    .map_err(js_error)
}

#[allow(clippy::too_many_arguments)]
fn prepare_native(
    service: &str,
    name: &str,
    arguments: &JsValue,
    required: u16,
    approvers: &[String],
    actor: &str,
    actor_terminal_grant_cbor: Option<&[u8]>,
    challenge: &[u8],
    evaluation_time: u64,
    validity_seconds: Option<u64>,
) -> Result<McpQuorumV1, EngineError> {
    if approvers.is_empty() || approvers.len() > MAX_APPROVERS {
        return Err(QuorumError::InvalidQuorum.into());
    }
    let approvers = approvers
        .iter()
        .map(|approver| PrincipalId::parse(approver))
        .collect::<Result<Vec<_>, _>>()?;
    let grant = actor_terminal_grant_cbor
        .map(|bytes| auths_codec::decode_signed_grant(bytes, &VerifierLimits::default_deployment()))
        .transpose()?;
    let actor = QuorumActor::new(PrincipalId::parse(actor)?, grant.as_ref())?;
    let call = McpToolCall::new(service, name, mcp_arguments_from_js(arguments)?)?;
    let canonical = McpProfile.canonicalize(&call.canonical_bytes()?)?;
    let display = McpProfile.review_display(&canonical)?;
    let challenge: [u8; 32] = challenge
        .try_into()
        .map_err(|_| EngineError::Abi("challenge must contain exactly 32 bytes"))?;
    let canonical_action_cbor = auths_codec::encode_canonical_action(&canonical)?;
    let resource = canonical.permission().resource().to_string();
    let audience = call.audience()?;
    let proposal = QuorumProposal::new(
        canonical,
        &audience,
        challenge,
        evaluation_time,
        validity_seconds,
        required,
        &approvers,
        &actor,
    )?;
    Ok(McpQuorumV1 {
        envelope_cbor: auths_codec::encode_action_envelope(proposal.envelope())?,
        proposal,
        canonical_action_cbor,
        arguments_json: serde_json_canonicalizer::to_vec(call.arguments())
            .map_err(|_| EngineError::Abi("MCP arguments could not be canonicalized"))?,
        audience: audience.to_string(),
        resource,
        display_digest_hex: display.canonical_digest_hex().to_owned(),
    })
}

/// The actor's envelope, the approval requirement, and one approval
/// statement per listed approver for one MCP action.
#[wasm_bindgen]
pub struct McpQuorumV1 {
    proposal: QuorumProposal,
    envelope_cbor: Vec<u8>,
    canonical_action_cbor: Vec<u8>,
    arguments_json: Vec<u8>,
    audience: String,
    resource: String,
    display_digest_hex: String,
}

#[wasm_bindgen]
impl McpQuorumV1 {
    /// Returns the threshold: how many listed approvers must approve.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn required(&self) -> u16 {
        self.proposal.required()
    }

    /// Returns the listed approvers in ascending order.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn approvers(&self) -> Vec<String> {
        self.proposal
            .approvers()
            .iter()
            .map(|approver| approver.as_str().to_owned())
            .collect()
    }

    /// Returns the actor that signs the action envelope.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn actor(&self) -> String {
        self.proposal.actor().as_str().to_owned()
    }

    /// Returns the approval requirement's identifier every statement binds.
    #[must_use]
    #[wasm_bindgen(getter, js_name = requirementId)]
    pub fn requirement_id(&self) -> Vec<u8> {
        self.proposal.requirement_id().as_bytes().to_vec()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = canonicalActionCbor)]
    pub fn canonical_action_cbor(&self) -> Vec<u8> {
        self.canonical_action_cbor.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = argumentsJson)]
    pub fn arguments_json(&self) -> Vec<u8> {
        self.arguments_json.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn audience(&self) -> String {
        self.audience.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn resource(&self) -> String {
        self.resource.clone()
    }

    /// Returns the shared validity as `[notBefore, expiresAt]`, both
    /// inclusive.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn validity(&self) -> Vec<u64> {
        let validity = self.proposal.envelope().validity();
        vec![validity.not_before().get(), validity.expires_at().get()]
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = displayDigestHex)]
    pub fn display_digest_hex(&self) -> String {
        self.display_digest_hex.clone()
    }

    /// Returns the unsigned envelope the actor signs.
    #[must_use]
    #[wasm_bindgen(getter, js_name = actionEnvelopeCbor)]
    pub fn action_envelope_cbor(&self) -> Vec<u8> {
        self.envelope_cbor.clone()
    }

    /// Prepares the custody request for `approver`'s approval statement.
    ///
    /// # Errors
    ///
    /// Rejects an approver the requirement does not list or a malformed
    /// signature descriptor.
    #[wasm_bindgen(js_name = prepareApprovalSigning)]
    pub fn prepare_approval_signing(
        &self,
        approver: &str,
        principal_method: &str,
        verification_method: &str,
        suite: &str,
    ) -> Result<AuthoringSigningRequestV1, JsValue> {
        self.prepare_approval_native(approver, principal_method, verification_method, suite)
            .map_err(js_error)
    }
}

impl McpQuorumV1 {
    pub(crate) const fn proposal(&self) -> &QuorumProposal {
        &self.proposal
    }

    fn prepare_approval_native(
        &self,
        approver: &str,
        principal_method: &str,
        verification_method: &str,
        suite: &str,
    ) -> Result<AuthoringSigningRequestV1, EngineError> {
        let statement = self
            .proposal
            .statement(&PrincipalId::parse(approver)?)
            .ok_or(QuorumError::UnknownApproval)?;
        let request = auths_author::prepare_approval(
            statement.clone(),
            signing_descriptor(principal_method, verification_method, suite)?,
            self.proposal.canonical().profile(),
        )?;
        Ok(signing_request(&request))
    }
}

/// The actor's signed envelope with its grant chain (root first) and the
/// public control evidence of each grant and of the signature.
#[wasm_bindgen]
pub struct McpQuorumActionV1 {
    action: SignedAction,
    grants: Vec<(SignedGrant, Vec<EvidenceObject>)>,
    action_evidence: Vec<EvidenceObject>,
}

#[wasm_bindgen]
impl McpQuorumActionV1 {
    /// Stages the actor's canonical signed action.
    ///
    /// # Errors
    ///
    /// Rejects a malformed signed action.
    #[wasm_bindgen(constructor)]
    pub fn new(signed_action_cbor: &[u8]) -> Result<Self, JsValue> {
        let action = auths_codec::decode_signed_action(
            signed_action_cbor,
            &VerifierLimits::default_deployment(),
        )
        .map_err(js_error)?;
        Ok(Self {
            action,
            grants: Vec::new(),
            action_evidence: Vec::new(),
        })
    }

    /// Appends one grant of the actor's chain, root first.
    ///
    /// # Errors
    ///
    /// Rejects a malformed grant or a full chain.
    #[wasm_bindgen(js_name = pushGrant)]
    pub fn push_grant(&mut self, signed_grant_cbor: &[u8]) -> Result<u32, JsValue> {
        self.push_grant_native(signed_grant_cbor).map_err(js_error)
    }

    /// Binds public control evidence to one staged grant.
    ///
    /// # Errors
    ///
    /// Rejects an unknown grant, invalid evidence, or a full collection.
    #[wasm_bindgen(js_name = bindGrantEvidence)]
    pub fn bind_grant_evidence(
        &mut self,
        grant: u32,
        evidence_type: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<(), JsValue> {
        let evidence = addressed_evidence(evidence_type, media_type, bytes).map_err(js_error)?;
        let (_, objects) = usize::try_from(grant)
            .ok()
            .and_then(|index| self.grants.get_mut(index))
            .ok_or_else(|| js_error(EngineError::Abi("grant index is out of range")))?;
        push_bounded(objects, evidence, MAX_STATEMENT_EVIDENCE).map_err(js_error)
    }

    /// Binds public control evidence to the actor's signature.
    ///
    /// # Errors
    ///
    /// Rejects invalid evidence or a full collection.
    #[wasm_bindgen(js_name = bindActionEvidence)]
    pub fn bind_action_evidence(
        &mut self,
        evidence_type: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<(), JsValue> {
        let evidence = addressed_evidence(evidence_type, media_type, bytes).map_err(js_error)?;
        push_bounded(&mut self.action_evidence, evidence, MAX_STATEMENT_EVIDENCE).map_err(js_error)
    }
}

impl McpQuorumActionV1 {
    fn push_grant_native(&mut self, signed_grant_cbor: &[u8]) -> Result<u32, EngineError> {
        if self.grants.len() >= MAX_ACTOR_GRANTS {
            return Err(EngineError::Abi("actor grant chain is full"));
        }
        let grant = auths_codec::decode_signed_grant(
            signed_grant_cbor,
            &VerifierLimits::default_deployment(),
        )?;
        self.grants.push((grant, Vec::new()));
        Ok(u32::try_from(self.grants.len() - 1)?)
    }

    pub(crate) fn native(&self) -> Result<QuorumAction, QuorumError> {
        QuorumAction::new(
            self.action.clone(),
            self.grants.clone(),
            self.action_evidence.clone(),
        )
    }
}

struct StagedApproval {
    approver: PrincipalId,
    descriptor: SignatureDescriptor,
    signature: SignatureBytes,
    evidence: Vec<EvidenceObject>,
}

/// Bounded collector of approver signatures for one in-process quorum.
#[wasm_bindgen]
pub struct McpQuorumProofBuilderV1 {
    approvals: Vec<StagedApproval>,
}

#[wasm_bindgen]
impl McpQuorumProofBuilderV1 {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            approvals: Vec::new(),
        }
    }

    /// Appends one approver's custody signature over its approval statement
    /// and returns the approval index.
    ///
    /// # Errors
    ///
    /// Rejects a malformed principal, descriptor, or signature, or a full
    /// collector.
    #[wasm_bindgen(js_name = addApproval)]
    pub fn add_approval(
        &mut self,
        approver: &str,
        principal_method: &str,
        verification_method: &str,
        suite: &str,
        signature: &[u8],
    ) -> Result<u32, JsValue> {
        self.add_native(
            approver,
            principal_method,
            verification_method,
            suite,
            signature,
        )
        .map_err(js_error)
    }

    /// Binds public control evidence to one approval's signature.
    ///
    /// # Errors
    ///
    /// Rejects an unknown approval, invalid evidence, or a full collection.
    #[wasm_bindgen(js_name = bindApprovalEvidence)]
    pub fn bind_approval_evidence(
        &mut self,
        approval: u32,
        evidence_type: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<(), JsValue> {
        let evidence = addressed_evidence(evidence_type, media_type, bytes).map_err(js_error)?;
        let staged = usize::try_from(approval)
            .ok()
            .and_then(|index| self.approvals.get_mut(index))
            .ok_or_else(|| js_error(EngineError::Abi("approval index is out of range")))?;
        push_bounded(&mut staged.evidence, evidence, MAX_APPROVER_EVIDENCE).map_err(js_error)
    }

    /// Assembles the canonical proof from the actor's signed action and the
    /// approvals of at least `required` distinct listed approvers.
    ///
    /// # Errors
    ///
    /// Rejects an action that is not `quorum`'s envelope, an approval by an
    /// approver `quorum` does not list, a repeated approver, fewer approvals
    /// than the threshold, or material outside collection bounds.
    pub fn finish(
        &self,
        quorum: &McpQuorumV1,
        action: &McpQuorumActionV1,
    ) -> Result<Vec<u8>, JsValue> {
        self.finish_native(quorum, action).map_err(js_error)
    }
}

impl Default for McpQuorumProofBuilderV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl McpQuorumProofBuilderV1 {
    fn add_native(
        &mut self,
        approver: &str,
        principal_method: &str,
        verification_method: &str,
        suite: &str,
        signature: &[u8],
    ) -> Result<u32, EngineError> {
        if self.approvals.len() >= MAX_APPROVERS {
            return Err(EngineError::Abi("approval quorum collector is full"));
        }
        self.approvals.push(StagedApproval {
            approver: PrincipalId::parse(approver)?,
            descriptor: signing_descriptor(principal_method, verification_method, suite)?,
            signature: SignatureBytes::new(signature.to_vec())?,
            evidence: Vec::new(),
        });
        Ok(u32::try_from(self.approvals.len() - 1)?)
    }

    fn finish_native(
        &self,
        quorum: &McpQuorumV1,
        action: &McpQuorumActionV1,
    ) -> Result<Vec<u8>, EngineError> {
        let approvals = self
            .approvals
            .iter()
            .map(|staged| {
                let statement = quorum
                    .proposal
                    .statement(&staged.approver)
                    .ok_or(QuorumError::UnknownApproval)?;
                Ok(SignedApproval::new(
                    statement.clone(),
                    SignatureEnvelope::new(staged.descriptor.clone(), staged.signature.clone()),
                    staged.evidence.clone(),
                )?)
            })
            .collect::<Result<Vec<_>, EngineError>>()?;
        Ok(auths_codec::encode_bundle(
            &quorum.proposal.assemble(&action.native()?, &approvals)?,
        )?)
    }
}

fn push_bounded(
    objects: &mut Vec<EvidenceObject>,
    evidence: EvidenceObject,
    limit: usize,
) -> Result<(), EngineError> {
    if objects.len() >= limit {
        return Err(EngineError::Abi("evidence collection is full"));
    }
    objects.push(evidence);
    Ok(())
}
