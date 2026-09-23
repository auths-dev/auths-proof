//! Thin projection of `auths-approval-quorum` for one exact MCP action.

use super::{EngineError, addressed_evidence, js_error, mcp_arguments_from_js};
use auths_approval_quorum::{
    MAX_APPROVAL_GRANTS, MAX_APPROVERS, MAX_STATEMENT_EVIDENCE, QuorumApproval, QuorumApprover,
    QuorumProposal,
};
use auths_model::{
    EvidenceObject, PrincipalId, SignedAction, SignedGrant, Timestamp, ValidityWindow,
    VerifierLimits,
};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::{McpProfile, McpToolCall};
use wasm_bindgen::prelude::*;

/// Ordered approver set collected before one quorum is prepared.
#[wasm_bindgen]
pub struct McpQuorumApproversV1 {
    approvers: Vec<QuorumApprover>,
}

#[wasm_bindgen]
impl McpQuorumApproversV1 {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            approvers: Vec::new(),
        }
    }

    /// Appends one approver. Omit the grant when the approver is itself a
    /// trust anchor of the verifier's installation.
    ///
    /// # Errors
    ///
    /// Rejects an invalid principal, a malformed grant, or a full set.
    #[wasm_bindgen(js_name = addApprover)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "wasm-bindgen passes an optional byte array only by value"
    )]
    pub fn add_approver(
        &mut self,
        actor: &str,
        terminal_grant_cbor: Option<Vec<u8>>,
    ) -> Result<(), JsValue> {
        self.add_native(actor, terminal_grant_cbor.as_deref())
            .map_err(js_error)
    }

    /// Prepares one envelope per approver under a `required`-of-N plan.
    ///
    /// # Errors
    ///
    /// Rejects malformed arguments, an impossible threshold, a repeated
    /// approver, or an invalid validity window.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        &self,
        service: &str,
        name: &str,
        arguments: &JsValue,
        required: u16,
        challenge: &[u8],
        not_before: u64,
        expires_at: u64,
    ) -> Result<McpQuorumV1, JsValue> {
        self.prepare_native(
            service, name, arguments, required, challenge, not_before, expires_at,
        )
        .map_err(js_error)
    }
}

impl Default for McpQuorumApproversV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl McpQuorumApproversV1 {
    fn add_native(
        &mut self,
        actor: &str,
        terminal_grant_cbor: Option<&[u8]>,
    ) -> Result<(), EngineError> {
        if self.approvers.len() >= MAX_APPROVERS {
            return Err(EngineError::Abi("approval quorum approver set is full"));
        }
        let grant = terminal_grant_cbor
            .map(|bytes| {
                auths_codec::decode_signed_grant(bytes, &VerifierLimits::default_deployment())
            })
            .transpose()?;
        self.approvers.push(QuorumApprover::new(
            PrincipalId::parse(actor)?,
            grant.as_ref(),
        )?);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_native(
        &self,
        service: &str,
        name: &str,
        arguments: &JsValue,
        required: u16,
        challenge: &[u8],
        not_before: u64,
        expires_at: u64,
    ) -> Result<McpQuorumV1, EngineError> {
        let call = McpToolCall::new(service, name, mcp_arguments_from_js(arguments)?)?;
        let canonical = McpProfile.canonicalize(&call.canonical_bytes()?)?;
        let display = McpProfile.review_display(&canonical)?;
        let challenge: [u8; 32] = challenge
            .try_into()
            .map_err(|_| EngineError::Abi("challenge must contain exactly 32 bytes"))?;
        let validity = ValidityWindow::new(Timestamp::new(not_before), Timestamp::new(expires_at))?;
        let canonical_action_cbor = auths_codec::encode_canonical_action(&canonical)?;
        let resource = canonical.permission().resource().to_string();
        let audience = call.audience()?;
        let proposal = QuorumProposal::new(
            canonical,
            &audience,
            challenge,
            validity,
            required,
            &self.approvers,
        )?;
        Ok(McpQuorumV1 {
            proposal,
            canonical_action_cbor,
            arguments_json: serde_json_canonicalizer::to_vec(call.arguments())
                .map_err(|_| EngineError::Abi("MCP arguments could not be canonicalized"))?,
            audience: audience.to_string(),
            resource,
            display_digest_hex: display.canonical_digest_hex().to_owned(),
        })
    }
}

/// Exact envelopes and threshold plan for one MCP action.
#[wasm_bindgen]
pub struct McpQuorumV1 {
    proposal: QuorumProposal,
    canonical_action_cbor: Vec<u8>,
    arguments_json: Vec<u8>,
    audience: String,
    resource: String,
    display_digest_hex: String,
}

#[wasm_bindgen]
impl McpQuorumV1 {
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn required(&self) -> u16 {
        self.proposal.required()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = approverCount)]
    pub fn approver_count(&self) -> u32 {
        u32::try_from(self.proposal.envelopes().len()).unwrap_or(u32::MAX)
    }

    /// Returns the approver at `index`, in approver order.
    ///
    /// # Errors
    ///
    /// Rejects an index outside the approver set.
    pub fn approver(&self, index: u32) -> Result<String, JsValue> {
        self.envelope(index)
            .map(|envelope| envelope.actor().as_str().to_owned())
            .map_err(js_error)
    }

    /// Returns the core plan identifier every envelope commits to.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error only if canonical encoding fails.
    #[wasm_bindgen(getter, js_name = planId)]
    pub fn plan_id(&self) -> Result<Vec<u8>, JsValue> {
        auths_codec::plan_id(self.proposal.plan())
            .map(|id| id.as_bytes().to_vec())
            .map_err(js_error)
    }

    /// Returns the canonical threshold plan.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error only if canonical encoding fails.
    #[wasm_bindgen(getter, js_name = planCbor)]
    pub fn plan_cbor(&self) -> Result<Vec<u8>, JsValue> {
        auths_codec::encode_authorization_plan(self.proposal.plan()).map_err(js_error)
    }

    /// Returns the concatenated 32-byte proof references in approver order.
    #[must_use]
    #[wasm_bindgen(getter, js_name = proofReferences)]
    pub fn proof_references(&self) -> Vec<u8> {
        self.proposal
            .envelopes()
            .iter()
            .flat_map(|envelope| *envelope.proof_ref().as_bytes())
            .collect()
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

    #[must_use]
    #[wasm_bindgen(getter, js_name = displayDigestHex)]
    pub fn display_digest_hex(&self) -> String {
        self.display_digest_hex.clone()
    }

    /// Returns the unsigned envelope the approver at `index` signs.
    ///
    /// # Errors
    ///
    /// Rejects an index outside the approver set.
    #[wasm_bindgen(js_name = actionEnvelopeCbor)]
    pub fn action_envelope_cbor(&self, index: u32) -> Result<Vec<u8>, JsValue> {
        self.envelope(index)
            .and_then(|envelope| Ok(auths_codec::encode_action_envelope(envelope)?))
            .map_err(js_error)
    }
}

impl McpQuorumV1 {
    fn envelope(&self, index: u32) -> Result<&auths_model::ActionEnvelope, EngineError> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.proposal.envelopes().get(index))
            .ok_or(EngineError::Abi("approver index is out of range"))
    }
}

struct StagedApproval {
    action: SignedAction,
    grants: Vec<(SignedGrant, Vec<EvidenceObject>)>,
    action_evidence: Vec<EvidenceObject>,
}

/// Bounded collector of signed approvals and their public control evidence.
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

    /// Appends one signed envelope and returns its approval index.
    ///
    /// # Errors
    ///
    /// Rejects a malformed signed action or a full collector.
    #[wasm_bindgen(js_name = addApproval)]
    pub fn add_approval(&mut self, signed_action_cbor: &[u8]) -> Result<u32, JsValue> {
        self.add_native(signed_action_cbor).map_err(js_error)
    }

    /// Appends one grant of an approval's chain, root first.
    ///
    /// # Errors
    ///
    /// Rejects an unknown approval, a malformed grant, or an oversized chain.
    #[wasm_bindgen(js_name = pushGrant)]
    pub fn push_grant(&mut self, approval: u32, signed_grant_cbor: &[u8]) -> Result<u32, JsValue> {
        self.push_grant_native(approval, signed_grant_cbor)
            .map_err(js_error)
    }

    /// Binds public control evidence to one grant of one approval.
    ///
    /// # Errors
    ///
    /// Rejects an unknown index, invalid evidence, or an oversized set.
    #[wasm_bindgen(js_name = bindGrantEvidence)]
    pub fn bind_grant_evidence(
        &mut self,
        approval: u32,
        grant: u32,
        evidence_type: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<(), JsValue> {
        let evidence = addressed_evidence(evidence_type, media_type, bytes).map_err(js_error)?;
        let staged = self.staged(approval).map_err(js_error)?;
        let (_, objects) = usize::try_from(grant)
            .ok()
            .and_then(|index| staged.grants.get_mut(index))
            .ok_or_else(|| js_error(EngineError::Abi("grant index is out of range")))?;
        push_bounded(objects, evidence).map_err(js_error)
    }

    /// Binds public control evidence to one approval's signed action.
    ///
    /// # Errors
    ///
    /// Rejects an unknown approval, invalid evidence, or an oversized set.
    #[wasm_bindgen(js_name = bindActionEvidence)]
    pub fn bind_action_evidence(
        &mut self,
        approval: u32,
        evidence_type: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<(), JsValue> {
        let evidence = addressed_evidence(evidence_type, media_type, bytes).map_err(js_error)?;
        let staged = self.staged(approval).map_err(js_error)?;
        push_bounded(&mut staged.action_evidence, evidence).map_err(js_error)
    }

    /// Assembles the canonical proof; every approver of `quorum` must appear
    /// exactly once.
    ///
    /// # Errors
    ///
    /// Rejects an approval outside the quorum, a repeated approval, a missing
    /// approver, or material outside collection bounds.
    pub fn finish(&self, quorum: &McpQuorumV1) -> Result<Vec<u8>, JsValue> {
        self.finish_native(quorum).map_err(js_error)
    }
}

impl Default for McpQuorumProofBuilderV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl McpQuorumProofBuilderV1 {
    fn add_native(&mut self, signed_action_cbor: &[u8]) -> Result<u32, EngineError> {
        if self.approvals.len() >= MAX_APPROVERS {
            return Err(EngineError::Abi("approval quorum collector is full"));
        }
        let action = auths_codec::decode_signed_action(
            signed_action_cbor,
            &VerifierLimits::default_deployment(),
        )?;
        self.approvals.push(StagedApproval {
            action,
            grants: Vec::new(),
            action_evidence: Vec::new(),
        });
        Ok(u32::try_from(self.approvals.len() - 1)?)
    }

    fn push_grant_native(
        &mut self,
        approval: u32,
        signed_grant_cbor: &[u8],
    ) -> Result<u32, EngineError> {
        let grant = auths_codec::decode_signed_grant(
            signed_grant_cbor,
            &VerifierLimits::default_deployment(),
        )?;
        let staged = self.staged(approval)?;
        if staged.grants.len() >= MAX_APPROVAL_GRANTS {
            return Err(EngineError::Abi("approval grant chain is full"));
        }
        staged.grants.push((grant, Vec::new()));
        Ok(u32::try_from(staged.grants.len() - 1)?)
    }

    fn staged(&mut self, approval: u32) -> Result<&mut StagedApproval, EngineError> {
        usize::try_from(approval)
            .ok()
            .and_then(|index| self.approvals.get_mut(index))
            .ok_or(EngineError::Abi("approval index is out of range"))
    }

    fn finish_native(&self, quorum: &McpQuorumV1) -> Result<Vec<u8>, EngineError> {
        let approvals = self
            .approvals
            .iter()
            .map(|staged| {
                QuorumApproval::new(
                    staged.action.clone(),
                    staged.grants.clone(),
                    staged.action_evidence.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(auths_codec::encode_bundle(
            &quorum.proposal.assemble(&approvals)?,
        )?)
    }
}

fn push_bounded(
    objects: &mut Vec<EvidenceObject>,
    evidence: EvidenceObject,
) -> Result<(), EngineError> {
    if objects.len() >= MAX_STATEMENT_EVIDENCE {
        return Err(EngineError::Abi("evidence collection is full"));
    }
    objects.push(evidence);
    Ok(())
}
