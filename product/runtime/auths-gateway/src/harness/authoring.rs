//! Fixed-key native authoring for installed-process tests. This module is
//! available only in testkit builds. None of its public seeds are credentials.

use super::{HarnessError, Signer, audience, context_for_tool, fixture, grant_for_tool, window};
use auths_codec::{
    action_id, action_signing_preimage, body_digest, encode_bundle, encode_canonical_action,
    encode_verifier_context, grant_id, plan_id,
};
use auths_model::{
    ActionEnvelope, AuthorizationPlan, BundleHeader, Challenge, ChannelBindingId, ControlBinding,
    CriticalExtensions, EvidenceObject, ProofBundle, ProofRef, SignatureEnvelope, SignedAction,
    StatementRef,
};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::{McpProfile, McpToolCall};

/// A natively signed exact tool call and its fixed-key test trust. No approval,
/// entry permit, installed configuration or provider result is created here.
pub struct ToolFixture {
    /// Canonical native context restricted to this tool's permission.
    pub context: Vec<u8>,
    /// Canonical signed native proof.
    pub proof: Vec<u8>,
    /// Canonical exact tool action.
    pub action: Vec<u8>,
}

/// Authors a real native grant/action/proof with public fixed test keys.
/// The call remains the input to the native MCP canonicalizer; the helper does
/// not construct an effect, skip verification or approve execution.
///
/// # Errors
/// Refuses invalid time ranges, call encodings or native authoring inputs.
pub fn tool_fixture(call: &McpToolCall, now: u64) -> Result<ToolFixture, HarnessError> {
    let until = now
        .checked_add(86_400)
        .ok_or(HarnessError::Fixture("time"))?;
    tool_fixture_until(call, now, until)
}

/// Native test authoring with an explicit signed resource-authority end time.
/// This changes no verification rule; expired proofs still fail the native owner.
pub(crate) fn tool_fixture_until(
    call: &McpToolCall,
    now: u64,
    until: u64,
) -> Result<ToolFixture, HarnessError> {
    let root = Signer::new(0x11);
    let actor = Signer::new(0x22);
    let observer = Signer::new(0x33);
    let from = now
        .checked_sub(86_400)
        .ok_or(HarnessError::Fixture("time"))?;
    let context = context_for_tool(&root, &observer.principal, now, call)?;
    let grant = grant_for_tool(&root, &actor.principal, None, window(from, until)?, call)?;
    let canonical = fixture(
        McpProfile.canonicalize(&fixture(call.canonical_bytes(), "call")?),
        "canonical action",
    )?;
    let proof_ref = ProofRef::new([0x0b; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        None,
        audience()?,
        Challenge::new([0; 32]),
        window(from, until)?,
        actor.principal.clone(),
        Some(fixture(grant_id(grant.statement()), "grant ID")?),
        fixture(plan_id(&plan), "plan ID")?,
        fixture(ChannelBindingId::parse("none-v1"), "channel")?,
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let descriptor = actor.descriptor();
    let signature = actor.sign(&fixture(
        action_signing_preimage(&envelope, &descriptor),
        "action signing",
    )?);
    let action = SignedAction::new(envelope, SignatureEnvelope::new(descriptor, signature));
    let bindings = vec![
        fixture(
            ControlBinding::new(
                StatementRef::Grant(fixture(grant_id(grant.statement()), "grant ID")?),
                vec![root.evidence().id()],
            ),
            "grant control",
        )?,
        fixture(
            ControlBinding::new(
                StatementRef::Action(fixture(action_id(action.envelope()), "action ID")?),
                vec![actor.evidence().id()],
            ),
            "action control",
        )?,
    ];
    let mut evidence = vec![root.evidence(), actor.evidence()];
    evidence.sort_by_key(EvidenceObject::id);
    let bundle = fixture(
        ProofBundle::new(
            BundleHeader::v1(),
            vec![grant],
            vec![action],
            plan,
            evidence,
            bindings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(canonical.body().to_vec()),
        ),
        "bundle",
    )?;
    Ok(ToolFixture {
        context: fixture(encode_verifier_context(&context), "context")?,
        proof: fixture(encode_bundle(&bundle), "proof")?,
        action: fixture(encode_canonical_action(&canonical), "action")?,
    })
}

/// Fixed-key installed test trust for an explicit set of tools in one service.
/// Every grant/action still has a single exact permission and is fully verified.
///
/// # Errors
/// Refuses empty, duplicate, mixed-service or over-sixteen tool declarations.
pub fn tools_context(calls: &[McpToolCall], now: u64) -> Result<Vec<u8>, HarnessError> {
    let root = Signer::new(0x11);
    let observer = Signer::new(0x33);
    let context = super::context_for_tools(&root, &observer.principal, now, calls)?;
    fixture(encode_verifier_context(&context), "context")
}
