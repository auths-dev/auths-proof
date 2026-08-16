//! Authors a proof offline against the reference stack's trust anchor.
//!
//! This replaces `auths-sandbox-request`, which asked the NODE to mint an
//! authority. The node refuses that now, permanently and by design:
//! `kernel.rs` returns `UnauthenticatedPrincipal` for both `create` and
//! `delegate`, because `ProductionRequest.identity` is unauthenticated bytes
//! and there is no client authentication at that call site to require instead.
//!
//! Authority in V1 originates from a trust anchor's signature and arrives
//! INSIDE the proof. So the demo authors one here, holding the anchor key that
//! `auths-local-context` put into the trusted context, and hands the client a
//! proof plus a canonical action. The client then calls `execute` -- the only
//! verb the node will answer.
//!
//! LOCAL FIXTURE. The anchor key is derived from `AUTHS_LOCAL_SEED`, so anyone
//! holding the seed can author against this stack. That is the point of a
//! self-contained demo and disqualifying anywhere else.

use auths_author::{prepare_action, prepare_grant};
use auths_codec::{
    action_id, body_digest, encode_bundle, encode_canonical_action, evidence_id, grant_id, plan_id,
};
use auths_model::{
    ActionConstraint, BudgetAlgebraId, BudgetCeiling, BundleHeader, CriticalExtensions,
    GrantStatement, PrincipalMethodId, ProofBundle, SignatureBytes, SignatureDescriptor,
    SignatureSuiteId, StatusPolicy, Timestamp, ValidityWindow, VerificationMethod,
};
use auths_model::{
    ActionEnvelope, AuthorizationPlan, CanonicalAction, Challenge, ChannelBindingId,
    ControlBinding, EvidenceId, EvidenceObject, EvidenceTypeId, MediaType, ProofRef, StatementRef,
};
use auths_node::local_fixture::{
    SEED_ENV, anchor_principal, reference_grant_terms, reference_profile,
};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyType};
use auths_signature::ED25519_V1;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signer as _, SigningKey};
use std::{
    env, fs,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

fn fail(message: &str) -> ExitCode {
    eprintln!("auths-local-authority: {message}");
    ExitCode::from(1)
}

#[allow(
    clippy::too_many_lines,
    reason = "the local fixture is one auditable linear authoring transcript"
)]
fn main() -> ExitCode {
    let mut arguments = env::args().skip(1);
    let (Some(profile), Some(action_path), Some(agent_label)) =
        (arguments.next(), arguments.next(), arguments.next())
    else {
        eprintln!("usage: auths-local-authority <profile-id> <action-file> <agent-label>");
        return ExitCode::from(1);
    };
    if arguments.next().is_some() {
        return fail("unexpected extra argument");
    }

    let Ok(encoded_seed) = env::var(SEED_ENV) else {
        return fail(&format!("{SEED_ENV} is not set"));
    };
    let mut seed = [0_u8; 32];
    if Base64UrlUnpadded::decode(encoded_seed.trim(), &mut seed).is_err() {
        return fail(&format!("{SEED_ENV} is not 32 unpadded base64url bytes"));
    }
    let Ok(action) = fs::read(&action_path) else {
        return fail("the action file is unavailable");
    };

    let Ok((anchor_key, anchor_principal)) = anchor_principal(&seed) else {
        return fail("the trust anchor could not be derived");
    };
    let Ok(profile_ref) = reference_profile(&profile) else {
        return fail("that profile is not one the reference stack enables");
    };
    let Ok((permissions, audiences, assurance, action_permission, action_audience)) =
        reference_grant_terms(&profile)
    else {
        return fail("the reference grant terms are unavailable");
    };
    let profile_ref_for_action = profile_ref.clone();
    let profile_ref_for_canonical = profile_ref.clone();
    let action_permission_for_canonical = action_permission.clone();

    // The agent is a distinct principal, derived from the seed and its label so
    // the demo is reproducible without shipping a second secret.
    let mut agent_seed = [0_u8; 32];
    for (index, byte) in agent_label.as_bytes().iter().take(32).enumerate() {
        agent_seed[index] = seed[index] ^ byte;
    }
    let agent_key = SigningKey::from_bytes(&agent_seed);
    let Ok(agent_descriptor) = RawKeyDescriptor::new(
        RawKeyType::Ed25519,
        agent_key.verifying_key().to_bytes().to_vec(),
    ) else {
        return fail("the agent key is not a valid raw-key descriptor");
    };
    let Ok(agent_principal) = agent_descriptor.principal() else {
        return fail("the agent key has no principal");
    };
    let agent_principal_for_action = agent_principal.clone();
    let agent_principal_for_descriptor = agent_principal.clone();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    // The grant must be CONTAINED in the anchor's window, and the anchor's was
    // fixed when the context was generated -- earlier than now. Start one minute
    // in the past so a second boundary or host/container clock skew cannot make
    // a freshly authored action not-yet-valid. Fifteen minutes still fits
    // comfortably inside the fixture anchor's one-hour window.
    let Ok(validity) = ValidityWindow::new(
        Timestamp::new(now.saturating_sub(60)),
        Timestamp::new(now.saturating_add(900)),
    ) else {
        return fail("the validity window is invalid");
    };
    let Ok(algebra) = BudgetAlgebraId::parse("numeric-ceiling-v1") else {
        return fail("the budget algebra id is malformed");
    };
    // The action DECLARES a budget within the grant's ceiling. An absent
    // request beneath a bounded ceiling is denied -- an action that states no
    // bound on what it may spend is exactly the authority a ceiling exists to
    // refuse -- so the demo has to say what it intends to spend.
    let requested_budget = Some(BudgetCeiling::new(algebra.clone(), 1));

    // Root grant: the anchor delegates to the agent, one hop, bounded.
    let statement = GrantStatement::new(
        anchor_principal.clone(),
        agent_principal,
        profile_ref,
        permissions,
        validity,
        audiences,
        ActionConstraint::AnyBody,
        Some(BudgetCeiling::new(algebra, 1)),
        1,
        None,
        StatusPolicy::ExpiryOnly,
        assurance,
        CriticalExtensions::empty(),
    );
    let Ok(anchor_raw_descriptor) = RawKeyDescriptor::new(
        RawKeyType::Ed25519,
        anchor_key.verifying_key().to_bytes().to_vec(),
    ) else {
        return fail("the anchor key is not a valid raw-key descriptor");
    };
    let (Ok(method), Ok(verification), Ok(suite)) = (
        PrincipalMethodId::parse(RAW_KEY_V1),
        VerificationMethod::parse(anchor_principal.as_str()),
        SignatureSuiteId::parse(ED25519_V1),
    ) else {
        return fail("the anchor signature descriptor is malformed");
    };
    let descriptor = SignatureDescriptor::new(method, verification, suite);
    let Ok(request) = prepare_grant(statement, descriptor) else {
        return fail("the root grant could not be prepared");
    };
    let Ok(signature) = SignatureBytes::new(
        anchor_key
            .sign(request.signing_preimage())
            .to_bytes()
            .to_vec(),
    ) else {
        return fail("the anchor signature is not well formed");
    };
    let grant = request.complete(signature);

    let plan = AuthorizationPlan::proof(ProofRef::new([0x61; 32]));
    // A bundle must carry at least one signed action; the agent signs the one
    // the client will present.
    let Ok(terminal) = grant_id(grant.statement()) else {
        return fail("the root grant has no identifier");
    };
    let Ok(plan_identifier) = plan_id(&plan) else {
        return fail("the authorization plan has no identifier");
    };
    let Ok(media) = MediaType::parse("application/octet-stream") else {
        return fail("the media type is malformed");
    };
    let media_for_canonical = media.clone();
    let Ok(channel) = ChannelBindingId::parse("none-v1") else {
        return fail("the channel binding id is malformed");
    };
    let envelope = ActionEnvelope::new(
        profile_ref_for_action,
        media,
        body_digest(&action),
        action_permission,
        requested_budget.clone(),
        action_audience,
        Challenge::new([0x22; 32]),
        validity,
        agent_principal_for_action,
        Some(terminal),
        plan_identifier,
        channel,
        ProofRef::new([0x61; 32]),
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let (Ok(agent_method), Ok(agent_verification), Ok(agent_suite)) = (
        PrincipalMethodId::parse(RAW_KEY_V1),
        VerificationMethod::parse(agent_principal_for_descriptor.as_str()),
        SignatureSuiteId::parse(ED25519_V1),
    ) else {
        return fail("the agent signature descriptor is malformed");
    };
    let Ok(action_request) = prepare_action(
        envelope,
        SignatureDescriptor::new(agent_method, agent_verification, agent_suite),
    ) else {
        return fail("the action could not be prepared");
    };
    let Ok(action_signature) = SignatureBytes::new(
        agent_key
            .sign(action_request.signing_preimage())
            .to_bytes()
            .to_vec(),
    ) else {
        return fail("the agent signature is not well formed");
    };
    let signed_action = action_request.complete(action_signature);

    // Evidence binds each signature to the key that produced it. Without it the
    // verifier has a signed grant and no way to check who signed it, and denies.
    let evidence_for = |descriptor: &RawKeyDescriptor| -> Option<EvidenceObject> {
        let evidence_type = EvidenceTypeId::parse(RAW_KEY_V1).ok()?;
        let media = MediaType::parse(RAW_KEY_MEDIA_TYPE).ok()?;
        let unaddressed = EvidenceObject::new(
            EvidenceId::new([0; 32]),
            evidence_type.clone(),
            media.clone(),
            descriptor.encode(),
        )
        .ok()?;
        EvidenceObject::new(
            evidence_id(&unaddressed).ok()?,
            evidence_type,
            media,
            unaddressed.bytes().to_vec(),
        )
        .ok()
    };
    let (Some(anchor_evidence), Some(agent_evidence)) = (
        evidence_for(&anchor_raw_descriptor),
        evidence_for(&agent_descriptor),
    ) else {
        return fail("the key evidence could not be assembled");
    };
    let (Ok(grant_binding), Ok(action_binding)) = (
        ControlBinding::new(StatementRef::Grant(terminal), vec![anchor_evidence.id()]),
        action_id(signed_action.envelope())
            .map_err(|_| ())
            .and_then(|id| {
                ControlBinding::new(StatementRef::Action(id), vec![agent_evidence.id()])
                    .map_err(|_| ())
            }),
    ) else {
        return fail("the control bindings could not be assembled");
    };

    let bundle = match ProofBundle::new(
        BundleHeader::v1(),
        vec![grant],
        vec![signed_action],
        plan,
        vec![anchor_evidence, agent_evidence],
        vec![grant_binding, action_binding],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(action.clone()),
    ) {
        Ok(bundle) => bundle,
        Err(error) => {
            return fail(&format!(
                "the proof bundle could not be assembled: {error:?}"
            ));
        }
    };
    let Ok(proof) = encode_bundle(&bundle) else {
        return fail("the proof bundle could not be encoded canonically");
    };

    // The node decodes a CANONICAL ACTION, not the raw body, so emit that.
    let Ok(canonical) = CanonicalAction::new(
        profile_ref_for_canonical,
        media_for_canonical,
        action.clone(),
        action_permission_for_canonical,
        requested_budget,
    ) else {
        return fail("the canonical action could not be assembled");
    };
    let Ok(canonical_bytes) = encode_canonical_action(&canonical) else {
        return fail("the canonical action could not be encoded");
    };

    println!(
        "{{\"proof\":\"{}\",\"action\":\"{}\"}}",
        Base64UrlUnpadded::encode_string(&proof),
        Base64UrlUnpadded::encode_string(&canonical_bytes)
    );
    ExitCode::SUCCESS
}
