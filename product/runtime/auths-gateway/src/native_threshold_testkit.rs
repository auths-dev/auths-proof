//! Signed observation aging and threshold witnesses for real entry-fence races.
//! Authoring changes no verifier, approval, clock or adapter decision.
use super::*;
use crate::harness::authoring::ToolFixture;
use ed25519_dalek::{Signer as _, SigningKey};

fn requirement(maximum_age: u32) -> ObservationRequirement {
    ObservationRequirement::new(
        ObserverAnchorId::parse(ANCHOR).expect("anchor"),
        ObservationSchemaId::parse(READ_BACK_SCHEMA).expect("schema"),
        ObservationSubject::Resource(
            ResourceId::parse(&read_back_subject(RECORD)).expect("subject"),
        ),
        maximum_age,
        vec![ObservationCondition::new(
            name("value"),
            ConditionTest::EqLiteral(text("Pending")),
        )],
    )
    .expect("observation requirement")
}

pub(crate) fn signed(call: &McpToolCall, threshold: bool) -> ToolFixture {
    let root = signer(h::ROOT_SEED);
    let actor = signer(0x22);
    let observer = signer(h::OBSERVER_SEED);
    let context = h::context_for_tool(&root, &observer.principal, NOW, call).expect("trust");
    let observation = forged_read_back(&observer, &observer.principal, RECORD, "Pending");
    let (descriptors, detached) = attachments(&[observation]);
    let canonical = McpProfile
        .canonicalize(&call.canonical_bytes().expect("call"))
        .expect("canonical action")
        .with_detached_attachments(detached)
        .expect("attachments");
    let references = [ProofRef::new([0x40; 32]), ProofRef::new([0x41; 32])];
    let plan = if threshold {
        AuthorizationPlan::k_of_n(
            1,
            references
                .into_iter()
                .map(AuthorizationPlan::proof)
                .collect(),
        )
        .expect("one-of-two threshold")
    } else {
        AuthorizationPlan::proof(references[0])
    };
    let mut grants = Vec::new();
    let mut actions = Vec::new();
    let mut bindings = Vec::new();
    for (index, maximum_age) in [5, 300]
        .into_iter()
        .enumerate()
        .take(if threshold { 2 } else { 1 })
    {
        let grant = h::grant_for_tool(
            &root,
            &actor.principal,
            Some(requirement(maximum_age)),
            window(NOW - 3_600, NOW + 3_600),
            call,
        )
        .expect("signed grant");
        let action = sign_action(
            &actor,
            envelope(
                &actor,
                &canonical,
                &grant,
                &plan,
                references[index],
                descriptors.clone(),
            ),
        );
        bindings.push(
            ControlBinding::new(
                StatementRef::Grant(grant_id(grant.statement()).expect("grant ID")),
                vec![root.evidence().id()],
            )
            .expect("grant control"),
        );
        bindings.push(
            ControlBinding::new(
                StatementRef::Action(action_id(action.envelope()).expect("action ID")),
                vec![actor.evidence().id()],
            )
            .expect("action control"),
        );
        grants.push(grant);
        actions.push(action);
    }
    let mut evidence = vec![root.evidence(), actor.evidence()];
    evidence.sort_by_key(EvidenceObject::id);
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        grants,
        actions,
        plan,
        evidence,
        bindings,
        Vec::new(),
        Vec::new(),
        descriptors,
        Some(canonical.body().to_vec()),
    )
    .expect("native bundle");
    ToolFixture {
        context: auths_codec::encode_verifier_context(&context).expect("context bytes"),
        proof: encode_bundle(&bundle).expect("proof"),
        action: encode_canonical_action(&canonical).expect("action bytes"),
    }
}

pub(crate) fn selection_witness(signed: &ToolFixture, threshold: bool, after: u64) -> Value {
    let context = auths_codec::decode_verifier_context(&signed.context).expect("context");
    let before = crate::engine::verify_native(&context, NOW, &signed.proof, &signed.action)
        .expect("native authority before wait");
    let later = crate::engine::verify_native(&context, after, &signed.proof, &signed.action);
    let changed = after > NOW + 5;
    let mut witness = json!({
        "threshold": threshold,
        "observed_at": NOW,
        "short_maximum_age_seconds": 5,
        "evaluation_after_wait": after,
        "authorized_before_wait": true,
        "authorized_after_wait": later.is_ok(),
        "signed_inputs_reused": true,
    });
    assert_eq!(
        before.portable().authorized_branches().len(),
        if threshold { 2 } else { 1 }
    );
    if threshold || !changed {
        let later = later.expect("proof remains authorized");
        let before_authority =
            crate::effect::NativeAuthority::verified(before.portable(), &context)
                .expect("authority");
        let after_authority = crate::effect::NativeAuthority::verified(later.portable(), &context)
            .expect("authority");
        assert_eq!(
            before_authority.commitment() == after_authority.commitment(),
            !changed
        );
        assert_eq!(
            later.portable().authorized_branches().len(),
            if threshold && !changed { 2 } else { 1 }
        );
        assert_eq!(
            later.portable().observation_satisfactions().len(),
            if threshold && !changed { 2 } else { 1 }
        );
        witness["selected_branches_before"] = json!(
            before
                .portable()
                .authorized_branches()
                .iter()
                .map(|r| hex::encode(r.as_bytes()))
                .collect::<Vec<_>>()
        );
        witness["selected_branches_after"] = json!(
            later
                .portable()
                .authorized_branches()
                .iter()
                .map(|r| hex::encode(r.as_bytes()))
                .collect::<Vec<_>>()
        );
        witness["authority_commitment_changed"] = json!(changed);
    } else {
        assert_eq!(
            later.expect_err("single branch observation is stale"),
            indeterminate("observation-missing")
        );
    }
    witness
}

pub(crate) fn verify_binding(
    before: &crate::effect::EffectBinding,
    fresh: Result<crate::effect::BoundEffect, GatewaySubmitResult>,
    approval: crate::effect::ExactEffectApproval,
    threshold: bool,
    after: u64,
) {
    let changed = after > NOW + 5;
    if !threshold && changed {
        assert_eq!(
            fresh.expect_err("stale evidence cannot compile an effect"),
            indeterminate("observation-missing")
        );
        return;
    }
    let fresh = fresh.expect("native effect remains compilable");
    assert_eq!(before == fresh.binding(), !changed);
    let mut before_json: Value =
        serde_json::from_slice(&before.to_private_bytes().expect("binding")).expect("binding JSON");
    let mut after_json: Value =
        serde_json::from_slice(&fresh.binding().to_private_bytes().expect("binding"))
            .expect("binding JSON");
    before_json["native_authority"] = Value::Null;
    after_json["native_authority"] = Value::Null;
    assert_eq!(before_json, after_json, "only selected authority changes");
    let key = SigningKey::from_bytes(&[29; 32]).verifying_key().to_bytes();
    assert_eq!(fresh.approve(approval, &key, after).is_err(), changed);
}

/// Compile identical signed bytes on both sides of the future lock wait.
/// A threshold change remains authorized but invalidates the old exact approval;
/// a single-branch observation control actually becomes stale instead.
pub(crate) async fn authorize(
    engine: &crate::GatewayEngine,
    clock: &crate::FixedClock,
    root: &std::path::Path,
    operation: &str,
    threshold: bool,
    after: u64,
) -> Value {
    let call = engine
        .content_authorization_call(br#"{"record_id":"recTEST0000000001"}"#, operation)
        .await
        .expect("native call");
    let signed = signed(&call, threshold);
    let mut witness = selection_witness(&signed, threshold, after);
    let first = engine
        .compile_content_action(&signed.proof, &signed.action)
        .await
        .expect("initial native effect");
    let request = first
        .approval_request(NOW, NOW + 300)
        .expect("approval request");
    let key = SigningKey::from_bytes(&[29; 32]);
    let signature = key
        .sign(&request.signing_message().expect("message"))
        .to_bytes();
    let approval = request.with_signature(signature);
    let before_binding = first.binding().clone();
    first
        .approve(approval.clone(), &key.verifying_key().to_bytes(), after)
        .expect("original exact approval remains current after waiting");
    clock.set(after);
    let fresh = engine
        .compile_content_action(&signed.proof, &signed.action)
        .await;
    clock.set(NOW);
    verify_binding(&before_binding, fresh, approval.clone(), threshold, after);
    if threshold || after <= NOW + 5 {
        witness["old_approval_accepts_current_effect"] = json!(after <= NOW + 5);
    }
    for (suffix, bytes) in [
        ("proof", signed.proof),
        ("action", signed.action),
        (
            "approval",
            approval.to_private_bytes().expect("approval").to_vec(),
        ),
    ] {
        crate::native_process_tests::private(&root.join(format!("{operation}.{suffix}")), &bytes);
    }
    witness
}
