//! Independent writer/reader authoring for actual native recovery journeys.
use super::*;
use crate::harness::authoring::ToolFixture;
use ed25519_dalek::{Signer as _, SigningKey};

pub(crate) fn recipe() -> CompiledRecipe {
    CompiledRecipe::compile(
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
    )
    .expect("maintained recipe")
}

pub(crate) fn trust(writer_present: bool) -> Vec<u8> {
    trust_roots(if writer_present {
        &[0x11, 0x12]
    } else {
        &[0x12]
    })
}

pub(crate) fn trust_roots(seeds: &[u8]) -> Vec<u8> {
    let recipe = recipe();
    let tools = [recipe.review().tool(), crate::effect::RECOVERY_READ_TOOL]
        .map(|tool| McpToolCall::new(recipe.review().service(), tool, Map::new()).expect("tool"));
    let observer = signer(h::OBSERVER_SEED);
    let signers: Vec<_> = seeds.iter().map(|seed| signer(*seed)).collect();
    let roots: Vec<_> = signers.iter().collect();
    let context =
        h::context_for_tools_with_roots(&roots, &observer.principal, NOW, &tools).expect("trust");
    auths_codec::encode_verifier_context(&context).expect("context bytes")
}

pub(crate) fn write_call(operation: &str) -> McpToolCall {
    let recipe = recipe();
    let arguments = json!({
        "operator_namespace": recipe.namespace().as_str(), "recipe_digest": recipe.digest_hex(),
        "operation_id": operation, "record_id": RECORD, "replacement": "Approved",
    });
    McpToolCall::new(
        recipe.review().service(),
        recipe.review().tool(),
        arguments.as_object().expect("args").clone(),
    )
    .expect("write call")
}

pub(crate) fn signed(call: &McpToolCall, reader: bool) -> ToolFixture {
    let root = signer(if reader { 0x12 } else { 0x11 });
    let actor = signer(if reader { 0x44 } else { 0x22 });
    let grant = h::grant_for_tool(
        &root,
        &actor.principal,
        None,
        window(NOW - 3_600, NOW + 3_600),
        call,
    )
    .expect("grant");
    let submission = submission_for_call(&root, &actor, &grant, call, &[]);
    ToolFixture {
        context: trust(!reader),
        proof: submission.proof,
        action: submission.action,
    }
}

pub(crate) fn approval(
    effect: &crate::effect::BoundEffect,
    now: u64,
) -> crate::effect::ExactEffectApproval {
    let request = effect
        .approval_request(now, NOW + 300)
        .expect("approval request");
    let key = SigningKey::from_bytes(&[29; 32]);
    let signature = key
        .sign(&request.signing_message().expect("message"))
        .to_bytes();
    request.with_signature(signature)
}

pub(crate) fn actor(reader: bool) -> String {
    signer(if reader { 0x44 } else { 0x22 })
        .principal
        .as_str()
        .to_owned()
}
