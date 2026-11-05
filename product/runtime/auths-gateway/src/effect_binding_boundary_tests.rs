//! Independent real-signed binding substitutions. Compilation and exact approval
//! are exercised through the native owner; this fixture cannot grant transport.
use super::*;
use crate::effect::{BoundEffect, ExactEffectApproval};
use std::num::NonZeroU64;

#[derive(Clone, Copy)]
enum Alteration {
    None,
    Header,
    Destination,
    Namespace,
    Configuration,
}

#[derive(Clone)]
struct Inputs {
    actor: u8,
    approver: u8,
    account: &'static str,
    generation: u64,
    partition: &'static str,
    epoch: u64,
    operation: &'static str,
    resource: &'static str,
    replacement: &'static str,
    alteration: Alteration,
}
impl Inputs {
    fn original() -> Self {
        Self {
            actor: 0x22,
            approver: 29,
            account: "acct_TESTACCOUNT01",
            generation: 1,
            partition: "binding-boundary",
            epoch: 1,
            operation: "binding-1",
            resource: "recTEST0000000001",
            replacement: "Approved",
            alteration: Alteration::None,
        }
    }
}

fn compile(input: &Inputs) -> Result<BoundEffect, crate::GatewaySubmitResult> {
    let mut source: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/airtable/recipe.json"
    ))
    .expect("source");
    if matches!(input.alteration, Alteration::Header) {
        source["provider_headers"] = json!({"X-GitHub-Api-Version":"2026-01-01"});
    }
    if matches!(input.alteration, Alteration::Destination) {
        source["origin"] = json!("https://different.example");
    }
    let recipe = CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("source"),
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
    )
    .expect("recipe");
    let call=McpToolCall::new(recipe.review().service(),recipe.review().tool(),json!({
        "operation_id":input.operation,"operator_namespace":if matches!(input.alteration, Alteration::Namespace) {"foreign-namespace"} else {recipe.namespace().as_str()},
        "recipe_digest":recipe.digest_hex(),"record_id":input.resource,"replacement":input.replacement
    }).as_object().expect("arguments").clone()).expect("native call");
    let root = signer(h::ROOT_SEED);
    let actor = signer(input.actor);
    let observer = signer(h::OBSERVER_SEED);
    let mut context = h::context_for_tool(&root, &observer.principal, NOW, &call).expect("trust");
    if matches!(input.alteration, Alteration::Configuration) {
        context = context
            .with_configuration(auths_model::VerifierConfigurationId::new([0x99; 32]))
            .expect("explicit required configuration");
    }
    let grant = h::grant_for_tool(
        &root,
        &actor.principal,
        None,
        window(NOW - 10, NOW + 3600),
        &call,
    )
    .expect("grant");
    let signed = submission_for_call_during(
        &root,
        &actor,
        &grant,
        &call,
        &[],
        window(NOW - 5, NOW + 300),
    );
    let initial = connection_account(&recipe, crate::submit::account_commitment(input.account));
    let connection = ConnectionRecord::new(
        initial.provider_kind().clone(),
        initial.alias().clone(),
        initial.connection_id().clone(),
        initial.contract().clone(),
        initial.descriptor_schema().clone(),
        initial.descriptor().to_vec(),
        *initial.account_commitment(),
        *initial.credential_reference_commitment(),
        NonZeroU64::new(input.generation).expect("nonzero generation"),
        initial.state(),
        initial.allowed_workloads().to_vec(),
        initial.allowed_profiles().to_vec(),
        initial.created_at_unix_seconds(),
        initial.updated_at_unix_seconds(),
        None,
    )
    .expect("installed record");
    let public = SigningKey::from_bytes(&[input.approver; 32])
        .verifying_key()
        .to_bytes();
    let policy = EffectPolicy::new(input.partition.to_owned(), input.epoch, public)
        .expect("installed policy");
    compile_mutation_effect(
        &policy.installation(
            &recipe,
            &context,
            &connection,
            crate::QualificationPolicy::Optional,
            [12; 32],
        ),
        NOW,
        &signed.proof,
        &signed.action,
    )
}

fn approval(effect: &BoundEffect, approver: u8) -> ExactEffectApproval {
    let request = effect
        .approval_request(NOW, NOW + 300)
        .expect("native approval request");
    let signature = SigningKey::from_bytes(&[approver; 32])
        .sign(&request.signing_message().expect("preimage"))
        .to_bytes();
    request.with_signature(signature)
}

#[test]
fn native_independent_binding_substitutions_require_new_approval() {
    let original = Inputs::original();
    let baseline = compile(&original).expect("baseline");
    let baseline_id = *baseline.binding().id().as_bytes();
    let old_approval = approval(&baseline, 29);
    let mut cases = Vec::new();
    let mut failures = Vec::new();
    for name in [
        "actor",
        "account",
        "credential-generation",
        "partition",
        "epoch",
        "operation",
        "resource",
        "body",
        "header",
        "destination",
        "approver",
        "namespace",
        "verifier-configuration",
    ] {
        match std::panic::catch_unwind(|| binding_case(name, &original, baseline_id, &old_approval))
        {
            Ok(value) => cases.push(value),
            Err(_) => failures.push(name),
        }
    }
    baseline
        .approve(
            old_approval,
            &SigningKey::from_bytes(&[29; 32]).verifying_key().to_bytes(),
            NOW,
        )
        .expect("original control");
    assert!(
        failures.is_empty(),
        "independent binding failures: {failures:?}"
    );
    let bytes=serde_json::to_vec_pretty(&json!({"schema":"auths.native-independent-bindings/1",
        "scope":"ordinary native signed proof, compiled effect and exact approval; explicit synthetic trust/connection/clock",
        "excluded":["durable entry","provider execution","human presence"],"cases":cases})).expect("artifact");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/native-independent-bindings.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("artifact");
    }
    assert_eq!(std::fs::read(path).expect("artifact"), bytes);
}

fn binding_case(
    name: &str,
    original: &Inputs,
    baseline_id: [u8; 32],
    old_approval: &ExactEffectApproval,
) -> Value {
    let mut changed = original.clone();
    match name {
        "actor" => changed.actor = 0x23,
        "account" => changed.account = "acct_TESTACCOUNT02",
        "credential-generation" => changed.generation = 2,
        "partition" => changed.partition = "other-partition",
        "epoch" => changed.epoch = 2,
        "operation" => changed.operation = "binding-2",
        "resource" => changed.resource = "recTEST0000000002",
        "body" => changed.replacement = "Pending",
        "header" => changed.alteration = Alteration::Header,
        "destination" => changed.alteration = Alteration::Destination,
        "approver" => changed.approver = 30,
        "namespace" => changed.alteration = Alteration::Namespace,
        "verifier-configuration" => changed.alteration = Alteration::Configuration,
        _ => unreachable!("closed source corpus"),
    }
    let result = compile(&changed);
    if matches!(
        changed.alteration,
        Alteration::Namespace | Alteration::Configuration
    ) {
        assert!(
            result.is_err(),
            "{name} must refuse before approval/admission"
        );
        return json!({"case":name,"native_compilation_refused":true});
    }
    let effect = result.expect("independently authorized changed action");
    let id = *effect.binding().id().as_bytes();
    assert_ne!(id, baseline_id, "{name}");
    let fresh = approval(&effect, changed.approver);
    let public = SigningKey::from_bytes(&[changed.approver; 32])
        .verifying_key()
        .to_bytes();
    assert!(
        effect.approve(old_approval.clone(), &public, NOW).is_err(),
        "{name}"
    );
    compile(&changed)
        .expect("fresh native control")
        .approve(fresh, &public, NOW)
        .expect("fresh exact approval");
    json!({"case":name,"baseline_effect":hex::encode(baseline_id),"changed_effect":hex::encode(id),
            "old_exact_approval_refused":true,"fresh_native_authority_and_approval_accepted":true})
}
