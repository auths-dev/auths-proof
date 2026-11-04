//! Native signed approval witnesses for changed review meaning. Pure compilation
//! uses explicit synthetic trust/connection/clock; no transport or human claim.
use super::*;
use crate::effect::{BoundEffect, ExactEffectApproval, fixture_policy};
use crate::harness::authoring::{ToolFixture, tool_fixture_in_window};

struct NativeCase {
    recipe: CompiledRecipe,
    signed: ToolFixture,
    effect: BoundEffect,
}

fn effect(
    recipe: &CompiledRecipe,
    signed: &ToolFixture,
) -> Result<BoundEffect, crate::GatewaySubmitResult> {
    let context = auths_codec::decode_verifier_context(&signed.context).expect("explicit trust");
    let connection = connection_account(
        recipe,
        crate::submit::account_commitment("acct_TESTACCOUNT01"),
    );
    let policy = fixture_policy().expect("policy");
    compile_mutation_effect(
        &policy.installation(
            recipe,
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

fn native(source: &Value, lock: &[u8], financial: bool) -> NativeCase {
    let recipe = CompiledRecipe::compile(&serde_json::to_vec(source).expect("source"), lock)
        .expect("reviewed recipe");
    let mut arguments = if financial {
        json!({"amount":500,"currency":"usd","connect_account":"acct_TESTACCOUNT01","payment_intent":"pi_review_fixture"})
    } else {
        json!({"record_id":"recTEST0000000001","replacement":"Approved"})
    };
    arguments["operation_id"] = json!("review-bound-1");
    arguments["operator_namespace"] = json!(recipe.namespace().as_str());
    arguments["recipe_digest"] = json!(recipe.digest_hex());
    let call = McpToolCall::new(
        recipe.review().service(),
        recipe.review().tool(),
        arguments.as_object().expect("arguments").clone(),
    )
    .expect("native call");
    let policy = financial.then(|| {
        crate::ArgumentCeilingPolicy::new("amount", 1_000, 3_600, 10)
            .expect("bound")
            .with_sum(
                10_000,
                Some(crate::ListedValues::new("currency", &["usd"]).expect("partition")),
            )
            .expect("sum")
            .with_scope(
                crate::ListedValues::new("connect_account", &["acct_TESTACCOUNT01"])
                    .expect("scope"),
            )
            .expect("scope bound")
    });
    let signed = tool_fixture_in_window(&call, NOW, NOW - 10, NOW + 3_600, policy.as_ref())
        .expect("real signed native proof");
    let effect = effect(&recipe, &signed).expect("native effect");
    NativeCase {
        recipe,
        signed,
        effect,
    }
}

fn approval(effect: &BoundEffect) -> ExactEffectApproval {
    let request = effect
        .approval_request(NOW, NOW + 300)
        .expect("complete native request");
    let signature = SigningKey::from_bytes(&[29; 32])
        .sign(&request.signing_message().expect("native preimage"))
        .to_bytes();
    request.with_signature(signature)
}

fn case(
    source: &Value,
    lock: &[u8],
    financial: bool,
    name: &str,
    pointer: &str,
    replacement: Value,
) -> Value {
    let original = native(source, lock, financial);
    let original_id = *original.effect.binding().id().as_bytes();
    let old_approval = approval(&original.effect);
    let mut changed_source = source.clone();
    *changed_source
        .pointer_mut(pointer)
        .expect("declared review field") = replacement;
    let changed = native(&changed_source, lock, financial);
    let changed_id = *changed.effect.binding().id().as_bytes();
    assert_ne!(original.recipe.digest(), changed.recipe.digest());
    assert_ne!(original_id, changed_id);
    assert!(
        effect(&changed.recipe, &original.signed).is_err(),
        "old native action pins the original recipe"
    );
    let request = changed
        .effect
        .approval_request(NOW, NOW + 300)
        .expect("fresh review request");
    let fresh_approval = approval(&changed.effect);
    let review = changed
        .effect
        .private_review()
        .expect("complete private review");
    let literal = review
        .render_literal(crate::effect::LITERAL_REVIEW_RENDERER)
        .expect("supported complete renderer");
    assert_eq!(
        serde_json::from_str::<Value>(&literal).expect("literal"),
        serde_json::from_slice::<Value>(&review.to_private_bytes().expect("review bytes"))
            .expect("review")
    );
    assert!(review.render_literal("summary-with-truncation/1").is_err());
    let public = SigningKey::from_bytes(&[29; 32]).verifying_key().to_bytes();
    assert!(
        changed
            .effect
            .approve(old_approval.clone(), &public, NOW)
            .is_err(),
        "changed meaning cannot reuse approval"
    );
    original
        .effect
        .approve(old_approval, &public, NOW)
        .expect("original positive control");
    let fresh = native(&changed_source, lock, financial);
    fresh
        .effect
        .approve(fresh_approval, &public, NOW)
        .expect("fresh exact approval positive control");
    json!({"case":name,"original_effect":hex::encode(original_id),"changed_effect":hex::encode(changed_id),
        "old_native_action_refused":true,"old_exact_approval_refused":true,"fresh_exact_approval_accepted":true,
        "complete_native_literal":literal.as_str(),"native_signing_request":serde_json::to_value(request).expect("request")})
}

fn incomplete(source: &Value, lock: &[u8]) -> Vec<Value> {
    let mut cases = Vec::new();
    for (name, pointer, replacement) in [
        (
            "missing-unit",
            "/review/fields/amount",
            json!({"kind":"integer","label":"Amount"}),
        ),
        ("null-unit", "/review/fields/amount/unit", Value::Null),
        ("empty-unit", "/review/fields/amount/unit", json!("")),
        (
            "whitespace-unit",
            "/review/fields/amount/unit",
            json!(" minor units "),
        ),
        (
            "unit-limit-plus-one",
            "/review/fields/amount/unit",
            json!("u".repeat(81)),
        ),
        (
            "unit-nonascii",
            "/review/fields/amount/unit",
            json!("\u{202e}USD"),
        ),
        (
            "unit-control",
            "/review/fields/amount/unit",
            json!("USD\nDestination: hidden"),
        ),
        ("missing-fields", "/review/fields", json!({})),
        (
            "unsupported-review",
            "/review/schema",
            json!("auths.effect-review-contract/999"),
        ),
        ("missing-consequences", "/review/consequences", json!([])),
        (
            "consequence-limit-plus-one",
            "/review/consequences",
            json!(["c".repeat(513)]),
        ),
        (
            "too-many-consequences",
            "/review/consequences",
            json!(vec!["Consequence"; 9]),
        ),
        (
            "case-insensitive-label-collision",
            "/review/fields/amount/label",
            json!("currency"),
        ),
    ] {
        let mut changed = source.clone();
        *changed.pointer_mut(pointer).expect("declared field") = replacement;
        let input = serde_json::to_vec(&changed).expect("source");
        let refusal = CompiledRecipe::compile(&input, lock).expect_err(name);
        cases.push(json!({"case":name,"code":refusal.code(),"source_json":String::from_utf8(input).expect("JSON")}));
    }
    cases
}

#[test]
fn native_review_changes_require_fresh_authority_and_approval() {
    let airtable: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/airtable/recipe.json"
    ))
    .expect("source");
    let airtable_lock =
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json");
    let stripe: Value = serde_json::from_slice(include_bytes!(
        "../../../../examples/stripe-refund-approval/recipe.json"
    ))
    .expect("source");
    let stripe_lock =
        include_bytes!("../../../../examples/stripe-refund-approval/profile.lock.json");
    let cases = vec![
        case(
            &airtable,
            airtable_lock,
            false,
            "label-as-literal-data",
            "/review/fields/replacement/label",
            json!("<script>Label is data</script>"),
        ),
        case(
            &airtable,
            airtable_lock,
            false,
            "consequences",
            "/review/consequences",
            json!(["Replace the named field; independent writers may change it afterward."]),
        ),
        case(
            &airtable,
            airtable_lock,
            false,
            "destination",
            "/origin",
            json!("https://different.example"),
        ),
        case(
            &stripe,
            stripe_lock,
            true,
            "financial-units",
            "/review/fields/amount/unit",
            json!("different explicitly reviewed units"),
        ),
        case(
            &stripe,
            stripe_lock,
            true,
            "financial-unit-limit",
            "/review/fields/amount/unit",
            json!("u".repeat(80)),
        ),
    ];
    let bytes = serde_json::to_vec_pretty(&json!({"schema":"auths.native-review-approval-boundary/1",
        "scope":"native signed proof and exact approval; complete literal review; explicit synthetic trust/connection/clock",
        "excluded":["provider entry","durable adapter","installed frontend","human presence","provider qualification"],
        "cases":cases,"incomplete_review_refusals":incomplete(&stripe,stripe_lock)})).expect("artifact");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/review-approval-boundary.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), bytes);
}
