//! AP074 compilation tests using native signed proof fixtures. These establish
//! compilation/approval behavior only; journal and transport evidence is separate.

use super::*;
use crate::effect::{EffectBinding, EffectInstallation, compile_mutation_effect};
use auths_connections::{
    ConnectionAlias, ConnectionId, ConnectionProfile, ConnectionRecord, ConnectionState,
    ProviderKind, SemanticId,
};
use ed25519_dalek::{Signer as _, SigningKey};

fn connection(recipe: &CompiledRecipe) -> ConnectionRecord {
    ConnectionRecord::new(
        ProviderKind::parse("airtable").expect("provider"),
        ConnectionAlias::parse("synthetic").expect("alias"),
        ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").expect("connection ID"),
        SemanticId::parse("auths.gateway-operation/1").expect("contract"),
        SemanticId::parse("auths.gateway-connection-descriptor/1").expect("schema"),
        crate::GatewayConnectionDescriptor::approve(recipe, "Authorization")
            .expect("descriptor")
            .to_bytes()
            .expect("descriptor bytes"),
        [4; 32],
        [5; 32],
        std::num::NonZeroU64::MIN,
        ConnectionState::Active,
        vec!["gateway".to_owned()],
        vec![
            ConnectionProfile::new(SemanticId::parse("auths.mcp").expect("profile"), 2)
                .expect("profile"),
        ],
        NOW - 100,
        NOW - 100,
        None,
    )
    .expect("connection")
}

#[test]
fn native_compilation_approval_and_reverification_keep_exact_request() {
    let root = signer(h::ROOT_SEED);
    let agent = signer(0x22);
    let observer = signer(h::OBSERVER_SEED);
    let recipe = recipe(
        &json!({
            "replacement": {"type": "enum", "variants": ["private-sentinel-Approved", "Pending"]}
        }),
        &Value::Null,
    );
    let context = context(&root, &observer.principal, None);
    let connection = connection(&recipe);
    let arguments = json!({
        "operation_id": "bound-native-1", "operator_namespace": NAMESPACE,
        "recipe_digest": recipe.digest_hex(), "record_id": RECORD,
        "replacement": "private-sentinel-Approved"
    })
    .as_object()
    .expect("arguments")
    .clone();
    let grant = grant(&root, &agent, None);
    let submission = submission(&root, &agent, &grant, &arguments, &[]);
    let installed = EffectInstallation {
        recipe: &recipe,
        context: &context,
        connection: &connection,
        partition: "synthetic-partition",
        epoch: 1,
        qualification: crate::QualificationPolicy::Optional,
    };
    let effect = compile_mutation_effect(&installed, NOW, &submission.proof, &submission.action)
        .expect("native effect");
    let later = compile_mutation_effect(&installed, NOW + 1, &submission.proof, &submission.action)
        .expect("fresh native effect");
    assert_eq!(
        effect.binding(),
        later.binding(),
        "evaluation time is not signed event time"
    );
    let expected = recipe
        .closed_request_from_arguments(&arguments, submission.commitment)
        .expect("compiler output");
    assert_eq!(effect.private_request().body(), expected.body());
    assert_eq!(effect.private_request().url(), expected.url());
    assert_eq!(effect.private_request().headers(), expected.headers());
    let bytes = effect.binding().to_private_bytes().expect("binding bytes");
    assert_eq!(
        &EffectBinding::from_private_bytes(&bytes).expect("binding data"),
        effect.binding()
    );
    assert!(
        !String::from_utf8(bytes.to_vec())
            .expect("json")
            .contains("private-sentinel")
    );
    assert!(!format!("{effect:?}").contains("private-sentinel"));
    let key = SigningKey::from_bytes(&[29; 32]);
    let public = key.verifying_key().to_bytes();
    let review = effect
        .approval_request(public, NOW, NOW + 30)
        .expect("review");
    let signature = key
        .sign(&review.signing_message().expect("native message"))
        .to_bytes();
    let approval = review.with_signature(signature);
    let fixture = serde_json::to_vec_pretty(&json!({
        "schema": "auths.effect-fixture/1",
        "scope": "native compilation and exact approval; no entry or durability claim",
        "effect_id_hex": hex::encode(effect.binding().id().as_bytes()),
        "binding_canonical": std::str::from_utf8(&bytes).expect("binding UTF-8"),
        "approval_canonical": std::str::from_utf8(&approval.to_private_bytes().expect("approval bytes")).expect("approval UTF-8"),
        "approver_public_key_hex": hex::encode(public),
        "request_method": expected.method().as_str(),
        "request_url": expected.url(),
        "request_body": std::str::from_utf8(expected.body()).expect("request UTF-8"),
        "evaluated_at": NOW,
        "approval_expires_at": NOW + 30,
    })).expect("fixture JSON");
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/effect-binding.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").as_deref() == Some(std::ffi::OsStr::new("1")) {
        std::fs::write(&fixture_path, &fixture).expect("write native fixture");
    }
    assert_eq!(
        std::fs::read(&fixture_path).expect("native fixture"),
        fixture
    );
    let approved = effect
        .approve(approval.clone(), &public, NOW)
        .expect("exact approval");
    assert_eq!(approved.effect().private_request().body(), expected.body());
    assert!(approved.validate_approval(&public, NOW + 29).is_ok());
    assert!(approved.validate_approval(&public, NOW + 30).is_err());
    let changed_installation = EffectInstallation {
        epoch: 2,
        ..installed
    };
    let changed = compile_mutation_effect(
        &changed_installation,
        NOW,
        &submission.proof,
        &submission.action,
    )
    .expect("changed epoch");
    assert!(changed.approve(approval, &public, NOW).is_err());
    assert!(compile_mutation_effect(&changed_installation, NOW, &[], &submission.action).is_err());
}
