//! AP074 compilation tests using native signed proof fixtures. These establish
//! compilation/approval behavior only; journal and transport evidence is separate.

use super::*;
use crate::effect::{EffectBinding, EffectInstallation, EffectPolicy, compile_mutation_effect};
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
    let key = SigningKey::from_bytes(&[29; 32]);
    let public = key.verifying_key().to_bytes();
    let policy = EffectPolicy::new("synthetic-partition".to_owned(), 1, public)
        .expect("installed effect policy");
    let policy_bytes = policy.to_private_bytes().expect("policy bytes");
    assert_eq!(
        EffectPolicy::from_private_bytes(&policy_bytes).expect("policy"),
        policy
    );
    let installed = policy.installation(
        &recipe,
        &context,
        &connection,
        crate::QualificationPolicy::Optional,
    );
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
    let private_review = effect.private_review().expect("native private review");
    let review_bytes = private_review.to_private_bytes().expect("review JSON");
    let review_json: Value = serde_json::from_slice(&review_bytes).expect("review JSON");
    assert_eq!(
        review_json["effect_id_hex"],
        hex::encode(effect.binding().id().as_bytes())
    );
    assert_eq!(
        review_json["native"]["request"]["body"],
        std::str::from_utf8(expected.body()).expect("body")
    );
    assert_eq!(review_json["native"]["request"]["url"], expected.url());
    assert!(!format!("{private_review:?}").contains("private-sentinel"));
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
    let review = effect.approval_request(NOW, NOW + 30).expect("review");
    let signature = key
        .sign(&review.signing_message().expect("native message"))
        .to_bytes();
    let signing_request = review
        .to_private_bytes()
        .expect("canonical signing request");
    assert_eq!(
        crate::effect::EffectApprovalRequest::from_private_bytes(&signing_request)
            .expect("signing data"),
        review
    );
    let approval = review.with_signature(signature);
    let frame = crate::app::AppSubmission {
        schema: crate::app::APP_REQUEST_SCHEMA.to_owned(),
        proof_b64: base64ct::Base64UrlUnpadded::encode_string(&submission.proof),
        action_b64: base64ct::Base64UrlUnpadded::encode_string(&submission.action),
        approval_b64: base64ct::Base64UrlUnpadded::encode_string(
            &approval.to_private_bytes().expect("approval"),
        ),
    };
    let fixture = serde_json::to_vec_pretty(&json!({
        "schema": "auths.effect-fixture/1",
        "scope": "native compilation and exact approval; no entry or durability claim",
        "effect_id_hex": hex::encode(effect.binding().id().as_bytes()),
        "operation_key_hex": hex::encode(crate::GatewayAttemptKey::for_operation(&policy, expected.namespace(), expected.operation_id()).expect("native replay key").as_bytes()),
        "binding_canonical": std::str::from_utf8(&bytes).expect("binding UTF-8"),
        "approval_canonical": std::str::from_utf8(&approval.to_private_bytes().expect("approval bytes")).expect("approval UTF-8"),
        "approver_public_key_hex": hex::encode(public),
        "request_method": expected.method().as_str(),
        "request_url": expected.url(),
        "request_body": std::str::from_utf8(expected.body()).expect("request UTF-8"),
        "evaluated_at": NOW,
        "approval_expires_at": NOW + 30,
        "submission_frame_canonical": String::from_utf8(serde_json_canonicalizer::to_vec(&frame).expect("native frame")).expect("UTF-8"),
    })).expect("fixture JSON");
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/effect-binding.json");
    let policy_path = fixture_path.with_file_name("effect-policy.json");
    let request_path = fixture_path.with_file_name("effect-approval-request.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").as_deref() == Some(std::ffi::OsStr::new("1")) {
        std::fs::write(&fixture_path, &fixture).expect("write native fixture");
        std::fs::write(&policy_path, &policy_bytes).expect("write native policy fixture");
        std::fs::write(&request_path, &signing_request).expect("write native signing fixture");
    }
    assert_eq!(
        std::fs::read(&policy_path).expect("policy fixture"),
        *policy_bytes
    );
    assert_eq!(
        std::fs::read(&request_path).expect("signing fixture"),
        *signing_request
    );
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
    assert!(approved.validate_for_entry(&installed, NOW + 29).is_ok());
    assert!(approved.validate_for_entry(&installed, NOW + 30).is_err());
    let late_request = later
        .approval_request(NOW + 3_570, NOW + 3_605)
        .expect("approval spanning native action expiry");
    let late_signature = key
        .sign(&late_request.signing_message().expect("message"))
        .to_bytes();
    let late = later
        .approve(
            late_request.with_signature(late_signature),
            &public,
            NOW + 3_570,
        )
        .expect("late approval");
    assert!(late.validate_for_entry(&installed, NOW + 3_599).is_ok());
    assert!(late.validate_approval(&public, NOW + 3_601).is_ok());
    assert!(
        late.validate_for_entry(&installed, NOW + 3_601).is_err(),
        "a current human approval must not revive expired native resource authority"
    );
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
