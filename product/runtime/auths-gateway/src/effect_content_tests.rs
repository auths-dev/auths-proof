//! Native recipe/content compilation corpus. No runtime acquisition, content
//! custody, release or provider transport is asserted by these fixtures.
use super::*;
use crate::effect::{CONTENT_READ_TOOL, ContentReadTarget, compile_content_acquisition};

fn declaration(projection: Value) -> Value {
    json!({"schema": "auths.gateway-content-read/1", "resource_field": "record_id",
        "path": [{"kind": "fixed", "value": "documents"}, {"kind": "field", "name": "record_id"}],
        "query": [{"name": "format", "value": "text/plain"}], "projection": projection,
        "maximum_response_bytes": 1024, "maximum_content_bytes": 64})
}

fn content_recipe(content: Value) -> Result<CompiledRecipe, crate::GatewayRecipeError> {
    let (source, lock) = h::recipe_sources(&json!({}), &Value::Null).expect("source/lock");
    let mut source: Value = serde_json::from_slice(&source).expect("source");
    source["content"] = content;
    CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source bytes"), &lock)
}

fn invalid_declarations() -> Value {
    let original = declaration(json!({"kind": "json-string", "pointer": "/content"}));
    let mut cases = vec![];
    for field in [
        "schema",
        "resource_field",
        "path",
        "query",
        "projection",
        "maximum_response_bytes",
        "maximum_content_bytes",
    ] {
        let mut changed = original.clone();
        changed[field] = match field {
            "schema" => json!("auths.gateway-content-read/0"),
            "resource_field" => json!("operation_id"),
            "path" => json!([{"kind": "response-field", "pointer": "/url", "max_bytes": 20}]),
            "query" => json!([{"name": "format", "value": "a"}, {"name": "format", "value": "b"}]),
            "projection" => json!({"kind": "json-string", "pointer": "/bad~3pointer"}),
            "maximum_response_bytes" => json!(65537),
            "maximum_content_bytes" => json!(1025),
            _ => unreachable!(),
        };
        assert!(content_recipe(changed).is_err(), "{field}");
        cases.push(field);
    }
    for path in [
        json!([{"kind": "fixed", "value": ".."}, {"kind": "field", "name": "record_id"}]),
        json!([{"kind": "field", "name": "operation_id"}, {"kind": "field", "name": "record_id"}]),
        json!([{"kind": "field", "name": "replacement"}, {"kind": "field", "name": "record_id"}]),
    ] {
        let mut changed = original.clone();
        changed["path"] = path;
        assert!(content_recipe(changed).is_err());
    }
    for query in [
        json!([{"name": "z", "value": "a"}, {"name": "a", "value": "b"}]),
        json!([{"name": "a&evil", "value": "a"}]),
        json!([{"name": "a", "value": "x\r\ny"}]),
        json!([{"name": "a", "value": "x".repeat(513)}]),
    ] {
        let mut changed = original.clone();
        changed["query"] = query;
        assert!(content_recipe(changed).is_err());
    }
    for pointer in ["/bad~", "/bad~3", "", "/a/b/c/d/e/f/g/h/i"] {
        let mut changed = original.clone();
        changed["projection"]["pointer"] = json!(pointer);
        assert!(content_recipe(changed).is_err());
    }
    json!({"invalid_fields_refused": cases, "unsafe_path_query_pointer_refused": true})
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded representation and stable response-code corpus"
)]
fn projections(
    recipe: &CompiledRecipe,
    arguments: &Map<String, Value>,
    json_string: bool,
) -> Value {
    let read = recipe.content_read(arguments).expect("closed read");
    let sentinel = "PRIVATE-CONTENT-SYNTHETIC";
    let body = if json_string {
        serde_json::to_vec(&json!({"content": sentinel})).expect("JSON")
    } else {
        sentinel.as_bytes().to_vec()
    };
    let content = read
        .project_response(200, read.media_type(), &body)
        .expect("private content");
    assert_eq!(content.as_slice(), sentinel.as_bytes());
    assert!(
        read.project_response(200, &format!("{}; charset=utf-8", read.media_type()), &body)
            .is_ok()
    );
    assert!(
        read.project_response(403, read.media_type(), &body)
            .is_err()
    );
    assert!(
        read.project_response(200, "application/octet-stream", &body)
            .is_err()
    );
    assert!(
        read.project_response(
            200,
            &format!("{}; charset=iso-8859-1", read.media_type()),
            &body
        )
        .is_err()
    );
    assert!(
        read.project_response(
            200,
            &format!("{}; charset=utf-8; extra=x", read.media_type()),
            &body
        )
        .is_err()
    );
    assert!(
        read.project_response(200, read.media_type(), &vec![b'a'; 1025])
            .is_err()
    );
    assert!(
        read.project_response(200, read.media_type(), &[255])
            .is_err()
    );
    for length in [0, 64, 65] {
        let body = if json_string {
            serde_json::to_vec(&json!({"content": "x".repeat(length)})).expect("JSON")
        } else {
            vec![b'x'; length]
        };
        assert_eq!(
            read.project_response(200, read.media_type(), &body).is_ok(),
            length <= 64
        );
    }
    if json_string {
        for body in [
            br#"{"content":"wrong","content":"right"}"#.as_slice(),
            br#"{"other":"value"}"#,
            br#"{"content":42}"#,
            br#"{"content":"ok"} {}"#,
        ] {
            assert!(read.project_response(200, read.media_type(), body).is_err());
        }
    }
    let over_content = if json_string {
        serde_json::to_vec(&json!({"content": "x".repeat(65)})).expect("JSON")
    } else {
        vec![b'x'; 65]
    };
    let mut codes = vec![
        read.project_response(403, read.media_type(), &body)
            .expect_err("status")
            .code(),
        read.project_response(200, "application/octet-stream", &body)
            .expect_err("media")
            .code(),
        read.project_response(200, read.media_type(), &vec![b'x'; 1025])
            .expect_err("response bound")
            .code(),
        read.project_response(200, read.media_type(), &[255])
            .expect_err("invalid response")
            .code(),
        read.project_response(200, read.media_type(), &over_content)
            .expect_err("content bound")
            .code(),
    ];
    assert_eq!(
        codes,
        vec![
            "gateway.content.response-status",
            "gateway.content.response-media-type",
            "gateway.content.response-too-large",
            "gateway.content.invalid-response",
            "gateway.content.content-too-large"
        ]
    );
    if json_string {
        let code = read
            .project_response(200, read.media_type(), b"{}")
            .expect_err("missing projection")
            .code();
        assert_eq!(code, "gateway.content.missing-projection");
        codes.push(code);
    }
    assert_eq!(
        format!("{read:?}"),
        "ClosedContentRead { private: [redacted] }"
    );
    assert!(!read.private_contract().to_string().contains(sentinel));
    json!({"projection": if json_string {"json-string"} else {"utf8"},
        "status_media_utf8_and_limits_enforced": true, "private_content_not_in_contract_or_debug": true,
        "request": read.private_contract(), "response_codes": codes})
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one native signed compilation corpus with independent negative cases"
)]
fn native_content_compilation_fixture_is_current() {
    let root = signer(h::ROOT_SEED);
    let reader = signer(0x33);
    let observer = signer(h::OBSERVER_SEED);
    let key = SigningKey::from_bytes(&[29; 32]);
    let public = key.verifying_key().to_bytes();
    let policy = EffectPolicy::new("synthetic-content".to_owned(), 1, public).expect("policy");
    let arguments = json!({"record_id": RECORD})
        .as_object()
        .expect("arguments")
        .clone();
    let mut cases = vec![];
    let mut projection_cases = vec![];
    for projection in [
        json!({"kind": "utf8"}),
        json!({"kind": "json-string", "pointer": "/content"}),
    ] {
        let recipe = content_recipe(declaration(projection.clone())).expect("content recipe");
        assert_eq!(
            recipe.review_document()["content_acquisition"]["declaration"],
            declaration(projection.clone())
        );
        let connection = connection(&recipe);
        let target = ContentReadTarget::new(&recipe, &connection, arguments.clone())
            .expect("content target");
        let operation = LogicalOperationId::parse("content-1").expect("operation");
        let call = target
            .authorization_call(&recipe, &operation)
            .expect("native read call");
        let read_context =
            h::context_for_tool(&root, &observer.principal, NOW, &call).expect("read trust");
        let grant = h::grant_for_tool(
            &root,
            &reader.principal,
            None,
            window(NOW - 3600, NOW + 3600),
            &call,
        )
        .expect("grant");
        let submission = submission_for_call(&root, &reader, &grant, &call, &[]);
        let installed = policy.installation(
            &recipe,
            &read_context,
            &connection,
            crate::QualificationPolicy::Optional,
            [12; 32],
        );
        let effect = compile_content_acquisition(
            &installed,
            &target,
            NOW,
            &submission.proof,
            &submission.action,
        )
        .expect("native effect");
        assert!(effect.private_request().is_none(), "not a mutation");
        let review = effect.private_review().expect("review");
        let literal = review
            .render_literal(crate::effect::LITERAL_REVIEW_RENDERER)
            .expect("complete review");
        assert!(literal.contains("/documents/"));
        assert!(literal.contains("format=text%2Fplain"));
        assert!(literal.contains("separate-authorization-required"));
        let binding: Value =
            serde_json::from_slice(&effect.binding().to_private_bytes().expect("binding"))
                .expect("JSON");
        assert_eq!(binding["protocol"]["kind"], "acquisition");
        assert_eq!(
            binding["reservations"]
                .as_array()
                .expect("reservations")
                .len(),
            2
        );
        let request = effect
            .approval_request(NOW, NOW + 30)
            .expect("approval request");
        let signature = key
            .sign(&request.signing_message().expect("message"))
            .to_bytes();
        let approval = request.with_signature(signature);
        let approved = effect
            .approve(approval.clone(), &public, NOW)
            .expect("exact approved read");
        approved
            .validate_for_entry(&installed, NOW + 1)
            .expect("fresh recompile");
        assert!(approved.validate_for_entry(&installed, NOW + 30).is_err());
        assert!(
            approved.recovery_plan().is_err(),
            "content cannot borrow recovery admission"
        );
        assert!(
            approved.candidate_target().is_none(),
            "content cannot borrow candidate admission"
        );
        let next_call = target
            .authorization_call(
                &recipe,
                &LogicalOperationId::parse("content-2").expect("operation"),
            )
            .expect("call");
        let next_submission = submission_for_call(&root, &reader, &grant, &next_call, &[]);
        let next = compile_content_acquisition(
            &installed,
            &target,
            NOW,
            &next_submission.proof,
            &next_submission.action,
        )
        .expect("next native effect");
        let next_binding: Value =
            serde_json::from_slice(&next.binding().to_private_bytes().expect("binding"))
                .expect("JSON");
        assert_eq!(
            binding["reservations"], next_binding["reservations"],
            "new logical operation cannot change source lifetime capacity"
        );
        assert!(
            next.approve(approval, &public, NOW).is_err(),
            "old approval cannot authorize new operation"
        );
        let touched = connection
            .transition_state(ConnectionState::Disabled, NOW - 10)
            .expect("disable")
            .transition_state(ConnectionState::Active, NOW - 5)
            .expect("enable");
        let touched_target =
            ContentReadTarget::new(&recipe, &touched, arguments.clone()).expect("touched target");
        let touched_call = touched_target
            .authorization_call(
                &recipe,
                &LogicalOperationId::parse("content-after-admin").expect("operation"),
            )
            .expect("call");
        let touched_submission = submission_for_call(&root, &reader, &grant, &touched_call, &[]);
        let touched_installation = policy.installation(
            &recipe,
            &read_context,
            &touched,
            crate::QualificationPolicy::Optional,
            [12; 32],
        );
        assert!(
            approved
                .validate_for_entry(&touched_installation, NOW + 1)
                .is_err(),
            "changed installation cannot use old bound approval"
        );
        let touched_effect = compile_content_acquisition(
            &touched_installation,
            &touched_target,
            NOW,
            &touched_submission.proof,
            &touched_submission.action,
        )
        .expect("fresh native target");
        let touched_binding: Value = serde_json::from_slice(
            &touched_effect
                .binding()
                .to_private_bytes()
                .expect("binding"),
        )
        .expect("JSON");
        assert_eq!(
            binding["reservations"], touched_binding["reservations"],
            "administrative state/time changes cannot reset source allowance"
        );
        assert_ne!(
            binding["connection"], touched_binding["connection"],
            "binding still pins full live connection"
        );
        let mut different_resource = arguments.clone();
        different_resource.insert("record_id".to_owned(), json!("recDIFFERENT000001"));
        let different_target = ContentReadTarget::new(&recipe, &connection, different_resource)
            .expect("different resource");
        assert!(
            compile_content_acquisition(
                &installed,
                &different_target,
                NOW,
                &submission.proof,
                &submission.action
            )
            .is_err()
        );
        let mut wrong_args = call.arguments().clone();
        wrong_args.insert("maximum_response_bytes".to_owned(), json!(1025));
        let wrong_call =
            McpToolCall::new(call.service(), CONTENT_READ_TOOL, wrong_args).expect("call");
        let changed = submission_for_call(&root, &reader, &grant, &wrong_call, &[]);
        assert!(
            compile_content_acquisition(&installed, &target, NOW, &changed.proof, &changed.action)
                .is_err()
        );
        let mut extra = arguments.clone();
        extra.insert("url".to_owned(), json!("https://untrusted.invalid/"));
        assert!(recipe.content_read(&extra).is_err());
        assert!(recipe.content_read(&Map::new()).is_err());
        assert!(
            compile_mutation_effect(&installed, NOW, &submission.proof, &submission.action)
                .is_err()
        );
        projection_cases.push(projections(
            &recipe,
            &arguments,
            projection["kind"] == "json-string",
        ));
        cases.push(json!({"projection": projection, "binding": binding, "native_call": call.arguments(),
            "review": serde_json::from_slice::<Value>(&review.to_private_bytes().expect("private review")).expect("JSON"),
            "fresh_recompile_passed": true, "expired_approval_refused": true,
            "new_operation_preserves_capacity": true, "administrative_metadata_preserves_capacity": true,
            "changed_installation_and_resource_refused": true, "old_approval_new_operation_refused": true,
            "changed_limit_extra_arguments_mutation_refused": true}));
    }
    let (source, lock) = h::recipe_sources(&json!({}), &Value::Null).expect("source/lock");
    let mut source: Value = serde_json::from_slice(&source).expect("source");
    let mut lock: Value = serde_json::from_slice(&lock).expect("lock");
    source["tool"] = json!(CONTENT_READ_TOOL);
    lock["tool"] = json!(CONTENT_READ_TOOL);
    assert!(
        CompiledRecipe::compile(
            &serde_json::to_vec(&source).expect("source"),
            &serde_json::to_vec(&lock).expect("lock")
        )
        .is_err()
    );
    let no_content = recipe(&json!({}), &Value::Null);
    assert!(no_content.content_read(&arguments).is_err());
    let fixture = json!({"schema": "auths.gateway-content-compilation-fixture/1",
        "scope": "native compilation and pure bounded projection; no acquisition entry, custody or disclosure",
        "cases": cases, "projections": projection_cases, "invalid_declarations": invalid_declarations(),
        "undeclared_content_read_refused": true});
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/content-compilation.json");
    let bytes = serde_json::to_vec_pretty(&fixture).expect("fixture");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("fixture");
    }
    assert_eq!(std::fs::read(&path).expect("fixture"), bytes);
}
