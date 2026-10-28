//! Native content compilation and durable acquisition corpora. Transport
//! evidence is scoped to the journal fixture; neither corpus claims disclosure.
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

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one installed native admission/entry and bounded HTTP evidence corpus"
)]
async fn native_content_journal_fixture_is_current() {
    use auths_connections::{ConnectionCredentialStore as _, SecretBytes};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    let root = signer(h::ROOT_SEED);
    let reader = signer(0x33);
    let observer = signer(h::OBSERVER_SEED);
    let approval_key = SigningKey::from_bytes(&[29; 32]);
    let public = approval_key.verifying_key().to_bytes();
    let policy =
        EffectPolicy::new("synthetic-content-journal".to_owned(), 1, public).expect("policy");
    let (source, lock) = h::recipe_sources(&json!({}), &Value::Null).expect("source");
    let mut source: Value = serde_json::from_slice(&source).expect("source JSON");
    source["content"] = declaration(json!({"kind": "utf8"}));
    source["provider_headers"] = json!({"Stripe-Version": "2024-06-20"});
    let recipe =
        CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source bytes"), &lock)
            .expect("recipe");
    let initial = connection(&recipe);
    let credentials = auths_connections::InMemoryCredentialStore::new(1, 1024).expect("custody");
    let reference = credentials
        .install(
            initial.connection_id(),
            initial.credential_generation(),
            SecretBytes::new(b"SYNTHETIC-CONTENT-TEST-CREDENTIAL".to_vec()).expect("secret"),
        )
        .await
        .expect("install");
    let record = ConnectionRecord::new(
        initial.provider_kind().clone(),
        initial.alias().clone(),
        initial.connection_id().clone(),
        initial.contract().clone(),
        initial.descriptor_schema().clone(),
        initial.descriptor().to_vec(),
        *initial.account_commitment(),
        *reference.as_bytes(),
        initial.generation(),
        initial.state(),
        initial.allowed_workloads().to_vec(),
        initial.allowed_profiles().to_vec(),
        initial.created_at_unix_seconds(),
        initial.updated_at_unix_seconds(),
        None,
    )
    .expect("record");
    let args = json!({"record_id": RECORD})
        .as_object()
        .expect("args")
        .clone();
    let target = ContentReadTarget::new(&recipe, &record, args).expect("target");
    let call = target
        .authorization_call(
            &recipe,
            &LogicalOperationId::parse("content-journal-0").expect("op"),
        )
        .expect("call");
    let trust = h::context_for_tool(&root, &observer.principal, NOW, &call).expect("trust");
    let grant = h::grant_for_tool(
        &root,
        &reader.principal,
        None,
        window(NOW - 3600, NOW + 3600),
        &call,
    )
    .expect("grant");
    let installed = policy.installation(
        &recipe,
        &trust,
        &record,
        crate::QualificationPolicy::Optional,
        [12; 32],
    );
    let approve = |operation: &str| {
        let call = target
            .authorization_call(&recipe, &LogicalOperationId::parse(operation).expect("op"))
            .expect("call");
        let signed = submission_for_call(&root, &reader, &grant, &call, &[]);
        let effect =
            compile_content_acquisition(&installed, &target, NOW, &signed.proof, &signed.action)
                .expect("effect");
        let request = effect.approval_request(NOW, NOW + 60).expect("request");
        let signature = approval_key
            .sign(&request.signing_message().expect("message"))
            .to_bytes();
        Arc::new(
            effect
                .approve(request.with_signature(signature), &public, NOW)
                .expect("approval"),
        )
    };
    let directory = tempfile::tempdir().expect("directory");
    let path = std::fs::canonicalize(directory.path())
        .expect("path")
        .join("journal");
    let store: Arc<dyn crate::GatewayAttemptStore> =
        Arc::new(crate::FileGatewayAttemptStore::open(&path).expect("store"));
    let attempts =
        crate::GatewayAttempts::new(Arc::clone(&store), policy.clone()).expect("attempts");
    let shared = crate::SharedConnection::new(
        Arc::clone(&store),
        record.provider_kind().clone(),
        record.alias().clone(),
    );
    let clock = Arc::new(crate::FixedClock::at(NOW));
    let qualification = Arc::new(crate::QualificationGate::new(
        crate::QualificationPolicy::Optional,
        None,
        None,
        Box::new(Arc::clone(&clock)),
        auths_recipe_qualification::VerifierState::default(),
    ));
    let configuration = crate::configuration::SharedConfiguration::new(
        Arc::clone(&store),
        policy.configuration_key(recipe.namespace()).expect("key"),
        installed.configuration,
    );
    configuration
        .initialize(&qualification)
        .expect("configuration");
    let approved = approve("content-journal-0");
    assert!(
        attempts
            .claim_content(
                &approved,
                NOW,
                crate::entry::EntryValidation::Oracle { now: NOW }
            )
            .await
            .is_err(),
        "missing connection"
    );
    shared.insert(&record).await.expect("connection");
    let loaded = shared.load().await.expect("load").expect("connection");
    let validation = || {
        crate::entry::EntryValidation::Installed(Box::new(crate::entry::InstalledEntry {
            recipe: recipe.clone(),
            trust: trust.clone(),
            observer: None,
            policy: policy.clone(),
            configuration: configuration.clone(),
            connection: crate::entry::EntryConnection::Installed(Box::new(loaded.clone())),
            connection_key: crate::connection_key(record.provider_kind(), record.alias()),
            qualification: Arc::clone(&qualification),
            workload: record.allowed_workloads()[0].clone(),
            profile: record.allowed_profiles()[0].clone(),
            started: std::time::Instant::now(),
            #[cfg(unix)]
            commissioning: None,
        }))
    };
    assert!(
        attempts
            .claim_recovery(&approved, NOW, validation())
            .await
            .is_err()
    );
    assert!(
        attempts
            .claim_candidate(&approved, NOW, validation())
            .await
            .is_err()
    );
    let lease = credentials
        .lease_secret(
            &record.credential_binding(),
            std::time::Instant::now() + std::time::Duration::from_secs(30),
        )
        .await
        .expect("lease");
    let mut histories = vec![];
    let mut first_protected = Value::Null;
    let mut disclosures = Vec::new();
    for index in 0..17 {
        let approved = approve(&format!("content-journal-{index}"));
        let claim = attempts
            .claim_content(&approved, NOW, validation())
            .await
            .expect("claim");
        if index == 16 {
            let crate::AcquisitionClaim::Existing(snapshot) = claim else {
                panic!("source allowance exceeded");
            };
            assert_eq!(snapshot.stage, crate::AcquisitionStage::NotEntered);
            assert_eq!(snapshot.reserved_calls, 0);
            histories.push(json!({"case": "source-exhausted", "snapshot": snapshot}));
            continue;
        }
        let crate::AcquisitionClaim::Reserved(reserved) = claim else {
            panic!("reservation");
        };
        let crate::AcquisitionClaim::Reserved(stale) = attempts
            .claim_content(&approved, NOW, validation())
            .await
            .expect("resume")
        else {
            panic!("resume reservation");
        };
        let (granted, permit) = reserved
            .grant_entry(Arc::clone(&approved), validation(), NOW)
            .await
            .expect("native grant");
        assert!(
            stale
                .grant_entry(Arc::clone(&approved), validation(), NOW)
                .await
                .is_err(),
            "one grant only"
        );
        if index == 15 {
            drop(permit);
            let snapshot = granted.record_unknown().await.expect("unknown");
            assert_eq!(snapshot.reserved_calls, 1);
            assert_eq!(snapshot.reserved_bytes, 1024);
            histories.push(json!({"case": "lost-permit", "snapshot": snapshot}));
            continue;
        }
        let headers = match index {
            0 => "Content-Type: text/plain\r\n",
            1 => "Content-Type: text/plain\r\nContent-Encoding: gzip\r\n",
            2 => "Content-Type: text/plain\r\nContent-Type: application/json\r\n",
            3 => "",
            4 => {
                "Content-Type: text/plain\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\n"
            }
            5 => "Content-Type: application/json\r\n",
            6..=12 | 14 => "Content-Type: text/plain\r\n",
            13 => "Content-Type: text/plain\r\nContent-Encoding: identity\r\n",
            _ => unreachable!(),
        };
        let body = match index {
            6 => vec![b'x'; 1025],
            9 => vec![],
            10 => vec![b'x'; 64],
            11 => vec![b'x'; 65],
            12 => vec![255],
            _ => b"PRIVATE-SYNTHETIC-CONTENT".to_vec(),
        };
        let expected_body = body.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("port").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut head = vec![];
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).await.expect("request");
                head.push(byte[0]);
                assert!(head.len() < 8192);
            }
            let head = String::from_utf8(head).expect("head");
            assert!(head.starts_with(&format!(
                "GET /documents/{RECORD}?format=text%2Fplain HTTP/1.1\r\n"
            )));
            assert!(head.to_ascii_lowercase().contains("accept: text/plain\r\n"));
            assert!(
                head.to_ascii_lowercase()
                    .contains("accept-encoding: identity\r\n")
            );
            assert!(!head.to_ascii_lowercase().contains("idempotency-key"));
            let status = if index == 7 {
                "403 Forbidden"
            } else {
                "200 OK"
            };
            assert!(
                head.to_ascii_lowercase()
                    .contains("stripe-version: 2024-06-20\r\n")
            );
            let version = if index == 14 {
                ""
            } else {
                "Stripe-Version: 2024-06-20\r\n"
            };
            stream.write_all(format!("HTTP/1.1 {status}\r\n{headers}{version}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.expect("headers");
            stream.write_all(&body).await.expect("body");
        });
        let transport = crate::transport::GatewayHttpTransport::for_loopback_test(&recipe, port);
        let response = transport.acquire_content(permit, &lease).await;
        server.await.expect("server");
        let snapshot = match response {
            Some(response) => granted
                .record_content_response(response, NOW)
                .await
                .expect("retained"),
            None => granted.record_unknown().await.expect("unknown"),
        };
        assert_eq!(
            snapshot.stage,
            if index == 6 {
                crate::AcquisitionStage::Unknown
            } else {
                crate::AcquisitionStage::ResponseRecorded
            }
        );
        let key = crate::GatewayAttemptKey::for_operation(
            &policy,
            recipe.namespace(),
            &LogicalOperationId::parse(&format!("content-journal-{index}")).expect("op"),
        )
        .expect("key");
        let retained = store
            .load(crate::GatewayRecordKind::Attempt, &key)
            .expect("load")
            .expect("retained");
        let value: Value = serde_json::from_slice(&retained).expect("record JSON");
        let phase = &value["state"]["facts"]["phase"];
        let metadata = &phase["metadata"];
        if index != 6 {
            assert_eq!(phase["stage"], "content-response-recorded");
            let expected_media = match index {
                2 => json!({"kind": "invalid"}),
                3 => json!({"kind": "missing"}),
                5 => json!({"kind": "single", "value": "application/json"}),
                _ => json!({"kind": "single", "value": "text/plain"}),
            };
            let expected_encoding = match index {
                1 => json!({"kind": "single", "value": "gzip"}),
                4 => json!({"kind": "invalid"}),
                13 => json!({"kind": "single", "value": "identity"}),
                _ => json!({"kind": "missing"}),
            };
            assert_eq!(metadata["media_type"], expected_media);
            assert_eq!(metadata["encoding"], expected_encoding);
            assert_eq!(
                phase["response"]["body_b64"],
                base64ct::Base64::encode_string(&expected_body)
            );
            // Content cannot be decoded as ordinary credential evidence by
            // stripping the authenticated transport metadata variant.
            let mut downgraded = value.clone();
            let phase = downgraded["state"]["facts"]["phase"]
                .as_object_mut()
                .expect("phase");
            phase.insert("stage".to_owned(), json!("response-recorded"));
            phase.remove("metadata");
            phase.remove("content");
            let changed = serde_json_canonicalizer::to_vec(&downgraded).expect("corrupt bytes");
            store
                .replace(crate::GatewayRecordKind::Attempt, &key, &retained, &changed)
                .expect("inject corruption");
            assert!(attempts.read_acquisition(&approved).await.is_err());
            store
                .replace(crate::GatewayRecordKind::Attempt, &key, &changed, &retained)
                .expect("restore fixture");
        } else {
            assert_eq!(phase["stage"], "unknown");
        }
        let projection = serde_json::to_value(&snapshot.content_projection).expect("status");
        let expected_projection = match index {
            0 | 8 | 9 | 10 | 13 => json!({"kind": "ready", "bytes": expected_body.len()}),
            1 | 4 => json!({"kind": "rejected", "code": "gateway.content.response-encoding"}),
            2 | 3 | 5 => json!({"kind": "rejected", "code": "gateway.content.response-media-type"}),
            6 => Value::Null,
            7 => json!({"kind": "rejected", "code": "gateway.content.response-status"}),
            11 => json!({"kind": "rejected", "code": "gateway.content.content-too-large"}),
            12 => json!({"kind": "rejected", "code": "gateway.content.invalid-response"}),
            14 => json!({"kind": "rejected", "code": "gateway.content.response-version"}),
            _ => unreachable!(),
        };
        assert_eq!(projection, expected_projection);
        let retained_source = attempts
            .retained_content(
                recipe.namespace(),
                &LogicalOperationId::parse(&format!("content-journal-{index}")).expect("operation"),
            )
            .await;
        if matches!(index, 0 | 8 | 9 | 10 | 13) {
            let retained_source = retained_source.expect("validated source");
            assert_eq!(retained_source.bytes, expected_body.len() as u64);
            if matches!(index, 0 | 9) {
                disclosures.push(disclosure_compilation_cases(
                    retained_source,
                    &recipe,
                    &record,
                    &policy,
                    &approval_key,
                ));
            }
        } else {
            assert!(retained_source.is_err(), "rejected/unknown source {index}");
        }
        if index == 0 {
            first_protected = phase["content"].clone();
            for pointer in [
                "/schema",
                "/state/facts/phase/content/value/key/0",
                "/state/facts/phase/content/value/commitment/0",
                "/state/facts/phase/content/value/bytes",
                "/state/facts/phase/content/value/schema",
                "/state/facts/phase/response/body_b64",
                "/state/facts/phase/response/version_ok",
                "/state/facts/phase/metadata/media_type/value",
            ] {
                let mut changed = value.clone();
                let cell = changed.pointer_mut(pointer).expect("field");
                *cell = match pointer {
                    "/schema" => json!("auths.gateway-attempt/12"),
                    "/state/facts/phase/content/value/schema" => {
                        json!("auths.gateway-protected-content/0")
                    }
                    "/state/facts/phase/response/body_b64" => {
                        json!(base64ct::Base64::encode_string(b"CHANGED-PRIVATE-CONTENT"))
                    }
                    "/state/facts/phase/response/version_ok" => json!(false),
                    "/state/facts/phase/metadata/media_type/value" => json!("application/json"),
                    _ => json!(cell.as_u64().expect("number") ^ 1),
                };
                let bytes = serde_json_canonicalizer::to_vec(&changed).expect("changed bytes");
                store
                    .replace(crate::GatewayRecordKind::Attempt, &key, &retained, &bytes)
                    .expect("inject");
                assert!(
                    attempts.read_acquisition(&approved).await.is_err(),
                    "{pointer}"
                );
                store
                    .replace(crate::GatewayRecordKind::Attempt, &key, &bytes, &retained)
                    .expect("restore");
            }
        }
        if index == 8 {
            assert_ne!(
                phase["content"]["value"]["key"],
                first_protected["value"]["key"]
            );
            assert_ne!(
                phase["content"]["value"]["commitment"],
                first_protected["value"]["commitment"]
            );
            let mut changed = value.clone();
            changed["state"]["facts"]["phase"]["content"] = first_protected.clone();
            let bytes = serde_json_canonicalizer::to_vec(&changed).expect("changed bytes");
            store
                .replace(crate::GatewayRecordKind::Attempt, &key, &retained, &bytes)
                .expect("substitute source");
            assert!(
                attempts.read_acquisition(&approved).await.is_err(),
                "same bytes from another source do not satisfy this commitment"
            );
            store
                .replace(crate::GatewayRecordKind::Attempt, &key, &bytes, &retained)
                .expect("restore");
        }
        let retained_text = String::from_utf8(retained.clone()).expect("JSON");
        assert!(!retained_text.contains("SYNTHETIC-CONTENT-TEST-CREDENTIAL"));
        let reopened = crate::GatewayAttempts::new(
            Arc::new(crate::FileGatewayAttemptStore::open(&path).expect("reopen")),
            policy.clone(),
        )
        .expect("attempts");
        let crate::AcquisitionClaim::Existing(replay) = reopened
            .claim_content(&approved, NOW, validation())
            .await
            .expect("replay")
        else {
            panic!("no fresh permit");
        };
        assert_eq!(snapshot, replay);
        assert_eq!(
            store
                .load(crate::GatewayRecordKind::Attempt, &key)
                .expect("reload")
                .expect("record"),
            retained
        );
        let public_json = serde_json::to_string(&snapshot).expect("public");
        assert!(!public_json.contains("PRIVATE-SYNTHETIC-CONTENT"));
        assert!(!public_json.contains("commitment"));
        assert!(!public_json.contains("key"));
        histories.push(
            json!({"case": index, "snapshot": snapshot, "private_response_metadata": metadata}),
        );
    }
    // A different current connection cannot satisfy this retained source;
    // changing administrative metadata leaves capacity keys unchanged.
    let changed = record
        .transition_state(ConnectionState::Disabled, NOW - 10)
        .expect("disable");
    let plan = approved.content_plan().expect("content plan");
    assert!(
        !plan
            .source_matches(Some(&changed.to_canonical_cbor().expect("bytes")))
            .expect("source match")
            .0
    );
    let fixture = json!({"schema": "auths.gateway-content-journal-fixture/3",
        "scope": "native signed compilation, installed file admission/entry, real bounded HTTP, reopened journal replay; no disclosure or process/PostgreSQL qualification",
        "permanent_source_attempts": 16, "real_http_requests": 15,
        "protected_content_mutations_refused": true, "same_content_foreign_source_refused": true,
        "history": histories, "disclosure_compilation": disclosures});
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/content-journal.json");
    let bytes = serde_json::to_vec_pretty(&fixture).expect("fixture");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("fixture");
    }
    assert_eq!(std::fs::read(&path).expect("fixture"), bytes);
}

/// The source was loaded from a validated, real-HTTP content journal above.
/// All values written to the fixture are public case results, never private
/// content, MACs, source correlations, signed proof bytes or review material.
#[allow(
    clippy::too_many_lines,
    reason = "one native disclosure compilation corpus over validated retained content"
)]
fn disclosure_compilation_cases(
    retained: crate::RetainedContent,
    recipe: &CompiledRecipe,
    connection: &ConnectionRecord,
    policy: &EffectPolicy,
    approval_key: &SigningKey,
) -> Value {
    use crate::effect::{DisclosureTarget, compile_disclosure};
    let root = signer(h::ROOT_SEED);
    let observer = signer(h::OBSERVER_SEED);
    let releaser = signer(0x44);
    let recipient = SigningKey::from_bytes(&[51; 32]);
    let recipient_key = recipient.verifying_key().to_bytes();
    let target = DisclosureTarget::new(retained.clone(), recipient_key, [20; 32], [21; 32])
        .expect("delivery target");
    assert_eq!(
        format!("{retained:?}"),
        "RetainedContent { private: [redacted] }"
    );
    assert_eq!(
        format!("{target:?}"),
        "DisclosureTarget { private: [redacted] }"
    );
    let operation = LogicalOperationId::parse("disclosure-1").expect("operation");
    let call = target
        .authorization_call(recipe, &operation)
        .expect("release call");
    let trust = h::context_for_tool(&root, &observer.principal, NOW, &call).expect("release trust");
    let grant = h::grant_for_tool(
        &root,
        &releaser.principal,
        None,
        window(NOW - 3600, NOW + 3600),
        &call,
    )
    .expect("release grant");
    let signed = submission_for_call(&root, &releaser, &grant, &call, &[]);
    let installed = policy.installation(
        recipe,
        &trust,
        connection,
        crate::QualificationPolicy::Optional,
        [12; 32],
    );
    let limit = retained.bytes.max(1);
    let budget = crate::ArgumentCeilingPolicy::new("maximum_disclosure_bytes", limit, 3600, 2)
        .expect("budget")
        .with_sum(limit * 2, None)
        .expect("byte budget");
    let budget_grant = super::read_budget_tests::read_grant(&root, &releaser, &call, &budget);
    let budget_signed = submission_for_call(&root, &releaser, &budget_grant, &call, &[]);
    let budget_effect = compile_disclosure(
        &installed,
        &target,
        NOW,
        &budget_signed.proof,
        &budget_signed.action,
    )
    .expect("budget effect");
    let budget_wire: Value = serde_json::from_slice(
        &budget_effect
            .binding()
            .to_private_bytes()
            .expect("budget bytes"),
    )
    .expect("budget JSON");
    let fixed: Vec<_> = budget_wire["reservations"]
        .as_array()
        .expect("reservations")
        .iter()
        .filter(|r| r["window"]["kind"] == "fixed")
        .collect();
    assert_eq!(fixed.len(), 2);
    assert!(
        fixed
            .iter()
            .any(|r| r["unit"] == "disclosure-count" && r["amount"] == 1 && r["ceiling"] == 2)
    );
    assert!(fixed.iter().any(|r| r["unit"] == "disclosure-bytes"
        && r["amount"] == retained.bytes
        && r["ceiling"] == limit * 2));
    let wrong_budget = crate::ArgumentCeilingPolicy::new("maximum_response_bytes", limit, 3600, 2)
        .expect("wrong budget");
    let wrong_grant = super::read_budget_tests::read_grant(&root, &releaser, &call, &wrong_budget);
    let wrong_signed = submission_for_call(&root, &releaser, &wrong_grant, &call, &[]);
    assert!(
        compile_disclosure(
            &installed,
            &target,
            NOW,
            &wrong_signed.proof,
            &wrong_signed.action
        )
        .is_err()
    );
    let bound = compile_disclosure(&installed, &target, NOW, &signed.proof, &signed.action)
        .expect("native release");
    assert!(bound.private_request().is_none());
    let bytes = bound.binding().to_private_bytes().expect("binding");
    let binding: Value = serde_json::from_slice(&bytes).expect("binding JSON");
    assert_eq!(binding["protocol"]["maximum_bytes"], retained.bytes);
    assert_eq!(
        binding["protocol"]["source_effect"],
        json!(retained.source.id().as_bytes())
    );
    let reservations = binding["reservations"].as_array().expect("reservations");
    assert_eq!(reservations.len(), 2);
    assert!(
        reservations
            .iter()
            .any(|r| r["unit"] == "disclosure-count" && r["amount"] == 1 && r["ceiling"] == 16)
    );
    assert!(
        reservations
            .iter()
            .any(|r| r["unit"] == "disclosure-bytes" && r["amount"] == retained.bytes)
    );
    let review = bound
        .private_review()
        .expect("review")
        .render_literal(crate::effect::LITERAL_REVIEW_RENDERER)
        .expect("render");

    assert!(review.contains("maximum_disclosure_bytes"));
    assert!(review.contains("delivery_instance"));
    assert!(review.contains("resource_arguments"));
    assert!(review.contains(RECORD));
    assert!(review.contains("projection"));
    assert!(!review.contains("PRIVATE-SYNTHETIC-CONTENT"));
    let request = bound
        .approval_request(NOW, NOW + 60)
        .expect("approval request");
    let approval = request.clone().with_signature(
        approval_key
            .sign(&request.signing_message().expect("message"))
            .to_bytes(),
    );
    let approved = bound
        .approve(
            approval.clone(),
            &approval_key.verifying_key().to_bytes(),
            NOW,
        )
        .expect("exact approval");
    approved
        .validate_for_entry(&installed, NOW)
        .expect("fresh full recompile");
    assert!(approved.validate_for_entry(&installed, NOW + 61).is_err());
    assert!(approved.command().is_none());
    assert!(approved.content_target().is_none());
    assert!(approved.recovery_target().is_none());
    assert!(approved.prerequisite_plans().expect("no reads").is_empty());
    assert!(approved.content_plan().is_err());
    assert!(approved.recovery_plan().is_err());
    let ack_request = crate::effect::DisclosureAcknowledgementRequest::for_delivery(
        approved.effect().binding(),
        retained.bytes,
        recipient_key,
    )
    .expect("ACK statement");
    let ack = ack_request.clone().with_signature(
        recipient
            .sign(&ack_request.signing_message().expect("message"))
            .to_bytes(),
    );
    assert!(
        ack.verify(approved.effect().binding(), retained.bytes)
            .is_ok()
    );
    assert!(
        ack.verify(approved.effect().binding(), retained.bytes + 1)
            .is_err()
    );
    let mut refused = Vec::new();
    for (name, changed) in [
        (
            "channel",
            DisclosureTarget::new(retained.clone(), recipient_key, [22; 32], [21; 32])
                .expect("target"),
        ),
        (
            "instance",
            DisclosureTarget::new(retained.clone(), recipient_key, [20; 32], [22; 32])
                .expect("target"),
        ),
        (
            "recipient",
            DisclosureTarget::new(
                retained.clone(),
                SigningKey::from_bytes(&[52; 32]).verifying_key().to_bytes(),
                [20; 32],
                [21; 32],
            )
            .expect("target"),
        ),
    ] {
        assert!(
            compile_disclosure(&installed, &changed, NOW, &signed.proof, &signed.action).is_err()
        );
        let changed_call = changed
            .authorization_call(recipe, &operation)
            .expect("call");
        let changed_signed = submission_for_call(&root, &releaser, &grant, &changed_call, &[]);
        let changed_bound = compile_disclosure(
            &installed,
            &changed,
            NOW,
            &changed_signed.proof,
            &changed_signed.action,
        )
        .expect("new native action");
        assert_ne!(
            changed_bound.binding().id(),
            approved.effect().binding().id()
        );
        assert!(ack.verify(changed_bound.binding(), retained.bytes).is_err());
        assert!(
            changed_bound
                .approve(
                    approval.clone(),
                    &approval_key.verifying_key().to_bytes(),
                    NOW
                )
                .is_err()
        );
        refused.push(name);
    }
    let new_call = target
        .authorization_call(
            recipe,
            &LogicalOperationId::parse("disclosure-2").expect("operation"),
        )
        .expect("call");
    let new_signed = submission_for_call(&root, &releaser, &grant, &new_call, &[]);
    let new_bound = compile_disclosure(
        &installed,
        &target,
        NOW,
        &new_signed.proof,
        &new_signed.action,
    )
    .expect("new effect");
    let new_bytes = new_bound.binding().to_private_bytes().expect("binding");
    let new_binding: Value = serde_json::from_slice(&new_bytes).expect("JSON");
    assert_eq!(new_binding["reservations"], binding["reservations"]);
    assert!(
        new_bound
            .approve(approval, &approval_key.verifying_key().to_bytes(), NOW)
            .is_err()
    );
    let wrong_partition = EffectPolicy::new(
        "different-partition".to_owned(),
        1,
        approval_key.verifying_key().to_bytes(),
    )
    .expect("policy");
    let wrong_install = wrong_partition.installation(
        recipe,
        &trust,
        connection,
        crate::QualificationPolicy::Optional,
        [12; 32],
    );
    assert!(
        compile_disclosure(&wrong_install, &target, NOW, &signed.proof, &signed.action).is_err()
    );
    let read = ContentReadTarget::new(
        recipe,
        connection,
        json!({"record_id": RECORD})
            .as_object()
            .expect("args")
            .clone(),
    )
    .expect("read");
    let read_call = read
        .authorization_call(recipe, &operation)
        .expect("read call");
    let read_grant = h::grant_for_tool(
        &root,
        &releaser.principal,
        None,
        window(NOW - 3600, NOW + 3600),
        &read_call,
    )
    .expect("read grant");
    let read_signed = submission_for_call(&root, &releaser, &read_grant, &read_call, &[]);
    assert!(
        compile_disclosure(
            &installed,
            &target,
            NOW,
            &read_signed.proof,
            &read_signed.action
        )
        .is_err()
    );
    json!({"bytes": retained.bytes, "native_release_compiled": true,
        "read_authority_refused": true, "no_provider_prerequisites": true,
        "managed_disclosure_count_and_bytes": true, "acquisition_budget_argument_refused": true,
        "substitutions_refused": refused, "different_partition_refused": true,
        "new_operation_retains_capacity_keys": true, "old_approval_refused": true,
        "exact_ack_validates": true, "scope": "compilation and evidence only; no delivery grant or transport"})
}
