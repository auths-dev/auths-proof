use super::*;
use crate::{FileGatewayAttemptStore, GatewayAttemptError, GatewayAttemptStage};
use serde_json::json;
use std::sync::Arc;
use url::form_urlencoded;

fn fixture(name: &str) -> (&'static [u8], &'static [u8]) {
    match name {
        "airtable" => (
            include_bytes!("../../../../../bindings/fixtures/gateway/airtable/recipe.json"),
            include_bytes!("../../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
        ),
        "todoist" => (
            include_bytes!("../../../../../bindings/fixtures/gateway/todoist/recipe.json"),
            include_bytes!("../../../../../bindings/fixtures/gateway/todoist/profile.lock.json"),
        ),
        "github" => (
            include_bytes!("../../../../../bindings/fixtures/gateway/github/recipe.json"),
            include_bytes!("../../../../../bindings/fixtures/gateway/github/profile.lock.json"),
        ),
        _ => panic!("unknown test-only fixture"),
    }
}

fn compiled(name: &str) -> CompiledRecipe {
    let (recipe, lock) = fixture(name);
    CompiledRecipe::compile(recipe, lock).expect("canonical fixture compiles")
}

fn arguments(recipe: &CompiledRecipe, values: &Value) -> Map<String, Value> {
    let mut object = values.as_object().expect("object fixture").clone();
    object.insert(
        "operator_namespace".into(),
        Value::String(recipe.namespace().as_str().to_owned()),
    );
    object.insert("recipe_digest".into(), Value::String(recipe.digest_hex()));
    object
}

#[test]
fn three_independent_recipes_compile_without_provider_code() {
    for name in ["airtable", "todoist", "github"] {
        let recipe = compiled(name);
        assert!(recipe.review().origin().starts_with("https://"));
        assert_eq!(recipe.digest_hex().len(), 64);
        assert_eq!(recipe.review().maximum_body_bytes(), MAX_BODY_BYTES);
    }
}

#[test]
fn hostile_recipe_corpus_fails_with_exact_codes() {
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../../../bindings/fixtures/gateway/hostile-recipes.json"
    ))
    .expect("valid corpus");
    assert_eq!(
        corpus.get("schema").and_then(Value::as_str),
        Some("auths.gateway-hostile-recipes/1")
    );
    for case in corpus["cases"].as_array().expect("cases") {
        let base = case["base"].as_str().expect("base");
        let pointer = case["pointer"].as_str().expect("pointer");
        let expected = case["code"].as_str().expect("code");
        let (source, lock) = fixture(base);
        let mut mutated: Value = serde_json::from_slice(source).expect("recipe JSON");
        let value = case["value"].clone();
        if pointer.ends_with("/items/1") {
            mutated
                .pointer_mut("/write/body/fields/commands/value/items")
                .and_then(Value::as_array_mut)
                .expect("array")
                .push(value);
        } else if let Some(existing) = mutated.pointer_mut(pointer) {
            *existing = value;
        } else {
            let (parent, key) = pointer.rsplit_once('/').expect("child pointer");
            mutated
                .pointer_mut(parent)
                .and_then(Value::as_object_mut)
                .expect("existing parent object")
                .insert(key.to_owned(), value);
        }
        let bytes = serde_json::to_vec(&mutated).expect("fixture JSON");
        let result = CompiledRecipe::compile(&bytes, lock).expect_err("hostile recipe");
        assert_eq!(result.code(), expected, "{}", case["id"]);
    }
}

/// Compiles the Airtable fixture with `extra` profile fields and an
/// optional precondition block, recomputing the lock digest.
fn with_preconditions(
    extra: &Value,
    preconditions: Option<Value>,
    without_observation: bool,
) -> Result<CompiledRecipe, GatewayRecipeError> {
    let (source, lock) = fixture("airtable");
    let mut lock: Value = serde_json::from_slice(lock).expect("lock");
    for (key, value) in extra.as_object().expect("extra") {
        lock["command_schema"]["fields"][key] = value.clone();
    }
    let digest = hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&lock["command_schema"]).expect("schema"),
    ));
    lock["schema_digest"] = Value::String(digest.clone());
    let mut source: Value = serde_json::from_slice(source).expect("source");
    source["profile_schema_digest"] = Value::String(digest);
    if let Some(preconditions) = preconditions {
        source["preconditions"] = preconditions;
    }
    if without_observation {
        let object = source.as_object_mut().expect("object");
        object.remove("observation");
        object.remove("echo");
    }
    CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("source"),
        &serde_json::to_vec(&lock).expect("lock"),
    )
}

fn precondition_fields() -> Value {
    json!({
        "expected": {"type": "enum", "variants": ["Approved", "Pending"]},
        "record_uri": {"kind": "string", "minimum": 1, "maximum": 256},
        "count": {"kind": "integer", "minimum": 0, "maximum": 10},
        "signed": {"kind": "integer", "minimum": -1, "maximum": 10},
        "flag": {"kind": "boolean"},
        "long": {"kind": "string", "minimum": 1, "maximum": 257}
    })
}

#[test]
fn preconditions_are_closed_reviewed_and_digest_bound() {
    let extra = precondition_fields();
    let all = json!({
        "read_back_subject": "record_uri",
        "verified": ["expected", "count", "signed", "flag", "long"]
    });
    assert_eq!(
        with_preconditions(&extra, Some(all), false).err(),
        Some(GatewayRecipeError::PreconditionConflict),
        "signed integers, booleans, and over-bound strings have no fact form"
    );
    let unused = json!({"expected": extra["expected"], "record_uri": extra["record_uri"]});
    let good = json!({"read_back_subject": "record_uri", "verified": ["expected"]});
    let recipe = with_preconditions(&unused, Some(good.clone()), false).expect("compiles");
    assert_ne!(recipe.digest(), compiled("airtable").digest());
    let review = recipe.review();
    let preconditions = review.preconditions().expect("reviewed");
    assert_eq!(preconditions.read_back_subject(), Some("record_uri"));
    assert_eq!(preconditions.verified(), ["expected"]);
    assert!(
        preconditions
            .disclosure()
            .contains("never sent to the provider")
    );
    assert!(compiled("airtable").review().preconditions().is_none());
    assert_eq!(
        with_preconditions(&unused, None, false).err(),
        Some(GatewayRecipeError::UnsafeTemplate),
        "an argument no request uses still needs an explicit declaration"
    );
    assert_eq!(
        with_preconditions(&unused, Some(good), true).err(),
        Some(GatewayRecipeError::PreconditionWithoutObservation)
    );
    for (hostile, code) in [
        (json!({}), GatewayRecipeError::InvalidSource),
        (
            json!({"verified": ["expected"], "extra": 1}),
            GatewayRecipeError::InvalidSource,
        ),
        (
            json!({"read_back_subject": "record_uri", "verified": ["replacement", "expected"]}),
            GatewayRecipeError::PreconditionConflict,
        ),
        (
            json!({"read_back_subject": "record_uri", "verified": ["expected", "operation_id"]}),
            GatewayRecipeError::PreconditionConflict,
        ),
        (
            json!({"read_back_subject": "record_uri", "verified": ["expected", "expected"]}),
            GatewayRecipeError::PreconditionConflict,
        ),
        (
            json!({"read_back_subject": "expected", "verified": ["record_uri"]}),
            GatewayRecipeError::PreconditionConflict,
        ),
        (
            json!({"read_back_subject": "record_uri", "verified": ["expected", "record_uri"]}),
            GatewayRecipeError::PreconditionConflict,
        ),
    ] {
        assert_eq!(
            with_preconditions(&unused, Some(hostile.clone()), false).err(),
            Some(code),
            "{hostile}"
        );
    }
    let many: Value = (0..9)
        .map(|index| {
            (
                format!("v{index}"),
                json!({"type": "enum", "variants": ["a"]}),
            )
        })
        .collect::<Map<_, _>>()
        .into();
    let names: Vec<String> = (0..9).map(|index| format!("v{index}")).collect();
    assert_eq!(
        with_preconditions(&many, Some(json!({"verified": names})), false).err(),
        Some(GatewayRecipeError::PreconditionConflict)
    );
}

#[test]
fn read_back_subject_must_name_exactly_the_observed_record() {
    let extra = json!({
        "expected": {"type": "enum", "variants": ["Approved", "Pending"]},
        "record_uri": {"kind": "string", "minimum": 1, "maximum": 256}
    });
    let recipe = with_preconditions(
        &extra,
        Some(json!({"read_back_subject": "record_uri", "verified": ["expected"]})),
        false,
    )
    .expect("recipe");
    let subject = "https://api.airtable.com/v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001#/fields/DemoStatus";
    let request = |uri: &str| {
        recipe.closed_request_from_arguments(
            &arguments(
                &recipe,
                &json!({"operation_id": "run-1", "record_id": "recTEST0000000001",
                    "replacement": "Approved", "expected": "Pending", "record_uri": uri}),
            ),
            [1; 32],
        )
    };
    let closed = request(subject).expect("matching subject");
    assert_eq!(
        closed.observation().expect("observation").subject(),
        subject
    );
    assert!(!String::from_utf8_lossy(closed.body()).contains("Pending"));
    for hostile in [
        subject.replace("0001#", "0002#"),
        subject.replace("DemoStatus", "Other"),
        subject.trim_end_matches("#/fields/DemoStatus").to_owned(),
    ] {
        assert_eq!(
            request(&hostile).err(),
            Some(GatewayRecipeError::PreconditionSubjectMismatch)
        );
    }
}

#[test]
fn read_back_target_takes_exactly_the_observation_path_fields() {
    let recipe = compiled("airtable");
    let target = |value: Value| recipe.read_back_target(value.as_object().expect("object"));
    let closed = target(json!({"record_id": "recTEST0000000001"})).expect("target");
    assert_eq!(
        closed.url(),
        "https://api.airtable.com/v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001"
    );
    assert_eq!(closed.expected(), &Value::Null);
    assert_eq!(
        closed.observed_values(br#"{"fields":{"DemoStatus":"Pending","auths_echo":null}}"#),
        Some((json!("Pending"), None))
    );
    assert_eq!(closed.observed_values(br#"{"fields":{}}"#), None);
    for hostile in [
        json!({}),
        json!({"record_id": "short"}),
        json!({"record_id": "recTEST0000000001", "replacement": "Approved"}),
        json!({"url": "https://attacker.example"}),
    ] {
        assert_eq!(
            target(hostile).err(),
            Some(GatewayRecipeError::ActionMismatch)
        );
    }
    assert!(
        compiled("github").read_back_target(&Map::new()).is_err(),
        "a recipe without an observation has no read-back"
    );
}

#[test]
fn airtable_closed_request_uses_only_bound_values() {
    let recipe = compiled("airtable");
    let arguments = arguments(
        &recipe,
        &json!({
            "operation_id": "run-123",
            "record_id": "recTEST0000000001",
            "replacement": "Approved"
        }),
    );
    let request = recipe
        .closed_request_from_arguments(&arguments, [5; 32])
        .expect("closed request");
    assert_eq!(request.method(), WriteMethod::Patch);
    assert_eq!(
        request.url(),
        "https://api.airtable.com/v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001"
    );
    let token = echo_token(
        recipe.namespace(),
        &LogicalOperationId::parse("run-123").expect("operation"),
        &[5; 32],
    );
    assert_eq!(request.echo_token(), Some(token.as_str()));
    assert_eq!(
        request.body(),
        format!(r#"{{"fields":{{"DemoStatus":"Approved","auths_echo":"{token}"}}}}"#).as_bytes()
    );
    let observation = request.observation().expect("read-back declared");
    assert_eq!(observation.json_pointer(), "/fields/DemoStatus");
    assert_eq!(observation.expected(), "Approved");
    assert_eq!(observation.echo_pointer(), Some("/fields/auths_echo"));
}

#[test]
fn echo_token_is_domain_separated_and_bound_to_every_input() {
    let namespace = OperatorNamespace::parse("airtable-demo").expect("namespace");
    let operation = LogicalOperationId::parse("run-1").expect("operation");
    let token = echo_token(&namespace, &operation, &[1; 32]);
    let mut preimage = b"auths.gateway-echo/1\0airtable-demo\0run-1\0".to_vec();
    preimage.extend_from_slice(&[1; 32]);
    assert_eq!(
        token,
        format!("auths-e1-{}", hex::encode(Sha256::digest(&preimage)))
    );
    assert_eq!(token.len(), 73);
    assert_ne!(token, echo_token(&namespace, &operation, &[2; 32]));
    assert_ne!(
        token,
        echo_token(
            &namespace,
            &LogicalOperationId::parse("run-2").expect("operation"),
            &[1; 32]
        )
    );
    assert_ne!(
        token,
        echo_token(
            &OperatorNamespace::parse("other").expect("namespace"),
            &operation,
            &[1; 32]
        )
    );
}

#[test]
fn idempotency_key_is_domain_separated_and_bound_to_namespace_and_operation() {
    let namespace = |value| OperatorNamespace::parse(value).expect("namespace");
    let operation = |value| LogicalOperationId::parse(value).expect("operation");
    let key = idempotency_key(&namespace("stripe-refunds"), &operation("refund-1"));
    assert_eq!(
        key,
        format!(
            "auths-i1-{}",
            hex::encode(Sha256::digest(
                b"auths.gateway-idempotency-key/1\0stripe-refunds\0refund-1"
            ))
        )
    );
    assert_eq!(key.len(), 73);
    assert_eq!(
        key,
        idempotency_key(&namespace("stripe-refunds"), &operation("refund-1")),
        "deterministic"
    );
    assert_ne!(
        key,
        idempotency_key(&namespace("stripe-refunds"), &operation("refund-2"))
    );
    assert_ne!(
        key,
        idempotency_key(&namespace("other"), &operation("refund-1"))
    );
    assert_ne!(
        idempotency_key(&namespace("ab"), &operation("c")),
        idempotency_key(&namespace("a"), &operation("bc")),
        "the separator keeps the two fields apart"
    );
    let replay = crate::GatewayAttemptKey::for_operation(
        &namespace("stripe-refunds"),
        &operation("refund-1"),
    );
    assert_ne!(key[9..], hex::encode(replay.as_bytes()), "own hash domain");
}

/// Compiles fixture `name` with `write.idempotency_key` set to `value`.
fn with_idempotency(name: &str, value: Value) -> Result<CompiledRecipe, GatewayRecipeError> {
    let (source, lock) = fixture(name);
    let mut source: Value = serde_json::from_slice(source).expect("source");
    source["write"]["idempotency"] = value;
    CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source"), lock)
}

fn derived_header() -> Value {
    json!({"kind": "derived-header", "retention_seconds": 86_400})
}

#[test]
fn idempotency_is_opt_in_reviewed_and_digest_bound() {
    for name in ["airtable", "todoist", "github"] {
        let (source, _) = fixture(name);
        let plain = compiled(name);
        let mut preimage = DIGEST_DOMAIN.to_vec();
        preimage.extend(
            serde_json_canonicalizer::to_vec(
                &serde_json::from_slice::<Value>(source).expect("source"),
            )
            .expect("canonical source"),
        );
        assert_eq!(
            plain.digest_hex(),
            hex::encode(Sha256::digest(&preimage)),
            "{name}: an undeclared mechanism adds nothing to the canonical source"
        );
        assert!(!plain.review().sends_idempotency_key());
        let declared = with_idempotency(name, derived_header()).expect("declared");
        assert_ne!(
            declared.digest(),
            plain.digest(),
            "{name}: needs a new approval"
        );
        assert!(declared.review().sends_idempotency_key());
        let longer = with_idempotency(
            name,
            json!({"kind": "derived-header", "retention_seconds": 86_401}),
        )
        .expect("declared");
        assert_ne!(
            longer.digest(),
            declared.digest(),
            "{name}: retention is bound"
        );
    }
}

#[test]
fn closed_request_carries_the_derived_key_only_when_declared() {
    let values = |operation: &str, replacement: &str| {
        json!({"operation_id": operation, "record_id": "recTEST0000000001",
            "replacement": replacement})
    };
    let plain = compiled("airtable");
    let undeclared = plain
        .closed_request_from_arguments(&arguments(&plain, &values("run-7", "Approved")), [1; 32])
        .expect("request");
    assert_eq!(undeclared.idempotency_key(), None);
    assert!(undeclared.headers().is_empty());
    let recipe = with_idempotency("airtable", derived_header()).expect("declared");
    let request = |operation: &str, replacement: &str, commitment: [u8; 32]| {
        recipe
            .closed_request_from_arguments(
                &arguments(&recipe, &values(operation, replacement)),
                commitment,
            )
            .expect("request")
    };
    let first = request("run-7", "Approved", [1; 32]);
    let key = idempotency_key(
        recipe.namespace(),
        &LogicalOperationId::parse("run-7").expect("operation"),
    );
    assert_eq!(first.idempotency_key(), Some(key.as_str()));
    assert_eq!(
        first
            .headers()
            .iter()
            .map(|header| (header.name(), header.value()))
            .collect::<Vec<_>>(),
        [("Idempotency-Key", key.as_str())]
    );
    assert!(
        first
            .observation()
            .expect("observation")
            .headers()
            .is_empty(),
        "no read sends the key"
    );
    assert!(!String::from_utf8_lossy(first.body()).contains(&key));
    assert!(!first.url().contains(&key));
    let reentered = request("run-7", "Pending", [2; 32]);
    assert_ne!(reentered.echo_token(), first.echo_token());
    assert_eq!(
        reentered.idempotency_key(),
        first.idempotency_key(),
        "a fresh challenge or changed action for the same logical operation sends the same key"
    );
    assert_ne!(
        request("run-8", "Approved", [1; 32]).idempotency_key(),
        first.idempotency_key()
    );
    let declared_field = with_idempotency(
        "todoist",
        json!({"kind": "operation-id-field",
            "location": {"form_field": "commands", "pointer": "/0/uuid"},
            "retention_seconds": 3600}),
    )
    .expect("operation-id field");
    assert!(!declared_field.review().sends_idempotency_key());
}

#[test]
fn echo_changes_the_digest_and_is_shown_in_review() {
    let recipe = compiled("airtable");
    let review = recipe.review();
    let echo = review.echo().expect("airtable declares echo");
    assert_eq!(echo.write(), "/fields/auths_echo");
    assert_eq!(echo.observe(), "/fields/auths_echo");
    assert!(echo.disclosure().contains("anyone who can read the record"));
    assert!(echo.disclosure().contains("secrets"));
    let (source, lock) = fixture("airtable");
    let mut without: Value = serde_json::from_slice(source).expect("source");
    without.as_object_mut().expect("object").remove("echo");
    let plain = CompiledRecipe::compile(&serde_json::to_vec(&without).expect("source"), lock)
        .expect("recipe without echo");
    assert_ne!(plain.digest(), recipe.digest());
    assert!(plain.review().echo().is_none());
    for name in ["todoist", "github"] {
        assert!(compiled(name).review().echo().is_none());
    }
}

#[test]
fn read_back_links_only_an_exact_token_with_the_verified_value() {
    let recipe = compiled("airtable");
    let args = arguments(
        &recipe,
        &json!({"operation_id": "run-9", "record_id": "recTEST0000000001", "replacement": "Approved"}),
    );
    let request = recipe
        .closed_request_from_arguments(&args, [3; 32])
        .expect("request");
    let token = request.echo_token().expect("token");
    let observation = request.observation().expect("observation");
    let read = |fields: Value| {
        observation.read_back(
            Some(token),
            &serde_json::to_vec(&json!({"fields": fields})).expect("bytes"),
        )
    };
    assert_eq!(
        read(json!({"DemoStatus": "Approved", "auths_echo": token})),
        Some(ReadBack::EchoMatched)
    );
    assert_eq!(
        read(json!({"DemoStatus": "Pending", "auths_echo": token})),
        Some(ReadBack::Value { matched: false })
    );
    assert_eq!(
        read(json!({"DemoStatus": "Approved", "auths_echo": "auths-e1-other"})),
        Some(ReadBack::EchoMismatch)
    );
    assert_eq!(
        read(json!({"DemoStatus": "Approved", "auths_echo": 7})),
        Some(ReadBack::EchoMismatch)
    );
    assert_eq!(
        read(json!({"DemoStatus": "Approved"})),
        Some(ReadBack::Value { matched: true })
    );
    assert_eq!(
        read(json!({"DemoStatus": "Approved", "auths_echo": null})),
        Some(ReadBack::Value { matched: true })
    );
    assert_eq!(read(json!({"auths_echo": token})), None);
    assert_eq!(observation.read_back(Some(token), b"not json"), None);
}

#[test]
fn todoist_sync_body_is_compiler_serialized_one_command() {
    let recipe = compiled("todoist");
    let arguments = arguments(
        &recipe,
        &json!({
            "operation_id": "f38bff5f-430e-4fe1-814b-6e43690a641f",
            "content": "Auths gateway test",
            "description": "Auths demo run f38bff5f-430e-4fe1-814b-6e43690a641f",
            "temp_id": "f5034de3-4de1-42e0-bb54-70a340226f0e"
        }),
    );
    let request = recipe
        .closed_request_from_arguments(&arguments, [0; 32])
        .expect("closed request");
    assert_eq!(request.method(), WriteMethod::Post);
    assert_eq!(request.echo_token(), None);
    assert_eq!(request.url(), "https://api.todoist.com/api/v1/sync");
    let form: BTreeMap<String, String> = form_urlencoded::parse(request.body())
        .into_owned()
        .collect();
    assert_eq!(form.len(), 1);
    let commands: Value = serde_json::from_str(&form["commands"]).expect("JSON form field");
    assert_eq!(commands.as_array().expect("array").len(), 1);
    assert_eq!(commands[0]["type"], "item_add");
}

#[test]
fn form_body_renders_an_integer_field_as_decimal_text() {
    let schema = json!({"kind": "object", "fields": {
        "operation_id": {"kind": "string", "minimum": 1, "maximum": 128},
        "operator_namespace": {"type": "enum", "variants": ["refunds"]},
        "recipe_digest": {"kind": "string", "minimum": 64, "maximum": 64},
        "payment_intent": {"kind": "string", "minimum": 3, "maximum": 255},
        "amount": {"kind": "integer", "minimum": 1, "maximum": 99_999_999}
    }});
    let digest = hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&schema).expect("canonical schema"),
    ));
    let lock = json!({
        "command_schema": schema, "generator_format": 2, "profile": "refund",
        "schema": "auths.self-hosted-profile-lock/1", "schema_digest": digest,
        "service": "refunds", "tool": "create_refund_v1", "version": 1
    });
    let source = json!({
        "schema": "auths.gateway-recipe-source/2", "profile_schema_digest": digest,
        "service": "refunds", "tool": "create_refund_v1", "operator_namespace": "refunds",
        "credential": {"kind": "bearer"}, "origin": "https://api.stripe.com",
        "write": {"method": "POST",
            "path": [{"kind": "fixed", "value": "v1"}, {"kind": "fixed", "value": "refunds"}],
            "body": {"kind": "form", "fields": {
                "payment_intent": {"kind": "field", "name": "payment_intent"},
                "amount": {"kind": "field", "name": "amount"}}}}
    });
    let recipe = CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("source"),
        &serde_json::to_vec(&lock).expect("lock"),
    )
    .expect("form recipe compiles");
    let arguments = arguments(
        &recipe,
        &json!({"operation_id": "refund-1", "payment_intent": "pi_1", "amount": 1500}),
    );
    let request = recipe
        .closed_request_from_arguments(&arguments, [0; 32])
        .expect("closed request");
    assert_eq!(request.url(), "https://api.stripe.com/v1/refunds");
    assert_eq!(request.content_type(), "application/x-www-form-urlencoded");
    assert_eq!(request.body(), b"amount=1500&payment_intent=pi_1");
}

#[test]
fn github_recipe_change_invalidates_old_authorized_arguments() {
    let original = compiled("github");
    let arguments = arguments(
        &original,
        &json!({"operation_id": "issue-1", "title": "Example", "body": "Example body"}),
    );
    let (source, lock) = fixture("github");
    let mut mutated: Value = serde_json::from_slice(source).expect("source");
    mutated["write"]["path"][2]["value"] = Value::String("other-repo".into());
    let changed = CompiledRecipe::compile(&serde_json::to_vec(&mutated).expect("source"), lock)
        .expect("deliberate changed recipe");
    assert_ne!(original.digest(), changed.digest());
    assert_eq!(
        changed
            .closed_request_from_arguments(&arguments, [0; 32])
            .err(),
        Some(GatewayRecipeError::ActionMismatch)
    );
}

#[test]
fn logical_id_and_namespace_are_canonical_and_bounded() {
    assert!(LogicalOperationId::parse("run-1.2").is_ok());
    assert!(OperatorNamespace::parse("operator_A").is_ok());
    for hostile in ["", "-leading", "with/slash", "with space", "x\n"] {
        assert!(LogicalOperationId::parse(hostile).is_err());
        assert!(OperatorNamespace::parse(hostile).is_err());
    }
    assert!(LogicalOperationId::parse(&"x".repeat(129)).is_err());
    assert!(OperatorNamespace::parse(&"x".repeat(65)).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_claim_is_one_use_across_races_and_restart() {
    let fixture: Value = serde_json::from_slice(include_bytes!(
        "../../../../../bindings/fixtures/gateway/attempt-scenarios.json"
    ))
    .expect("valid state corpus");
    assert_eq!(fixture["schema"], "auths.gateway-attempt-scenarios/1");
    assert_eq!(fixture["cases"].as_array().expect("cases").len(), 19);
    let recipe = compiled("github");
    let args = arguments(
        &recipe,
        &json!({"operation_id": "issue-42", "title": "Exact", "body": "One issue"}),
    );
    let request = Arc::new(
        recipe
            .closed_request_from_arguments(&args, [7; 32])
            .expect("request"),
    );
    let temp = tempfile::tempdir().expect("temp directory");
    let root = std::fs::canonicalize(temp.path())
        .expect("canonical temp")
        .join("attempts");
    let store = crate::GatewayAttempts::new(Arc::new(
        FileGatewayAttemptStore::open(&root).expect("private store"),
    ));
    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let store = store.clone();
            let request = Arc::clone(&request);
            let digest = *recipe.digest();
            tokio::spawn(async move { store.claim(&request, digest).await.map(drop) })
        })
        .collect();
    let mut outcomes = Vec::new();
    for task in tasks {
        outcomes.push(task.await.expect("task"));
    }
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(GatewayAttemptError::Replay)))
            .count(),
        15
    );
    drop(store);
    let restarted = crate::GatewayAttempts::new(Arc::new(
        FileGatewayAttemptStore::open(&root).expect("restart"),
    ));
    let snapshot = restarted
        .read(request.namespace(), request.operation_id())
        .await
        .expect("read")
        .expect("retained claim");
    assert_eq!(snapshot.stage(), GatewayAttemptStage::Unknown);
    assert!(matches!(
        restarted.claim(&request, *recipe.digest()).await,
        Err(GatewayAttemptError::Replay)
    ));
}

#[tokio::test]
async fn response_and_observation_are_distinct_durable_stages() {
    let recipe = compiled("airtable");
    let args = arguments(
        &recipe,
        &json!({"operation_id": "record-1", "record_id": "recTEST0000000001", "replacement": "Approved"}),
    );
    let request = recipe
        .closed_request_from_arguments(&args, [9; 32])
        .expect("request");
    let temp = tempfile::tempdir().expect("temp directory");
    let root = std::fs::canonicalize(temp.path())
        .expect("canonical temp")
        .join("attempts");
    let store = crate::GatewayAttempts::new(Arc::new(
        FileGatewayAttemptStore::open(&root).expect("store"),
    ));
    let claim = store
        .claim(&request, *recipe.digest())
        .await
        .expect("claim");
    let response = claim.record_response(200, [3; 32]).await.expect("response");
    assert_eq!(
        response.snapshot().expect("snapshot").stage(),
        GatewayAttemptStage::ResponseRecorded
    );
    let observed = response
        .record_observation(true)
        .await
        .expect("observation");
    assert_eq!(observed.stage(), GatewayAttemptStage::Observed);
    assert_eq!(observed.observation_match(), Some(true));
    assert_eq!(
        store
            .read(request.namespace(), request.operation_id())
            .await
            .expect("read"),
        Some(observed)
    );
    assert!(matches!(
        store.claim(&request, *recipe.digest()).await,
        Err(GatewayAttemptError::Replay)
    ));
}

/// The `/2` corpus of the recipe revision: valid bases and hostile cases.
fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../bindings/fixtures/gateway/hostile-recipes-v2.json"
    ))
    .expect("corpus")
}

fn corpus_recipe(base: &str) -> CompiledRecipe {
    let corpus = corpus();
    let base = &corpus["bases"][base];
    CompiledRecipe::compile(
        &serde_json::to_vec(&base["recipe"]).expect("recipe"),
        &serde_json::to_vec(&base["lock"]).expect("lock"),
    )
    .expect("corpus base compiles")
}

const ACCOUNT: &str = "acct_TESTACCOUNT01";

fn stripe_arguments(recipe: &CompiledRecipe, account: Option<&str>) -> Map<String, Value> {
    let mut values = json!({"operation_id": "refund-1", "payment_intent": "pi_TEST0000000001",
        "amount": 500, "currency": "usd"});
    if let Some(account) = account {
        values["connect_account"] = json!(account);
    }
    arguments(recipe, &values)
}

fn header_pairs(headers: &[RequestHeader]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|header| (header.name(), header.value()))
        .collect()
}

#[test]
fn source_v1_is_refused_without_a_reader() {
    for name in ["airtable", "todoist", "github"] {
        let (source, lock) = fixture(name);
        let mut source: Value = serde_json::from_slice(source).expect("source");
        source["schema"] = json!("auths.gateway-recipe-source/1");
        assert_eq!(
            CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source"), lock).err(),
            Some(GatewayRecipeError::InvalidSource),
            "{name}"
        );
    }
}

#[test]
fn review_document_is_v2_and_discloses_every_declaration() {
    let stripe = corpus_recipe("stripe");
    let review = stripe.review_document();
    assert_eq!(review["schema"], RECIPE_REVIEW_SCHEMA);
    assert_eq!(review["digest"], stripe.digest_hex());
    assert_eq!(review["write_is_conditional"], false);
    assert_eq!(review["recovery"]["schema"], RECOVERY_CAPABILITY_SCHEMA);
    assert_eq!(review["recovery"]["class"], "linked-after-response");
    assert_eq!(review["recovery"]["write_is_conditional"], false);
    assert_eq!(
        review["provider_headers"]["Stripe-Version"]["response"],
        "required"
    );
    assert!(
        review["idempotency"]["disclosure"]
            .as_str()
            .expect("idempotency")
            .contains("cannot verify that the provider honors it")
    );
    assert!(
        review["credential_guard"]["disclosure"]
            .as_str()
            .expect("guard")
            .contains("a denied read shows only the refusals observed")
    );
    assert_eq!(
        review["credential_guard"]["denied_reads"][1]["path"],
        json!(["v1", "payouts"])
    );
    assert_eq!(review["account_scope"]["header"], "Stripe-Account");
    assert!(
        review["account_scope"]["disclosure"]
            .as_str()
            .expect("scope")
            .contains("a value the grant lists")
    );
    assert_eq!(
        review["relative_ceiling"]["rule"],
        "amount ≤ floor(basis × 5000 / 10000)"
    );
    assert_eq!(review["bounds"]["sum"]["partition"], "currency");
    assert_eq!(review["observation"]["locator"], "response-locator");
    assert_eq!(review["echo"]["kind"], "form-field");
    assert_eq!(review["pre_entry"], Value::Null);
    let pre_entry = corpus_recipe("airtable-pre-entry").review_document();
    assert!(
        pre_entry["pre_entry"]["disclosure"]
            .as_str()
            .expect("pre-entry")
            .contains("the write is not conditional")
    );
    let plain = compiled("github").review_document();
    for absent in [
        "provider_headers",
        "credential_guard",
        "idempotency",
        "observation",
        "pre_entry",
        "account_scope",
        "relative_ceiling",
        "bounds",
        "echo",
    ] {
        assert_eq!(plain[absent], Value::Null, "{absent}");
    }
    assert_eq!(plain["recovery"]["class"], "recorded");
}

#[test]
fn recovery_capability_follows_its_table() {
    let observations = [
        StateObservation::None,
        StateObservation::VerifiedLocator,
        StateObservation::ResponseLocator,
    ];
    let reentries = [
        LostClaimReentry::None,
        LostClaimReentry::Declared {
            kind: IdempotencyKind::DerivedHeader,
            retention_seconds: 86_400,
        },
        LostClaimReentry::Declared {
            kind: IdempotencyKind::OperationIdField,
            retention_seconds: 1,
        },
    ];
    for observation in observations {
        for echo in [false, true] {
            for idempotency in reentries {
                for pre_entry in [false, true] {
                    let capability = recovery_capability(RecoveryDeclarations {
                        observation,
                        echo,
                        idempotency,
                        pre_entry,
                    });
                    let link = if echo {
                        observation
                    } else {
                        StateObservation::None
                    };
                    let class = match (observation, echo) {
                        (StateObservation::VerifiedLocator, true) => RecoveryClass::Linked,
                        (StateObservation::ResponseLocator, true) => {
                            RecoveryClass::LinkedAfterResponse
                        }
                        (StateObservation::None, _) => RecoveryClass::Recorded,
                        (_, false) => RecoveryClass::Observed,
                    };
                    assert_eq!(capability.state_observation, observation);
                    assert_eq!(capability.provider_link, link);
                    assert_eq!(capability.class, class);
                    assert_eq!(
                        capability.unknown_resolution == UnknownResolution::GatewayReobservation,
                        class == RecoveryClass::Linked
                    );
                    assert_eq!(capability.lost_claim_reentry, idempotency);
                    assert_eq!(capability.pre_entry_reread, pre_entry);
                    assert!(!capability.write_is_conditional);
                }
            }
        }
    }
}

#[test]
fn form_echo_is_placed_in_sorted_field_order() {
    let recipe = corpus_recipe("stripe-platform");
    let request = recipe
        .closed_request_from_arguments(&stripe_arguments(&recipe, None), [4; 32])
        .expect("request");
    let token = request.echo_token().expect("echo token");
    assert_eq!(
        String::from_utf8(request.body().to_vec()).expect("form body"),
        format!("amount=500&metadata%5Bauths_echo%5D={token}&payment_intent=pi_TEST0000000001")
    );
    assert_eq!(request.content_type(), "application/x-www-form-urlencoded");
}

#[test]
fn account_scope_header_is_exact_on_the_write_and_action_reads_and_nowhere_else() {
    let recipe = corpus_recipe("stripe");
    let request = recipe
        .closed_request_from_arguments(&stripe_arguments(&recipe, Some(ACCOUNT)), [4; 32])
        .expect("request");
    let version = ("Stripe-Version", "2025-03-31.basil");
    let key = idempotency_key(
        recipe.namespace(),
        &LogicalOperationId::parse("refund-1").expect("operation"),
    );
    assert_eq!(
        header_pairs(request.headers()),
        [
            version,
            ("Stripe-Account", ACCOUNT),
            ("Idempotency-Key", key.as_str())
        ]
    );
    let ceiling = request
        .relative_ceiling_read()
        .expect("relative ceiling read");
    assert_eq!(
        ceiling.url(),
        "https://api.stripe.com/v1/payment_intents/pi_TEST0000000001"
    );
    assert_eq!(
        header_pairs(ceiling.headers()),
        [version, ("Stripe-Account", ACCOUNT)]
    );
    assert!(
        request.observation().is_none(),
        "a response locator is resolved only from the recorded response"
    );
    let reads = recipe.credential_reads().expect("credential reads");
    for read in reads
        .probe()
        .into_iter()
        .chain(reads.account())
        .chain(reads.denied())
    {
        assert_eq!(header_pairs(read.headers()), [version], "{}", read.url());
    }
    let platform = corpus_recipe("stripe-platform");
    let unscoped = platform
        .closed_request_from_arguments(&stripe_arguments(&platform, None), [4; 32])
        .expect("platform request");
    let no_scope = |headers: &[RequestHeader]| {
        headers
            .iter()
            .all(|header| !header.name().eq_ignore_ascii_case("stripe-account"))
    };
    assert!(no_scope(unscoped.headers()));
    assert!(no_scope(
        unscoped
            .relative_ceiling_read()
            .expect("relative ceiling read")
            .headers()
    ));
}

#[test]
fn account_scope_value_outside_its_grammar_is_refused() {
    let recipe = corpus_recipe("stripe");
    for hostile in [
        "acct_TEST\r\nX-Injected: 1",
        "acct_TEST ACCOUNT",
        "acct_TEST-ACCOUNT",
        "cust_TESTACCOUNT01",
        "acct_SHORT12",
    ] {
        assert_eq!(
            recipe
                .closed_request_from_arguments(&stripe_arguments(&recipe, Some(hostile)), [4; 32])
                .err(),
            Some(GatewayRecipeError::ActionMismatch),
            "{hostile:?}"
        );
    }
}

#[test]
fn credential_reads_are_fixed_and_carry_no_action_value() {
    let recipe = corpus_recipe("stripe");
    let reads = recipe.credential_reads().expect("credential reads");
    let probe = reads.probe().expect("probe");
    assert_eq!(probe.method(), CredentialReadMethod::Get);
    assert_eq!(probe.url(), "https://api.stripe.com/v1/balance");
    assert_eq!(probe.maximum_response_bytes(), 16_384);
    assert_eq!(
        reads.account().expect("account").url(),
        "https://api.stripe.com/v1/account"
    );
    assert_eq!(
        reads
            .denied()
            .iter()
            .map(|read| (
                read.method().as_str(),
                read.url(),
                read.maximum_response_bytes()
            ))
            .collect::<Vec<_>>(),
        [
            ("GET", "https://api.stripe.com/v1/customers", 16_384),
            ("GET", "https://api.stripe.com/v1/payouts", 16_384)
        ]
    );
    let corpus = corpus();
    let mut source = corpus["bases"]["stripe"]["recipe"].clone();
    source["credential"]["guard"]["denied_reads"][0]["method"] = json!("HEAD");
    let head = CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("recipe"),
        &serde_json::to_vec(&corpus["bases"]["stripe"]["lock"]).expect("lock"),
    )
    .expect("HEAD denied read");
    assert_eq!(
        head.credential_reads().expect("reads").denied()[0].method(),
        CredentialReadMethod::Head
    );
    assert!(
        compiled("github")
            .credential_reads()
            .expect("reads")
            .denied()
            .is_empty()
    );
}

#[test]
fn only_executed_capabilities_run_in_an_engine() {
    for name in ["airtable", "todoist", "github"] {
        assert!(!compiled(name).declares_unexecuted_capability(), "{name}");
    }
    assert!(!corpus_recipe("stripe-plain").declares_unexecuted_capability());
    assert!(!corpus_recipe("todoist-operation-id").declares_unexecuted_capability());
    for base in [
        "stripe",
        "stripe-platform",
        "airtable-pre-entry",
        "github-response-locator",
    ] {
        assert!(
            corpus_recipe(base).declares_unexecuted_capability(),
            "{base}"
        );
    }
}

/// The serde renderer the construction leaf replaced, kept only as a test
/// oracle: it evaluates the template to a JSON value, inserts the echo, and
/// serializes under RFC 8785, or form-encodes the sorted pairs.
mod oracle {
    use super::super::source::{BodySource, EchoPlacement, FormExpr, PathSegment, ValueExpr};
    use serde_json::{Map, Value};
    use std::collections::BTreeMap;
    use url::form_urlencoded;

    fn eval(value: &ValueExpr, arguments: &Map<String, Value>) -> Value {
        match value {
            ValueExpr::String { value } => Value::String(value.clone()),
            ValueExpr::Integer { value } => Value::from(*value),
            ValueExpr::Boolean { value } => Value::Bool(*value),
            ValueExpr::Field { name } => arguments[name].clone(),
            ValueExpr::Object { fields } => Value::Object(
                fields
                    .iter()
                    .map(|(name, value)| (name.clone(), eval(value, arguments)))
                    .collect(),
            ),
            ValueExpr::Array { items } => {
                Value::Array(items.iter().map(|item| eval(item, arguments)).collect())
            }
            ValueExpr::Echo => Value::Null,
        }
    }

    pub(super) fn body(
        body: &BodySource,
        echo: Option<(&EchoPlacement, &str)>,
        arguments: &Map<String, Value>,
    ) -> Vec<u8> {
        match body {
            BodySource::Json { value } => {
                let mut value = eval(value, arguments);
                if let Some((EchoPlacement::JsonPointer { pointer }, token)) = echo {
                    let (parent, key) = pointer.rsplit_once('/').expect("pointer");
                    value
                        .pointer_mut(parent)
                        .and_then(Value::as_object_mut)
                        .expect("object")
                        .insert(key.to_owned(), Value::String(token.to_owned()));
                }
                serde_json_canonicalizer::to_vec(&value).expect("canonical")
            }
            BodySource::Form { fields } => {
                let mut pairs: BTreeMap<String, String> = fields
                    .iter()
                    .map(|(name, value)| {
                        let text = match value {
                            FormExpr::String { value } => value.clone(),
                            FormExpr::Field { name } => match &arguments[name] {
                                Value::String(text) => text.clone(),
                                other => other.to_string(),
                            },
                            FormExpr::Json { value } => String::from_utf8(
                                serde_json_canonicalizer::to_vec(&eval(value, arguments))
                                    .expect("canonical"),
                            )
                            .expect("utf-8"),
                            FormExpr::Echo => String::new(),
                        };
                        (name.clone(), text)
                    })
                    .collect();
                if let Some((EchoPlacement::FormField { name }, token)) = echo {
                    pairs.insert(name.clone(), token.to_owned());
                }
                let mut serializer = form_urlencoded::Serializer::new(String::new());
                for (name, value) in pairs {
                    serializer.append_pair(&name, &value);
                }
                serializer.finish().into_bytes()
            }
        }
    }

    pub(super) fn path(segments: &[PathSegment], arguments: &Map<String, Value>) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut path = String::new();
        for segment in segments {
            path.push('/');
            match segment {
                PathSegment::Fixed { value } => path.push_str(value),
                PathSegment::Field { name } => {
                    for byte in arguments[name].as_str().expect("text").bytes() {
                        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
                        {
                            path.push(char::from(byte));
                        } else {
                            path.push('%');
                            path.push(char::from(HEX[usize::from(byte >> 4)]));
                            path.push(char::from(HEX[usize::from(byte & 0x0f)]));
                        }
                    }
                }
                PathSegment::ResponseField { .. } | PathSegment::Echo => {}
            }
        }
        path
    }
}

fn oracle_request(recipe: &CompiledRecipe, arguments: &Map<String, Value>, commitment: [u8; 32]) {
    let request = recipe
        .closed_request_from_arguments(arguments, commitment)
        .expect("request");
    let echo = recipe
        .source
        .echo
        .as_ref()
        .map(|echo| (&echo.write, request.echo_token().expect("token")));
    assert_eq!(
        request.body(),
        oracle::body(&recipe.source.write.body, echo, arguments),
        "body"
    );
    assert_eq!(
        request.url(),
        format!(
            "{}{}",
            recipe.source.origin,
            oracle::path(&recipe.source.write.path, arguments)
        ),
        "url"
    );
}

/// Arbitrary text with quotes, backslashes, controls other than NUL,
/// separators, percent signs, and multi-byte characters.
fn hostile_text(
    minimum: usize,
    maximum: usize,
) -> impl proptest::strategy::Strategy<Value = String> {
    use proptest::prelude::*;
    let unit = prop_oneof![
        4 => proptest::char::range('a', 'z'),
        1 => proptest::char::range('\u{1}', '\u{1f}'),
        1 => Just('"'),
        1 => Just('\\'),
        1 => Just('/'),
        1 => Just(' '),
        1 => Just('%'),
        1 => Just('&'),
        1 => Just('\u{7f}'),
        1 => Just('é'),
        1 => Just('\u{2028}'),
        1 => Just('😀'),
    ];
    proptest::collection::vec(unit, 0..maximum)
        .prop_map(|chars| chars.into_iter().collect::<String>())
        .prop_filter("byte length", move |text| {
            (minimum..=maximum).contains(&text.len())
        })
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    #[test]
    fn construction_leaf_matches_the_serde_oracle_on_json_bodies(
        title in hostile_text(1, 128),
        body in hostile_text(0, 256),
        record in hostile_text(17, 43),
    ) {
        let github = compiled("github");
        oracle_request(
            &github,
            &arguments(&github, &json!({"operation_id": "issue-1", "title": title, "body": body})),
            [2; 32],
        );
        let airtable = compiled("airtable");
        oracle_request(
            &airtable,
            &arguments(
                &airtable,
                &json!({"operation_id": "run-1", "record_id": record, "replacement": "Pending"}),
            ),
            [3; 32],
        );
    }

    #[test]
    fn construction_leaf_matches_the_serde_oracle_on_form_bodies(
        content in hostile_text(1, 256),
        description in hostile_text(1, 80),
        intent in hostile_text(3, 255),
        amount in 1_i64..=99_999_999,
    ) {
        let todoist = compiled("todoist");
        oracle_request(
            &todoist,
            &arguments(&todoist, &json!({
                "operation_id": "f38bff5f-430e-4fe1-814b-6e43690a641f",
                "content": content,
                "description": description,
                "temp_id": "f5034de3-4de1-42e0-bb54-70a340226f0e"
            })),
            [5; 32],
        );
        let stripe = corpus_recipe("stripe-plain");
        oracle_request(
            &stripe,
            &arguments(&stripe, &json!({"operation_id": "refund-1", "payment_intent": intent,
                "amount": amount})),
            [6; 32],
        );
        let platform = corpus_recipe("stripe-platform");
        oracle_request(
            &platform,
            &arguments(&platform, &json!({"operation_id": "refund-1", "payment_intent": intent,
                "amount": amount, "currency": "usd"})),
            [7; 32],
        );
    }

    #[test]
    fn a_path_value_never_adds_a_segment(record in hostile_text(17, 43)) {
        let airtable = compiled("airtable");
        let request = airtable.closed_request_from_arguments(
            &arguments(
                &airtable,
                &json!({"operation_id": "run-1", "record_id": record, "replacement": "Pending"}),
            ),
            [3; 32],
        );
        match request {
            Ok(request) => {
                let path = request
                    .url()
                    .strip_prefix("https://api.airtable.com")
                    .expect("origin");
                proptest::prop_assert_eq!(path.matches('/').count(), 4);
                proptest::prop_assert!(!path.contains('?') && !path.contains('#'));
            }
            Err(error) => proptest::prop_assert_eq!(error, GatewayRecipeError::UnsafePath),
        }
    }
}
