//! Valid native authority is necessary, but cannot extend a closed managed
//! contract or move retained content between operator partitions.
use super::*;
use crate::effect::EffectPolicy;

fn scope_substitutions() -> Vec<(&'static str, Value)> {
    vec![
        ("task", json!({"commitment": vec![7; 32]})),
        ("scope", json!({"kind":"task", "commitment": vec![7; 32]})),
        ("participants", json!(["caller-selected-participant"])),
        ("ancestors", json!(["caller-selected-parent"])),
        ("charges", json!([])),
        ("partition", json!("caller-selected-partition")),
        ("epoch", json!(2)),
        ("operator_namespace", json!("another-operator")),
        ("recipe_digest", json!("00".repeat(32))),
        ("content_contract", json!("00".repeat(32))),
        ("maximum_response_bytes", json!(1)),
    ]
}

fn refused_contract(fixture: &Fixture, field: &str, value: Value) -> Value {
    let original = fixture
        .runtime
        .block_on(Input::content(&fixture.engine, Change::None));
    let call = fixture
        .runtime
        .block_on(
            fixture
                .engine
                .content_authorization_call(br#"{"record_id":"recTEST0000000001"}"#, SOURCE),
        )
        .expect("native call");
    let mut arguments = call.arguments().clone();
    arguments.insert(field.to_owned(), value);
    let changed = McpToolCall::new(call.service(), call.name(), arguments).expect("changed call");
    let signed = tool_fixture_until(&changed, NOW, NOW + 86_400).expect("genuine native proof");
    assert_native_authorized(fixture, &signed.proof, &signed.action);
    let before = fixture.records();
    let witness = fixture.engine.execution_witness();
    let compiled = fixture.runtime.block_on(
        fixture
            .engine
            .compile_content_action(&signed.proof, &signed.action),
    );
    assert!(
        matches!(compiled, Err(crate::GatewaySubmitResult::NotEntered {code})
        if code == "gateway.acquisition.binding"),
        "closed managed contract must reject {field}"
    );
    let refused = fixture
        .runtime
        .block_on(fixture.engine.acquire_content_action(
            &signed.proof,
            &signed.action,
            original.approval,
        ));
    assert!(
        matches!(refused, Err(crate::GatewaySubmitResult::NotEntered {code})
        if code == "gateway.acquisition.binding"),
        "no entry with substituted {field}"
    );
    assert_eq!(fixture.records(), before);
    assert_eq!(fixture.engine.execution_witness(), witness);
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 0);
    json!({"field":field, "native_authorized":true, "managed_compile_refused":true,
        "entry_refused":true, "journal_unchanged":true, "credential_leases":0,
        "provider_reads":0})
}

fn assert_native_authorized(fixture: &Fixture, proof: &[u8], action: &[u8]) {
    let context_bytes = controls(fixture.clock.clone(), 29)
        .trust
        .expect("installed trust");
    let context = auths_codec::decode_verifier_context(&context_bytes).expect("context");
    let verified = crate::engine::verify_native(&context, NOW, proof, action)
        .expect("ordinary native authority must be valid for this changed call");
    assert!(verified.action().is_some());
}

fn partition_engine(fixture: &Fixture) -> GatewayEngine {
    let mut candidate_controls = controls(fixture.clock.clone(), 29);
    candidate_controls.policy = EffectPolicy::new(
        "independent-partition".to_owned(),
        1,
        SigningKey::from_bytes(&[29; 32]).verifying_key().to_bytes(),
    )
    .expect("different operator partition");
    let attempts = GatewayAttempts::new(
        fixture.store.reopen().store(),
        candidate_controls.policy.clone(),
    )
    .expect("separate scoped attempts");
    let (candidate, _) = fixture.runtime.block_on(load_controlled_engine(
        &fixture.setup,
        "independent-partition",
        attempts,
        candidate_controls,
    ));
    candidate
        .initialize_effect_configuration()
        .expect("independent partition initialization");
    assert_ne!(
        fixture
            .engine
            .shared_configuration()
            .expect("original control")
            .key(),
        candidate
            .shared_configuration()
            .expect("candidate control")
            .key(),
    );
    candidate
}

fn cross_partition(fixture: &Fixture) -> Value {
    let input = fixture
        .runtime
        .block_on(Input::content(&fixture.engine, Change::None));
    let original = fixture
        .runtime
        .block_on(
            fixture
                .engine
                .compile_content_action(&input.proof, &input.action),
        )
        .expect("original valid effect");
    let candidate = partition_engine(fixture);
    let candidate_effect = fixture
        .runtime
        .block_on(candidate.compile_content_action(&input.proof, &input.action))
        .expect("same proof is valid in an independently installed partition");
    assert_ne!(original.binding().id(), candidate_effect.binding().id());
    let before = fixture.records();
    let witness = candidate.execution_witness();
    assert!(
        fixture
            .runtime
            .block_on(candidate.acquire_content_action(
                &input.proof,
                &input.action,
                input.approval.clone(),
            ))
            .is_err(),
        "approval cannot cross partitions even with same actor and operation"
    );
    assert_eq!(fixture.records(), before);
    assert_eq!(candidate.execution_witness(), witness);
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 0);
    let acquired = fixture
        .runtime
        .block_on(fixture.engine.acquire_content_action(
            &input.proof,
            &input.action,
            input.approval.clone(),
        ))
        .expect("original exact approval still works");
    let records = fixture.records();
    assert_eq!(records.len(), 1);
    foreign_history_refused(fixture, &candidate);
    assert_eq!(fixture.records(), records);
    assert_eq!(candidate.execution_witness(), witness);
    let original_witness = fixture.engine.execution_witness();
    assert_eq!(
        fixture
            .runtime
            .block_on(fixture.engine.acquire_content_action(
                &input.proof,
                &input.action,
                input.approval,
            ))
            .expect("original historical replay"),
        acquired
    );
    assert_eq!(fixture.engine.execution_witness(), original_witness);
    assert_eq!(fixture.records(), records);
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
    json!({"same_valid_native_proof":true, "different_partition_effect_identity":true,
        "foreign_exact_approval_refused":true, "foreign_history_refused":true,
        "foreign_disclosure_source_refused":true, "original_replay_retained":true,
        "provider_reads":1, "retained_attempts":1})
}

fn foreign_history_refused(fixture: &Fixture, candidate: &GatewayEngine) {
    assert!(
        fixture
            .runtime
            .block_on(candidate.content_history(SOURCE))
            .is_err()
    );
    let uid = std::fs::metadata(&fixture.setup.root).expect("owner").uid();
    let policy = UnixDisclosurePolicy::new(uid, uid, [51; 32]);
    assert!(
        fixture
            .runtime
            .block_on(candidate.disclosure_target(
                SOURCE,
                SigningKey::from_bytes(&[47; 32]).verifying_key().to_bytes(),
                policy.commitment().expect("channel"),
                [52; 32],
            ))
            .is_err(),
        "foreign content cannot become a disclosure proposal"
    );
}

fn disclosure_substitutions() -> Vec<(&'static str, Value)> {
    let mut cases = scope_substitutions();
    cases.extend([
        ("disclosure_contract", json!("00".repeat(32))),
        ("source_effect", json!("00".repeat(32))),
        ("source_operation", json!("another-read")),
        ("recipient", json!("another-recipient")),
        ("channel", json!("00".repeat(32))),
        ("delivery_instance", json!("00".repeat(32))),
        ("maximum_disclosure_bytes", json!(0)),
    ]);
    cases
}

fn refused_disclosure(
    fixture: &Fixture,
    target: &crate::effect::DisclosureTarget,
    field: &str,
    value: Value,
) -> Value {
    let original =
        fixture
            .runtime
            .block_on(Input::disclosure(&fixture.engine, target, Change::None));
    let call = target
        .authorization_call(
            &recipe(),
            &LogicalOperationId::parse(RELEASE).expect("release operation"),
        )
        .expect("native disclosure call");
    let mut arguments = call.arguments().clone();
    arguments.insert(field.to_owned(), value);
    let changed = McpToolCall::new(call.service(), call.name(), arguments).expect("changed call");
    let signed = tool_fixture_until(&changed, NOW, NOW + 86_400).expect("genuine release proof");
    assert_native_authorized(fixture, &signed.proof, &signed.action);
    let records = fixture.records();
    let witness = fixture.engine.execution_witness();
    let compiled = fixture
        .runtime
        .block_on(
            fixture
                .engine
                .compile_disclosure_effect(target, &signed.proof, &signed.action),
        );
    assert!(
        matches!(compiled, Err(crate::GatewaySubmitResult::NotEntered {code})
        if code == "gateway.disclosure.binding"),
        "changed {field} must fail managed disclosure compilation"
    );
    assert!(
        fixture
            .runtime
            .block_on(fixture.engine.admit_disclosure(
                target,
                &signed.proof,
                &signed.action,
                original.approval,
            ))
            .is_err(),
        "changed {field} cannot reserve release"
    );
    assert_eq!(fixture.records(), records);
    assert_eq!(fixture.engine.execution_witness(), witness);
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
    json!({"field":field, "native_authorized":true, "managed_compile_refused":true,
        "reservation_refused":true, "journal_unchanged":true,
        "credential_leases":0, "additional_provider_reads":0})
}

fn disclosure_cases(fixture: &Fixture) -> Vec<Value> {
    let uid = std::fs::metadata(&fixture.setup.root).expect("owner").uid();
    let policy = UnixDisclosurePolicy::new(uid, uid, [51; 32]);
    let recipient = SigningKey::from_bytes(&[47; 32]);
    let target = fixture
        .runtime
        .block_on(fixture.engine.disclosure_target(
            SOURCE,
            recipient.verifying_key().to_bytes(),
            policy.commitment().expect("channel"),
            [52; 32],
        ))
        .expect("original retained source");
    let cases = disclosure_substitutions()
        .into_iter()
        .map(|(field, value)| refused_disclosure(fixture, &target, field, value))
        .collect();
    let input = fixture
        .runtime
        .block_on(Input::disclosure(&fixture.engine, &target, Change::None));
    fixture.runtime.block_on(release(
        &fixture.engine,
        &input,
        &target,
        &policy,
        &recipient,
        true,
    ));
    assert_eq!(
        fixture.records().len(),
        2,
        "only original acquisition and exact release admitted"
    );
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
    cases
}

fn changed_recipe_engine(fixture: &Fixture) -> GatewayEngine {
    let mut source: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/content-only/recipe.json"
    ))
    .expect("recipe source");
    source["content"]["maximum_content_bytes"] = json!(63);
    let changed = crate::CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("changed source"),
        include_bytes!("../../../../bindings/fixtures/gateway/content-only/profile.lock.json"),
    )
    .expect("different valid recipe with identical resource and transport");
    assert_ne!(changed.digest(), recipe().digest());
    let mut candidate_controls = controls(fixture.clock.clone(), 29);
    candidate_controls.recipe = Some(changed);
    let attempts = GatewayAttempts::new(
        fixture.store.reopen().store(),
        candidate_controls.policy.clone(),
    )
    .expect("same partition journal");
    let (candidate, record) = fixture.runtime.block_on(
        crate::native_process_tests::load_controlled_engine_at_generation(
            &fixture.setup,
            "different-recipe",
            attempts,
            candidate_controls,
            std::num::NonZeroU64::new(2).expect("new credential generation"),
        ),
    );
    assert!(candidate.initialize_effect_configuration().is_err());
    let revision = candidate
        .effect_configuration_revision()
        .expect("operator review");
    candidate
        .activate_effect_configuration(revision)
        .expect("explicit recipe activation");
    assert!(
        fixture
            .runtime
            .block_on(candidate.content_authorization_call(
                br#"{"record_id":"recTEST0000000001"}"#,
                "recipe-current",
            ))
            .is_err(),
        "activation cannot bypass the pinned connection descriptor"
    );
    let shared = SharedConnection::new(
        fixture.store.raw(),
        record.provider_kind().clone(),
        record.alias().clone(),
    );
    let loaded = fixture
        .runtime
        .block_on(shared.load())
        .expect("load")
        .expect("old connection");
    let rotated = loaded
        .record()
        .rotated(
            record.descriptor().to_vec(),
            *record.account_commitment(),
            *record.credential_reference_commitment(),
            record.updated_at_unix_seconds(),
        )
        .expect("native generation-incrementing rotation");
    assert_eq!(
        rotated, record,
        "fixture must use the actual native rotation result"
    );
    fixture
        .runtime
        .block_on(shared.replace(&loaded, &rotated))
        .expect("operator connection CAS");
    candidate
}

fn signed_input(fixture: &Fixture, engine: &GatewayEngine, operation: &str) -> Input {
    let call = fixture
        .runtime
        .block_on(
            engine.content_authorization_call(br#"{"record_id":"recTEST0000000001"}"#, operation),
        )
        .expect("native call");
    let signed = tool_fixture_until(&call, NOW, NOW + 86_400).expect("valid native proof");
    assert_native_authorized(fixture, &signed.proof, &signed.action);
    let effect = fixture
        .runtime
        .block_on(engine.compile_content_action(&signed.proof, &signed.action))
        .expect("candidate recipe compiles its own valid action");
    Input {
        proof: signed.proof,
        action: signed.action,
        approval: Input::approval(&effect, Change::None),
    }
}

fn cross_recipe(fixture: &Fixture) -> Value {
    let original = fixture
        .runtime
        .block_on(Input::content(&fixture.engine, Change::None));
    let retained = fixture
        .runtime
        .block_on(fixture.engine.content_history(SOURCE))
        .expect("original content history");
    let candidate = changed_recipe_engine(fixture);
    let records = fixture.records();
    let witness = candidate.execution_witness();
    assert!(
        fixture
            .runtime
            .block_on(candidate.compile_content_action(&original.proof, &original.action,))
            .is_err(),
        "old recipe's otherwise valid native proof cannot compile here"
    );
    assert_native_authorized(fixture, &original.proof, &original.action);
    assert!(
        fixture
            .runtime
            .block_on(candidate.acquire_content_action(
                &original.proof,
                &original.action,
                original.approval.clone(),
            ))
            .is_err()
    );
    let changed = signed_input(fixture, &candidate, SOURCE);
    assert!(
        fixture
            .runtime
            .block_on(candidate.acquire_content_action(
                &changed.proof,
                &changed.action,
                original.approval,
            ))
            .is_err(),
        "old exact approval cannot approve the new recipe"
    );
    assert!(
        fixture
            .runtime
            .block_on(candidate.acquire_content_action(
                &changed.proof,
                &changed.action,
                changed.approval,
            ))
            .is_err(),
        "even fresh authority cannot overwrite the retained logical operation"
    );
    foreign_history_refused(fixture, &candidate);
    assert_eq!(fixture.records(), records);
    assert_eq!(candidate.execution_witness(), witness);
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .runtime
            .block_on(fixture.engine.content_history(SOURCE))
            .expect("old history remains available to its own recipe"),
        retained
    );
    let fresh = signed_input(fixture, &candidate, "recipe-current");
    fixture
        .runtime
        .block_on(candidate.acquire_content_action(&fresh.proof, &fresh.action, fresh.approval))
        .expect("new recipe can perform a separately approved new operation");
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.records().len(), records.len() + 1);
    json!({"same_namespace_partition_epoch_actor_resource":true,
        "explicit_operator_activation":true, "old_native_proof_still_authorized":true,
        "activation_without_connection_reapproval_refused":true,
        "native_connection_rotation_cas":true,
        "old_recipe_compile_refused":true, "old_approval_refused":true,
        "fresh_approval_cannot_overwrite_retained_operation":true,
        "foreign_history_and_disclosure_source_refused":true,
        "original_history_retained":true, "new_exact_operation_succeeds":true,
        "provider_reads":2, "retained_attempts":3})
}

fn matrix(backend: Backend) {
    let fixture = Fixture::new(backend);
    let cases: Vec<_> = scope_substitutions()
        .into_iter()
        .map(|(field, value)| refused_contract(&fixture, field, value))
        .collect();
    let partition = cross_partition(&fixture);
    let disclosures = disclosure_cases(&fixture);
    let recipe = cross_recipe(&fixture);
    let artifact = serde_json::to_vec_pretty(&json!({
        "schema":"auths.native-managed-scope/1", "adapter":backend.label(),
        "signed_contract_substitutions":cases, "cross_partition":partition,
        "disclosure_substitutions":disclosures, "original_disclosure_acknowledged":true,
        "cross_recipe":recipe,
        "scope":"native verification, managed compilation and entry over one durable adapter with independent engine configurations and actual local HTTP",
        "excluded":["multi-agent task semantics", "hostile OS containment", "installed language framing", "all binding dimensions"]
    })).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-managed-scope-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write artifact");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}

#[test]
fn native_file_managed_scope_fixture_is_current() {
    matrix(Backend::File);
}

#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_managed_scope_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
