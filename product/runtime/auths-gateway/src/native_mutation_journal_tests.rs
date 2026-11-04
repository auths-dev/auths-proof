//! The mutation replay path consumes the same strict journal decoder.
use super::*;

fn one(backend: Backend) -> Value {
    let directory = tempfile::tempdir().expect("directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("private");
    let store = TestAttempts::open(backend);
    let provider = Provider::start();
    let setup = Setup {
        backend: backend.label().to_owned(),
        location: store.location(),
        root,
        provider_port: provider.port,
        barrier_port: 0,
    };
    let clock = Arc::new(FixedClock::at(NOW));
    let runtime = runtime();
    let (engine, connection) = runtime.block_on(load_controlled_engine(
        &setup,
        "original",
        store.attempts().clone(),
        controls(clock.clone(), 29),
    ));
    let shared = SharedConnection::new(
        store.raw(),
        connection.provider_kind().clone(),
        connection.alias().clone(),
    );
    runtime
        .block_on(shared.insert(&connection))
        .expect("connection");
    engine.initialize_effect_configuration().expect("config");
    let input = runtime.block_on(Input::author(&engine, Change::None));
    let expected = runtime.block_on(input.submit(&engine));
    assert_eq!(
        expected,
        GatewaySubmitResult::ResponseRecorded { status: 200 }
    );
    let operation = LogicalOperationId::parse(OPERATION).expect("operation");
    let key = crate::GatewayAttemptKey::for_operation(
        &crate::effect::fixture_policy().expect("policy"),
        recipe().namespace(),
        &operation,
    )
    .expect("key");
    let raw = store.raw();
    let original = raw
        .load(GatewayRecordKind::Attempt, &key)
        .expect("load")
        .expect("record");
    let reopened = reopened_engine(Change::None, &runtime, &setup, &store, &clock);
    let witness = reopened.execution_witness();
    let cases = crate::native_journal_tests::exercise(
        &*raw,
        key,
        &original,
        || {
            assert_eq!(
                runtime.block_on(input.submit(&reopened)),
                GatewaySubmitResult::Indeterminate {
                    code: "gateway.attempt.state-unavailable".to_owned()
                }
            );
            assert!(
                runtime
                    .block_on(store.attempts().read(recipe().namespace(), &operation))
                    .is_err()
            );
            assert_eq!(reopened.execution_witness(), witness);
            assert_eq!(
                *provider.bodies.lock().expect("requests"),
                vec![input.body.clone()]
            );
        },
        || {
            assert_eq!(runtime.block_on(input.submit(&reopened)), expected);
            assert_eq!(reopened.execution_witness(), witness);
            assert_eq!(
                *provider.bodies.lock().expect("requests"),
                vec![input.body.clone()]
            );
        },
    );
    json!({"protocol":"mutation-response","cases":cases,"real_provider_writes":1,"retained_charges_preserved":true})
}
fn matrix(backend: Backend) {
    let bytes=serde_json::to_vec_pretty(&json!({"schema":"auths.native-mutation-journal/1","adapter":backend.label(),
        "scope":"native signed mutation, real HTTP, reopened engine and adapter; isolated privileged record corruption",
        "excluded":["hostile store rewriting every correlated record","whole-store rollback without independent anchor","power loss"],"case":one(backend)})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-mutation-journal-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("artifact");
    }
    assert_eq!(std::fs::read(path).expect("artifact"), bytes);
}
#[test]
fn native_file_mutation_journal_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires maintained TLS PostgreSQL fixture"]
fn postgres_native_mutation_journal_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
