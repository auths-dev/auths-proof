//! Malformed persisted read/disclosure facts never become current capabilities.
use super::*;

fn one(backend: Backend, protocol: Protocol) -> Value {
    let fixture = Fixture::new(backend);
    let input = fixture
        .runtime
        .block_on(Input::content(&fixture.engine, Change::None));
    let acquired = fixture
        .runtime
        .block_on(fixture.engine.acquire_content_action(
            &input.proof,
            &input.action,
            input.approval.clone(),
        ))
        .expect("native read");
    let history = prepare_release(&fixture, protocol, Change::None);
    let operation = LogicalOperationId::parse(if history.is_some() { RELEASE } else { SOURCE })
        .expect("operation");
    let key = crate::GatewayAttemptKey::for_operation(
        &crate::effect::fixture_policy().expect("policy"),
        recipe().namespace(),
        &operation,
    )
    .expect("key");
    let raw = fixture.store.raw();
    let original = raw
        .load(GatewayRecordKind::Attempt, &key)
        .expect("load")
        .expect("record");
    let reopened = fixture.change_and_reopen(Change::None);
    let witness = reopened.execution_witness();
    let cases = crate::native_journal_tests::exercise(
        &*raw,
        key,
        &original,
        || {
            fixture.runtime.block_on(async {
                if let Some(history) = &history {
                    let (server, mut client) = UnixStream::pair().expect("channel");
                    assert!(
                        reopened
                            .disclose(
                                &history.target,
                                &history.input.proof,
                                &history.input.action,
                                history.input.approval.clone(),
                                crate::disclosure_transport::DisclosureConnection::new(
                                    server,
                                    history.policy.clone()
                                )
                            )
                            .await
                            .is_err()
                    );
                    let mut byte = [0];
                    assert_eq!(client.read(&mut byte).await.expect("closed channel"), 0);
                } else {
                    assert!(
                        reopened
                            .acquire_content_action(
                                &input.proof,
                                &input.action,
                                input.approval.clone()
                            )
                            .await
                            .is_err()
                    );
                }
                assert!(reopened.content_history(operation.as_str()).await.is_err());
            });
            assert_eq!(reopened.execution_witness(), witness);
            assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
        },
        || {
            fixture.runtime.block_on(async {
                if let Some(history) = &history {
                    replay_release(&reopened, history).await;
                } else {
                    replay_content(&reopened, &input, &acquired).await;
                }
            });
            assert_eq!(reopened.execution_witness(), witness);
            assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
        },
        || {
            fixture.runtime.block_on(replay_at_limit(
                &reopened,
                &input,
                history.as_ref(),
                &acquired,
            ));
            assert_eq!(reopened.execution_witness(), witness);
            assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
        },
    );
    json!({"protocol":protocol.label(),"cases":cases,"real_provider_reads":1,
        "exact_retained_charges_preserved":true,"disclosure_replay_sends_zero_bytes":true})
}

fn matrix(backend: Backend) {
    let cases = [
        Protocol::Acquisition,
        Protocol::Acknowledged,
        Protocol::LostAcknowledgement,
    ]
    .map(|protocol| one(backend, protocol));
    let bytes=serde_json::to_vec_pretty(&json!({"schema":"auths.native-information-journal/1","adapter":backend.label(),
        "scope":"native signed acquisition/disclosure, real HTTP and authenticated Unix delivery, reopened engine and adapter; isolated privileged record corruption",
        "excluded":["hostile store rewriting every correlated record","whole-store rollback without independent anchor","power loss"],"cases":cases})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-information-journal-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("artifact");
    }
    assert_eq!(std::fs::read(path).expect("artifact"), bytes);
}
#[test]
fn native_file_information_journal_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires maintained TLS PostgreSQL fixture"]
fn postgres_native_information_journal_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}

async fn replay_at_limit(
    engine: &GatewayEngine,
    input: &Input,
    history: Option<&ReleaseHistory>,
    acquired: &crate::AcquisitionSnapshot,
) {
    if let Some(history) = history {
        let (server, mut client) = UnixStream::pair().expect("read-only replay channel");
        let mut expected = history.snapshot.clone();
        expected.revision = crate::store::MAX_OPERATION_REVISIONS;
        assert_eq!(
            engine
                .disclose(
                    &history.target,
                    &history.input.proof,
                    &history.input.action,
                    history.input.approval.clone(),
                    crate::disclosure_transport::DisclosureConnection::new(
                        server,
                        history.policy.clone()
                    )
                )
                .await
                .expect("terminal history at limit"),
            expected
        );
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).await.expect("closed channel"), 0);
    } else {
        let mut expected = acquired.clone();
        expected.revision = crate::store::MAX_OPERATION_REVISIONS;
        assert_eq!(
            engine
                .acquire_content_action(&input.proof, &input.action, input.approval.clone())
                .await
                .expect("terminal history at limit"),
            expected
        );
    }
}
