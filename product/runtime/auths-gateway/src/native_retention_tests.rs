//! Retained native facts survive expiry-slot cleanup; no permit is recreated.
use super::*;
use crate::harness::authoring::tool_fixture_using_policy;
use crate::{ArgumentCeilingPolicy, GatewayAttemptKey};

const WINDOW: u64 = 60;
type StoredRecord = (GatewayRecordKind, GatewayAttemptKey, Vec<u8>);

async fn bounded_input(engine: &GatewayEngine, operation: &str) -> Input {
    let call = engine
        .content_authorization_call(br#"{"record_id":"recTEST0000000001"}"#, operation)
        .await
        .expect("native call");
    let policy = ArgumentCeilingPolicy::new("maximum_response_bytes", 1024, WINDOW, 1)
        .expect("count bound")
        .with_sum(1024, None)
        .expect("byte bound");
    let signed = tool_fixture_using_policy(&call, NOW, NOW + 86_400, Some(&policy))
        .expect("native bounded proof");
    let effect = engine
        .compile_content_action(&signed.proof, &signed.action)
        .await
        .expect("bound effect");
    Input {
        proof: signed.proof,
        action: signed.action,
        approval: Input::approval(&effect, Change::None),
    }
}

fn slots(fixture: &Fixture) -> Vec<StoredRecord> {
    let mut slots = Vec::new();
    for bytes in fixture.records() {
        let record: Value = serde_json::from_slice(&bytes).expect("native record");
        for counter in record["state"]["facts"]["counters"]
            .as_array()
            .expect("counters")
        {
            let digest: [u8; 32] = hex::decode(counter["counter"].as_str().expect("digest"))
                .expect("hex")
                .try_into()
                .expect("length");
            let slot = counter["slot"].as_u64().expect("slot");
            let (kind, key) = if counter["kind"] == "count" {
                (
                    GatewayRecordKind::CountSlot,
                    crate::bounds::count_slot_key(&digest, slot),
                )
            } else {
                assert_eq!(counter["kind"], "sum");
                (
                    GatewayRecordKind::SumSlot,
                    crate::bounds::sum_slot_key(&digest, slot),
                )
            };
            let key = GatewayAttemptKey::from_bytes(key);
            let bytes = fixture
                .store
                .raw()
                .load(kind, &key)
                .expect("slot load")
                .expect("slot");
            slots.push((kind, key, bytes));
        }
    }
    assert_eq!(
        slots.len(),
        2,
        "only the bounded source's count and byte slots"
    );
    slots
}

async fn replay(
    engine: &GatewayEngine,
    input: &Input,
    acquired: &crate::AcquisitionSnapshot,
    disclosure: Option<&ReleaseHistory>,
) -> Value {
    let acquisition = replay_content(engine, input, acquired).await;
    match disclosure {
        Some(history) => replay_release(engine, history).await,
        None => acquisition,
    }
}

fn retained_case(backend: Backend, protocol: Protocol) -> Value {
    let fixture = Fixture::new(backend);
    let source = fixture
        .runtime
        .block_on(bounded_input(&fixture.engine, SOURCE));
    let acquired = fixture
        .runtime
        .block_on(fixture.engine.acquire_content_action(
            &source.proof,
            &source.action,
            source.approval.clone(),
        ))
        .expect("one real GET");
    let disclosure = prepare_release(&fixture, protocol, Change::None);
    let before = fixture.records();
    let allocated = slots(&fixture);
    let expiry = (NOW / WINDOW + 2) * WINDOW;
    let witness = fixture.engine.execution_witness();
    fixture.clock.set(expiry - 1);
    assert_eq!(
        fixture
            .runtime
            .block_on(fixture.engine.sweep_expired_slots()),
        Ok(0)
    );
    for (kind, key, expected) in &allocated {
        assert_eq!(
            fixture.store.raw().load(*kind, key).expect("slot"),
            Some(expected.clone())
        );
    }
    // Approval is still valid: deleting the old window cannot license another
    // grant for the exact same retained operation in the new window.
    assert!(expiry < NOW + 300);
    fixture.clock.set(expiry);
    assert_eq!(
        fixture
            .runtime
            .block_on(fixture.engine.sweep_expired_slots()),
        Ok(2)
    );
    assert_eq!(
        fixture
            .runtime
            .block_on(fixture.engine.sweep_expired_slots()),
        Ok(0)
    );
    for (kind, key, _) in &allocated {
        assert_eq!(
            fixture.store.raw().load(*kind, key).expect("expired slot"),
            None
        );
    }
    let after_sweep = fixture.runtime.block_on(replay(
        &fixture.engine,
        &source,
        &acquired,
        disclosure.as_ref(),
    ));
    assert_eq!(fixture.engine.execution_witness(), witness);
    assert_eq!(
        fixture.records(),
        before,
        "claims, allocations and charges remain recorded"
    );
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
    // A fresh proof for another operation cannot consume the original approval.
    let substituted = fixture
        .runtime
        .block_on(bounded_input(&fixture.engine, "after-sweep"));
    assert!(
        fixture
            .runtime
            .block_on(fixture.engine.acquire_content_action(
                &substituted.proof,
                &substituted.action,
                source.approval.clone()
            ))
            .is_err()
    );
    assert_eq!(fixture.records(), before);
    let reopened = fixture.change_and_reopen(Change::None);
    fixture.clock.set(NOW + 86_401);
    let reopened_witness = reopened.execution_witness();
    fixture
        .runtime
        .block_on(replay(&reopened, &source, &acquired, disclosure.as_ref()));
    assert_eq!(reopened.execution_witness(), reopened_witness);
    assert_eq!(fixture.records(), before);
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
    json!({"protocol":protocol.label(), "window_seconds":WINDOW,
        "slot_expiry":expiry, "deleted_before_expiry":0, "deleted_at_expiry":2,
        "original_approval_current_at_sweep":true, "native_snapshot":after_sweep,
        "new_operation_with_old_approval_refused":true,
        "claims_and_recorded_allocations_unchanged":true,
        "replay_after_window_cleanup_and_full_authority_expiry_sends_nothing":true,
        "provider_reads":1})
}

fn matrix(backend: Backend) {
    let cases: Vec<_> = [
        Protocol::Acquisition,
        Protocol::Acknowledged,
        Protocol::LostAcknowledgement,
    ]
    .into_iter()
    .map(|protocol| retained_case(backend, protocol))
    .collect();
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-retention/1",
        "adapter":backend.label(),
        "scope":"real native bounded proof/approval, HTTP and authenticated Unix delivery; expiry-slot sweep on file/TLS PostgreSQL; retained full records serve as replay tombstones",
        "excluded":["epoch changes and rollback floors", "malicious whole-store rollback", "hostile OS or live provider qualification"],
        "cases":cases})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-retention-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write artifact");
    }
    assert_eq!(std::fs::read(path).expect("retained artifact"), artifact);
}

#[test]
fn native_file_retention_fixture_is_current() {
    matrix(Backend::File);
}

#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_retention_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
