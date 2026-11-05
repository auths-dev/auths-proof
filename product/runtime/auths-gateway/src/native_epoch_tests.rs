//! A partition has one activated epoch; old facts are not new entry authority.
use super::*;
use crate::effect::EffectPolicy;

const PENDING: &str = "epoch-pending";

async fn input(engine: &GatewayEngine, operation: &str) -> Input {
    let call = engine
        .content_authorization_call(br#"{"record_id":"recTEST0000000001"}"#, operation)
        .await
        .expect("native call");
    let signed = tool_fixture_until(&call, NOW, NOW + 86_400).expect("native proof");
    let effect = engine
        .compile_content_action(&signed.proof, &signed.action)
        .await
        .expect("effect");
    Input {
        proof: signed.proof,
        action: signed.action,
        approval: Input::approval(&effect, Change::None),
    }
}

async fn acquire(
    engine: &GatewayEngine,
    input: &Input,
) -> Result<crate::AcquisitionSnapshot, crate::GatewaySubmitResult> {
    engine
        .acquire_content_action(&input.proof, &input.action, input.approval.clone())
        .await
}

fn next_epoch(fixture: &Fixture) -> GatewayEngine {
    let mut candidate_controls = controls(fixture.clock.clone(), 29);
    candidate_controls.policy = EffectPolicy::new(
        "test-partition".to_owned(),
        2,
        SigningKey::from_bytes(&[29; 32]).verifying_key().to_bytes(),
    )
    .expect("epoch-two policy");
    let attempts = GatewayAttempts::new(
        fixture.store.reopen().store(),
        candidate_controls.policy.clone(),
    )
    .expect("new epoch owner");
    let (candidate, _) = fixture.runtime.block_on(load_controlled_engine(
        &fixture.setup,
        "epoch-two",
        attempts,
        candidate_controls,
    ));
    candidate
}

fn activate(fixture: &Fixture, candidate: &GatewayEngine, pending: &Input) -> ([u8; 32], [u8; 32]) {
    let old_configuration = fixture.engine.shared_configuration().expect("old config");
    let new_configuration = candidate.shared_configuration().expect("new config");
    assert_eq!(
        old_configuration.key(),
        new_configuration.key(),
        "epoch changes must share the same partition control and writer fence"
    );
    assert!(
        candidate.initialize_effect_configuration().is_err(),
        "joining a new epoch must not create a parallel active authority"
    );
    assert!(
        fixture
            .runtime
            .block_on(candidate.compile_content_action(&pending.proof, &pending.action))
            .is_err(),
        "operator activation is required"
    );
    let before = candidate
        .effect_configuration_revision()
        .expect("operator review");
    candidate
        .activate_effect_configuration(before)
        .expect("activate epoch two");
    let activated = candidate
        .effect_configuration_revision()
        .expect("activated revision");
    assert_ne!(activated, before);
    (before, activated)
}

fn one_case(backend: Backend) -> Value {
    let fixture = Fixture::new(backend);
    let previous = fixture.runtime.block_on(input(&fixture.engine, SOURCE));
    let previous_result = fixture
        .runtime
        .block_on(acquire(&fixture.engine, &previous))
        .expect("epoch-one GET");
    let pending = fixture.runtime.block_on(input(&fixture.engine, PENDING));
    let original = fixture
        .runtime
        .block_on(
            fixture
                .engine
                .compile_content_action(&pending.proof, &pending.action),
        )
        .expect("old proof and approval start current");
    let old_id = original.binding().id();
    let old_witness = fixture.engine.execution_witness();
    let candidate = next_epoch(&fixture);
    let (before, activated) = activate(&fixture, &candidate, &pending);
    let records_before_refusals = fixture.records();
    assert!(
        fixture
            .runtime
            .block_on(acquire(&fixture.engine, &pending))
            .is_err(),
        "a cached epoch-one host cannot grant new entry"
    );
    let next_effect = fixture
        .runtime
        .block_on(candidate.compile_content_action(&pending.proof, &pending.action))
        .expect("same native proof is still authorized in epoch two");
    assert_ne!(next_effect.binding().id(), old_id);
    assert!(
        fixture
            .runtime
            .block_on(acquire(&candidate, &pending))
            .is_err(),
        "old epoch approval cannot authorize a new epoch effect"
    );
    assert_eq!(fixture.records(), records_before_refusals);
    assert_eq!(fixture.engine.execution_witness(), old_witness);
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
    assert!(
        fixture
            .engine
            .activate_effect_configuration(activated)
            .is_err(),
        "even a fresh operator review cannot reactivate a lower epoch"
    );
    assert!(
        candidate.activate_effect_configuration(before).is_err(),
        "stale operator tokens lose the shared CAS"
    );
    assert_eq!(
        candidate
            .effect_configuration_revision()
            .expect("no downgrade"),
        activated
    );
    let current = Input {
        proof: pending.proof.clone(),
        action: pending.action.clone(),
        approval: Input::approval(&next_effect, Change::None),
    };
    let current_result = fixture
        .runtime
        .block_on(acquire(&candidate, &current))
        .expect("new exact approval permits one current-epoch GET");
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 2);
    retained_history(
        &fixture,
        &candidate,
        &previous,
        &previous_result,
        &current,
        &current_result,
    )
}

fn retained_history(
    fixture: &Fixture,
    candidate: &GatewayEngine,
    previous: &Input,
    previous_result: &crate::AcquisitionSnapshot,
    current: &Input,
    current_result: &crate::AcquisitionSnapshot,
) -> Value {
    let records = fixture.records();
    assert_eq!(records.len(), 2, "both epochs retain their operation facts");
    let mut allocations: Vec<u64> = records
        .iter()
        .map(|bytes| {
            let record: Value = serde_json::from_slice(bytes).expect("retained record");
            record["state"]["facts"]["allocation"]
                .as_u64()
                .expect("lifetime allocation")
        })
        .collect();
    allocations.sort_unstable();
    assert_eq!(
        allocations,
        [0, 1],
        "epoch changes cannot reset source lifetime capacity"
    );
    let old_witness = fixture.engine.execution_witness();
    let current_witness = candidate.execution_witness();
    assert_eq!(
        fixture
            .runtime
            .block_on(acquire(&fixture.engine, previous))
            .expect("historical epoch-one replay"),
        *previous_result
    );
    assert_eq!(
        fixture
            .runtime
            .block_on(acquire(candidate, current))
            .expect("current epoch replay"),
        *current_result
    );
    assert_eq!(fixture.engine.execution_witness(), old_witness);
    assert_eq!(candidate.execution_witness(), current_witness);
    assert_eq!(fixture.records(), records);
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 2);
    let raw = fixture
        .store
        .raw()
        .load(
            GatewayRecordKind::EffectConfiguration,
            &candidate
                .shared_configuration()
                .expect("active control")
                .key(),
        )
        .expect("control load")
        .expect("one control");
    let control: Value = serde_json::from_slice(&raw).expect("control");
    assert_eq!(control["schema"], "auths.effect-configuration/2");
    assert_eq!(control["epoch"], 2);
    json!({"activated_epoch":2, "one_shared_partition_control":true,
        "cached_old_epoch_entry_refused":true, "same_native_proof_still_authorized":true,
        "old_approval_new_epoch_refused":true, "fresh_operator_downgrade_refused":true,
        "stale_operator_review_refused":true, "old_and_new_epoch_history_retained":true,
        "historical_replay_recreates_no_permit_or_charge":true,
        "previous_epoch_snapshot":previous_result, "current_epoch_snapshot":current_result,
        "lifetime_allocation_slots":allocations, "provider_reads":2})
}

fn matrix(backend: Backend) {
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-epoch-fence/1",
        "adapter":backend.label(), "case":one_case(backend),
        "independent_generation_floor":generation_floor_case(backend),
        "scope":"actual native proofs and exact approvals, shared activation fence, real HTTP and two engine/store instances; public fixture keys and maintained clock",
        "excluded":["malicious store rollback without an independent anchor", "all protocol race schedules", "hostile OS and live-provider qualification"]})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-epoch-fence-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write artifact");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}

fn generation_floor_case(backend: Backend) -> Value {
    use crate::native_process_tests::load_controlled_engine_at_generation;
    use std::num::NonZeroU64;
    let fixture = Fixture::new(backend);
    let template = crate::harness::fixture_connection(&recipe()).expect("template");
    let shared = SharedConnection::new(
        fixture.store.raw(),
        template.provider_kind().clone(),
        template.alias().clone(),
    );
    let current = fixture
        .runtime
        .block_on(shared.load())
        .expect("load")
        .expect("connection");
    let floor = crate::GenerationFloor::new(fixture.setup.root.clone());
    floor
        .initialize(current.record())
        .expect("independent initial floor");
    let key = crate::connection::connection_key(template.provider_kind(), template.alias());
    let old = fixture
        .store
        .raw()
        .load(GatewayRecordKind::Connection, &key)
        .expect("load")
        .expect("connection");
    let (next, record) = fixture
        .runtime
        .block_on(load_controlled_engine_at_generation(
            &fixture.setup,
            "generation-two",
            fixture.store.attempts().clone(),
            controls(fixture.clock.clone(), 29),
            NonZeroU64::new(2).expect("generation"),
        ));
    let next = next.with_generation_floor(floor.clone());
    fixture
        .runtime
        .block_on(shared.replace(&current, &record))
        .expect("generation-two install");
    let signed = fixture.runtime.block_on(input(&next, "floor-positive"));
    let accepted = fixture
        .runtime
        .block_on(acquire(&next, &signed))
        .expect("current floor positive");
    assert_eq!(accepted.stage, crate::AcquisitionStage::ResponseRecorded);
    let raw = fixture.store.raw();
    let newer = raw
        .load(GatewayRecordKind::Connection, &key)
        .expect("load")
        .expect("new connection");
    let floor_path = fixture.setup.root.join("connection-floor.json");
    let retained_floor = std::fs::read(&floor_path).expect("accepted independent floor");
    let records = fixture.records();
    let witness = next.execution_witness();
    // Restore only the database connection. The separately retained floor is
    // deliberately not restored; this is the supported backup premise.
    raw.replace(GatewayRecordKind::Connection, &key, &newer, &old)
        .expect("isolated connection rollback");
    let mut checks = Vec::new();
    for name in [
        "older-connection",
        "same-generation-substitution",
        "missing-floor",
        "malformed-floor",
        "obsolete-floor",
    ] {
        if name == "same-generation-substitution" {
            raw.replace(GatewayRecordKind::Connection, &key, &old, &newer)
                .expect("restore current generation");
        }
        change_floor(name, &floor_path, &retained_floor);
        assert!(
            fixture
                .runtime
                .block_on(next.compile_content_action(&signed.proof, &signed.action))
                .is_err(),
            "{name}"
        );
        assert_eq!(next.execution_witness(), witness);
        assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.records(), records);
        checks.push(
            json!({"case":name,"refused_before_custody_and_entry":true,"attempts_unchanged":true}),
        );
        // Only the test operator restores the independent anchor. Runtime may
        // never bootstrap a missing floor from a restored database record.
        if name == "missing-floor" {
            assert!(!floor_path.exists());
        }
        std::fs::write(&floor_path, &retained_floor).expect("operator restores exact anchor");
        std::fs::set_permissions(&floor_path, std::fs::Permissions::from_mode(0o600))
            .expect("private floor");
    }
    assert_eq!(
        fixture
            .runtime
            .block_on(acquire(&next, &signed))
            .expect("retained exact replay"),
        accepted
    );
    assert_eq!(next.execution_witness(), witness);
    json!({"current_generation":2,"current_positive_provider_reads":1,"cases":checks,
        "premise":"host-local independent floor survives database backup/restore",
        "excluded":"rollback of both the complete store and every independent floor"})
}

#[test]
fn native_file_epoch_fence_fixture_is_current() {
    matrix(Backend::File);
}

#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_epoch_fence_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}

fn change_floor(name: &str, path: &Path, retained: &[u8]) {
    match name {
        "same-generation-substitution" | "obsolete-floor" => {
            let mut value: Value = serde_json::from_slice(retained).expect("floor");
            if name == "same-generation-substitution" {
                value["record_sha256"] = json!("00".repeat(32));
            } else {
                value["schema"] = json!("auths.gateway-generation-floor/0");
            }
            std::fs::write(path, serde_json::to_vec(&value).expect("floor"))
                .expect("changed floor");
        }
        "missing-floor" => std::fs::remove_file(path).expect("remove floor"),
        "malformed-floor" => std::fs::write(path, b"{").expect("malformed"),
        "older-connection" => {}
        _ => unreachable!("closed floor corpus"),
    }
}
