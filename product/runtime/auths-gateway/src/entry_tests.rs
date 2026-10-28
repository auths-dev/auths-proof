//! Native grant corpus and adapter conformance. Synthetic post-verification
//! commands exercise persistence, never claim installed resource authority.
use super::*;
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};

const NOW: u64 = 1_790_000_000;
const RESUMED_AT: u64 = NOW + crate::recipe::ENTRY_DEADLINE_SECONDS + 1;

fn approved() -> Arc<ApprovedEffect> {
    let recipe = crate::CompiledRecipe::compile(
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
    )
    .expect("recipe");
    let arguments = serde_json::json!({
        "operation_id": "synthetic-entry", "record_id": "recTEST0000000001", "replacement": "Approved",
        "operator_namespace": recipe.namespace().as_str(), "recipe_digest": recipe.digest_hex(),
    });
    let command = crate::scenario_tests::admitted(
        &recipe,
        arguments.as_object().expect("arguments"),
        [11; 32],
        Vec::new(),
        60,
        Vec::new(),
        NOW,
    )
    .expect("post-native command");
    Arc::new(
        crate::effect::approve_driver_fixture(command, *recipe.digest(), NOW, None)
            .expect("approval"),
    )
}

fn bounded_approval() -> Arc<ApprovedEffect> {
    use ed25519_dalek::Signer as _;
    let recipes: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/hostile-recipes-v2.json"
    ))
    .expect("recipes");
    let scenarios: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/attempt-scenarios-v3.json"
    ))
    .expect("scenarios");
    let recipe = crate::CompiledRecipe::compile(
        &serde_json::to_vec(&recipes["bases"]["stripe"]["recipe"]).expect("recipe"),
        &serde_json::to_vec(&recipes["bases"]["stripe"]["lock"]).expect("lock"),
    )
    .expect("compile");
    let mut setup = scenarios["defaults"]["stripe"].clone();
    setup["grant_policy"]["max_count"] = serde_json::json!(1);
    setup["grant_policy"]["sum_limit"] = serde_json::json!(500);
    let mut arguments = setup["arguments"].as_object().expect("arguments").clone();
    arguments.insert(
        "operator_namespace".to_owned(),
        serde_json::json!(recipe.namespace().as_str()),
    );
    arguments.insert(
        "recipe_digest".to_owned(),
        serde_json::json!(recipe.digest_hex()),
    );
    let command = crate::scenario_tests::admitted(
        &recipe,
        &arguments,
        [11; 32],
        Vec::new(),
        3600,
        vec![crate::bounds::BoundLink {
            subject: crate::harness::Signer::new(0x44).principal,
            policy: crate::scenario_tests::policy_from_members(&setup["grant_policy"]),
        }],
        NOW,
    )
    .expect("bounded command");
    let approved =
        crate::effect::approve_driver_fixture(command.clone(), *recipe.digest(), NOW, None)
            .expect("approval");
    let request = approved
        .effect()
        .approval_request(NOW, NOW + 5)
        .expect("short approval");
    let signature = ed25519_dalek::SigningKey::from_bytes(&[29; 32])
        .sign(&request.signing_message().expect("signing message"))
        .to_bytes();
    Arc::new(
        crate::effect::approve_driver_fixture(
            command,
            *recipe.digest(),
            NOW,
            Some(request.with_signature(signature)),
        )
        .expect("short approved effect"),
    )
}

async fn slot_bytes(
    store: &TestAttempts,
    kind: GatewayRecordKind,
    key: [u8; 32],
) -> Option<Vec<u8>> {
    let raw = store.raw();
    tokio::task::spawn_blocking(move || raw.load(kind, &GatewayAttemptKey(key)))
        .await
        .expect("slot read task")
        .expect("slot read")
}

/// Reopening a reservation retains its one count/sum allocation and initial
/// evidence. Only fresh approval and a new acknowledged revision grant entry.
#[allow(
    clippy::too_many_lines,
    reason = "one ordered crash/reopen history retains its audit assertions together"
)]
async fn reservation_restart(backend: Backend) -> serde_json::Value {
    let store = TestAttempts::open(backend);
    let approved = bounded_approval();
    let initial = crate::GatewayPreEntry {
        observations: Vec::new(),
        basis: Some(crate::GatewayRelativeBasis {
            value: 1001,
            response_digest: [1; 32],
            read_at: NOW,
        }),
    };
    let fresh = crate::GatewayPreEntry {
        observations: Vec::new(),
        basis: Some(crate::GatewayRelativeBasis {
            value: 1002,
            response_digest: [2; 32],
            read_at: RESUMED_AT,
        }),
    };
    let claim = reserved(store.attempts(), &approved)
        .await
        .record_checkpoint(&initial)
        .await
        .expect("first checkpoint");
    assert_eq!(claim.attempt.record.revision, 2);
    let original_bytes = claim.attempt.stored.clone();
    let original_approval = claim.attempt.record.approval_canonical.clone();
    let recipe_digest = digest_bytes(&claim.attempt.record.recipe_digest).expect("recipe digest");
    let counters = claim.attempt.record.counters().expect("counters");
    assert!(counters.iter().any(|c| c.kind == GatewayCounterKind::Count));
    assert!(counters.iter().any(|c| c.kind == GatewayCounterKind::Sum));
    let slot_keys = counters
        .iter()
        .map(|counter| match counter.kind {
            GatewayCounterKind::Count => (
                GatewayRecordKind::CountSlot,
                crate::bounds::count_slot_key(&counter.counter, counter.slot),
            ),
            GatewayCounterKind::Sum => (
                GatewayRecordKind::SumSlot,
                crate::bounds::sum_slot_key(&counter.counter, counter.slot),
            ),
        })
        .collect::<Vec<_>>();
    let mut slots_before = Vec::new();
    for (kind, key) in &slot_keys {
        slots_before.push(slot_bytes(&store, *kind, *key).await.expect("allocated"));
    }
    let stale = stale_copy(&claim);
    drop(claim);
    let restarted = store.reopen();
    let renewed = Arc::new(
        crate::effect::approve_driver_fixture(
            approved.command().expect("mutation command").clone(),
            recipe_digest,
            RESUMED_AT,
            None,
        )
        .expect("renewed approval"),
    );
    assert_eq!(approved.effect().binding(), renewed.effect().binding());
    let BoundedClaim::Claimed(claim) = restarted
        .claim_bounded(&renewed, RESUMED_AT)
        .await
        .expect("reopen")
    else {
        panic!("existing reservation must not exhaust again")
    };
    assert_eq!(claim.attempt.stored, original_bytes);
    assert!(
        stale_copy(&claim)
            .grant_entry(
                Arc::clone(&renewed),
                crate::entry::EntryValidation::Oracle { now: RESUMED_AT },
                NOW,
                &fresh,
            )
            .await
            .is_err(),
        "original submission deadline cannot authorize a resumed grant"
    );
    assert!(
        stale_copy(&claim)
            .grant_entry(
                Arc::clone(&approved),
                crate::entry::EntryValidation::Oracle { now: RESUMED_AT },
                RESUMED_AT,
                &fresh,
            )
            .await
            .is_err(),
        "expired approval cannot authorize a resumed grant"
    );
    let claim = claim
        .record_checkpoint(&fresh)
        .await
        .expect("fresh checkpoint is retained at grant");
    assert_eq!(
        claim.attempt.stored, original_bytes,
        "first checkpoint remains immutable"
    );
    let (granted, permit) = claim
        .grant_entry(
            Arc::clone(&renewed),
            crate::entry::EntryValidation::Oracle { now: RESUMED_AT },
            RESUMED_AT,
            &fresh,
        )
        .await
        .expect("resumed grant");
    drop(permit);
    assert_eq!(granted.attempt.record.revision, 3);
    assert_eq!(granted.attempt.record.approval_canonical, original_approval);
    assert_eq!(
        granted
            .attempt
            .record
            .pre_entry
            .as_ref()
            .expect("initial evidence")
            .decode()
            .expect("decode"),
        initial
    );
    let audit = granted.attempt.record.entry.as_ref().expect("grant audit");
    assert_eq!(audit.revision, 3);
    assert_eq!(audit.authorization_started_at, RESUMED_AT);
    assert_ne!(audit.approval_canonical, original_approval);
    assert_eq!(
        audit.approval_canonical.as_bytes(),
        renewed
            .approval()
            .to_private_bytes()
            .expect("new approval")
            .as_slice()
    );
    assert_eq!(
        audit
            .pre_entry
            .as_ref()
            .expect("fresh evidence")
            .decode()
            .expect("decode"),
        fresh
    );
    let snapshot = granted.attempt.record.snapshot(true).expect("snapshot");
    assert_eq!(snapshot.revision(), 3);
    assert_eq!(snapshot.pre_entry(), Some(&fresh));
    assert_eq!(snapshot.stage(), GatewayAttemptStage::Unknown);
    assert!(
        stale
            .grant_entry(
                Arc::clone(&renewed),
                crate::entry::EntryValidation::Oracle { now: RESUMED_AT },
                RESUMED_AT,
                &fresh,
            )
            .await
            .is_err(),
        "stale reservation cannot grant again"
    );
    assert!(matches!(
        restarted.claim_bounded(&renewed, RESUMED_AT).await,
        Err(GatewayAttemptError::Replay)
    ));
    for ((kind, key), before) in slot_keys.iter().zip(&slots_before) {
        assert_eq!(
            &slot_bytes(&store, *kind, *key).await.expect("retained"),
            before
        );
    }
    for counter in &counters {
        let (kind, key) = match counter.kind {
            GatewayCounterKind::Count => (
                GatewayRecordKind::CountSlot,
                crate::bounds::count_slot_key(&counter.counter, counter.slot + 1),
            ),
            GatewayCounterKind::Sum => (
                GatewayRecordKind::SumSlot,
                crate::bounds::sum_slot_key(&counter.counter, counter.slot + 1),
            ),
        };
        assert!(slot_bytes(&store, kind, key).await.is_none());
    }
    serde_json::json!({
        "initial_revision": 1, "checkpoint_revision": 2, "grant_revision": 3,
        "reservation_slots_retained": counters.len(), "additional_slots": 0,
        "old_deadline_refused": true, "expired_approval_refused": true,
        "stale_grant_refused": true, "initial_evidence_retained": true,
        "grant_audit": serde_json::to_value(audit).expect("audit"),
    })
}

#[tokio::test]
#[ignore = "requires the TLS PostgreSQL fixture"]
async fn postgres_reservation_restart_retains_capacity_and_requires_fresh_approval() {
    assert!(postgres_configured());
    reservation_restart(Backend::Postgres).await;
}

async fn reserved(
    attempts: &GatewayAttempts,
    approved: &Arc<ApprovedEffect>,
) -> ClaimedGatewayAttempt {
    let BoundedClaim::Claimed(claim) = attempts.claim_bounded(approved, NOW).await.expect("claim")
    else {
        panic!("claim refused")
    };
    *claim
}

fn stale_copy(claim: &ClaimedGatewayAttempt) -> ClaimedGatewayAttempt {
    ClaimedGatewayAttempt {
        attempt: Attempt {
            store: Arc::clone(&claim.attempt.store),
            key: claim.attempt.key,
            stored: claim.attempt.stored.clone(),
            record: claim.attempt.record.clone(),
        },
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "canonical records and transitions are emitted from the same native grant"
)]
async fn native_entry_fixture_is_current() {
    let store = TestAttempts::open(Backend::File);
    let approved = approved();
    let claim = reserved(store.attempts(), &approved).await;
    assert_eq!(claim.attempt.record.stage, GatewayAttemptStage::Reserved);
    assert!(claim.attempt.record.entry.is_none());
    let stale = stale_copy(&claim);
    let (granted, permit) = claim
        .grant_entry(
            Arc::clone(&approved),
            crate::entry::EntryValidation::Oracle { now: NOW },
            NOW,
            &crate::GatewayPreEntry::default(),
        )
        .await
        .expect("grant");
    assert_eq!(
        granted.attempt.record.stage,
        GatewayAttemptStage::EntryGranted
    );
    assert_eq!(
        permit.request().body(),
        approved.command().expect("mutation command").request.body()
    );
    let audit = serde_json::to_value(granted.attempt.record.entry.as_ref().expect("audit"))
        .expect("audit JSON");
    drop(permit); // A crash before send still consumes the one grant.
    assert!(
        stale
            .grant_entry(
                Arc::clone(&approved),
                crate::entry::EntryValidation::Oracle { now: NOW },
                NOW,
                &crate::GatewayPreEntry::default(),
            )
            .await
            .is_err()
    );
    let read = store
        .reopen()
        .read(
            approved
                .command()
                .expect("mutation command")
                .request
                .namespace(),
            approved
                .command()
                .expect("mutation command")
                .request
                .operation_id(),
        )
        .await
        .expect("read")
        .expect("retained");
    assert_eq!(read.stage(), GatewayAttemptStage::Unknown);
    let mut next = granted.attempt.record.clone();
    next.revision += 1;
    next.stage = GatewayAttemptStage::NotEntered;
    next.refusal = Some("test.no-send".to_owned());
    assert!(!valid_transition(&granted.attempt.record, &next).expect("transition"));
    // Canonical native records also seed the shipping decoder/transition fuzzer.
    // The nonce is private replay evidence, independent of signed effect bytes;
    // a fixed synthetic value makes the corpus reproducible.
    let mut entry = granted.attempt.record.clone();
    entry.nonce = "00112233445566778899aabbccddeeff".to_owned();
    let mut reserved = entry.clone();
    reserved.revision = 1;
    reserved.stage = GatewayAttemptStage::Reserved;
    reserved.entry = None;
    let mut refused = reserved.clone();
    refused.revision = 2;
    refused.stage = GatewayAttemptStage::NotEntered;
    refused.refusal = Some("test.before-grant".to_owned());
    let mut unknown = entry.clone();
    unknown.revision = entry.revision + 1;
    unknown.stage = GatewayAttemptStage::Unknown;
    let mut response = entry.clone();
    response.revision = entry.revision + 1;
    response.stage = GatewayAttemptStage::ResponseRecorded;
    response.response_status = Some(200);
    response.response_digest = Some(hex::encode([9; 32]));
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/target_gateway_attempt");
    let write_seed = |name: &str, bytes: &[u8]| {
        let path = root.join(name);
        if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
            std::fs::write(&path, bytes).expect("seed");
        }
        assert_eq!(std::fs::read(path).expect("seed"), bytes);
    };
    for (name, record) in [
        ("reserved", &reserved),
        ("entry-granted", &entry),
        ("not-entered", &refused),
        ("unknown", &unknown),
        ("response-recorded", &response),
    ] {
        record.snapshot(false).expect("valid native record");
        write_seed(
            &format!("record-{name}-synthetic-entry"),
            &encode(record).expect("encode"),
        );
    }
    for (name, old, new) in [
        ("reserved-to-entry-granted", &reserved, &entry),
        ("reserved-to-not-entered", &reserved, &refused),
        ("entry-granted-to-unknown", &entry, &unknown),
        ("entry-granted-to-response-recorded", &entry, &response),
    ] {
        assert!(valid_transition(old, new).expect("transition"));
        let old = encode(old).expect("old");
        let mut bytes = u32::try_from(old.len())
            .expect("bounded length")
            .to_be_bytes()
            .to_vec();
        bytes.extend_from_slice(&old);
        bytes.extend_from_slice(&encode(new).expect("new"));
        write_seed(&format!("transition-{name}-synthetic-entry"), &bytes);
    }
    let fixture = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "auths.effect-entry-fixture/2",
        "reservation_restart": reservation_restart(Backend::File).await,
        "scope": "native synthetic post-verification grant; no provider entry or installed authority claim",
        "reserved_stage": "reserved", "granted_stage": "entry-granted", "restart_projection": "unknown",
        "second_grant_refused": true, "post_grant_nonentry_refused": true, "entry_audit": audit,
    })).expect("fixture");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/effect-entry.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &fixture).expect("write fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), fixture);
}

async fn grant_conformance(backend: Backend) {
    let store = TestAttempts::open(backend);
    let approved = approved();
    let claim = reserved(store.attempts(), &approved).await;
    let stale = stale_copy(&claim);
    let pre_entry = crate::GatewayPreEntry::default();
    let (left, right) = tokio::join!(
        claim.grant_entry(
            Arc::clone(&approved),
            crate::entry::EntryValidation::Oracle { now: NOW },
            NOW,
            &pre_entry,
        ),
        stale.grant_entry(
            Arc::clone(&approved),
            crate::entry::EntryValidation::Oracle { now: NOW },
            NOW,
            &pre_entry,
        ),
    );
    assert_eq!(
        usize::from(left.is_ok()) + usize::from(right.is_ok()),
        1,
        "one acknowledged permit"
    );
    let (claim, permit) = left.or(right).expect("winner");
    drop(permit);
    assert!(
        claim
            .record_not_entered("test.no-send", None)
            .await
            .is_err(),
        "even unsent grants retain uncertainty"
    );
    let snapshot = store
        .reopen()
        .read(
            approved
                .command()
                .expect("mutation command")
                .request
                .namespace(),
            approved
                .command()
                .expect("mutation command")
                .request
                .operation_id(),
        )
        .await
        .expect("reopen")
        .expect("retained");
    assert_eq!(snapshot.stage(), GatewayAttemptStage::Unknown);
    assert!(matches!(
        store.attempts().claim_bounded(&approved, NOW).await,
        Err(GatewayAttemptError::Replay)
    ));
}

#[tokio::test]
async fn file_grant_has_one_winner_and_no_restart_permit() {
    grant_conformance(Backend::File).await;
}

#[tokio::test]
#[ignore = "requires the TLS PostgreSQL fixture"]
async fn postgres_grant_has_one_winner_and_no_restart_permit() {
    assert!(postgres_configured());
    grant_conformance(Backend::Postgres).await;
}
