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

#[test]
fn retained_native_authority_projection_is_required_and_bound() {
    use base64ct::{Base64, Encoding as _};
    let approved = approved();
    let record = claim_record(
        &approved.command().expect("mutation").request,
        approved.effect().binding(),
        approved.approval(),
        approved.effect().native_authority(),
        NOW,
    )
    .expect("native header");
    let bytes = encode(&record).expect("encode");
    assert!(decode(&bytes).is_ok());
    let original: serde_json::Value = serde_json::from_slice(&bytes).expect("record JSON");
    let evidence = approved.effect().native_authority().private_bytes();
    let mut damaged = evidence.to_vec();
    damaged[0] ^= 1;
    for replacement in [
        None,
        Some("not-canonical-base64".to_owned()),
        Some(Base64::encode_string(&damaged)),
        Some(Base64::encode_string(
            crate::effect::NativeAuthority::oracle([42; 32]).private_bytes(),
        )),
    ] {
        let mut altered = original.clone();
        match replacement {
            Some(value) => altered["authority_canonical_b64"] = serde_json::json!(value),
            None => {
                altered
                    .as_object_mut()
                    .expect("object")
                    .remove("authority_canonical_b64");
            }
        }
        assert!(matches!(
            decode(&serde_json::to_vec(&altered).expect("JSON")),
            Err(GatewayAttemptError::Corrupt)
        ));
    }
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
        .claim_bounded(
            &renewed,
            RESUMED_AT,
            crate::entry::EntryValidation::Oracle { now: RESUMED_AT },
        )
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
            .state
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
        restarted
            .claim_bounded(
                &renewed,
                RESUMED_AT,
                crate::entry::EntryValidation::Oracle { now: RESUMED_AT }
            )
            .await,
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
    let BoundedClaim::Claimed(claim) = attempts
        .claim_bounded(
            approved,
            NOW,
            crate::entry::EntryValidation::Oracle { now: NOW },
        )
        .await
        .expect("claim")
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
    assert_eq!(
        claim.attempt.record.state.stage,
        GatewayAttemptStage::Reserved
    );
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
        granted.attempt.record.state.stage,
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
    next.state.stage = GatewayAttemptStage::NotEntered;
    next.state.refusal = Some("test.no-send".to_owned());
    assert!(!valid_transition(&granted.attempt.record, &next).expect("transition"));
    // Canonical native records also seed the shipping decoder/transition fuzzer.
    // The nonce is private replay evidence, independent of signed effect bytes;
    // a fixed synthetic value makes the corpus reproducible.
    let mut entry = granted.attempt.record.clone();
    entry.nonce = "00112233445566778899aabbccddeeff".to_owned();
    let mut reserved = entry.clone();
    reserved.revision = 1;
    reserved.state.stage = GatewayAttemptStage::Reserved;
    reserved.entry = None;
    let mut refused = reserved.clone();
    refused.revision = 2;
    refused.state.stage = GatewayAttemptStage::NotEntered;
    refused.state.refusal = Some("test.before-grant".to_owned());
    let mut unknown = entry.clone();
    unknown.revision = entry.revision + 1;
    unknown.state.stage = GatewayAttemptStage::Unknown;
    let mut response = entry.clone();
    response.revision = entry.revision + 1;
    response.state.stage = GatewayAttemptStage::ResponseRecorded;
    response.state.response_status = Some(200);
    response.state.response_digest = Some(hex::encode([9; 32]));
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
        store
            .attempts()
            .claim_bounded(
                &approved,
                NOW,
                crate::entry::EntryValidation::Oracle { now: NOW }
            )
            .await,
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

/// Real adapter history with an explicit-time approval oracle. This establishes
/// atomic persistence and original timestamps, not installed resource authority.
async fn admission_conformance(backend: Backend) -> serde_json::Value {
    let store = TestAttempts::open(backend);
    let approved = bounded_approval();
    let command = approved.command().expect("mutation");
    let bound = command.bound.as_ref().expect("capacity");
    let slots = bound
        .counts
        .iter()
        .map(|counter| {
            (
                GatewayRecordKind::CountSlot,
                crate::bounds::count_slot_key(&counter.key, 0),
            )
        })
        .chain(bound.sums.iter().map(|counter| {
            (
                GatewayRecordKind::SumSlot,
                crate::bounds::sum_slot_key(&counter.key, 0),
            )
        }))
        .collect::<Vec<_>>();
    // The original approval expires at NOW + 5. Refusal cannot consume an ID
    // or either capacity unit, even though frontier selection already ran.
    assert!(
        store
            .attempts()
            .claim_bounded(
                &approved,
                NOW,
                crate::entry::EntryValidation::Oracle { now: NOW + 6 }
            )
            .await
            .is_err()
    );
    assert!(
        store
            .attempts()
            .read_effect(&approved)
            .await
            .expect("read")
            .is_none()
    );
    for (kind, key) in &slots {
        assert!(slot_bytes(&store, *kind, *key).await.is_none());
    }
    let BoundedClaim::Claimed(claim) = store
        .attempts()
        .claim_bounded(
            &approved,
            NOW,
            crate::entry::EntryValidation::Oracle { now: NOW + 2 },
        )
        .await
        .expect("admission")
    else {
        panic!("reserved");
    };
    assert_eq!(claim.attempt.record.evaluated_at, NOW + 2);
    assert!(claim.attempt.record.entry.is_none());
    let original = claim.attempt.stored.clone();
    let mut allocated = Vec::new();
    for (kind, key) in &slots {
        allocated.push(slot_bytes(&store, *kind, *key).await.expect("charged"));
    }
    // Reopening does not validate expired admission again or alter its facts.
    // It still cannot grant entry with that expired approval.
    let BoundedClaim::Claimed(reopened) = store
        .reopen()
        .claim_bounded(
            &approved,
            NOW + 6,
            crate::entry::EntryValidation::Oracle { now: NOW + 6 },
        )
        .await
        .expect("reopen")
    else {
        panic!("reopened");
    };
    assert_eq!(reopened.attempt.stored, original);
    assert!(
        reopened
            .grant_entry(
                Arc::clone(&approved),
                crate::entry::EntryValidation::Oracle { now: NOW + 6 },
                NOW + 6,
                &crate::GatewayPreEntry::default()
            )
            .await
            .is_err()
    );
    for ((kind, key), bytes) in slots.iter().zip(allocated) {
        assert_eq!(slot_bytes(&store, *kind, *key).await, Some(bytes));
    }
    serde_json::json!({
        "backend": backend.label(), "authorization_started_at": NOW,
        "admitted_at": NOW + 2, "capacity_records": slots.len(),
        "expired_admission_persists_nothing": true, "reopen_preserves_bytes": true,
        "expired_entry_refused": true, "charges_retained": true, "provider_calls": 0,
    })
}

fn admission_batch_contract(store: &dyn GatewayAttemptStore) -> serde_json::Value {
    let entry = |kind, id, bytes: &[u8]| GatewayRecordEntry {
        kind,
        key: GatewayAttemptKey([id; 32]),
        record: bytes.to_vec(),
        expires_at: None,
    };
    let dependency = entry(GatewayRecordKind::EffectConfiguration, 190, b"current");
    store.insert(&dependency).expect("dependency");
    let entries = [
        entry(GatewayRecordKind::Attempt, 191, b"initial"),
        entry(GatewayRecordKind::EffectAllocation, 192, b"charge"),
    ];
    let dependencies = [(dependency.kind, dependency.key)];
    let missing = [(dependency.kind, GatewayAttemptKey([193; 32]))];
    assert!(
        store
            .fenced_insert_all(&entries, &missing, &mut |snapshots| {
                assert_eq!(snapshots, &[None]);
                Err(GatewayAttemptError::InvalidTransition)
            })
            .is_err()
    );
    assert!(
        store
            .fenced_insert_all(&entries, &dependencies, &mut |snapshots| {
                assert_eq!(snapshots, &[Some(b"current".to_vec())]);
                Err(GatewayAttemptError::InvalidTransition)
            })
            .is_err()
    );
    for row in &entries {
        assert!(store.load(row.kind, &row.key).expect("read").is_none());
    }
    assert_eq!(
        store
            .fenced_insert_all(&entries, &dependencies, &mut |snapshots| {
                assert_eq!(snapshots, &[Some(b"current".to_vec())]);
                Ok(b"admitted".to_vec())
            })
            .expect("insert"),
        GatewayInsert::Inserted
    );
    assert_eq!(
        store.load(entries[0].kind, &entries[0].key).expect("claim"),
        Some(b"admitted".to_vec())
    );
    assert_eq!(
        store
            .load(entries[1].kind, &entries[1].key)
            .expect("charge"),
        Some(b"charge".to_vec())
    );
    assert_eq!(
        store
            .fenced_insert_all(&entries, &dependencies, &mut |_| panic!("replay decision"))
            .expect("replay"),
        GatewayInsert::Exists { index: 0 }
    );
    let competing = [
        entry(GatewayRecordKind::Attempt, 194, b"other"),
        entries[1].clone(),
    ];
    assert_eq!(
        store
            .fenced_insert_all(&competing, &dependencies, &mut |_| panic!(
                "occupied capacity"
            ))
            .expect("collision"),
        GatewayInsert::Exists { index: 1 }
    );
    assert!(
        store
            .load(competing[0].kind, &competing[0].key)
            .expect("other")
            .is_none()
    );
    assert!(
        store
            .fenced_insert_all(
                &competing,
                &[(competing[0].kind, competing[0].key)],
                &mut |_| panic!("overlapping set")
            )
            .is_err()
    );
    serde_json::json!({"dependency_refusal_atomic": true, "missing_dependency_refused": true,
        "first_record_stamped": true, "allocation_unchanged": true,
        "replay_skips_decision": true, "capacity_collision_atomic": true,
        "overlapping_set_refused": true})
}

/// A writer holds the common fence while admission starts. The decision must
/// observe the writer's committed dependency, never its earlier value.
fn admission_dependency_order(store: &Arc<dyn GatewayAttemptStore>) -> serde_json::Value {
    use std::sync::mpsc;
    use std::time::Duration;
    let dependency = (
        GatewayRecordKind::EffectConfiguration,
        GatewayAttemptKey([195; 32]),
    );
    store
        .insert(&GatewayRecordEntry {
            kind: dependency.0,
            key: dependency.1,
            record: b"current".to_vec(),
            expires_at: None,
        })
        .expect("dependency");
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let writer_store = Arc::clone(store);
    let writer = std::thread::spawn(move || {
        writer_store.fenced_replace(&[dependency], &mut |snapshots| {
            assert_eq!(snapshots, &[Some(b"current".to_vec())]);
            locked_tx.send(()).expect("locked");
            release_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("release writer");
            Ok(b"revoked".to_vec())
        })
    });
    locked_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("writer locked");
    let (started_tx, started_rx) = mpsc::channel();
    let admission_store = Arc::clone(store);
    let claim_key = GatewayAttemptKey([196; 32]);
    let charge_key = GatewayAttemptKey([197; 32]);
    let admission = std::thread::spawn(move || {
        let entries = [
            GatewayRecordEntry {
                kind: GatewayRecordKind::Attempt,
                key: claim_key,
                record: b"claim".to_vec(),
                expires_at: None,
            },
            GatewayRecordEntry {
                kind: GatewayRecordKind::EffectAllocation,
                key: charge_key,
                record: b"charge".to_vec(),
                expires_at: None,
            },
        ];
        started_tx.send(()).expect("admission started");
        admission_store.fenced_insert_all(&entries, &[dependency], &mut |snapshots| {
            assert_eq!(snapshots, &[Some(b"revoked".to_vec())]);
            Err(GatewayAttemptError::InvalidTransition)
        })
    });
    started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("admission start");
    release_tx.send(()).expect("release");
    writer.join().expect("writer").expect("updated dependency");
    assert!(matches!(
        admission.join().expect("admission"),
        Err(GatewayAttemptError::InvalidTransition)
    ));
    assert!(
        store
            .load(GatewayRecordKind::Attempt, &claim_key)
            .expect("claim")
            .is_none()
    );
    assert!(
        store
            .load(GatewayRecordKind::EffectAllocation, &charge_key)
            .expect("charge")
            .is_none()
    );
    serde_json::json!({"writer_commits_before_admission_decision": true,
        "decision_observes_changed_dependency": true, "refusal_leaves_no_claim_or_charge": true})
}

#[tokio::test]
async fn native_admission_fixture_is_current() {
    let store = TestAttempts::open(Backend::File);
    let raw = store.raw();
    let (mechanism, dependency_order) = tokio::task::spawn_blocking(move || {
        (
            admission_batch_contract(&*raw),
            admission_dependency_order(&raw),
        )
    })
    .await
    .expect("mechanism history");
    let fixture = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "auths.effect-admission-fixture/1",
        "scope": "file adapter and explicit-time approval oracle; no installed authority or transport claim",
        "mechanism": mechanism, "dependency_order": dependency_order,
        "history": admission_conformance(Backend::File).await,
    })).expect("fixture");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/effect-admission.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &fixture).expect("write fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), fixture);
}

#[tokio::test]
#[ignore = "requires the TLS PostgreSQL fixture"]
async fn postgres_admission_checks_authority_before_atomic_charges() {
    assert!(postgres_configured());
    admission_conformance(Backend::Postgres).await;
    let store = TestAttempts::open(Backend::Postgres);
    let raw = store.raw();
    tokio::task::spawn_blocking(move || {
        admission_batch_contract(&*raw);
        admission_dependency_order(&raw);
    })
    .await
    .expect("contract");
}
