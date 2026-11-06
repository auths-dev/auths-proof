//! Native parent membership, participant read charges and real durable child
//! grants. No credential, provider I/O, response or completed predicate is claimed.
use super::admission_tests::{FaultStore, Setup};
use super::*;
use crate::effect::{ApprovedEffect, PrerequisiteKind};
use crate::store_testkit::{Backend, postgres_configured};

fn recipe_fixture() -> CompiledRecipe {
    let (source, lock) = h::recipe_sources(&json!({}), &Value::Null).unwrap();
    let mut source: Value = serde_json::from_slice(&source).unwrap();
    source["pre_entry"] = json!({"path": source["observation"]["path"],
        "pointers":["/fields/DemoStatus"], "maximum_response_bytes":16384});
    CompiledRecipe::compile(&serde_json::to_vec(&source).unwrap(), &lock).unwrap()
}

fn approved(setup: &Setup) -> Arc<ApprovedEffect> {
    Arc::new(approve(
        compile_mutation_effect(
            &setup
                .policy
                .installation(
                    &setup.recipe,
                    &setup.native.context,
                    &setup.connection,
                    crate::QualificationPolicy::Optional,
                    [12; 32],
                )
                .with_enrollment(Some(&setup.native.tree)),
            NOW,
            &setup.native.action.proof,
            &setup.native.action.action,
        )
        .unwrap(),
    ))
}

fn key(setup: &Setup, child: bool) -> crate::GatewayAttemptKey {
    let parent = crate::GatewayAttemptKey::for_operation(
        &setup.policy,
        setup.recipe.namespace(),
        &crate::LogicalOperationId::parse("initial").unwrap(),
    )
    .unwrap();
    if child {
        crate::store::fixture_prerequisite_key(parent, 0)
    } else {
        parent
    }
}

async fn bytes(setup: &Setup, child: bool) -> Option<Vec<u8>> {
    let key = key(setup, child);
    let store = setup.backend.raw();
    tokio::task::spawn_blocking(move || {
        store.load(crate::GatewayRecordKind::Attempt, &key).unwrap()
    })
    .await
    .unwrap()
}

async fn parent(setup: &Setup, approved: &Arc<ApprovedEffect>) {
    let attempts = setup.attempts(Arc::clone(&setup.store));
    let crate::store::BoundedClaim::Claimed(claimed) = attempts
        .claim_bounded(approved, NOW, setup.validation())
        .await
        .unwrap()
    else {
        panic!("parent reservation");
    };
    drop(claimed);
}

async fn read_rows(setup: &Setup, approved: &ApprovedEffect) -> Vec<Option<Value>> {
    let declarations = approved
        .effect()
        .binding()
        .prerequisite_engagement_reservations(0, 16384)
        .unwrap();
    let mut rows = Vec::new();
    for declaration in declarations {
        let key = crate::store::fixture_engagement_allocation_key(&declaration.key, 0);
        let store = setup.backend.raw();
        rows.push(
            tokio::task::spawn_blocking(move || {
                store
                    .load(crate::GatewayRecordKind::EffectAllocation, &key)
                    .unwrap()
                    .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap())
            })
            .await
            .unwrap(),
        );
    }
    rows
}

#[allow(
    clippy::too_many_lines,
    reason = "one native child reservation/grant history and protocol substitutions"
)]
async fn lifecycle(backend: Backend) -> Value {
    let setup = Setup::with_recipe(backend, recipe_fixture(), [1; 32]).await;
    let approved = approved(&setup);
    let binding: Value =
        serde_json::from_slice(&approved.effect().binding().to_private_bytes().unwrap()).unwrap();
    assert_eq!(binding["prerequisite_budgets"].as_array().unwrap().len(), 1);
    assert_eq!(
        binding["prerequisite_budgets"][0]["reservations"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    for case in 0..6 {
        let mut changed = binding.clone();
        match case {
            0 => changed["prerequisite_budgets"][0]["index"] = json!(1),
            1 => changed["prerequisite_budgets"][0]["maximum_response_bytes"] = json!(0),
            2 => {
                changed["prerequisite_budgets"][0]["reservations"][0]["unit"] =
                    json!("mutation-count");
            }
            3 => {
                changed["prerequisite_budgets"][0]["reservations"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            4 => changed["prerequisite_budgets"][0]["reservations"][0]["ceiling"] = json!(64),
            _ => changed["prerequisite_budgets"][0]["maximum_response_bytes"] = json!(65537),
        }
        assert!(
            EffectBinding::from_private_bytes(&serde_json_canonicalizer::to_vec(&changed).unwrap())
                .is_err()
        );
    }
    let attempts = setup.attempts(Arc::clone(&setup.store));
    assert!(
        attempts
            .claim_prerequisite(
                &approved,
                PrerequisiteKind::PreEntry,
                NOW,
                setup.validation()
            )
            .await
            .is_err(),
        "no source reservation"
    );
    parent(&setup, &approved).await;
    let parent_before = bytes(&setup, false).await.unwrap();
    let parent_wire: Value = serde_json::from_slice(&parent_before).unwrap();
    let crate::AcquisitionClaim::Reserved(reserved) = attempts
        .claim_prerequisite(
            &approved,
            PrerequisiteKind::PreEntry,
            NOW,
            setup.validation(),
        )
        .await
        .unwrap()
    else {
        panic!("child reservation");
    };
    let before = bytes(&setup, true).await.unwrap();
    let child_wire: Value = serde_json::from_slice(&before).unwrap();
    let charges = child_wire["engagement_allocations"].as_array().unwrap();
    assert_eq!(charges.len(), 2);
    assert!(
        charges
            .iter()
            .all(|r| r["reservation"]["unit"] == "acquisition-count")
    );
    assert!(
        parent_wire["engagement_allocations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["reservation"]["unit"] == "mutation-count")
    );
    assert_ne!(
        parent_wire["engagement_allocations"],
        child_wire["engagement_allocations"]
    );
    // A common header accepts typed primary/prerequisite data, but the state
    // owner must reject attaching write charges to an acquisition child.
    let mut substituted = child_wire.clone();
    substituted["engagement_allocations"] = parent_wire["engagement_allocations"].clone();
    assert!(
        crate::store::fixture_journal_revision(
            &serde_json_canonicalizer::to_vec(&substituted).unwrap()
        )
        .is_err()
    );
    substituted = child_wire.clone();
    substituted["state"]["facts"]["plan"]["plan"]["index"] = json!(1);
    assert!(
        crate::store::fixture_journal_revision(
            &serde_json_canonicalizer::to_vec(&substituted).unwrap()
        )
        .is_err()
    );
    let rows = read_rows(&setup, &approved).await;
    assert!(rows.iter().all(Option::is_some));
    let crate::AcquisitionClaim::Reserved(replay) = attempts
        .claim_prerequisite(
            &approved,
            PrerequisiteKind::PreEntry,
            NOW,
            setup.validation(),
        )
        .await
        .unwrap()
    else {
        panic!("child replay");
    };
    assert_eq!(bytes(&setup, true).await.unwrap(), before);
    assert_eq!(read_rows(&setup, &approved).await, rows);
    let (granted, permit) = reserved
        .grant_entry(Arc::clone(&approved), setup.validation(), NOW)
        .await
        .unwrap();
    drop((granted, permit));
    assert!(
        replay
            .grant_entry(Arc::clone(&approved), setup.validation(), NOW)
            .await
            .is_err()
    );
    let reopened = setup.attempts(setup.backend.raw());
    let crate::AcquisitionClaim::Existing(snapshot) = reopened
        .claim_prerequisite(
            &approved,
            PrerequisiteKind::PreEntry,
            NOW,
            setup.validation(),
        )
        .await
        .unwrap()
    else {
        panic!("retained child facts");
    };
    assert_eq!(snapshot.stage, crate::AcquisitionStage::Unknown);
    assert_eq!(snapshot.reserved_calls, 1);
    assert_eq!(snapshot.reserved_bytes, 16384);
    assert_eq!(bytes(&setup, false).await.unwrap(), parent_before);
    assert_eq!(read_rows(&setup, &approved).await, rows);
    json!({"binding":binding, "read_allocation_rows":rows, "child_snapshot":snapshot,
        "parent_write_charge_unchanged":true, "replay_added_no_charge":true,
        "write_charge_substitution_refused":true, "no_provider_permit_reconstructed":true,
        "provider_requests":0})
}

async fn acknowledgement_loss(backend: Backend) {
    let setup = Setup::with_recipe(backend, recipe_fixture(), [1; 32]).await;
    let approved = approved(&setup);
    parent(&setup, &approved).await;
    let fault = Arc::new(FaultStore::new(setup.backend.raw()));
    fault.lose_next_claim_reply();
    let attempts = setup.attempts(fault.clone());
    assert!(
        attempts
            .claim_prerequisite(
                &approved,
                PrerequisiteKind::PreEntry,
                NOW,
                setup.validation()
            )
            .await
            .is_err()
    );
    let before = bytes(&setup, true).await.unwrap();
    let rows = read_rows(&setup, &approved).await;
    let crate::AcquisitionClaim::Reserved(reserved) = attempts
        .claim_prerequisite(
            &approved,
            PrerequisiteKind::PreEntry,
            NOW,
            setup.validation(),
        )
        .await
        .unwrap()
    else {
        panic!("acknowledged recovery");
    };
    assert_eq!(bytes(&setup, true).await.unwrap(), before);
    fault.lose_next_grant_reply();
    assert!(
        reserved
            .grant_entry(Arc::clone(&approved), setup.validation(), NOW)
            .await
            .is_err()
    );
    let reopened = setup.attempts(setup.backend.raw());
    assert!(matches!(
        reopened
            .claim_prerequisite(
                &approved,
                PrerequisiteKind::PreEntry,
                NOW,
                setup.validation()
            )
            .await
            .unwrap(),
        crate::AcquisitionClaim::Existing(crate::AcquisitionSnapshot {
            stage: crate::AcquisitionStage::Unknown,
            ..
        })
    ));
    assert_eq!(read_rows(&setup, &approved).await, rows);
}

async fn withdrawn_actor(backend: Backend) {
    let setup = Setup::with_recipe(backend, recipe_fixture(), [1; 32]).await;
    let approved = approved(&setup);
    parent(&setup, &approved).await;
    let attempts = setup.attempts(Arc::clone(&setup.store));
    let crate::AcquisitionClaim::Reserved(reserved) = attempts
        .claim_prerequisite(
            &approved,
            PrerequisiteKind::PreEntry,
            NOW,
            setup.validation(),
        )
        .await
        .unwrap()
    else {
        panic!("child reservation");
    };
    let rows = read_rows(&setup, &approved).await;
    tokio::task::block_in_place(|| setup.native.withdraw_root(&setup.controller));
    assert!(
        reserved
            .grant_entry(Arc::clone(&approved), setup.validation(), NOW)
            .await
            .is_err()
    );
    assert_eq!(read_rows(&setup, &approved).await, rows);
    let wire: Value = serde_json::from_slice(&bytes(&setup, true).await.unwrap()).unwrap();
    assert!(wire["entry"].is_null());
}

#[tokio::test(flavor = "multi_thread")]
async fn native_engagement_prerequisite_fixture_is_current() {
    let lifecycle = tokio::spawn(lifecycle(Backend::File));
    let ack = tokio::spawn(acknowledgement_loss(Backend::File));
    let withdrawal = tokio::spawn(withdrawn_actor(Backend::File));
    let (lifecycle, ack, withdrawal) = tokio::join!(lifecycle, ack, withdrawal);
    assert!(
        lifecycle.is_ok() && ack.is_ok() && withdrawal.is_ok(),
        "lifecycle={lifecycle:?}, ack={ack:?}, withdrawal={withdrawal:?}"
    );
    let artifact = json!({"schema":"auths.engagement-prerequisite-vectors/1",
        "generated_by":"native_engagement_prerequisite_fixture_is_current",
        "scope":"native full parent verification and exact approval; real file parent/child admissions and child grant; permits dropped; controlled ACK loss; no provider request or predicate result",
        "not_established":["postgres-execution","process-crash","provider-predicate",
            "cross-process-concurrency","installed-key-containment"],
        "case":lifecycle.unwrap(), "claim_and_grant_ack_loss_preserve_single_read_charge":true,
        "current_withdrawal_prevents_child_grant_without_refund":true});
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/prerequisite.json");
    let mut bytes = serde_json::to_vec_pretty(&artifact).unwrap();
    bytes.push(b'\n');
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the TLS PostgreSQL fixture"]
async fn postgres_native_prerequisite_read_charges_and_acknowledgements() {
    assert!(postgres_configured(), "TLS PostgreSQL fixture is required");
    Box::pin(lifecycle(Backend::Postgres)).await;
    Box::pin(acknowledgement_loss(Backend::Postgres)).await;
    Box::pin(withdrawn_actor(Backend::Postgres)).await;
}
