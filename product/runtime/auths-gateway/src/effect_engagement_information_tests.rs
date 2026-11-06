//! Native scoped information compilers and maintained file/PostgreSQL journals.
//! Responses below are injected synthetic transport facts, never provider or
//! live-recipient evidence. No credential is leased and no content is delivered.
use super::super::content_tests::{content_recipe, declaration};
use super::admission_tests::Setup;
use super::*;
use crate::effect::{
    ApprovedEffect, ContentReadTarget, DisclosureTarget, compile_content_acquisition,
    compile_content_action, compile_disclosure, compile_recovery_acquisition,
};
use crate::store_testkit::{Backend, postgres_configured};

fn content_recipe_fixture() -> CompiledRecipe {
    content_recipe(declaration(&json!({"kind":"utf8"}))).unwrap()
}

fn installation(setup: &Setup) -> EffectInstallation<'_> {
    setup
        .policy
        .installation(
            &setup.recipe,
            &setup.native.context,
            &setup.connection,
            crate::QualificationPolicy::Optional,
            [12; 32],
        )
        .with_enrollment(Some(&setup.native.tree))
}

fn private(binding: &EffectBinding) -> Value {
    serde_json::from_slice(&binding.to_private_bytes().unwrap()).unwrap()
}

fn content_effect(
    setup: &Setup,
    operation: &str,
    actor: u8,
    resource: &str,
) -> Result<crate::effect::BoundEffect, crate::GatewaySubmitResult> {
    let target = ContentReadTarget::new(
        &setup.recipe,
        &setup.connection,
        json!({"record_id":resource}).as_object().unwrap().clone(),
    )
    .unwrap();
    let call = target
        .authorization_call(
            &setup.recipe,
            &crate::LogicalOperationId::parse(operation).unwrap(),
        )
        .unwrap();
    let native = setup.native.signed_call(&call, actor);
    let effect = compile_content_acquisition(
        &installation(setup),
        &target,
        NOW,
        &native.proof,
        &native.action,
    )?;
    let from_action =
        compile_content_action(&installation(setup), NOW, &native.proof, &native.action)?;
    assert!(effect.binding() == from_action.binding());
    Ok(effect)
}

async fn record(setup: &Setup, operation: &str) -> Option<Value> {
    let key = crate::GatewayAttemptKey::for_operation(
        &setup.policy,
        setup.recipe.namespace(),
        &crate::LogicalOperationId::parse(operation).unwrap(),
    )
    .unwrap();
    let store = setup.backend.raw();
    tokio::task::spawn_blocking(move || {
        store
            .load(crate::GatewayRecordKind::Attempt, &key)
            .unwrap()
            .map(|bytes| serde_json::from_slice(&bytes).unwrap())
    })
    .await
    .unwrap()
}

async fn allocation_rows(
    setup: &Setup,
    approved: &ApprovedEffect,
    slot: u64,
) -> Vec<Option<Value>> {
    let mut rows = Vec::new();
    for declaration in approved.effect().binding().engagement_reservations() {
        let key = crate::store::fixture_engagement_allocation_key(&declaration.key, slot);
        let store = setup.backend.raw();
        rows.push(
            tokio::task::spawn_blocking(move || {
                store
                    .load(crate::GatewayRecordKind::EffectAllocation, &key)
                    .unwrap()
                    .map(|bytes| serde_json::from_slice(&bytes).unwrap())
            })
            .await
            .unwrap(),
        );
    }
    rows
}

async fn acquire(
    setup: &Setup,
    approved: &Arc<ApprovedEffect>,
    body: &[u8],
) -> crate::RetainedContent {
    let attempts = setup.attempts(Arc::clone(&setup.store));
    let crate::AcquisitionClaim::Reserved(reserved) = attempts
        .claim_content(approved, NOW, setup.validation())
        .await
        .unwrap()
    else {
        panic!("fresh content reservation required");
    };
    assert_eq!(
        record(setup, approved.effect().binding().journal_identity().1)
            .await
            .unwrap()["engagement_allocations"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let (granted, permit) = reserved
        .grant_entry(Arc::clone(approved), setup.validation(), NOW)
        .await
        .unwrap();
    drop(permit);
    // Inject complete synthetic transport facts through the native response
    // owner. This establishes projection/journal behavior, not HTTPS behavior.
    let response = crate::transport::ContentProviderResponse {
        status: 200,
        version_ok: true,
        body: zeroize::Zeroizing::new(body.to_vec()),
        metadata: serde_json::from_value(
            json!({"media_type":{"kind":"single", "value":"text/plain"},
            "encoding":{"kind":"missing"}}),
        )
        .unwrap(),
    };
    let snapshot = granted
        .record_content_response(response, NOW)
        .await
        .unwrap();
    assert_eq!(snapshot.stage, crate::AcquisitionStage::ResponseRecorded);
    let public = serde_json::to_string(&snapshot).unwrap();
    assert!(!public.contains("PRIVATE-NATIVE-INFORMATION"));
    assert!(!public.contains(&setup.native.root.principal.to_string()));
    let operation =
        crate::LogicalOperationId::parse(approved.effect().binding().journal_identity().1).unwrap();
    let reopened = setup.attempts(setup.backend.raw());
    assert!(matches!(
        reopened
            .claim_content(approved, NOW, setup.validation())
            .await
            .unwrap(),
        crate::AcquisitionClaim::Existing(_)
    ));
    reopened
        .retained_content(setup.recipe.namespace(), &operation)
        .await
        .unwrap()
}

fn disclosure_effect(
    setup: &Setup,
    retained: crate::RetainedContent,
    operation: &str,
    recipient_seed: u8,
    channel: [u8; 32],
) -> Result<crate::effect::BoundEffect, crate::GatewaySubmitResult> {
    let recipient = SigningKey::from_bytes(&[recipient_seed; 32])
        .verifying_key()
        .to_bytes();
    let target = DisclosureTarget::new(retained, recipient, channel, [0x79; 32]).unwrap();
    let call = target
        .authorization_call(
            &setup.recipe,
            &crate::LogicalOperationId::parse(operation).unwrap(),
        )
        .unwrap();
    let native = setup.native.signed_call(&call, 0x44);
    compile_disclosure(
        &installation(setup),
        &target,
        NOW,
        &native.proof,
        &native.action,
    )
}

fn channel(setup: &Setup) -> [u8; 32] {
    setup.native.root.permitted_channels["sibling-channel"].channel_binding
}

#[allow(
    clippy::too_many_lines,
    reason = "one complete native information flow and related refusal histories"
)]
async fn information_lifecycle(backend: Backend) -> Value {
    let setup = Setup::with_recipe(backend, content_recipe_fixture(), [1; 32]).await;
    let read = content_effect(&setup, "native-info-read", 0x44, RECORD).unwrap();
    let read_binding = private(read.binding());
    let approved = Arc::new(approve(read));
    assert_eq!(
        approved.effect().binding().engagement_reservations().len(),
        2
    );
    assert!(content_effect(&setup, "foreign-resource", 0x44, OTHER_RECORD).is_err());
    assert!(content_effect(&setup, "unenrolled-native-holder", 0x66, RECORD).is_err());
    let retained = acquire(&setup, &approved, b"PRIVATE-NATIVE-INFORMATION").await;
    let acquired = record(&setup, "native-info-read").await.unwrap();
    let read_rows = allocation_rows(&setup, &approved, 0).await;
    assert!(read_rows.iter().all(Option::is_some));
    // A separately enrolled, native-valid engagement cannot import provenance
    // from this one even with the identical recipe, credential and resource.
    let other = Setup::with_recipe(backend, content_recipe_fixture(), [2; 32]).await;
    assert!(
        disclosure_effect(
            &other,
            retained.clone(),
            "cross-task-release",
            0x55,
            channel(&other)
        )
        .is_err()
    );
    assert!(
        disclosure_effect(
            &setup,
            retained.clone(),
            "unknown-recipient",
            0x66,
            channel(&setup)
        )
        .is_err()
    );
    assert!(disclosure_effect(&setup, retained.clone(), "wrong-channel", 0x55, [0; 32]).is_err());
    let release = disclosure_effect(
        &setup,
        retained.clone(),
        "native-info-release",
        0x55,
        channel(&setup),
    )
    .unwrap();
    let release_binding = private(release.binding());
    let released = Arc::new(approve(release));
    let declarations = released.effect().binding().engagement_reservations();
    assert_eq!(
        declarations.len(),
        6,
        "actor and recipient paths share one root"
    );
    let reservations = release_binding["reservations"].as_array().unwrap();
    for unit in ["disclosure-count", "disclosure-bytes"] {
        assert_eq!(
            reservations
                .iter()
                .filter(|r| r["window"]["kind"] == "engagement-lifetime" && r["unit"] == unit)
                .count(),
            3
        );
    }
    let recipient_enrollment: [u8; 32] = serde_json::from_value(
        release_binding["scope"]["bound"]["recipient"]["ancestors"][1]["enrollment"].clone(),
    )
    .unwrap();
    let mut withdrawn = setup.native.tree.clone();
    withdrawn.revoke(recipient_enrollment).unwrap();
    assert!(
        released
            .validate_for_entry(&installation(&setup).with_enrollment(Some(&withdrawn)), NOW)
            .is_err()
    );
    let unscoped = EffectPolicy::new(
        "recipe-partition".to_owned(),
        1,
        SigningKey::from_bytes(&[29; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    assert!(
        released
            .validate_for_entry(
                &unscoped.installation(
                    &setup.recipe,
                    &setup.native.context,
                    &setup.connection,
                    crate::QualificationPolicy::Optional,
                    [12; 32]
                ),
                NOW
            )
            .is_err()
    );
    let attempts = setup.attempts(Arc::clone(&setup.store));
    let snapshot = attempts
        .claim_disclosure(&released, NOW, setup.validation())
        .await
        .unwrap();
    assert_eq!(snapshot.stage, crate::DisclosureStage::Reserved);
    let reserved = record(&setup, "native-info-release").await.unwrap();
    assert_eq!(
        reserved["engagement_allocations"].as_array().unwrap().len(),
        6
    );
    assert!(
        allocation_rows(&setup, &released, 0)
            .await
            .iter()
            .all(Option::is_some)
    );
    // Reservation/reopen is still not recipient authentication or a grant.
    let reopened = setup.attempts(setup.backend.raw());
    assert_eq!(
        reopened
            .claim_disclosure(&released, NOW, setup.validation())
            .await
            .unwrap()
            .stage,
        crate::DisclosureStage::Reserved
    );
    assert_eq!(
        record(&setup, "native-info-release").await.unwrap(),
        reserved
    );
    assert!(reserved["entry"].is_null());
    let again = Arc::new(approve(
        disclosure_effect(&setup, retained, "release-exhausted", 0x55, channel(&setup)).unwrap(),
    ));
    assert!(
        attempts
            .claim_disclosure(&again, NOW, setup.validation())
            .await
            .is_err()
    );
    assert!(record(&setup, "release-exhausted").await.is_none());
    assert!(
        allocation_rows(&setup, &again, 1)
            .await
            .iter()
            .all(Option::is_none)
    );
    // Two independent reads consume the shared ancestor allowance, irrespective
    // of actor. A third cannot partially reserve a different child's allowance.
    let second = Arc::new(approve(
        content_effect(&setup, "native-info-read-b", 0x55, RECORD).unwrap(),
    ));
    let crate::AcquisitionClaim::Reserved(lost) = attempts
        .claim_content(&second, NOW, setup.validation())
        .await
        .unwrap()
    else {
        panic!("second read reservation");
    };
    let (granted, permit) = lost
        .grant_entry(Arc::clone(&second), setup.validation(), NOW)
        .await
        .unwrap();
    drop((granted, permit));
    assert!(matches!(
        reopened
            .claim_content(&second, NOW, setup.validation())
            .await
            .unwrap(),
        crate::AcquisitionClaim::Existing(crate::AcquisitionSnapshot {
            stage: crate::AcquisitionStage::Unknown,
            ..
        })
    ));
    let third = Arc::new(approve(
        content_effect(&setup, "native-info-third", 0x55, RECORD).unwrap(),
    ));
    assert!(
        attempts
            .claim_content(&third, NOW, setup.validation())
            .await
            .is_err()
    );
    assert!(record(&setup, "native-info-third").await.is_none());
    assert_eq!(record(&setup, "native-info-read").await.unwrap(), acquired);
    // Canonical diagnostic projection intentionally excludes the randomized
    // content MAC, operation nonces and their dependent disclosure identity.
    // The actual complete bindings and journal bytes were compared above.
    json!({"content_binding":read_binding,
        "disclosure_projection":{"schema":"auths.engagement-information-projection/1",
            "scope":release_binding["scope"], "reservations":release_binding["reservations"],
            "maximum_disclosure_bytes":b"PRIVATE-NATIVE-INFORMATION".len(),"stage":"reserved", "ancestor_slots":6},
        "denials":["foreign-resource","unenrolled-native-holder","cross-task-release",
            "unknown-recipient","wrong-channel","recipient-withdrawal","unscoped-source-escape",
            "release-replay","ancestor-disclosure-exhaustion","ancestor-read-exhaustion"],
        "dropped_read_permit_reopens_unknown":true, "no_partial_charge":true,
        "provider_requests":0,"disclosure_grants":0,"bytes_delivered":0})
}

#[tokio::test(flavor = "multi_thread")]
async fn native_engagement_information_fixture_is_current() {
    // Collect independent constructor failures as one cohort, even when a
    // native case panics. All use their own maintained stores/configuration.
    let empty = tokio::spawn(zero_content(Backend::File));
    let recovery = tokio::spawn(recovery_after_writer_withdrawal(Backend::File));
    let withdrawal = tokio::spawn(recipient_withdrawal_before_reservation(Backend::File));
    let lifecycle = tokio::spawn(information_lifecycle(Backend::File));
    let (empty, recovery, withdrawal, lifecycle) =
        tokio::join!(empty, recovery, withdrawal, lifecycle);
    assert!(
        empty.is_ok() && recovery.is_ok() && withdrawal.is_ok() && lifecycle.is_ok(),
        "empty={empty:?}, recovery={recovery:?}, withdrawal={withdrawal:?}, lifecycle={lifecycle:?}"
    );
    let document = json!({"schema":"auths.engagement-information-vectors/1",
        "generated_by":"native_engagement_information_fixture_is_current",
        "scope":"native enrollment and full proof compilation; real file reservations and read grant; injected synthetic response; no provider send or disclosure grant",
        "not_established":["live-provider","live-recipient-authentication","postgres-execution",
            "cross-process-concurrency","process-crash","independent-original-control-proof-history"],
        "case":lifecycle.unwrap(),
        "empty_content_count_reserved":true, "withdrawn_writer_independent_reader_granted":true,
        "current_recipient_withdrawal_denied_without_charge":true});
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/information.json");
    let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
    bytes.push(b'\n');
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[tokio::test]
async fn postgres_native_information_scope_and_ancestor_accounting() {
    if postgres_configured() {
        information_lifecycle(Backend::Postgres).await;
    }
}

async fn recipient_withdrawal_before_reservation(backend: Backend) {
    let setup = Setup::with_recipe(backend, content_recipe_fixture(), [1; 32]).await;
    let read = Arc::new(approve(
        content_effect(&setup, "withdrawal-read", 0x44, RECORD).unwrap(),
    ));
    let retained = acquire(&setup, &read, b"PRIVATE-NATIVE-INFORMATION").await;
    let release = Arc::new(approve(
        disclosure_effect(
            &setup,
            retained,
            "withdrawal-release",
            0x55,
            channel(&setup),
        )
        .unwrap(),
    ));
    let wire = private(release.effect().binding());
    let recipient: [u8; 32] = serde_json::from_value(
        wire["scope"]["bound"]["recipient"]["ancestors"][1]["enrollment"].clone(),
    )
    .unwrap();
    tokio::task::block_in_place(|| {
        setup
            .native
            .withdraw_participant(&setup.controller, recipient)
    });
    let attempts = setup.attempts(Arc::clone(&setup.store));
    assert!(
        attempts
            .claim_disclosure(&release, NOW, setup.validation())
            .await
            .is_err()
    );
    assert!(record(&setup, "withdrawal-release").await.is_none());
    assert!(
        allocation_rows(&setup, &release, 0)
            .await
            .iter()
            .all(Option::is_none)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_current_recipient_withdrawal_prevents_information_reservation() {
    if postgres_configured() {
        recipient_withdrawal_before_reservation(Backend::Postgres).await;
    }
}

async fn zero_content(backend: Backend) {
    let setup = Setup::with_recipe(backend, content_recipe_fixture(), [1; 32]).await;
    let read = Arc::new(approve(
        content_effect(&setup, "empty-read", 0x44, RECORD).unwrap(),
    ));
    let retained = acquire(&setup, &read, b"").await;
    let release = Arc::new(approve(
        disclosure_effect(&setup, retained, "empty-release", 0x55, channel(&setup)).unwrap(),
    ));
    let wire = private(release.effect().binding());
    let reservations = wire["reservations"].as_array().unwrap();
    assert_eq!(
        reservations
            .iter()
            .filter(|r| r["unit"] == "disclosure-count" && r["amount"] == 1)
            .count(),
        4
    );
    assert_eq!(
        reservations
            .iter()
            .filter(|r| r["unit"] == "disclosure-bytes" && r["amount"] == 0)
            .count(),
        4
    );
    let attempts = setup.attempts(Arc::clone(&setup.store));
    assert_eq!(
        attempts
            .claim_disclosure(&release, NOW, setup.validation())
            .await
            .unwrap()
            .stage,
        crate::DisclosureStage::Reserved
    );
    assert_eq!(allocation_rows(&setup, &release, 0).await.len(), 6);
}

#[tokio::test]
async fn file_empty_native_content_still_reserves_disclosure_count() {
    zero_content(Backend::File).await;
}
#[tokio::test]
async fn postgres_empty_native_content_still_reserves_disclosure_count() {
    if postgres_configured() {
        zero_content(Backend::Postgres).await;
    }
}

async fn recovery_after_writer_withdrawal(backend: Backend) {
    let setup = Setup::with_recipe(backend, content_recipe_fixture(), [1; 32]).await;
    let installed = installation(&setup);
    let source = Arc::new(approve(
        compile_mutation_effect(
            &installed,
            NOW,
            &setup.native.action.proof,
            &setup.native.action.action,
        )
        .unwrap(),
    ));
    let attempts = setup.attempts(Arc::clone(&setup.store));
    let crate::store::BoundedClaim::Claimed(claimed) = attempts
        .claim_bounded(&source, NOW, setup.validation())
        .await
        .unwrap()
    else {
        panic!("mutation reservation");
    };
    let (granted, permit) = claimed
        .grant_entry(
            Arc::clone(&source),
            setup.validation(),
            NOW,
            &crate::GatewayPreEntry::default(),
        )
        .await
        .unwrap();
    drop((granted, permit));
    let target = attempts
        .retained_recovery_target(
            setup.recipe.namespace(),
            &crate::LogicalOperationId::parse("initial").unwrap(),
            *setup.recipe.digest(),
        )
        .await
        .unwrap();
    let call = target
        .authorization_call(
            &setup.recipe,
            &crate::LogicalOperationId::parse("fresh-reader").unwrap(),
        )
        .unwrap();
    let native = setup.native.signed_call(&call, 0x55);
    let read = Arc::new(approve(
        compile_recovery_acquisition(&installed, &target, NOW, &native.proof, &native.action)
            .unwrap(),
    ));
    let writer: [u8; 32] = serde_json::from_value(
        private(source.effect().binding())["scope"]["bound"]["ancestors"][1]["enrollment"].clone(),
    )
    .unwrap();
    {
        let mut current = setup.native.tree.clone();
        current.revoke(writer).unwrap();
        assert!(
            source
                .validate_for_entry(&installed.with_enrollment(Some(&current)), NOW)
                .is_err()
        );
        read.validate_for_entry(&installation(&setup).with_enrollment(Some(&current)), NOW)
            .unwrap();
    }
    let controller = setup.controller.clone();
    tokio::task::block_in_place(|| setup.native.withdraw_participant(&controller, writer));
    // Entry uses the current persisted tree, not the compile-time copy held by
    // setup or the source writer's original proof.
    let crate::AcquisitionClaim::Reserved(reserved) = attempts
        .claim_recovery(&read, NOW, setup.validation())
        .await
        .unwrap()
    else {
        panic!("fresh reader");
    };
    let (granted, permit) = reserved
        .grant_entry(Arc::clone(&read), setup.validation(), NOW)
        .await
        .unwrap();
    drop((granted, permit));
    assert_eq!(allocation_rows(&setup, &read, 0).await.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn file_native_recovery_uses_current_reader_after_writer_withdrawal() {
    recovery_after_writer_withdrawal(Backend::File).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn postgres_native_recovery_uses_current_reader_after_writer_withdrawal() {
    if postgres_configured() {
        recovery_after_writer_withdrawal(Backend::Postgres).await;
    }
}
