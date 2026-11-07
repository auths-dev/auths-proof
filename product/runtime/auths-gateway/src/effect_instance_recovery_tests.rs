//! Actual native admission/control/entry and permanent accounting on both
//! adapters. Provider responses are injected; no credential or provider I/O.
use super::admission_tests::{FaultStore, Setup};
use super::information_tests::{acquire, allocation_rows, content_recipe_fixture, private, record};
use super::*;
use crate::effect::{ContentReadTarget, compile_content_acquisition};
use crate::store_testkit::{Backend, postgres_configured};
use crate::{GatewayAttemptError, GatewayAttemptStage};

#[derive(Clone, Copy, Debug)]
enum ReplyLoss {
    None,
    Withdrawal,
    Successor,
}
impl ReplyLoss {
    const ALL: [Self; 3] = [Self::None, Self::Withdrawal, Self::Successor];
}

fn content(
    setup: &Setup,
    tree: &crate::participant_enrollment::EnrollmentTree,
    actor: u8,
    operation: &str,
) -> crate::effect::BoundEffect {
    let target = ContentReadTarget::new(
        &setup.recipe,
        &setup.connection,
        json!({"record_id":RECORD}).as_object().unwrap().clone(),
    )
    .unwrap();
    let call = target
        .authorization_call(
            &setup.recipe,
            &crate::LogicalOperationId::parse(operation).unwrap(),
        )
        .unwrap();
    let native = setup.native.signed_call(&call, actor);
    compile_content_acquisition(
        &setup
            .policy
            .installation(
                &setup.recipe,
                &setup.native.context,
                &setup.connection,
                crate::QualificationPolicy::Optional,
                [12; 32],
            )
            .with_enrollment(Some(tree)),
        &target,
        NOW,
        &native.proof,
        &native.action,
    )
    .unwrap()
}
fn mutation(
    setup: &Setup,
    tree: &crate::participant_enrollment::EnrollmentTree,
    actor: u8,
    operation: &str,
) -> crate::effect::BoundEffect {
    let call=auths_profile_mcp::McpToolCall::new(setup.recipe.service(),setup.recipe.review().tool(),
        json!({"operation_id":operation,"operator_namespace":setup.recipe.namespace().as_str(),"recipe_digest":setup.recipe.digest_hex(),
            "record_id":RECORD,"replacement":"Approved"}).as_object().unwrap().clone()).unwrap();
    let native = setup.native.signed_call(&call, actor);
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
            .with_enrollment(Some(tree)),
        NOW,
        &native.proof,
        &native.action,
    )
    .unwrap()
}
async fn snapshot(setup: &Setup) -> crate::EngagementConfigurationSnapshot {
    let controller = setup.controller.clone();
    tokio::task::spawn_blocking(move || controller.snapshot())
        .await
        .unwrap()
        .unwrap()
}
async fn apply(
    controller: crate::EngagementConfiguration,
    evidence: crate::EngagementControlEvidence,
) -> Result<crate::EngagementConfigurationSnapshot, crate::EngagementConfigurationError> {
    tokio::task::spawn_blocking(move || controller.apply_control(evidence))
        .await
        .unwrap()
}
fn evidence_copy(value: &crate::EngagementControlEvidence) -> crate::EngagementControlEvidence {
    crate::EngagementControlEvidence::from_private_bytes(&value.to_private_bytes().unwrap())
        .unwrap()
}

async fn recorded(
    controller: crate::EngagementConfiguration,
    evidence: crate::EngagementControlEvidence,
) -> Option<u64> {
    tokio::task::spawn_blocking(move || controller.recorded_control(&evidence))
        .await
        .unwrap()
        .unwrap()
}

#[allow(
    clippy::too_many_lines,
    reason = "one complete native successor and permanent-capacity/fault history"
)]
async fn lifecycle(backend: Backend, loss: ReplyLoss) -> Value {
    let setup = Setup::with_instance_recovery(backend, content_recipe_fixture()).await;
    let attempts = setup.attempts(setup.backend.raw());
    let initial = snapshot(&setup).await;
    assert_eq!(initial.revision(), 3);
    let first = Arc::new(approve(content(
        &setup,
        initial.tree(),
        0x44,
        "before-recovery-one",
    )));
    acquire(&setup, &first, b"PRIVATE-BEFORE-INSTANCE-RECOVERY").await;
    let second = Arc::new(approve(content(
        &setup,
        initial.tree(),
        0x44,
        "reserved-before-recovery",
    )));
    let crate::AcquisitionClaim::Reserved(reserved) = attempts
        .claim_content(&second, NOW, setup.validation())
        .await
        .unwrap()
    else {
        panic!("second reserved read")
    };
    let reserved_bytes = record(&setup, "reserved-before-recovery").await.unwrap();
    let first_rows = allocation_rows(&setup, &first, 0).await;
    let second_rows = allocation_rows(&setup, &second, 1).await;
    assert!(first_rows.iter().chain(&second_rows).all(Option::is_some));
    let write = Arc::new(approve(mutation(
        &setup,
        initial.tree(),
        0x44,
        "unknown-before-recovery",
    )));
    let crate::store::BoundedClaim::Claimed(claimed) = attempts
        .claim_bounded(&write, NOW, setup.validation())
        .await
        .unwrap()
    else {
        panic!("old mutation")
    };
    let (granted, permit) = claimed
        .grant_entry(
            Arc::clone(&write),
            setup.validation(),
            NOW,
            &crate::GatewayPreEntry::default(),
        )
        .await
        .unwrap();
    drop((granted, permit));
    let unknown_bytes = record(&setup, "unknown-before-recovery").await.unwrap();
    assert_eq!(
        attempts
            .read(
                setup.recipe.namespace(),
                &crate::LogicalOperationId::parse("unknown-before-recovery").unwrap()
            )
            .await
            .unwrap()
            .unwrap()
            .stage(),
        GatewayAttemptStage::Unknown
    );
    let write_rows = allocation_rows(&setup, &write, 0).await;
    let evidence = setup.native.recovery_evidence(initial.tree(), 0x44, 0x66);
    assert!(
        apply(setup.controller.clone(), evidence_copy(&evidence))
            .await
            .is_err(),
        "active predecessor recovered"
    );
    assert_eq!(snapshot(&setup).await.revision(), 3);
    let fault = Arc::new(FaultStore::new(setup.backend.raw()));
    let controller = crate::EngagementConfiguration::new(
        fault.clone(),
        setup.native.root.clone(),
        setup.native.context.clone(),
        setup.configuration.clone(),
        Arc::clone(&setup.qualification),
    )
    .unwrap();
    let withdraw = setup.native.withdrawal_evidence(0x44);
    if matches!(loss, ReplyLoss::Withdrawal) {
        fault.lose_next_grant_reply();
    }
    let result = apply(controller.clone(), evidence_copy(&withdraw)).await;
    if matches!(loss, ReplyLoss::Withdrawal) {
        assert!(result.is_err());
    } else {
        assert_eq!(result.unwrap().revision(), 4);
    }
    assert_eq!(
        snapshot(&setup).await.revision(),
        4,
        "withdrawal publication precedes any ambiguous acknowledgement"
    );
    assert_eq!(
        recorded(controller.clone(), evidence_copy(&withdraw)).await,
        Some(4)
    );
    assert!(
        reserved
            .grant_entry(Arc::clone(&second), setup.validation(), NOW)
            .await
            .is_err(),
        "old reserved read granted after withdrawal"
    );
    assert_eq!(
        record(&setup, "reserved-before-recovery").await.unwrap(),
        reserved_bytes
    );
    if matches!(loss, ReplyLoss::Successor) {
        fault.lose_next_grant_reply();
    }
    let result = apply(controller.clone(), evidence_copy(&evidence)).await;
    if matches!(loss, ReplyLoss::Successor) {
        assert!(result.is_err());
    } else {
        assert_eq!(result.unwrap().revision(), 5);
    }
    let current = snapshot(&setup).await;
    assert_eq!(current.revision(), 5);
    assert_eq!(current.tree().participant_count(), 4);
    assert_eq!(
        recorded(controller.clone(), evidence_copy(&evidence)).await,
        Some(5)
    );
    let recovered = Arc::new(approve(content(
        &setup,
        current.tree(),
        0x66,
        "after-recovery",
    )));
    assert!(
        first.effect().binding().engagement_reservations()
            == recovered.effect().binding().engagement_reservations(),
        "current instance change cannot replace ancestor counter keys or ceilings"
    );
    let old = private(first.effect().binding());
    let new = private(recovered.effect().binding());
    assert_ne!(
        old["scope"]["bound"]["ancestors"][1]["enrollment"],
        new["scope"]["bound"]["ancestors"][1]["enrollment"]
    );
    assert_eq!(
        old["scope"]["bound"]["ancestors"][1]["capacity_enrollment"],
        new["scope"]["bound"]["ancestors"][1]["capacity_enrollment"]
    );
    acquire(&setup, &recovered, b"PRIVATE-AFTER-INSTANCE-RECOVERY").await;
    let third_rows = allocation_rows(&setup, &recovered, 2).await;
    assert!(third_rows.iter().all(Option::is_some));
    let exhausted = Arc::new(approve(content(
        &setup,
        current.tree(),
        0x66,
        "recovery-cannot-reset",
    )));
    assert!(matches!(
        attempts
            .claim_content(&exhausted, NOW, setup.validation())
            .await,
        Err(GatewayAttemptError::InvalidTransition)
    ));
    assert!(record(&setup, "recovery-cannot-reset").await.is_none());
    assert!(
        allocation_rows(&setup, &exhausted, 3)
            .await
            .iter()
            .all(Option::is_none)
    );
    let sibling = Arc::new(approve(content(
        &setup,
        current.tree(),
        0x55,
        "sibling-capacity-positive-control",
    )));
    acquire(&setup, &sibling, b"PRIVATE-SIBLING-CAPACITY-POSITIVE").await;
    let next_write = Arc::new(approve(mutation(
        &setup,
        current.tree(),
        0x66,
        "recovery-cannot-repeat-unknown",
    )));
    assert!(matches!(
        attempts
            .claim_bounded(&next_write, NOW, setup.validation())
            .await,
        Err(GatewayAttemptError::InvalidTransition)
    ));
    assert!(
        record(&setup, "recovery-cannot-repeat-unknown")
            .await
            .is_none()
    );
    assert_eq!(
        record(&setup, "unknown-before-recovery").await.unwrap(),
        unknown_bytes
    );
    assert_eq!(allocation_rows(&setup, &write, 0).await, write_rows);
    assert_eq!(allocation_rows(&setup, &first, 0).await, first_rows);
    assert_eq!(allocation_rows(&setup, &second, 1).await, second_rows);
    assert_eq!(allocation_rows(&setup, &recovered, 2).await, third_rows);
    assert!(matches!(
        attempts
            .claim_content(&recovered, NOW, setup.validation())
            .await
            .unwrap(),
        crate::AcquisitionClaim::Existing(_)
    ));
    let second_successor = setup.native.recovery_evidence(current.tree(), 0x66, 0x77);
    assert!(
        apply(controller.clone(), evidence_copy(&second_successor))
            .await
            .is_err()
    );
    // Withdrawal proof uses the same original parent, independently of the
    // successor's own key. The fixture derives the current target explicitly.
    let principal = crate::harness::Signer::new(0x66).principal;
    let next = current
        .tree()
        .retained_principal_pins(principal.as_str())
        .unwrap()
        .enrollment_commitment;
    let control = setup.controller.clone();
    tokio::task::block_in_place(|| setup.native.withdraw_participant(&control, next));
    let latest = apply(controller.clone(), second_successor).await.unwrap();
    assert_eq!(latest.revision(), 7);
    let newest = Arc::new(approve(content(
        &setup,
        latest.tree(),
        0x77,
        "second-recovery-cannot-reset",
    )));
    assert!(
        newest.effect().binding().engagement_reservations()
            == first.effect().binding().engagement_reservations()
    );
    assert!(
        attempts
            .claim_content(&newest, NOW, setup.validation())
            .await
            .is_err()
    );
    assert_eq!(
        record(&setup, "unknown-before-recovery").await.unwrap(),
        unknown_bytes
    );
    let audit = controller.clone();
    let root = setup.native.root.clone();
    let context = setup.native.context.clone();
    let verified = tokio::task::spawn_blocking(move || {
        let (archive, head) = audit.export_audit_checkpointed().unwrap();
        archive.verify(&root, &[context], &head).unwrap().revision()
    })
    .await
    .unwrap();
    assert_eq!(verified, 7);
    json!({"case":format!("{loss:?}"),"backend":backend.label(),"control_revisions":[3,4,5,6,7],
        "withdrawal_ack_loss":matches!(loss,ReplyLoss::Withdrawal),"successor_ack_loss":matches!(loss,ReplyLoss::Successor),
        "original_control_history_lookup_no_new_revision":true,"old_reserved_entry_refused":true,
        "current_key_original_capacity_distinct":true,"old_reads_retained":2,"successor_reads":1,"original_child_read_ceiling":3,
        "parent_read_ceiling":4,"sibling_positive_control":true,"second_recovery_no_new_capacity":true,
        "unknown_source_and_original_rows_unchanged":true,"independent_control_audit_revision":verified,
        "provider_calls":0,"responses_are_injected":true})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_instance_recovery_store_fixture_is_current() {
    let mut cases = Vec::new();
    let mut failures = Vec::new();
    for loss in ReplyLoss::ALL {
        match tokio::spawn(lifecycle(Backend::File, loss)).await {
            Ok(value) => cases.push(value),
            Err(_) => failures.push(format!("{loss:?}")),
        }
    }
    assert!(
        failures.is_empty(),
        "native instance recovery failures: {failures:?}"
    );
    assert_eq!(cases.len(), 3);
    let bytes=serde_json::to_vec_pretty(&json!({"schema":"auths.instance-recovery-store-vectors/1","cases":cases,
        "not_established":["actual-provider-effect","installed-key-containment","TLS-postgres","source-linked-formal","full-F12"]})).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/instance-recovery-store.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the real TLS PostgreSQL fixture; CI invokes explicitly"]
async fn postgres_native_instance_recovery_store_matrix() {
    assert!(postgres_configured());
    let mut failures = Vec::new();
    for loss in ReplyLoss::ALL {
        if tokio::spawn(lifecycle(Backend::Postgres, loss))
            .await
            .is_err()
        {
            failures.push(format!("{loss:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "PostgreSQL instance recovery failures: {failures:?}"
    );
}
