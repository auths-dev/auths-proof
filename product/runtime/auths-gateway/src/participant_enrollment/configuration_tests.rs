//! Native control evidence over the maintained adapters. No provider permit,
//! budget decision or operation transition is constructed by these fixtures.

use super::{Fixture, NOW, invocation};
use crate::configuration::SharedConfiguration;
use crate::participant_enrollment::{EnrollmentTree, EnrollmentTreeError};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    EngagementConfiguration, EngagementConfigurationError, FixedClock, GatewayAttemptError,
    GatewayAttemptKey, GatewayAttemptStore, GatewayInsert, GatewayRecordEntry, GatewayRecordKind,
    QualificationGate, QualificationPolicy,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

fn did_alias(signer: &crate::harness::Signer) -> auths_model::PrincipalId {
    let key = auths_multikey::Multikey::from_public_key(
        auths_multikey::MultikeyType::Ed25519,
        signer.key.verifying_key().to_bytes().to_vec(),
    )
    .unwrap();
    auths_model::PrincipalId::parse(&format!("did:key:{}", key.encoded())).unwrap()
}

#[test]
fn parent_key_alias_cannot_be_enrolled_as_an_independent_child() {
    let fixture = Fixture::new();
    let mut changed = fixture.enrollment.clone();
    changed.child_principal = did_alias(&fixture.parent).as_str().to_owned();
    let resource = fixture.resource_proof("record-a");
    assert_eq!(
        fixture.verify(&changed, &changed, &resource).unwrap_err(),
        crate::participant_enrollment::ParticipantEnrollmentError::Invalid
    );
}

#[test]
fn stored_tree_refuses_distinct_identifiers_for_the_same_child_key() {
    let mut fixture = Fixture::new();
    let alias = did_alias(&fixture.child);
    fixture.pins.permitted_channels.insert(
        "alias-channel".into(),
        crate::participant_enrollment::EnrollmentChannelPins {
            principal: alias.clone(),
            instance_generation: 1,
            channel_binding: [0x77; 32],
        },
    );
    fixture.commit_root();
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    fixture.enroll_tree(&mut tree).unwrap();
    let mut descriptor = fixture.enrollment.clone();
    descriptor.enrollment_id = "alias-child".into();
    descriptor.child_principal = alias.as_str().into();
    descriptor.delivery_channel = "alias-channel".into();
    let mut stored: serde_json::Value = serde_json::from_slice(&tree.encode().unwrap()).unwrap();
    stored["children"]["alias-child"] = serde_json::json!({
        "descriptor": descriptor, "commitment": descriptor.commitment().unwrap(), "revoked": false,
    });
    let bytes = serde_json_canonicalizer::to_vec(&stored).unwrap();
    assert_eq!(
        EnrollmentTree::decode(&bytes, &fixture.pins),
        Err(EnrollmentTreeError::Corrupt)
    );
}

fn controller(
    fixture: &Fixture,
    store: Arc<dyn GatewayAttemptStore>,
    clock: Arc<FixedClock>,
) -> (EngagementConfiguration, SharedConfiguration) {
    let gate = Arc::new(QualificationGate::new(
        QualificationPolicy::Optional,
        None,
        None,
        Box::new(clock),
        auths_recipe_qualification::VerifierState::default(),
    ));
    let configuration = SharedConfiguration::new(Arc::clone(&store), [0x91; 32], [0x92; 32], 2);
    configuration.initialize(&gate).unwrap();
    let control = EngagementConfiguration::new(
        store,
        fixture.pins.clone(),
        fixture.context.clone(),
        configuration.clone(),
        gate,
    )
    .unwrap();
    (control, configuration)
}

#[test]
fn native_withdrawal_refuses_ancestor_other_root_and_stale_control() {
    let mut fixture = Fixture::new();
    fixture.commit_root();
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    let child = fixture.enroll_tree(&mut tree).unwrap();
    let before = tree.clone();
    let against_parent = fixture.withdraw_as_child(fixture.pins.enrollment_commitment);
    assert_eq!(
        tree.revoke_authorized(&fixture.context, NOW, &invocation(&against_parent)),
        Err(EnrollmentTreeError::Binding)
    );
    assert_eq!(tree, before);

    let mut wrong_root = Fixture::new();
    wrong_root.pins.admission_partition = "other-partition".into();
    wrong_root.commit_root();
    let withdrawal = wrong_root.withdraw_as_parent(child);
    assert_eq!(
        tree.revoke_authorized(&fixture.context, NOW, &invocation(&withdrawal)),
        Err(EnrollmentTreeError::Binding)
    );
    assert_eq!(tree, before);

    let withdrawal = fixture.withdraw_as_parent(child);
    assert!(
        tree.revoke_authorized(&fixture.context, NOW + 3_601, &invocation(&withdrawal))
            .is_err()
    );
    assert_eq!(tree, before);
    tree.revoke_authorized(&fixture.context, NOW, &invocation(&withdrawal))
        .unwrap();
    assert_eq!(
        tree.parent_pins(child, NOW),
        Err(EnrollmentTreeError::Inactive)
    );
    let retained = tree.clone();
    tree.revoke_authorized(&fixture.context, NOW, &invocation(&withdrawal))
        .unwrap();
    assert_eq!(tree, retained);
}

fn configuration_journey(backend: Backend) {
    let db = TestAttempts::open(backend);
    let clock = Arc::new(FixedClock::at(NOW));
    let mut fixture = Fixture::new();
    fixture.commit_root();
    let (control, _) = controller(&fixture, db.raw(), Arc::clone(&clock));
    let root = fixture.bootstrap_configuration(&control).unwrap();
    assert_eq!(root.revision(), 1);
    assert_eq!(root.accepted_at(), NOW);
    let enrolled = fixture.enroll_configuration(&control).unwrap();
    assert_eq!(enrolled.revision(), 2);
    assert_eq!(enrolled.tree().participant_count(), 2);
    assert_eq!(
        fixture.enroll_configuration(&control),
        Err(EngagementConfigurationError::Native(
            EnrollmentTreeError::Replay
        ))
    );
    assert_eq!(control.snapshot().unwrap(), enrolled);

    let (reopened, _) = controller(&fixture, db.reopen().store(), Arc::clone(&clock));
    assert_eq!(reopened.dependency_key(), control.dependency_key());
    assert_eq!(reopened.snapshot().unwrap(), enrolled);
    clock.set(NOW - 1);
    let child = fixture.enrollment.commitment().unwrap();
    let withdrawal = fixture.withdraw_as_parent(child);
    assert_eq!(
        reopened.revoke(&invocation(&withdrawal)),
        Err(EngagementConfigurationError::ClockRollback)
    );
    assert_eq!(control.snapshot().unwrap(), enrolled);
    clock.set(NOW + 1);
    let revoked = reopened.revoke(&invocation(&withdrawal)).unwrap();
    assert_eq!(revoked.revision(), 3);
    assert_eq!(
        revoked.tree().parent_pins(child, NOW + 1),
        Err(EnrollmentTreeError::Inactive)
    );
    assert_eq!(control.revoke(&invocation(&withdrawal)).unwrap(), revoked);
    assert_eq!(fixture.bootstrap_configuration(&control).unwrap(), revoked);

    let root_withdrawal = fixture.withdraw_as_parent(fixture.pins.enrollment_commitment);
    let dead_root = reopened.revoke(&invocation(&root_withdrawal)).unwrap();
    assert_eq!(dead_root.revision(), 4);
    let (fresh_process, _) = controller(&fixture, db.reopen().store(), Arc::clone(&clock));
    assert_eq!(
        fixture.bootstrap_configuration(&fresh_process).unwrap(),
        dead_root
    );
    assert_eq!(
        fixture.enroll_configuration(&fresh_process),
        Err(EngagementConfigurationError::Native(
            EnrollmentTreeError::Inactive
        ))
    );
    clock.set(NOW + 86_400);
    assert_eq!(fresh_process.snapshot().unwrap(), dead_root);
    assert!(db.raw().attempt_keys(16).unwrap().is_empty());
    for debug in [format!("{fresh_process:?}"), format!("{dead_root:?}")] {
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains(fixture.child.principal.as_str()));
    }
}

#[test]
fn file_native_engagement_configuration_retains_ordered_revocation_after_reopen() {
    configuration_journey(Backend::File);
}

#[test]
fn postgres_native_engagement_configuration_retains_ordered_revocation_after_reopen() {
    if postgres_configured() {
        configuration_journey(Backend::Postgres);
    }
}

fn concurrent_enrollment(backend: Backend) {
    let db = TestAttempts::open(backend);
    let clock = Arc::new(FixedClock::at(NOW));
    let mut first = Fixture::new();
    first.commit_root();
    let mut second = Fixture::new();
    second.commit_root();
    let (left, _) = controller(&first, db.raw(), Arc::clone(&clock));
    let (right, _) = controller(&second, db.reopen().store(), Arc::clone(&clock));
    first.bootstrap_configuration(&left).unwrap();
    let retained = left.clone();
    let start = Arc::new(std::sync::Barrier::new(3));
    let a = Arc::clone(&start);
    let one = std::thread::spawn(move || {
        a.wait();
        first.enroll_configuration(&left)
    });
    let b = Arc::clone(&start);
    let two = std::thread::spawn(move || {
        b.wait();
        second.enroll_configuration(&right)
    });
    start.wait();
    let results = [one.join().unwrap(), two.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(EngagementConfigurationError::Native(
                    EnrollmentTreeError::Replay
                ))
            ))
            .count(),
        1
    );
    let snapshot = retained.snapshot().unwrap();
    assert_eq!(snapshot.revision(), 2);
    assert_eq!(snapshot.tree().participant_count(), 2);
    assert!(db.raw().attempt_keys(16).unwrap().is_empty());
}

#[test]
fn file_independent_controllers_cannot_publish_the_same_child_twice() {
    concurrent_enrollment(Backend::File);
}

#[test]
fn postgres_independent_controllers_cannot_publish_the_same_child_twice() {
    if postgres_configured() {
        concurrent_enrollment(Backend::Postgres);
    }
}

fn configuration_withdrawal(backend: Backend) {
    let db = TestAttempts::open(backend);
    let clock = Arc::new(FixedClock::at(NOW));
    let mut fixture = Fixture::new();
    fixture.commit_root();
    let (control, configuration) = controller(&fixture, db.raw(), Arc::clone(&clock));
    let original = fixture.bootstrap_configuration(&control).unwrap();
    let replacement = SharedConfiguration::new(db.raw(), [0x91; 32], [0x93; 32], 2);
    let previous = configuration.current_revision().unwrap();
    replacement
        .activate(previous, &QualificationGate::development())
        .unwrap();
    assert_eq!(
        fixture.enroll_configuration(&control),
        Err(EngagementConfigurationError::Configuration)
    );
    assert_eq!(control.snapshot().unwrap(), original);
}

#[test]
fn file_configuration_change_orders_before_new_native_enrollment() {
    configuration_withdrawal(Backend::File);
}

#[test]
fn postgres_configuration_change_orders_before_new_native_enrollment() {
    if postgres_configured() {
        configuration_withdrawal(Backend::Postgres);
    }
}

/// Forward real native decisions and unchanged snapshots. A reply can be lost
/// only after the maintained adapter actually commits; no bytes or grants are
/// synthesized. Clock advancement occurs inside its acquired writer fence.
struct ControlFaultStore {
    inner: Arc<dyn GatewayAttemptStore>,
    lose_reply: AtomicBool,
    advance_at_decision: AtomicBool,
    clock: Arc<FixedClock>,
}

impl GatewayAttemptStore for ControlFaultStore {
    fn fenced_insert_all(
        &self,
        entries: &[GatewayRecordEntry],
        dependencies: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut crate::GatewayFenceDecision<'_>,
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        self.inner.fenced_insert_all(entries, dependencies, decide)
    }
    fn fenced_replace(
        &self,
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut crate::GatewayFenceDecision<'_>,
    ) -> Result<(), GatewayAttemptError> {
        self.inner.fenced_replace(keys, &mut |snapshots| {
            if self.advance_at_decision.swap(false, Ordering::SeqCst) {
                self.clock.set(NOW + 601);
            }
            decide(snapshots)
        })?;
        if self.lose_reply.swap(false, Ordering::SeqCst) {
            Err(GatewayAttemptError::Unavailable)
        } else {
            Ok(())
        }
    }
    fn insert_all(
        &self,
        entries: &[GatewayRecordEntry],
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        self.inner.insert_all(entries)
    }
    fn load(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
    ) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        self.inner.load(kind, key)
    }
    fn replace(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        self.inner.replace(kind, key, current, next)
    }
    fn sweep_expired(&self, now: u64, limit: usize) -> Result<usize, GatewayAttemptError> {
        self.inner.sweep_expired(now, limit)
    }
    fn attempt_keys(&self, limit: usize) -> Result<Vec<GatewayAttemptKey>, GatewayAttemptError> {
        self.inner.attempt_keys(limit)
    }
}

#[test]
fn committed_enrollment_with_lost_reply_is_retained_without_republication() {
    let db = TestAttempts::open(Backend::File);
    let clock = Arc::new(FixedClock::at(NOW));
    let store = Arc::new(ControlFaultStore {
        inner: db.raw(),
        lose_reply: AtomicBool::new(false),
        advance_at_decision: AtomicBool::new(false),
        clock: Arc::clone(&clock),
    });
    let mut fixture = Fixture::new();
    fixture.commit_root();
    let (control, _) = controller(&fixture, store.clone(), clock);
    fixture.bootstrap_configuration(&control).unwrap();
    store.lose_reply.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture.enroll_configuration(&control),
        Err(EngagementConfigurationError::Store(
            GatewayAttemptError::Unavailable
        ))
    );
    let committed = control.snapshot().unwrap();
    assert_eq!(committed.revision(), 2);
    assert_eq!(committed.tree().participant_count(), 2);
    assert_eq!(
        fixture.enroll_configuration(&control),
        Err(EngagementConfigurationError::Native(
            EnrollmentTreeError::Replay
        ))
    );
    assert_eq!(control.snapshot().unwrap(), committed);
}

#[test]
fn enrollment_samples_current_time_inside_the_adapter_decision_fence() {
    let db = TestAttempts::open(Backend::File);
    let clock = Arc::new(FixedClock::at(NOW));
    let store = Arc::new(ControlFaultStore {
        inner: db.raw(),
        lose_reply: AtomicBool::new(false),
        advance_at_decision: AtomicBool::new(false),
        clock: Arc::clone(&clock),
    });
    let mut fixture = Fixture::new();
    fixture.commit_root();
    let (control, _) = controller(&fixture, store.clone(), clock);
    let original = fixture.bootstrap_configuration(&control).unwrap();
    store.advance_at_decision.store(true, Ordering::SeqCst);
    assert!(fixture.enroll_configuration(&control).is_err());
    assert_eq!(control.snapshot().unwrap(), original);
}

#[test]
fn corrupt_configuration_never_becomes_absent_or_reactivates_root() {
    let db = TestAttempts::open(Backend::File);
    let clock = Arc::new(FixedClock::at(NOW));
    let mut fixture = Fixture::new();
    fixture.commit_root();
    let (control, _) = controller(&fixture, db.raw(), clock);
    let root = fixture.bootstrap_configuration(&control).unwrap();
    let store = db.raw();
    let key = control.dependency_key();
    let original = store
        .load(GatewayRecordKind::EffectConfiguration, &key)
        .unwrap()
        .unwrap();
    for change in 0..8 {
        let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
        match change {
            0 => record["schema"] = serde_json::json!("auths.engagement-configuration/0"),
            1 => record["root"] = serde_json::json!([0]),
            2 => record["revision"] = serde_json::json!(0),
            3 => record["accepted_at"] = serde_json::json!(u64::MAX),
            4 => record["tree"] = serde_json::json!("{}"),
            5 => record["unknown"] = serde_json::json!(true),
            6 => record["tree"] = serde_json::json!(" ".repeat(196_609)),
            _ => {}
        }
        let mut changed = serde_json::to_vec(&record).unwrap();
        if change == 7 {
            changed.push(b' ');
        }
        store
            .replace(
                GatewayRecordKind::EffectConfiguration,
                &key,
                &original,
                &changed,
            )
            .unwrap();
        assert_eq!(
            control.snapshot(),
            Err(EngagementConfigurationError::Corrupt),
            "case {change}"
        );
        assert_eq!(
            fixture.bootstrap_configuration(&control),
            Err(EngagementConfigurationError::Corrupt)
        );
        assert_eq!(
            store
                .load(GatewayRecordKind::EffectConfiguration, &key)
                .unwrap(),
            Some(changed.clone())
        );
        store
            .replace(
                GatewayRecordKind::EffectConfiguration,
                &key,
                &changed,
                &original,
            )
            .unwrap();
    }
    assert_eq!(control.snapshot().unwrap(), root);
}

#[test]
fn configuration_revision_saturation_preserves_history_without_partial_enrollment() {
    let db = TestAttempts::open(Backend::File);
    let clock = Arc::new(FixedClock::at(NOW));
    let mut fixture = Fixture::new();
    fixture.commit_root();
    let (control, _) = controller(&fixture, db.raw(), clock);
    fixture.bootstrap_configuration(&control).unwrap();
    let store = db.raw();
    let key = control.dependency_key();
    let original = store
        .load(GatewayRecordKind::EffectConfiguration, &key)
        .unwrap()
        .unwrap();
    let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
    record["revision"] = serde_json::json!((1u64 << 53) - 1);
    let saturated = serde_json_canonicalizer::to_vec(&record).unwrap();
    store
        .replace(
            GatewayRecordKind::EffectConfiguration,
            &key,
            &original,
            &saturated,
        )
        .unwrap();
    let before = control.snapshot().unwrap();
    assert_eq!(
        fixture.enroll_configuration(&control),
        Err(EngagementConfigurationError::RevisionExhausted)
    );
    assert_eq!(control.snapshot().unwrap(), before);
    assert_eq!(before.tree().participant_count(), 1);
}

#[test]
fn provider_eligibility_failure_is_not_a_new_withdrawal_gate() {
    let db = TestAttempts::open(Backend::File);
    let clock = Arc::new(FixedClock::at(NOW));
    let mut fixture = Fixture::new();
    fixture.commit_root();
    let (initial, configuration) = controller(&fixture, db.raw(), Arc::clone(&clock));
    fixture.bootstrap_configuration(&initial).unwrap();
    let gate = Arc::new(QualificationGate::new(
        QualificationPolicy::Required,
        None,
        None,
        Box::new(clock),
        auths_recipe_qualification::VerifierState::default(),
    ));
    assert!(gate.check().is_err());
    // The unit fixture holds the same installed configuration and qualification
    // memory. It isolates the native control rule, not a live qualification
    // expiration or a production configuration-policy transition.
    let restricted = EngagementConfiguration::new(
        db.raw(),
        fixture.pins.clone(),
        fixture.context.clone(),
        configuration,
        gate,
    )
    .unwrap();
    assert_eq!(
        fixture.enroll_configuration(&restricted),
        Err(EngagementConfigurationError::Configuration)
    );
    let withdrawal = fixture.withdraw_as_parent(fixture.pins.enrollment_commitment);
    let stopped = restricted.revoke(&invocation(&withdrawal)).unwrap();
    assert_eq!(
        stopped
            .tree()
            .parent_pins(fixture.pins.enrollment_commitment, NOW),
        Err(EnrollmentTreeError::Inactive)
    );
}

/// Canonical private control records from real native decisions and the
/// maintained file adapter. This does not construct an operation or permit.
#[test]
fn native_engagement_configuration_fixture_is_current() {
    let db = TestAttempts::open(Backend::File);
    let clock = Arc::new(FixedClock::at(NOW));
    let mut fixture = Fixture::new();
    fixture.commit_root();
    let (control, _) = controller(&fixture, db.raw(), Arc::clone(&clock));
    let store = db.raw();
    let key = control.dependency_key();
    let retained_bytes = || {
        String::from_utf8(
            store
                .load(GatewayRecordKind::EffectConfiguration, &key)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    };
    let root = fixture.bootstrap_configuration(&control).unwrap();
    let root_bytes = retained_bytes();
    let enrolled = fixture.enroll_configuration(&control).unwrap();
    let enrolled_bytes = retained_bytes();
    let child = fixture.enrollment.commitment().unwrap();
    let withdrawal = fixture.withdraw_as_parent(child);
    let revoked = control.revoke(&invocation(&withdrawal)).unwrap();
    let revoked_bytes = retained_bytes();
    assert_eq!(
        revoked.tree().parent_pins(child, NOW),
        Err(EnrollmentTreeError::Inactive)
    );
    let (reopened, _) = controller(&fixture, db.reopen().store(), Arc::clone(&clock));
    assert_eq!(reopened.snapshot().unwrap(), revoked);
    assert_eq!(fixture.bootstrap_configuration(&reopened).unwrap(), revoked);
    assert_eq!(reopened.revoke(&invocation(&withdrawal)).unwrap(), revoked);
    assert_eq!(retained_bytes(), revoked_bytes);
    assert_eq!(store.sweep_expired(NOW + 86_400, 64).unwrap(), 0);
    assert_eq!(reopened.snapshot().unwrap(), revoked);
    assert!(store.attempt_keys(16).unwrap().is_empty());

    let value = serde_json::json!({
        "schema": "auths.engagement-configuration-vectors/1",
        "claim_boundary": "private native control configuration; no operation admission, budget reservation or transport permit",
        "original_proof_retention": "not retained in these configuration records; independent audit needs original inputs",
        "record_kind": GatewayRecordKind::EffectConfiguration.as_str(),
        "record_key_hex": hex::encode(key.as_bytes()),
        "records": [
            {"stage": "root", "revision": root.revision(), "accepted_at": root.accepted_at(),
                "canonical_json": root_bytes, "participants": root.tree().participant_count()},
            {"stage": "child-enrolled", "revision": enrolled.revision(), "accepted_at": enrolled.accepted_at(),
                "canonical_json": enrolled_bytes, "participants": enrolled.tree().participant_count()},
            {"stage": "child-withdrawn", "revision": revoked.revision(), "accepted_at": revoked.accepted_at(),
                "canonical_json": revoked_bytes, "participants": revoked.tree().participant_count(),
                "new_child_scope_eligible": false}
        ],
        "operation_records": 0,
        "reopen_preserves_withdrawal": true,
        "bootstrap_replay_reactivates_nothing": true,
        "withdrawal_replay_adds_no_revision": true,
        "expiry_sweep_removes_no_control_records": true
    });
    let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/configuration.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    } else {
        assert_eq!(
            std::fs::read(path).unwrap(),
            bytes,
            "regenerate native engagement configuration corpus with AUTHS_UPDATE_FIXTURES=1"
        );
    }
}
