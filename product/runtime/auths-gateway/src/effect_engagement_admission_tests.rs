//! Native enrolled siblings and real adapter fences. Grants here are dropped;
//! no credential is leased, provider contacted or external outcome asserted.
use super::*;
use crate::participant_enrollment::tests::{EffectScopeFixture, effect_scope_fixture_for_actor};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    GatewayAttemptError, GatewayAttemptKey, GatewayAttemptStore, GatewayInsert, GatewayRecordEntry,
    GatewayRecordKind,
};
use std::sync::{
    Barrier,
    atomic::{AtomicBool, Ordering},
};

pub(super) struct Setup {
    pub(super) backend: TestAttempts,
    pub(super) store: Arc<dyn GatewayAttemptStore>,
    pub(super) recipe: CompiledRecipe,
    pub(super) connection: ConnectionRecord,
    pub(super) native: EffectScopeFixture,
    pub(super) policy: EffectPolicy,
    pub(super) loaded: crate::LoadedConnection,
    pub(super) configuration: crate::configuration::SharedConfiguration,
    pub(super) controller: crate::EngagementConfiguration,
    pub(super) qualification: Arc<crate::QualificationGate>,
}

impl Setup {
    async fn new(backend: Backend) -> Self {
        Self::with_recipe(backend, recipe(&json!({}), &Value::Null), [1; 32]).await
    }
    pub(super) async fn with_recipe(
        backend: Backend,
        recipe: CompiledRecipe,
        engagement: [u8; 32],
    ) -> Self {
        Self::with_inputs(backend, recipe, engagement, None).await
    }
    pub(super) async fn with_channel(
        backend: Backend,
        recipe: CompiledRecipe,
        engagement: [u8; 32],
        channel: [u8; 32],
    ) -> Self {
        Self::with_inputs(backend, recipe, engagement, Some(channel)).await
    }
    async fn with_inputs(
        backend: Backend,
        recipe: CompiledRecipe,
        engagement: [u8; 32],
        channel: Option<[u8; 32]>,
    ) -> Self {
        let backend = TestAttempts::open(backend);
        let store = backend.raw();
        let connection = connection(&recipe);
        let args = json!({"operation_id":"initial", "operator_namespace":NAMESPACE, "recipe_digest":recipe.digest_hex(), "record_id":RECORD, "replacement":"Approved"});
        let native = crate::participant_enrollment::tests::effect_scope_fixture_with_channel(
            &recipe,
            &connection,
            args.as_object().unwrap(),
            0x44,
            engagement,
            channel,
        );
        let policy = policy(native.root.clone(), "gateway");
        let configuration = crate::configuration::SharedConfiguration::new(
            Arc::clone(&store),
            policy.configuration_key(recipe.namespace()).unwrap(),
            [12; 32],
            policy.epoch(),
        );
        let qualification = Arc::new(crate::QualificationGate::new(
            crate::QualificationPolicy::Optional,
            None,
            None,
            Box::new(Arc::new(crate::FixedClock::at(NOW))),
            auths_recipe_qualification::VerifierState::default(),
        ));
        let shared = crate::SharedConnection::new(
            Arc::clone(&store),
            connection.provider_kind().clone(),
            connection.alias().clone(),
        );
        shared.insert(&connection).await.unwrap();
        let loaded = shared.load().await.unwrap().unwrap();
        let (controller, native) = {
            let store = Arc::clone(&store);
            let config = configuration.clone();
            let gate = Arc::clone(&qualification);
            tokio::task::spawn_blocking(move || {
                config.initialize(&gate).unwrap();
                let controller = crate::EngagementConfiguration::new(
                    store,
                    native.root.clone(),
                    native.context.clone(),
                    config,
                    gate,
                )
                .unwrap();
                native.persist(&controller);
                (controller, native)
            })
            .await
            .unwrap()
        };
        Self {
            backend,
            store,
            recipe,
            connection,
            native,
            policy,
            loaded,
            configuration,
            controller,
            qualification,
        }
    }
    fn approved(&self, operation: &str, actor: u8) -> Arc<crate::effect::ApprovedEffect> {
        let native = native(&self.recipe, &self.connection, operation, actor);
        assert!(native.root == self.native.root && native.tree == self.native.tree);
        Arc::new(approve(
            compile_mutation_effect(
                &self
                    .policy
                    .installation(
                        &self.recipe,
                        &native.context,
                        &self.connection,
                        crate::QualificationPolicy::Optional,
                        [12; 32],
                    )
                    .with_enrollment(Some(&native.tree)),
                NOW,
                &native.action.proof,
                &native.action.action,
            )
            .unwrap(),
        ))
    }
    pub(super) fn validation(&self) -> crate::entry::EntryValidation {
        crate::entry::EntryValidation::Installed(Box::new(crate::entry::InstalledEntry {
            recipe: self.recipe.clone(),
            trust: self.native.context.clone(),
            observer: None,
            policy: self.policy.clone(),
            configuration: self.configuration.clone(),
            engagement: Some(self.controller.clone()),
            connection: crate::entry::EntryConnection::Installed(Box::new(self.loaded.clone())),
            connection_key: crate::connection_key(
                self.connection.provider_kind(),
                self.connection.alias(),
            ),
            qualification: Arc::clone(&self.qualification),
            workload: "gateway".to_owned(),
            profile: self.connection.allowed_profiles()[0].clone(),
            started: std::time::Instant::now(),
            #[cfg(unix)]
            commissioning: None,
        }))
    }
    pub(super) fn attempts(&self, store: Arc<dyn GatewayAttemptStore>) -> crate::GatewayAttempts {
        crate::GatewayAttempts::new(store, self.policy.clone()).unwrap()
    }
    fn key(&self, operation: &str) -> GatewayAttemptKey {
        GatewayAttemptKey::for_operation(
            &self.policy,
            self.recipe.namespace(),
            &crate::LogicalOperationId::parse(operation).unwrap(),
        )
        .unwrap()
    }
    async fn record(&self, operation: &str) -> Option<Vec<u8>> {
        load(&self.store, GatewayRecordKind::Attempt, self.key(operation)).await
    }
    async fn allocations(&self, approved: &crate::effect::ApprovedEffect) -> Vec<Option<Vec<u8>>> {
        let mut rows = Vec::new();
        for declaration in approved.effect().binding().engagement_reservations() {
            rows.push(
                load(
                    &self.store,
                    GatewayRecordKind::EffectAllocation,
                    crate::store::fixture_engagement_allocation_key(&declaration.key, 0),
                )
                .await,
            );
        }
        rows
    }
}
fn native(
    recipe: &CompiledRecipe,
    connection: &ConnectionRecord,
    operation: &str,
    actor: u8,
) -> EffectScopeFixture {
    let args = json!({"operation_id":operation, "operator_namespace":NAMESPACE,
        "recipe_digest":recipe.digest_hex(), "record_id":RECORD, "replacement":"Approved"});
    effect_scope_fixture_for_actor(recipe, connection, args.as_object().unwrap(), actor)
}
async fn load(
    store: &Arc<dyn GatewayAttemptStore>,
    kind: GatewayRecordKind,
    key: GatewayAttemptKey,
) -> Option<Vec<u8>> {
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || store.load(kind, &key).unwrap())
        .await
        .unwrap()
}
fn claimed(claim: crate::store::BoundedClaim) -> crate::ClaimedGatewayAttempt {
    match claim {
        crate::store::BoundedClaim::Claimed(claimed) => *claimed,
        _ => panic!("native claim required"),
    }
}

/// Faults alter only acknowledgement delivery or a final snapshot. All preceding
/// writes, decisions, transactions and reopen behavior use maintained adapters.
pub(super) struct FaultStore {
    inner: Arc<dyn GatewayAttemptStore>,
    lose_claim_reply: AtomicBool,
    lose_grant_reply: AtomicBool,
    hide_allocation: AtomicBool,
    preceding_lookup_absence: AtomicBool,
    candidate_barrier: Option<Arc<Barrier>>,
    wait_once: AtomicBool,
}
impl FaultStore {
    pub(super) fn new(inner: Arc<dyn GatewayAttemptStore>) -> Self {
        Self {
            inner,
            lose_claim_reply: AtomicBool::new(false),
            lose_grant_reply: AtomicBool::new(false),
            hide_allocation: AtomicBool::new(false),
            preceding_lookup_absence: AtomicBool::new(false),
            candidate_barrier: None,
            wait_once: AtomicBool::new(true),
        }
    }
    pub(super) fn lose_next_claim_reply(&self) {
        self.lose_claim_reply.store(true, Ordering::SeqCst);
    }
    pub(super) fn lose_next_grant_reply(&self) {
        self.lose_grant_reply.store(true, Ordering::SeqCst);
    }
}
impl GatewayAttemptStore for FaultStore {
    fn fenced_insert_all(
        &self,
        entries: &[GatewayRecordEntry],
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut crate::GatewayFenceDecision<'_>,
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        if entries
            .first()
            .is_some_and(|entry| entry.kind == GatewayRecordKind::Attempt)
            && self.wait_once.swap(false, Ordering::SeqCst)
            && let Some(barrier) = &self.candidate_barrier
        {
            barrier.wait();
        }
        let result = self.inner.fenced_insert_all(entries, keys, decide)?;
        if result == GatewayInsert::Inserted && self.lose_claim_reply.swap(false, Ordering::SeqCst)
        {
            return Err(GatewayAttemptError::Unavailable);
        }
        Ok(result)
    }
    fn fenced_replace(
        &self,
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut crate::GatewayFenceDecision<'_>,
    ) -> Result<(), GatewayAttemptError> {
        self.inner.fenced_replace(keys, &mut |snapshots| {
            if self.hide_allocation.load(Ordering::SeqCst) {
                let mut altered = snapshots.to_vec();
                let index = keys
                    .iter()
                    .position(|(kind, _)| *kind == GatewayRecordKind::EffectAllocation)
                    .unwrap();
                altered[index] = None;
                decide(&altered)
            } else {
                decide(snapshots)
            }
        })?;
        if self.lose_grant_reply.swap(false, Ordering::SeqCst) {
            return Err(GatewayAttemptError::Unavailable);
        }
        Ok(())
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
        if kind == GatewayRecordKind::Attempt
            && self.preceding_lookup_absence.swap(false, Ordering::SeqCst)
        {
            // Model the caller's lookup just before a winning transaction;
            // every subsequent allocation/history read uses actual state.
            return Ok(None);
        }
        self.inner.load(kind, key)
    }
    fn replace(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
        old: &[u8],
        new: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        self.inner.replace(kind, key, old, new)
    }
    fn sweep_expired(&self, now: u64, limit: usize) -> Result<usize, GatewayAttemptError> {
        self.inner.sweep_expired(now, limit)
    }
    fn attempt_keys(&self, limit: usize) -> Result<Vec<GatewayAttemptKey>, GatewayAttemptError> {
        self.inner.attempt_keys(limit)
    }
}

async fn lifecycle(backend: Backend) -> Value {
    let setup = Setup::new(backend).await;
    let approved = setup.approved("first", 0x44);
    let attempts = setup.attempts(Arc::clone(&setup.store));
    let reserved = claimed(
        attempts
            .claim_bounded(&approved, NOW, setup.validation())
            .await
            .unwrap(),
    );
    let reserved_bytes = setup.record("first").await.unwrap();
    let record: Value = serde_json::from_slice(&reserved_bytes).unwrap();
    assert_eq!(record["schema"], "auths.gateway-attempt/17");
    assert_eq!(
        record["engagement_allocations"].as_array().unwrap().len(),
        2
    );
    let slots = setup.allocations(&approved).await;
    assert!(slots.iter().all(Option::is_some));
    let replay = claimed(
        attempts
            .claim_bounded(&approved, NOW, setup.validation())
            .await
            .unwrap(),
    );
    drop(replay);
    assert_eq!(setup.record("first").await.unwrap(), reserved_bytes);
    assert_eq!(setup.allocations(&approved).await, slots);
    let (granted, permit) = reserved
        .grant_entry(
            Arc::clone(&approved),
            setup.validation(),
            NOW,
            &crate::GatewayPreEntry::default(),
        )
        .await
        .unwrap();
    drop((granted, permit)); // process loss after durable entry, before any send
    let reopened = setup.attempts(setup.backend.raw());
    let snapshot = reopened
        .read(
            setup.recipe.namespace(),
            &crate::LogicalOperationId::parse("first").unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.stage(), crate::GatewayAttemptStage::Unknown);
    assert!(matches!(
        reopened
            .claim_bounded(&approved, NOW, setup.validation())
            .await,
        Err(GatewayAttemptError::Replay)
    ));
    let sibling = setup.approved("sibling", 0x55);
    assert!(
        reopened
            .claim_bounded(&sibling, NOW, setup.validation())
            .await
            .is_err()
    );
    assert!(setup.record("sibling").await.is_none());
    let sibling_rows = setup.allocations(&sibling).await;
    assert_eq!(
        sibling_rows.iter().filter(|row| row.is_some()).count(),
        1,
        "only shared root was already spent"
    );
    assert_eq!(setup.allocations(&approved).await, slots);
    let input = native(&setup.recipe, &setup.connection, "first", 0x44);
    let context = setup
        .policy
        .installation(
            &setup.recipe,
            &input.context,
            &setup.connection,
            crate::QualificationPolicy::Optional,
            [12; 32],
        )
        .native_context()
        .unwrap();
    let project = |mut record: Value| {
        record.as_object_mut().unwrap().remove("nonce");
        record["schema"] = json!("auths.engagement-admission-private-projection/1");
        record
    };
    json!({"reserved_record":project(record), "after_dropped_grant":project(serde_json::from_slice::<Value>(&setup.record("first").await.unwrap()).unwrap()),
        "record_schema":"auths.gateway-attempt/17", "projection_omits_private_random_nonce":true,
        "native_authorization":{"proof_hex":hex::encode(input.action.proof), "action_hex":hex::encode(input.action.action),
            "context_hex":hex::encode(auths_codec::encode_verifier_context(&context).unwrap())},
        "allocation_rows":slots.into_iter().map(|row| serde_json::from_slice::<Value>(&row.unwrap()).unwrap()).collect::<Vec<_>>(),
        "replay_created_no_permit":true, "sibling_denied_without_partial_charge":true, "provider_calls":0})
}

#[tokio::test]
async fn file_native_ancestor_admission_survives_replay_and_reopen() {
    lifecycle(Backend::File).await;
}
#[tokio::test]
async fn postgres_native_ancestor_admission_survives_replay_and_reopen() {
    if postgres_configured() {
        lifecycle(Backend::Postgres).await;
    }
}

async fn concurrent_siblings(backend: Backend) {
    let setup = Setup::new(backend).await;
    let a = setup.approved("race-a", 0x44);
    let b = setup.approved("race-b", 0x55);
    let barrier = Arc::new(Barrier::new(2));
    let wrap = || {
        let mut wrapped = FaultStore::new(setup.backend.raw());
        wrapped.candidate_barrier = Some(Arc::clone(&barrier));
        Arc::new(wrapped) as Arc<dyn GatewayAttemptStore>
    };
    let first = setup.attempts(wrap());
    let second = setup.attempts(wrap());
    let va = setup.validation();
    let vb = setup.validation();
    let (a_result, b_result) = tokio::join!(
        first.claim_bounded(&a, NOW, va),
        second.claim_bounded(&b, NOW, vb)
    );
    assert_eq!(
        usize::from(a_result.is_ok()) + usize::from(b_result.is_ok()),
        1
    );
    let a_rows = setup.allocations(&a).await;
    let b_rows = setup.allocations(&b).await;
    assert_eq!(
        a_rows.iter().filter(|r| r.is_some()).count()
            + b_rows.iter().filter(|r| r.is_some()).count(),
        3
    );
    assert_eq!(
        usize::from(setup.record("race-a").await.is_some())
            + usize::from(setup.record("race-b").await.is_some()),
        1
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_independent_adapters_cannot_double_spend_the_last_root_unit() {
    concurrent_siblings(Backend::File).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_independent_adapters_cannot_double_spend_the_last_root_unit() {
    if postgres_configured() {
        concurrent_siblings(Backend::Postgres).await;
    }
}

async fn acknowledgement_loss(backend: Backend, grant: bool) {
    let setup = Setup::new(backend).await;
    let faults = Arc::new(FaultStore::new(setup.backend.raw()));
    let store: Arc<dyn GatewayAttemptStore> = faults.clone();
    let attempts = setup.attempts(store);
    let approved = setup.approved("lost-reply", 0x44);
    if !grant {
        faults.lose_claim_reply.store(true, Ordering::SeqCst);
    }
    let result = attempts
        .claim_bounded(&approved, NOW, setup.validation())
        .await;
    if grant {
        let reserved = claimed(result.unwrap());
        faults.lose_grant_reply.store(true, Ordering::SeqCst);
        assert!(
            reserved
                .grant_entry(
                    Arc::clone(&approved),
                    setup.validation(),
                    NOW,
                    &crate::GatewayPreEntry::default()
                )
                .await
                .is_err()
        );
    } else {
        assert!(matches!(result, Err(GatewayAttemptError::Unavailable)));
    }
    let retained = setup.record("lost-reply").await.unwrap();
    assert!(
        setup
            .allocations(&approved)
            .await
            .iter()
            .all(Option::is_some)
    );
    let replay = attempts
        .claim_bounded(&approved, NOW, setup.validation())
        .await;
    if grant {
        assert!(matches!(replay, Err(GatewayAttemptError::Replay)));
    } else {
        drop(claimed(replay.unwrap()));
    }
    assert_eq!(setup.record("lost-reply").await.unwrap(), retained);
    assert!(
        attempts
            .claim_bounded(&setup.approved("other", 0x55), NOW, setup.validation())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn file_ambiguous_claim_and_grant_acknowledgements_never_recharge_or_remint() {
    acknowledgement_loss(Backend::File, false).await;
    acknowledgement_loss(Backend::File, true).await;
}
#[tokio::test]
async fn postgres_ambiguous_claim_and_grant_acknowledgements_never_recharge_or_remint() {
    if postgres_configured() {
        acknowledgement_loss(Backend::Postgres, false).await;
        acknowledgement_loss(Backend::Postgres, true).await;
    }
}

async fn missing_allocation(backend: Backend) {
    let setup = Setup::new(backend).await;
    let faults = Arc::new(FaultStore::new(setup.backend.raw()));
    let store: Arc<dyn GatewayAttemptStore> = faults.clone();
    let attempts = setup.attempts(store);
    let approved = setup.approved("missing", 0x44);
    let reserved = claimed(
        attempts
            .claim_bounded(&approved, NOW, setup.validation())
            .await
            .unwrap(),
    );
    faults.hide_allocation.store(true, Ordering::SeqCst);
    assert!(
        reserved
            .grant_entry(
                Arc::clone(&approved),
                setup.validation(),
                NOW,
                &crate::GatewayPreEntry::default()
            )
            .await
            .is_err()
    );
    let record: Value = serde_json::from_slice(&setup.record("missing").await.unwrap()).unwrap();
    assert!(record["entry"].is_null());
    assert_eq!(record["state"]["facts"]["stage"], "reserved");
}
#[tokio::test]
async fn file_incomplete_allocation_snapshot_cannot_grant_entry() {
    missing_allocation(Backend::File).await;
}
#[tokio::test]
async fn postgres_incomplete_allocation_snapshot_cannot_grant_entry() {
    if postgres_configured() {
        missing_allocation(Backend::Postgres).await;
    }
}

async fn revocation(backend: Backend, after_claim: bool) {
    let setup = Setup::new(backend).await;
    let approved = setup.approved("revoked", 0x44);
    let attempts = setup.attempts(Arc::clone(&setup.store));
    let reserved = if after_claim {
        Some(claimed(
            attempts
                .claim_bounded(&approved, NOW, setup.validation())
                .await
                .unwrap(),
        ))
    } else {
        None
    };
    let controller = setup.controller.clone();
    // Native control proof is retained in the fixture; perform the actual
    // narrowing transaction off the async executor for both maintained adapters.
    let native = native(&setup.recipe, &setup.connection, "revoked", 0x44);
    tokio::task::spawn_blocking(move || native.withdraw_root(&controller))
        .await
        .unwrap();
    if let Some(reserved) = reserved {
        assert!(
            reserved
                .grant_entry(
                    Arc::clone(&approved),
                    setup.validation(),
                    NOW,
                    &crate::GatewayPreEntry::default()
                )
                .await
                .is_err()
        );
        assert!(
            setup
                .allocations(&approved)
                .await
                .iter()
                .all(Option::is_some)
        );
    } else {
        assert!(
            attempts
                .claim_bounded(&approved, NOW, setup.validation())
                .await
                .is_err()
        );
        assert!(setup.record("revoked").await.is_none());
        assert!(
            setup
                .allocations(&approved)
                .await
                .iter()
                .all(Option::is_none)
        );
    }
}
#[tokio::test]
async fn file_native_root_revocation_orders_before_claim_or_entry() {
    revocation(Backend::File, false).await;
    revocation(Backend::File, true).await;
}
#[tokio::test]
async fn postgres_native_root_revocation_orders_before_claim_or_entry() {
    if postgres_configured() {
        revocation(Backend::Postgres, false).await;
        revocation(Backend::Postgres, true).await;
    }
}

#[cfg(all(unix, feature = "loopback-provider", feature = "testkit-harness"))]
#[tokio::test]
async fn file_partial_ancestor_batch_io_failures_reopen_without_partial_admission() {
    for skip in 0..3 {
        let setup = Setup::new(Backend::File).await;
        let file = Arc::new(
            crate::FileGatewayAttemptStore::open(std::path::PathBuf::from(
                setup.backend.location(),
            ))
            .unwrap(),
        );
        file.arm_io_failure(crate::store::FileIoPoint::InstallTarget, skip)
            .unwrap();
        let store: Arc<dyn GatewayAttemptStore> = file.clone();
        let attempts = setup.attempts(store);
        let approved = setup.approved("partial", 0x44);
        assert!(
            attempts
                .claim_bounded(&approved, NOW, setup.validation())
                .await
                .is_err()
        );
        assert_eq!(file.injected_io_failures().unwrap(), 1);
        // A newly opened adapter runs the maintained crashed-batch rollback.
        drop(setup.backend.raw());
        assert!(setup.record("partial").await.is_none());
        assert!(
            setup
                .allocations(&approved)
                .await
                .iter()
                .all(Option::is_none)
        );
    }
}
#[cfg(all(unix, feature = "loopback-provider", feature = "testkit-harness"))]
#[tokio::test]
async fn postgres_server_rejection_rolls_back_operation_and_all_ancestor_rows() {
    if !postgres_configured() {
        return;
    }
    for fail_at in 1..=3 {
        let setup = Setup::new(Backend::Postgres).await;
        setup.backend.reject_postgres_batch_insert(fail_at);
        let attempts = setup.attempts(Arc::clone(&setup.store));
        let approved = setup.approved("rollback", 0x44);
        assert!(
            attempts
                .claim_bounded(&approved, NOW, setup.validation())
                .await
                .is_err()
        );
        assert_eq!(setup.backend.clear_postgres_batch_failure(), fail_at);
        assert!(setup.record("rollback").await.is_none());
        assert!(
            setup
                .allocations(&approved)
                .await
                .iter()
                .all(Option::is_none)
        );
    }
}

#[tokio::test]
async fn native_engagement_admission_fixture_is_current() {
    let document = json!({"schema":"auths.engagement-admission-vectors/1",
        "generated_by":"native_engagement_admission_fixture_is_current",
        "scope":"native root activation, two child consents, real file admission and durable grant; controlled deployment clock; dropped permit; no provider send",
        "not_established":["actual-provider-effect", "postgres-execution", "cross-process-concurrency", "forced-process-crash", "cross-recipe-resource-authority", "installed-key-containment", "independent-original-control-proof-history"],
        "case":lifecycle(Backend::File).await});
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/admission.json");
    let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
    bytes.push(b'\n');
    // The artifact carries an explicitly named private projection, not edited
    // restorable journal bytes. Nonces are omitted by the native case above.
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

async fn winner_after_lookup(backend: Backend) {
    let setup = Setup::new(backend).await;
    let approved = setup.approved("lookup-winner", 0x44);
    let attempts = setup.attempts(Arc::clone(&setup.store));
    drop(claimed(
        attempts
            .claim_bounded(&approved, NOW, setup.validation())
            .await
            .unwrap(),
    ));
    let before = setup.record("lookup-winner").await.unwrap();
    let slots = setup.allocations(&approved).await;
    let faults = Arc::new(FaultStore::new(setup.backend.raw()));
    faults
        .preceding_lookup_absence
        .store(true, Ordering::SeqCst);
    let attempts = setup.attempts(faults);
    drop(claimed(
        attempts
            .claim_bounded(&approved, NOW, setup.validation())
            .await
            .unwrap(),
    ));
    assert_eq!(setup.record("lookup-winner").await.unwrap(), before);
    assert_eq!(setup.allocations(&approved).await, slots);
}
#[tokio::test]
async fn file_winner_after_history_lookup_reopens_without_a_second_charge() {
    winner_after_lookup(Backend::File).await;
}
#[tokio::test]
async fn postgres_winner_after_history_lookup_reopens_without_a_second_charge() {
    if postgres_configured() {
        winner_after_lookup(Backend::Postgres).await;
    }
}
