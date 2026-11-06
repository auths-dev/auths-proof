//! Actual engine/application control transport over real Unix sockets. Fixed
//! public fixture keys and same-process peers establish no installed isolation.
use super::admission_tests::FaultStore;
use super::*;
use crate::app::{
    APP_PARTICIPANT_SCHEMA, AppParticipantControl, app_session, read_frame, write_frame,
};
use crate::participant_enrollment::tests::{EffectScopeFixture, effect_scope_fixture};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    EngagementControlEvidence, GatewayAttemptStore, GatewayEngine, ParticipantControlOutcome,
};
use base64ct::{Base64, Base64UrlUnpadded};
use tokio::net::UnixStream;

struct Control {
    backend: TestAttempts,
    store: Arc<FaultStore>,
    engine: Arc<GatewayEngine>,
    recipe: CompiledRecipe,
    connection: ConnectionRecord,
    native: EffectScopeFixture,
    policy: EffectPolicy,
    clock: Arc<crate::FixedClock>,
}
impl Control {
    async fn new(backend: Backend, scoped: bool) -> Self {
        let backend = TestAttempts::open(backend);
        let store = Arc::new(FaultStore::new(backend.raw()));
        let recipe = recipe(&json!({}), &Value::Null);
        let connection = connection(&recipe);
        let arguments = json!({"operation_id":"control-check", "operator_namespace":NAMESPACE,
            "recipe_digest":recipe.digest_hex(), "record_id":RECORD, "replacement":"Approved"});
        let native = effect_scope_fixture(&recipe, &connection, arguments.as_object().unwrap());
        let policy = if scoped {
            policy(native.root.clone(), "gateway")
        } else {
            EffectPolicy::new(
                "recipe-partition".into(),
                1,
                SigningKey::from_bytes(&[29; 32]).verifying_key().to_bytes(),
            )
            .unwrap()
        };
        let attempts = crate::GatewayAttempts::new(store.clone(), policy.clone()).unwrap();
        let clock = Arc::new(crate::FixedClock::at(NOW));
        let gate = Arc::new(crate::QualificationGate::new(
            crate::QualificationPolicy::Optional,
            None,
            None,
            Box::new(Arc::clone(&clock)),
            auths_recipe_qualification::VerifierState::default(),
        ));
        // There is no provider credential to acquire. Native control must work
        // without one and cannot obtain it by a successful enrollment receipt.
        let credentials =
            Arc::new(auths_connections::InMemoryCredentialStore::new(4, 65_536).unwrap());
        let engine = Arc::new(
            GatewayEngine::new(
                recipe.clone(),
                *recipe.digest(),
                &auths_codec::encode_verifier_context(&native.context).unwrap(),
                policy.clone(),
                connection.provider_kind().clone(),
                connection.alias().clone(),
                "gateway".into(),
                connection.allowed_profiles()[0].clone(),
                credentials,
                attempts,
            )
            .unwrap()
            .with_qualification(gate),
        );
        crate::SharedConnection::new(
            store.clone(),
            connection.provider_kind().clone(),
            connection.alias().clone(),
        )
        .insert(&connection)
        .await
        .unwrap();
        let initialize = Arc::clone(&engine);
        tokio::task::spawn_blocking(move || initialize.initialize_effect_configuration())
            .await
            .unwrap()
            .unwrap();
        Self {
            backend,
            store,
            engine,
            recipe,
            connection,
            native,
            policy,
            clock,
        }
    }
    fn request(&self, evidence: EngagementControlEvidence) -> AppParticipantControl {
        AppParticipantControl {
            schema: APP_PARTICIPANT_SCHEMA.into(),
            evidence_b64: Base64UrlUnpadded::encode_string(&evidence.to_private_bytes().unwrap()),
        }
    }
    async fn send(&self, evidence: EngagementControlEvidence) -> ParticipantControlOutcome {
        let bytes = serde_json::to_vec(&self.request(evidence)).unwrap();
        serde_json::from_value(exchange(Arc::clone(&self.engine), &bytes).await).unwrap()
    }
    fn snapshot(&self) -> crate::EngagementConfigurationSnapshot {
        self.engine
            .engagement_configuration(self.native.root.clone())
            .unwrap()
            .snapshot()
            .unwrap()
    }
    fn eligible(&self) -> bool {
        let snapshot = self.snapshot();
        let installed = self
            .policy
            .installation(
                &self.recipe,
                &self.native.context,
                &self.connection,
                crate::QualificationPolicy::Optional,
                self.engine.effect_configuration_candidate().unwrap(),
            )
            .with_enrollment(Some(snapshot.tree()));
        compile_mutation_effect(
            &installed,
            NOW,
            &self.native.action.proof,
            &self.native.action.action,
        )
        .is_ok()
    }
}
async fn exchange(engine: Arc<GatewayEngine>, request: &[u8]) -> Value {
    let (server, mut client) = UnixStream::pair().unwrap();
    let task = tokio::spawn(async move { app_session(server, &*engine).await });
    write_frame(&mut client, request).await.unwrap();
    let result = serde_json::from_slice(&read_frame(&mut client).await.unwrap()).unwrap();
    task.await.unwrap();
    result
}
fn recorded(revision: u64) -> ParticipantControlOutcome {
    ParticipantControlOutcome::Recorded { revision }
}
fn case(id: &str, outcome: ParticipantControlOutcome, revision: u64) -> Value {
    json!({"id":id, "response":outcome, "revision":revision})
}

#[allow(
    clippy::too_many_lines,
    reason = "one complete native control and acknowledgement-loss history constructs the corpus"
)]
async fn cases(backend: Backend) -> Value {
    let setup = Control::new(backend, true).await;
    let mut cases = Vec::new();
    let root_app = setup.send(setup.native.root_evidence()).await;
    assert_eq!(
        root_app,
        ParticipantControlOutcome::Refused {
            code: "gateway.engagement.operator-required".into()
        }
    );
    cases.push(case("app-cannot-bootstrap-root", root_app, 0));
    assert_eq!(
        setup
            .engine
            .bootstrap_engagement(setup.native.root_evidence())
            .await,
        recorded(1)
    );
    let mut authoring = setup.native.root.clone();
    for scope in &mut authoring.scopes {
        scope.connection_binding = [0; 32];
    }
    let prepared = setup
        .engine
        .prepare_engagement_root(authoring)
        .await
        .unwrap();
    assert!(
        prepared == setup.native.root,
        "root authoring derives the installed connection natively"
    );
    assert!(!setup.eligible());
    let request = serde_json::to_value(setup.request(setup.native.enrollment_evidence(0))).unwrap();
    let enrolled = setup.send(setup.native.enrollment_evidence(0)).await;
    assert_eq!(enrolled, recorded(2));
    assert!(setup.eligible());
    cases.push(case("parent-and-child-consent", enrolled.clone(), 2));
    assert_eq!(
        setup.send(setup.native.enrollment_evidence(1)).await,
        recorded(3)
    );
    let retried = setup.send(setup.native.enrollment_evidence(0)).await;
    assert_eq!(retried, recorded(2));
    assert_eq!(setup.snapshot().revision(), 3);
    cases.push(case("exact-retry-original-revision", retried, 3));

    let mut forged: Value = serde_json::from_slice(
        &setup
            .native
            .enrollment_evidence(0)
            .to_private_bytes()
            .unwrap(),
    )
    .unwrap();
    let encoded = forged["control"]["authorization"]["proof_b64"]
        .as_str()
        .unwrap();
    let mut proof = Base64::decode_vec(encoded).unwrap();
    let last = proof.len() - 1;
    proof[last] ^= 1;
    forged["control"]["authorization"]["proof_b64"] = json!(Base64::encode_string(&proof));
    let forged =
        EngagementControlEvidence::from_json(&serde_json::to_vec(&forged).unwrap()).unwrap();
    let denied = setup.send(forged).await;
    assert!(matches!(denied, ParticipantControlOutcome::Refused { .. }));
    assert_eq!(setup.snapshot().revision(), 3);
    cases.push(case("changed-original-proof-is-not-retry", denied, 3));
    for field in ["root", "context", "now", "capacity"] {
        let mut injected = request.clone();
        injected[field] = json!("ATTACKER-CONTROL-CANARY");
        let result = exchange(
            Arc::clone(&setup.engine),
            &serde_json::to_vec(&injected).unwrap(),
        )
        .await;
        assert_eq!(result["outcome"], "indeterminate");
        assert!(!result.to_string().contains("ATTACKER"));
    }
    assert_eq!(setup.snapshot().revision(), 3);
    let withdrawn = setup.send(setup.native.withdrawal_evidence(0x44)).await;
    assert_eq!(withdrawn, recorded(4));
    assert!(!setup.eligible());
    cases.push(case("native-parent-withdrawal", withdrawn, 4));
    let historical = setup.send(setup.native.enrollment_evidence(0)).await;
    assert_eq!(historical, recorded(2));
    assert!(!setup.eligible());
    assert_eq!(setup.snapshot().revision(), 4);
    cases.push(case(
        "retry-after-withdrawal-does-not-reactivate",
        historical,
        4,
    ));
    setup.clock.set(NOW + 86_400);
    assert_eq!(
        setup.send(setup.native.enrollment_evidence(0)).await,
        recorded(2)
    );
    assert_eq!(setup.snapshot().revision(), 4);
    cases.push(case(
        "expired-evidence-still-only-historical",
        recorded(2),
        4,
    ));
    let (archive, head) = setup.engine.export_engagement_audit().unwrap();
    assert_eq!(
        archive
            .verify(
                &setup.native.root,
                std::slice::from_ref(&setup.native.context),
                &head
            )
            .unwrap()
            .revision(),
        4
    );
    assert!(setup.store.attempt_keys(100).unwrap().is_empty());
    let reopened = setup.backend.reopen();
    let control = crate::EngagementConfiguration::new(
        reopened.store(),
        setup.native.root.clone(),
        setup.native.context.clone(),
        setup.engine.shared_configuration().unwrap(),
        Arc::new(crate::QualificationGate::unconfigured()),
    )
    .unwrap();
    assert_eq!(
        control
            .recorded_control(&setup.native.enrollment_evidence(0))
            .unwrap(),
        Some(2)
    );

    let lost = Control::new(backend, true).await;
    assert_eq!(
        lost.engine
            .bootstrap_engagement(lost.native.root_evidence())
            .await,
        recorded(1)
    );
    lost.store.lose_next_grant_reply();
    let unknown = lost.send(lost.native.enrollment_evidence(0)).await;
    assert!(matches!(
        unknown,
        ParticipantControlOutcome::Indeterminate { .. }
    ));
    assert_eq!(lost.snapshot().revision(), 2);
    cases.push(case("commit-ack-lost", unknown, 2));
    let recovered = lost.send(lost.native.enrollment_evidence(0)).await;
    assert_eq!(recovered, recorded(2));
    assert_eq!(lost.snapshot().revision(), 2);
    cases.push(case("exact-evidence-resolves-lost-ack", recovered, 2));
    let (first, second) = tokio::join!(
        lost.send(lost.native.enrollment_evidence(1)),
        lost.send(lost.native.enrollment_evidence(1))
    );
    assert!(first == recorded(3) || second == recorded(3));
    assert_eq!(lost.snapshot().revision(), 3);
    assert_eq!(
        lost.send(lost.native.enrollment_evidence(1)).await,
        recorded(3)
    );
    cases.push(case(
        "competing-identical-controls-one-transition",
        recorded(3),
        3,
    ));
    let disconnected = Control::new(backend, true).await;
    assert_eq!(
        disconnected
            .engine
            .bootstrap_engagement(disconnected.native.root_evidence())
            .await,
        recorded(1)
    );
    let disconnected_request =
        serde_json::to_vec(&disconnected.request(disconnected.native.enrollment_evidence(0)))
            .unwrap();
    let (server, mut client) = UnixStream::pair().unwrap();
    let engine = Arc::clone(&disconnected.engine);
    let serving = tokio::spawn(async move { app_session(server, &*engine).await });
    write_frame(&mut client, &disconnected_request)
        .await
        .unwrap();
    drop(client);
    serving.await.unwrap();
    assert_eq!(disconnected.snapshot().revision(), 2);
    let original = disconnected
        .send(disconnected.native.enrollment_evidence(0))
        .await;
    assert_eq!(original, recorded(2));
    assert_eq!(disconnected.snapshot().revision(), 2);
    cases.push(case(
        "app-disconnect-retains-control-and-original-receipt",
        original,
        2,
    ));
    let unscoped = Control::new(backend, false).await;
    let denied = unscoped.send(unscoped.native.enrollment_evidence(0)).await;
    assert_eq!(
        denied,
        ParticipantControlOutcome::Refused {
            code: "gateway.engagement.installation".into()
        }
    );
    cases.push(case("app-cannot-install-scoped-policy", denied, 0));
    json!({"enrollment_request":request, "enrollment_response":enrolled, "cases":cases,
        "archive_revision":setup.snapshot().revision(), "forbidden_request_fields":["root","context","now","capacity"],
        "provider_attempt_rows":0})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_engagement_control_fixture_is_current() {
    control_transport_cap_fits_shared_frame_without_expanding_it();
    let actual = cases(Backend::File).await;
    let document = json!({"schema":"auths.engagement-control-vectors/1",
        "generated_by":"native_engagement_control_fixture_is_current",
        "max_control_bytes":crate::MAX_ENGAGEMENT_CONTROL_BYTES,
        "claims":["actual-engine-and-unix-app-session", "installed-root-only", "native-control-fence",
            "lost-ack-original-receipt", "withdrawal-survives-evidence-retry", "private-audit-export-native-replay"],
        "not_established":["installed-binary-processes", "distinct-uid-containment", "private-agent-key-custody",
            "machine-agent-agent-hierarchy", "provider-https", "postgres-execution"], "file":actual});
    let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
    bytes.push(b'\n');
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/control.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_native_engine_controls_retain_original_revision_after_withdrawal_and_lost_ack() {
    if postgres_configured() {
        cases(Backend::Postgres).await;
    }
}

#[test]
fn control_transport_cap_fits_shared_frame_without_expanding_it() {
    let request = AppParticipantControl {
        schema: APP_PARTICIPANT_SCHEMA.into(),
        evidence_b64: Base64UrlUnpadded::encode_string(&vec![
            0;
            crate::MAX_ENGAGEMENT_CONTROL_BYTES
        ]),
    };
    assert!(serde_json::to_vec(&request).unwrap().len() <= crate::app::MAX_FRAME_BYTES);
    assert!(request.decode().is_err());
    let invalid = AppParticipantControl {
        schema: APP_PARTICIPANT_SCHEMA.into(),
        evidence_b64: "AA==".into(),
    };
    assert!(invalid.decode().is_err());
}
