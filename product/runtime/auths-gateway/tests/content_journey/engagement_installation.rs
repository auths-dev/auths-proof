//! Native operator policy cutover over actual installed connection metadata.
//! Candidate policy is data, not resource authority or a provider entry permit.
use super::*;
use auths_gateway::participant_enrollment::ParentEnrollmentPins;
use auths_gateway::{FileGatewayAttemptStore, GatewayAttempts, GatewayEngine};
use std::os::unix::fs::MetadataExt as _;

fn review(state: &Path, policy: Option<&Path>) -> Value {
    let mut args = vec![("--state-dir", path(state))];
    if let Some(policy) = policy {
        args.push(("--effect-policy", path(policy)));
    }
    serde_json::from_slice(&success(cli(
        "effect-configuration-review",
        &args,
        &[],
        None,
    )))
    .expect("review")
}
fn activation(state: &Path, policy: &Path, review: &Value) -> Output {
    cli(
        "effect-configuration-activate",
        &[
            ("--state-dir", path(state)),
            ("--effect-policy", path(policy)),
            (
                "--expected-revision",
                review["previous_revision_hex"].as_str().expect("revision"),
            ),
            (
                "--expected-candidate",
                review["candidate_hex"].as_str().expect("candidate"),
            ),
        ],
        &[],
        None,
    )
}
fn policy_file(directory: &Path, filename: &str, policy: &EffectPolicy) -> PathBuf {
    let path = directory.join(filename);
    private(&path, &policy.to_private_bytes().expect("policy"));
    path
}

fn installed_connection_binding(state: &Path) -> [u8; 32] {
    let store =
        Arc::new(FileGatewayAttemptStore::open(state.join("attempts")).expect("actual store"));
    let shared = auths_gateway::SharedConnection::new(
        store,
        auths_connections::ProviderKind::parse("airtable").expect("provider"),
        auths_connections::ConnectionAlias::parse("capacity").expect("alias"),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let actual = runtime
        .block_on(shared.load())
        .expect("native connection load")
        .expect("installed connection");
    *auths_codec::domain_commitment(
        "auths.effect-installation/1",
        &actual
            .record()
            .to_canonical_cbor()
            .expect("native connection bytes"),
    )
    .expect("native commitment")
    .as_bytes()
}

/// Construct the same candidate through the public native engine API, then
/// stop after its durable configuration acknowledgement. This is the exact
/// crash boundary before local manifest publication, not a fabricated journal.
fn candidate_engine(state: &Path, policy: EffectPolicy) -> GatewayEngine {
    // A development install without a private qualification root still uses
    // the build's pinned root. Omitting it changes the native contract digest.
    let qualification_root = auths_gateway::PINNED_QUALIFICATION_ROOT
        .map(auths_recipe_qualification::QualificationTrustRoot::from_canonical_json)
        .transpose()
        .expect("same build-pinned qualification root as CLI");
    let recipe = CompiledRecipe::compile(
        &std::fs::read(state.join("recipe.json")).expect("recipe"),
        &std::fs::read(state.join("profile.lock.json")).expect("lock"),
    )
    .expect("recipe");
    let attempts = GatewayAttempts::new(
        Arc::new(FileGatewayAttemptStore::open(state.join("attempts")).expect("store")),
        policy.clone(),
    )
    .expect("attempts");
    GatewayEngine::new(
        recipe.clone(),
        *recipe.digest(),
        &std::fs::read(state.join("trusted.context.cbor")).expect("trust"),
        policy,
        auths_connections::ProviderKind::parse("airtable").expect("provider"),
        auths_connections::ConnectionAlias::parse("capacity").expect("alias"),
        "gateway".into(),
        auths_connections::ConnectionProfile::new(
            auths_connections::SemanticId::parse("auths.mcp").expect("profile"),
            2,
        )
        .expect("profile"),
        Arc::new(auths_connections::InMemoryCredentialStore::new(1, 1).expect("empty credentials")),
        attempts,
    )
    .expect("native engine")
    .with_qualification(Arc::new(auths_gateway::QualificationGate::new(
        auths_gateway::QualificationPolicy::Optional,
        qualification_root,
        None,
        Box::new(auths_gateway::DevelopmentClock),
        auths_recipe_qualification::VerifierState::default(),
    )))
}
fn acknowledge_without_manifest(state: &Path, policy: EffectPolicy, expected: &Value) {
    let engine = candidate_engine(state, policy);
    assert_eq!(
        hex::encode(engine.effect_configuration_candidate().expect("candidate")),
        expected["candidate_hex"]
    );
    let mut revision = [0; 32];
    hex::decode_to_slice(
        expected["previous_revision_hex"]
            .as_str()
            .expect("revision"),
        &mut revision,
    )
    .expect("revision hex");
    engine
        .activate_effect_configuration(revision)
        .expect("durable native acknowledgement");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one installed operator cutover, concurrent publication and crash-recovery artifact"
)]
fn native_engagement_installation_fixture_is_current() {
    let installation = ReadOnlyInstallation::create();
    let state = &installation.state;
    let root = &installation.root;
    let manifest_path = state.join("installation.json");
    let original_bytes = std::fs::read(&manifest_path).expect("manifest");
    let original_lock =
        std::fs::metadata(state.join("installation.lock")).expect("installation lock");
    let baseline = review(state, None);
    let original =
        EffectPolicy::from_private_bytes(&std::fs::read(root.join("policy")).expect("policy"))
            .expect("native policy");
    let source: Value = serde_json::from_slice(include_bytes!(
        "../../../../../bindings/fixtures/gateway/engagement/effect.json"
    ))
    .expect("scope corpus");
    let mut pins: ParentEnrollmentPins =
        serde_json::from_value(source["root"].clone()).expect("root pins");
    let recipe = CompiledRecipe::compile(
        &std::fs::read(root.join("recipe")).expect("recipe"),
        &std::fs::read(root.join("lock")).expect("lock"),
    )
    .expect("recipe");
    for scope in &mut pins.scopes {
        scope.recipe_digest = recipe.digest_hex();
        scope.service = recipe.review().service().into();
        scope.connection_binding = [0; 32];
    }
    let pins_path = root.join("root-authoring.json");
    private(&pins_path, &serde_json::to_vec(&pins).expect("pins"));
    let prepared = success(cli(
        "engagement-root",
        &[("--state-dir", path(state)), ("--pins", path(&pins_path))],
        &[],
        None,
    ));
    let pins: ParentEnrollmentPins =
        serde_json::from_slice(&prepared).expect("native prepared pins");
    let expected_connection = installed_connection_binding(state);
    assert!(
        pins.scopes
            .iter()
            .all(|scope| scope.connection_binding == expected_connection)
    );
    private(&pins_path, &prepared);
    let scoped_bytes = success(cli(
        "effect-policy",
        &[
            ("--partition", "process-capacity"),
            ("--epoch", "1"),
            (
                "--approver-public-key",
                &hex::encode(installation.reviewer.verifying_key().to_bytes()),
            ),
            ("--engagement-root", path(&pins_path)),
        ],
        &[],
        None,
    ));
    let scoped = EffectPolicy::from_private_bytes(&scoped_bytes).expect("scoped policy");
    let candidate_file = root.join("candidate.policy");
    private(&candidate_file, &scoped_bytes);
    let candidate = review(state, Some(&candidate_file));
    assert_eq!(
        candidate["previous_revision_hex"],
        baseline["previous_revision_hex"]
    );
    assert_ne!(candidate["candidate_hex"], baseline["candidate_hex"]);
    assert_eq!(
        std::fs::read(&manifest_path).expect("read-only review"),
        original_bytes
    );
    let reviewed_lock =
        std::fs::metadata(state.join("installation.lock")).expect("retained installation lock");
    assert_eq!(reviewed_lock.ino(), original_lock.ino());
    assert_eq!(
        reviewed_lock.modified().expect("time"),
        original_lock.modified().expect("time")
    );

    let mut wrong_digest = candidate.clone();
    wrong_digest["candidate_hex"] = baseline["candidate_hex"].clone();
    assert!(
        !activation(state, &candidate_file, &wrong_digest)
            .status
            .success()
    );
    assert_eq!(
        std::fs::read(&manifest_path).expect("no unreviewed install"),
        original_bytes
    );
    let changed = EffectPolicy::new(
        "process-capacity".into(),
        1,
        SigningKey::from_bytes(&[28; 32]).verifying_key().to_bytes(),
    )
    .expect("changed policy");
    private(
        &candidate_file,
        &changed
            .to_private_bytes()
            .expect("changed canonical policy"),
    );
    assert!(
        !activation(state, &candidate_file, &candidate)
            .status
            .success(),
        "changed input invalidates review"
    );
    assert_eq!(
        std::fs::read(&manifest_path).expect("no changed install"),
        original_bytes
    );
    private(&candidate_file, &scoped_bytes);
    success(activation(state, &candidate_file, &candidate));
    let activated = review(state, None);
    assert_eq!(activated["candidate_hex"], candidate["candidate_hex"]);
    assert_ne!(
        activated["previous_revision_hex"],
        baseline["previous_revision_hex"]
    );
    assert_eq!(
        activated["installation"]["effect_policy"],
        candidate["installation"]["effect_policy"]
    );
    let active_bytes = std::fs::read(&manifest_path).expect("published manifest");
    assert_eq!(
        std::fs::metadata(&manifest_path)
            .expect("private manifest")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(
        !activation(state, &candidate_file, &candidate)
            .status
            .success(),
        "stale review cannot activate twice"
    );
    assert_eq!(
        std::fs::read(&manifest_path).expect("stale leaves settings"),
        active_bytes
    );

    let foreign = EffectPolicy::new(
        "fresh-partition".into(),
        1,
        installation.reviewer.verifying_key().to_bytes(),
    )
    .expect("foreign policy");
    let foreign_file = policy_file(root, "foreign.policy", &foreign);
    assert!(
        !cli(
            "effect-configuration-review",
            &[
                ("--state-dir", path(state)),
                ("--effect-policy", path(&foreign_file))
            ],
            &[],
            None
        )
        .status
        .success()
    );
    assert_eq!(
        review(state, None)["previous_revision_hex"],
        activated["previous_revision_hex"]
    );

    // Stop after the real native CAS, with the old local manifest retained.
    let recovery_file = policy_file(root, "recovery.policy", &changed);
    let before_crash = review(state, Some(&recovery_file));
    acknowledge_without_manifest(state, changed.clone(), &before_crash);
    assert!(
        candidate_engine(state, scoped.clone())
            .initialize_effect_configuration()
            .is_err(),
        "old local configuration cannot reinitialize an acknowledged newer candidate"
    );
    assert_eq!(
        std::fs::read(&manifest_path).expect("crash retained old settings"),
        active_bytes
    );
    assert!(
        !activation(state, &recovery_file, &before_crash)
            .status
            .success(),
        "stale retry cannot rewind the configuration"
    );
    let recovery = review(state, Some(&recovery_file));
    assert_ne!(
        recovery["previous_revision_hex"],
        before_crash["previous_revision_hex"]
    );
    assert_eq!(recovery["candidate_hex"], before_crash["candidate_hex"]);
    success(activation(state, &recovery_file, &recovery));
    assert_eq!(
        review(state, None)["candidate_hex"],
        recovery["candidate_hex"]
    );

    // Two real CLI processes serialize local publication and race the same
    // native revision. Only its winner may publish a manifest.
    let first_file = policy_file(root, "first.policy", &original);
    let second_file = policy_file(root, "second.policy", &scoped);
    let first = review(state, Some(&first_file));
    let second = review(state, Some(&second_file));
    assert_eq!(
        first["previous_revision_hex"],
        second["previous_revision_hex"]
    );
    let spawn = |file: &Path, review: &Value| {
        let mut child = command(
            "effect-configuration-activate",
            &[
                ("--state-dir", path(state)),
                ("--effect-policy", path(file)),
                (
                    "--expected-revision",
                    review["previous_revision_hex"].as_str().expect("revision"),
                ),
                (
                    "--expected-candidate",
                    review["candidate_hex"].as_str().expect("candidate"),
                ),
            ],
            &[],
        )
        .spawn()
        .expect("operator process");
        drop(child.stdin.take());
        child
    };
    let first_process = spawn(&first_file, &first);
    let second_process = spawn(&second_file, &second);
    let finish = |mut process: Child| {
        let deadline = Instant::now() + Duration::from_secs(30);
        while process.try_wait().expect("operator status").is_none() {
            if Instant::now() >= deadline {
                let _ = process.kill();
                let _ = process.wait();
                panic!("operator publication timeout");
            }
            thread::sleep(Duration::from_millis(10));
        }
        process
            .wait_with_output()
            .expect("operator output")
            .status
            .success()
    };
    let first_won = finish(first_process);
    let second_won = finish(second_process);
    assert_eq!(usize::from(first_won) + usize::from(second_won), 1);
    let winner = if first_won { &first } else { &second };
    assert_eq!(
        std::fs::metadata(&manifest_path)
            .expect("private winning manifest")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        review(state, None)["candidate_hex"],
        winner["candidate_hex"]
    );
    let artifact=serde_json::to_vec_pretty(&json!({"schema":"auths.engagement-installation-vectors/1",
        "generated_by":"native_engagement_installation_fixture_is_current",
        "scope":"actual CLI installation, native connection/root authoring, candidate review, shared CAS, local manifest publication and interrupted-publication recovery; no enrollment/provider/language/UID claim",
        "read_only_review":true,"actual_connection_pins":true,"changed_candidate_refused":true,
        "stale_revision_refused":true,"partition_reset_refused":true,"concurrent_winners":1,
        "ack_before_manifest_requires_fresh_review":true,"provider_observation":"not-exercised",
        "not_established":["native-root-activation","installed-multi-agent-journey","process-kill-during-activation","power-loss","production-custody","postgres-execution"]})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/installation.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("artifact");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
