//! Production candidate CLI over private synthetic installation files and real
//! local custody. No approved provider acquisition or publication is claimed.
#![cfg(unix)]

use auths_connections::{
    ConnectionAlias, ConnectionCredentialStore, ConnectionId, ConnectionProfile, ConnectionRecord,
    ConnectionState, PersistentCredentialStore, ProviderKind, SecretBytes, SemanticId,
};
use auths_gateway::{
    CompiledRecipe, FileGatewayAttemptStore, GatewayAttempts, GatewayEngine, QualificationGate,
    SharedConnection,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    io::Write as _,
    num::NonZeroU64,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
};

fn private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("private write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("private mode");
}

fn spawn_stage(root: &Path, out: &Path) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_auths-gateway"))
        .arg("candidate-stage-rotation")
        .arg("--state-dir")
        .arg(root)
        .arg("--credential-stdin")
        .arg("--proposal-out")
        .arg(out)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("stage CLI")
}

fn stage(root: &Path, out: &Path, secret: &[u8]) -> std::process::Output {
    let mut child = spawn_stage(root, out);
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(secret)
        .expect("secret input");
    child.wait_with_output().expect("stage output")
}

#[tokio::test]
async fn native_candidate_cli_fixture_is_current() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bindings/fixtures/gateway");
    let recipes: Value = serde_json::from_slice(
        &std::fs::read(fixtures.join("hostile-recipes-v2.json")).expect("recipes"),
    )
    .expect("JSON");
    let source = serde_json::to_vec(&recipes["bases"]["stripe"]["recipe"]).expect("recipe");
    let lock = serde_json::to_vec(&recipes["bases"]["stripe"]["lock"]).expect("lock");
    let recipe = CompiledRecipe::compile(&source, &lock).expect("compile");
    let input: Value = serde_json::from_slice(
        &std::fs::read(fixtures.join("approval-quorum.json")).expect("trust fixture"),
    )
    .expect("JSON");
    let trust =
        Base64UrlUnpadded::decode_vec(input["trusted_context_b64"].as_str().expect("context"))
            .expect("decode");
    let public = ed25519_dalek::SigningKey::from_bytes(&[29; 32])
        .verifying_key()
        .to_bytes();
    let policy =
        auths_gateway::effect::EffectPolicy::new("candidate-cli-test".to_owned(), 1, public)
            .expect("policy");
    let fixture = rotation_installation(&source, &lock, &trust, &policy, &recipe).await;
    let RotationInstallation {
        root,
        shared,
        record,
        id,
        ..
    } = &fixture;
    let proposal = competing_staging_processes(root);
    let proposal_bytes = std::fs::read(&proposal).expect("proposal");
    assert_eq!(
        std::fs::metadata(&proposal)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let target = auths_gateway::effect::CandidateCredentialTarget::from_private_bytes(
        &recipe,
        &proposal_bytes,
    )
    .expect("target");
    assert_eq!(
        shared
            .load()
            .await
            .expect("load")
            .expect("current")
            .record(),
        record
    );
    let repeat = stage(root, &proposal, b"rk_test_other\n");
    assert!(!repeat.status.success());
    assert_eq!(
        std::fs::read(&proposal).expect("same proposal"),
        proposal_bytes
    );
    let conflict = stage(root, &root.join("conflict.json"), b"rk_test_other\n");
    assert!(!conflict.status.success());
    assert!(!root.join("conflict.json").exists());
    let reopened = PersistentCredentialStore::open(root.join("credentials.cbor")).expect("reopen");
    assert_eq!(
        reopened.stored_generations(id).expect("generations"),
        vec![NonZeroU64::MIN, NonZeroU64::new(2).expect("two")]
    );
    let proposed: Value = serde_json::from_slice(&proposal_bytes).expect("proposal JSON");
    let staged = ConnectionRecord::from_canonical_cbor(
        &hex::decode(proposed["candidate"].as_str().expect("hex")).expect("bytes"),
    )
    .expect("candidate record");
    assert!(reopened.holds(&staged.credential_binding()).await.is_ok());
    let custody_lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("credentials.cbor.lock"))
        .expect("custody lock");
    custody_lock.try_lock().expect("hold custody fence");
    let blocked = stage(root, &root.join("blocked.json"), b"rk_test_blocked\n");
    assert!(!blocked.status.success());
    assert!(!root.join("blocked.json").exists());
    drop(custody_lock);
    assert_call_authoring(root, &proposal, &target, &recipe);
    let first_installation = first_installation(&source, &lock, &trust, &policy, &recipe).await;
    let fixture = serde_json::to_vec_pretty(&json!({
        "first_installation": first_installation,
        "schema": "auths.candidate-cli-fixture/1", "scope": "production staging and call-authoring CLI with real file custody, cleanup journal and generation floor; synthetic installation/trust; no approved provider acquisition or publication claim",
        "competing_processes_one_staging_winner": true, "held_custody_fence_refuses_without_proposal": true,
        "staged_generation": 2, "current_record_unchanged": true, "proposal_and_call_mode": "0600",
        "existing_proposal_refused_without_overwrite": true, "different_secret_same_generation_refused": true,
        "reopened_custody_holds_exact_candidate": true, "authored_call_matches_native": true,
        "permissive_proposal_refused": true
    })).expect("fixture");
    let path = fixtures.join("candidate-cli.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &fixture).expect("fixture write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), fixture);
}

async fn first_installation(
    source: &[u8],
    lock: &[u8],
    trust: &[u8],
    policy: &auths_gateway::effect::EffectPolicy,
    recipe: &CompiledRecipe,
) -> Value {
    let directory = tempfile::tempdir().expect("installation directory");
    let root = std::fs::canonicalize(directory.path()).expect("path");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("mode");
    for (name, bytes) in [
        ("source.json", source),
        ("lock.json", lock),
        ("trust.cbor", trust),
        (
            "policy.json",
            policy.to_private_bytes().expect("policy").as_slice(),
        ),
    ] {
        private(&root.join(name), bytes);
    }
    let state = root.join("state");
    install_candidate_cli(&root, &state, recipe);
    let proposal = state.join("candidate-installation.json");
    let bytes = std::fs::read(&proposal).expect("proposal");
    let json: Value = serde_json::from_slice(&bytes).expect("proposal JSON");
    assert!(json["previous"].is_null());
    let candidate = ConnectionRecord::from_canonical_cbor(
        &hex::decode(json["candidate"].as_str().expect("candidate hex")).expect("hex"),
    )
    .expect("record");
    let shared = SharedConnection::new(
        Arc::new(FileGatewayAttemptStore::open(state.join("attempts")).expect("store")),
        candidate.provider_kind().clone(),
        candidate.alias().clone(),
    );
    assert!(shared.load().await.expect("load").is_none());
    let custody = PersistentCredentialStore::open(state.join("credentials.cbor")).expect("custody");
    assert!(custody.holds(&candidate.credential_binding()).await.is_ok());
    auths_gateway::GenerationFloor::new(state.clone())
        .accept(&candidate)
        .expect("floor");
    assert_eq!(
        auths_gateway::CredentialJournal::new(state.clone())
            .generations(candidate.connection_id())
            .expect("notes"),
        vec![NonZeroU64::MIN]
    );
    let resume = |out: &Path, secret: &[u8]| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_auths-gateway"))
            .arg("candidate-stage-installation")
            .arg("--state-dir")
            .arg(&state)
            .arg("--proposal-out")
            .arg(out)
            .arg("--credential-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("resume process");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(secret)
            .expect("secret");
        child.wait_with_output().expect("resume output")
    };
    let repeated = state.join("resumed.json");
    let result = resume(&repeated, b"rk_test_initial_install\n");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read(&repeated).expect("resumed bytes"), bytes);
    let conflict = resume(&state.join("conflict.json"), b"rk_test_different\n");
    assert!(!conflict.status.success());
    assert!(!state.join("conflict.json").exists());
    assert!(
        !resume(&proposal, b"rk_test_initial_install\n")
            .status
            .success()
    );
    assert_eq!(std::fs::read(&proposal).expect("preserved"), bytes);
    for path in [
        &proposal,
        &repeated,
        &state.join("candidate-installation.cbor"),
    ] {
        assert_eq!(
            std::fs::metadata(path).expect("mode").permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(shared.load().await.expect("load").is_none());
    json!({"production_install_stages_without_publication":true,"private_draft_and_proposal":true,"exact_floor_and_cleanup_note":true,"independent_resume_process_reuses_exact_proposal":true,"different_secret_refused":true,"existing_output_preserved":true,"no_approved_provider_execution_claim":true})
}

struct RotationInstallation {
    _directory: tempfile::TempDir,
    root: std::path::PathBuf,
    shared: SharedConnection,
    record: ConnectionRecord,
    id: ConnectionId,
}

async fn rotation_installation(
    source: &[u8],
    lock: &[u8],
    trust: &[u8],
    policy: &auths_gateway::effect::EffectPolicy,
    recipe: &CompiledRecipe,
) -> RotationInstallation {
    let directory = tempfile::tempdir().expect("directory");
    let root = std::fs::canonicalize(directory.path()).expect("path");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let store = Arc::new(FileGatewayAttemptStore::open(root.join("attempts")).expect("store"));
    let attempts = GatewayAttempts::new(store.clone(), policy.clone()).expect("attempts");
    let provider = ProviderKind::parse("stripe").expect("provider");
    let alias = ConnectionAlias::parse("synthetic").expect("alias");
    let id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").expect("id");
    let profile = ConnectionProfile::new(SemanticId::parse("auths.mcp").expect("profile"), 2)
        .expect("profile");
    let credentials =
        Arc::new(PersistentCredentialStore::open(root.join("credentials.cbor")).expect("custody"));
    let reference = credentials
        .install(
            &id,
            NonZeroU64::MIN,
            SecretBytes::new(b"rk_test_initial".to_vec()).expect("secret"),
        )
        .await
        .expect("initial custody");
    let record = ConnectionRecord::new(
        provider.clone(),
        alias.clone(),
        id.clone(),
        SemanticId::parse("auths.gateway-operation/1").expect("contract"),
        SemanticId::parse("auths.gateway-connection-descriptor/1").expect("schema"),
        auths_gateway::GatewayConnectionDescriptor::approve(recipe, "Authorization")
            .expect("descriptor")
            .to_bytes()
            .expect("bytes"),
        [4; 32],
        *reference.as_bytes(),
        NonZeroU64::MIN,
        ConnectionState::Active,
        vec!["gateway".to_owned()],
        vec![profile.clone()],
        1_790_000_000,
        1_790_000_000,
        None,
    )
    .expect("record");
    let shared = SharedConnection::new(store, provider.clone(), alias.clone());
    shared.insert(&record).await.expect("initial record");
    auths_gateway::GenerationFloor::new(root.clone())
        .initialize(&record)
        .expect("floor");
    let journal = auths_gateway::CredentialJournal::new(root.clone());
    journal.initialize(&id).expect("journal");
    journal.register(&id, NonZeroU64::MIN).expect("note");
    initialize_configuration(recipe, trust, policy, &record, credentials, attempts);
    for (name, bytes) in [
        ("recipe.json", &source),
        ("profile.lock.json", &lock),
        ("trusted.context.cbor", &trust),
    ] {
        private(&root.join(name), bytes);
    }
    private(&root.join("installation.json"), &serde_json_canonicalizer::to_vec(&json!({
        "schema": "auths.gateway-installation/6", "recipe_digest": recipe.digest_hex(),
        "profile_lock_sha256": hex::encode(Sha256::digest(lock)), "trusted_context_sha256": hex::encode(Sha256::digest(trust)),
        "effect_policy": policy, "provider": "stripe", "alias": "synthetic", "deployment": "development",
        "operator_attestation_sha256": null, "attempt_store": root.join("attempts"),
        "credential_store": {"kind": "local-file-v1"}, "qualification": {"policy": "optional"}
    })).expect("manifest"));
    RotationInstallation {
        _directory: directory,
        root,
        shared,
        record,
        id,
    }
}

fn initialize_configuration(
    recipe: &CompiledRecipe,
    trust: &[u8],
    policy: &auths_gateway::effect::EffectPolicy,
    record: &ConnectionRecord,
    credentials: Arc<PersistentCredentialStore>,
    attempts: GatewayAttempts,
) {
    let engine = GatewayEngine::new(
        recipe.clone(),
        *recipe.digest(),
        trust,
        policy.clone(),
        record.provider_kind().clone(),
        record.alias().clone(),
        "gateway".to_owned(),
        record.allowed_profiles()[0].clone(),
        credentials,
        attempts,
    )
    .expect("engine")
    .with_qualification(Arc::new(QualificationGate::new(
        auths_gateway::QualificationPolicy::Optional,
        auths_gateway::PINNED_QUALIFICATION_ROOT.map(|bytes| {
            auths_recipe_qualification::QualificationTrustRoot::from_canonical_json(bytes)
                .expect("pinned root")
        }),
        None,
        Box::new(auths_gateway::DevelopmentClock),
        auths_recipe_qualification::VerifierState::default(),
    )));
    engine
        .qualification()
        .load(&auths_gateway::QualificationBundle {
            signer_certificate: Vec::new(),
            revocation_list: Vec::new(),
            release_index: Vec::new(),
            records: Vec::new(),
            attestations: Vec::new(),
        });
    engine
        .initialize_effect_configuration()
        .expect("configuration");
}

fn competing_staging_processes(root: &Path) -> std::path::PathBuf {
    let first_path = root.join("candidate-a.json");
    let second_path = root.join("candidate-b.json");
    let mut first = spawn_stage(root, &first_path);
    let mut second = spawn_stage(root, &second_path);
    first
        .stdin
        .take()
        .expect("first stdin")
        .write_all(b"rk_test_first\n")
        .expect("first secret");
    second
        .stdin
        .take()
        .expect("second stdin")
        .write_all(b"rk_test_second\n")
        .expect("second secret");
    let first = first.wait_with_output().expect("first process");
    let second = second.wait_with_output().expect("second process");
    assert_ne!(
        first.status.success(),
        second.status.success(),
        "one successful staging process: first={}, second={}",
        String::from_utf8_lossy(&first.stderr),
        String::from_utf8_lossy(&second.stderr)
    );
    if first.status.success() {
        first_path
    } else {
        second_path
    }
}

fn assert_call_authoring(
    root: &Path,
    proposal: &Path,
    target: &auths_gateway::effect::CandidateCredentialTarget,
    recipe: &CompiledRecipe,
) {
    let call_out = root.join("call.json");
    let call = Command::new(env!("CARGO_BIN_EXE_auths-gateway"))
        .arg("effect-candidate-call")
        .arg("--state-dir")
        .arg(root)
        .arg("--candidate")
        .arg(proposal)
        .arg("--operation")
        .arg("candidate-cli-1")
        .arg("--call-out")
        .arg(&call_out)
        .output()
        .expect("call CLI");
    assert!(
        call.status.success(),
        "{}",
        String::from_utf8_lossy(&call.stderr)
    );
    let expected = target
        .authorization_call(
            recipe,
            &auths_gateway::LogicalOperationId::parse("candidate-cli-1").expect("operation"),
        )
        .expect("call");
    assert_eq!(
        std::fs::read(&call_out).expect("call bytes"),
        serde_json_canonicalizer::to_vec(&expected).expect("native call")
    );
    assert_eq!(
        std::fs::metadata(&call_out)
            .expect("call mode")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mut wide = std::fs::metadata(proposal)
        .expect("proposal mode")
        .permissions();
    wide.set_mode(0o644);
    std::fs::set_permissions(proposal, wide).expect("wide mode");
    let refused = Command::new(env!("CARGO_BIN_EXE_auths-gateway"))
        .arg("effect-candidate-call")
        .arg("--state-dir")
        .arg(root)
        .arg("--candidate")
        .arg(proposal)
        .arg("--operation")
        .arg("candidate-cli-2")
        .arg("--call-out")
        .arg(root.join("refused.json"))
        .output()
        .expect("refusal CLI");
    assert!(!refused.status.success());
    assert!(!root.join("refused.json").exists());
}

fn install_candidate_cli(root: &Path, state: &Path, recipe: &CompiledRecipe) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_auths-gateway"))
        .arg("install")
        .arg("--state-dir")
        .arg(state)
        .arg("--recipe")
        .arg(root.join("source.json"))
        .arg("--profile-lock")
        .arg(root.join("lock.json"))
        .arg("--trusted-context")
        .arg(root.join("trust.cbor"))
        .arg("--effect-policy")
        .arg(root.join("policy.json"))
        .arg("--approve-digest")
        .arg(recipe.digest_hex())
        .args([
            "--provider",
            "stripe",
            "--alias",
            "synthetic",
            "--account-label",
            "acct_TESTACCOUNT01",
            "--credential-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("install process");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"rk_test_initial_install\n")
        .expect("secret");
    let output = child.wait_with_output().expect("install output");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
