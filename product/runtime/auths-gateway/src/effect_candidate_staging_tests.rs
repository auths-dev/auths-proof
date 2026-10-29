//! Actual durable custody and engine staging; no provider execution claim.
use super::*;
use auths_connections::{ConnectionCredentialStore, PersistentCredentialStore, SecretBytes};
use std::{num::NonZeroU64, sync::Arc};

pub(super) async fn histories(
    recipe: &CompiledRecipe,
    trust: &auths_model::TrustedContext,
    policy: &EffectPolicy,
) -> Value {
    let mut cases = Vec::new();
    for case in [
        "active",
        "disabled",
        "revoked",
        "missing-journal",
        "bad-prefix",
    ] {
        let fixture = rotation_fixture(recipe, trust, policy, case).await;
        let RotationFixture {
            credentials_path,
            credentials,
            record,
            shared,
            engine,
            ..
        } = &fixture;
        let stale =
            PersistentCredentialStore::open(credentials_path).expect("second pre-staging handle");
        let before = engine.execution_witness();
        assert_eq!(
            engine
                .rotate_connection(zeroize::Zeroizing::new(b"rk_test_direct".to_vec()))
                .await
                .unwrap_err(),
            "gateway.admin.candidate-approval-required"
        );
        assert_eq!(
            engine
                .prepare_rotation(zeroize::Zeroizing::new(b"rk_test_direct".to_vec()))
                .await
                .unwrap_err(),
            "gateway.admin.candidate-approval-required"
        );
        assert_eq!(
            engine.commit_rotation([7; 32]).await.unwrap_err(),
            "gateway.admin.candidate-approval-required"
        );

        let secret = if case == "bad-prefix" {
            b"sk_live_invalid".as_slice()
        } else {
            b"rk_test_stage".as_slice()
        };
        let result = engine
            .stage_candidate_rotation(zeroize::Zeroizing::new(secret.to_vec()))
            .await;
        if matches!(case, "active" | "disabled") {
            let target = result.expect("staged");
            cases.push(assert_staged_rotation(&fixture, &stale, &target, secret, case).await);
        } else {
            assert!(result.is_err(), "{case}");
            assert_eq!(
                credentials
                    .stored_generations(record.connection_id())
                    .expect("generations"),
                vec![record.credential_generation()]
            );
            cases.push(json!({"case": case, "refused_without_custody_change": true}));
        }
        assert_eq!(
            shared
                .load()
                .await
                .expect("load")
                .expect("current")
                .record(),
            record
        );
        assert_eq!(
            engine.execution_witness(),
            before,
            "no lease or provider entry"
        );
    }
    let installation = installation_histories(recipe, trust, policy).await;
    json!({"installation": installation, "schema": "auths.candidate-staging-fixture/1", "scope": "actual engine, persistent file custody, generation floor and cleanup journal; fixed deployment clock; no provider execution, process crash or PostgreSQL claim", "cases": cases})
}

async fn installation_histories(
    recipe: &CompiledRecipe,
    trust: &auths_model::TrustedContext,
    policy: &EffectPolicy,
) -> Value {
    let mut cases = Vec::new();
    for case in [
        "staged",
        "bad-prefix",
        "existing-connection",
        "substituted-floor",
        "corrupt-journal",
    ] {
        let (_directory, root) = private_case_directory();
        let credentials = Arc::new(
            PersistentCredentialStore::open(root.join("credentials.cbor")).expect("custody"),
        );
        let store =
            Arc::new(crate::FileGatewayAttemptStore::open(root.join("attempts")).expect("store"));
        let draft = installation_draft(recipe);
        let shared = crate::SharedConnection::new(
            store.clone(),
            draft.provider_kind().clone(),
            draft.alias().clone(),
        );
        let floor = crate::GenerationFloor::new(root.clone());
        if case == "existing-connection" {
            shared.insert(&draft).await.expect("existing");
        }
        if case == "substituted-floor" {
            floor.initialize(&draft).expect("substituted floor");
        }
        if case == "corrupt-journal" {
            std::fs::write(root.join("credential-journal.json"), b"invalid")
                .expect("corrupt journal");
        }
        let make_engine =
            || installation_engine(recipe, trust, policy, &draft, &root, &store, &floor);
        assert_eq!(
            crate::install_connection(
                recipe,
                &shared,
                &*credentials,
                |_| panic!("unapproved draft must not run"),
                draft.connection_id(),
                SecretBytes::new(b"rk_test_unapproved".to_vec()).expect("secret")
            )
            .await
            .err(),
            Some("gateway.install.candidate-approval-required"),
        );
        let engine = make_engine();
        engine
            .initialize_effect_configuration()
            .expect("configuration");
        let before = engine.execution_witness();
        let secret = if case == "bad-prefix" {
            b"sk_live_invalid".as_slice()
        } else {
            b"rk_test_first_install".as_slice()
        };
        let result = engine
            .stage_candidate_installation(&draft, zeroize::Zeroizing::new(secret.to_vec()))
            .await;
        if case == "staged" {
            let target = result.expect("staged");
            assert_eq!(engine.execution_witness(), before);
            drop(engine);
            cases.push(
                assert_staged_installation(
                    &target,
                    &draft,
                    &root,
                    &credentials,
                    &floor,
                    &shared,
                    make_engine,
                )
                .await,
            );
        } else {
            assert!(result.is_err(), "{case}");
            assert_eq!(engine.execution_witness(), before);
            let generations = credentials
                .stored_generations(draft.connection_id())
                .expect("generations");
            assert_eq!(generations.len(), usize::from(case == "substituted-floor"));
            if case != "existing-connection" {
                assert!(shared.load().await.expect("load").is_none());
            }
            cases.push(json!({"case":case,"refused":true,"stored_generations":generations.len(),"no_provider_entry":true}));
        }
    }
    json!({"direct_install_requires_approval_before_custody":true,"cases":cases})
}

struct RotationFixture {
    _directory: tempfile::TempDir,
    credentials_path: std::path::PathBuf,
    credentials: Arc<PersistentCredentialStore>,
    record: ConnectionRecord,
    shared: crate::SharedConnection,
    journal: crate::CredentialJournal,
    engine: crate::GatewayEngine,
}

async fn rotation_fixture(
    recipe: &CompiledRecipe,
    trust: &auths_model::TrustedContext,
    policy: &EffectPolicy,
    case: &str,
) -> RotationFixture {
    let directory = tempfile::tempdir().expect("directory");
    let root = std::fs::canonicalize(directory.path()).expect("path");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
    }
    let credentials_path = root.join("credentials.cbor");
    let credentials =
        Arc::new(PersistentCredentialStore::open(&credentials_path).expect("custody"));
    let store: Arc<dyn crate::GatewayAttemptStore> =
        Arc::new(crate::FileGatewayAttemptStore::open(root.join("attempts")).expect("store"));
    let attempts =
        crate::GatewayAttempts::new(Arc::clone(&store), policy.clone()).expect("attempts");
    let template = connection_account(
        recipe,
        crate::submit::account_commitment("acct_TESTACCOUNT01"),
    );
    let first = credentials
        .install(
            template.connection_id(),
            NonZeroU64::MIN,
            SecretBytes::new(b"rk_test_initial".to_vec()).expect("secret"),
        )
        .await
        .expect("custody install");
    let record = rotation_record(&template, *first.as_bytes(), case);
    let shared = crate::SharedConnection::new(
        Arc::clone(&store),
        record.provider_kind().clone(),
        record.alias().clone(),
    );
    shared.insert(&record).await.expect("insert");
    let journal = crate::CredentialJournal::new(root.clone());
    if case != "missing-journal" {
        journal.initialize(record.connection_id()).expect("journal");
        journal
            .register(record.connection_id(), record.credential_generation())
            .expect("first note");
    }
    let floor = crate::GenerationFloor::new(root.clone());
    floor.initialize(&record).expect("floor");
    let engine = crate::GatewayEngine::new(
        recipe.clone(),
        *recipe.digest(),
        &auths_codec::encode_verifier_context(trust).expect("trust"),
        policy.clone(),
        record.provider_kind().clone(),
        record.alias().clone(),
        "gateway".to_owned(),
        record.allowed_profiles()[0].clone(),
        credentials.clone(),
        attempts,
    )
    .expect("engine")
    .with_credential_journal(journal.clone())
    .with_generation_floor(floor)
    .with_qualification(Arc::new(crate::QualificationGate::new(
        crate::QualificationPolicy::Optional,
        None,
        None,
        Box::new(Arc::new(crate::FixedClock::at(NOW))),
        auths_recipe_qualification::VerifierState::default(),
    )));
    engine
        .initialize_effect_configuration()
        .expect("configuration");
    RotationFixture {
        _directory: directory,
        credentials_path,
        credentials,
        record,
        shared,
        journal,
        engine,
    }
}

fn rotation_record(template: &ConnectionRecord, first: [u8; 32], case: &str) -> ConnectionRecord {
    let record = ConnectionRecord::new(
        template.provider_kind().clone(),
        template.alias().clone(),
        template.connection_id().clone(),
        SemanticId::parse("auths.gateway-operation/1").expect("contract"),
        SemanticId::parse("auths.gateway-connection-descriptor/1").expect("schema"),
        template.descriptor().to_vec(),
        *template.account_commitment(),
        first,
        NonZeroU64::MIN,
        ConnectionState::Active,
        template.allowed_workloads().to_vec(),
        template.allowed_profiles().to_vec(),
        NOW - 100,
        NOW - 100,
        None,
    )
    .expect("record");

    match case {
        "disabled" => record
            .transition_state(ConnectionState::Disabled, NOW - 10)
            .expect("disable"),
        "revoked" => record
            .transition_state(ConnectionState::Revoked, NOW - 10)
            .expect("revoke"),
        _ => record,
    }
}

async fn assert_staged_rotation(
    fixture: &RotationFixture,
    stale: &PersistentCredentialStore,
    target: &crate::effect::CandidateCredentialTarget,
    secret: &[u8],
    case: &str,
) -> Value {
    let RotationFixture {
        credentials,
        record,
        engine,
        ..
    } = fixture;
    assert_eq!(target.record().state(), record.state());
    assert_eq!(
        target.record().generation().get(),
        record.generation().get() + 1
    );
    assert_eq!(
        target.record().credential_generation(),
        target.record().generation()
    );
    assert_eq!(target.previous(), Some(record));
    assert!(
        credentials
            .holds(&record.credential_binding())
            .await
            .is_ok()
    );
    assert!(
        credentials
            .holds(&target.record().credential_binding())
            .await
            .is_ok()
    );
    assert!(
        stale
            .holds(&target.record().credential_binding())
            .await
            .is_ok(),
        "a preexisting reader refreshes custody"
    );
    assert!(
        stale
            .replace(
                record.connection_id(),
                record.generation(),
                target.record().credential_generation(),
                SecretBytes::new(b"rk_test_stale".to_vec()).expect("secret")
            )
            .await
            .is_err(),
        "a stale writer cannot overwrite the committed candidate"
    );
    let bytes = target.to_private_bytes().expect("proposal");
    let repeated = engine
        .stage_candidate_rotation(zeroize::Zeroizing::new(secret.to_vec()))
        .await
        .expect("idempotent custody stage");
    assert_eq!(repeated.to_private_bytes().expect("repeated"), bytes);
    assert!(
        engine
            .stage_candidate_rotation(zeroize::Zeroizing::new(b"rk_test_other".to_vec()))
            .await
            .is_err(),
        "never overwrite a staged candidate"
    );
    assert_reopened_candidate(fixture, stale, target).await;
    json!({"case": case, "staged_generation": target.record().credential_generation().get(), "same_secret_idempotent": true, "different_secret_refused": true, "reopen_retains_current_and_candidate": true, "cleanup_notes_retained": true, "preexisting_reader_refreshes_custody": true, "stale_writer_cannot_overwrite": true, "completed_delete_visible_to_stale_reader": true})
}

async fn assert_reopened_candidate(
    fixture: &RotationFixture,
    stale: &PersistentCredentialStore,
    target: &crate::effect::CandidateCredentialTarget,
) {
    let RotationFixture {
        credentials_path,
        record,
        journal,
        ..
    } = fixture;
    let reopened = PersistentCredentialStore::open(credentials_path).expect("reopen");
    assert!(reopened.holds(&record.credential_binding()).await.is_ok());
    assert!(
        reopened
            .holds(&target.record().credential_binding())
            .await
            .is_ok()
    );
    let generations = reopened
        .stored_generations(record.connection_id())
        .expect("generations");
    assert_eq!(
        generations,
        vec![
            record.credential_generation(),
            target.record().credential_generation()
        ]
    );
    assert_eq!(
        journal.generations(record.connection_id()).expect("notes"),
        generations
    );
    reopened
        .revoke(
            record.connection_id(),
            target.record().credential_generation(),
        )
        .await
        .expect("delete staged generation");
    assert!(
        stale
            .holds(&target.record().credential_binding())
            .await
            .is_err(),
        "completed deletion is visible to a stale reader"
    );
    assert!(
        stale.holds(&record.credential_binding()).await.is_ok(),
        "current credential remains"
    );
}

fn installation_draft(recipe: &CompiledRecipe) -> ConnectionRecord {
    let template = connection_account(
        recipe,
        crate::submit::account_commitment("acct_TESTACCOUNT01"),
    );

    ConnectionRecord::new(
        template.provider_kind().clone(),
        template.alias().clone(),
        template.connection_id().clone(),
        template.contract().clone(),
        template.descriptor_schema().clone(),
        template.descriptor().to_vec(),
        *template.account_commitment(),
        [0; 32],
        NonZeroU64::MIN,
        ConnectionState::Active,
        template.allowed_workloads().to_vec(),
        template.allowed_profiles().to_vec(),
        NOW,
        NOW,
        None,
    )
    .expect("draft")
}

fn installation_engine(
    recipe: &CompiledRecipe,
    trust: &auths_model::TrustedContext,
    policy: &EffectPolicy,
    draft: &ConnectionRecord,
    root: &std::path::Path,
    store: &Arc<crate::FileGatewayAttemptStore>,
    floor: &crate::GenerationFloor,
) -> crate::GatewayEngine {
    crate::GatewayEngine::new(
        recipe.clone(),
        *recipe.digest(),
        &auths_codec::encode_verifier_context(trust).expect("trust"),
        policy.clone(),
        draft.provider_kind().clone(),
        draft.alias().clone(),
        "gateway".to_owned(),
        draft.allowed_profiles()[0].clone(),
        Arc::new(
            PersistentCredentialStore::open(root.join("credentials.cbor"))
                .expect("reopened custody"),
        ),
        crate::GatewayAttempts::new(store.clone(), policy.clone()).expect("attempts"),
    )
    .expect("engine")
    .with_credential_journal(crate::CredentialJournal::new(root.to_path_buf()))
    .with_generation_floor(floor.clone())
    .with_qualification(Arc::new(crate::QualificationGate::new(
        crate::QualificationPolicy::Optional,
        None,
        None,
        Box::new(Arc::new(crate::FixedClock::at(NOW))),
        auths_recipe_qualification::VerifierState::default(),
    )))
}

async fn assert_staged_installation(
    target: &crate::effect::CandidateCredentialTarget,
    draft: &ConnectionRecord,
    root: &std::path::Path,
    credentials: &PersistentCredentialStore,
    floor: &crate::GenerationFloor,
    shared: &crate::SharedConnection,
    make_engine: impl Fn() -> crate::GatewayEngine,
) -> Value {
    assert!(target.previous().is_none());
    assert_eq!(target.record().generation(), NonZeroU64::MIN);
    assert!(
        credentials
            .holds(&target.record().credential_binding())
            .await
            .is_ok()
    );
    floor.accept(target.record()).expect("floor exact");
    assert!(
        floor.accept(draft).is_err(),
        "same generation substitution refused"
    );
    let bytes = target.to_private_bytes().expect("proposal");
    let reopened = make_engine();
    let reopened_before = reopened.execution_witness();
    let repeated = reopened
        .stage_candidate_installation(
            draft,
            zeroize::Zeroizing::new(b"rk_test_first_install".to_vec()),
        )
        .await
        .expect("resume");
    assert_eq!(
        repeated.to_private_bytes().expect("resumed proposal"),
        bytes
    );
    assert!(
        reopened
            .stage_candidate_installation(draft, zeroize::Zeroizing::new(b"rk_test_other".to_vec()))
            .await
            .is_err()
    );
    std::fs::remove_file(root.join("connection-floor.json")).expect("lost floor");
    let refused = reopened
        .compile_candidate_effect(target, &[], &[])
        .await
        .expect_err("missing floor refusal");
    assert_eq!(
        refused,
        crate::GatewaySubmitResult::NotEntered {
            code: "gateway.connection.restore-rollback".to_owned()
        }
    );
    assert!(
        !root.join("connection-floor.json").exists(),
        "runtime cannot repair floor"
    );
    let restored = reopened
        .stage_candidate_installation(
            draft,
            zeroize::Zeroizing::new(b"rk_test_first_install".to_vec()),
        )
        .await
        .expect("explicit operator restaging");
    assert_eq!(restored.to_private_bytes().expect("restaged"), bytes);
    assert_eq!(reopened.execution_witness(), reopened_before);
    assert!(shared.load().await.expect("load").is_none());
    assert_eq!(
        crate::CredentialJournal::new(root.to_path_buf())
            .generations(draft.connection_id())
            .expect("notes"),
        vec![NonZeroU64::MIN]
    );
    json!({"case":"staged","reopened_same_draft_and_secret_exact":true,"different_secret_refused":true,"runtime_missing_floor_refused_without_repair":true,"explicit_restaging_exact":true,"connection_remains_absent":true,"cleanup_note_retained":true})
}

fn private_case_directory() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().expect("directory");
    let root = std::fs::canonicalize(directory.path()).expect("path");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("mode");
    }
    (directory, root)
}
