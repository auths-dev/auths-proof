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
            Arc::new(crate::FileGatewayAttemptStore::open(&root.join("attempts")).expect("store"));
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
        let record = ConnectionRecord::new(
            template.provider_kind().clone(),
            template.alias().clone(),
            template.connection_id().clone(),
            SemanticId::parse("auths.gateway-operation/1").expect("contract"),
            SemanticId::parse("auths.gateway-connection-descriptor/1").expect("schema"),
            template.descriptor().to_vec(),
            *template.account_commitment(),
            *first.as_bytes(),
            NonZeroU64::MIN,
            ConnectionState::Active,
            template.allowed_workloads().to_vec(),
            template.allowed_profiles().to_vec(),
            NOW - 100,
            NOW - 100,
            None,
        )
        .expect("record");
        let record = match case {
            "disabled" => record
                .transition_state(ConnectionState::Disabled, NOW - 10)
                .expect("disable"),
            "revoked" => record
                .transition_state(ConnectionState::Revoked, NOW - 10)
                .expect("revoke"),
            _ => record,
        };
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
        let stale =
            PersistentCredentialStore::open(&credentials_path).expect("second pre-staging handle");
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
            assert_eq!(target.record().state(), record.state());
            assert_eq!(
                target.record().generation().get(),
                record.generation().get() + 1
            );
            assert_eq!(
                target.record().credential_generation(),
                target.record().generation()
            );
            assert_eq!(target.previous(), Some(&record));
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
            let reopened = PersistentCredentialStore::open(&credentials_path).expect("reopen");
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
            cases.push(json!({"case": case, "staged_generation": target.record().credential_generation().get(), "same_secret_idempotent": true, "different_secret_refused": true, "reopen_retains_current_and_candidate": true, "cleanup_notes_retained": true, "preexisting_reader_refreshes_custody": true, "stale_writer_cannot_overwrite": true, "completed_delete_visible_to_stale_reader": true}));
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
            &record
        );
        assert_eq!(
            engine.execution_witness(),
            before,
            "no lease or provider entry"
        );
    }
    json!({"schema": "auths.candidate-staging-fixture/1", "scope": "actual engine, persistent file custody, generation floor and cleanup journal; fixed deployment clock; no provider execution, process crash or PostgreSQL claim", "cases": cases})
}
