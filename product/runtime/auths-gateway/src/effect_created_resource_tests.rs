//! Original native entered source and independently authorized recovery on the
//! maintained adapters. Response facts are injected, not real provider evidence.
use super::admission_tests::Setup;
use super::information_tests::{allocation_rows, private, record};
use super::*;
use crate::effect::compile_recovery_acquisition;
use crate::store_testkit::{Backend, postgres_configured};
use sha2::Digest as _;

const CHILD: &str = "PRIVATE-SELECTED-CREATED-RESOURCE";

fn source() -> (Value, Value) {
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/hostile-recipes-v2.json"
    ))
    .unwrap();
    let mut source = corpus["bases"]["airtable"]["recipe"].clone();
    source["write"]["method"] = json!("POST");
    source["write"]["path"] = json!([{"kind":"fixed","value":"parents"},{"kind":"field","name":"record_id"},{"kind":"fixed","value":"children"}]);
    source["write"]["body"]["value"]["fields"]["parent_id"] =
        json!({"kind":"field","name":"record_id"});
    source["observation"] = json!({"path":[{"kind":"fixed","value":"parents"},{"kind":"field","name":"record_id"},{"kind":"fixed","value":"children"}],
        "json_pointer":"/records","expected_field":"record_id","maximum_response_bytes":4096,
        "created_resource":{"schema":"auths.created-resource-selection/1","resource_pointer":"/id","parent_pointer":"/parent_id","parent_kind":"scalar",
            "maximum_items":8,"complete":[{"kind":"absent","pointer":"/offset"}]}});
    source["echo"]["observe"] = json!("/auths_echo");
    // Native enrollment helper also authors independent recovery permission.
    source["content"] = json!({"schema":"auths.gateway-content-read/1","resource_field":"record_id",
        "path":[{"kind":"fixed","value":"documents"},{"kind":"field","name":"record_id"}],
        "query":[],
        "projection":{"kind":"utf8"},"maximum_response_bytes":1024,"maximum_content_bytes":64});
    let mut lock = corpus["bases"]["airtable"]["lock"].clone();
    source["service"] = json!("created-resource-fixture");
    lock["service"] = source["service"].clone();
    source["tool"] = json!("create_child_v1");
    lock["tool"] = source["tool"].clone();
    (source, lock)
}
fn recipe() -> CompiledRecipe {
    let (source, lock) = source();
    CompiledRecipe::compile(
        &serde_json::to_vec(&source).unwrap(),
        &serde_json::to_vec(&lock).unwrap(),
    )
    .unwrap()
}
fn installed(setup: &Setup) -> EffectInstallation<'_> {
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

#[test]
fn creation_recipe_rejects_ambiguous_or_unbound_contracts() {
    let (source, lock) = source();
    let mut invalid = Vec::new();
    let mut value = source.clone();
    value["observation"]["created_resource"]["maximum_items"] = json!(65);
    invalid.push(value);
    let mut value = source.clone();
    value["observation"]["path"][1] =
        json!({"kind":"response-field","pointer":"/id","max_bytes":64});
    invalid.push(value);
    let mut value = source.clone();
    value["observation"]["created_resource"]["resource_pointer"] = json!("/auths_echo");
    invalid.push(value);
    let mut value = source.clone();
    value["observation"]["created_resource"]["parent_pointer"] = json!("/invalid~8");
    invalid.push(value);
    let mut value = source.clone();
    value["write"]["body"]["value"]["fields"]
        .as_object_mut()
        .unwrap()
        .remove("parent_id");
    invalid.push(value);
    let mut value = source.clone();
    value.as_object_mut().unwrap().remove("echo");
    invalid.push(value);
    let mut value = source.clone();
    value["observation"]["created_resource"]["complete"] = json!([]);
    invalid.push(value);
    for value in invalid {
        assert!(
            CompiledRecipe::compile(
                &serde_json::to_vec(&value).unwrap(),
                &serde_json::to_vec(&lock).unwrap()
            )
            .is_err()
        );
    }
    let recipe = recipe();
    let review = recipe.review_document();
    assert_eq!(
        review["created_resource_selection"]["declaration"]["schema"],
        "auths.created-resource-selection/1"
    );
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Unique,
    Zero,
    Multiple,
    Incomplete,
    WrongParent,
    Malformed,
    VersionMismatch,
    Stale,
    WriterWithdrawn,
}
impl Case {
    const ALL: [Self; 9] = [
        Self::Unique,
        Self::Zero,
        Self::Multiple,
        Self::Incomplete,
        Self::WrongParent,
        Self::Malformed,
        Self::VersionMismatch,
        Self::Stale,
        Self::WriterWithdrawn,
    ];
    fn unique(self) -> bool {
        matches!(self, Self::Unique | Self::WriterWithdrawn)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "complete native source/read/refinement/replay and privacy relation"
)]
async fn lifecycle(backend: Backend, case: Case) -> Value {
    let setup = Setup::with_recipe(backend, recipe(), [1; 32]).await;
    let source = Arc::new(approve(
        compile_mutation_effect(
            &installed(&setup),
            NOW,
            &setup.native.action.proof,
            &setup.native.action.action,
        )
        .unwrap(),
    ));
    let attempts = setup.attempts(Arc::clone(&setup.store));
    let crate::store::BoundedClaim::Claimed(reserved) = attempts
        .claim_bounded(&source, NOW, setup.validation())
        .await
        .unwrap()
    else {
        panic!("source claim");
    };
    let (granted, permit) = reserved
        .grant_entry(
            Arc::clone(&source),
            setup.validation(),
            NOW,
            &crate::GatewayPreEntry::default(),
        )
        .await
        .unwrap();
    drop((granted, permit)); // possible send, no write response or effect assertion
    let source_rows = allocation_rows(&setup, &source, 0).await;
    assert!(source_rows.iter().all(Option::is_some));
    let source_operation = crate::LogicalOperationId::parse("initial").unwrap();
    let target = attempts
        .retained_recovery_target(
            setup.recipe.namespace(),
            &source_operation,
            *setup.recipe.digest(),
        )
        .await
        .unwrap();
    let call = target
        .authorization_call(
            &setup.recipe,
            &crate::LogicalOperationId::parse("lookup-child").unwrap(),
        )
        .unwrap();
    let native = setup.native.signed_call(&call, 0x55);
    let read = Arc::new(approve(
        compile_recovery_acquisition(
            &installed(&setup),
            &target,
            NOW,
            &native.proof,
            &native.action,
        )
        .unwrap(),
    ));
    assert_eq!(
        private(read.effect().binding())["protocol"]["kind"],
        "acquisition"
    );
    if matches!(case, Case::WriterWithdrawn) {
        let writer: [u8; 32] = serde_json::from_value(
            private(source.effect().binding())["scope"]["bound"]["ancestors"][1]["enrollment"]
                .clone(),
        )
        .unwrap();
        let controller = setup.controller.clone();
        tokio::task::block_in_place(|| setup.native.withdraw_participant(&controller, writer));
    }
    let crate::AcquisitionClaim::Reserved(reserved) = attempts
        .claim_recovery(&read, NOW, setup.validation())
        .await
        .unwrap()
    else {
        panic!("read claim");
    };
    let (granted, permit) = reserved
        .grant_entry(Arc::clone(&read), setup.validation(), NOW)
        .await
        .unwrap();
    drop(permit);
    let token = crate::recipe::echo_token(
        setup.recipe.namespace(),
        &source_operation,
        &setup.native.action.commitment,
    );
    let item = json!({"id":CHILD,"parent_id":RECORD,"auths_echo":token});
    let mut document = json!({"records":[item.clone()]});
    match case {
        Case::Zero => document["records"] = json!([]),
        Case::Multiple => document["records"] = json!([item.clone(), item.clone()]),
        Case::Incomplete => document["offset"] = json!("next"),
        Case::WrongParent => document["records"][0]["parent_id"] = json!("other-parent"),
        _ => {}
    }
    let body = if matches!(case, Case::Malformed) {
        format!(
            "{{\"records\":[],\"records\":[{}]}}",
            serde_json::to_string(&item).unwrap()
        )
        .into_bytes()
    } else {
        serde_json::to_vec(&document).unwrap()
    };
    granted
        .record_response(200, !matches!(case, Case::VersionMismatch), &body, NOW)
        .await
        .unwrap();
    let clock = if matches!(case, Case::Stale) {
        Arc::new(crate::QualificationGate::new(
            crate::QualificationPolicy::Optional,
            None,
            None,
            Box::new(Arc::new(crate::FixedClock::at(NOW + 31))),
            auths_recipe_qualification::VerifierState::default(),
        ))
    } else {
        Arc::clone(&setup.qualification)
    };
    let read_rows = allocation_rows(&setup, &read, 0).await;
    assert!(read_rows.iter().all(Option::is_some));
    let read_operation = crate::LogicalOperationId::parse("lookup-child").unwrap();
    let result = attempts
        .refine_recovery(
            setup.recipe.namespace(),
            &source_operation,
            &read_operation,
            *setup.recipe.digest(),
            Arc::clone(&clock),
        )
        .await
        .unwrap();
    assert_eq!(
        result.disposition == crate::RecoveryDisposition::Recorded,
        case.unique()
    );
    assert_eq!(
        result.source.stage(),
        if case.unique() {
            crate::GatewayAttemptStage::ObservedByProvider
        } else {
            crate::GatewayAttemptStage::Unknown
        }
    );
    assert!(
        result.source.response_status().is_none(),
        "read evidence must not fabricate a lost write response"
    );
    let retained = record(&setup, "initial").await.unwrap();
    assert_eq!(
        retained["state"]["facts"]["created_resource"],
        if case.unique() {
            json!(CHILD)
        } else {
            Value::Null
        }
    );
    assert_eq!(
        !retained["state"]["facts"]["recovery_evidence"].is_null(),
        case.unique()
    );
    let public = serde_json::to_string(&result.report()).unwrap();
    assert!(!public.contains(CHILD));
    assert!(!public.contains(&token));
    assert!(!public.contains(&hex::encode(sha2::Sha256::digest(&body))));
    let replay = attempts
        .refine_recovery(
            setup.recipe.namespace(),
            &source_operation,
            &read_operation,
            *setup.recipe.digest(),
            clock,
        )
        .await
        .unwrap();
    if case.unique() {
        assert_eq!(
            replay.disposition,
            crate::RecoveryDisposition::AlreadyRecorded
        );
    }
    assert_eq!(record(&setup, "initial").await.unwrap(), retained);
    assert_eq!(allocation_rows(&setup, &source, 0).await, source_rows);
    assert_eq!(allocation_rows(&setup, &read, 0).await, read_rows);
    assert!(matches!(
        attempts
            .claim_recovery(&read, NOW, setup.validation())
            .await
            .unwrap(),
        crate::AcquisitionClaim::Existing(_)
    ));
    assert!(matches!(
        attempts
            .claim_bounded(&source, NOW, setup.validation())
            .await,
        Err(crate::GatewayAttemptError::Replay)
            | Err(crate::GatewayAttemptError::InvalidTransition)
    ));
    if case.unique() {
        let key = crate::GatewayAttemptKey::for_operation(
            &setup.policy,
            setup.recipe.namespace(),
            &source_operation,
        )
        .unwrap();
        let store = setup.backend.raw();
        let (store, key, original, substituted) = tokio::task::spawn_blocking(move || {
            let original = store
                .load(crate::GatewayRecordKind::Attempt, &key)
                .unwrap()
                .unwrap();
            let substituted = crate::store::fixture_created_resource_substitution(
                &original,
                "forged-selected-child",
            )
            .unwrap();
            store
                .replace(
                    crate::GatewayRecordKind::Attempt,
                    &key,
                    &original,
                    &substituted,
                )
                .unwrap();
            (store, key, original, substituted)
        })
        .await
        .unwrap();
        assert!(matches!(
            attempts
                .read(setup.recipe.namespace(), &source_operation)
                .await,
            Err(crate::GatewayAttemptError::Corrupt)
        ));
        tokio::task::spawn_blocking(move || {
            store.replace(
                crate::GatewayRecordKind::Attempt,
                &key,
                &substituted,
                &original,
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(record(&setup, "initial").await.unwrap(), retained);
        let read_key = crate::GatewayAttemptKey::for_operation(
            &setup.policy,
            setup.recipe.namespace(),
            &read_operation,
        )
        .unwrap();
        let store = setup.backend.raw();
        let original_read = tokio::task::spawn_blocking(move || {
            store.load(crate::GatewayRecordKind::Attempt, &read_key)
        })
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let substitutions =
            crate::store::fixture_created_history_substitutions(&original_read).unwrap();
        assert_eq!(substitutions.len(), 5);
        for (name, substituted) in substitutions {
            let store = setup.backend.raw();
            let before = original_read.clone();
            let after = substituted.clone();
            tokio::task::spawn_blocking(move || {
                store.replace(
                    crate::GatewayRecordKind::Attempt,
                    &read_key,
                    &before,
                    &after,
                )
            })
            .await
            .unwrap()
            .unwrap();
            assert!(
                matches!(
                    attempts
                        .read(setup.recipe.namespace(), &source_operation)
                        .await,
                    Err(crate::GatewayAttemptError::Corrupt)
                ),
                "selected identity accepted with substituted original acquisition {name}"
            );
            assert!(matches!(
                attempts.read_effect(&source).await,
                Err(crate::GatewayAttemptError::Corrupt)
            ));
            let store = setup.backend.raw();
            let before = substituted;
            let after = original_read.clone();
            tokio::task::spawn_blocking(move || {
                store.replace(
                    crate::GatewayRecordKind::Attempt,
                    &read_key,
                    &before,
                    &after,
                )
            })
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                attempts
                    .read(setup.recipe.namespace(), &source_operation)
                    .await
                    .unwrap()
                    .unwrap(),
                result.source
            );
        }
        assert_eq!(record(&setup, "initial").await.unwrap(), retained);
        assert_eq!(allocation_rows(&setup, &source, 0).await, source_rows);
        assert_eq!(allocation_rows(&setup, &read, 0).await, read_rows);
    }
    json!({"case":format!("{case:?}"),"private_identity_recorded":case.unique(),"source_response_status":Value::Null,"original_source_and_recovery_link_retained":case.unique(),
        "public_identity_echo_and_raw_hash_absent":true,"no_new_claim_or_charge_on_replay":true,"canonical_identity_substitution_refused":case.unique(),
        "original_acquisition_substitutions_refused":if case.unique(){5}else{0},"provider_calls":0,"responses_are_injected":true})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_created_resource_recovery_fixture_is_current() {
    creation_recipe_rejects_ambiguous_or_unbound_contracts();
    let mut cases = Vec::new();
    let mut failures = Vec::new();
    for case in Case::ALL {
        match tokio::spawn(lifecycle(Backend::File, case)).await {
            Ok(value) => cases.push(value),
            Err(_) => failures.push(format!("{case:?}")),
        }
    }
    assert!(
        failures.is_empty(),
        "native creation recovery case failures: {failures:?}"
    );
    let bytes=serde_json::to_vec_pretty(&json!({"schema":"auths.created-resource-recovery-vectors/2","cases":cases,"compiler_refusal_matrix_checked":true,
        "scope":"native entered source, separately authorized/approved current read and real file source/read/allocation fence with injected response facts",
        "not_established":["actual-provider-create","TLS-postgres","dependent-child-entry","installed-key-isolation","human-presence","full-F10"]})).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/creation-recovery.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the TLS PostgreSQL fixture; CI invokes explicitly"]
async fn postgres_native_created_resource_recovery_matrix() {
    assert!(postgres_configured());
    let mut failures = Vec::new();
    for case in Case::ALL {
        if tokio::spawn(lifecycle(Backend::Postgres, case))
            .await
            .is_err()
        {
            failures.push(format!("{case:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "PostgreSQL creation recovery case failures: {failures:?}"
    );
}
