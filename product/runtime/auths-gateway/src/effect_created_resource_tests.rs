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

fn child_effect(
    setup: &Setup,
    lineages: &[crate::effect::CreatedLineage],
    resource: &str,
    operation: &str,
) -> Result<crate::effect::BoundEffect, crate::GatewaySubmitResult> {
    let target = crate::effect::ContentReadTarget::new(
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
    let native = setup.native.signed_call(&call, 0x55);
    crate::effect::compile_content_acquisition(
        &installed(setup).with_lineages(lineages),
        &target,
        NOW,
        &native.proof,
        &native.action,
    )
}

async fn replace_raw_read(
    setup: &Setup,
    key: crate::GatewayAttemptKey,
    before: Vec<u8>,
    after: Vec<u8>,
) {
    let store = setup.backend.raw();
    tokio::task::spawn_blocking(move || {
        store.replace(crate::GatewayRecordKind::Attempt, &key, &before, &after)
    })
    .await
    .unwrap()
    .unwrap();
}

#[allow(
    clippy::too_many_lines,
    reason = "one complete native lineage substitution and final-fence schedule"
)]
async fn consume_child(setup: &Setup, unique: bool) -> Value {
    let attempts = setup.attempts(setup.backend.raw());
    let lineages = attempts
        .created_lineages(Some(&setup.native.root))
        .await
        .unwrap();
    assert!(child_effect(setup, &[], CHILD, "consume-created-child").is_err());
    assert!(
        child_effect(
            setup,
            &lineages,
            "forged-other-child",
            "consume-created-child"
        )
        .is_err()
    );
    if !unique {
        assert!(lineages.is_empty());
        assert!(child_effect(setup, &lineages, CHILD, "consume-created-child").is_err());
        return json!({"selected":false,"consumer_refused":true});
    }
    assert_eq!(lineages.len(), 1);
    let lineage = &lineages[0];
    assert_eq!(lineage.resource, CHILD);
    assert!(child_effect(setup, &lineages, CHILD, &lineage.producer_operation).is_err());
    assert!(child_effect(setup, &lineages, CHILD, "lookup-child").is_err());
    let mut mutations = Vec::new();
    for field in [
        "root",
        "engagement",
        "authority-epoch",
        "namespace",
        "partition",
        "epoch",
        "operation",
        "recipe",
        "parent-scope",
        "connection",
        "resource",
        "producer-key",
        "acquisition-key",
        "allocation-key",
        "producer-effect",
        "acquisition-effect",
        "producer-revision",
        "acquisition-revision",
    ] {
        let mut altered = lineage.clone();
        match field {
            "root" => altered.root[0] ^= 1,
            "engagement" => altered.engagement[0] ^= 1,
            "authority-epoch" => altered.authority_epoch += 1,
            "namespace" => altered.producer_namespace.push('x'),
            "partition" => altered.producer_partition.push('x'),
            "epoch" => altered.producer_epoch += 1,
            "operation" => altered.producer_operation.push('x'),
            "recipe" => altered.producer_recipe = "ab".repeat(32),
            "parent-scope" => altered.parent_scope = "ab".repeat(32),
            "connection" => altered.connection[0] ^= 1,
            "resource" => altered.resource = "forged-child".into(),
            "producer-key" => altered.producer_key[0] ^= 1,
            "acquisition-key" => altered.acquisition_key[0] ^= 1,
            "allocation-key" => altered.allocation_key[0] ^= 1,
            "producer-effect" => altered.producer_effect[0] ^= 1,
            "acquisition-effect" => altered.acquisition_effect[0] ^= 1,
            "producer-revision" => altered.producer_revision += 1,
            "acquisition-revision" => altered.acquisition_revision += 1,
            _ => panic!("mutation case"),
        }
        if let Ok(effect) = child_effect(setup, &[altered], CHILD, "consume-created-child") {
            let approved = Arc::new(approve(effect));
            assert!(
                attempts
                    .claim_content(&approved, NOW, setup.validation())
                    .await
                    .is_err(),
                "substituted lineage admitted: {field}"
            );
        }
        assert!(record(setup, "consume-created-child").await.is_none());
        mutations.push(field);
    }
    let approved = Arc::new(approve(
        child_effect(setup, &lineages, CHILD, "consume-created-child").unwrap(),
    ));
    let review = private(approved.effect().binding());
    assert_eq!(
        review["scope"]["bound"]["lineage"]["resource"],
        json!(CHILD)
    );
    let crate::AcquisitionClaim::Reserved(reserved) = attempts
        .claim_content(&approved, NOW, setup.validation())
        .await
        .unwrap()
    else {
        panic!("child reservation")
    };
    let key = crate::GatewayAttemptKey::from_bytes(lineage.acquisition_key);
    let store = setup.backend.raw();
    let original =
        tokio::task::spawn_blocking(move || store.load(crate::GatewayRecordKind::Attempt, &key))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    let substituted = crate::store::fixture_created_history_substitutions(&original)
        .unwrap()
        .into_iter()
        .find(|(name, _)| *name == "body")
        .unwrap()
        .1;
    replace_raw_read(setup, key, original.clone(), substituted.clone()).await;
    assert!(
        reserved
            .grant_entry(Arc::clone(&approved), setup.validation(), NOW)
            .await
            .is_err(),
        "stale pre-lock provenance granted child entry"
    );
    assert!(record(setup, "consume-created-child").await.unwrap()["entry"].is_null());
    replace_raw_read(setup, key, substituted, original).await;
    // Reopening the unentered reservation creates no new charge. A fresh fence
    // may grant it only after the original immutable dependency is restored.
    let content =
        super::information_tests::acquire(setup, &approved, b"PRIVATE-CREATED-CHILD-CONTENT").await;
    let recipient = SigningKey::from_bytes(&[0x55; 32])
        .verifying_key()
        .to_bytes();
    let channel = super::information_tests::channel(setup);
    let target =
        crate::effect::DisclosureTarget::new(content, recipient, channel, [0x79; 32]).unwrap();
    let call = target
        .authorization_call(
            &setup.recipe,
            &crate::LogicalOperationId::parse("release-created-child").unwrap(),
        )
        .unwrap();
    let native = setup.native.signed_call(&call, 0x55);
    let release = Arc::new(approve(
        crate::effect::compile_disclosure(
            &installed(setup).with_lineages(&lineages),
            &target,
            NOW,
            &native.proof,
            &native.action,
        )
        .unwrap(),
    ));
    let disclosure = attempts
        .claim_disclosure(&release, NOW, setup.validation())
        .await
        .unwrap();
    assert_eq!(disclosure.stage, crate::DisclosureStage::Reserved);
    assert!(record(setup, "release-created-child").await.unwrap()["entry"].is_null());
    json!({"selected":true,"lineage_mutations_refused":mutations,"stale_original_read_refused_at_final_fence":true,
        "native_child_acquisition_entered_once_after_exact_restoration":true,"child_disclosure_reserved_without_delivery_permit":true,
        "responses_are_injected":true,"provider_calls":0})
}

#[allow(
    clippy::too_many_lines,
    reason = "complete native source/read/refinement/replay and privacy relation"
)]
async fn lifecycle(backend: Backend, case: Case) -> Value {
    let setup = Setup::with_created_resource(backend, recipe(), [1; 32]).await;
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
    let consumer = consume_child(&setup, case.unique()).await;
    json!({"case":format!("{case:?}"),"private_identity_recorded":case.unique(),"source_response_status":Value::Null,"original_source_and_recovery_link_retained":case.unique(),
        "public_identity_echo_and_raw_hash_absent":true,"no_new_claim_or_charge_on_replay":true,"canonical_identity_substitution_refused":case.unique(),
        "original_acquisition_substitutions_refused":if case.unique(){5}else{0},"consumer":consumer,"provider_calls":0,"responses_are_injected":true})
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
    let bytes=serde_json::to_vec_pretty(&json!({"schema":"auths.created-resource-recovery-vectors/3","cases":cases,"compiler_refusal_matrix_checked":true,
        "scope":"native entered source, separately authorized/approved current read and real file source/read/allocation fence with injected response facts",
        "not_established":["actual-provider-create","TLS-postgres","real-provider-dependent-child-entry","installed-key-isolation","human-presence","full-F10"]})).unwrap();
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
