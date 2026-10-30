//! AP074 compilation tests using native signed proof fixtures. These establish
//! compilation/approval behavior only; journal and transport evidence is separate.

use super::*;
use crate::effect::{EffectBinding, EffectInstallation, EffectPolicy, compile_mutation_effect};
use auths_connections::{
    ConnectionAlias, ConnectionId, ConnectionProfile, ConnectionRecord, ConnectionState,
    ProviderKind, SemanticId,
};
use ed25519_dalek::{Signer as _, SigningKey};

#[path = "effect_candidate_tests.rs"]
mod candidate_tests;

#[cfg(feature = "testkit-harness")]
#[path = "native_differential_tests.rs"]
mod differential_tests;

#[path = "effect_disclosure_journal_tests.rs"]
mod disclosure_journal_tests;

#[path = "effect_content_tests.rs"]
mod content_tests;

#[path = "effect_prerequisite_tests.rs"]
mod prerequisite_tests;

#[path = "effect_read_budget_tests.rs"]
mod read_budget_tests;

#[path = "effect_recovery_prerequisite_tests.rs"]
mod recovery_prerequisite_tests;

/// Native read authority is independent of an expired source writer. File
/// provenance is real; the source entry is a test grant with no provider send.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one native compilation corpus and its negative cases"
)]
async fn native_recovery_acquisition_fixture_is_current() {
    use crate::effect::compile_recovery_acquisition;
    use std::sync::Arc;
    // A recipe with the native read name could otherwise turn a read proof
    // into a mutation. Both source and profile lock must be refused together.
    let mut reserved_source: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/airtable/recipe.json"
    ))
    .expect("recipe source");
    let mut reserved_lock: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/airtable/profile.lock.json"
    ))
    .expect("profile lock");
    reserved_source["tool"] = json!(crate::effect::RECOVERY_READ_TOOL);
    reserved_lock["tool"] = json!(crate::effect::RECOVERY_READ_TOOL);
    assert_eq!(
        CompiledRecipe::compile(
            &serde_json::to_vec(&reserved_source).expect("recipe"),
            &serde_json::to_vec(&reserved_lock).expect("lock"),
        )
        .expect_err("reserved acquisition tool")
        .code(),
        "gateway.recipe.invalid-source",
    );
    let root = signer(h::ROOT_SEED);
    let writer = signer(0x22);
    let reader = signer(0x33);
    let observer = signer(h::OBSERVER_SEED);
    let recipe = recipe(&json!({}), &Value::Null);
    let writer_context = context(&root, &observer.principal, None);
    let connection = connection(&recipe);
    let key = SigningKey::from_bytes(&[29; 32]);
    let public = key.verifying_key().to_bytes();
    let policy = EffectPolicy::new("recovery-fixture".to_owned(), 1, public).expect("policy");
    let installed = policy.installation(
        &recipe,
        &writer_context,
        &connection,
        crate::QualificationPolicy::Optional,
        [12; 32],
    );
    let args = json!({"operation_id": "source-1", "operator_namespace": NAMESPACE,
        "recipe_digest": recipe.digest_hex(), "record_id": RECORD, "replacement": "Approved"});
    let writer_grant =
        h::grant_within(&root, &writer.principal, None, window(NOW - 10, NOW + 1)).expect("grant");
    let original = submission_for_call_during(
        &root,
        &writer,
        &writer_grant,
        &call(args.as_object().expect("args")),
        &[],
        window(NOW, NOW + 1),
    );
    let source = compile_mutation_effect(&installed, NOW, &original.proof, &original.action)
        .expect("source");
    let request = source.approval_request(NOW, NOW + 30).expect("approval");
    let signature = key
        .sign(&request.signing_message().expect("message"))
        .to_bytes();
    let original_approval = request.with_signature(signature);
    let source = Arc::new(
        source
            .approve(original_approval.clone(), &public, NOW)
            .expect("approved source"),
    );
    let directory = tempfile::tempdir().expect("directory");
    let root_path = std::fs::canonicalize(directory.path())
        .expect("canonical")
        .join("journal");
    let store = Arc::new(crate::FileGatewayAttemptStore::open(&root_path).expect("file journal"));
    let attempts = crate::GatewayAttempts::new(store, policy.clone()).expect("attempts");
    let crate::store::BoundedClaim::Claimed(claim) = attempts
        .claim_bounded(
            &source,
            NOW,
            crate::entry::EntryValidation::Oracle { now: NOW },
        )
        .await
        .expect("claim")
    else {
        panic!("expected source claim");
    };
    let (_, permit) = claim
        .grant_entry(
            source.clone(),
            crate::entry::EntryValidation::Oracle { now: NOW },
            NOW,
            &crate::GatewayPreEntry::default(),
        )
        .await
        .expect("source grant fixture");
    drop(permit);
    let operation = LogicalOperationId::parse("source-1").expect("operation");
    let target = attempts
        .resume_observable_operation(recipe.namespace(), &operation, *recipe.digest())
        .await
        .expect("lookup")
        .expect("source")
        .recovery_target()
        .expect("native target");
    let before = attempts
        .read(recipe.namespace(), &operation)
        .await
        .expect("read")
        .expect("source");
    let read_call = target
        .authorization_call(
            &recipe,
            &LogicalOperationId::parse("read-1").expect("read operation"),
        )
        .expect("read authorization call");
    let read_context =
        h::context_for_tool(&root, &observer.principal, NOW, &read_call).expect("read trust");
    let read_grant = h::grant_for_tool(
        &root,
        &reader.principal,
        None,
        window(NOW - 3_600, NOW + 3_600),
        &read_call,
    )
    .expect("read grant");
    let read = submission_for_call(&root, &reader, &read_grant, &read_call, &[]);
    let read_installation = policy.installation(
        &recipe,
        &read_context,
        &connection,
        crate::QualificationPolicy::Optional,
        [12; 32],
    );
    assert!(
        compile_mutation_effect(&installed, NOW + 2, &original.proof, &original.action).is_err(),
        "the original writer is expired"
    );
    assert!(
        compile_recovery_acquisition(&installed, &target, NOW, &original.proof, &original.action)
            .is_err(),
        "a valid mutation is not a recovery read"
    );
    let effect = compile_recovery_acquisition(
        &read_installation,
        &target,
        NOW + 2,
        &read.proof,
        &read.action,
    )
    .expect("separate native read authority");
    assert!(
        effect.private_request().is_none(),
        "acquisition has no mutation request"
    );
    let binding = effect
        .binding()
        .to_private_bytes()
        .expect("canonical binding");
    assert_eq!(
        &EffectBinding::from_private_bytes(&binding).expect("binding"),
        effect.binding()
    );
    let review = effect.private_review().expect("review");
    let literal = review
        .render_literal(crate::effect::LITERAL_REVIEW_RENDERER)
        .expect("literal");
    let review_json: Value = serde_json::from_str(&literal).expect("review JSON");
    assert_eq!(
        review_json["native"]["actors"],
        json!([reader.principal.as_str()])
    );
    assert_eq!(
        review_json["native"]["recovery"]["source_effect"],
        hex::encode(source.effect().binding().id().as_bytes())
    );
    assert_eq!(review_json["native"]["method"], "GET");
    let request = effect
        .approval_request(NOW + 2, NOW + 100)
        .expect("read approval request");
    let signature = key
        .sign(&request.signing_message().expect("read message"))
        .to_bytes();
    let approved = Arc::new(
        effect
            .approve(request.with_signature(signature), &public, NOW + 2)
            .expect("read approval"),
    );
    approved
        .validate_for_entry(&read_installation, NOW + 3)
        .expect("fresh read validation");
    assert!(
        approved
            .validate_for_entry(&read_installation, NOW + 101)
            .is_err(),
        "approval is not refreshed"
    );
    assert!(
        matches!(
            attempts
                .claim_bounded(
                    &approved,
                    NOW + 3,
                    crate::entry::EntryValidation::Oracle { now: NOW + 3 }
                )
                .await,
            Err(crate::GatewayAttemptError::InvalidTransition)
        ),
        "mutation admission rejects acquisition"
    );
    let other = compile_recovery_acquisition(
        &read_installation,
        &target,
        NOW + 2,
        &read.proof,
        &read.action,
    )
    .expect("same read");
    assert!(
        other
            .approve(original_approval.clone(), &public, NOW + 2)
            .is_err(),
        "write approval cannot authorize the read"
    );
    let mut refused = Vec::new();
    for (field, value) in [
        ("source_effect", json!("00".repeat(32))),
        ("source_operation", json!("other-source")),
        ("read_contract", json!("00".repeat(32))),
        ("maximum_response_bytes", json!(65_536)),
        ("recipe_digest", json!("00".repeat(32))),
        ("operator_namespace", json!("other-namespace")),
        ("operation_id", json!("source-1")),
        ("recipient", json!("unsupported-agent")),
    ] {
        let mut changed = read_call.arguments().clone();
        changed.insert(field.to_owned(), value);
        let call =
            McpToolCall::new(read_call.service(), read_call.name(), changed).expect("changed call");
        let proof = submission_for_call(&root, &reader, &read_grant, &call, &[]);
        assert!(
            compile_recovery_acquisition(
                &read_installation,
                &target,
                NOW + 2,
                &proof.proof,
                &proof.action
            )
            .is_err(),
            "{field}"
        );
        refused.push(field);
    }
    assert_eq!(
        attempts
            .read(recipe.namespace(), &operation)
            .await
            .expect("read"),
        Some(before.clone())
    );
    let fixture = json!({
        "schema": "auths.gateway-recovery-compilation-fixture/1",
        "scope": "native signed read proof and file-derived target; test-only source grant; no acquisition entry or provider claim",
        "binding_canonical": std::str::from_utf8(&binding).expect("UTF-8"),
        "effect_id": hex::encode(approved.effect().binding().id().as_bytes()),
        "authorization_call": serde_json::from_slice::<Value>(&read_call.canonical_bytes().expect("call")).expect("call JSON"),
        "literal_review": literal.as_str(), "refused_changed_fields": refused,
        "original_writer_expired": true, "separate_reader": true,
        "mutation_admission_refused": true, "source_journal_unchanged": true,
        "reserved_mutation_recipe_refused": {"source": reserved_source, "profile_lock": reserved_lock},
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/recovery-compilation.json");
    let bytes = serde_json::to_vec_pretty(&fixture).expect("fixture");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("write fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), bytes);
    let mut reads = vec![approved];
    for index in 2..=17 {
        let call = target
            .authorization_call(
                &recipe,
                &LogicalOperationId::parse(&format!("read-{index}")).expect("read operation"),
            )
            .expect("native read call");
        let read = submission_for_call(&root, &reader, &read_grant, &call, &[]);
        let effect = compile_recovery_acquisition(
            &read_installation,
            &target,
            NOW + 2,
            &read.proof,
            &read.action,
        )
        .expect("native read effect");
        let request = effect
            .approval_request(NOW + 2, NOW + 100)
            .expect("read request");
        let signature = key
            .sign(&request.signing_message().expect("message"))
            .to_bytes();
        reads.push(Arc::new(
            effect
                .approve(request.with_signature(signature), &public, NOW + 2)
                .expect("exact read approval"),
        ));
    }
    let corpus =
        exercise_recovery_journal(&attempts, &root_path, policy.clone(), reads.clone()).await;
    assert_eq!(
        attempts
            .read(recipe.namespace(), &operation)
            .await
            .expect("source read"),
        Some(before)
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/recovery-entry.json");
    let bytes = serde_json::to_vec_pretty(&corpus).expect("recovery entry corpus");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("write recovery entry corpus");
    }
    assert_eq!(std::fs::read(path).expect("recovery entry corpus"), bytes);
    let budget_corpus =
        read_budget_tests::corpus(&source, &target, &read_installation, &policy, &root).await;
    let budget_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/recovery-policy-budgets.json");
    let budget_bytes = serde_json::to_vec_pretty(&budget_corpus).expect("budget corpus");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&budget_path, &budget_bytes).expect("write budget corpus");
    }
    assert_eq!(
        std::fs::read(&budget_path).expect("budget corpus"),
        budget_bytes
    );
    let mut corpus = exercise_recovery_refinement(&attempts, &recipe, &source, &reads).await;
    let mut frame_cases = Vec::new();
    for (command, accepted) in [
        (
            json!({"command": "recover", "source_operation": "source-1"}),
            true,
        ),
        (
            json!({"command": "recovery-record", "source_operation": "source-1", "acquisition_operation": "read-1"}),
            true,
        ),
        (
            json!({"command": "reobserve", "operation_id": "source-1"}),
            false,
        ),
        (
            json!({"command": "recover", "source_operation": "source-1", "url": "https://untrusted.example/"}),
            false,
        ),
        (
            json!({"command": "recovery-record", "source_operation": "source-1", "acquisition_operation": "read-1", "evidence": "synthetic"}),
            false,
        ),
    ] {
        let mut frame = command;
        frame["schema"] = json!(crate::admin::ADMIN_REQUEST_SCHEMA);
        let bytes = serde_json::to_vec(&frame).expect("admin frame");
        assert_eq!(crate::admin::parse_admin_request(&bytes).is_ok(), accepted);
        frame_cases.push(json!({"frame": frame, "accepted": accepted}));
    }
    corpus["admin_frames"] = json!(frame_cases);
    let frame = crate::app::AppSubmission {
        schema: crate::app::APP_REQUEST_SCHEMA.to_owned(),
        proof_b64: Base64UrlUnpadded::encode_string(&original.proof),
        action_b64: Base64UrlUnpadded::encode_string(&original.action),
        approval_b64: Base64UrlUnpadded::encode_string(
            &original_approval.to_private_bytes().expect("approval"),
        ),
    };
    let decoded = frame.decode().expect("bounded shared input decoder");
    assert_eq!(&*decoded.proof, &original.proof);
    assert_eq!(&*decoded.action, &original.action);
    assert_eq!(
        decoded.approval.to_private_bytes().expect("approval"),
        original_approval.to_private_bytes().expect("approval")
    );
    corpus["shared_native_submission_decoder"] =
        json!("bounded data only; no authority from decoding");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/recovery-refinement.json");
    let bytes = serde_json::to_vec_pretty(&corpus).expect("refinement corpus");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("write refinement corpus");
    }
    assert_eq!(std::fs::read(path).expect("refinement corpus"), bytes);
}

/// Real file-journal race and restart evidence. Both source and read entry use
/// a test validation oracle, and the response is synthetic; no installed
/// credential, real provider call or source observation is claimed.
#[allow(
    clippy::too_many_lines,
    reason = "one bounded native journal history produces the corpus"
)]
async fn exercise_recovery_journal(
    attempts: &crate::GatewayAttempts,
    path: &std::path::Path,
    policy: EffectPolicy,
    reads: Vec<std::sync::Arc<crate::effect::ApprovedEffect>>,
) -> Value {
    use crate::{AcquisitionClaim, AcquisitionStage};
    use std::sync::Arc;
    let first = Arc::clone(&reads[0]);
    let AcquisitionClaim::Reserved(reserved) = attempts
        .claim_recovery(
            &first,
            NOW + 2,
            crate::entry::EntryValidation::Oracle { now: NOW + 2 },
        )
        .await
        .expect("reserve read")
    else {
        panic!("reserved read");
    };
    let reserved_view = reserved.snapshot().expect("snapshot");
    assert_eq!(reserved_view.stage, AcquisitionStage::Reserved);
    assert_eq!(reserved_view.reserved_calls, 1);
    let AcquisitionClaim::Reserved(stale) = attempts
        .claim_recovery(
            &first,
            NOW + 2,
            crate::entry::EntryValidation::Oracle { now: NOW + 2 },
        )
        .await
        .expect("reopen equal read")
    else {
        panic!("reopened read");
    };
    assert_eq!(stale.snapshot().expect("snapshot"), reserved_view);
    let (granted, permit) = reserved
        .grant_entry(
            Arc::clone(&first),
            crate::entry::EntryValidation::Oracle { now: NOW + 3 },
            NOW + 2,
        )
        .await
        .expect("unique read grant");
    assert!(
        matches!(permit.request(), crate::store::AcquisitionRequest::Recovery(read) if read.url().starts_with("https://"))
    );
    drop(permit);
    drop(granted);
    assert!(
        stale
            .grant_entry(
                Arc::clone(&first),
                crate::entry::EntryValidation::Oracle { now: NOW + 3 },
                NOW + 2
            )
            .await
            .is_err()
    );
    let reopened = crate::GatewayAttempts::new(
        Arc::new(crate::FileGatewayAttemptStore::open(path).expect("reopened file store")),
        policy,
    )
    .expect("attempt owner");
    let AcquisitionClaim::Existing(replay) = reopened
        .claim_recovery(
            &first,
            NOW + 3,
            crate::entry::EntryValidation::Oracle { now: NOW + 3 },
        )
        .await
        .expect("replay after permit loss")
    else {
        panic!("history only");
    };
    assert_eq!(replay.stage, AcquisitionStage::Unknown);
    assert_eq!(replay.revision, 2);
    assert_eq!(replay.reserved_calls, 1);
    assert_eq!(replay.reserved_bytes, reserved_view.reserved_bytes);
    assert_eq!(
        reopened
            .sweep_expired(NOW + 864_000, 1024)
            .await
            .expect("sweep"),
        0
    );
    let mut tasks = tokio::task::JoinSet::new();
    for (index, approved) in reads.iter().enumerate().skip(1) {
        let approved = Arc::clone(approved);
        let attempts = reopened.clone();
        tasks.spawn(async move {
            (
                index,
                attempts
                    .claim_recovery(
                        &approved,
                        NOW + 2,
                        crate::entry::EntryValidation::Oracle { now: NOW + 2 },
                    )
                    .await
                    .expect("race admission"),
            )
        });
    }
    let mut winners = Vec::new();
    let mut exhausted = 0;
    while let Some(result) = tasks.join_next().await {
        let (index, claim) = result.expect("joined race");
        match claim {
            AcquisitionClaim::Reserved(reserved) => winners.push((index, reserved)),
            AcquisitionClaim::Existing(snapshot) => {
                assert_eq!(snapshot.stage, AcquisitionStage::NotEntered);
                assert_eq!(snapshot.reserved_calls, 0);
                assert_eq!(snapshot.reserved_bytes, 0);
                exhausted += 1;
            }
        }
    }
    assert_eq!(winners.len(), 15);
    assert_eq!(exhausted, 1);
    winners.sort_by_key(|(index, _)| *index);
    let (index, reserved) = winners.remove(0);
    let (granted, permit) = reserved
        .grant_entry(
            Arc::clone(&reads[index]),
            crate::entry::EntryValidation::Oracle { now: NOW + 3 },
            NOW + 2,
        )
        .await
        .expect("response case grant");
    drop(permit);
    let response = granted
        .record_response(200, true, b"{}", NOW + 4)
        .await
        .expect("synthetic response record");
    assert_eq!(response.stage, AcquisitionStage::ResponseRecorded);
    assert_eq!(response.response_bytes, Some(2));
    assert_eq!(response.reserved_calls, 1);
    assert_eq!(response.reserved_bytes, reserved_view.reserved_bytes);
    let AcquisitionClaim::Existing(history) = reopened
        .claim_recovery(
            &reads[index],
            NOW + 4,
            crate::entry::EntryValidation::Oracle { now: NOW + 4 },
        )
        .await
        .expect("response replay")
    else {
        panic!("response history only");
    };
    assert_eq!(history, response);
    let mut retained_calls = 0;
    let mut retained_bytes = 0;
    for approved in &reads {
        let snapshot = reopened
            .read_acquisition(approved)
            .await
            .expect("read history")
            .expect("record");
        retained_calls += snapshot.reserved_calls;
        retained_bytes += snapshot.reserved_bytes;
    }
    assert_eq!(retained_calls, 16);
    assert_eq!(retained_bytes, 16 * reserved_view.reserved_bytes);
    let stages = reopened.stages(64).await.expect("mixed journal projection");
    let mutation_count = stages
        .iter()
        .filter(|(_, stage)| matches!(stage, crate::GatewayOperationStage::Mutation(_)))
        .count();
    let acquisition_count = stages
        .iter()
        .filter(|(_, stage)| matches!(stage, crate::GatewayOperationStage::Acquisition(_)))
        .count();
    assert_eq!((mutation_count, acquisition_count), (1, 17));
    assert!(!stages.iter().any(|(_, stage)| matches!(
        stage,
        crate::GatewayOperationStage::Acquisition(AcquisitionStage::EntryGranted)
    )));
    json!({
        "schema": "auths.recovery-entry-fixture/1",
        "scope": "native read proofs and file journal; synthetic entry validation and response; no provider or installed-authority claim",
        "admission": {"calls": 1, "bytes": reserved_view.reserved_bytes, "reopen_does_not_charge": true},
        "permit_loss": {"stage": "unknown", "revision": replay.revision, "stale_grant_refused": true},
        "race": {"remaining_capacity": 15, "contenders": 16, "winners": 15, "exhausted": exhausted},
        "retention": {"calls": retained_calls, "bytes": retained_bytes, "sweep_removed": 0},
        "response": {"stage": "response-recorded", "revision": response.revision, "received_bytes": 2, "replay_preserves_facts": true},
        "source_journal_unchanged": true,
        "mixed_projection": {"mutations": mutation_count, "acquisitions": acquisition_count, "grants_project_unknown": true},
    })
}

/// Signed read effects and durable file records with synthetic provider bodies.
/// No installed authority, network or `PostgreSQL` claim is made by this corpus.
#[allow(
    clippy::too_many_lines,
    reason = "one native evidence history and its refusal matrix"
)]
async fn exercise_recovery_refinement(
    attempts: &crate::GatewayAttempts,
    recipe: &CompiledRecipe,
    source: &std::sync::Arc<crate::effect::ApprovedEffect>,
    reads: &[std::sync::Arc<crate::effect::ApprovedEffect>],
) -> Value {
    use crate::{AcquisitionClaim, AcquisitionStage, RecoveryDisposition as D};
    use std::sync::Arc;
    let source_operation = LogicalOperationId::parse("source-1").expect("source operation");
    let namespace = recipe.namespace();
    let before = attempts
        .read(namespace, &source_operation)
        .await
        .expect("source")
        .expect("record");
    let token = crate::echo_token(namespace, &source_operation, before.action_commitment());
    let matched =
        serde_json::to_vec(&json!({"fields": {"DemoStatus": "Approved", "auths_echo": token}, "private_note": "synthetic-recovery-content-canary"}))
            .expect("body");
    let cases = vec![
        ("http-error", 503, true, matched.clone(), D::ResponseUnusable),
        ("wrong-version", 200, false, matched.clone(), D::ResponseUnusable),
        ("missing-field", 200, true, b"{}".to_vec(), D::ResponseUnusable),
        ("malformed-json", 200, true, b"{".to_vec(), D::ResponseUnusable),
        ("multiple-records", 200, true, b"[{\"fields\":{\"DemoStatus\":\"Approved\"}},{\"fields\":{\"DemoStatus\":\"Approved\"}}]".to_vec(), D::ResponseUnusable),
        ("duplicate-members", 200, true, format!("{{\"fields\":{{\"DemoStatus\":\"Pending\",\"DemoStatus\":\"Approved\",\"auths_echo\":\"{token}\"}}}}").into_bytes(), D::ResponseUnusable),
        ("state-match-without-echo", 200, true, b"{\"fields\":{\"DemoStatus\":\"Approved\"}}".to_vec(), D::Inconclusive),
        ("unrelated-echo", 200, true, b"{\"fields\":{\"DemoStatus\":\"Approved\",\"auths_echo\":\"unrelated\"}}".to_vec(), D::Inconclusive),
        ("wrong-value", 200, true, serde_json::to_vec(&json!({"fields": {"DemoStatus": "Pending", "auths_echo": token}})).expect("body"), D::Inconclusive),
        ("exact-linked-evidence", 200, true, matched.clone(), D::Recorded),
    ];
    let clock = Arc::new(crate::FixedClock::at(NOW + 4));
    let gate = Arc::new(crate::QualificationGate::new(
        crate::QualificationPolicy::Optional,
        None,
        None,
        Box::new(Arc::clone(&clock)),
        auths_recipe_qualification::VerifierState::default(),
    ));
    let mut available = Vec::new();
    for read in reads {
        if attempts
            .read_acquisition(read)
            .await
            .expect("read")
            .expect("record")
            .stage
            == AcquisitionStage::Reserved
        {
            available.push(Arc::clone(read));
        }
    }
    assert!(available.len() >= cases.len());
    let incomplete = LogicalOperationId::parse(reads[0].effect().binding().journal_identity().1)
        .expect("operation");
    let unknown = attempts
        .refine_recovery(
            namespace,
            &source_operation,
            &incomplete,
            *recipe.digest(),
            Arc::clone(&gate),
        )
        .await
        .expect("incomplete history");
    assert_eq!(unknown.disposition, D::AcquisitionIncomplete);
    assert_eq!(unknown.source, before);
    assert_eq!(unknown.budget.retained_attempts, 16);
    assert_eq!(
        unknown.report().escalation,
        crate::RecoveryEscalation::CapacityExhausted
    );
    assert_eq!(unknown.acquisition_received_at, None);
    let mut outcomes = Vec::new();
    for ((name, status, version_ok, body, expected), read) in cases.into_iter().zip(&available) {
        let operation = LogicalOperationId::parse(read.effect().binding().journal_identity().1)
            .expect("read operation");
        let AcquisitionClaim::Reserved(reserved) = attempts
            .claim_recovery(
                read,
                NOW + 2,
                crate::entry::EntryValidation::Oracle { now: NOW + 2 },
            )
            .await
            .expect("resume")
        else {
            panic!("reservation");
        };
        let (granted, permit) = reserved
            .grant_entry(
                Arc::clone(read),
                crate::entry::EntryValidation::Oracle { now: NOW + 3 },
                NOW + 2,
            )
            .await
            .expect("grant");
        drop(permit);
        granted
            .record_response(status, version_ok, &body, NOW + 4)
            .await
            .expect("synthetic response");
        assert!(
            attempts
                .refine_recovery(
                    namespace,
                    &source_operation,
                    &operation,
                    [255; 32],
                    Arc::clone(&gate)
                )
                .await
                .is_err(),
            "wrong recipe"
        );
        if expected == D::Recorded {
            clock.set(NOW + 35);
            let stale = attempts
                .refine_recovery(
                    namespace,
                    &source_operation,
                    &operation,
                    *recipe.digest(),
                    Arc::clone(&gate),
                )
                .await
                .expect("stale history");
            assert_eq!(stale.disposition, D::EvidenceStale);
            assert_eq!(stale.source, before);
            clock.set(NOW + 3);
            let future = attempts
                .refine_recovery(
                    namespace,
                    &source_operation,
                    &operation,
                    *recipe.digest(),
                    Arc::clone(&gate),
                )
                .await
                .expect("future history");
            assert_eq!(future.disposition, D::EvidenceStale);
            assert_eq!(future.source, before);
            clock.set(NOW + 34);
        }
        let refine = || {
            attempts.refine_recovery(
                namespace,
                &source_operation,
                &operation,
                *recipe.digest(),
                Arc::clone(&gate),
            )
        };
        let result = if expected == D::Recorded {
            let (first, second) = tokio::join!(refine(), refine());
            let (first, second) = (
                first.expect("concurrent refinement"),
                second.expect("concurrent refinement"),
            );
            assert_eq!(first.source, second.source);
            let (recorded, replay) = if first.disposition == D::Recorded {
                (first, second)
            } else {
                (second, first)
            };
            assert_eq!(replay.disposition, D::AlreadyRecorded);
            recorded
        } else {
            refine().await.expect("refinement")
        };
        assert_eq!(result.disposition, expected, "{name}");
        assert_eq!(result.acquisition.reserved_calls, 1);
        assert_eq!(result.budget, unknown.budget);
        assert_eq!(result.acquisition_received_at, Some(NOW + 4));
        if expected == D::Recorded {
            assert_eq!(
                result.source.stage(),
                crate::GatewayAttemptStage::ObservedByProvider
            );
            assert_eq!(result.source.revision(), before.revision() + 1);
            assert_eq!(result.source.evaluated_at(), before.evaluated_at());
            assert_eq!(
                result.source.action_commitment(),
                before.action_commitment()
            );
            assert_eq!(result.source.counters(), before.counters());
            assert_eq!(result.source.response_status(), None);
            assert!(result.source.has_recovery_evidence());
            assert_eq!(result.source.recovery_received_at(), Some(NOW + 4));
            assert_eq!(
                result
                    .source
                    .provider_evidence()
                    .expect("evidence")
                    .evidence(),
                matched
            );
            clock.set(NOW + 1000);
            let replay = attempts
                .refine_recovery(
                    namespace,
                    &source_operation,
                    &operation,
                    *recipe.digest(),
                    Arc::clone(&gate),
                )
                .await
                .expect("late history replay");
            assert_eq!(replay.disposition, D::AlreadyRecorded);
            assert_eq!(replay.source, result.source);
            assert_eq!(replay.acquisition, result.acquisition);
            let retained = attempts
                .retained_recovery_target(namespace, &source_operation, *recipe.digest())
                .await
                .expect("terminal contract remains available for replay");
            assert!(
                read.recovery_plan()
                    .expect("approved plan")
                    .matches_target(&retained)
                    .expect("retained target")
            );
            assert!(
                matches!(
                    attempts
                        .claim_recovery(
                            read,
                            NOW + 4,
                            crate::entry::EntryValidation::Oracle { now: NOW + 4 }
                        )
                        .await
                        .expect("read replay"),
                    AcquisitionClaim::Existing(_)
                ),
                "terminal read cannot grant again"
            );
            assert!(
                matches!(
                    attempts
                        .claim_bounded(
                            source,
                            NOW,
                            crate::entry::EntryValidation::Oracle { now: NOW }
                        )
                        .await,
                    Err(crate::GatewayAttemptError::Replay)
                ),
                "no new mutation admission"
            );
        } else {
            assert_eq!(result.source, before, "unresolved source remains unchanged");
        }
        let report = result.report();
        let report_bytes = serde_json::to_vec(&report).expect("public report");
        let text = std::str::from_utf8(&report_bytes).expect("report UTF-8");
        for private in [
            token.as_str(),
            "Approved",
            "synthetic-recovery-content-canary",
        ] {
            assert!(!text.contains(private), "private data in report");
        }
        assert!(!text.contains(&hex::encode(before.action_commitment())));
        outcomes.push(json!({"case": name, "disposition": result.disposition, "report": report}));
    }
    json!({
        "schema": "auths.recovery-refinement-fixture/1",
        "scope": "native signed effects and real file journal; synthetic entry validation/provider bodies and controlled deployment clock; no installed transport or PostgreSQL claim",
        "cases": outcomes,
        "freshness": {"maximum_age_seconds": 30, "age_31_refused": true, "future_receipt_refused": true, "age_30_recorded": true},
        "history": {"expired_writer_preserved": true, "late_replay_idempotent": true, "receipt_time_unchanged": true, "charges_retained": true, "no_mutation_readmission": true},
        "recipe_substitution_refused": true,
        "concurrent_refinement": "one recorded, one already-recorded, same immutable facts",
        "public_report_excludes_private_content_and_commitments": true,
    })
}

fn connection(recipe: &CompiledRecipe) -> ConnectionRecord {
    connection_account(recipe, [4; 32])
}

fn connection_account(recipe: &CompiledRecipe, account: [u8; 32]) -> ConnectionRecord {
    ConnectionRecord::new(
        ProviderKind::parse("airtable").expect("provider"),
        ConnectionAlias::parse("synthetic").expect("alias"),
        ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").expect("connection ID"),
        SemanticId::parse("auths.gateway-operation/1").expect("contract"),
        SemanticId::parse("auths.gateway-connection-descriptor/1").expect("schema"),
        crate::GatewayConnectionDescriptor::approve(recipe, "Authorization")
            .expect("descriptor")
            .to_bytes()
            .expect("descriptor bytes"),
        account,
        [5; 32],
        std::num::NonZeroU64::MIN,
        ConnectionState::Active,
        vec!["gateway".to_owned()],
        vec![
            ConnectionProfile::new(SemanticId::parse("auths.mcp").expect("profile"), 2)
                .expect("profile"),
        ],
        NOW - 100,
        NOW - 100,
        None,
    )
    .expect("connection")
}

fn assert_compiled_request(
    effect: &crate::effect::BoundEffect,
    expected: &crate::ClosedProviderRequest,
) {
    assert_eq!(
        effect.private_request().expect("mutation request").body(),
        expected.body()
    );
    assert_eq!(
        effect.private_request().expect("mutation request").url(),
        expected.url()
    );
    assert_eq!(
        effect
            .private_request()
            .expect("mutation request")
            .headers(),
        expected.headers()
    );
}

fn assert_effect_fixtures(
    fixture: &[u8],
    policy_bytes: &[u8],
    signing_request: &[u8],
    approval_bytes: &[u8],
) {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/effect-binding.json");
    let policy_path = fixture_path.with_file_name("effect-policy.json");
    let request_path = fixture_path.with_file_name("effect-approval-request.json");
    let approval_path = fixture_path.with_file_name("effect-approval.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").as_deref() == Some(std::ffi::OsStr::new("1")) {
        std::fs::write(&fixture_path, fixture).expect("write native fixture");
        std::fs::write(&policy_path, policy_bytes).expect("write native policy fixture");
        std::fs::write(&request_path, signing_request).expect("write native signing fixture");
        std::fs::write(&approval_path, approval_bytes).expect("write native approval fixture");
    }
    assert_eq!(
        std::fs::read(&approval_path).expect("approval fixture"),
        approval_bytes
    );
    assert_eq!(
        std::fs::read(&policy_path).expect("policy fixture"),
        policy_bytes
    );
    assert_eq!(
        std::fs::read(&request_path).expect("signing fixture"),
        signing_request
    );
    assert_eq!(
        std::fs::read(&fixture_path).expect("native fixture"),
        fixture
    );
}

fn assert_complete_private_review(
    effect: &crate::effect::BoundEffect,
    expected: &crate::ClosedProviderRequest,
) -> (Value, zeroize::Zeroizing<String>) {
    let private_review = effect.private_review().expect("native private review");
    let review_bytes = private_review.to_private_bytes().expect("review JSON");
    let review_json: Value = serde_json::from_slice(&review_bytes).expect("review JSON");
    assert_eq!(
        review_json["effect_id_hex"],
        hex::encode(effect.binding().id().as_bytes())
    );
    assert_eq!(
        review_json["native"]["request"]["body"],
        std::str::from_utf8(expected.body()).expect("body")
    );
    assert_eq!(review_json["native"]["request"]["url"], expected.url());
    assert_eq!(review_json["schema"], "auths.private-effect-review/2");
    assert_eq!(
        review_json["semantic"]["contract"]["schema"],
        "auths.effect-review-contract/1"
    );
    let literal = private_review
        .render_literal("auths.literal-complete-review/1")
        .expect("complete native rendering");
    assert!(literal.is_ascii());
    assert!(
        literal.contains("\\u202e"),
        "bidi controls remain escaped data"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&literal).expect("literal JSON"),
        review_json
    );
    assert!(
        private_review
            .render_literal("truncate-to-summary/1")
            .is_err()
    );
    assert!(!format!("{private_review:?}").contains("private-sentinel"));
    (review_json, literal)
}

#[test]
fn native_compilation_approval_and_reverification_keep_exact_request() {
    let root = signer(h::ROOT_SEED);
    let agent = signer(0x22);
    let observer = signer(h::OBSERVER_SEED);
    let recipe = recipe(
        &json!({
            "replacement": {"kind": "string", "minimum": 1, "maximum": 64}
        }),
        &Value::Null,
    );
    let context = context(&root, &observer.principal, None);
    let connection = connection(&recipe);
    let arguments = json!({
        "operation_id": "bound-native-1", "operator_namespace": NAMESPACE,
        "recipe_digest": recipe.digest_hex(), "record_id": RECORD,
        "replacement": "private-sentinel-\u{202e}<tag>Approved"
    })
    .as_object()
    .expect("arguments")
    .clone();
    let grant = grant(&root, &agent, None);
    let submission = submission(&root, &agent, &grant, &arguments, &[]);
    let key = SigningKey::from_bytes(&[29; 32]);
    let public = key.verifying_key().to_bytes();
    let policy = EffectPolicy::new("synthetic-partition".to_owned(), 1, public)
        .expect("installed effect policy");
    let policy_bytes = policy.to_private_bytes().expect("policy bytes");
    assert_eq!(
        EffectPolicy::from_private_bytes(&policy_bytes).expect("policy"),
        policy
    );
    let installed = policy.installation(
        &recipe,
        &context,
        &connection,
        crate::QualificationPolicy::Optional,
        [12; 32],
    );
    let effect = compile_mutation_effect(&installed, NOW, &submission.proof, &submission.action)
        .expect("native effect");
    let later = compile_mutation_effect(&installed, NOW + 1, &submission.proof, &submission.action)
        .expect("fresh native effect");
    assert_eq!(
        effect.binding(),
        later.binding(),
        "evaluation time is not signed event time"
    );
    let expected = recipe
        .closed_request_from_arguments(&arguments, submission.commitment)
        .expect("compiler output");
    assert_compiled_request(&effect, &expected);
    let bytes = effect.binding().to_private_bytes().expect("binding bytes");
    let (review_json, literal) = assert_complete_private_review(&effect, &expected);
    let (approval, signing_request) = assert_bound_approval(&effect, &bytes, &key);
    let frame = crate::app::AppSubmission {
        schema: crate::app::APP_REQUEST_SCHEMA.to_owned(),
        proof_b64: base64ct::Base64UrlUnpadded::encode_string(&submission.proof),
        action_b64: base64ct::Base64UrlUnpadded::encode_string(&submission.action),
        approval_b64: base64ct::Base64UrlUnpadded::encode_string(
            &approval.to_private_bytes().expect("approval"),
        ),
    };
    let fixture = serde_json::to_vec_pretty(&json!({
        "schema": "auths.effect-fixture/2",
        "private_review": review_json,
        "literal_review": literal.as_str(),
        "scope": "native compilation and exact approval; no entry or durability claim",
        "effect_id_hex": hex::encode(effect.binding().id().as_bytes()),
        "operation_key_hex": hex::encode(crate::GatewayAttemptKey::for_operation(&policy, expected.namespace(), expected.operation_id()).expect("native replay key").as_bytes()),
        "binding_canonical": std::str::from_utf8(&bytes).expect("binding UTF-8"),
        "approval_canonical": std::str::from_utf8(&approval.to_private_bytes().expect("approval bytes")).expect("approval UTF-8"),
        "approver_public_key_hex": hex::encode(public),
        "request_method": expected.method().as_str(),
        "request_url": expected.url(),
        "request_body": std::str::from_utf8(expected.body()).expect("request UTF-8"),
        "evaluated_at": NOW,
        "approval_expires_at": NOW + 30,
        "submission_frame_canonical": String::from_utf8(serde_json_canonicalizer::to_vec(&frame).expect("native frame")).expect("UTF-8"),
    })).expect("fixture JSON");
    assert_effect_fixtures(
        &fixture,
        &policy_bytes,
        &signing_request,
        &approval.to_private_bytes().expect("approval bytes"),
    );
    assert_approval_entry(
        effect,
        later,
        &installed,
        &key,
        approval,
        &expected,
        (&submission.proof, &submission.action),
    );
}

fn assert_approval_entry(
    effect: crate::effect::BoundEffect,
    later: crate::effect::BoundEffect,
    installed: &EffectInstallation<'_>,
    key: &SigningKey,
    approval: crate::effect::ExactEffectApproval,
    expected: &crate::ClosedProviderRequest,
    submission: (&[u8], &[u8]),
) {
    let public = key.verifying_key().to_bytes();
    let approved = effect
        .approve(approval.clone(), &public, NOW)
        .expect("exact approval");
    assert_eq!(
        approved
            .effect()
            .private_request()
            .expect("mutation request")
            .body(),
        expected.body()
    );
    assert!(approved.validate_approval(&public, NOW + 29).is_ok());
    assert!(approved.validate_approval(&public, NOW + 30).is_err());
    assert!(approved.validate_for_entry(installed, NOW + 29).is_ok());
    assert!(approved.validate_for_entry(installed, NOW + 30).is_err());
    let late_request = later
        .approval_request(NOW + 3_570, NOW + 3_605)
        .expect("approval spanning native action expiry");
    let late_signature = key
        .sign(&late_request.signing_message().expect("message"))
        .to_bytes();
    let late = later
        .approve(
            late_request.with_signature(late_signature),
            &public,
            NOW + 3_570,
        )
        .expect("late approval");
    assert!(late.validate_for_entry(installed, NOW + 3_599).is_ok());
    assert!(late.validate_approval(&public, NOW + 3_601).is_ok());
    assert!(
        late.validate_for_entry(installed, NOW + 3_601).is_err(),
        "a current human approval must not revive expired native resource authority"
    );
    let changed_installation = EffectInstallation {
        epoch: 2,
        ..*installed
    };
    let changed = compile_mutation_effect(&changed_installation, NOW, submission.0, submission.1)
        .expect("changed epoch");
    assert!(changed.approve(approval, &public, NOW).is_err());
    assert!(compile_mutation_effect(&changed_installation, NOW, &[], submission.1).is_err());
}

fn assert_bound_approval(
    effect: &crate::effect::BoundEffect,
    bytes: &[u8],
    key: &SigningKey,
) -> (
    crate::effect::ExactEffectApproval,
    zeroize::Zeroizing<Vec<u8>>,
) {
    assert_eq!(
        &EffectBinding::from_private_bytes(bytes).expect("binding data"),
        effect.binding()
    );
    assert!(
        !String::from_utf8(bytes.to_vec())
            .expect("json")
            .contains("private-sentinel")
    );
    assert!(!format!("{effect:?}").contains("private-sentinel"));
    let review = effect.approval_request(NOW, NOW + 30).expect("review");
    let signature = key
        .sign(&review.signing_message().expect("native message"))
        .to_bytes();
    let signing_request = review
        .to_private_bytes()
        .expect("canonical signing request");
    assert_eq!(
        crate::effect::EffectApprovalRequest::from_private_bytes(&signing_request)
            .expect("signing data"),
        review
    );
    let approval = review.with_signature(signature);
    (approval, signing_request)
}
