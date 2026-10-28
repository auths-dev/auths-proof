//! Native candidate compilation, acquisition and fenced publication corpus.
use super::*;
use crate::effect::{
    CANDIDATE_CHECK_TOOL, CandidateCredentialTarget, compile_candidate_credential,
};

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one signed candidate corpus and its substitution witnesses"
)]
async fn native_candidate_compilation_fixture_is_current() {
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/hostile-recipes-v2.json"
    ))
    .expect("recipes");
    let root = signer(h::ROOT_SEED);
    let reader = signer(0x33);
    let observer = signer(h::OBSERVER_SEED);
    let key = SigningKey::from_bytes(&[29; 32]);
    let public = key.verifying_key().to_bytes();
    let policy = EffectPolicy::new("synthetic-candidate".to_owned(), 1, public).expect("policy");
    let mut cases = Vec::new();
    let mut journal_cases = Vec::new();
    let mut capacity_cases = Vec::new();
    let capacity_directory = tempfile::tempdir().expect("capacity directory");
    let capacity_store = std::sync::Arc::new(
        crate::FileGatewayAttemptStore::open(
            &std::fs::canonicalize(capacity_directory.path())
                .expect("path")
                .join("journal"),
        )
        .expect("store"),
    );
    let capacity_attempts =
        crate::GatewayAttempts::new(capacity_store, policy.clone()).expect("capacity attempts");
    for case in [
        "first-install",
        "rotation",
        "disabled-rotation",
        "head-final",
        "probe-only",
    ] {
        let mut source = corpus["bases"]["stripe"]["recipe"].clone();
        let lock = &corpus["bases"]["stripe"]["lock"];
        if case == "head-final" {
            source["credential"]["guard"]["denied_reads"][1]["method"] = json!("HEAD");
        }
        if case == "probe-only" {
            source["credential"]["guard"]["probe"]["maximum_response_bytes"] = json!(8192);
            source["credential"]["guard"]
                .as_object_mut()
                .expect("guard")
                .remove("account");
            source["credential"]["guard"]
                .as_object_mut()
                .expect("guard")
                .remove("denied_reads");
        }
        let recipe = CompiledRecipe::compile(
            &serde_json::to_vec(&source).expect("source"),
            &serde_json::to_vec(lock).expect("lock"),
        )
        .expect("recipe");
        for (body, valid) in [
            (br#"{"livemode":false}"#.as_slice(), true),
            (br#"{"livemode":true,"livemode":false}"#.as_slice(), false),
            (br#"{"livemode":true}"#.as_slice(), false),
        ] {
            let evidence = crate::store::PrerequisiteResponse {
                kind: crate::effect::PrerequisiteKind::Probe,
                response: crate::transport::ProviderResponse {
                    status: 200,
                    version_ok: true,
                    body: body.to_vec(),
                },
                observed_at: NOW,
                received_at: NOW,
            };
            assert_eq!(
                crate::entry::validate_credential_evidence(&recipe, [4; 32], &evidence).is_ok(),
                valid
            );
        }
        let initial = connection_account(
            &recipe,
            crate::submit::account_commitment("acct_TESTACCOUNT01"),
        );
        let previous = match case {
            "rotation" => Some(initial.clone()),
            "disabled-rotation" => Some(
                initial
                    .transition_state(ConnectionState::Disabled, NOW - 50)
                    .expect("disable"),
            ),
            _ => None,
        };
        let candidate = previous.as_ref().map_or_else(
            || initial.clone(),
            |previous| {
                previous
                    .rotated(
                        previous.descriptor().to_vec(),
                        *previous.account_commitment(),
                        [6; 32],
                        NOW - 10,
                    )
                    .expect("rotation")
            },
        );
        let target =
            CandidateCredentialTarget::new(&recipe, &candidate, previous.as_ref()).expect("target");
        let proposal = target.to_private_bytes().expect("private proposal");
        let decoded = CandidateCredentialTarget::from_private_bytes(&recipe, &proposal)
            .expect("decode proposal");
        assert!(
            decoded.journal_plan().expect("decoded plan")
                == target.journal_plan().expect("original plan"),
            "private proposal preserves its complete compiled plan"
        );
        assert_eq!(
            decoded.to_private_bytes().expect("canonical roundtrip"),
            proposal
        );
        let proposal_value: Value = serde_json::from_slice(&proposal).expect("proposal JSON");
        let mut invalid_proposals = Vec::new();
        for field in ["schema", "recipe", "candidate", "previous", "extra"] {
            let mut changed = proposal_value.clone();
            changed[field] = json!("invalid");
            assert!(
                CandidateCredentialTarget::from_private_bytes(
                    &recipe,
                    &serde_json_canonicalizer::to_vec(&changed).expect("changed proposal")
                )
                .is_err(),
                "{field}"
            );
            invalid_proposals.push(field);
        }
        let duplicate = format!(
            "{{\"schema\":\"auths.gateway-credential-candidate/1\",{}",
            std::str::from_utf8(&proposal[1..]).expect("UTF-8")
        );
        assert!(
            CandidateCredentialTarget::from_private_bytes(&recipe, duplicate.as_bytes()).is_err()
        );
        let mut padded = proposal.to_vec();
        padded.push(b' ');
        assert!(CandidateCredentialTarget::from_private_bytes(&recipe, &padded).is_err());
        assert!(
            CandidateCredentialTarget::from_private_bytes(
                &recipe,
                &vec![b' '; crate::effect::MAX_EFFECT_BYTES + 1]
            )
            .is_err()
        );
        invalid_proposals.extend(["duplicate", "noncanonical", "oversized"]);
        // All subsequent signed compilation/journal cases use the decoded data.
        let target = decoded;
        let call = target
            .authorization_call(
                &recipe,
                &LogicalOperationId::parse("candidate-1").expect("operation"),
            )
            .expect("call");
        let trust = h::context_for_tool(&root, &observer.principal, NOW, &call).expect("trust");
        let grant = h::grant_for_tool(
            &root,
            &reader.principal,
            None,
            window(NOW - 3_600, NOW + 3_600),
            &call,
        )
        .expect("grant");
        let submission = submission_for_call(&root, &reader, &grant, &call, &[]);
        let installed = policy.installation(
            &recipe,
            &trust,
            &candidate,
            crate::QualificationPolicy::Optional,
            [12; 32],
        );
        let compile = || {
            compile_candidate_credential(
                &installed,
                &target,
                NOW,
                &submission.proof,
                &submission.action,
            )
            .expect("compile")
        };
        let effect = compile();
        assert!(effect.private_request().is_none());
        let review: Value = serde_json::from_slice(
            &effect
                .private_review()
                .expect("review")
                .to_private_bytes()
                .expect("bytes"),
        )
        .expect("JSON");
        assert_eq!(
            review["native"]["actors"],
            json!([reader.principal.as_str()])
        );
        let plan = &review["native"]["candidate"];
        assert_eq!(
            plan["candidate"]["credential_generation"],
            candidate.credential_generation().get()
        );
        assert_eq!(
            plan["candidate"]["state"],
            if case == "disabled-rotation" {
                "disabled"
            } else {
                "active"
            }
        );
        assert_eq!(plan["expected_previous"].is_null(), previous.is_none());
        assert!(
            plan["candidate"]["descriptor"].is_object(),
            "human-readable descriptor"
        );
        if case == "probe-only" {
            assert_eq!(plan["ordered_prerequisites"], json!([]));
            assert_eq!(plan["final_check"]["purpose"]["kind"], "probe");
        } else {
            assert_eq!(
                plan["ordered_prerequisites"]
                    .as_array()
                    .expect("prefix")
                    .len(),
                3
            );
            assert_eq!(plan["ordered_prerequisites"][0]["purpose"]["kind"], "probe");
            assert_eq!(
                plan["ordered_prerequisites"][1]["purpose"]["kind"],
                "account"
            );
            assert_eq!(plan["ordered_prerequisites"][2]["purpose"]["index"], 0);
            assert_eq!(plan["final_check"]["purpose"]["index"], 1);
        }
        assert_eq!(
            review["native"]["method"],
            if case == "head-final" { "HEAD" } else { "GET" }
        );
        let signing = effect
            .approval_request(NOW, NOW + 60)
            .expect("signing request");
        let signature = key
            .sign(&signing.signing_message().expect("message"))
            .to_bytes();
        let approval = signing.with_signature(signature);
        let binding = effect.binding().to_private_bytes().expect("binding");
        assert_eq!(
            EffectBinding::from_private_bytes(&binding).expect("decode"),
            *effect.binding()
        );
        let approved = std::sync::Arc::new(
            effect
                .approve(approval.clone(), &public, NOW)
                .expect("approval"),
        );
        approved
            .validate_for_entry(&installed, NOW + 1)
            .expect("same native recompile");
        assert!(approved.validate_for_entry(&installed, NOW + 61).is_err());
        assert!(approved.command().is_none());
        assert!(approved.recovery_target().is_none());
        assert!(approved.recovery_plan().is_err());
        let children = approved.prerequisite_plans().expect("membership");
        assert_eq!(children.len(), if case == "probe-only" { 0 } else { 3 });
        for child in &children {
            child
                .validate(approved.effect().binding())
                .expect("membership witness");
        }
        // A native-approved candidate must not enter either existing root path.
        let directory = tempfile::tempdir().expect("tempdir");
        let store = std::sync::Arc::new(
            crate::FileGatewayAttemptStore::open(
                &std::fs::canonicalize(directory.path())
                    .expect("canonical")
                    .join("journal"),
            )
            .expect("store"),
        );
        let attempts = crate::GatewayAttempts::new(store, policy.clone()).expect("attempts");
        assert!(
            attempts
                .claim_bounded(
                    &approved,
                    NOW,
                    crate::entry::EntryValidation::Oracle { now: NOW }
                )
                .await
                .is_err()
        );
        assert!(
            attempts
                .claim_recovery(
                    &approved,
                    NOW,
                    crate::entry::EntryValidation::Oracle { now: NOW }
                )
                .await
                .is_err()
        );
        if !children.is_empty() {
            assert!(
                attempts
                    .claim_prerequisite(
                        &approved,
                        crate::effect::PrerequisiteKind::Probe,
                        NOW,
                        crate::entry::EntryValidation::Oracle { now: NOW }
                    )
                    .await
                    .is_err()
            );
        }
        journal_cases.push(
            candidate_journal(
                case,
                &approved,
                &installed,
                &policy,
                &target,
                previous.as_ref(),
            )
            .await,
        );
        if previous.is_none() {
            let call = target
                .authorization_call(
                    &recipe,
                    &LogicalOperationId::parse(&format!("capacity-{case}")).expect("operation"),
                )
                .expect("call");
            let signed = submission_for_call(&root, &reader, &grant, &call, &[]);
            let effect = compile_candidate_credential(
                &installed,
                &target,
                NOW,
                &signed.proof,
                &signed.action,
            )
            .expect("capacity effect");
            let request = effect.approval_request(NOW, NOW + 60).expect("request");
            let signature = key
                .sign(&request.signing_message().expect("message"))
                .to_bytes();
            let approved = std::sync::Arc::new(
                effect
                    .approve(request.with_signature(signature), &public, NOW)
                    .expect("capacity approval"),
            );
            let result = capacity_attempts
                .claim_candidate(
                    &approved,
                    NOW,
                    crate::entry::EntryValidation::Oracle { now: NOW },
                )
                .await;
            if case == "probe-only" {
                assert!(
                    matches!(result, Err(crate::GatewayAttemptError::BindingConflict)),
                    "same credential cannot change its previously allocated byte ceiling"
                );
                assert!(
                    capacity_attempts
                        .read_acquisition(&approved)
                        .await
                        .expect("read")
                        .is_none()
                );
            } else {
                assert!(matches!(result, Ok(crate::AcquisitionClaim::Reserved(_))));
            }
            capacity_cases.push(json!({"case": case, "shared_credential_capacity": if case == "probe-only" { "changed ceiling refused without record" } else { "one retained allocation" }}));
        }
        let mut refused = Vec::new();
        for field in [
            "candidate_connection",
            "expected_previous",
            "read_contract",
            "recipe_digest",
            "maximum_response_bytes",
            "extra",
        ] {
            let mut args = call.arguments().clone();
            args.insert(
                field.to_owned(),
                if field == "maximum_response_bytes" {
                    json!(1)
                } else {
                    json!("substituted")
                },
            );
            let changed = McpToolCall::new(recipe.service(), CANDIDATE_CHECK_TOOL, args)
                .expect("changed call");
            let signed = submission_for_call(&root, &reader, &grant, &changed, &[]);
            assert!(
                compile_candidate_credential(
                    &installed,
                    &target,
                    NOW,
                    &signed.proof,
                    &signed.action
                )
                .is_err(),
                "{field}"
            );
            refused.push(field);
        }
        let next_call = target
            .authorization_call(
                &recipe,
                &LogicalOperationId::parse("candidate-2").expect("operation"),
            )
            .expect("next call");
        let next = submission_for_call(&root, &reader, &grant, &next_call, &[]);
        let next_effect =
            compile_candidate_credential(&installed, &target, NOW, &next.proof, &next.action)
                .expect("independent operation");
        let next_binding: Value =
            serde_json::from_slice(&next_effect.binding().to_private_bytes().expect("binding"))
                .expect("JSON");
        let original_binding: Value = serde_json::from_slice(&binding).expect("JSON");
        assert_eq!(
            original_binding["reservations"], next_binding["reservations"],
            "new operation cannot reset lifetime allowance"
        );
        assert!(
            next_effect.approve(approval, &public, NOW).is_err(),
            "old exact approval cannot authorize next operation"
        );
        let altered = candidate
            .rotated(
                candidate.descriptor().to_vec(),
                *candidate.account_commitment(),
                [7; 32],
                NOW,
            )
            .expect("altered connection");
        let changed_installation = policy.installation(
            &recipe,
            &trust,
            &altered,
            crate::QualificationPolicy::Optional,
            [12; 32],
        );
        assert!(
            approved
                .validate_for_entry(&changed_installation, NOW + 1)
                .is_err()
        );
        if let Some(previous) = &previous {
            assert!(CandidateCredentialTarget::new(&recipe, &candidate, None).is_err());
            let changed_previous = previous
                .transition_state(ConnectionState::Revoked, NOW - 20)
                .expect("revoked");
            assert!(
                CandidateCredentialTarget::new(&recipe, &candidate, Some(&changed_previous))
                    .is_err()
            );
            let changed_account = previous
                .rotated(previous.descriptor().to_vec(), [8; 32], [6; 32], NOW - 10)
                .expect("changed account");
            assert!(
                CandidateCredentialTarget::new(&recipe, &changed_account, Some(previous)).is_err()
            );
            // Retimestamping the same credential changes the target and approval,
            // but cannot reset its stable lifetime charge keys.
            let retimed = previous
                .rotated(
                    previous.descriptor().to_vec(),
                    *previous.account_commitment(),
                    [6; 32],
                    NOW - 9,
                )
                .expect("retimed");
            let retimed_target = CandidateCredentialTarget::new(&recipe, &retimed, Some(previous))
                .expect("retimed target");
            let retimed_call = retimed_target
                .authorization_call(
                    &recipe,
                    &LogicalOperationId::parse("candidate-3").expect("op"),
                )
                .expect("call");
            let retimed_submission =
                submission_for_call(&root, &reader, &grant, &retimed_call, &[]);
            let retimed_installation = policy.installation(
                &recipe,
                &trust,
                &retimed,
                crate::QualificationPolicy::Optional,
                [12; 32],
            );
            let retimed_effect = compile_candidate_credential(
                &retimed_installation,
                &retimed_target,
                NOW,
                &retimed_submission.proof,
                &retimed_submission.action,
            )
            .expect("compile retimed");
            let retimed_binding: Value = serde_json::from_slice(
                &retimed_effect
                    .binding()
                    .to_private_bytes()
                    .expect("binding"),
            )
            .expect("JSON");
            assert_eq!(
                original_binding["reservations"],
                retimed_binding["reservations"]
            );
            assert_ne!(
                original_binding["connection"],
                retimed_binding["connection"]
            );
        }
        // The reserved native name cannot compile as a mutation recipe.
        source["tool"] = json!(CANDIDATE_CHECK_TOOL);
        let mut reserved_lock = lock.clone();
        reserved_lock["tool"] = json!(CANDIDATE_CHECK_TOOL);
        assert!(
            CompiledRecipe::compile(
                &serde_json::to_vec(&source).expect("source"),
                &serde_json::to_vec(&reserved_lock).expect("lock")
            )
            .is_err()
        );
        cases.push(json!({"case": case, "review": review, "candidate_proposal_canonical": std::str::from_utf8(&proposal).expect("UTF-8"), "invalid_proposals_refused": invalid_proposals, "binding_canonical": std::str::from_utf8(&binding).expect("UTF-8"),
            "substitutions_refused": refused, "native_reverification": "same effect; altered connection and expired approval refused",
            "admission": "mutation, recovery and orphan child refused; candidate runtime admission tested separately",
            "same_credential_new_operation_retains_lifetime_reservations": true,
            "probe_predicate": "exact value accepted; wrong value and duplicate member refused" }));
    }
    let no_reads = recipe(&json!({}), &Value::Null);
    assert!(
        CandidateCredentialTarget::new(&no_reads, &connection(&no_reads), None).is_err(),
        "no invented provider read for an offline recipe"
    );
    let fixture = serde_json::to_vec_pretty(&json!({"schema": "auths.candidate-compilation-fixture/1",
        "scope": "native signed compilation, exact approval and existing-route refusal; no candidate transport, custody, publication, installed UI or PostgreSQL claim", "cases": cases })).expect("fixture");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/candidate-compilation.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").as_deref() == Some(std::ffi::OsStr::new("1")) {
        std::fs::write(&path, &fixture).expect("write fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), fixture);
    let fixture = serde_json::to_vec_pretty(&json!({"schema": "auths.candidate-journal-fixture/1", "scope": "native signed authority and actual fenced entry predicates with real file journal; synthetic configuration, clock and provider bodies; includes fenced operator publication; no installed provider, custody or PostgreSQL claim", "cases": journal_cases, "cross_proposal_capacity": capacity_cases})).expect("fixture");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/candidate-journal.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &fixture).expect("write fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), fixture);
}

#[allow(
    clippy::too_many_lines,
    reason = "ordered native fence histories keep state and evidence together"
)]
async fn candidate_journal(
    name: &str,
    approved: &std::sync::Arc<crate::effect::ApprovedEffect>,
    installed: &EffectInstallation<'_>,
    policy: &EffectPolicy,
    target: &CandidateCredentialTarget,
    previous: Option<&ConnectionRecord>,
) -> Value {
    use crate::effect::PrerequisiteKind;
    use std::sync::Arc;
    let mut histories = Vec::new();
    for case in [
        "recorded",
        "lost-main-permit",
        "missing-child",
        "bad-probe",
        "stale-child",
        "changed-before-admission",
        "changed-before-child",
        "changed-before-main",
        "publish-success",
        "publish-bad-final",
        "publish-bad-version",
        "publish-unknown",
        "publish-stale-primary",
        "publish-stale-child",
        "publish-expired-approval",
        "publish-changed-configuration",
        "publish-changed-predecessor",
    ] {
        if matches!(
            case,
            "missing-child"
                | "bad-probe"
                | "stale-child"
                | "changed-before-child"
                | "publish-stale-child"
        ) && approved.prerequisite_plans().expect("plans").is_empty()
        {
            continue;
        }
        let directory = tempfile::tempdir().expect("directory");
        let path = std::fs::canonicalize(directory.path())
            .expect("path")
            .join("journal");
        let store: Arc<dyn crate::GatewayAttemptStore> =
            Arc::new(crate::FileGatewayAttemptStore::open(&path).expect("store"));
        let attempts =
            crate::GatewayAttempts::new(Arc::clone(&store), policy.clone()).expect("attempts");
        let connection = crate::SharedConnection::new(
            Arc::clone(&store),
            target.record().provider_kind().clone(),
            target.record().alias().clone(),
        );
        if let Some(previous) = previous {
            connection.insert(previous).await.expect("predecessor");
        }
        let clock = Arc::new(crate::FixedClock::at(NOW));
        let qualification = Arc::new(crate::QualificationGate::new(
            crate::QualificationPolicy::Optional,
            None,
            None,
            Box::new(Arc::clone(&clock)),
            auths_recipe_qualification::VerifierState::default(),
        ));
        let configuration = crate::configuration::SharedConfiguration::new(
            Arc::clone(&store),
            policy
                .configuration_key(installed.recipe.namespace())
                .expect("key"),
            installed.configuration,
        );
        configuration
            .initialize(&qualification)
            .expect("initialize");
        let validation = || {
            crate::entry::EntryValidation::Installed(Box::new(crate::entry::InstalledEntry {
                recipe: installed.recipe.clone(),
                trust: installed.context.clone(),
                observer: None,
                policy: policy.clone(),
                configuration: configuration.clone(),
                connection: crate::entry::EntryConnection::Candidate(Box::new(target.clone())),
                connection_key: crate::connection_key(
                    target.record().provider_kind(),
                    target.record().alias(),
                ),
                qualification: Arc::clone(&qualification),
                workload: "gateway".to_owned(),
                profile: ConnectionProfile::new(
                    SemanticId::parse("auths.mcp").expect("profile"),
                    2,
                )
                .expect("profile"),
                started: std::time::Instant::now(),
                #[cfg(unix)]
                commissioning: None,
            }))
        };
        if case == "changed-before-admission" {
            change_predecessor(&connection, target, previous).await;
            assert!(
                attempts
                    .claim_candidate(approved, NOW, validation())
                    .await
                    .is_err()
            );
            assert!(
                attempts
                    .read_acquisition(approved)
                    .await
                    .expect("read")
                    .is_none()
            );
            histories.push(json!({"case": case, "claim": "refused", "no_record": true}));
            continue;
        }
        let crate::AcquisitionClaim::Reserved(reserved) = attempts
            .claim_candidate(approved, NOW, validation())
            .await
            .expect("native admission")
        else {
            panic!("reservation");
        };
        let before = reserved.snapshot().expect("snapshot");
        assert_eq!(before.reserved_calls, 1);
        assert!(matches!(
            attempts
                .claim_candidate(approved, NOW, validation())
                .await
                .expect("replay"),
            crate::AcquisitionClaim::Reserved(_)
        ));
        assert_eq!(
            attempts
                .read_acquisition(approved)
                .await
                .expect("read")
                .expect("snapshot"),
            before
        );
        if case == "changed-before-child" {
            change_predecessor(&connection, target, previous).await;
        }
        let mut children = Vec::new();
        for plan in approved.prerequisite_plans().expect("plans") {
            let kind = plan.kind().expect("purpose");
            if case == "missing-child" {
                break;
            }
            let admission = attempts
                .claim_prerequisite(approved, kind, NOW, validation())
                .await;
            if case == "changed-before-child" {
                assert!(admission.is_err());
                break;
            }
            let crate::AcquisitionClaim::Reserved(child) = admission.expect("child admission")
            else {
                panic!("child reservation");
            };
            let (granted, permit) = child
                .grant_entry(Arc::clone(approved), validation(), NOW)
                .await
                .expect("native child entry");
            drop(permit);
            let (status, body) = match kind {
                PrerequisiteKind::Probe if case == "bad-probe" => {
                    (200, br#"{"livemode":true}"#.as_slice())
                }
                PrerequisiteKind::Probe => (200, br#"{"livemode":false}"#.as_slice()),
                PrerequisiteKind::Account => (200, br#"{"id":"acct_TESTACCOUNT01"}"#.as_slice()),
                PrerequisiteKind::DeniedCapability(_) => (403, b"".as_slice()),
                _ => panic!("credential-only checks"),
            };
            children.push(
                granted
                    .record_response(status, true, body, NOW)
                    .await
                    .expect("record child"),
            );
        }
        if case == "changed-before-main" {
            change_predecessor(&connection, target, previous).await;
        }
        let main_time = match case {
            "stale-child" => NOW + 31,
            "publish-stale-child" => NOW + 30,
            _ => NOW,
        };
        clock.set(main_time);
        let granted = reserved
            .grant_entry(Arc::clone(approved), validation(), main_time)
            .await;
        if matches!(
            case,
            "missing-child"
                | "bad-probe"
                | "stale-child"
                | "changed-before-child"
                | "changed-before-main"
        ) {
            assert!(granted.is_err(), "{case}");
        } else {
            let (granted, permit) = granted.expect("native main entry");
            let crate::store::AcquisitionRequest::Prerequisite(request) = permit.request() else {
                panic!("candidate request");
            };
            assert_eq!(
                serde_json::to_value(request).expect("request"),
                serde_json::to_value(target.final_request()).expect("compiled request")
            );
            drop(permit);
            if case == "recorded" || (case.starts_with("publish-") && case != "publish-unknown") {
                let (status, body): (u16, &[u8]) = match target.final_kind() {
                    PrerequisiteKind::Probe => (200, br#"{"livemode":false}"#),
                    PrerequisiteKind::Account => (200, br#"{"id":"acct_TESTACCOUNT01"}"#),
                    PrerequisiteKind::DeniedCapability(_) => (403, b""),
                    _ => panic!("credential final purpose"),
                };
                let (status, body) = if case == "publish-bad-final" {
                    match target.final_kind() {
                        PrerequisiteKind::Probe => (200, br#"{"livemode":true}"#.as_slice()),
                        PrerequisiteKind::Account => (200, br#"{"id":"wrong"}"#.as_slice()),
                        _ => (200, b"".as_slice()),
                    }
                } else {
                    (status, body)
                };
                granted
                    .record_response(status, case != "publish-bad-version", body, main_time)
                    .await
                    .expect("record primary");
            } else {
                drop(granted);
            }
        }
        let snapshot = attempts
            .read_acquisition(approved)
            .await
            .expect("read")
            .expect("snapshot");
        let reopened = crate::GatewayAttempts::new(
            Arc::new(crate::FileGatewayAttemptStore::open(&path).expect("reopen")),
            policy.clone(),
        )
        .expect("attempts");
        assert_eq!(
            reopened
                .read_acquisition(approved)
                .await
                .expect("read reopened")
                .expect("snapshot"),
            snapshot
        );
        if matches!(case, "recorded" | "lost-main-permit") {
            assert!(matches!(
                reopened
                    .claim_candidate(approved, NOW, validation())
                    .await
                    .expect("terminal replay"),
                crate::AcquisitionClaim::Existing(_)
            ));
        }
        let mut publication = Value::Null;
        if case.starts_with("publish-") {
            let publish_time = match case {
                "publish-stale-primary" | "publish-stale-child" => NOW + 31,
                "publish-expired-approval" => NOW + 61,
                _ => NOW,
            };
            clock.set(publish_time);
            if case == "publish-changed-configuration" {
                let changed = crate::configuration::SharedConfiguration::new(
                    Arc::clone(&store),
                    policy
                        .configuration_key(installed.recipe.namespace())
                        .expect("key"),
                    [99; 32],
                );
                changed
                    .activate(
                        configuration.current_revision().expect("revision"),
                        &qualification,
                    )
                    .expect("activate");
            }
            if case == "publish-changed-predecessor" {
                if previous.is_some() {
                    change_predecessor(&connection, target, previous).await;
                } else {
                    let revoked = target
                        .record()
                        .transition_state(ConnectionState::Revoked, NOW)
                        .expect("revoked");
                    connection
                        .insert(&revoked)
                        .await
                        .expect("conflicting installation");
                }
            }
            let connection_key =
                crate::connection_key(target.record().provider_kind(), target.record().alias());
            let before_publish = store
                .load(crate::GatewayRecordKind::Connection, &connection_key)
                .expect("before");
            let result = reopened
                .publish_candidate(Arc::clone(approved), validation(), publish_time)
                .await;
            if case == "publish-success" {
                assert_eq!(
                    result.expect("publish"),
                    crate::CandidatePublication::Published
                );
                let bytes = target.record().to_canonical_cbor().expect("bytes");
                assert_eq!(
                    store
                        .load(crate::GatewayRecordKind::Connection, &connection_key)
                        .expect("after"),
                    Some(bytes.clone())
                );
                // Losing the caller's acknowledgement cannot cause provider I/O,
                // reallocation or evidence renewal on the next explicit action.
                assert_eq!(
                    reopened
                        .publish_candidate(Arc::clone(approved), validation(), publish_time)
                        .await
                        .expect("repeat"),
                    crate::CandidatePublication::AlreadyCurrent
                );
                assert_eq!(
                    store
                        .load(crate::GatewayRecordKind::Connection, &connection_key)
                        .expect("repeat bytes"),
                    Some(bytes)
                );
                publication = json!({"result": "published", "replay": "already-current", "exact_candidate": true});
            } else {
                assert!(result.is_err(), "publication must refuse {name}/{case}");
                assert_eq!(
                    store
                        .load(crate::GatewayRecordKind::Connection, &connection_key)
                        .expect("after"),
                    before_publish
                );
                publication = json!({"result": "refused", "connection_unchanged": true});
            }
            assert_eq!(
                reopened
                    .read_acquisition(approved)
                    .await
                    .expect("unchanged root"),
                Some(snapshot.clone())
            );
        }
        assert_eq!(snapshot.reserved_calls, 1);
        assert_eq!(snapshot.reserved_bytes, before.reserved_bytes);
        histories.push(json!({"case": case, "snapshot": snapshot, "children": children, "publication": publication, "restart_preserves_facts_and_charges": true}));
    }
    json!({"target": name, "histories": histories})
}

async fn change_predecessor(
    connection: &crate::SharedConnection,
    target: &CandidateCredentialTarget,
    previous: Option<&ConnectionRecord>,
) {
    if let Some(previous) = previous {
        let current = connection.load().await.expect("load").expect("previous");
        let revoked = previous
            .transition_state(ConnectionState::Revoked, NOW)
            .expect("revoke");
        connection
            .replace(&current, &revoked)
            .await
            .expect("replace");
    } else {
        connection
            .insert(target.record())
            .await
            .expect("race first publication");
    }
}
