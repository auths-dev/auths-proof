//! Native candidate compilation corpus; no candidate publication/entry claim.
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
            .approval_request(NOW, NOW + 30)
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
        assert!(approved.validate_for_entry(&installed, NOW + 31).is_err());
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
        cases.push(json!({"case": case, "review": review, "binding_canonical": std::str::from_utf8(&binding).expect("UTF-8"),
            "substitutions_refused": refused, "native_reverification": "same effect; altered connection and expired approval refused",
            "admission": "mutation, recovery and orphan child refused; candidate runtime not implemented",
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
}
