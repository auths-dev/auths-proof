//! Recovery credential prerequisites share mutation's journal and predicates.
//! File histories use oracle entry; native evidence evaluation is tested apart.
use super::*;
use crate::effect::{ApprovedEffect, PrerequisiteKind, compile_recovery_acquisition};
use crate::entry::EntryValidation::Oracle;
use crate::store::BoundedClaim;
use crate::{AcquisitionClaim, AcquisitionStage, GatewayAttempts};
use std::sync::Arc;

#[allow(
    clippy::too_many_lines,
    reason = "one native recovery/child history emits a bounded evidence corpus"
)]
pub(super) async fn fixture(
    source: &Arc<ApprovedEffect>,
    installed: &EffectInstallation<'_>,
    policy: &EffectPolicy,
    root: &Signer,
) {
    let key = SigningKey::from_bytes(&[29; 32]);
    let public = key.verifying_key().to_bytes();
    let reader = signer(0x33);
    let observer = signer(h::OBSERVER_SEED);
    let mut cases = Vec::new();
    for history in [
        "recorded",
        "missing",
        "lost-permit",
        "stale",
        "wrong-account",
        "excess-capability",
    ] {
        let directory = tempfile::tempdir().expect("directory");
        let path = std::fs::canonicalize(directory.path())
            .expect("canonical")
            .join("journal");
        let attempts = GatewayAttempts::new(
            Arc::new(crate::FileGatewayAttemptStore::open(&path).expect("store")),
            policy.clone(),
        )
        .expect("attempts");
        let BoundedClaim::Claimed(parent) = attempts
            .claim_bounded(source, NOW, Oracle { now: NOW })
            .await
            .expect("source claim")
        else {
            panic!("source");
        };
        // Establish a response-recorded source using the existing mutation fixture's
        // explicit-time entry oracle. These synthetic bodies do not establish
        // that an installed mutation could pass its prerequisite predicates.
        for plan in source.prerequisite_plans().expect("source plan") {
            let kind = plan.kind().expect("kind");
            let AcquisitionClaim::Reserved(child) = attempts
                .claim_prerequisite(source, kind, NOW, Oracle { now: NOW })
                .await
                .expect("source child")
            else {
                panic!("child");
            };
            let (granted, permit) = child
                .grant_entry(source.clone(), Oracle { now: NOW }, NOW)
                .await
                .expect("source child grant");
            drop(permit);
            granted
                .record_response(200, true, b"{}", NOW)
                .await
                .expect("source response");
        }
        let (granted_source, permit) = parent
            .grant_entry(
                source.clone(),
                Oracle { now: NOW },
                NOW,
                &crate::GatewayPreEntry::default(),
            )
            .await
            .expect("source grant");
        drop(permit);
        let body = b"{\"id\":\"re_SYNTHETIC074\"}";
        let locator = source
            .command()
            .expect("mutation")
            .request
            .observation_template()
            .expect("observation template")
            .extract_locator(body)
            .expect("source locator");
        use sha2::Digest as _;
        granted_source
            .record_response(200, sha2::Sha256::digest(body).into(), Some(locator))
            .await
            .expect("synthetic recorded source response");
        let source_operation =
            LogicalOperationId::parse(source.effect().binding().journal_identity().1)
                .expect("source operation");
        let target = attempts
            .retained_recovery_target(
                installed.recipe.namespace(),
                &source_operation,
                *installed.recipe.digest(),
            )
            .await
            .expect("target");
        let call = target
            .authorization_call(
                installed.recipe,
                &LogicalOperationId::parse("recovery-with-checks").expect("operation"),
            )
            .expect("call");
        let context = h::context_for_tool(root, &observer.principal, NOW, &call).expect("trust");
        let grant = h::grant_for_tool(
            root,
            &reader.principal,
            None,
            window(NOW - 3_600, NOW + 3_600),
            &call,
        )
        .expect("read grant");
        let submission = submission_for_call(root, &reader, &grant, &call, &[]);
        let read_installation = policy.installation(
            installed.recipe,
            &context,
            installed.connection,
            crate::QualificationPolicy::Optional,
            [12; 32],
        );
        let effect = compile_recovery_acquisition(
            &read_installation,
            &target,
            NOW + 1,
            &submission.proof,
            &submission.action,
        )
        .expect("recovery compilation despite mutation spend-sum requirement");
        let review: Value = serde_json::from_slice(
            &effect
                .private_review()
                .expect("review")
                .to_private_bytes()
                .expect("bytes"),
        )
        .expect("JSON");
        let declarations = &review["semantic"]["prerequisite_acquisitions"];
        assert_eq!(declarations.as_array().expect("declarations").len(), 3);
        assert_eq!(declarations[0]["purpose"]["kind"], "account");
        assert_eq!(declarations[1]["purpose"]["kind"], "denied-capability");
        assert_eq!(declarations[2]["purpose"]["index"], 1);
        assert!(
            !declarations.to_string().contains("/balance"),
            "onboarding probe remains separate"
        );
        let request = effect
            .approval_request(NOW + 1, NOW + 100)
            .expect("request");
        let signature = key
            .sign(&request.signing_message().expect("message"))
            .to_bytes();
        let approved = Arc::new(
            effect
                .approve(request.with_signature(signature), &public, NOW + 1)
                .expect("approval"),
        );
        approved
            .validate_for_entry(&read_installation, NOW + 2)
            .expect("fresh native recompile");
        let plans = approved.prerequisite_plans().expect("plans");
        assert!(
            attempts
                .claim_prerequisite(
                    &approved,
                    PrerequisiteKind::Account,
                    NOW + 1,
                    Oracle { now: NOW + 1 }
                )
                .await
                .is_err(),
            "child needs admitted recovery parent"
        );
        let AcquisitionClaim::Reserved(parent) = attempts
            .claim_recovery(&approved, NOW + 1, Oracle { now: NOW + 1 })
            .await
            .expect("recovery admission")
        else {
            panic!("recovery parent");
        };
        let mut children = Vec::new();
        let mut evidence = Vec::new();
        for plan in &plans {
            let kind = plan.kind().expect("purpose");
            let capacity = plan
                .validate(approved.effect().binding())
                .expect("acquisition parent membership");
            assert_eq!(capacity.attempts, 1);
            let mut changed = serde_json::to_value(plan).expect("plan");
            changed["transport_canonical"] = json!("{}");
            let changed: crate::effect::PrerequisitePlan =
                serde_json::from_value(changed).expect("witness");
            assert!(changed.validate(approved.effect().binding()).is_err());
            if history == "missing" {
                continue;
            }
            let AcquisitionClaim::Reserved(child) = attempts
                .claim_prerequisite(&approved, kind, NOW + 1, Oracle { now: NOW + 1 })
                .await
                .expect("child admission")
            else {
                panic!("child reservation");
            };
            let (granted, permit) = child
                .grant_entry(approved.clone(), Oracle { now: NOW + 1 }, NOW + 1)
                .await
                .expect("child grant");
            assert!(matches!(
                permit.request(),
                crate::store::AcquisitionRequest::Prerequisite(_)
            ));
            drop(permit);
            if history == "lost-permit" {
                drop(granted);
            } else {
                let (status, body) = match kind {
                    PrerequisiteKind::Account => (
                        200,
                        if history == "wrong-account" {
                            b"{\"id\":\"acct_OTHER\"}".as_slice()
                        } else {
                            b"{\"id\":\"acct_TESTACCOUNT01\"}".as_slice()
                        },
                    ),
                    PrerequisiteKind::DeniedCapability(_) => (
                        if history == "excess-capability" {
                            200
                        } else {
                            403
                        },
                        b"{}".as_slice(),
                    ),
                    _ => panic!("recovery has only credential prerequisites"),
                };
                granted
                    .record_response(status, true, body, NOW + 2)
                    .await
                    .expect("recorded response");
                evidence.push(
                    attempts
                        .read_prerequisite(&approved, kind, NOW + 3)
                        .await
                        .expect("retained evidence"),
                );
            }
            let AcquisitionClaim::Existing(snapshot) = attempts
                .claim_prerequisite(&approved, kind, NOW + 3, Oracle { now: NOW + 3 })
                .await
                .expect("child replay")
            else {
                panic!("no second child entry");
            };
            assert_eq!(snapshot.reserved_calls, 1);
            assert_eq!(snapshot.reserved_bytes, capacity.maximum_bytes);
            assert_eq!(
                snapshot.policy_count_counters, 0,
                "parent policies are not recharged"
            );
            children.push(snapshot);
        }
        let final_at = if history == "stale" {
            NOW + 32
        } else {
            NOW + 3
        };
        let eligible = crate::entry::validate_prerequisite_evidence(
            &approved,
            &read_installation,
            None,
            &crate::GatewayPreEntry::default(),
            &evidence,
            final_at,
        )
        .is_ok();
        assert_eq!(
            eligible,
            history == "recorded",
            "native credential predicates and freshness: {history}"
        );
        // Oracle entry proves the journal dependency boundary, independently of
        // the actual-purpose predicate exercised above. Do not claim it rejects
        // wrong account/capability bodies without installed validation.
        let grant = parent
            .grant_entry(approved.clone(), Oracle { now: final_at }, final_at)
            .await;
        let membership_eligible = !matches!(history, "missing" | "lost-permit" | "stale");
        assert_eq!(
            grant.is_ok(),
            membership_eligible,
            "journal dependency boundary"
        );
        if let Ok((_, permit)) = grant {
            drop(permit);
        }
        let reopened = GatewayAttempts::new(
            Arc::new(crate::FileGatewayAttemptStore::open(&path).expect("reopen")),
            policy.clone(),
        )
        .expect("attempts");
        let snapshot = reopened
            .read_acquisition(&approved)
            .await
            .expect("history")
            .expect("parent");
        assert_eq!(
            snapshot.stage,
            if membership_eligible {
                AcquisitionStage::Unknown
            } else {
                AcquisitionStage::Reserved
            }
        );
        assert_eq!(snapshot.reserved_calls, 1);
        cases.push(
            json!({"history": history, "native_evidence_eligible": eligible,
            "oracle_journal_grant": membership_eligible, "children": children,
            "reopened_parent": snapshot, "prerequisite_acquisitions": declarations,
            "unadmitted_parent_refused": true, "substituted_membership_witness_refused": true}),
        );
    }
    let bytes = serde_json::to_vec_pretty(&json!({"schema": "auths.recovery-prerequisite-fixture/1", "scope": "native signed recovery compilation and actual credential predicates; file dependency/restart histories use oracle entry; no installed provider/PostgreSQL claim", "cases": cases})).expect("fixture");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/recovery-prerequisites.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("write fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), bytes);
}
