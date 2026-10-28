//! Native signed compilation witnesses for prerequisite acquisition declarations.
//! This fixture does not claim durable acquisition admission or provider entry.

use super::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one signed compilation corpus keeps each declaration and its witness together"
)]
async fn native_prerequisite_compilation_fixture_is_current() {
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/hostile-recipes-v2.json"
    ))
    .expect("recipes");
    let scenarios: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/attempt-scenarios-v3.json"
    ))
    .expect("scenario inputs");
    let root = signer(h::ROOT_SEED);
    let agent = signer(0x22);
    let observer = signer(h::OBSERVER_SEED);
    let key = SigningKey::from_bytes(&[29; 32]);
    let public = key.verifying_key().to_bytes();
    let policy =
        EffectPolicy::new("synthetic-prerequisites".to_owned(), 1, public).expect("policy");
    let mut cases = Vec::new();
    let mut journals = Vec::new();
    for base in ["stripe", "airtable-pre-entry"] {
        let recipe = CompiledRecipe::compile(
            &serde_json::to_vec(&corpus["bases"][base]["recipe"]).expect("source"),
            &serde_json::to_vec(&corpus["bases"][base]["lock"]).expect("lock"),
        )
        .expect("compiled recipe");
        let mut arguments = scenarios["defaults"][base]["arguments"]
            .as_object()
            .expect("arguments")
            .clone();
        arguments.insert(
            "operator_namespace".to_owned(),
            json!(recipe.namespace().as_str()),
        );
        arguments.insert("recipe_digest".to_owned(), json!(recipe.digest_hex()));
        let call = McpToolCall::new(recipe.review().service(), recipe.review().tool(), arguments)
            .expect("call");
        let context = h::context_for_tool(&root, &observer.principal, NOW, &call).expect("trust");
        let connection = connection(&recipe);
        let grant = if base == "stripe" {
            let bound = crate::ArgumentCeilingPolicy::new("amount", 1_000, 3_600, 10)
                .expect("bound")
                .with_sum(
                    10_000,
                    Some(crate::ListedValues::new("currency", &["usd"]).expect("partition")),
                )
                .expect("sum")
                .with_scope(
                    crate::ListedValues::new("connect_account", &["acct_TESTACCOUNT01"])
                        .expect("scope"),
                )
                .expect("scope bound");
            let extension = CriticalExtension::new(
                ExtensionId::parse(auths_registries::BOUNDED_POLICY_COMMITMENT_EXTENSION_V1)
                    .expect("extension ID"),
                bound.extension_body(None).expect("bound extension"),
            )
            .expect("extension");
            let statement = GrantStatement::new(
                root.principal.clone(),
                agent.principal.clone(),
                call.profile_ref().expect("profile"),
                PermissionSet::new(vec![call.permission().expect("permission")])
                    .expect("permissions"),
                window(NOW - 3_600, NOW + 3_600),
                AudienceSet::new(vec![audience()]).expect("audiences"),
                ActionConstraint::AnyBody,
                None,
                0,
                None,
                StatusPolicy::ExpiryOnly,
                AssurancePolicyId::parse(ASSURANCE).expect("assurance"),
                CriticalExtensions::new(vec![extension]).expect("extensions"),
            );
            let descriptor = root.descriptor();
            let signature =
                root.sign(&grant_signing_preimage(&statement, &descriptor).expect("preimage"));
            SignedGrant::new(statement, SignatureEnvelope::new(descriptor, signature))
        } else {
            // Compilation pins all selected native authority. Runtime admission
            // still requires the pre-entry observation requirement; this case
            // demonstrates only request/plan compilation, never entry eligibility.
            h::grant_for_tool(
                &root,
                &agent.principal,
                None,
                window(NOW - 3_600, NOW + 3_600),
                &call,
            )
            .expect("grant")
        };
        let submission = submission_for_call(&root, &agent, &grant, &call, &[]);
        let installed = policy.installation(
            &recipe,
            &context,
            &connection,
            crate::QualificationPolicy::Optional,
            [12; 32],
        );
        let effect =
            compile_mutation_effect(&installed, NOW, &submission.proof, &submission.action)
                .expect("native compilation");
        let review: Value = serde_json::from_slice(
            &effect
                .private_review()
                .expect("review")
                .to_private_bytes()
                .expect("private bytes"),
        )
        .expect("review JSON");
        let plan = review["semantic"]["prerequisite_acquisitions"]
            .as_array()
            .expect("plan");
        assert_eq!(plan.len(), if base == "stripe" { 4 } else { 1 });
        for read in plan {
            assert_eq!(read["maximum_calls"], 1);
            assert_eq!(read["maximum_transport_seconds"], 15);
            assert_eq!(read["maximum_evidence_age_seconds"], 30);
            assert_eq!(read["disclosure"], "none");
            assert!(
                (1..=65_536).contains(
                    &read["request"]["maximum_response_bytes"]
                        .as_u64()
                        .expect("limit")
                )
            );
            assert!(
                !read["request"]["url"]
                    .as_str()
                    .expect("URL")
                    .ends_with("/balance"),
                "onboarding probe is not implicit mutation I/O"
            );
        }
        if base == "stripe" {
            assert_eq!(plan[0]["purpose"]["kind"], "account");
            assert_eq!(
                plan[0]["purpose"]["expected_account_commitment"],
                json!(connection.account_commitment())
            );
            assert_eq!(plan[1]["purpose"]["kind"], "denied-capability");
            assert_eq!(plan[2]["purpose"]["index"], 1);
            assert_eq!(plan[1]["purpose"]["refused_statuses"], json!([403]));
            assert_eq!(plan[3]["purpose"]["kind"], "relative-ceiling");
            assert_eq!(plan[3]["purpose"]["argument"], 500);
            assert_eq!(plan[3]["purpose"]["binds"], json!([["/currency", "usd"]]));
            assert_eq!(
                plan[3]["request"]["url"],
                "https://api.stripe.com/v1/payment_intents/pi_TEST0000000001"
            );
            for read in &plan[..3] {
                assert!(
                    !read["request"]["headers"]
                        .as_array()
                        .expect("headers")
                        .iter()
                        .any(|header| header[0] == "Stripe-Account")
                );
            }
            assert!(
                plan[3]["request"]["headers"]
                    .as_array()
                    .expect("headers")
                    .contains(&json!(["Stripe-Account", "acct_TESTACCOUNT01"]))
            );
        } else {
            assert_eq!(plan[0]["purpose"]["kind"], "pre-entry");
            assert_eq!(
                plan[0]["purpose"]["json_pointers"],
                json!(["/fields/DemoStatus"])
            );
        }
        let mut obsolete: Value =
            serde_json::from_slice(&effect.binding().to_private_bytes().expect("binding"))
                .expect("binding JSON");
        obsolete["compiler"] = json!("auths.gateway-effect-compiler/4");
        assert_eq!(
            EffectBinding::from_private_bytes(
                &serde_json_canonicalizer::to_vec(&obsolete).expect("canonical obsolete binding")
            ),
            Err(crate::effect::EffectBindingError::Unsupported),
        );
        let approval_request = effect
            .approval_request(NOW, NOW + 60)
            .expect("approval request");
        let signature = key
            .sign(&approval_request.signing_message().expect("message"))
            .to_bytes();
        let approval = approval_request.with_signature(signature);
        let approved = effect
            .approve(approval.clone(), &public, NOW)
            .expect("approved exact plan");
        approved
            .validate_for_entry(&installed, NOW + 1)
            .expect("same native compilation and plan");
        let approved = std::sync::Arc::new(approved);
        journals.push(journal_witness(&approved, &policy, base).await);
        cases.push(json!({
            "recipe": base,
            "effect_id_hex": hex::encode(approved.effect().binding().id().as_bytes()),
            "binding_canonical": std::str::from_utf8(&approved.effect().binding().to_private_bytes().expect("binding")).expect("binding UTF-8"),
            "approval_canonical": std::str::from_utf8(&approval.to_private_bytes().expect("approval")).expect("approval UTF-8"),
            "prerequisite_acquisitions": plan,
            "fresh_native_recompilation_preserves_plan": true,
            "previous_compiler_binding_refused": true,
        }));
    }
    let fixture = serde_json::to_vec_pretty(&json!({
        "schema": "auths.prerequisite-compilation-fixture/1",
        "scope": "native signed compilation and exact approval only; no prerequisite admission, permit, provider, disclosure or installed human claim",
        "cases": cases,
    })).expect("fixture");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/prerequisite-compilation.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &fixture).expect("write fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), fixture);
    let journal = serde_json::to_vec_pretty(&json!({
        "schema": "auths.prerequisite-entry-fixture/1",
        "scope": "native signed compilation; real file journal with explicit-time oracle grants and synthetic responses; no provider send or installed authority claim",
        "attempt_schema": "auths.gateway-attempt/9",
        "cases": journals,
    })).expect("journal fixture");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/prerequisite-entry.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &journal).expect("write journal fixture");
    }
    assert_eq!(std::fs::read(path).expect("journal fixture"), journal);
}

async fn journal_witness(
    approved: &std::sync::Arc<crate::effect::ApprovedEffect>,
    policy: &EffectPolicy,
    recipe: &str,
) -> Value {
    use crate::entry::EntryValidation;
    use crate::{AcquisitionClaim, AcquisitionStage, GatewayAttempts};
    use std::sync::Arc;
    let plans = approved.prerequisite_plans().expect("closed plans");
    let mut histories = Vec::new();
    for history in [
        "recorded-response",
        "lost-permit",
        "missing-read",
        "stale-response",
    ] {
        let lose_permit = history == "lost-permit";
        let directory = tempfile::tempdir().expect("directory");
        let path = std::fs::canonicalize(directory.path())
            .expect("canonical directory")
            .join("journal");
        let store = Arc::new(crate::FileGatewayAttemptStore::open(&path).expect("journal"));
        let attempts = GatewayAttempts::new(store, policy.clone()).expect("attempts");
        let crate::store::BoundedClaim::Claimed(parent) = attempts
            .claim_bounded(approved, NOW)
            .await
            .expect("parent claim")
        else {
            panic!("parent reservation")
        };
        let mut snapshots = Vec::new();
        for plan in plans.iter().filter(|_| history != "missing-read") {
            let kind = plan.kind().expect("closed purpose");
            let capacity = plan
                .validate(approved.effect().binding())
                .expect("membership");
            assert_eq!(capacity.attempts, 1);
            let mut corrupted = serde_json::to_value(plan).expect("plan audit");
            corrupted["transport_canonical"] = json!("{}");
            let corrupted: crate::effect::PrerequisitePlan =
                serde_json::from_value(corrupted).expect("audit only");
            assert!(corrupted.validate(approved.effect().binding()).is_err());
            let AcquisitionClaim::Reserved(reserved) = attempts
                .claim_prerequisite(approved, kind, NOW)
                .await
                .expect("read claim")
            else {
                panic!("reserved")
            };
            let AcquisitionClaim::Reserved(stale) = attempts
                .claim_prerequisite(approved, kind, NOW)
                .await
                .expect("equal reservation")
            else {
                panic!("equal reservation")
            };
            assert_eq!(
                reserved.snapshot().expect("snapshot"),
                stale.snapshot().expect("snapshot")
            );
            let (granted, permit) = reserved
                .grant_entry(
                    Arc::clone(approved),
                    EntryValidation::Oracle { now: NOW },
                    NOW,
                )
                .await
                .expect("read grant");
            assert!(matches!(
                permit.request(),
                crate::store::AcquisitionRequest::Prerequisite(_)
            ));
            drop(permit);
            assert!(
                stale
                    .grant_entry(
                        Arc::clone(approved),
                        EntryValidation::Oracle { now: NOW },
                        NOW
                    )
                    .await
                    .is_err()
            );
            if lose_permit {
                drop(granted);
            } else {
                granted
                    .record_response(200, true, b"{}", NOW + 1)
                    .await
                    .expect("retained synthetic response");
                let response = attempts
                    .read_prerequisite(approved, kind, NOW + 2)
                    .await
                    .expect("fresh response");
                assert_eq!(response.received_at, NOW + 1);
                assert_eq!(response.observed_at, NOW);
                assert!(
                    attempts
                        .read_prerequisite(approved, kind, NOW)
                        .await
                        .is_err(),
                    "future response cannot be fresh"
                );
                assert!(
                    attempts
                        .read_prerequisite(approved, kind, NOW + 32)
                        .await
                        .is_err()
                );
            }
            let reopened = GatewayAttempts::new(
                Arc::new(crate::FileGatewayAttemptStore::open(&path).expect("reopen journal")),
                policy.clone(),
            )
            .expect("reopened attempts");
            let AcquisitionClaim::Existing(snapshot) = reopened
                .claim_prerequisite(approved, kind, NOW + 2)
                .await
                .expect("replay")
            else {
                panic!("no second permit")
            };
            assert_eq!(
                snapshot.stage,
                if lose_permit {
                    AcquisitionStage::Unknown
                } else {
                    AcquisitionStage::ResponseRecorded
                }
            );
            assert_eq!(snapshot.reserved_calls, 1);
            assert_eq!(snapshot.reserved_bytes, capacity.maximum_bytes);
            snapshots.push(json!(snapshot));
        }
        let grant = parent
            .grant_entry(
                Arc::clone(approved),
                EntryValidation::Oracle {
                    now: if history == "stale-response" {
                        NOW + 31
                    } else {
                        NOW + 2
                    },
                },
                NOW,
                &crate::GatewayPreEntry::default(),
            )
            .await;
        assert_eq!(grant.is_ok(), history == "recorded-response");
        drop(grant);
        histories.push(
            json!({ "history": history, "lost_read_permits": lose_permit, "reopened_reads": snapshots,
            "second_read_grants": 0, "write_grant": history == "recorded-response", "provider_calls": 0,
            "stale_evidence_refused": !lose_permit }),
        );
    }
    json!({ "recipe": recipe, "histories": histories })
}
