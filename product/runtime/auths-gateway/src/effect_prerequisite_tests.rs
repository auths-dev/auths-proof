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
        let connection = if base == "stripe" {
            connection_account(
                &recipe,
                crate::submit::account_commitment("acct_TESTACCOUNT01"),
            )
        } else {
            connection(&recipe)
        };
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
        if base == "stripe" {
            guard_evidence_fixture(&approved, &installed);
            super::recovery_prerequisite_tests::fixture(&approved, &installed, &policy, &root)
                .await;
        }
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
        "attempt_schema": "auths.gateway-attempt/14",
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
            .claim_bounded(
                approved,
                NOW,
                crate::entry::EntryValidation::Oracle { now: NOW },
            )
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
                .claim_prerequisite(
                    approved,
                    kind,
                    NOW,
                    crate::entry::EntryValidation::Oracle { now: NOW },
                )
                .await
                .expect("read claim")
            else {
                panic!("reserved")
            };
            let AcquisitionClaim::Reserved(stale) = attempts
                .claim_prerequisite(
                    approved,
                    kind,
                    NOW,
                    crate::entry::EntryValidation::Oracle { now: NOW },
                )
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
                .claim_prerequisite(
                    approved,
                    kind,
                    NOW + 2,
                    crate::entry::EntryValidation::Oracle { now: NOW + 2 },
                )
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

/// Exercises the exact evidence predicate called inside the installed writer
/// fence, using native signed authority and signed observations. This corpus
/// does not claim an installed adapter race or provider transport execution.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one signed evidence corpus retains its substitutions together"
)]
fn native_prerequisite_evidence_fixture_is_current() {
    use crate::effect::PrerequisiteKind;
    use crate::store::PrerequisiteResponse;
    use crate::transport::ProviderResponse;
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/hostile-recipes-v2.json"
    ))
    .expect("recipes");
    let scenarios: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/attempt-scenarios-v3.json"
    ))
    .expect("scenarios");
    let recipe = CompiledRecipe::compile(
        &serde_json::to_vec(&corpus["bases"]["airtable-pre-entry"]["recipe"]).expect("recipe"),
        &serde_json::to_vec(&corpus["bases"]["airtable-pre-entry"]["lock"]).expect("lock"),
    )
    .expect("compiled");
    let root = signer(h::ROOT_SEED);
    let agent = signer(0x22);
    let observer = crate::GatewayObserver::from_test_seed(h::OBSERVER_SEED);
    let mut arguments = scenarios["defaults"]["airtable-pre-entry"]["arguments"]
        .as_object()
        .expect("arguments")
        .clone();
    arguments.insert(
        "operator_namespace".to_owned(),
        json!(recipe.namespace().as_str()),
    );
    arguments.insert("recipe_digest".to_owned(), json!(recipe.digest_hex()));
    let call = McpToolCall::new(recipe.service(), recipe.review().tool(), arguments.clone())
        .expect("call");
    let context = h::context_for_tool(&root, observer.principal(), NOW, &call).expect("trust");
    let original = read_back_requirement();
    let requirement = ObservationRequirement::new(
        original.observer_anchor().clone(),
        original.schema().clone(),
        original.subject().clone(),
        2,
        original.conditions().to_vec(),
    )
    .expect("two second requirement");
    let grant = h::grant_for_tool(
        &root,
        &agent.principal,
        Some(requirement),
        window(NOW - 3_600, NOW + 3_600),
        &call,
    )
    .expect("grant");
    let subject = arguments["record_uri"].as_str().expect("subject");
    let expected = arguments["expected"].clone();
    let initial = observer
        .sign(
            READ_BACK_SCHEMA,
            subject,
            NOW,
            crate::observer::read_back_facts(&expected, None).expect("facts"),
        )
        .expect("authority evidence");
    let submission = submission_for_call(&root, &agent, &grant, &call, &[initial.bytes().to_vec()]);
    let key = SigningKey::from_bytes(&[29; 32]);
    let public = key.verifying_key().to_bytes();
    let policy = EffectPolicy::new("prerequisite-evidence".to_owned(), 1, public).expect("policy");
    let connection = connection(&recipe);
    let installed = policy.installation(
        &recipe,
        &context,
        &connection,
        crate::QualificationPolicy::Optional,
        [12; 32],
    );
    let effect = compile_mutation_effect(&installed, NOW, &submission.proof, &submission.action)
        .expect("native effect");
    let signing = effect.approval_request(NOW, NOW + 60).expect("approval");
    let signature = key
        .sign(&signing.signing_message().expect("message"))
        .to_bytes();
    let approved = effect
        .approve(signing.with_signature(signature), &public, NOW)
        .expect("approved");
    let read = approved
        .command()
        .expect("command")
        .request
        .pre_entry_read()
        .expect("pre-entry read");
    let pointers = recipe.pre_entry_pointers().expect("pointers");
    let body = serde_json::to_vec(&json!({"fields": {"DemoStatus": expected}})).expect("body");
    let sign = |body: &[u8], at| {
        crate::pre_entry::sign_observations(&observer, read, pointers, body, at)
            .expect("signed response")
            .into_iter()
            .map(|value| value.bytes)
            .collect::<Vec<_>>()
    };
    let exact = crate::GatewayPreEntry {
        observations: sign(&body, NOW),
        basis: None,
    };
    let mut cases = Vec::new();
    for case in [
        "exact",
        "age-limit",
        "selected-age-exceeded",
        "wrong-facts",
        "condition-false",
        "refreshed-time",
        "wrong-subject",
        "wrong-observer",
        "signature-changed",
        "missing-observation",
        "extra-observation",
        "duplicate-provider-member",
        "wrong-status",
        "wrong-version",
        "unrelated-ceiling-basis",
    ] {
        let mut checkpoint = exact.clone();
        let mut response = ProviderResponse {
            status: 200,
            version_ok: true,
            body: body.clone(),
        };
        let mut at = NOW + 1;
        match case {
            "age-limit" => at = NOW + 2,
            "selected-age-exceeded" => at = NOW + 3,
            "wrong-facts" | "condition-false" => {
                let other = if expected == "Pending" {
                    "Approved"
                } else {
                    "Pending"
                };
                response.body = serde_json::to_vec(&json!({"fields": {"DemoStatus": other}}))
                    .expect("other body");
                if case == "condition-false" {
                    checkpoint.observations = sign(&response.body, NOW);
                }
            }
            "refreshed-time" => checkpoint.observations = sign(&body, NOW + 1),
            "wrong-subject" => {
                checkpoint.observations = vec![
                    observer
                        .sign(
                            READ_BACK_SCHEMA,
                            "https://api.airtable.com/unrelated#field",
                            NOW,
                            crate::observer::read_back_facts(&expected, None).expect("facts"),
                        )
                        .expect("wrong subject signature")
                        .bytes()
                        .to_vec(),
                ]
            }
            "wrong-observer" => {
                checkpoint.observations = vec![
                    crate::GatewayObserver::from_test_seed(77)
                        .sign(
                            READ_BACK_SCHEMA,
                            subject,
                            NOW,
                            crate::observer::read_back_facts(&expected, None).expect("facts"),
                        )
                        .expect("other signature")
                        .bytes()
                        .to_vec(),
                ]
            }
            "signature-changed" => {
                let signed = auths_codec::decode_signed_observation(
                    &checkpoint.observations[0],
                    &VerifierLimits::default(),
                )
                .expect("canonical signature input");
                let mut bytes = signed.signature().signature().as_slice().to_vec();
                bytes[0] ^= 1;
                let substituted = SignedObservation::new(
                    signed.statement().clone(),
                    SignatureEnvelope::new(
                        signed.signature().descriptor().clone(),
                        auths_model::SignatureBytes::new(bytes).expect("signature bytes"),
                    ),
                    signed.evidence().to_vec(),
                )
                .expect("substituted signature");
                checkpoint.observations[0] = auths_codec::encode_signed_observation(&substituted)
                    .expect("canonical invalid signature");
            }
            "missing-observation" => checkpoint.observations.clear(),
            "extra-observation" => checkpoint
                .observations
                .push(checkpoint.observations[0].clone()),
            "duplicate-provider-member" => {
                response.body =
                    br#"{"fields":{"DemoStatus":"Pending","DemoStatus":"Approved"}}"#.to_vec()
            }
            "wrong-status" => response.status = 403,
            "wrong-version" => response.version_ok = false,
            "unrelated-ceiling-basis" => {
                checkpoint.basis = Some(crate::GatewayRelativeBasis {
                    value: 1,
                    response_digest: [0; 32],
                    read_at: NOW,
                })
            }
            _ => {}
        }
        let acquired = [PrerequisiteResponse {
            kind: PrerequisiteKind::PreEntry,
            response,
            observed_at: NOW,
            received_at: NOW + 1,
        }];
        let accepted = crate::entry::validate_prerequisite_evidence(
            &approved,
            &installed,
            Some(observer.principal()),
            &checkpoint,
            &acquired,
            at,
        )
        .is_ok();
        assert_eq!(accepted, matches!(case, "exact" | "age-limit"), "{case}");
        cases.push(json!({"case": case, "accepted": accepted, "evidence_age_seconds": at - NOW}));
    }
    let bytes = serde_json::to_vec_pretty(&json!({
        "schema": "auths.prerequisite-evidence-fixture/1",
        "scope": "native signed authority and observation substitutions against the installed entry predicate; no adapter lock, process, custody or provider execution claim",
        "selected_maximum_age_seconds": 2,
        "acquisition_maximum_age_seconds": 30,
        "cases": cases,
    })).expect("fixture");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/prerequisite-evidence.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("write fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), bytes);
}

#[allow(
    clippy::too_many_lines,
    reason = "one native guard corpus retains exact response and checkpoint substitutions"
)]
fn guard_evidence_fixture(
    approved: &crate::effect::ApprovedEffect,
    installed: &EffectInstallation<'_>,
) {
    use crate::effect::PrerequisiteKind;
    use crate::store::PrerequisiteResponse;
    use crate::transport::ProviderResponse;
    use sha2::{Digest as _, Sha256};
    let mut cases = Vec::new();
    for case in [
        "exact",
        "account-mismatch",
        "duplicate-account",
        "capability-excess",
        "denied-version",
        "currency-mismatch",
        "above-ceiling",
        "wrong-basis",
        "wrong-digest",
        "refreshed-basis-time",
        "missing-basis",
        "duplicate-basis",
        "wrong-order",
        "missing-read",
        "unrelated-observation",
    ] {
        let mut acquired = approved
            .prerequisite_plans()
            .expect("plans")
            .iter()
            .map(|plan| {
                let kind = plan.kind().expect("kind");
                let (status, body) = match kind {
                    PrerequisiteKind::Account => (200, br#"{"id":"acct_TESTACCOUNT01"}"#.to_vec()),
                    PrerequisiteKind::DeniedCapability(_) => (403, Vec::new()),
                    PrerequisiteKind::RelativeCeiling => (
                        200,
                        br#"{"amount_received":1000,"currency":"usd"}"#.to_vec(),
                    ),
                    _ => panic!("Stripe prerequisite"),
                };
                PrerequisiteResponse {
                    kind,
                    response: ProviderResponse {
                        status,
                        version_ok: true,
                        body,
                    },
                    observed_at: NOW,
                    received_at: NOW + 1,
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(acquired.len(), 4);
        let digest = Sha256::digest(&acquired[3].response.body).into();
        let mut checkpoint = crate::GatewayPreEntry {
            observations: Vec::new(),
            basis: Some(crate::GatewayRelativeBasis {
                value: 1000,
                response_digest: digest,
                read_at: NOW,
            }),
        };
        match case {
            "account-mismatch" => acquired[0].response.body = br#"{"id":"acct_WRONG"}"#.to_vec(),
            "duplicate-account" => {
                acquired[0].response.body =
                    br#"{"id":"acct_WRONG","id":"acct_TESTACCOUNT01"}"#.to_vec()
            }
            "capability-excess" => acquired[1].response.status = 200,
            "denied-version" => acquired[2].response.version_ok = false,
            "currency-mismatch" => {
                acquired[3].response.body = br#"{"amount_received":1000,"currency":"eur"}"#.to_vec()
            }
            "above-ceiling" => {
                acquired[3].response.body = br#"{"amount_received":900,"currency":"usd"}"#.to_vec();
                let basis = checkpoint.basis.as_mut().expect("basis");
                basis.value = 900;
                basis.response_digest = Sha256::digest(&acquired[3].response.body).into();
            }
            "wrong-basis" => checkpoint.basis.as_mut().expect("basis").value = 2000,
            "wrong-digest" => checkpoint.basis.as_mut().expect("basis").response_digest = [1; 32],
            "refreshed-basis-time" => checkpoint.basis.as_mut().expect("basis").read_at = NOW + 1,
            "missing-basis" => checkpoint.basis = None,
            "duplicate-basis" => {
                acquired[3].response.body =
                    br#"{"amount_received":0,"amount_received":1000,"currency":"usd"}"#.to_vec()
            }
            "wrong-order" => acquired.swap(0, 1),
            "missing-read" => {
                acquired.pop();
            }
            "unrelated-observation" => checkpoint.observations.push(vec![0]),
            _ => {}
        }
        let accepted = crate::entry::validate_prerequisite_evidence(
            approved,
            installed,
            None,
            &checkpoint,
            &acquired,
            NOW + 1,
        )
        .is_ok();
        assert_eq!(accepted, case == "exact", "{case}");
        cases.push(json!({"case": case, "accepted": accepted}));
    }
    let bytes = serde_json::to_vec_pretty(&json!({
        "schema": "auths.prerequisite-guard-evidence-fixture/1",
        "scope": "native signed Stripe effect and synthetic response/checkpoint substitutions against the installed entry predicate; no installed transport or adapter race claim",
        "cases": cases,
    })).expect("fixture");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/prerequisite-guard-evidence.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("write fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), bytes);
}
