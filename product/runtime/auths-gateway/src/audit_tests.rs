//! Offline audit `/2` with real proofs: the provider result beside each
//! verdict, the relative-ceiling check, and the pre-entry check.
//!
//! Outcomes the gateway would never sign, such as one whose basis does not
//! admit its argument, are signed here with the test observer's key: the
//! audit exists to catch a gateway, or a bundle, that says otherwise.

use super::*;
use crate::observer::{OutcomeRecord, READ_BACK_SCHEMA, read_back_facts};
use crate::{AuditPins, AuditReport, AuditStatus, GatewayAttemptStage, pre_entry_digest};
use sha2::{Digest as _, Sha256};

/// A test recipe's source and lock after `edit` changes the source.
fn edited_recipe(
    extra: &Value,
    preconditions: &Value,
    edit: impl FnOnce(&mut Value),
) -> (Vec<u8>, Vec<u8>, CompiledRecipe) {
    let (source, lock) = h::recipe_sources(extra, preconditions).expect("recipe sources");
    let mut value: Value = serde_json::from_slice(&source).expect("source JSON");
    edit(&mut value);
    let source = serde_json::to_vec(&value).expect("source bytes");
    let recipe = CompiledRecipe::compile(&source, &lock).expect("edited recipe compiles");
    (source, lock, recipe)
}

fn record_path() -> Value {
    json!([
        {"kind": "fixed", "value": "v0"},
        {"kind": "fixed", "value": "appTEST0000000001"},
        {"kind": "fixed", "value": "tblTEST0000000001"},
        {"kind": "field", "name": "record_id"}
    ])
}

/// A recipe whose write carries the verified `amount`, bounded to half of
/// the integer the gateway reads at `/fields/Basis`.
fn ceiling_recipe() -> (Vec<u8>, Vec<u8>, CompiledRecipe) {
    edited_recipe(
        &json!({"amount": {"kind": "integer", "minimum": 0, "maximum": 1_000_000}}),
        &json!({}),
        |source| {
            if let Some(object) = source.as_object_mut() {
                object.remove("preconditions");
            }
            source["write"]["body"]["value"]["fields"]["fields"]["fields"]["Amount"] =
                json!({"kind": "field", "name": "amount"});
            source["relative_ceiling"] = json!({
                "argument": "amount",
                "basis_points": 5_000,
                "path": record_path(),
                "json_pointer": "/fields/Basis",
                "maximum_response_bytes": 16_384
            });
        },
    )
}

/// The update recipe with a pre-entry re-read of the field its read-back
/// requirement constrains.
fn pre_entry_recipe() -> (Vec<u8>, Vec<u8>, CompiledRecipe) {
    edited_recipe(
        &json!({
            "expected": {"type": "enum", "variants": ["Approved", "Pending"]},
            "record_uri": {"kind": "string", "minimum": 1, "maximum": 256}
        }),
        &json!({"read_back_subject": "record_uri", "verified": ["expected"]}),
        |source| {
            source["pre_entry"] = json!({
                "path": record_path(),
                "pointers": ["/fields/DemoStatus"],
                "maximum_response_bytes": 16_384
            });
        },
    )
}

fn bundle(
    source: &[u8],
    lock: &[u8],
    context: &TrustedContext,
    entries: &[Value],
) -> (Vec<u8>, AuditPins, [u8; 32]) {
    let trust = auths_codec::encode_verifier_context(context).expect("context bytes");
    let digest: [u8; 32] = Sha256::digest(&trust).into();
    let document = json!({
        "schema": crate::AUDIT_BUNDLE_SCHEMA,
        "recipe_b64": Base64UrlUnpadded::encode_string(source),
        "profile_lock_b64": Base64UrlUnpadded::encode_string(lock),
        "trusted_context_b64": Base64UrlUnpadded::encode_string(&trust),
        "entries": entries,
    });
    let pins = AuditPins {
        trusted_context_sha256: digest,
        observer: GatewayObserver::from_test_seed(h::OBSERVER_SEED)
            .principal()
            .clone(),
    };
    (serde_json::to_vec(&document).expect("bundle"), pins, digest)
}

fn audit(bytes: &[u8], pins: &AuditPins) -> AuditReport {
    crate::audit_bundle(bytes, pins).expect("audit")
}

/// An outcome the test observer signs for `submission` of `operation`.
fn signed_outcome(
    recipe: &CompiledRecipe,
    operation: &str,
    submission: &Submission,
    edit: impl FnOnce(&mut OutcomeRecord),
) -> String {
    let mut record = OutcomeRecord {
        commitment: hex::encode(submission.commitment),
        stage: GatewayAttemptStage::ResponseRecorded,
        evaluated_at: NOW,
        recipe_digest: recipe.digest_hex(),
        counters_digest: None,
        refusal: None,
        http_status: Some(200),
        response_digest: Some([0x0d; 32]),
        observation: None,
        evidence_digest: None,
        pre_entry_digest: None,
        relative_basis: None,
        relative_basis_digest: None,
    };
    edit(&mut record);
    let facts = record.facts().expect("a well-formed outcome");
    let subject = operation_subject(
        recipe.namespace(),
        &LogicalOperationId::parse(operation).expect("operation"),
    );
    let signed = GatewayObserver::from_test_seed(h::OBSERVER_SEED)
        .sign(OUTCOME_SCHEMA, &subject, NOW + 1, facts)
        .expect("signed outcome");
    Base64UrlUnpadded::encode_string(signed.bytes())
}

fn entry(operation: &str, submission: &Submission, outcome: Option<&str>) -> Value {
    json!({
        "operation_id": operation,
        "proof_b64": Base64UrlUnpadded::encode_string(&submission.proof),
        "action_b64": Base64UrlUnpadded::encode_string(&submission.action),
        "outcome_b64": outcome,
    })
}

fn verdicts(report: &AuditReport) -> Vec<(AuditStatus, String)> {
    report
        .entries
        .iter()
        .map(|entry| (entry.status, entry.code.clone()))
        .collect()
}

/// The audit flags a bundle whose basis does not admit its argument, and one
/// whose outcome carries no basis; it shows the provider's status beside the
/// verdict, a rejected write included.
#[test]
fn audit_flags_a_basis_that_does_not_admit_its_argument() {
    use AuditStatus::{Inconsistent, Verified};
    let (source, lock, recipe) = ceiling_recipe();
    let harness = Harness::open(recipe.clone(), Backend::File);
    let submit = |operation: &str, amount: u64| {
        let arguments = harness.arguments(operation, RECORD, &json!({"amount": amount}));
        harness.sign(None, &arguments, &[])
    };
    let basis = |value: u64| {
        move |record: &mut OutcomeRecord| {
            record.relative_basis = Some(value);
            record.relative_basis_digest = Some([0x0b; 32]);
        }
    };
    let admitted = submit("at-ratio", 500);
    let above = submit("above-ratio", 501);
    let without = submit("no-basis", 100);
    let rejected = submit("rejected", 400);
    let entries = vec![
        entry(
            "at-ratio",
            &admitted,
            Some(&signed_outcome(
                &recipe,
                "at-ratio",
                &admitted,
                basis(1_000),
            )),
        ),
        entry(
            "above-ratio",
            &above,
            Some(&signed_outcome(
                &recipe,
                "above-ratio",
                &above,
                basis(1_000),
            )),
        ),
        entry(
            "no-basis",
            &without,
            Some(&signed_outcome(&recipe, "no-basis", &without, |_| {})),
        ),
        entry(
            "rejected",
            &rejected,
            Some(&signed_outcome(&recipe, "rejected", &rejected, |record| {
                basis(1_000)(record);
                record.http_status = Some(400);
            })),
        ),
    ];
    let (bytes, pins, _) = bundle(&source, &lock, &harness.context, &entries);
    let report = audit(&bytes, &pins);
    assert_eq!(report.schema, "auths.gateway-audit-report/2");
    assert_eq!(report.recovery["class"], "linked");
    assert_eq!(
        verdicts(&report),
        vec![
            (Verified, "audit.verified".to_owned()),
            (Inconsistent, "audit.relative-ceiling-exceeded".to_owned()),
            (Inconsistent, "audit.relative-ceiling-missing".to_owned()),
            (Verified, "audit.verified".to_owned()),
        ]
    );
    let statuses: Vec<Option<u16>> = report
        .entries
        .iter()
        .map(|entry| {
            entry
                .provider_result
                .as_ref()
                .and_then(|result| result.http_status)
        })
        .collect();
    assert_eq!(statuses, [Some(200), Some(200), Some(200), Some(400)]);
    let result = report.entries[3].provider_result.as_ref().expect("result");
    assert_eq!(result.relative_basis, Some(1_000));
    assert_eq!(
        result.response_digest.as_deref(),
        Some(hex::encode([0x0d; 32]).as_str())
    );
    assert_eq!(report.inconsistent, 2);
}

/// An entered entry's outcome must carry the counter set the audit derives
/// at `evaluated-at`; an unbounded action's outcome carries none.
#[test]
fn audit_requires_the_counter_set_the_audit_derives() {
    let (source, lock, recipe) = ceiling_recipe();
    let harness = Harness::open(recipe.clone(), Backend::File);
    let arguments = harness.arguments("unbounded", RECORD, &json!({"amount": 10}));
    let submission = harness.sign(None, &arguments, &[]);
    let outcome = signed_outcome(&recipe, "unbounded", &submission, |record| {
        record.counters_digest = Some([0x0c; 32]);
        record.relative_basis = Some(1_000);
        record.relative_basis_digest = Some([0x0b; 32]);
    });
    let (bytes, pins, _) = bundle(
        &source,
        &lock,
        &harness.context,
        &[entry("unbounded", &submission, Some(&outcome))],
    );
    assert_eq!(
        verdicts(&audit(&bytes, &pins)),
        vec![(
            AuditStatus::Inconsistent,
            "audit.counters-mismatch".to_owned()
        )]
    );
}

/// The pre-entry observations the gateway stored satisfy the audit; a
/// bundle without them, with altered bytes, or whose signed observation
/// fails the requirement is flagged.
#[tokio::test]
async fn audit_checks_the_pre_entry_observations() {
    use AuditStatus::{Inconsistent, Verified};
    let (source, lock, recipe) = pre_entry_recipe();
    let harness = Harness::open(recipe.clone(), Backend::File);
    let observation = harness.read_back(RECORD, NOW).await;
    let arguments = harness.arguments("pre-entry", RECORD, &update_extra(RECORD, "Pending"));
    let submission = harness.sign(Some(read_back_requirement()), &arguments, &[observation]);
    let result = harness.submit(&submission, NOW + 30).await;
    assert!(
        matches!(result, GatewaySubmitResult::ObservedByProvider { .. }),
        "{result:?}"
    );
    let outcome = signed_bytes(harness.outcome("pre-entry", NOW + 31).await);
    let GatewayObserveResult::PreEntry {
        observations_b64, ..
    } = harness
        .core
        .observe(
            &GatewayObserveRequest::PreEntry {
                operation_id: "pre-entry".to_owned(),
            },
            NOW + 31,
        )
        .await
    else {
        panic!("expected the stored pre-entry observations");
    };
    assert_eq!(observations_b64.len(), 1);
    let base = |pre_entry: Option<Vec<String>>, outcome: &[u8]| {
        let mut value = entry(
            "pre-entry",
            &submission,
            Some(&Base64UrlUnpadded::encode_string(outcome)),
        );
        if let Some(items) = pre_entry {
            value["pre_entry_b64"] = json!(items);
        }
        value
    };
    let run = |value: Value| {
        let (bytes, pins, _) = bundle(&source, &lock, &harness.context, &[value]);
        let report = audit(&bytes, &pins);
        let pre_entry = report.entries[0]
            .provider_result
            .as_ref()
            .and_then(|result| result.pre_entry);
        (verdicts(&report).remove(0), pre_entry)
    };

    let (verdict, pre_entry) = run(base(Some(observations_b64.clone()), &outcome));
    assert_eq!(verdict, (Verified, "audit.verified".to_owned()));
    assert_eq!(
        pre_entry,
        Some(crate::AuditedPreEntry {
            observations: 1,
            verified: true
        })
    );

    assert_eq!(
        run(base(None, &outcome)).0,
        (Inconsistent, "audit.pre-entry-missing".to_owned())
    );
    let mut altered = Base64UrlUnpadded::decode_vec(&observations_b64[0]).expect("base64");
    let last = altered.len() - 1;
    altered[last] ^= 1;
    assert_eq!(
        run(base(
            Some(vec![Base64UrlUnpadded::encode_string(&altered)]),
            &outcome
        ))
        .0,
        (Inconsistent, "audit.pre-entry-invalid".to_owned())
    );

    // An observation that makes the requirement false, with an outcome that
    // commits to it: a gateway that entered anyway.
    let observer = GatewayObserver::from_test_seed(h::OBSERVER_SEED);
    let unsatisfying = observer
        .sign(
            READ_BACK_SCHEMA,
            &read_back_subject(RECORD),
            NOW + 30,
            read_back_facts(&json!("Approved"), None).expect("facts"),
        )
        .expect("signed read-back")
        .bytes()
        .to_vec();
    let forged = signed_outcome(&recipe, "pre-entry", &submission, |record| {
        record.evaluated_at = NOW + 30;
        record.pre_entry_digest = pre_entry_digest(std::slice::from_ref(&unsatisfying));
    });
    let forged = Base64UrlUnpadded::decode_vec(&forged).expect("base64");
    assert_eq!(
        run(base(
            Some(vec![Base64UrlUnpadded::encode_string(&unsatisfying)]),
            &forged
        ))
        .0,
        (Inconsistent, "audit.pre-entry-unsatisfied".to_owned())
    );
}
