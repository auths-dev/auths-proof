//! Structural vectors: one valid instance of every artifact, and hostile
//! cases that each break exactly one structural rule.
//!
//! A case is the valid artifact plus mutations, re-encoded canonically, so
//! its only fault is the one it names; a `text` case carries exact bytes
//! where the fault is the encoding itself; a `pad_to` case is the valid
//! artifact followed by spaces up to that length.

#![allow(clippy::too_many_lines, reason = "case tables read top to bottom")]

use super::{
    DAY, HOUR, Keys, NOW, apply_mutation, attestation, attestation_statement, certificate,
    certificate_statement, contract, decoded_contract, index, index_entry, index_statement, load,
    record, require_current, revocation, revocation_statement, text, trust_root, tuple,
};
use crate::{
    MAX_ATTESTATION_BYTES, MAX_INDEX_ENTRIES, MAX_INSTALLED_PACKAGES, MAX_MANUAL_ASSUMPTIONS,
    MAX_PROVIDER_CONTRACT_BYTES, MAX_PROVIDER_RESOURCES, MAX_QUALIFICATION_SECONDS,
    MAX_RECORD_BYTES, MAX_RECORD_STATEMENTS, MAX_RELEASE_INDEX_BYTES, MAX_REVOCATION_LIST_BYTES,
    MAX_REVOCATION_SECONDS, MAX_REVOKED_QUALIFICATIONS, MAX_REVOKED_SIGNERS,
    MAX_SIGNER_CERTIFICATE_BYTES, MAX_SIGNER_SECONDS, MAX_TRUST_ROOT_BYTES, ProviderContract,
    QualificationFormatError, QualificationReleaseIndex, QualificationRevocationList,
    QualificationSignerCertificate, QualificationTrustRoot, RecipeQualificationAttestation,
    RecipeQualificationRecord,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) const FILE: &str = "schema-vectors.json";
const SCHEMA: &str = "auths.qualification-schema-vectors/1";

/// The valid canonical text of every artifact, by fixture name.
fn valid() -> Value {
    let keys = Keys::fixed();
    let record_text = text(&record(1, tuple()));
    let attestation_text = text(&attestation(
        attestation_statement(&record_text, 1),
        &keys.signer,
    ));
    let entries = vec![index_entry(1, &record_text, &attestation_text)];
    json!({
        "trust_root": text(&trust_root(&keys)),
        "signer_certificate": text(&certificate(certificate_statement(&keys), &keys.root)),
        "revocation_list": text(&revocation(revocation_statement(NOW - HOUR), &keys.root)),
        "release_index": text(&index(index_statement(entries), &keys.signer)),
        "record": record_text,
        "attestation": attestation_text,
        "provider_contract": text(&contract()),
    })
}

fn limits() -> Value {
    json!({
        "trust_root_bytes": MAX_TRUST_ROOT_BYTES,
        "signer_certificate_bytes": MAX_SIGNER_CERTIFICATE_BYTES,
        "revocation_list_bytes": MAX_REVOCATION_LIST_BYTES,
        "release_index_bytes": MAX_RELEASE_INDEX_BYTES,
        "record_bytes": MAX_RECORD_BYTES,
        "attestation_bytes": MAX_ATTESTATION_BYTES,
        "provider_contract_bytes": MAX_PROVIDER_CONTRACT_BYTES,
        "revoked_signers": MAX_REVOKED_SIGNERS,
        "revoked_qualifications": MAX_REVOKED_QUALIFICATIONS,
        "index_entries": MAX_INDEX_ENTRIES,
        "installed_packages": MAX_INSTALLED_PACKAGES,
        "provider_resources": MAX_PROVIDER_RESOURCES,
        "record_statements": MAX_RECORD_STATEMENTS,
        "manual_assumptions": MAX_MANUAL_ASSUMPTIONS,
        "qualification_seconds": MAX_QUALIFICATION_SECONDS,
        "signer_seconds": MAX_SIGNER_SECONDS,
        "revocation_seconds": MAX_REVOCATION_SECONDS,
    })
}

fn set(pointer: &str, value: Value) -> Value {
    let mut mutation = json!({"op": "set", "pointer": pointer});
    mutation["value"] = value;
    mutation
}

fn remove(pointer: &str) -> Value {
    json!({"op": "remove", "pointer": pointer})
}

fn fill(pointer: &str, count: usize, width: usize, template: Value) -> Value {
    let mut mutation = json!({"op": "fill", "pointer": pointer, "count": count, "width": width});
    mutation["template"] = template;
    mutation
}

fn case(id: &str, artifact: &str, class: &str, reason: &str, mutations: Vec<Value>) -> Value {
    let mut case = json!({"id": id, "artifact": artifact, "class": class, "reason": reason});
    case["mutations"] = Value::Array(mutations);
    case
}

fn raw(id: &str, artifact: &str, class: &str, reason: &str, text: String) -> Value {
    let mut case = json!({"id": id, "artifact": artifact, "class": class, "reason": reason});
    case["text"] = Value::String(text);
    case
}

fn padded(id: &str, artifact: &str, limit: usize) -> Value {
    json!({"id": id, "artifact": artifact, "class": "oversize", "reason": "oversized", "pad_to": limit + 1})
}

fn parsed(valid: &Value, artifact: &str) -> Value {
    serde_json::from_str(valid[artifact].as_str().expect("valid text")).expect("valid JSON")
}

fn record_shape_cases(valid: &Value) -> Vec<Value> {
    let record = parsed(valid, "record");
    let c = |id: &str, class: &str, reason: &str, mutations: Vec<Value>| {
        case(id, "record", class, reason, mutations)
    };
    vec![
        c(
            "record-extra-member",
            "extra-field",
            "malformed",
            vec![set("/reviewed", json!(true))],
        ),
        c(
            "record-self-declared-state",
            "self-declared-qualification",
            "malformed",
            vec![set("/state", json!("qualified"))],
        ),
        c(
            "record-unknown-evidence-member",
            "unknown-enum-member",
            "malformed",
            vec![set("/evidence/0/member", json!("mock"))],
        ),
        c(
            "record-failed-member-result",
            "unknown-enum-member",
            "malformed",
            vec![set("/evidence/3/result", json!("failed"))],
        ),
        c(
            "record-skipped-member-result",
            "unknown-enum-member",
            "malformed",
            vec![set("/evidence/4/result", json!("not-applicable"))],
        ),
        c(
            "record-unknown-credential-store",
            "wrong-credential-store",
            "malformed",
            vec![set(
                "/tuple/target/credential_store_kind",
                json!("vault-v1"),
            )],
        ),
        c(
            "record-unknown-store-kind",
            "wrong-store",
            "malformed",
            vec![set("/tuple/target/store_kind", json!("sqlite-v1"))],
        ),
        c(
            "record-unknown-architecture",
            "wrong-target",
            "malformed",
            vec![set("/tuple/target/arch", json!("any"))],
        ),
        c(
            "record-uppercase-digest",
            "non-canonical",
            "malformed",
            vec![set(
                "/tuple/compiled_recipe_sha256",
                json!(
                    record["tuple"]["compiled_recipe_sha256"]
                        .as_str()
                        .expect("digest")
                        .to_uppercase()
                ),
            )],
        ),
        c(
            "record-unicode-family",
            "unicode-confusion",
            "malformed",
            vec![set(
                "/tuple/recipe_family",
                json!("example-r\u{435}fund-v1"),
            )],
        ),
        c(
            "record-unicode-resource",
            "unicode-confusion",
            "malformed",
            vec![set(
                "/provider_resources/0",
                json!("refund:fixture\u{2010}0001"),
            )],
        ),
        c(
            "record-abbreviated-commit",
            "mutable-alias",
            "malformed",
            vec![set("/provenance/commit", json!("0123456"))],
        ),
        c(
            "record-branch-as-commit",
            "mutable-alias",
            "malformed",
            vec![set("/provenance/commit", json!("main"))],
        ),
        c(
            "record-other-schema-version",
            "unknown-enum-member",
            "unknown-schema",
            vec![set("/schema", json!("auths.recipe-qualification/2"))],
        ),
        c(
            "record-attestation-schema",
            "unknown-enum-member",
            "unknown-schema",
            vec![set(
                "/schema",
                json!("auths.recipe-qualification-attestation/1"),
            )],
        ),
    ]
}

fn record_evidence_cases(valid: &Value) -> Vec<Value> {
    let record = parsed(valid, "record");
    let c = |id: &str, class: &str, mutations: Vec<Value>| {
        case(id, "record", class, "invalid-evidence", mutations)
    };
    vec![
        c(
            "record-member-missing",
            "evidence-not-closed",
            vec![remove("/evidence/9")],
        ),
        c(
            "record-members-out-of-order",
            "evidence-not-closed",
            vec![
                set("/evidence/0", record["evidence"][1].clone()),
                set("/evidence/1", record["evidence"][0].clone()),
            ],
        ),
        c(
            "record-member-repeated",
            "evidence-not-closed",
            vec![set("/evidence/1", record["evidence"][0].clone())],
        ),
        c(
            "record-unauthorized-provider-entry",
            "evidence-not-closed",
            vec![set("/evidence/2/unauthorized_provider_entries", json!(1))],
        ),
        c(
            "record-member-without-cases",
            "evidence-not-closed",
            vec![set("/evidence/5/cases", json!(0))],
        ),
        c(
            "record-live-response-without-read-back",
            "response-without-read-back",
            vec![set("/live_effects/confirmed_by_read_back", json!(3))],
        ),
        c(
            "record-no-live-effect",
            "response-without-read-back",
            vec![set(
                "/live_effects",
                json!({"entered": 0, "confirmed_by_read_back": 0}),
            )],
        ),
        c(
            "record-observation-not-applicable",
            "response-without-read-back",
            vec![set(
                "/capabilities/9",
                json!({"capability": "observation", "result": "not-applicable",
                    "reason": "the recipe declares no read-back"}),
            )],
        ),
        c(
            "record-capability-omitted",
            "evidence-not-closed",
            vec![remove("/capabilities/11")],
        ),
        c(
            "record-not-applicable-without-reason",
            "evidence-not-closed",
            vec![remove("/capabilities/2/reason")],
        ),
        c(
            "record-exercised-with-reason",
            "evidence-not-closed",
            vec![set("/capabilities/0/reason", json!("not needed"))],
        ),
    ]
}

fn record_bound_cases(valid: &Value) -> Vec<Value> {
    let record = parsed(valid, "record");
    let start = record["not_before"].as_u64().expect("not_before");
    let digest = record["source_closure_sha256"].clone();
    let package = json!({"name": "package-{}", "version": "1", "sha256": digest});
    let text = valid["record"].as_str().expect("record text");
    vec![
        case(
            "record-window-91-days",
            "record",
            "widened-time-bound",
            "invalid-time-window",
            vec![set("/not_after", json!(start + 91 * DAY))],
        ),
        case(
            "record-window-reversed",
            "record",
            "widened-time-bound",
            "invalid-time-window",
            vec![set("/not_after", json!(start))],
        ),
        case(
            "record-resources-unsorted",
            "record",
            "non-canonical",
            "list-order",
            vec![
                set(
                    "/provider_resources/0",
                    record["provider_resources"][1].clone(),
                ),
                set(
                    "/provider_resources/1",
                    record["provider_resources"][0].clone(),
                ),
            ],
        ),
        case(
            "record-resource-repeated",
            "record",
            "non-canonical",
            "list-order",
            vec![set(
                "/provider_resources/1",
                record["provider_resources"][0].clone(),
            )],
        ),
        case(
            "record-no-packages",
            "record",
            "oversize",
            "list-bound",
            vec![set("/installed_packages", json!([]))],
        ),
        case(
            "record-nine-packages",
            "record",
            "oversize",
            "list-bound",
            vec![fill(
                "/installed_packages",
                MAX_INSTALLED_PACKAGES + 1,
                2,
                package,
            )],
        ),
        case(
            "record-33-resources",
            "record",
            "oversize",
            "list-bound",
            vec![fill(
                "/provider_resources",
                MAX_PROVIDER_RESOURCES + 1,
                4,
                json!("refund:fixture-{}"),
            )],
        ),
        padded("record-oversized", "record", MAX_RECORD_BYTES),
        raw(
            "record-trailing-newline",
            "record",
            "non-canonical",
            "non-canonical",
            format!("{text}\n"),
        ),
        raw(
            "record-exponent-time",
            "record",
            "non-canonical",
            "malformed",
            text.replace(
                &format!("\"not_before\":{start}"),
                "\"not_before\":1.7899928e9",
            ),
        ),
        raw(
            "record-repeated-member",
            "record",
            "non-canonical",
            "malformed",
            text.replacen('{', "{\"schema\":\"auths.recipe-qualification/1\",", 1),
        ),
    ]
}

fn certificate_cases(valid: &Value) -> Vec<Value> {
    let statement = parsed(valid, "signer_certificate")["statement"].clone();
    let start = statement["not_before"].as_u64().expect("not_before");
    let c = |id: &str, class: &str, reason: &str, mutations: Vec<Value>| {
        case(id, "signer_certificate", class, reason, mutations)
    };
    let kinds = "/statement/permitted_artifact_kinds";
    vec![
        c(
            "certificate-hardware-signer-kind",
            "wrong-signer-kind",
            "malformed",
            vec![set(
                "/statement/signer_kind",
                json!("hardware-release-key-v1"),
            )],
        ),
        c(
            "certificate-kms-signer-kind",
            "wrong-signer-kind",
            "malformed",
            vec![set("/statement/signer_kind", json!("aws-kms-p256-v1"))],
        ),
        c(
            "certificate-unknown-suite",
            "unknown-enum-member",
            "malformed",
            vec![set("/statement/signature_suite", json!("p256-sha256-v1"))],
        ),
        c(
            "certificate-permits-certificates",
            "signer-signed-root-artifact",
            "malformed",
            vec![set(
                kinds,
                json!([
                    "qualification-release-index",
                    "qualification-signer-certificate"
                ]),
            )],
        ),
        c(
            "certificate-permits-revocations",
            "signer-signed-root-artifact",
            "malformed",
            vec![set(
                kinds,
                json!([
                    "qualification-release-index",
                    "qualification-revocation-list"
                ]),
            )],
        ),
        c(
            "certificate-permits-nothing",
            "oversize",
            "list-bound",
            vec![set(kinds, json!([]))],
        ),
        c(
            "certificate-kinds-unsorted",
            "non-canonical",
            "list-order",
            vec![set(
                kinds,
                json!([
                    "recipe-qualification-attestation",
                    "qualification-release-index"
                ]),
            )],
        ),
        c(
            "certificate-kind-repeated",
            "non-canonical",
            "list-order",
            vec![set(
                kinds,
                json!(["qualification-release-index", "qualification-release-index"]),
            )],
        ),
        c(
            "certificate-window-366-days",
            "widened-time-bound",
            "invalid-time-window",
            vec![set("/statement/not_after", json!(start + 366 * DAY))],
        ),
        c(
            "certificate-issued-after-expiry",
            "widened-time-bound",
            "invalid-time-window",
            vec![set("/statement/issued_at", statement["not_after"].clone())],
        ),
        c(
            "certificate-maximum-age-member",
            "widened-time-bound",
            "malformed",
            vec![set("/statement/maximum_age_seconds", json!(63_072_000))],
        ),
        c(
            "certificate-short-key",
            "unknown-enum-member",
            "malformed",
            vec![set(
                "/statement/public_key_b64",
                json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            )],
        ),
        padded(
            "certificate-oversized",
            "signer_certificate",
            MAX_SIGNER_CERTIFICATE_BYTES,
        ),
    ]
}

fn revocation_cases(valid: &Value) -> Vec<Value> {
    let statement = parsed(valid, "revocation_list")["statement"].clone();
    let issued = statement["issued_at"].as_u64().expect("issued_at");
    let c = |id: &str, class: &str, reason: &str, mutations: Vec<Value>| {
        case(id, "revocation_list", class, reason, mutations)
    };
    vec![
        c(
            "revocation-window-73-hours",
            "widened-time-bound",
            "invalid-time-window",
            vec![set("/statement/next_update", json!(issued + 73 * HOUR))],
        ),
        c(
            "revocation-next-update-at-issue",
            "widened-time-bound",
            "invalid-time-window",
            vec![set("/statement/next_update", json!(issued))],
        ),
        c(
            "revocation-grace-member",
            "widened-time-bound",
            "malformed",
            vec![set("/statement/grace_seconds", json!(86_400))],
        ),
        c(
            "revocation-sequence-zero",
            "non-canonical",
            "malformed",
            vec![set("/statement/sequence", json!(0))],
        ),
        c(
            "revocation-signers-unsorted",
            "non-canonical",
            "list-order",
            vec![set(
                "/statement/revoked_signers",
                json!(["signer-b", "signer-a"]),
            )],
        ),
        c(
            "revocation-qualification-repeated",
            "non-canonical",
            "list-order",
            vec![fill(
                "/statement/revoked_qualifications",
                2,
                1,
                json!("qlf_0000000000000000000000000000000a"),
            )],
        ),
        c(
            "revocation-65-signers",
            "oversize",
            "list-bound",
            vec![fill(
                "/statement/revoked_signers",
                MAX_REVOKED_SIGNERS + 1,
                4,
                json!("signer-{}"),
            )],
        ),
        c(
            "revocation-1025-qualifications",
            "oversize",
            "list-bound",
            vec![fill(
                "/statement/revoked_qualifications",
                MAX_REVOKED_QUALIFICATIONS + 1,
                32,
                json!("qlf_{}"),
            )],
        ),
        padded(
            "revocation-oversized",
            "revocation_list",
            MAX_REVOCATION_LIST_BYTES,
        ),
    ]
}

fn index_and_attestation_cases(valid: &Value) -> Vec<Value> {
    let index = parsed(valid, "release_index");
    let entry = index["statement"]["entries"][0].clone();
    let mut template = entry.clone();
    template["qualification_id"] = json!("qlf_{}");
    let start = parsed(valid, "attestation")["statement"]["not_before"]
        .as_u64()
        .expect("not_before");
    vec![
        case(
            "index-entry-repeated",
            "release_index",
            "non-canonical",
            "list-order",
            vec![set("/statement/entries", json!([entry.clone(), entry]))],
        ),
        case(
            "index-257-entries",
            "release_index",
            "oversize",
            "list-bound",
            vec![fill(
                "/statement/entries",
                MAX_INDEX_ENTRIES + 1,
                32,
                template,
            )],
        ),
        case(
            "index-own-freshness-member",
            "release_index",
            "widened-time-bound",
            "malformed",
            vec![set("/statement/next_update", json!(NOW + 365 * DAY))],
        ),
        padded("index-oversized", "release_index", MAX_RELEASE_INDEX_BYTES),
        case(
            "attestation-window-91-days",
            "attestation",
            "widened-time-bound",
            "invalid-time-window",
            vec![set("/statement/not_after", json!(start + 91 * DAY))],
        ),
        case(
            "attestation-embedded-state",
            "attestation",
            "self-declared-qualification",
            "malformed",
            vec![set("/statement/state", json!("qualified"))],
        ),
        case(
            "attestation-unknown-suite",
            "attestation",
            "unknown-enum-member",
            "malformed",
            vec![set("/statement/signature_suite", json!("none"))],
        ),
        case(
            "attestation-short-signature",
            "attestation",
            "forged",
            "malformed",
            vec![set("/signature_b64", json!("AAAA"))],
        ),
        padded(
            "attestation-oversized",
            "attestation",
            MAX_ATTESTATION_BYTES,
        ),
    ]
}

fn root_and_contract_cases(valid: &Value) -> Vec<Value> {
    let root_text = valid["trust_root"].as_str().expect("root text");
    let root = parsed(valid, "trust_root");
    let reversed: serde_json::Map<String, Value> = root
        .as_object()
        .expect("root object")
        .iter()
        .rev()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let c = |id: &str, class: &str, reason: &str, mutations: Vec<Value>| {
        case(id, "provider_contract", class, reason, mutations)
    };
    vec![
        case(
            "trust-root-private-key-member",
            "trust_root",
            "extra-field",
            "malformed",
            vec![set("/private_key_b64", json!("not-a-key"))],
        ),
        case(
            "trust-root-unknown-suite",
            "trust_root",
            "unknown-enum-member",
            "malformed",
            vec![set("/signature_suite", json!("rsa-pkcs1-sha256-v1"))],
        ),
        raw(
            "trust-root-members-reordered",
            "trust_root",
            "non-canonical",
            "non-canonical",
            serde_json::to_string(&Value::Object(reversed)).expect("reordered"),
        ),
        raw(
            "trust-root-spaced",
            "trust_root",
            "non-canonical",
            "non-canonical",
            root_text.replacen(':', ": ", 1),
        ),
        padded("trust-root-oversized", "trust_root", MAX_TRUST_ROOT_BYTES),
        c(
            "contract-mock-environment",
            "unknown-enum-member",
            "malformed",
            vec![set("/environment_class", json!("mock"))],
        ),
        c(
            "contract-null-slice",
            "non-canonical",
            "non-canonical",
            vec![set("/openapi_slice_sha256", Value::Null)],
        ),
        c(
            "contract-assumptions-unsorted",
            "non-canonical",
            "list-order",
            vec![set(
                "/manual_assumptions",
                json!(["b assumption", "a assumption"]),
            )],
        ),
        c(
            "contract-33-assumptions",
            "oversize",
            "list-bound",
            vec![fill(
                "/manual_assumptions",
                MAX_MANUAL_ASSUMPTIONS + 1,
                4,
                json!("assumption {}"),
            )],
        ),
        c(
            "contract-unicode-provider",
            "unicode-confusion",
            "malformed",
            vec![set("/provider", json!("ex\u{430}mple-payments"))],
        ),
        padded(
            "contract-oversized",
            "provider_contract",
            MAX_PROVIDER_CONTRACT_BYTES,
        ),
    ]
}

/// Valid contracts that differ from the base in one input. Each has its own
/// identifier, so a recipe whose bytes did not change is still stale.
fn contract_drift() -> Vec<Value> {
    let base = serde_json::to_value(contract()).expect("contract");
    [
        (
            "contract-drift-api-release",
            vec![set("/api_release", json!("2026-10-01.fixture"))],
        ),
        (
            "contract-drift-slice",
            vec![set("/openapi_slice_sha256", json!("ab".repeat(32)))],
        ),
        (
            "contract-drift-slice-removed",
            vec![remove("/openapi_slice_sha256")],
        ),
        (
            "contract-drift-assumption",
            vec![set(
                "/manual_assumptions/1",
                json!("the idempotency key is honored for at least 1 hour"),
            )],
        ),
        (
            "contract-drift-environment",
            vec![set(
                "/environment_class",
                json!("disposable-live-resources"),
            )],
        ),
        (
            "contract-drift-corpus",
            vec![set("/corpus_manifest_sha256", json!("cd".repeat(32)))],
        ),
        (
            "contract-drift-oracle",
            vec![set("/oracle_version", json!("oracle-2"))],
        ),
        (
            "contract-drift-recovery",
            vec![set("/declarations/recovery_sha256", json!("ef".repeat(32)))],
        ),
    ]
    .into_iter()
    .map(|(id, mutations)| {
        let mut drifted = base.clone();
        for mutation in &mutations {
            apply_mutation(&mut drifted, mutation);
        }
        let contract_id = ProviderContract::from_canonical_json(text(&drifted).as_bytes())
            .expect(id)
            .contract_id();
        json!({"id": id, "class": "contract-drift", "mutations": mutations,
            "provider_contract_id": contract_id.digest().to_hex()})
    })
    .collect()
}

fn document() -> Value {
    let valid = valid();
    let cases: Vec<Value> = [
        record_shape_cases(&valid),
        record_evidence_cases(&valid),
        record_bound_cases(&valid),
        certificate_cases(&valid),
        revocation_cases(&valid),
        index_and_attestation_cases(&valid),
        root_and_contract_cases(&valid),
    ]
    .concat();
    json!({
        "schema": SCHEMA,
        "limits": limits(),
        "valid": valid,
        "provider_contract_id": decoded_contract(&contract()).contract_id().digest().to_hex(),
        "cases": cases,
        "contract_drift": contract_drift(),
    })
}

#[test]
fn schema_vectors_are_current() {
    require_current(FILE, &document());
}

fn decode(artifact: &str, bytes: &[u8]) -> Result<(), QualificationFormatError> {
    match artifact {
        "trust_root" => QualificationTrustRoot::from_canonical_json(bytes).map(drop),
        "signer_certificate" => {
            QualificationSignerCertificate::from_canonical_json(bytes).map(drop)
        }
        "revocation_list" => QualificationRevocationList::from_canonical_json(bytes).map(drop),
        "release_index" => QualificationReleaseIndex::from_canonical_json(bytes).map(drop),
        "record" => RecipeQualificationRecord::from_canonical_json(bytes).map(drop),
        "attestation" => RecipeQualificationAttestation::from_canonical_json(bytes).map(drop),
        "provider_contract" => ProviderContract::from_canonical_json(bytes).map(drop),
        _ => panic!("unknown artifact {artifact}"),
    }
}

/// The exact bytes a case presents to the decoder.
fn case_bytes(valid: &Value, case: &Value) -> Vec<u8> {
    let base = valid[case["artifact"].as_str().expect("artifact")]
        .as_str()
        .expect("valid text");
    if let Some(text) = case["text"].as_str() {
        return text.as_bytes().to_vec();
    }
    if let Some(length) = case["pad_to"].as_u64() {
        let mut bytes = base.as_bytes().to_vec();
        bytes.resize(usize::try_from(length).expect("length"), b' ');
        return bytes;
    }
    let mut document: Value = serde_json::from_str(base).expect("valid JSON");
    for mutation in case["mutations"].as_array().expect("mutations") {
        apply_mutation(&mut document, mutation);
    }
    text(&document).into_bytes()
}

#[test]
fn every_valid_artifact_decodes() {
    let corpus = load(FILE);
    for (artifact, text) in corpus["valid"].as_object().expect("valid") {
        assert_eq!(
            decode(artifact, text.as_str().expect("text").as_bytes()),
            Ok(()),
            "{artifact}"
        );
    }
    let contract = ProviderContract::from_canonical_json(
        corpus["valid"]["provider_contract"]
            .as_str()
            .expect("text")
            .as_bytes(),
    )
    .expect("contract");
    assert_eq!(
        contract.contract_id().digest().to_hex(),
        corpus["provider_contract_id"]
    );
    assert_eq!(corpus["limits"], limits());
}

#[test]
fn every_structural_case_is_refused_with_its_reason() {
    let corpus = load(FILE);
    let mut ids = BTreeSet::new();
    for case in corpus["cases"].as_array().expect("cases") {
        let id = case["id"].as_str().expect("id");
        assert!(ids.insert(id), "duplicate case {id}");
        let artifact = case["artifact"].as_str().expect("artifact");
        let refused = decode(artifact, &case_bytes(&corpus["valid"], case)).expect_err(id);
        assert_eq!(refused.as_str(), case["reason"], "case {id}");
    }
}

#[test]
fn contract_drift_changes_the_contract_identifier() {
    let corpus = load(FILE);
    let mut identifiers = BTreeSet::new();
    identifiers.insert(
        corpus["provider_contract_id"]
            .as_str()
            .expect("base")
            .to_owned(),
    );
    for case in corpus["contract_drift"].as_array().expect("drift") {
        let id = case["id"].as_str().expect("id");
        let mut drifted: Value =
            serde_json::from_str(corpus["valid"]["provider_contract"].as_str().expect("text"))
                .expect("contract JSON");
        for mutation in case["mutations"].as_array().expect("mutations") {
            apply_mutation(&mut drifted, mutation);
        }
        let contract = ProviderContract::from_canonical_json(text(&drifted).as_bytes()).expect(id);
        let identifier = contract.contract_id().digest().to_hex();
        assert_eq!(identifier, case["provider_contract_id"], "case {id}");
        assert!(
            identifiers.insert(identifier),
            "{id} does not change the identifier"
        );
    }
}
