//! The derivation corpus: every case's exact output bytes or exact rejection
//! list, and every derived recipe compiled by the real gateway compiler.
//!
//! Vendor documents are pinned by digest, not committed. Their cases run when
//! `AUTHS_OPENAPI_CORPUS_DIR` holds `github.json`, `todoist.json`, and
//! `openai.json`; otherwise they are counted and skipped. Setting
//! `AUTHS_OPENAPI_DERIVATION_UPDATE=1` rewrites the expected files for review.

use auths_gateway::{CompiledRecipe, GatewayConnectionDescriptor};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn corpus() -> PathBuf {
    repository().join("bindings/fixtures/openapi-derivation")
}

fn updating() -> bool {
    std::env::var("AUTHS_OPENAPI_DERIVATION_UPDATE").as_deref() == Ok("1")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn cases() -> Vec<Value> {
    read_json(&corpus().join("cases.json"))["cases"]
        .as_array()
        .expect("cases array")
        .clone()
}

/// Loads a case document, verifying pinned vendor bytes. `None` means the
/// vendor directory is not configured.
fn document(case: &Value) -> Option<(Vec<u8>, String)> {
    let source = &case["document"];
    if let Some(file) = source["file"].as_str() {
        let bytes = fs::read(corpus().join(file)).expect("corpus document");
        let name = Path::new(file)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        return Some((bytes, name));
    }
    let vendor = source["vendor"].as_str().expect("vendor or file");
    let directory = std::env::var("AUTHS_OPENAPI_CORPUS_DIR").ok()?;
    let manifest = read_json(&repository().join("bindings/fixtures/openapi-corpus/cases.json"));
    let pinned = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["vendor"] == vendor)
        .expect("vendor pinned in the published corpus");
    let name = format!("{}.json", vendor.to_ascii_lowercase());
    let bytes = fs::read(Path::new(&directory).join(&name)).expect("vendor document");
    assert_eq!(
        bytes.len() as u64,
        pinned["source"]["bytes"].as_u64().unwrap(),
        "{vendor} length"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        pinned["source"]["sha256"].as_str().unwrap(),
        "{vendor} digest"
    );
    Some((bytes, name))
}

fn arguments(case: &Value) -> Vec<String> {
    case["arguments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect()
}

fn check_file(path: &Path, actual: &str) {
    if updating() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, actual).unwrap();
        return;
    }
    let expected =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    assert_eq!(expected, actual, "{} differs", path.display());
}

fn review(recipe: &str, lock: &[u8]) -> Value {
    let compiled = CompiledRecipe::compile(recipe.as_bytes(), lock)
        .expect("derived recipe compiles under recipe check");
    let review = compiled.review();
    let header = match review.credential() {
        auths_gateway::CredentialRequirement::Bearer => "Authorization".to_owned(),
        auths_gateway::CredentialRequirement::HeaderApiKey { header } => header.clone(),
    };
    GatewayConnectionDescriptor::approve(&compiled, &header)
        .expect("operator binding accepts the credential requirement");
    json!({
        "schema": "auths.gateway-recipe-review/1",
        "digest": compiled.digest_hex(),
        "operator_namespace": compiled.namespace().as_str(),
        "service": review.service(),
        "tool": review.tool(),
        "origin": review.origin(),
        "method": review.method().as_str(),
        "path": review.path(),
        "credential": review.credential(),
        "operator_credential_header": header,
        "has_observation": review.has_observation(),
    })
}

fn derived_case(case: &Value, directory: &Path, derived: &auths_openapi_derive::Derived) {
    check_file(&directory.join("profile.toml"), derived.profile_toml());
    check_file(&directory.join("recipe.json"), derived.recipe_json());
    check_file(
        &directory.join("derivation.json"),
        derived.derivation_json(),
    );
    check_file(
        &directory.join("report.txt"),
        &format!("{}\n", derived.lines().join("\n")),
    );
    let lock_path = directory.join("profile.lock.json");
    let Ok(lock) = fs::read(&lock_path) else {
        assert!(
            updating(),
            "{}: run the Python lock step, then update again",
            case["id"]
        );
        return;
    };
    let lock_value: Value = serde_json::from_slice(&lock).unwrap();
    let recipe_value: Value = serde_json::from_str(derived.recipe_json()).unwrap();
    if updating()
        && (lock_value["schema_digest"] != recipe_value["profile_schema_digest"]
            || lock_value["tool"] != recipe_value["tool"])
    {
        // A stale lock: the Python lock step rewrites it, then a second
        // update run records the review.
        return;
    }
    assert_eq!(
        lock_value["schema_digest"], recipe_value["profile_schema_digest"],
        "{}: the packaged generator's schema digest must equal the derived recipe's",
        case["id"]
    );
    let review = review(derived.recipe_json(), &lock);
    let mut text = serde_json::to_string_pretty(&review).unwrap();
    text.push('\n');
    check_file(&directory.join("review.json"), &text);
}

fn rejected_case(directory: &Path, rejected: &auths_openapi_derive::Rejected) {
    let diagnostics: Vec<Value> = rejected
        .diagnostics()
        .iter()
        .map(|diagnostic| {
            json!({
                "code": diagnostic.code().as_str(),
                "pointer": diagnostic.pointer(),
                "overrides": diagnostic.overrides(),
            })
        })
        .collect();
    let mut text = serde_json::to_string_pretty(&diagnostics).unwrap();
    text.push('\n');
    check_file(&directory.join("rejections.json"), &text);
    check_file(
        &directory.join("report.txt"),
        &format!("{}\n", rejected.lines().join("\n")),
    );
    for diagnostic in rejected.diagnostics() {
        assert!(diagnostic.code().as_str().starts_with("contract.derive."));
        assert!(!diagnostic.message().is_empty());
    }
}

#[test]
fn every_corpus_case_produces_its_exact_output() {
    let mut skipped = Vec::new();
    let mut seen = BTreeSet::new();
    for case in cases() {
        let id = case["id"].as_str().unwrap();
        assert!(seen.insert(id.to_owned()), "duplicate case {id}");
        let Some((bytes, name)) = document(&case) else {
            skipped.push(id.to_owned());
            continue;
        };
        let directory = corpus().join("expected").join(id);
        let result = auths_openapi_derive::derive(&bytes, &name, &arguments(&case));
        let encoded: Value = serde_json::from_str(&auths_openapi_derive::derive_to_json(
            &bytes,
            &name,
            &arguments(&case),
        ))
        .unwrap();
        match (case["outcome"].as_str(), &result) {
            (Some("derived"), Ok(derived)) => {
                assert_eq!(encoded["ok"], true);
                assert_eq!(encoded["files"]["recipe.json"], derived.recipe_json());
                derived_case(&case, &directory, derived);
            }
            (Some("rejected"), Err(rejected)) => {
                assert_eq!(encoded["ok"], false);
                assert_eq!(
                    encoded["diagnostics"].as_array().unwrap().len(),
                    rejected.diagnostics().len()
                );
                rejected_case(&directory, rejected);
            }
            (outcome, Ok(derived)) => panic!(
                "{id}: expected {outcome:?}, derived:\n{}",
                derived.lines().join("\n")
            ),
            (outcome, Err(rejected)) => panic!(
                "{id}: expected {outcome:?}, rejected:\n{}",
                rejected.lines().join("\n")
            ),
        }
    }
    let on_disk: BTreeSet<String> = fs::read_dir(corpus().join("expected"))
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    let stale: Vec<&String> = on_disk.difference(&seen).collect();
    assert!(
        stale.is_empty(),
        "expected outputs without a case: {stale:?}"
    );
    if !skipped.is_empty() {
        eprintln!("vendor cases skipped without AUTHS_OPENAPI_CORPUS_DIR: {skipped:?}");
    }
}

#[test]
fn derivation_is_deterministic_and_order_independent() {
    let case = cases()
        .into_iter()
        .find(|case| case["id"] == "minimal-create-note")
        .unwrap();
    let (bytes, name) = document(&case).unwrap();
    let forward = arguments(&case);
    let mut pairs: Vec<[String; 2]> = forward
        .chunks(2)
        .map(|pair| [pair[0].clone(), pair[1].clone()])
        .collect();
    pairs.reverse();
    let reversed: Vec<String> = pairs.into_iter().flatten().collect();
    let first = auths_openapi_derive::derive(&bytes, &name, &forward).unwrap();
    let second = auths_openapi_derive::derive(&bytes, "renamed.json", &reversed).unwrap();
    assert_eq!(first.profile_toml(), second.profile_toml());
    assert_eq!(first.recipe_json(), second.recipe_json());
    assert_eq!(first.derivation_json(), second.derivation_json());
}

#[test]
fn a_changed_document_or_override_changes_the_provenance() {
    let case = cases()
        .into_iter()
        .find(|case| case["id"] == "minimal-create-note")
        .unwrap();
    let (bytes, name) = document(&case).unwrap();
    let base = auths_openapi_derive::derive(&bytes, &name, &arguments(&case)).unwrap();
    let mut edited = bytes.clone();
    edited.push(b'\n');
    let changed_document = auths_openapi_derive::derive(&edited, &name, &arguments(&case)).unwrap();
    assert_eq!(base.profile_toml(), changed_document.profile_toml());
    assert_ne!(base.derivation_json(), changed_document.derivation_json());
    let mut narrowed = arguments(&case);
    let at = narrowed
        .iter()
        .position(|value| value == "title=100")
        .unwrap();
    narrowed[at] = "title=80".to_owned();
    let changed_override = auths_openapi_derive::derive(&bytes, &name, &narrowed).unwrap();
    assert_ne!(base.profile_toml(), changed_override.profile_toml());
    assert_ne!(base.derivation_json(), changed_override.derivation_json());
}

fn derived(id: &str) -> Option<auths_openapi_derive::Derived> {
    let case = cases().into_iter().find(|case| case["id"] == id).unwrap();
    let (bytes, name) = document(&case)?;
    Some(auths_openapi_derive::derive(&bytes, &name, &arguments(&case)).unwrap())
}

fn fixture(name: &str) -> (Vec<u8>, Vec<u8>) {
    let directory = repository().join("bindings/fixtures/gateway").join(name);
    (
        fs::read(directory.join("recipe.json")).unwrap(),
        fs::read(directory.join("profile.lock.json")).unwrap(),
    )
}

fn expected_lock(id: &str) -> Vec<u8> {
    fs::read(corpus().join("expected").join(id).join("profile.lock.json")).unwrap()
}

#[test]
fn derived_airtable_and_todoist_recipes_compare_with_the_hand_authored_fixtures() {
    let (hand_recipe, hand_lock) = fixture("airtable");
    let hand = CompiledRecipe::compile(&hand_recipe, &hand_lock).unwrap();
    let airtable = derived("airtable-set-demo-status").unwrap();
    let ours = CompiledRecipe::compile(
        airtable.recipe_json().as_bytes(),
        &expected_lock("airtable-set-demo-status"),
    )
    .unwrap();
    // Same request target and credential requirement.
    assert_eq!(ours.review().origin(), hand.review().origin());
    assert_eq!(ours.review().method(), hand.review().method());
    assert_eq!(ours.review().path(), hand.review().path());
    assert_eq!(ours.review().credential(), hand.review().credential());
    assert_eq!(ours.namespace(), hand.namespace());
    assert_eq!(ours.review().tool(), hand.review().tool());
    // Different identity: the body field keeps its structural name, and the
    // hand-authored recipe adds a read-back observation and echo that
    // derivation does not produce.
    assert!(
        airtable
            .profile_toml()
            .contains("[arguments.fields.fields_DemoStatus]")
    );
    assert!(!airtable.profile_toml().contains("replacement"));
    assert!(hand.review().has_observation() && hand.review().echo().is_some());
    assert!(!ours.review().has_observation() && ours.review().echo().is_none());
    assert_ne!(ours.digest_hex(), hand.digest_hex());

    let (hand_recipe, hand_lock) = fixture("todoist");
    let hand = CompiledRecipe::compile(&hand_recipe, &hand_lock).unwrap();
    let todoist = derived("todoist-rest-create-task").unwrap();
    let ours = CompiledRecipe::compile(
        todoist.recipe_json().as_bytes(),
        &expected_lock("todoist-rest-create-task"),
    )
    .unwrap();
    // The hand-authored recipe is a different request: the sync endpoint with
    // a form-encoded command carrying the logical ID as its uuid.
    assert_eq!(ours.review().origin(), hand.review().origin());
    assert_eq!(ours.review().tool(), hand.review().tool());
    assert_eq!(ours.namespace(), hand.namespace());
    assert_eq!(ours.review().path(), ["api", "v1", "tasks"]);
    assert_eq!(hand.review().path(), ["api", "v1", "sync"]);
    assert_ne!(ours.digest_hex(), hand.digest_hex());
}

#[test]
fn vendor_todoist_derivation_equals_the_committed_excerpt() {
    let (Some(vendor), Some(excerpt)) = (
        derived("todoist-create-task"),
        derived("todoist-rest-create-task"),
    ) else {
        eprintln!("skipped: AUTHS_OPENAPI_CORPUS_DIR is not set");
        return;
    };
    assert_eq!(vendor.profile_toml(), excerpt.profile_toml());
    assert_eq!(vendor.recipe_json(), excerpt.recipe_json());
}

#[test]
fn derived_github_request_equals_the_hand_authored_request_up_to_profile_bounds() {
    let Some(github) = derived("github-issues-create-fixed-repository") else {
        eprintln!("skipped: AUTHS_OPENAPI_CORPUS_DIR is not set");
        return;
    };
    let (hand_recipe, hand_lock) = fixture("github");
    let hand = CompiledRecipe::compile(&hand_recipe, &hand_lock).unwrap();
    let ours = CompiledRecipe::compile(
        github.recipe_json().as_bytes(),
        &expected_lock("github-issues-create-fixed-repository"),
    )
    .unwrap();
    // The profiles differ only in bounds the document does not state: the
    // hand-authored profile requires a 1-byte title and caps operation IDs at
    // 64 bytes, so the digests differ.
    assert_ne!(ours.digest_hex(), hand.digest_hex());
    // With the hand-authored profile digest substituted, the derived request
    // compiles to exactly the hand-authored recipe digest.
    let hand_source: Value = serde_json::from_slice(&hand_recipe).unwrap();
    let mut substituted: Value = serde_json::from_str(github.recipe_json()).unwrap();
    substituted["profile_schema_digest"] = hand_source["profile_schema_digest"].clone();
    let same =
        CompiledRecipe::compile(&serde_json::to_vec(&substituted).unwrap(), &hand_lock).unwrap();
    assert_eq!(same.digest_hex(), hand.digest_hex());
}

#[test]
fn vendor_rejection_walls_match_the_published_corpus() {
    let manifest = read_json(&repository().join("bindings/fixtures/openapi-corpus/cases.json"));
    for (vendor, id) in [
        ("GitHub", "github-issues-create-unmodified"),
        ("Todoist", "todoist-create-task-unmodified"),
        ("OpenAI", "openai-create-vector-store-unmodified"),
    ] {
        let case = cases().into_iter().find(|case| case["id"] == id).unwrap();
        let Some((bytes, name)) = document(&case) else {
            eprintln!("skipped {vendor}: AUTHS_OPENAPI_CORPUS_DIR is not set");
            continue;
        };
        let published = manifest["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["vendor"] == vendor)
            .unwrap();
        let expected: BTreeSet<&str> = published["unmodifiedRejections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["pointer"].as_str().unwrap())
            .collect();
        let rejected = auths_openapi_derive::derive(&bytes, &name, &arguments(&case)).unwrap_err();
        let actual: BTreeSet<&str> = rejected
            .diagnostics()
            .iter()
            .map(auths_openapi_derive::Diagnostic::pointer)
            .collect();
        assert_eq!(actual, expected, "{vendor} rejection wall");
        let mut candidate = arguments(&case);
        for override_ in published["candidateOverrides"].as_array().unwrap() {
            let (flag, value) = override_.as_str().unwrap().split_once(' ').unwrap();
            candidate.extend([flag.to_owned(), value.to_owned()]);
        }
        assert!(
            auths_openapi_derive::derive(&bytes, &name, &candidate).is_ok(),
            "{vendor} candidate overrides derive"
        );
    }
}
