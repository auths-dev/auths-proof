#![forbid(unsafe_code)]

use auths_proof_author::ProofBundleBuilder;
use auths_proof_codec::{action_id, encode_bundle, grant_id};
use auths_proof_model::{
    Decision, PrincipalEvidenceEntry, SignatureBytes, SignatureEnvelope, SignedAction, StatementId,
    VerdictReason,
};
use auths_proof_testkit::{
    assert_milestone_one_conformance, assert_milestone_three_conformance,
    assert_milestone_two_conformance, did_key_root_did_web_agent_fixture,
    historical_did_web_without_statement_fixture, historically_pinned_did_web_fixture,
    keri_root_raw_agent_fixture, milestone_one_fixture, raw_root_keri_agent_fixture,
    verify_milestone_fixture, ACTION_BODY,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".into());
    match command.as_str() {
        "ci" => ci(),
        "arch" => arch(),
        "wire" => wire(args.any(|arg| arg == "--update")),
        "conformance" => {
            assert_milestone_one_conformance();
            assert_milestone_two_conformance();
            assert_milestone_three_conformance();
            println!("adapter and Milestones 1-3 conformance passed");
            Ok(())
        }
        "wasm" => wasm(),
        "fuzz-smoke" => cargo(&[
            "test",
            "-p",
            "auths-proof-verifier",
            "arbitrary_bytes_never_panic",
        ]),
        "release-check" => release_check(),
        _ => {
            println!(
                "usage: cargo xtask <ci|arch|wire [--update]|conformance|wasm|fuzz-smoke|release-check>"
            );
            Ok(())
        }
    }
}

fn ci() -> Result<(), String> {
    cargo(&["fmt", "--all", "--check"])?;
    cargo(&["check", "--workspace", "--all-targets", "--all-features"])?;
    cargo(&["test", "--workspace", "--all-features"])?;
    cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--",
        "-D",
        "warnings",
    ])?;
    arch()?;
    wire(false)?;
    assert_milestone_one_conformance();
    assert_milestone_two_conformance();
    assert_milestone_three_conformance();
    println!("adapter and Milestones 1-3 conformance passed");
    cargo(&[
        "test",
        "-p",
        "auths-proof-verifier",
        "arbitrary_bytes_never_panic",
    ])?;
    wasm()
}

fn release_check() -> Result<(), String> {
    ci()?;
    cargo(&["test", "--workspace", "--no-default-features"])?;
    println!("release checks passed");
    Ok(())
}

fn cargo(args: &[&str]) -> Result<(), String> {
    let status = Command::new("cargo")
        .args(args)
        .current_dir(root())
        .status()
        .map_err(|error| format!("could not run cargo: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("cargo {} failed with {status}", args.join(" ")))
    }
}

fn wasm() -> Result<(), String> {
    for package in [
        "auths-proof-verifier",
        "auths-proof-raw-key",
        "auths-proof-multikey",
        "auths-proof-did-key",
        "auths-proof-did-keri",
        "auths-proof-did-web",
    ] {
        cargo(&[
            "check",
            "-p",
            package,
            "--target",
            "wasm32-unknown-unknown",
            "--no-default-features",
        ])?;
    }
    Ok(())
}

fn arch() -> Result<(), String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not run cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err("cargo metadata failed".into());
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("invalid cargo metadata JSON: {error}"))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages")?;

    let workspace_names: BTreeSet<String> = packages
        .iter()
        .filter_map(|package| package["name"].as_str().map(String::from))
        .collect();
    let allowed: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::from([
        ("auths-proof-model", BTreeSet::new()),
        ("auths-proof-codec", BTreeSet::from(["auths-proof-model"])),
        (
            "auths-proof-adapter-api",
            BTreeSet::from(["auths-proof-model"]),
        ),
        (
            "auths-proof-verifier",
            BTreeSet::from([
                "auths-proof-model",
                "auths-proof-codec",
                "auths-proof-adapter-api",
                "auths-proof-author",
                "auths-proof-raw-key",
                "proptest",
            ]),
        ),
        (
            "auths-proof-author",
            BTreeSet::from(["auths-proof-model", "auths-proof-codec"]),
        ),
        (
            "auths-proof-raw-key",
            BTreeSet::from([
                "auths-proof-model",
                "auths-proof-codec",
                "auths-proof-adapter-api",
            ]),
        ),
        ("auths-proof-multikey", BTreeSet::new()),
        (
            "auths-proof-did-key",
            BTreeSet::from([
                "auths-proof-model",
                "auths-proof-codec",
                "auths-proof-adapter-api",
                "auths-proof-multikey",
            ]),
        ),
        (
            "auths-proof-did-keri",
            BTreeSet::from([
                "auths-proof-model",
                "auths-proof-codec",
                "auths-proof-adapter-api",
            ]),
        ),
        (
            "auths-proof-did-web",
            BTreeSet::from([
                "auths-proof-model",
                "auths-proof-codec",
                "auths-proof-adapter-api",
                "auths-proof-multikey",
            ]),
        ),
        (
            "auths-proof-did-web-http",
            BTreeSet::from(["auths-proof-model", "auths-proof-did-web"]),
        ),
    ]);
    let forbidden_external = [
        "tokio", "reqwest", "hyper", "git2", "sqlx", "rusqlite", "keyring",
    ];

    for package in packages {
        let Some(name) = package["name"].as_str() else {
            continue;
        };
        let Some(allowed_dependencies) = allowed.get(name) else {
            continue;
        };
        let dependencies = package["dependencies"]
            .as_array()
            .ok_or("package dependencies are not an array")?;
        for dependency in dependencies {
            let dependency_name = dependency["name"]
                .as_str()
                .ok_or("dependency has no name")?;
            let is_dev = dependency["kind"].as_str() == Some("dev");
            if forbidden_external.contains(&dependency_name) && name != "auths-proof-did-web-http" {
                return Err(format!(
                    "forbidden dependency edge: {name} -> {dependency_name}"
                ));
            }
            if workspace_names.contains(dependency_name)
                && !allowed_dependencies.contains(dependency_name)
                && !is_dev
            {
                return Err(format!(
                    "disallowed workspace edge: {name} -> {dependency_name}"
                ));
            }
        }
    }
    println!("architecture dependency rules passed");
    Ok(())
}

fn wire(update: bool) -> Result<(), String> {
    let generated = generated_vectors()?;
    let fixture_root = root().join("fixtures/v1");
    if update {
        for (relative, bytes) in &generated {
            let path = fixture_root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
            }
            fs::write(&path, bytes)
                .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        }
        println!("updated {} golden vector files", generated.len());
        return Ok(());
    }

    for (relative, expected) in &generated {
        let path = fixture_root.join(relative);
        let actual = fs::read(&path)
            .map_err(|error| format!("missing golden vector {}: {error}", path.display()))?;
        if &actual != expected {
            return Err(format!(
                "golden vector {} changed; review and run `cargo xtask wire --update`",
                path.display()
            ));
        }
    }
    println!("{} golden vector files are byte-stable", generated.len());
    Ok(())
}

fn generated_vectors() -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    let mut fixture = milestone_one_fixture();
    let valid = fixture.encoded.clone();
    let keri_root_raw_agent = keri_root_raw_agent_fixture().encoded;
    let raw_root_keri_agent = raw_root_keri_agent_fixture().encoded;
    let did_web_current = did_key_root_did_web_agent_fixture();
    let did_web_historical = historically_pinned_did_web_fixture();
    let did_web_without_statement = historical_did_web_without_statement_fixture();
    if did_web_current.encoded != did_web_historical.encoded
        || did_web_current.encoded != did_web_without_statement.encoded
    {
        return Err("did:web trust mode changed the bundled proof bytes".into());
    }
    let did_web_bundle = did_web_current.encoded.clone();
    let did_web_current_trust = did_web_current.did_web_trust[0]
        .encode()
        .map_err(|error| error.to_string())?;
    let did_web_historical_trust = did_web_historical.did_web_trust[0]
        .encode()
        .map_err(|error| error.to_string())?;
    let did_web_incomplete_trust = did_web_without_statement.did_web_trust[0]
        .encode()
        .map_err(|error| error.to_string())?;
    let invalid = invalid_signature_bundle(&fixture)?;
    fixture.encoded = invalid.clone();
    let invalid_verdict = verify_milestone_fixture(&fixture, &fixture.body);
    if invalid_verdict.decision() != Decision::Denied
        || invalid_verdict.reasons() != [VerdictReason::InvalidSignature]
    {
        return Err(format!(
            "invalid-signature vector produced unexpected verdict: {:?} {:?}",
            invalid_verdict.decision(),
            invalid_verdict.reasons()
        ));
    }
    let valid_digest = hex::encode(Sha256::digest(&valid));
    let keri_root_raw_agent_digest = hex::encode(Sha256::digest(&keri_root_raw_agent));
    let raw_root_keri_agent_digest = hex::encode(Sha256::digest(&raw_root_keri_agent));
    let did_web_bundle_digest = hex::encode(Sha256::digest(&did_web_bundle));
    let did_web_current_trust_digest = hex::encode(Sha256::digest(&did_web_current_trust));
    let did_web_historical_trust_digest = hex::encode(Sha256::digest(&did_web_historical_trust));
    let did_web_incomplete_trust_digest = hex::encode(Sha256::digest(&did_web_incomplete_trust));
    let invalid_digest = hex::encode(Sha256::digest(&invalid));
    let body_digest = hex::encode(Sha256::digest(ACTION_BODY));
    let manifest = serde_json::to_vec_pretty(&json!({
        "protocol_version": 1,
        "fixture_set": "v1",
        "fixtures": [
            {
                "path": "valid/mixed-ed25519-p256.cbor",
                "kind": "valid",
                "sha256": valid_digest,
                "expected_decision": "Authorized"
            },
            {
                "path": "valid/keri-root-raw-key-agent.cbor",
                "kind": "valid",
                "sha256": keri_root_raw_agent_digest,
                "expected_decision": "Authorized"
            },
            {
                "path": "valid/raw-key-root-keri-agent.cbor",
                "kind": "valid",
                "sha256": raw_root_keri_agent_digest,
                "expected_decision": "Authorized"
            },
            {
                "path": "valid/did-key-root-did-web-agent.cbor",
                "kind": "valid",
                "sha256": did_web_bundle_digest,
                "expected_decision": "Authorized",
                "requires_trust": "trust/did-web-current.trust"
            },
            {
                "path": "trust/did-web-current.trust",
                "kind": "did-web-current-trust",
                "sha256": did_web_current_trust_digest
            },
            {
                "path": "trust/did-web-historical.trust",
                "kind": "did-web-historical-trust",
                "sha256": did_web_historical_trust_digest
            },
            {
                "path": "trust/did-web-historical-without-statement.trust",
                "kind": "did-web-incomplete-historical-trust",
                "sha256": did_web_incomplete_trust_digest,
                "expected_decision": "Indeterminate",
                "expected_reason": "HistoricalStateUnavailable"
            },
            {
                "path": "invalid/invalid-action-signature.cbor",
                "kind": "invalid",
                "sha256": invalid_digest,
                "expected_decision": "Denied",
                "expected_reason": "InvalidSignature"
            },
            {
                "path": "valid/action.json",
                "kind": "action-body",
                "sha256": body_digest
            }
        ]
    }))
    .map_err(|error| format!("could not encode fixture manifest: {error}"))?;

    Ok(BTreeMap::from([
        (PathBuf::from("valid/mixed-ed25519-p256.cbor"), valid),
        (
            PathBuf::from("valid/keri-root-raw-key-agent.cbor"),
            keri_root_raw_agent,
        ),
        (
            PathBuf::from("valid/raw-key-root-keri-agent.cbor"),
            raw_root_keri_agent,
        ),
        (
            PathBuf::from("valid/did-key-root-did-web-agent.cbor"),
            did_web_bundle,
        ),
        (
            PathBuf::from("trust/did-web-current.trust"),
            did_web_current_trust,
        ),
        (
            PathBuf::from("trust/did-web-historical.trust"),
            did_web_historical_trust,
        ),
        (
            PathBuf::from("trust/did-web-historical-without-statement.trust"),
            did_web_incomplete_trust,
        ),
        (
            PathBuf::from("invalid/invalid-action-signature.cbor"),
            invalid,
        ),
        (PathBuf::from("valid/action.json"), ACTION_BODY.to_vec()),
        (PathBuf::from("manifest.json"), manifest),
    ]))
}

fn invalid_signature_bundle(
    fixture: &auths_proof_testkit::MilestoneOneFixture,
) -> Result<Vec<u8>, String> {
    let original_action = fixture.bundle.action();
    let mut signature = original_action.signature().signature().as_slice().to_vec();
    let first = signature
        .first_mut()
        .ok_or("fixture action has an empty signature")?;
    *first ^= 0x01;
    let action = SignedAction::new(
        original_action.payload().clone(),
        SignatureEnvelope::new(
            original_action.signature().descriptor().clone(),
            SignatureBytes::new(signature).map_err(|error| error.to_string())?,
        ),
    );
    let action_evidence = evidence_for(
        &fixture.bundle,
        StatementId::Action(action_id(original_action)),
    )?
    .clone();
    let mut builder =
        ProofBundleBuilder::new(action, action_evidence).map_err(|error| error.to_string())?;
    for grant in fixture.bundle.grants() {
        let evidence = evidence_for(&fixture.bundle, StatementId::Grant(grant_id(grant)))?.clone();
        builder = builder
            .push_grant(grant.clone(), evidence)
            .map_err(|error| error.to_string())?;
    }
    encode_bundle(&builder.build().map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}

fn evidence_for(
    bundle: &auths_proof_model::ProofBundle,
    statement: StatementId,
) -> Result<&PrincipalEvidenceEntry, String> {
    let binding = bundle
        .principal_evidence_bindings()
        .iter()
        .find(|binding| binding.statement() == statement)
        .ok_or("fixture has no evidence binding")?;
    bundle
        .principal_evidence()
        .iter()
        .find(|evidence| evidence.id() == binding.evidence())
        .ok_or_else(|| "fixture has no bound evidence".into())
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is inside repository root")
        .to_path_buf()
}
