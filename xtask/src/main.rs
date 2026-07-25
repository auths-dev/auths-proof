#![forbid(unsafe_code)]

use auths_testkit::Expected;
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
        "spec-sync" => spec_sync(),
        "conformance" => target_conformance(),
        "semantic-digest" => semantic_digest(),
        "wasm" => wasm(),
        "fuzz-smoke" => fuzz_smoke(),
        "release-check" => release_check(),
        _ => {
            println!(
                "usage: cargo xtask <ci|arch|wire [--update]|spec-sync|conformance|semantic-digest|wasm|fuzz-smoke|release-check>"
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
    spec_sync()?;
    wire(false)?;
    target_conformance()?;
    fuzz_smoke()?;
    wasm()
}

fn spec_sync() -> Result<(), String> {
    use auths_model::{DenialReason as D, Requirement as R};

    let denied = [
        D::MalformedProof,
        D::NonCanonicalProof,
        D::ResourceLimitExceeded,
        D::DigestMismatch,
        D::DuplicateObject,
        D::MissingReference,
        D::ReferenceCycle,
        D::AmbiguousTerminalGrant,
        D::UnusedCriticalEvidence,
        D::InvalidSignature,
        D::PrincipalMethodMismatch,
        D::VerificationMethodMismatch,
        D::SignatureSuiteMismatch,
        D::UntrustedRoot,
        D::BrokenGrantChain,
        D::DelegationExpanded,
        D::PermissionNotGranted,
        D::ActionConstraintMismatch,
        D::BudgetCeilingExceeded,
        D::AuthorizationPlanInvalid,
        D::PlanActionMismatch,
        D::ActionBodyMismatch,
        D::AudienceMismatch,
        D::ChallengeMismatch,
        D::ActionOutsideValidity,
        D::PrincipalRevoked,
        D::GrantRevoked,
        D::StatusSequenceRollback,
        D::StatusMethodMismatch,
        D::StatusIssuerUntrusted,
        D::RegistryManifestMismatch,
        D::ResourceNamespaceMismatch,
        D::CriticalExtensionUnknown,
        D::AttachmentMissing,
        D::AttachmentDigestMismatch,
        D::AttachmentLengthMismatch,
        D::DuplicateAttachment,
        D::UnusedCriticalAttachment,
        D::OpaqueAttachmentNotAllowed,
        D::LocalPolicyDenied,
    ];
    let indeterminate = [
        R::UnsupportedProtocol,
        R::UnsupportedPrincipalMethod,
        R::UnsupportedSignatureSuite,
        R::UnsupportedEvidenceType,
        R::UnsupportedStatusMethod,
        R::UnsupportedProfile,
        R::UnsupportedProfilePolicy,
        R::UnsupportedResourceMatcher,
        R::UnsupportedBudgetAlgebra,
        R::UnsupportedCriticalExtension,
        R::UnsupportedAssuranceClaim,
        R::MissingPrincipalEvidence,
        R::MissingPrincipalStatus,
        R::MissingGrantStatus,
        R::StaleStatus,
        R::HistoricalStateUnavailable,
        R::AssuranceRequirementNotMet,
        R::ExternalFactUnavailable,
    ];
    let errors = fs::read_to_string(root().join("spec/v1/error-codes.md"))
        .map_err(|error| format!("could not read error registry: {error}"))?;
    for code in denied
        .iter()
        .map(|value| value.code())
        .chain(indeterminate.iter().map(|value| value.code()))
    {
        if !errors.contains(&format!("`{code}`")) {
            return Err(format!(
                "stable result code {code} is absent from error-codes.md"
            ));
        }
    }
    let reserved = BTreeSet::from([
        D::AmbiguousTerminalGrant.code(),
        D::AuthorizationPlanInvalid.code(),
        D::ReferenceCycle.code(),
    ]);
    let manifest_bytes = fs::read(root().join("fixtures/v1/manifest.json"))
        .map_err(|error| format!("could not read corpus manifest: {error}"))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("could not parse corpus manifest: {error}"))?;
    let fixtures = manifest
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| "corpus manifest has no fixtures array".to_owned())?;
    let covered: BTreeSet<&str> = fixtures
        .iter()
        .filter_map(|fixture| fixture.get("expected_code").and_then(Value::as_str))
        .collect();
    for code in denied
        .iter()
        .map(|value| value.code())
        .chain(indeterminate.iter().map(|value| value.code()))
    {
        if reserved.contains(code) {
            if covered.contains(code) {
                return Err(format!(
                    "reserved V1 result code {code} has a corpus vector"
                ));
            }
        } else if !covered.contains(code) {
            return Err(format!(
                "implemented V1 result code {code} has no committed corpus vector"
            ));
        }
    }
    if !covered.contains("authorized") {
        return Err("authorized V1 result has no committed corpus vector".to_owned());
    }
    let registry = fs::read_to_string(root().join("spec/v1/registry.md"))
        .map_err(|error| format!("could not read registry specification: {error}"))?;
    for identifier in [
        auths_registries::URI_NAMESPACE_V1,
        auths_registries::EXACT_PROFILE_V1,
        auths_registries::NUMERIC_CEILING_V1,
        auths_registries::EXACT_MARKER_EXTENSION_V1,
    ] {
        if !registry.contains(&format!("`{identifier}`")) {
            return Err(format!(
                "executable registry ID {identifier} is undocumented"
            ));
        }
    }
    println!("specification, registry, and result-code registries are synchronized");
    Ok(())
}

fn release_check() -> Result<(), String> {
    ci()?;
    cargo(&["test", "--workspace", "--no-default-features"])?;
    wire(false)?;
    println!("release checks passed");
    Ok(())
}

const FUZZ_TARGETS: [&str; 7] = [
    "target_codec",
    "target_portable_codecs",
    "target_model_state",
    "target_composition",
    "target_registry_handlers",
    "target_principal_parsers",
    "target_portable_abi",
];

fn fuzz_smoke() -> Result<(), String> {
    cargo(&["check", "--manifest-path", "fuzz/Cargo.toml", "--bins"])?;
    for target in FUZZ_TARGETS {
        let corpus = format!("fuzz/corpus/{target}");
        cargo(&[
            "run",
            "--manifest-path",
            "fuzz/Cargo.toml",
            "--bin",
            target,
            "--",
            &corpus,
            "-runs=8",
            "-max_len=4096",
            "-timeout=5",
        ])?;
    }
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
        "auths-proof",
        "auths-proof-wasm",
        "auths-model",
        "auths-codec",
        "auths-ports",
        "auths-registries",
        "auths-signature",
        "auths-authority",
        "auths-composition",
        "auths-assurance",
        "auths-status",
        "auths-verifier",
        "auths-author",
        "auths-multikey",
        "auths-raw-key",
        "auths-did-key",
        "auths-did-keri",
        "auths-did-web",
        "auths-hsm-attested",
        "auths-spiffe-x509",
        "auths-webauthn",
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

fn target_conformance() -> Result<(), String> {
    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(|error| error.to_string())?;
    let did_web = auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
        .map_err(|error| error.to_string())?;
    let webauthn =
        auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
            .map_err(|error| error.to_string())?;
    let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
        .map_err(|error| error.to_string())?;
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
        .map_err(|error| error.to_string())?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
        &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .map_err(|error| error.to_string())?;
    for fixture in auths_testkit::corpus() {
        let context = auths_codec::decode_verifier_context(fixture.context_bytes())
            .map_err(|error| format!("{} context: {error}", fixture.name()))?;
        let actual = auths_verifier::verify(
            fixture.proof_bytes(),
            fixture.canonical_action(),
            &context,
            &registries,
        );
        let matches = match (fixture.expected(), &actual) {
            (Expected::Authorized, auths_verifier::VerificationOutcome::Authorized(_)) => true,
            (Expected::Denied(expected), auths_verifier::VerificationOutcome::Denied(actual)) => {
                expected == *actual
            }
            (
                Expected::Indeterminate(expected),
                auths_verifier::VerificationOutcome::Indeterminate(actual),
            ) => expected == *actual,
            _ => false,
        };
        if !matches {
            return Err(format!(
                "{} expected {:?}, got {actual:?}",
                fixture.name(),
                fixture.expected()
            ));
        }
    }
    println!("target V1 canonical corpus conformance passed");
    Ok(())
}

fn semantic_digest() -> Result<(), String> {
    use auths_model::ParticipantRole;
    use auths_verifier::VerificationOutcome;

    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(|error| error.to_string())?;
    let did_web = auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
        .map_err(|error| error.to_string())?;
    let webauthn =
        auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
            .map_err(|error| error.to_string())?;
    let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
        .map_err(|error| error.to_string())?;
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
        .map_err(|error| error.to_string())?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
        &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .map_err(|error| error.to_string())?;
    let fixtures = auths_testkit::corpus();
    let mut summary = Sha256::new();
    for fixture in &fixtures {
        let context = auths_codec::decode_verifier_context(fixture.context_bytes())
            .map_err(|error| format!("{} context: {error}", fixture.name()))?;
        let outcome = auths_verifier::verify(
            fixture.proof_bytes(),
            fixture.canonical_action(),
            &context,
            &registries,
        );
        let (decision, code) = match &outcome {
            VerificationOutcome::Authorized(_) => ("authorized", "authorized"),
            VerificationOutcome::Denied(reason) => ("denied", reason.code()),
            VerificationOutcome::Indeterminate(requirement) => {
                ("indeterminate", requirement.code())
            }
        };
        let matches = match (fixture.expected(), &outcome) {
            (Expected::Authorized, VerificationOutcome::Authorized(_)) => true,
            (Expected::Denied(expected), VerificationOutcome::Denied(actual)) => {
                expected == *actual
            }
            (Expected::Indeterminate(expected), VerificationOutcome::Indeterminate(actual)) => {
                expected == *actual
            }
            _ => false,
        };
        if !matches {
            return Err(format!(
                "{} expected {:?}, got {outcome:?}",
                fixture.name(),
                fixture.expected()
            ));
        }
        let proof_digest = Sha256::digest(fixture.proof_bytes());
        let context_digest =
            auths_codec::context_digest(&context).map_err(|error| error.to_string())?;
        let action_bytes = auths_codec::encode_canonical_action(fixture.canonical_action())
            .map_err(|error| error.to_string())?;
        let action_digest = Sha256::digest(action_bytes);
        let plan = auths_verifier::decode_proof(fixture.proof_bytes(), &context)
            .ok()
            .and_then(|decoded| auths_codec::plan_id(decoded.bundle().plan()).ok());
        write_field(&mut summary, fixture.name());
        write_field(&mut summary, decision);
        write_field(&mut summary, code);
        write_bytes(&mut summary, &proof_digest);
        write_bytes(&mut summary, context_digest.as_bytes());
        write_bytes(&mut summary, &action_digest);
        write_bytes(
            &mut summary,
            plan.as_ref()
                .map_or(&[][..], |identifier| identifier.as_bytes()),
        );
        if let VerificationOutcome::Authorized(action) = &outcome {
            for identifier in action.action_ids() {
                write_bytes(&mut summary, identifier.as_bytes());
            }
            write_field(&mut summary, "|");
            for reference in action.authorized_branches() {
                write_bytes(&mut summary, reference.as_bytes());
            }
            write_field(&mut summary, "|");
            for report in action.assurance() {
                write_field(&mut summary, report.principal().as_str());
                write_field(
                    &mut summary,
                    match report.role() {
                        ParticipantRole::Root => "0",
                        ParticipantRole::Intermediate => "1",
                        ParticipantRole::Actor => "2",
                        ParticipantRole::ExternalIssuer => "3",
                    },
                );
                write_field(&mut summary, report.adapter().as_str());
                for claim in report.claims() {
                    write_field(&mut summary, claim.kind().as_str());
                    write_field(
                        &mut summary,
                        &claim
                            .observed_at()
                            .map_or_else(|| "-".to_owned(), |value| value.get().to_string()),
                    );
                }
                write_field(&mut summary, ";");
            }
        } else {
            write_field(&mut summary, "|");
            write_field(&mut summary, "|");
        }
        write_field(&mut summary, "\n");
    }
    println!("{}:{}", fixtures.len(), hex::encode(summary.finalize()));
    Ok(())
}

fn write_field(summary: &mut Sha256, value: &str) {
    summary.update(value.as_bytes());
    summary.update([0]);
}

fn write_bytes(summary: &mut Sha256, value: &[u8]) {
    write_field(summary, &hex::encode(value));
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
        (
            "auths-proof",
            BTreeSet::from([
                "auths-author",
                "auths-codec",
                "auths-model",
                "auths-ports",
                "auths-registries",
                "auths-verifier",
            ]),
        ),
        (
            "auths-proof-wasm",
            BTreeSet::from([
                "auths-codec",
                "auths-did-keri",
                "auths-did-key",
                "auths-model",
                "auths-ports",
                "auths-raw-key",
                "auths-registries",
                "auths-signature",
                "auths-testkit",
                "auths-verifier",
            ]),
        ),
        ("auths-model", BTreeSet::new()),
        ("auths-codec", BTreeSet::from(["auths-model"])),
        ("auths-ports", BTreeSet::from(["auths-model"])),
        (
            "auths-registries",
            BTreeSet::from(["auths-model", "auths-ports"]),
        ),
        (
            "auths-signature",
            BTreeSet::from(["auths-model", "auths-ports"]),
        ),
        ("auths-authority", BTreeSet::from(["auths-model"])),
        ("auths-composition", BTreeSet::from(["auths-model"])),
        ("auths-assurance", BTreeSet::from(["auths-model"])),
        ("auths-status", BTreeSet::from(["auths-model"])),
        (
            "auths-verifier",
            BTreeSet::from([
                "auths-model",
                "auths-codec",
                "auths-ports",
                "auths-registries",
                "auths-authority",
                "auths-composition",
                "auths-assurance",
                "auths-status",
                "auths-raw-key",
                "auths-signature",
                "auths-testkit",
            ]),
        ),
        (
            "auths-author",
            BTreeSet::from(["auths-model", "auths-codec"]),
        ),
        ("auths-multikey", BTreeSet::new()),
        (
            "auths-raw-key",
            BTreeSet::from(["auths-model", "auths-ports"]),
        ),
        (
            "auths-did-key",
            BTreeSet::from(["auths-model", "auths-multikey", "auths-ports"]),
        ),
        (
            "auths-did-keri",
            BTreeSet::from(["auths-model", "auths-ports"]),
        ),
        (
            "auths-did-web",
            BTreeSet::from(["auths-model", "auths-multikey", "auths-ports"]),
        ),
        (
            "auths-hsm-attested",
            BTreeSet::from(["auths-model", "auths-ports"]),
        ),
        (
            "auths-spiffe-x509",
            BTreeSet::from(["auths-model", "auths-ports"]),
        ),
        (
            "auths-webauthn",
            BTreeSet::from(["auths-model", "auths-ports"]),
        ),
        (
            "auths-testkit",
            BTreeSet::from([
                "auths-model",
                "auths-codec",
                "auths-author",
                "auths-did-key",
                "auths-did-keri",
                "auths-did-web",
                "auths-hsm-attested",
                "auths-multikey",
                "auths-raw-key",
                "auths-signature",
                "auths-spiffe-x509",
                "auths-webauthn",
            ]),
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
            if name == "xtask" {
                continue;
            }
            return Err(format!(
                "unknown workspace package {name}; assign an architecture layer or tooling exemption"
            ));
        };
        let dependencies = package["dependencies"]
            .as_array()
            .ok_or("package dependencies are not an array")?;
        for dependency in dependencies {
            let dependency_name = dependency["name"]
                .as_str()
                .ok_or("dependency has no name")?;
            let is_dev = dependency["kind"].as_str() == Some("dev");
            if forbidden_external.contains(&dependency_name) {
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
        for relative in fixture_inventory(&fixture_root)? {
            if !generated.contains_key(&relative) {
                fs::remove_file(fixture_root.join(&relative)).map_err(|error| {
                    format!(
                        "could not remove stale fixture {}: {error}",
                        relative.display()
                    )
                })?;
            }
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
    let actual = fixture_inventory(&fixture_root)?;
    let expected: BTreeSet<_> = generated.keys().cloned().collect();
    if actual != expected {
        let stale: Vec<_> = actual.difference(&expected).collect();
        let missing: Vec<_> = expected.difference(&actual).collect();
        return Err(format!(
            "fixture inventory mismatch; stale={stale:?}, missing={missing:?}"
        ));
    }
    println!("{} golden vector files are byte-stable", generated.len());
    Ok(())
}

fn generated_vectors() -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(|error| error.to_string())?;
    let did_web = auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
        .map_err(|error| error.to_string())?;
    let webauthn =
        auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
            .map_err(|error| error.to_string())?;
    let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
        .map_err(|error| error.to_string())?;
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
        .map_err(|error| error.to_string())?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
        &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .map_err(|error| error.to_string())?;
    let mut generated = BTreeMap::new();
    let mut entries = Vec::new();
    for fixture in auths_testkit::corpus() {
        let directory = fixture.class();
        let proof_path = format!("{directory}/{}.proof.cbor", fixture.name());
        let context_path = format!("{directory}/{}.context.cbor", fixture.name());
        let action_path = format!("{directory}/{}.action.cbor", fixture.name());
        let body_path = format!("{directory}/{}.body.cbor", fixture.name());
        let result_path = format!("{directory}/{}.result.cbor", fixture.name());
        let action_bytes = auths_codec::encode_canonical_action(fixture.canonical_action())
            .map_err(|error| format!("{} action: {error}", fixture.name()))?;
        let result_bytes = auths_verifier::verify_v1(
            fixture.proof_bytes(),
            &action_bytes,
            fixture.context_bytes(),
            &registries,
        )
        .map_err(|error| format!("{} portable ABI: {error}", fixture.name()))?;
        let result = auths_codec::decode_verification_result(&result_bytes)
            .map_err(|error| format!("{} result: {error}", fixture.name()))?;
        let (expected_decision, expected_code) = match fixture.expected() {
            Expected::Authorized => ("authorized", "authorized"),
            Expected::Denied(reason) => ("denied", reason.code()),
            Expected::Indeterminate(requirement) => ("indeterminate", requirement.code()),
        };
        entries.push(json!({
            "name": fixture.name(),
            "class": directory,
            "proof": {
                "path": proof_path,
                "sha256": hex::encode(Sha256::digest(fixture.proof_bytes())),
            },
            "context": {
                "path": context_path,
                "sha256": hex::encode(Sha256::digest(fixture.context_bytes())),
            },
            "canonical_action": {
                "path": action_path,
                "sha256": hex::encode(Sha256::digest(&action_bytes)),
                "profile": fixture.canonical_action().profile().id().as_str(),
                "profile_version": fixture.canonical_action().profile().version(),
                "media_type": fixture.canonical_action().media_type().as_str(),
                "capability": fixture.canonical_action().permission().capability().as_str(),
                "resource": fixture.canonical_action().permission().resource().as_str(),
                "requested_budget": fixture.canonical_action().requested_budget().map(|budget| {
                    json!({
                        "algebra": budget.algebra().as_str(),
                        "value": budget.value(),
                    })
                }),
            },
            "canonical_body": {
                "path": body_path,
                "sha256": hex::encode(Sha256::digest(fixture.canonical_action().body())),
            },
            "expected_result": {
                "path": result_path,
                "sha256": hex::encode(Sha256::digest(&result_bytes)),
                "stage": format!("{:?}", result.stage()).to_ascii_lowercase(),
                "decision": expected_decision,
                "code": expected_code,
                "proof_digest": hex::encode(result.proof_digest().as_bytes()),
                "action_digest": hex::encode(result.action_digest().as_bytes()),
                "context_digest": hex::encode(result.context_digest().as_bytes()),
                "plan_digest": result.plan_id().map(|id| hex::encode(id.as_bytes())),
                "result_digest": hex::encode(result.result_digest().as_bytes()),
                "authorized_branches": result.authorized_branches().iter()
                    .map(|id| hex::encode(id.as_bytes())).collect::<Vec<_>>(),
                "assurance_satisfactions": result.assurance_satisfactions().len(),
                "resources": {
                    "proof_bytes": result.resources().proof_bytes(),
                    "action_bytes": result.resources().action_bytes(),
                    "context_bytes": result.resources().context_bytes(),
                    "object_count": result.resources().object_count(),
                    "plan_leaves": result.resources().plan_leaves(),
                    "plan_depth": result.resources().plan_depth(),
                    "work_units": result.resources().work_units(),
                },
                "registry_manifest": hex::encode(result.registry_manifest().as_bytes()),
            },
            "expected_decision": expected_decision,
            "expected_code": expected_code,
        }));
        generated.insert(PathBuf::from(proof_path), fixture.proof_bytes().to_vec());
        generated.insert(
            PathBuf::from(context_path),
            fixture.context_bytes().to_vec(),
        );
        generated.insert(PathBuf::from(action_path), action_bytes);
        generated.insert(
            PathBuf::from(body_path),
            fixture.canonical_action().body().to_vec(),
        );
        generated.insert(PathBuf::from(result_path), result_bytes);
    }
    let manifest = serde_json::to_vec_pretty(&json!({
        "protocol": "Auths Proof Protocol V1",
        "protocol_major": 1,
        "fixture_set": "target-v1",
        "hash": "sha-256",
        "adapter_context": corpus_adapter_context(),
        "fixtures": entries,
    }))
    .map_err(|error| format!("could not encode target fixture manifest: {error}"))?;
    generated.insert(PathBuf::from("manifest.json"), manifest);
    Ok(generated)
}

fn fixture_inventory(root: &Path) -> Result<BTreeSet<PathBuf>, String> {
    fn walk(root: &Path, current: &Path, output: &mut BTreeSet<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(current)
            .map_err(|error| format!("could not list {}: {error}", current.display()))?
        {
            let entry = entry.map_err(|error| format!("invalid fixture entry: {error}"))?;
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, output)?;
            } else if path
                .extension()
                .is_some_and(|extension| extension == "cbor")
                || path.file_name().is_some_and(|name| name == "manifest.json")
            {
                output.insert(
                    path.strip_prefix(root)
                        .map_err(|_| "fixture escaped root".to_owned())?
                        .to_path_buf(),
                );
            }
        }
        Ok(())
    }
    let mut output = BTreeSet::new();
    walk(root, root, &mut output)?;
    Ok(output)
}

fn corpus_adapter_context() -> Value {
    let did_web = auths_testkit::did_web_corpus_trust_records()
        .iter()
        .map(|record| match record {
            auths_did_web::DidWebTrustRecord::Current {
                principal,
                document_digest,
                observed_at,
                valid_until,
            } => json!({
                "kind": "current",
                "principal": principal.as_str(),
                "document_digest": hex::encode(document_digest),
                "observed_at": observed_at.get(),
                "valid_until": valid_until.get(),
            }),
            auths_did_web::DidWebTrustRecord::Historical {
                principal,
                document_digest,
                valid_from,
                valid_until,
                statement,
            } => json!({
                "kind": "historical",
                "principal": principal.as_str(),
                "document_digest": hex::encode(document_digest),
                "valid_from": valid_from.get(),
                "valid_until": valid_until.get(),
                "statement": statement.map(|pin| json!({
                    "signing_preimage_digest":
                        hex::encode(pin.signing_preimage_digest()),
                    "existed_at": pin.existed_at().get(),
                })),
            }),
        })
        .collect::<Vec<_>>();
    let webauthn = auths_testkit::webauthn_corpus_credentials()
        .iter()
        .map(|credential| {
            let counter_policy = match credential.counter_policy() {
                auths_webauthn::CounterPolicy::Disabled => json!({"kind": "disabled"}),
                auths_webauthn::CounterPolicy::GreaterThan(value) => {
                    json!({"kind": "greater-than", "value": value})
                }
            };
            json!({
                "credential_id": hex::encode(credential.credential_id()),
                "principal": credential.principal().as_str(),
                "verification_method": credential.verification_method().as_str(),
                "public_key": hex::encode(credential.public_key()),
                "rp_id": credential.rp_id(),
                "origins": credential.origins(),
                "require_user_verification": credential.require_user_verification(),
                "counter_policy": counter_policy,
                "attestation_level": credential.attestation_level(),
                "observed_at": credential.observed_at().get(),
                "valid_until": credential.valid_until().get(),
            })
        })
        .collect::<Vec<_>>();
    let hsm = auths_testkit::hsm_corpus_records()
        .iter()
        .map(|record| {
            json!({
                "principal": record.principal().as_str(),
                "verification_method": record.verification_method().as_str(),
                "suite": record.suite().as_str(),
                "public_key": hex::encode(record.public_key()),
                "profile": record.profile(),
                "provider": record.provider(),
                "protection_level": record.protection_level(),
                "key_handle_digest": hex::encode(record.key_handle_digest()),
                "device_chain_digest": hex::encode(record.device_chain_digest()),
                "non_exportable": record.non_exportable(),
                "observed_at": record.observed_at().get(),
                "valid_until": record.valid_until().get(),
            })
        })
        .collect::<Vec<_>>();
    let (trust_domains, status) = auths_testkit::spiffe_corpus_context();
    let spiffe_trust_domains = trust_domains
        .iter()
        .map(|trust| {
            json!({
                "name": trust.name(),
                "roots": trust.roots().iter().map(hex::encode).collect::<Vec<_>>(),
                "require_status": trust.requires_status(),
            })
        })
        .collect::<Vec<_>>();
    let spiffe_status = status
        .iter()
        .map(|record| {
            json!({
                "leaf_digest": hex::encode(record.leaf_digest()),
                "active": record.is_active(),
                "observed_at": record.observed_at().get(),
                "valid_until": record.valid_until().get(),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "did_web": did_web,
        "webauthn": webauthn,
        "hsm": hsm,
        "spiffe": {
            "trust_domains": spiffe_trust_domains,
            "status": spiffe_status,
        },
        "did_keri": {
            "checkpoints": [],
        },
    })
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is inside repository root")
        .to_path_buf()
}
