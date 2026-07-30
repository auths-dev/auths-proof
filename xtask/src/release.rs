#![allow(clippy::too_many_lines)]

use crate::*;

pub(crate) fn release_check() -> Result<(), String> {
    if env::var_os("CI").is_some() {
        let status = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(root())
            .output()
            .map_err(|error| format!("could not inspect release worktree: {error}"))?;
        if !status.status.success() || !status.stdout.is_empty() {
            return Err("release checks require a clean CI worktree".to_owned());
        }
    }
    if let Ok(tag) = env::var("GITHUB_REF_NAME")
        && tag.starts_with('v')
        && tag != format!("v{}", env!("CARGO_PKG_VERSION"))
    {
        return Err(format!(
            "release tag {tag} does not match workspace version v{}",
            env!("CARGO_PKG_VERSION")
        ));
    }
    ci()?;
    cargo(&["test", "--workspace", "--no-default-features"])?;
    wire(false)?;
    let status = Command::new("cargo")
        .args(["doc", "--workspace", "--all-features", "--no-deps"])
        .env("RUSTDOCFLAGS", "-D warnings")
        .current_dir(root())
        .status()
        .map_err(|error| format!("could not build release documentation: {error}"))?;
    if !status.success() {
        return Err(format!("documentation build failed with {status}"));
    }
    package_check()?;
    release_evidence()?;
    println!("release checks passed");
    Ok(())
}

pub(crate) fn release_evidence() -> Result<(), String> {
    let metadata = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not generate dependency metadata: {error}"))?;
    if !metadata.status.success() {
        return Err("cargo metadata failed while generating release evidence".to_owned());
    }
    let metadata_value: Value = serde_json::from_slice(&metadata.stdout)
        .map_err(|error| format!("could not parse dependency metadata: {error}"))?;
    let packages = metadata_value["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages")?;
    let components: Vec<_> = packages
        .iter()
        .map(|package| {
            let component_type = if package["targets"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["kind"]
                        .as_array()
                        .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
                })
            }) {
                "application"
            } else {
                "library"
            };
            let name = package["name"].as_str().unwrap_or("unknown");
            let version = package["version"].as_str().unwrap_or("unknown");
            let purl = format!("pkg:cargo/{name}@{version}");
            let mut component = json!({
                "type": component_type,
                "bom-ref": purl,
                "name": package["name"],
                "version": package["version"],
                "purl": purl,
            });
            if let Some(license) = package["license"].as_str() {
                component["licenses"] = json!([{ "expression": license }]);
            }
            component
        })
        .collect();
    let workspace_members: BTreeSet<_> = metadata_value["workspace_members"]
        .as_array()
        .ok_or("cargo metadata has no workspace members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut package_checksums = BTreeMap::new();
    for package in packages.iter().filter(|package| {
        package["id"]
            .as_str()
            .is_some_and(|id| workspace_members.contains(id))
            && package_is_publishable(package)
    }) {
        let name = package["name"]
            .as_str()
            .ok_or("workspace package has no name")?;
        let version = package["version"]
            .as_str()
            .ok_or("workspace package has no version")?;
        let relative = format!("target/package/{name}-{version}.crate");
        let digest = sha256_file(&root().join(&relative))?;
        package_checksums.insert(relative, digest);
    }
    if package_checksums.is_empty() {
        return Err("release packaging produced no crate archives".to_owned());
    }
    let crate_archive_count = package_checksums.len();
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not identify release commit: {error}"))?;
    if !commit.status.success() {
        return Err("could not identify release commit".to_owned());
    }
    let toolchain = Command::new("rustc")
        .arg("--version")
        .output()
        .map_err(|error| format!("could not identify Rust toolchain: {error}"))?;
    if !toolchain.status.success() {
        return Err("could not identify Rust toolchain".to_owned());
    }
    let manifest = fs::read(root().join("core/fixtures/v1/manifest.json"))
        .map_err(|error| format!("could not read corpus manifest: {error}"))?;
    let evidence = root().join("target/release-evidence");
    fs::create_dir_all(&evidence)
        .map_err(|error| format!("could not create release evidence directory: {error}"))?;
    let platform_path = evidence.join("platform.json");
    platform_artifact(&platform_path)?;
    for relative in [
        "target/release-evidence/platform.json",
        "target/release-evidence/platform.sha256",
        "target/compliance/inventory.json",
        "target/compliance/report.json",
        "target/compliance/summary.txt",
    ] {
        package_checksums.insert(relative.to_owned(), sha256_file(&root().join(relative))?);
    }
    let sbom = serde_json::to_vec_pretty(&json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    }))
    .map_err(|error| format!("could not encode SBOM: {error}"))?;
    let sbom_path = evidence.join("sbom.cdx.json");
    fs::write(&sbom_path, &sbom).map_err(|error| format!("could not write SBOM: {error}"))?;
    let subjects: Vec<_> = package_checksums
        .iter()
        .map(|(name, digest)| {
            json!({
                "name": name,
                "digest": { "sha256": digest },
            })
        })
        .collect();
    let provenance = serde_json::to_vec_pretty(&json!({
        "schema": "auths-proof-release-evidence/v1",
        "source": {
            "commit": String::from_utf8_lossy(&commit.stdout).trim(),
            "repository": env::var("GITHUB_REPOSITORY").ok(),
            "ref": env::var("GITHUB_REF").ok(),
        },
        "build": {
            "command": "cargo xtask release-check",
            "toolchain": String::from_utf8_lossy(&toolchain.stdout).trim(),
            "workflow_run_id": env::var("GITHUB_RUN_ID").ok(),
            "workflow_run_attempt": env::var("GITHUB_RUN_ATTEMPT").ok(),
        },
        "inputs": {
            "corpus_manifest_sha256": hex::encode(Sha256::digest(manifest)),
            "wire_schema": "core/spec/v1/auths-proof.cddl",
            "configuration_commitments": [
                "PortableVerificationResult.required_configuration",
                "PortableVerificationResult.local_configuration",
            ],
        },
        "subjects": subjects,
    }))
    .map_err(|error| format!("could not encode provenance: {error}"))?;
    let provenance_path = evidence.join("provenance.json");
    fs::write(&provenance_path, &provenance)
        .map_err(|error| format!("could not write provenance: {error}"))?;
    let mut checksums = package_checksums;
    checksums.insert(
        "target/release-evidence/sbom.cdx.json".to_owned(),
        hex::encode(Sha256::digest(&sbom)),
    );
    checksums.insert(
        "target/release-evidence/provenance.json".to_owned(),
        hex::encode(Sha256::digest(&provenance)),
    );
    let checksum_manifest = checksums
        .iter()
        .map(|(path, digest)| format!("{digest}  {path}\n"))
        .collect::<String>();
    fs::write(evidence.join("SHA256SUMS"), checksum_manifest)
        .map_err(|error| format!("could not write release checksums: {error}"))?;
    validate_release_evidence(&evidence, &checksums)?;
    println!(
        "generated and validated release evidence for {} crate archives",
        crate_archive_count
    );
    Ok(())
}

pub(crate) fn platform_artifact(output: &Path) -> Result<(), String> {
    use auths_model::{
        DenialReason as D, Requirement as R, VerificationDecision as V, VerificationStage as S,
    };

    let policy = load_architecture_policy()?;
    let manifest_bytes = fs::read(root().join("core/fixtures/v1/manifest.json"))
        .map_err(|error| format!("could not read corpus manifest: {error}"))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("could not parse corpus manifest: {error}"))?;
    let fixture_values = manifest["fixtures"]
        .as_array()
        .ok_or("corpus manifest has no fixtures")?;
    let fixtures: Vec<_> = fixture_values
        .iter()
        .map(|fixture| {
            json!({
                "name": fixture["name"],
                "class": fixture["class"],
                "decision": fixture["expected_result"]["decision"],
                "code": fixture["expected_result"]["code"],
                "stage": fixture["expected_result"]["stage"],
                "profile": fixture["canonical_action"]["profile"],
            })
        })
        .collect();
    let mut fixture_counts = BTreeMap::<String, usize>::new();
    for fixture in fixture_values {
        let class = fixture["class"]
            .as_str()
            .ok_or("corpus fixture has no class")?;
        *fixture_counts.entry(class.to_owned()).or_default() += 1;
    }

    let mut packages = BTreeMap::<String, Vec<String>>::new();
    for (name, layer) in &policy.packages {
        packages
            .entry(layer.clone())
            .or_default()
            .push(name.clone());
    }
    let dependency_graph: Value = serde_json::from_slice(
        &fs::read(root().join("architecture/dependency-graph.json"))
            .map_err(|error| format!("could not read architecture snapshot: {error}"))?,
    )
    .map_err(|error| format!("could not parse architecture snapshot: {error}"))?;
    let graph_packages = dependency_graph["packages"]
        .as_array()
        .ok_or("architecture snapshot has no packages")?;
    let package_names_under = |prefix: &str| {
        graph_packages
            .iter()
            .filter_map(|package| {
                package["path"]
                    .as_str()
                    .is_some_and(|path| path.starts_with(prefix))
                    .then(|| package["name"].as_str().map(str::to_owned))
                    .flatten()
            })
            .collect::<Vec<_>>()
    };
    let mut adapters = package_names_under("core/adapters/");
    let mut transports = package_names_under("exchange/adapters/");
    adapters.sort();
    transports.sort();

    let mut profiles = fs::read_dir(root().join("product/spec/v1"))
        .map_err(|error| format!("could not list product profiles: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("md"))
        .filter(|path| path.file_stem().and_then(|value| value.to_str()) != Some("receipts"))
        .filter_map(|path| {
            path.file_stem()
                .and_then(|value| value.to_str())
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    profiles.sort();

    let denials = [
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
        D::CompositionRequirementNotMet,
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
        D::VerifierConfigurationMismatch,
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
    let requirements = [
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
    let code_record = |variant: String, code: &str, decision: &str| {
        json!({
            "variant": variant,
            "code": code,
            "decision": decision,
        })
    };

    let commit = command_output_in("git", &["rev-parse", "HEAD"], &root(), None)?;
    let generated = json!({
        "schemaVersion": 2,
        "artifactSchema": "auths-proof-platform/v1",
        "source": {
            "repository": "auths-dev/auths-proof",
            "commit": commit.trim(),
        },
        "protocol": manifest["protocol"],
        "protocolMajor": manifest["protocol_major"],
        "fixtureSet": manifest["fixture_set"],
        "packages": packages,
        "adapters": adapters,
        "transports": transports,
        "profiles": profiles,
        "verification": {
            "stages": [
                format!("{:?}", S::Decode),
                format!("{:?}", S::Resolve),
                format!("{:?}", S::PrincipalControl),
                format!("{:?}", S::Authority),
                format!("{:?}", S::Complete),
            ],
            "decisions": [
                format!("{:?}", V::Authorized),
                format!("{:?}", V::Denied),
                format!("{:?}", V::Indeterminate),
            ],
            "denialCodes": denials
                .iter()
                .map(|value| code_record(format!("{value:?}"), value.code(), "denied"))
                .collect::<Vec<_>>(),
            "requirementCodes": requirements
                .iter()
                .map(|value| code_record(format!("{value:?}"), value.code(), "indeterminate"))
                .collect::<Vec<_>>(),
        },
        "corpus": {
            "count": fixtures.len(),
            "byClass": fixture_counts,
            "fixtures": fixtures,
        },
        "fuzzTargets": FUZZ_TARGETS,
    });
    let mut bytes = serde_json::to_vec_pretty(&generated)
        .map_err(|error| format!("could not encode platform artifact: {error}"))?;
    bytes.push(b'\n');
    let parent = output
        .parent()
        .ok_or_else(|| format!("platform artifact path has no parent: {}", output.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create platform artifact directory: {error}"))?;
    fs::write(output, &bytes)
        .map_err(|error| format!("could not write {}: {error}", output.display()))?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let checksum_path = output.with_extension("sha256");
    let artifact_name = output
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("platform artifact has no file name: {}", output.display()))?;
    fs::write(&checksum_path, format!("{digest}  {artifact_name}\n"))
        .map_err(|error| format!("could not write {}: {error}", checksum_path.display()))?;
    println!(
        "generated {} ({digest}) from {}",
        output.display(),
        commit.trim()
    );
    Ok(())
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "could not read release artifact {}: {error}",
            path.display()
        )
    })?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn validate_release_evidence(
    evidence: &Path,
    checksums: &BTreeMap<String, String>,
) -> Result<(), String> {
    let sbom: Value = serde_json::from_slice(
        &fs::read(evidence.join("sbom.cdx.json"))
            .map_err(|error| format!("could not read generated SBOM: {error}"))?,
    )
    .map_err(|error| format!("generated SBOM is not valid JSON: {error}"))?;
    if sbom["bomFormat"] != "CycloneDX"
        || sbom["specVersion"] != "1.5"
        || sbom["version"] != 1
        || sbom["components"].as_array().is_none_or(Vec::is_empty)
    {
        return Err("generated SBOM is incomplete".to_owned());
    }
    let provenance: Value = serde_json::from_slice(
        &fs::read(evidence.join("provenance.json"))
            .map_err(|error| format!("could not read generated provenance: {error}"))?,
    )
    .map_err(|error| format!("generated provenance is not valid JSON: {error}"))?;
    if provenance["schema"] != "auths-proof-release-evidence/v1"
        || provenance["subjects"]
            .as_array()
            .is_none_or(|subjects| subjects.len() != checksums.len() - 2)
    {
        return Err("generated provenance is incomplete".to_owned());
    }
    let expected_manifest = checksums
        .iter()
        .map(|(path, digest)| format!("{digest}  {path}\n"))
        .collect::<String>();
    let actual_manifest = fs::read_to_string(evidence.join("SHA256SUMS"))
        .map_err(|error| format!("could not read generated release checksums: {error}"))?;
    if actual_manifest != expected_manifest {
        return Err("generated release checksum manifest is incomplete".to_owned());
    }
    for (relative, expected) in checksums {
        let actual = sha256_file(&root().join(relative))?;
        if &actual != expected {
            return Err(format!(
                "release artifact checksum changed after generation: {relative}"
            ));
        }
    }
    Ok(())
}
