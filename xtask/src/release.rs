#![allow(clippy::too_many_lines)]

use crate::*;

pub(crate) const RELEASE_MANIFEST_SCHEMA: &str = "auths.release-manifest/1";
const RELEASE_MANIFEST_INPUT_SCHEMA: &str = "auths.release-manifest-input/1";
const RELEASE_SUBJECTS_SCHEMA: &str = "auths.release-subjects/1";
pub(crate) const RELEASE_REPOSITORY: &str = "auths-dev/auths-proof";
const REPRODUCIBILITY_CLASSES: [&str; 4] = [
    "byte-identical",
    "deterministic-evidence",
    "platform-reproducible",
    "provenance-only",
];

#[derive(Debug, Deserialize)]
struct ReleaseSubjectCatalogue {
    schema: String,
    manifest_schema: String,
    product: String,
    repository: String,
    first_rc_tag: String,
    policy: String,
    families: Vec<ReleaseSubjectFamily>,
    excluded: Vec<ReleaseSubjectExclusion>,
}

#[derive(Debug, Deserialize)]
struct ReleaseSubjectFamily {
    id: String,
    coordinate: String,
    media_type: String,
    reproducibility: String,
    producer: String,
    publication: String,
}

#[derive(Debug, Deserialize)]
struct ReleaseSubjectExclusion {
    id: String,
    reason: String,
}

pub(crate) fn release_contract() -> Result<(), String> {
    validate_release_contract_sources()?;
    validate_release_workflow_contract()?;
    let fixture: Value = serde_json::from_slice(
        &fs::read(root().join("release/release-manifest.contract-fixture.json"))
            .map_err(|error| format!("could not read release-manifest fixture: {error}"))?,
    )
    .map_err(|error| format!("release-manifest fixture is not valid JSON: {error}"))?;
    validate_release_manifest_value(&fixture)?;
    println!("release-manifest schema and subject catalogue passed");
    Ok(())
}

fn validate_release_workflow_contract() -> Result<(), String> {
    let controller = fs::read_to_string(root().join(".github/workflows/release.yml"))
        .map_err(|error| format!("could not read release control workflow: {error}"))?;
    let builder = fs::read_to_string(root().join(".github/workflows/release-builder.yml"))
        .map_err(|error| format!("could not read reusable release builder: {error}"))?;
    for required in [
        "workflow_dispatch:",
        "uses: ./.github/workflows/release-builder.yml",
        "name: independent isolated reproduction",
        "cargo xtask release-control compare",
        "overwrite: false",
        "environment: release-promotion",
        "cargo xtask release-control verify-promotion",
        "Promotion remains blocked pending SLSA runtime assessment",
    ] {
        if !controller.contains(required) {
            return Err(format!("release control workflow is missing: {required}"));
        }
    }
    if controller.contains("tags: [\"auths-v*\"]") {
        return Err("release control must not build from a tag push".to_owned());
    }
    for required in [
        "workflow_call:",
        "environment: release-candidate",
        "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
        "subject-checksums: target/release-evidence/attestation-subjects.txt",
        "repo:auths-dev@260513770/auths-proof@1310728509:environment:release-candidate",
        "--deny-self-hosted-runners",
        "--signer-digest \"$CANDIDATE_COMMIT\"",
        "cargo xtask release-control finalize",
    ] {
        if !builder.contains(required) {
            return Err(format!("reusable release builder is missing: {required}"));
        }
    }
    let promotion = controller
        .split("  promote-github-prerelease:")
        .nth(1)
        .ok_or("release control workflow has no promotion job")?;
    validate_no_rebuild_promotion_job(promotion)
}

fn validate_no_rebuild_promotion_job(promotion: &str) -> Result<(), String> {
    for forbidden in [
        "cargo ",
        "npm ",
        "maturin",
        "wasm-pack",
        "nix ",
        "actions/checkout",
        "release-check",
        "release-control finalize",
    ] {
        if promotion.contains(forbidden) {
            return Err(format!(
                "promotion job contains a forbidden build or generation step: {forbidden}"
            ));
        }
    }
    if !promotion.contains("gh release create")
        || !promotion.contains("repos/auths-dev/auths-proof/git/refs")
        || !promotion.contains("sha256sum \"$MANIFEST\"")
    {
        return Err("promotion job does not verify and publish staged bytes exactly".to_owned());
    }
    Ok(())
}

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
    let is_tag_ref = env::var("GITHUB_REF_TYPE").is_ok_and(|value| value == "tag")
        || env::var("GITHUB_REF").is_ok_and(|value| value.starts_with("refs/tags/"));
    if is_tag_ref {
        let tag = env::var("GITHUB_REF_NAME")
            .map_err(|_| "tagged release is missing GITHUB_REF_NAME".to_owned())?;
        validate_release_tag(&tag, env!("CARGO_PKG_VERSION"))?;
    }
    ci()?;
    release_evidence()?;
    println!("release checks passed");
    Ok(())
}

pub(crate) fn release_evidence() -> Result<(), String> {
    validate_release_contract_sources()?;
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
    let mut subject_checksums = BTreeMap::new();
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
        subject_checksums.insert(relative, digest);
    }
    if subject_checksums.is_empty() {
        return Err("release packaging produced no crate archives".to_owned());
    }
    let crate_archive_count = subject_checksums.len();
    insert_single_artifact(
        &mut subject_checksums,
        "target/npm-package",
        "tgz",
        "npm SDK archive",
    )?;
    insert_single_artifact(
        &mut subject_checksums,
        "target/python-wheels",
        "whl",
        "Python SDK wheel",
    )?;
    let wasm_relative = "bindings/typescript/wasm/auths_proof_wasm_bg.wasm";
    subject_checksums.insert(
        wasm_relative.to_owned(),
        sha256_file(&root().join(wasm_relative))?,
    );
    let commit_output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not identify release commit: {error}"))?;
    if !commit_output.status.success() {
        return Err("could not identify release commit".to_owned());
    }
    let commit = String::from_utf8_lossy(&commit_output.stdout)
        .trim()
        .to_owned();
    let toolchain = Command::new("rustc")
        .arg("--version")
        .output()
        .map_err(|error| format!("could not identify Rust toolchain: {error}"))?;
    if !toolchain.status.success() {
        return Err("could not identify Rust toolchain".to_owned());
    }
    let fixture_manifest = fs::read(root().join("core/fixtures/v1/manifest.json"))
        .map_err(|error| format!("could not read corpus manifest: {error}"))?;
    let evidence = root().join("target/release-evidence");
    if evidence.exists() {
        fs::remove_dir_all(&evidence)
            .map_err(|error| format!("could not clear release evidence directory: {error}"))?;
    }
    fs::create_dir_all(&evidence)
        .map_err(|error| format!("could not create release evidence directory: {error}"))?;
    let platform_path = evidence.join("platform.json");
    platform_artifact(&platform_path)?;
    let mut evidence_checksums = BTreeMap::new();
    for relative in [
        "target/release-evidence/platform.json",
        "target/release-evidence/platform.sha256",
        "target/compliance/inventory.json",
        "target/compliance/report.json",
        "target/compliance/summary.txt",
    ] {
        evidence_checksums.insert(relative.to_owned(), sha256_file(&root().join(relative))?);
    }
    for (relative, digest) in prepare_release_archives(&commit)? {
        subject_checksums.insert(relative, digest);
    }
    let cyclone_dx = serde_json::to_vec_pretty(&json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    }))
    .map_err(|error| format!("could not encode supplementary CycloneDX SBOM: {error}"))?;
    let cyclone_dx_path = evidence.join("sbom.cdx.json");
    fs::write(&cyclone_dx_path, &cyclone_dx)
        .map_err(|error| format!("could not write supplementary CycloneDX SBOM: {error}"))?;
    evidence_checksums.insert(
        "target/release-evidence/sbom.cdx.json".to_owned(),
        hex::encode(Sha256::digest(&cyclone_dx)),
    );

    let subject_records = subject_checksums
        .iter()
        .map(|(name, digest)| release_subject_record(name, digest))
        .collect::<Result<Vec<_>, _>>()?;
    let spdx = generate_spdx(&metadata_value, &subject_records, &commit)?;
    let spdx_bytes = pretty_json(&spdx, "SPDX 2.3 SBOM")?;
    fs::write(evidence.join("sbom.spdx.json"), &spdx_bytes)
        .map_err(|error| format!("could not write SPDX 2.3 SBOM: {error}"))?;
    evidence_checksums.insert(
        "target/release-evidence/sbom.spdx.json".to_owned(),
        hex::encode(Sha256::digest(&spdx_bytes)),
    );

    let attestation_subjects = subject_checksums
        .iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect::<String>();
    fs::write(
        evidence.join("attestation-subjects.txt"),
        &attestation_subjects,
    )
    .map_err(|error| format!("could not write attestation subject set: {error}"))?;
    evidence_checksums.insert(
        "target/release-evidence/attestation-subjects.txt".to_owned(),
        hex::encode(Sha256::digest(attestation_subjects.as_bytes())),
    );

    let build_record = json!({
        "schema": "auths.build-record/1",
        "attestationStatus": "not-attested",
        "limitation": "This deterministic record is an input to hosted attestation. It is not signed provenance and does not establish SLSA Build Level 3.",
        "source": {
            "commit": commit,
            "repository": RELEASE_REPOSITORY,
            "ref": env::var("GITHUB_REF").ok(),
        },
        "build": {
            "command": "cargo xtask release-check",
            "toolchain": String::from_utf8_lossy(&toolchain.stdout).trim(),
            "workflow_run_id": env::var("GITHUB_RUN_ID").ok(),
            "workflow_run_attempt": env::var("GITHUB_RUN_ATTEMPT").ok(),
        },
        "inputs": {
            "corpus_manifest_sha256": hex::encode(Sha256::digest(fixture_manifest)),
            "wire_schema": "core/spec/v1/auths-proof.cddl",
            "configuration_commitments": [
                "PortableVerificationResult.required_configuration",
                "PortableVerificationResult.local_configuration",
            ],
        },
        "subjects": &subject_records,
    });
    let build_record_bytes = pretty_json(&build_record, "unsigned build record")?;
    fs::write(evidence.join("build-record.json"), &build_record_bytes)
        .map_err(|error| format!("could not write unsigned build record: {error}"))?;
    evidence_checksums.insert(
        "target/release-evidence/build-record.json".to_owned(),
        hex::encode(Sha256::digest(&build_record_bytes)),
    );

    let semantic_freeze_path = "release/semantic-freeze.json";
    let manifest_input = json!({
        "schema": RELEASE_MANIFEST_INPUT_SCHEMA,
        "targetSchema": RELEASE_MANIFEST_SCHEMA,
        "release": {
            "tag": format!("auths-v{}", env!("CARGO_PKG_VERSION")),
            "status": "preparation-input",
        },
        "source": {
            "repository": RELEASE_REPOSITORY,
            "commit": commit,
        },
        "semanticFreeze": {
            "path": semantic_freeze_path,
            "sha256": sha256_file(&root().join(semantic_freeze_path))?,
        },
        "subjects": &subject_records,
        "evidenceInputs": evidence_checksums.iter().map(|(path, sha256)| json!({
            "path": path,
            "sha256": sha256,
        })).collect::<Vec<_>>(),
        "requiredBeforeFinalManifest": [
            "signed hosted-build provenance whose subjects exactly equal attestation-subjects.txt",
            "SLSA 1.2 Build Level 3 assessment for every subject",
            "second isolated preparation and reproducibility comparison",
        ],
    });
    let manifest_input_bytes = pretty_json(&manifest_input, "release-manifest input")?;
    fs::write(
        evidence.join("release-manifest.input.json"),
        &manifest_input_bytes,
    )
    .map_err(|error| format!("could not write release-manifest input: {error}"))?;
    evidence_checksums.insert(
        "target/release-evidence/release-manifest.input.json".to_owned(),
        hex::encode(Sha256::digest(&manifest_input_bytes)),
    );

    let mut checksums = subject_checksums.clone();
    checksums.extend(evidence_checksums);
    let checksum_manifest = checksums
        .iter()
        .map(|(path, digest)| format!("{digest}  {path}\n"))
        .collect::<String>();
    fs::write(evidence.join("SHA256SUMS"), checksum_manifest)
        .map_err(|error| format!("could not write release checksums: {error}"))?;
    validate_release_evidence(&evidence, &subject_checksums, &checksums)?;
    println!(
        "generated release-manifest inputs and validated release evidence for {crate_archive_count} crate archives and {} total subjects; no signed provenance or final candidate manifest was emitted",
        subject_checksums.len()
    );
    Ok(())
}

fn validate_release_contract_sources() -> Result<(), String> {
    let schema: Value = serde_json::from_slice(
        &fs::read(root().join("release/release-manifest.schema.json"))
            .map_err(|error| format!("could not read release-manifest schema: {error}"))?,
    )
    .map_err(|error| format!("release-manifest schema is not valid JSON: {error}"))?;
    if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema"
        || schema["properties"]["schema"]["const"] != RELEASE_MANIFEST_SCHEMA
        || schema["properties"]["release"]["properties"]["status"]["const"] != "release-candidate"
    {
        return Err("release-manifest schema identity or release status drifted".to_owned());
    }

    let catalogue: ReleaseSubjectCatalogue = toml::from_str(
        &fs::read_to_string(root().join("release/release-subjects.toml"))
            .map_err(|error| format!("could not read release subject catalogue: {error}"))?,
    )
    .map_err(|error| format!("could not parse release subject catalogue: {error}"))?;
    validate_release_subject_catalogue(&catalogue)
}

fn validate_release_subject_catalogue(catalogue: &ReleaseSubjectCatalogue) -> Result<(), String> {
    if catalogue.schema != RELEASE_SUBJECTS_SCHEMA
        || catalogue.manifest_schema != RELEASE_MANIFEST_SCHEMA
        || catalogue.product != "Auths"
        || catalogue.repository != RELEASE_REPOSITORY
        || catalogue.first_rc_tag != "auths-v1.0.0-rc.1"
        || catalogue.policy.trim().is_empty()
    {
        return Err("release subject catalogue authority drifted".to_owned());
    }
    let expected = BTreeSet::from([
        "assurance-bundle",
        "python-sdk",
        "rust-crates",
        "source-archive",
        "typescript-sdk",
        "wasm-module",
    ]);
    let mut actual = BTreeSet::new();
    for family in &catalogue.families {
        if !actual.insert(family.id.as_str()) {
            return Err(format!("duplicate release subject family: {}", family.id));
        }
        if !REPRODUCIBILITY_CLASSES.contains(&family.reproducibility.as_str()) {
            return Err(format!(
                "unsupported reproducibility class for {}: {}",
                family.id, family.reproducibility
            ));
        }
        if [
            family.coordinate.as_str(),
            family.media_type.as_str(),
            family.producer.as_str(),
            family.publication.as_str(),
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err(format!(
                "release subject family {} is incomplete",
                family.id
            ));
        }
    }
    if actual != expected {
        return Err(format!(
            "release subject family set drifted; expected {expected:?}, got {actual:?}"
        ));
    }
    let mut exclusions = BTreeSet::new();
    for exclusion in &catalogue.excluded {
        if exclusion.id.trim().is_empty()
            || exclusion.reason.trim().is_empty()
            || !exclusions.insert(exclusion.id.as_str())
        {
            return Err("release subject exclusion is incomplete or duplicated".to_owned());
        }
    }
    if exclusions.is_empty() {
        return Err("release subject catalogue has no explicit exclusions".to_owned());
    }
    Ok(())
}

fn insert_single_artifact(
    checksums: &mut BTreeMap<String, String>,
    relative_directory: &str,
    extension: &str,
    label: &str,
) -> Result<(), String> {
    let directory = root().join(relative_directory);
    let mut matches = fs::read_dir(&directory)
        .map_err(|error| {
            format!(
                "could not list {label} directory {}: {error}",
                directory.display()
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some(extension))
        .collect::<Vec<_>>();
    matches.sort();
    if matches.len() != 1 {
        return Err(format!(
            "expected exactly one {label} in {}, found {}",
            directory.display(),
            matches.len()
        ));
    }
    let relative = matches[0]
        .strip_prefix(root())
        .map_err(|_| format!("{label} escaped repository root"))?;
    let relative = path_text(relative)?;
    checksums.insert(relative.to_owned(), sha256_file(&matches[0])?);
    Ok(())
}

fn release_subject_record(name: &str, sha256: &str) -> Result<Value, String> {
    validate_safe_relative_path(name)?;
    validate_sha256(sha256)?;
    let path = root().join(name);
    let size = fs::metadata(&path)
        .map_err(|error| format!("could not inspect release subject {name}: {error}"))?
        .len();
    if size == 0 {
        return Err(format!("release subject is empty: {name}"));
    }
    let (media_type, reproducibility, platform) = if name.ends_with(".crate") {
        ("application/vnd.rust.crate", "byte-identical", None)
    } else if name.ends_with(".tgz") {
        ("application/gzip", "byte-identical", None)
    } else if name.ends_with(".whl") {
        (
            "application/vnd.python.wheel",
            "platform-reproducible",
            Some(format!("{}-{}", env::consts::OS, env::consts::ARCH)),
        )
    } else if name.ends_with(".wasm") {
        (
            "application/wasm",
            "platform-reproducible",
            Some("wasm32-unknown-unknown".to_owned()),
        )
    } else if name.ends_with(".tar.zst") {
        ("application/zstd", "byte-identical", None)
    } else {
        return Err(format!(
            "release subject has no approved media type: {name}"
        ));
    };
    let mut record = json!({
        "name": name,
        "mediaType": media_type,
        "size": size,
        "sha256": sha256,
        "reproducibility": reproducibility,
    });
    if let Some(platform) = platform {
        record["platform"] = Value::String(platform);
    }
    Ok(record)
}

fn prepare_release_archives(commit: &str) -> Result<BTreeMap<String, String>, String> {
    validate_full_commit(commit)?;
    let output_directory = root().join("target/release-artifacts");
    if output_directory.exists() {
        fs::remove_dir_all(&output_directory).map_err(|error| {
            format!(
                "could not clear release artifact directory {}: {error}",
                output_directory.display()
            )
        })?;
    }
    fs::create_dir_all(&output_directory).map_err(|error| {
        format!(
            "could not create release artifact directory {}: {error}",
            output_directory.display()
        )
    })?;
    let version = env!("CARGO_PKG_VERSION");
    let timestamp = commit_timestamp_epoch(commit)?;
    let tracked = tracked_release_files()?;

    let source_relative = format!("target/release-artifacts/auths-{version}-source.tar.zst");
    write_deterministic_archive(
        &root().join(&source_relative),
        &format!("auths-{version}-source"),
        &tracked,
        timestamp,
    )?;

    let mut assurance = tracked
        .iter()
        .filter(|(path, _)| assurance_source_path(path))
        .map(|(path, mode)| (path.clone(), *mode))
        .collect::<BTreeMap<_, _>>();
    for generated_root in ["target/formal", "target/compliance"] {
        collect_generated_evidence(&root().join(generated_root), &mut assurance)?;
    }
    for generated in [
        "target/release-evidence/platform.json",
        "target/release-evidence/platform.sha256",
    ] {
        if root().join(generated).is_file() {
            assurance.insert(generated.to_owned(), 0o644);
        }
    }
    if assurance.is_empty() {
        return Err("assurance archive input set is empty".to_owned());
    }
    let assurance_relative = format!("target/release-artifacts/auths-{version}-assurance.tar.zst");
    write_deterministic_archive(
        &root().join(&assurance_relative),
        &format!("auths-{version}-assurance"),
        &assurance,
        timestamp,
    )?;

    Ok(BTreeMap::from([
        (
            source_relative.clone(),
            sha256_file(&root().join(source_relative))?,
        ),
        (
            assurance_relative.clone(),
            sha256_file(&root().join(assurance_relative))?,
        ),
    ]))
}

fn tracked_release_files() -> Result<BTreeMap<String, u32>, String> {
    let output = Command::new("git")
        .args(["ls-files", "--stage", "-z"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not enumerate tracked release files: {error}"))?;
    if !output.status.success() {
        return Err("git ls-files failed while preparing release archives".to_owned());
    }
    let mut files = BTreeMap::new();
    for entry in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let text = std::str::from_utf8(entry)
            .map_err(|error| format!("tracked path inventory is not UTF-8: {error}"))?;
        let (metadata, path) = text
            .split_once('\t')
            .ok_or("tracked path inventory entry has no path")?;
        let mut metadata = metadata.split_ascii_whitespace();
        let mode = metadata.next().ok_or("tracked path has no Git mode")?;
        let _object = metadata.next().ok_or("tracked path has no Git object")?;
        let stage = metadata.next().ok_or("tracked path has no Git stage")?;
        if stage != "0" || !matches!(mode, "100644" | "100755") {
            return Err(format!(
                "unsupported tracked release path mode or stage: {text}"
            ));
        }
        validate_safe_relative_path(path)?;
        if files
            .insert(
                path.to_owned(),
                if mode == "100755" { 0o755 } else { 0o644 },
            )
            .is_some()
        {
            return Err(format!("duplicate tracked release path: {path}"));
        }
    }
    if files.is_empty() {
        return Err("tracked release path inventory is empty".to_owned());
    }
    Ok(files)
}

fn assurance_source_path(path: &str) -> bool {
    [
        "formal/",
        "core/fixtures/v1/",
        "core/formal-vectors/v1/",
        "product/fixtures/v1/",
        "product/integrations/auths-stripe/fixtures/",
        "release/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
        || matches!(
            path,
            "architecture/dependency-graph.dot"
                | "architecture/dependency-graph.json"
                | "architecture.toml"
                | "bounded-domains.toml"
                | "compliance.toml"
                | "demos/benchmarks/profiles/release.toml"
                | "docs/research/domains/0004-seven-domain-bounded-authorization-performance-baseline.md"
        )
}

fn collect_generated_evidence(
    directory: &Path,
    files: &mut BTreeMap<String, u32>,
) -> Result<(), String> {
    if !directory.is_dir() {
        return Err(format!(
            "generated assurance directory is absent: {}",
            directory.display()
        ));
    }
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("could not read {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("could not enumerate {}: {error}", directory.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "generated assurance evidence must not contain symlinks: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            collect_generated_evidence(&path, files)?;
        } else if metadata.is_file() {
            let relative = path.strip_prefix(root()).map_err(|_| {
                format!("generated evidence escaped repository: {}", path.display())
            })?;
            let relative = path_text(relative)?.replace('\\', "/");
            validate_safe_relative_path(&relative)?;
            files.insert(relative, 0o644);
        }
    }
    Ok(())
}

fn commit_timestamp_epoch(commit: &str) -> Result<u64, String> {
    let output = Command::new("git")
        .args(["show", "-s", "--format=%ct", commit])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not read release commit timestamp: {error}"))?;
    if !output.status.success() {
        return Err("could not read release commit timestamp".to_owned());
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("release commit timestamp is invalid: {error}"))
}

fn write_deterministic_archive(
    output: &Path,
    prefix: &str,
    files: &BTreeMap<String, u32>,
    timestamp: u64,
) -> Result<(), String> {
    if files.is_empty() {
        return Err(format!("archive input set is empty: {}", output.display()));
    }
    let file = fs::File::create(output)
        .map_err(|error| format!("could not create {}: {error}", output.display()))?;
    let mut encoder = zstd::Encoder::new(file, 19)
        .map_err(|error| format!("could not create Zstandard encoder: {error}"))?;
    encoder
        .include_checksum(true)
        .map_err(|error| format!("could not configure Zstandard checksum: {error}"))?;
    let mut archive = tar::Builder::new(encoder);
    archive.mode(tar::HeaderMode::Deterministic);
    for (relative, mode) in files {
        let bytes = fs::read(root().join(relative))
            .map_err(|error| format!("could not read archive input {relative}: {error}"))?;
        // UStar keeps the path prefix in its dedicated 155-byte field. The
        // GNU header layout reuses that field and therefore rejects otherwise
        // valid repository paths once the release archive prefix pushes them
        // beyond the 100-byte name field.
        let mut header = tar::Header::new_ustar();
        header
            .set_path(Path::new(prefix).join(relative))
            .map_err(|error| format!("could not encode archive path {relative}: {error}"))?;
        header.set_size(
            u64::try_from(bytes.len())
                .map_err(|_| format!("archive input is too large: {relative}"))?,
        );
        header.set_mode(*mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(timestamp);
        header.set_cksum();
        archive
            .append(&header, std::io::Cursor::new(bytes))
            .map_err(|error| format!("could not append archive input {relative}: {error}"))?;
    }
    let encoder = archive
        .into_inner()
        .map_err(|error| format!("could not finish tar archive {}: {error}", output.display()))?;
    encoder.finish().map_err(|error| {
        format!(
            "could not finish Zstandard archive {}: {error}",
            output.display()
        )
    })?;
    Ok(())
}

fn generate_spdx(metadata: &Value, subjects: &[Value], commit: &str) -> Result<Value, String> {
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages for SPDX generation")?;
    let workspace_members: BTreeSet<_> = metadata["workspace_members"]
        .as_array()
        .ok_or("cargo metadata has no workspace members for SPDX generation")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut package_ids = BTreeMap::new();
    let mut spdx_packages = Vec::new();
    for package in packages {
        let id = package["id"].as_str().ok_or("Cargo package has no id")?;
        let name = package["name"]
            .as_str()
            .ok_or("Cargo package has no name")?;
        let version = package["version"]
            .as_str()
            .ok_or("Cargo package has no version")?;
        let spdx_id = format!(
            "SPDXRef-Package-{}-{}",
            sanitize_spdx(name),
            &hex::encode(Sha256::digest(id.as_bytes()))[..12]
        );
        package_ids.insert(id, spdx_id.clone());
        let license = package["license"].as_str().unwrap_or("NOASSERTION");
        spdx_packages.push(json!({
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": license,
            "copyrightText": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": format!("pkg:cargo/{name}@{version}"),
            }],
        }));
    }
    spdx_packages.sort_by(|left, right| left["SPDXID"].as_str().cmp(&right["SPDXID"].as_str()));

    let mut files = Vec::new();
    let mut relationships = BTreeSet::new();
    for subject in subjects {
        let name = subject["name"]
            .as_str()
            .ok_or("release subject has no name")?;
        let digest = subject["sha256"]
            .as_str()
            .ok_or("release subject has no SHA-256")?;
        let file_id = format!("SPDXRef-Artifact-{}-{}", sanitize_spdx(name), &digest[..12]);
        files.push(json!({
            "SPDXID": file_id,
            "fileName": name,
            "checksums": [{ "algorithm": "SHA256", "checksumValue": digest }],
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }));
        relationships.insert(format!("SPDXRef-DOCUMENT\tDESCRIBES\t{file_id}"));
    }
    files.sort_by(|left, right| left["fileName"].as_str().cmp(&right["fileName"].as_str()));

    if let Some(nodes) = metadata["resolve"]["nodes"].as_array() {
        for node in nodes {
            let Some(from) = node["id"].as_str().and_then(|id| package_ids.get(id)) else {
                continue;
            };
            if workspace_members.contains(node["id"].as_str().unwrap_or_default()) {
                relationships.insert(format!("SPDXRef-DOCUMENT\tDESCRIBES\t{from}"));
            }
            if let Some(dependencies) = node["dependencies"].as_array() {
                for dependency in dependencies.iter().filter_map(Value::as_str) {
                    if let Some(to) = package_ids.get(dependency) {
                        relationships.insert(format!("{from}\tDEPENDS_ON\t{to}"));
                    }
                }
            }
        }
    }
    let relationships = relationships
        .into_iter()
        .map(|line| {
            let mut parts = line.split('\t');
            json!({
                "spdxElementId": parts.next().unwrap_or_default(),
                "relationshipType": parts.next().unwrap_or_default(),
                "relatedSpdxElement": parts.next().unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    let created = git_commit_timestamp()?;
    Ok(json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("auths-{}-release-inputs", env!("CARGO_PKG_VERSION")),
        "documentNamespace": format!("https://auths.dev/spdx/{commit}"),
        "creationInfo": {
            "created": created,
            "creators": [format!("Tool: auths-xtask/{}", env!("CARGO_PKG_VERSION"))],
        },
        "packages": spdx_packages,
        "files": files,
        "relationships": relationships,
    }))
}

fn git_commit_timestamp() -> Result<String, String> {
    let output = Command::new("git")
        .args([
            "show",
            "-s",
            "--format=%cd",
            "--date=format-local:%Y-%m-%dT%H:%M:%SZ",
            "HEAD",
        ])
        .env("TZ", "UTC")
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not read commit timestamp: {error}"))?;
    if !output.status.success() {
        return Err("could not read commit timestamp".to_owned());
    }
    let timestamp = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if timestamp.len() != 20 || !timestamp.ends_with('Z') {
        return Err(format!(
            "commit timestamp is not normalized UTC: {timestamp}"
        ));
    }
    Ok(timestamp)
}

fn sanitize_spdx(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn pretty_json(value: &Value, label: &str) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not encode {label}: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
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
        "artifactSchema": "auths.platform/1",
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
    subjects: &BTreeMap<String, String>,
    checksums: &BTreeMap<String, String>,
) -> Result<(), String> {
    let spdx: Value = serde_json::from_slice(
        &fs::read(evidence.join("sbom.spdx.json"))
            .map_err(|error| format!("could not read generated SPDX SBOM: {error}"))?,
    )
    .map_err(|error| format!("generated SPDX SBOM is not valid JSON: {error}"))?;
    if spdx["spdxVersion"] != "SPDX-2.3"
        || spdx["dataLicense"] != "CC0-1.0"
        || spdx["SPDXID"] != "SPDXRef-DOCUMENT"
        || spdx["packages"].as_array().is_none_or(Vec::is_empty)
        || spdx["relationships"].as_array().is_none_or(Vec::is_empty)
    {
        return Err("generated SPDX 2.3 SBOM is incomplete".to_owned());
    }
    validate_spdx_package_metadata(&spdx)?;
    let spdx_subjects = spdx["files"]
        .as_array()
        .ok_or("generated SPDX SBOM has no subject files")?
        .iter()
        .map(|file| {
            let name = file["fileName"]
                .as_str()
                .ok_or("SPDX subject file has no fileName")?;
            let digest = file["checksums"]
                .as_array()
                .and_then(|checksums| {
                    checksums
                        .iter()
                        .find(|checksum| checksum["algorithm"] == "SHA256")
                })
                .and_then(|checksum| checksum["checksumValue"].as_str())
                .ok_or("SPDX subject file has no SHA256 checksum")?;
            Ok((name.to_owned(), digest.to_owned()))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    validate_subject_coverage("SPDX", &spdx_subjects, subjects)?;

    let cyclone_dx: Value = serde_json::from_slice(
        &fs::read(evidence.join("sbom.cdx.json"))
            .map_err(|error| format!("could not read supplementary CycloneDX SBOM: {error}"))?,
    )
    .map_err(|error| format!("supplementary CycloneDX SBOM is not valid JSON: {error}"))?;
    if cyclone_dx["bomFormat"] != "CycloneDX"
        || cyclone_dx["specVersion"] != "1.5"
        || cyclone_dx["components"]
            .as_array()
            .is_none_or(Vec::is_empty)
    {
        return Err("supplementary CycloneDX SBOM is incomplete".to_owned());
    }

    let build_record: Value = serde_json::from_slice(
        &fs::read(evidence.join("build-record.json"))
            .map_err(|error| format!("could not read unsigned build record: {error}"))?,
    )
    .map_err(|error| format!("unsigned build record is not valid JSON: {error}"))?;
    if build_record["schema"] != "auths.build-record/1"
        || build_record["attestationStatus"] != "not-attested"
        || build_record["limitation"]
            .as_str()
            .is_none_or(|limitation| !limitation.contains("not signed provenance"))
        || validate_subject_coverage(
            "unsigned build record",
            &subject_map(&build_record)?,
            subjects,
        )
        .is_err()
    {
        return Err("unsigned build record is incomplete or overclaims provenance".to_owned());
    }

    let manifest_input: Value = serde_json::from_slice(
        &fs::read(evidence.join("release-manifest.input.json"))
            .map_err(|error| format!("could not read release-manifest input: {error}"))?,
    )
    .map_err(|error| format!("release-manifest input is not valid JSON: {error}"))?;
    if manifest_input["schema"] != RELEASE_MANIFEST_INPUT_SCHEMA
        || manifest_input["targetSchema"] != RELEASE_MANIFEST_SCHEMA
        || manifest_input["release"]["status"] != "preparation-input"
        || manifest_input["source"]["repository"] != RELEASE_REPOSITORY
        || validate_subject_coverage(
            "release-manifest input",
            &subject_map(&manifest_input)?,
            subjects,
        )
        .is_err()
        || manifest_input["requiredBeforeFinalManifest"]
            .as_array()
            .is_none_or(|requirements| requirements.len() < 3)
    {
        return Err(
            "release-manifest input is incomplete or claims candidate completion".to_owned(),
        );
    }

    let expected_attestation_subjects = subjects
        .iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect::<String>();
    let actual_attestation_subjects = fs::read_to_string(evidence.join("attestation-subjects.txt"))
        .map_err(|error| format!("could not read attestation subject set: {error}"))?;
    if actual_attestation_subjects != expected_attestation_subjects {
        return Err("hosted-attestation subject set differs from release subjects".to_owned());
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

pub(crate) fn subject_map(document: &Value) -> Result<BTreeMap<String, String>, String> {
    document["subjects"]
        .as_array()
        .ok_or("release document has no subjects")?
        .iter()
        .map(|subject| {
            let name = subject["name"]
                .as_str()
                .ok_or("release subject has no name")?;
            let digest = subject["sha256"]
                .as_str()
                .or_else(|| subject["digest"]["sha256"].as_str())
                .ok_or("release subject has no SHA-256")?;
            Ok((name.to_owned(), digest.to_owned()))
        })
        .collect()
}

fn validate_subject_coverage(
    label: &str,
    actual: &BTreeMap<String, String>,
    expected: &BTreeMap<String, String>,
) -> Result<(), String> {
    if actual != expected {
        return Err(format!(
            "{label} subject coverage differs from release subjects"
        ));
    }
    Ok(())
}

fn validate_spdx_package_metadata(spdx: &Value) -> Result<(), String> {
    for package in spdx["packages"]
        .as_array()
        .ok_or("SPDX document has no packages")?
    {
        let name = package["name"].as_str().ok_or("SPDX package has no name")?;
        if package["versionInfo"].as_str().is_none_or(str::is_empty)
            || package["licenseDeclared"]
                .as_str()
                .is_none_or(|license| license.is_empty() || license == "NOASSERTION")
            || package["externalRefs"].as_array().is_none_or(Vec::is_empty)
        {
            return Err(format!("SPDX package metadata is incomplete: {name}"));
        }
    }
    Ok(())
}

pub(crate) fn validate_release_manifest_value(manifest: &Value) -> Result<(), String> {
    if manifest["schema"] != RELEASE_MANIFEST_SCHEMA {
        return Err("unknown release-manifest schema".to_owned());
    }
    let tag = manifest["release"]["tag"]
        .as_str()
        .ok_or("release manifest has no tag")?;
    validate_release_candidate_tag(tag)?;
    if manifest["release"]["status"] != "release-candidate" {
        return Err("release manifest is not explicitly a release candidate".to_owned());
    }
    if manifest["source"]["repository"] != RELEASE_REPOSITORY {
        return Err("release manifest repository identity differs".to_owned());
    }
    validate_full_commit(
        manifest["source"]["commit"]
            .as_str()
            .ok_or("release manifest has no source commit")?,
    )?;
    validate_digest_reference(&manifest["semanticFreeze"])?;

    let subjects = manifest["subjects"]
        .as_array()
        .ok_or("release manifest has no subjects")?;
    if subjects.is_empty() {
        return Err("release manifest has no subjects".to_owned());
    }
    let mut names = BTreeSet::new();
    for subject in subjects {
        let name = subject["name"]
            .as_str()
            .ok_or("release subject has no name")?;
        validate_safe_relative_path(name)?;
        if !names.insert(name) {
            return Err(format!("duplicate release subject name: {name}"));
        }
        if subject["mediaType"].as_str().is_none_or(str::is_empty)
            || subject["size"].as_u64().is_none_or(|size| size == 0)
        {
            return Err(format!("release subject metadata is incomplete: {name}"));
        }
        validate_sha256(
            subject["sha256"]
                .as_str()
                .ok_or("release subject has no SHA-256")?,
        )?;
        let reproducibility = subject["reproducibility"]
            .as_str()
            .ok_or("release subject has no reproducibility class")?;
        if !REPRODUCIBILITY_CLASSES.contains(&reproducibility) {
            return Err(format!(
                "unsupported release subject reproducibility class: {reproducibility}"
            ));
        }
        if reproducibility == "provenance-only"
            && subject["limitation"].as_str().is_none_or(str::is_empty)
        {
            return Err(format!(
                "provenance-only subject has no named limitation: {name}"
            ));
        }
    }
    let evidence = &manifest["evidence"];
    for field in ["spdx", "provenance", "conformance", "benchmarks"] {
        let references = evidence[field]
            .as_array()
            .ok_or_else(|| format!("release manifest evidence has no {field} array"))?;
        if references.is_empty() {
            return Err(format!("release manifest evidence {field} is empty"));
        }
        for reference in references {
            validate_digest_reference(reference)?;
        }
    }
    validate_digest_reference(&evidence["formalManifest"])
}

fn validate_digest_reference(reference: &Value) -> Result<(), String> {
    validate_safe_relative_path(
        reference["path"]
            .as_str()
            .ok_or("digest reference has no path")?,
    )?;
    validate_sha256(
        reference["sha256"]
            .as_str()
            .ok_or("digest reference has no SHA-256")?,
    )
}

pub(crate) fn validate_safe_relative_path(path: &str) -> Result<(), String> {
    let candidate = Path::new(path);
    if path.is_empty()
        || candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(format!("release path escapes its root: {path}"));
    }
    Ok(())
}

pub(crate) fn validate_sha256(digest: &str) -> Result<(), String> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("invalid SHA-256 digest: {digest}"));
    }
    Ok(())
}

pub(crate) fn validate_full_commit(commit: &str) -> Result<(), String> {
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("release manifest source commit is not a full Git SHA".to_owned());
    }
    Ok(())
}

pub(crate) fn validate_release_tag(tag: &str, version: &str) -> Result<(), String> {
    let expected = format!("auths-v{version}");
    if tag != expected {
        return Err(format!(
            "release tag {tag} does not match workspace version; expected {expected}"
        ));
    }
    Ok(())
}

fn validate_release_candidate_tag(tag: &str) -> Result<(), String> {
    let version = tag
        .strip_prefix("auths-v")
        .ok_or_else(|| format!("release candidate tag has wrong product prefix: {tag}"))?;
    let (core, ordinal) = version
        .rsplit_once("-rc.")
        .ok_or_else(|| format!("release candidate tag has no RC ordinal: {tag}"))?;
    let components = core.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components.iter().any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
        || ordinal
            .parse::<u64>()
            .ok()
            .is_none_or(|ordinal| ordinal == 0)
    {
        return Err(format!(
            "release candidate tag is not valid semver RC form: {tag}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_reference(path: &str) -> Value {
        json!({ "path": path, "sha256": "a".repeat(64) })
    }

    fn valid_manifest() -> Value {
        json!({
            "schema": RELEASE_MANIFEST_SCHEMA,
            "release": {
                "tag": "auths-v1.0.0-rc.1",
                "status": "release-candidate",
            },
            "source": {
                "repository": RELEASE_REPOSITORY,
                "commit": "b".repeat(40),
            },
            "semanticFreeze": digest_reference("release/semantic-freeze.json"),
            "subjects": [{
                "name": "target/package/auths-1.0.0-rc.1.crate",
                "mediaType": "application/vnd.rust.crate",
                "size": 42,
                "sha256": "c".repeat(64),
                "reproducibility": "byte-identical",
            }],
            "evidence": {
                "spdx": [digest_reference("evidence/sbom.spdx.json")],
                "provenance": [digest_reference("evidence/provenance.sigstore.json")],
                "formalManifest": digest_reference("formal/assurance-manifest-v1.toml"),
                "conformance": [digest_reference("evidence/conformance.json")],
                "benchmarks": [digest_reference("evidence/benchmarks.json")],
            },
        })
    }

    #[test]
    fn release_tag_matches_workspace_version() {
        validate_release_tag("auths-v1.0.0-rc.1", "1.0.0-rc.1")
            .expect("product-scoped release tag should pass");
    }

    #[test]
    fn release_tag_rejects_repository_prefix() {
        let error = validate_release_tag(concat!("auths-proof", "-v1.0.0-rc.1"), "1.0.0-rc.1")
            .expect_err("repository-scoped release tag must fail");
        assert!(error.contains("expected auths-v1.0.0-rc.1"));
    }

    #[test]
    fn release_tag_rejects_wrong_version() {
        let error = validate_release_tag("auths-v1.0.0-rc.2", "1.0.0-rc.1")
            .expect_err("wrong release version must fail");
        assert!(error.contains("expected auths-v1.0.0-rc.1"));
    }

    #[test]
    fn release_candidate_tag_rejects_zero_ordinal() {
        let error = validate_release_candidate_tag("auths-v1.0.0-rc.0")
            .expect_err("zero RC ordinal must fail");
        assert!(error.contains("not valid semver RC form"));
    }

    #[test]
    fn spdx_subject_coverage_rejects_missing_subject() {
        let expected = BTreeMap::from([
            ("auths.crate".to_owned(), "a".repeat(64)),
            ("auths.wasm".to_owned(), "b".repeat(64)),
        ]);
        let actual = BTreeMap::from([("auths.crate".to_owned(), "a".repeat(64))]);
        let error = validate_subject_coverage("SPDX", &actual, &expected)
            .expect_err("missing SPDX subject must fail");
        assert!(error.contains("SPDX subject coverage differs"));
    }

    #[test]
    fn provenance_subject_coverage_rejects_wrong_digest() {
        let expected = BTreeMap::from([("auths.crate".to_owned(), "a".repeat(64))]);
        let actual = BTreeMap::from([("auths.crate".to_owned(), "b".repeat(64))]);
        let error = validate_subject_coverage("signed provenance", &actual, &expected)
            .expect_err("wrong provenance subject digest must fail");
        assert!(error.contains("signed provenance subject coverage differs"));
    }

    #[test]
    fn spdx_package_metadata_rejects_missing_declared_license() {
        let spdx = json!({
            "packages": [{
                "name": "auths",
                "versionInfo": "1.0.0-rc.1",
                "licenseDeclared": "NOASSERTION",
                "externalRefs": [{"referenceType": "purl"}],
            }],
        });
        let error = validate_spdx_package_metadata(&spdx)
            .expect_err("missing SPDX license metadata must fail");
        assert!(error.contains("SPDX package metadata is incomplete"));
    }

    #[test]
    fn final_release_manifest_contract_accepts_exact_candidate() {
        validate_release_manifest_value(&valid_manifest())
            .expect("complete exact release manifest should pass");
    }

    #[test]
    fn final_release_manifest_rejects_unknown_schema() {
        let mut manifest = valid_manifest();
        manifest["schema"] = json!("auths.release-manifest/2");
        let error = validate_release_manifest_value(&manifest)
            .expect_err("unknown release schema must fail closed");
        assert!(error.contains("unknown release-manifest schema"));
    }

    #[test]
    fn final_release_manifest_rejects_empty_subjects() {
        let mut manifest = valid_manifest();
        manifest["subjects"] = json!([]);
        let error = validate_release_manifest_value(&manifest)
            .expect_err("empty release subject set must fail closed");
        assert!(error.contains("no subjects"));
    }

    #[test]
    fn final_release_manifest_rejects_duplicate_subject_names() {
        let mut manifest = valid_manifest();
        let duplicate = manifest["subjects"][0].clone();
        manifest["subjects"]
            .as_array_mut()
            .expect("subjects array")
            .push(duplicate);
        let error = validate_release_manifest_value(&manifest)
            .expect_err("duplicate artifact names must fail closed");
        assert!(error.contains("duplicate release subject"));
    }

    #[test]
    fn final_release_manifest_rejects_path_escape() {
        let mut manifest = valid_manifest();
        manifest["subjects"][0]["name"] = json!("../auths.crate");
        let error = validate_release_manifest_value(&manifest)
            .expect_err("relative path escape must fail closed");
        assert!(error.contains("escapes its root"));
    }

    #[test]
    fn final_release_manifest_rejects_unsupported_digest() {
        let mut manifest = valid_manifest();
        manifest["subjects"][0]["sha256"] = json!("sha512:not-supported");
        let error = validate_release_manifest_value(&manifest)
            .expect_err("unsupported digest must fail closed");
        assert!(error.contains("invalid SHA-256"));
    }

    #[test]
    fn final_release_manifest_rejects_unknown_reproducibility_class() {
        let mut manifest = valid_manifest();
        manifest["subjects"][0]["reproducibility"] = json!("reproducible-ish");
        let error = validate_release_manifest_value(&manifest)
            .expect_err("unknown reproducibility class must fail closed");
        assert!(error.contains("unsupported release subject reproducibility"));
    }

    #[test]
    fn provenance_only_subject_requires_named_limitation() {
        let mut manifest = valid_manifest();
        manifest["subjects"][0]["reproducibility"] = json!("provenance-only");
        let error = validate_release_manifest_value(&manifest)
            .expect_err("provenance-only artifact without limitation must fail");
        assert!(error.contains("no named limitation"));
    }

    #[test]
    fn final_release_manifest_requires_every_evidence_class() {
        let mut manifest = valid_manifest();
        manifest["evidence"]["provenance"] = json!([]);
        let error = validate_release_manifest_value(&manifest)
            .expect_err("missing signed provenance reference must fail");
        assert!(error.contains("provenance is empty"));
    }

    #[test]
    fn release_subject_catalogue_rejects_duplicate_family() {
        let bytes = fs::read_to_string(root().join("release/release-subjects.toml"))
            .expect("subject catalogue");
        let mut catalogue: ReleaseSubjectCatalogue =
            toml::from_str(&bytes).expect("valid subject catalogue");
        catalogue.families.push(ReleaseSubjectFamily {
            id: catalogue.families[0].id.clone(),
            coordinate: "duplicate".to_owned(),
            media_type: "application/octet-stream".to_owned(),
            reproducibility: "byte-identical".to_owned(),
            producer: "test".to_owned(),
            publication: "never".to_owned(),
        });
        let error = validate_release_subject_catalogue(&catalogue)
            .expect_err("duplicate subject family must fail closed");
        assert!(error.contains("duplicate release subject family"));
    }

    #[test]
    fn promotion_job_rejects_hidden_rebuild() {
        let error = validate_no_rebuild_promotion_job(
            "sha256sum \"$MANIFEST\"\nrepos/auths-dev/auths-proof/git/refs\ngh release create\ncargo build",
        )
        .expect_err("promotion rebuild must fail closed");
        assert!(error.contains("forbidden build"));
    }

    #[test]
    fn release_archive_encoding_is_deterministic() {
        let first = root().join("target/release-archive-determinism-a.tar.zst");
        let second = root().join("target/release-archive-determinism-b.tar.zst");
        let files = BTreeMap::from([
            ("Cargo.toml".to_owned(), 0o644),
            (
                "core/fixtures/v1/indeterminate/accepted-extension-without-handler.action.cbor"
                    .to_owned(),
                0o644,
            ),
        ]);
        write_deterministic_archive(&first, "auths-test", &files, 1)
            .expect("first deterministic archive");
        write_deterministic_archive(&second, "auths-test", &files, 1)
            .expect("second deterministic archive");
        assert_eq!(
            sha256_file(&first).expect("first digest"),
            sha256_file(&second).expect("second digest")
        );
        fs::remove_file(first).expect("remove first archive");
        fs::remove_file(second).expect("remove second archive");
    }
}
