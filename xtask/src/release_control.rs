use crate::*;
use auths_profile_kit::QualificationReleaseBuild;

const PREPARATION_COMPARISON_SCHEMA: &str = "auths.preparation-comparison/1";
const PROMOTION_REQUEST_SCHEMA: &str = "auths.promotion-request/1";
const OWNER_AUTHORIZATION_SCHEMA: &str = "auths.owner-release-authorization/1";
const OWNER_AUTHORIZATION_STATEMENT: &str =
    "I authorize promotion of these exact prepared bytes to a GitHub prerelease.";
const EXPECTED_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
const EXPECTED_OIDC_SUBJECT: &str =
    "repo:auths-dev@260513770/auths-proof@1310728509:ref:refs/heads/main";
const EXPECTED_BUILDER_WORKFLOW: &str =
    "auths-dev/auths-proof/.github/workflows/release-builder.yml";
const SLSA_ASSESSMENT_PATH: &str = "release/slsa-build-level-3-assessment.json";
const SLSA_ASSESSMENT_EVIDENCE_PATH: &str =
    "target/release-evidence/slsa-build-level-3-assessment.json";
const SLSA_ASSESSMENT_SCHEMA: &str = "auths.slsa-build-assessment/1";
const SLSA_TARGET: &str = "SLSA 1.2 Build Level 3";
const ASSESSED_BUILDER_PATH: &str = ".github/workflows/release-builder.yml";
const ASSESSED_BUILDER_EVIDENCE_PATH: &str = "target/release-evidence/release-builder.yml";
const REQUIRED_SLSA_REQUIREMENTS: [&str; 8] = [
    "build-l1-consistent-process",
    "build-l1-provenance-exists",
    "build-l1-provenance-distributed",
    "build-l2-hosted-platform",
    "build-l2-authentic-provenance",
    "build-l2-consumer-verification",
    "build-l3-isolated-builds",
    "build-l3-signing-secrets-inaccessible",
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnerAuthorizationRecord {
    schema: String,
    operation: String,
    repository: String,
    authorized_by: String,
    authorized_by_id: String,
    issued_at: String,
    candidate_commit: String,
    tag: String,
    manifest_sha256: String,
    preparation_run_id: String,
    destinations: Vec<String>,
    statement: String,
}

pub(crate) fn release_control(arguments: Vec<String>) -> Result<(), String> {
    match arguments.as_slice() {
        [command, tag, commit, provenance, trusted_root, verification, workflow, digest]
            if command == "finalize" =>
        {
            finalize_preparation(
                tag,
                commit,
                Path::new(provenance),
                Path::new(trusted_root),
                Path::new(verification),
                workflow,
                digest,
            )
        }
        [command, first, second, output] if command == "compare" => {
            compare_preparations(Path::new(first), Path::new(second), Path::new(output))
        }
        [command, staged, request, authorization] if command == "verify-promotion" => {
            verify_promotion(
                Path::new(staged),
                Path::new(request),
                Path::new(authorization),
            )
        }
        [command, input, output] if command == "canonicalize-qualification-build" => {
            canonicalize_qualification_build(Path::new(input), Path::new(output))
        }
        [command, release_build, surface, members, artifact_root, commit]
            if command == "verify-qualification-release-build" =>
        {
            verify_qualification_release_build_files(
                Path::new(release_build),
                Path::new(surface),
                Path::new(members),
                Path::new(artifact_root),
                commit,
            )
        }
        _ => Err(
            "usage: cargo xtask release-control <finalize TAG COMMIT PROVENANCE TRUSTED_ROOT VERIFICATION BUILDER_WORKFLOW BUILDER_DIGEST|compare FIRST SECOND OUTPUT|verify-promotion STAGED REQUEST AUTHORIZATION|canonicalize-qualification-build INPUT OUTPUT|verify-qualification-release-build RELEASE_BUILD SURFACE MEMBERS ARTIFACT_ROOT COMMIT>"
                .to_owned(),
        ),
    }
}

fn canonicalize_qualification_build(input: &Path, output: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(input)
        .map_err(|error| format!("could not inspect qualification release build: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > 262_144
    {
        return Err("qualification release build input is not a bounded regular file".to_owned());
    }
    let bytes = fs::read(input)
        .map_err(|error| format!("could not read qualification release build: {error}"))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("qualification release build is not JSON: {error}"))?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| format!("could not canonicalize qualification release build: {error}"))?;
    let build = QualificationReleaseBuild::from_json(&canonical)
        .map_err(|error| format!("qualification release build is invalid: {error}"))?;
    let verified = build
        .canonical_json()
        .map_err(|error| format!("could not encode qualification release build: {error}"))?;
    if canonical != verified {
        return Err("qualification release build canonical projection drifted".to_owned());
    }
    if output.exists() {
        return Err(format!(
            "qualification release build output already exists: {}",
            output.display()
        ));
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create qualification release output: {error}"))?;
    }
    fs::write(output, verified)
        .map_err(|error| format!("could not write qualification release build: {error}"))
}

fn finalize_preparation(
    tag: &str,
    commit: &str,
    provenance_source: &Path,
    trusted_root_source: &Path,
    verification_source: &Path,
    builder_workflow: &str,
    builder_digest: &str,
) -> Result<(), String> {
    validate_release_tag(tag, env!("CARGO_PKG_VERSION"))?;
    validate_full_commit(commit)?;
    validate_full_commit(builder_digest)?;
    if builder_workflow != EXPECTED_BUILDER_WORKFLOW {
        return Err(format!(
            "release builder workflow identity differs: {builder_workflow}"
        ));
    }
    let evidence = root().join("target/release-evidence");
    let input: Value = read_json(
        &evidence.join("release-manifest.input.json"),
        "release-manifest input",
    )?;
    if input["schema"] != "auths.release-manifest-input/1"
        || input["targetSchema"] != RELEASE_MANIFEST_SCHEMA
        || input["source"]["repository"] != RELEASE_REPOSITORY
        || input["source"]["commit"] != commit
    {
        return Err("release-manifest input does not match the candidate".to_owned());
    }
    let subjects = subject_map(&input)?;
    if subjects.is_empty() {
        return Err("release-manifest input has no subjects".to_owned());
    }

    let provenance_path = copy_evidence_file(
        provenance_source,
        &evidence.join("provenance.sigstore.json"),
        "signed provenance bundle",
    )?;
    let trusted_root_path = copy_evidence_file(
        trusted_root_source,
        &evidence.join("trusted-root.jsonl"),
        "Sigstore trusted root",
    )?;
    let verification_path = copy_evidence_file(
        verification_source,
        &evidence.join("attestation-verification.json"),
        "attestation verification report",
    )?;
    validate_attestation_verification(&verification_path, &subjects)?;
    validate_slsa_assessment(&root(), SLSA_ASSESSMENT_PATH, ASSESSED_BUILDER_PATH)?;
    copy_evidence_file(
        &root().join(SLSA_ASSESSMENT_PATH),
        &root().join(SLSA_ASSESSMENT_EVIDENCE_PATH),
        "SLSA Build Level 3 assessment",
    )?;
    copy_evidence_file(
        &root().join(ASSESSED_BUILDER_PATH),
        &root().join(ASSESSED_BUILDER_EVIDENCE_PATH),
        "assessed reusable builder",
    )?;
    copy_evidence_file(
        &root().join("release/RELEASE_CANDIDATE_NOTES.md"),
        &root().join("target/release-evidence/RELEASE_CANDIDATE_NOTES.md"),
        "release-candidate notes",
    )?;

    let subject_values = input["subjects"]
        .as_array()
        .ok_or("release-manifest input subjects are not an array")?
        .clone();
    let manifest = json!({
        "schema": RELEASE_MANIFEST_SCHEMA,
        "release": {
            "tag": tag,
            "status": "release-candidate",
        },
        "source": {
            "repository": RELEASE_REPOSITORY,
            "commit": commit,
        },
        "semanticFreeze": input["semanticFreeze"].clone(),
        "subjects": subject_values,
        "builder": {
            "workflow": builder_workflow,
            "workflowDigest": builder_digest,
            "environment": null,
            "oidcIssuer": EXPECTED_OIDC_ISSUER,
            "oidcSubject": EXPECTED_OIDC_SUBJECT,
            "slsaTarget": SLSA_TARGET,
            "slsaAssessmentStatus": "passed",
            "slsaAssessment": digest_reference(SLSA_ASSESSMENT_EVIDENCE_PATH)?,
            "slsaBuilderWorkflow": digest_reference(ASSESSED_BUILDER_EVIDENCE_PATH)?,
        },
        "evidence": {
            "spdx": [digest_reference("target/release-evidence/sbom.spdx.json")?],
            "provenance": [digest_reference(path_text(&provenance_path)?)?],
            "formalManifest": digest_reference("formal/assurance-manifest-v1.toml")?,
            "conformance": [
                digest_reference("target/release-evidence/platform.json")?,
                digest_reference("target/compliance/report.json")?,
            ],
            "benchmarks": [
                digest_reference("demos/benchmarks/profiles/release.toml")?,
                digest_reference("docs/research/domains/0004-seven-domain-bounded-authorization-performance-baseline.md")?,
            ],
            "releaseNotes": digest_reference("target/release-evidence/RELEASE_CANDIDATE_NOTES.md")?,
            "trustedRoot": digest_reference(path_text(&trusted_root_path)?)?,
            "attestationVerification": digest_reference(path_text(&verification_path)?)?,
        },
        "limitations": [
            "Preparation is not publication authorization.",
            "The SLSA Build Level 3 assessment is bound to the exact reusable-builder bytes and becomes stale if they change.",
            "No independent security audit is claimed.",
        ],
    });
    validate_release_manifest_value(&manifest)?;
    validate_manifest_files(&manifest, &root())?;
    let mut bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("could not encode final release manifest: {error}"))?;
    bytes.push(b'\n');
    let manifest_path = evidence.join("release-manifest.json");
    fs::write(&manifest_path, &bytes)
        .map_err(|error| format!("could not write {}: {error}", manifest_path.display()))?;
    let digest = hex::encode(Sha256::digest(&bytes));
    fs::write(
        evidence.join("release-manifest.sha256"),
        format!("{digest}  release-manifest.json\n"),
    )
    .map_err(|error| format!("could not write release-manifest digest: {error}"))?;
    println!("finalized release preparation manifest {digest}; publication remains blocked");
    Ok(())
}

fn compare_preparations(first: &Path, second: &Path, output: &Path) -> Result<(), String> {
    let first_manifest = read_json(first, "first release manifest")?;
    let second_manifest = read_json(second, "second release manifest")?;
    validate_release_manifest_value(&first_manifest)?;
    validate_release_manifest_value(&second_manifest)?;
    if first_manifest["source"] != second_manifest["source"]
        || first_manifest["release"] != second_manifest["release"]
        || first_manifest["semanticFreeze"] != second_manifest["semanticFreeze"]
    {
        return Err("isolated preparations do not describe the same candidate".to_owned());
    }
    let first_subjects = indexed_subjects(&first_manifest)?;
    let second_subjects = indexed_subjects(&second_manifest)?;
    if first_subjects.keys().collect::<Vec<_>>() != second_subjects.keys().collect::<Vec<_>>() {
        return Err("isolated preparation subject sets differ".to_owned());
    }
    let mut comparisons = Vec::new();
    for (name, first_subject) in first_subjects {
        let second_subject = second_subjects
            .get(name)
            .ok_or_else(|| format!("second preparation is missing {name}"))?;
        comparisons.push(compare_subject_pair(name, first_subject, second_subject)?);
    }
    let report = json!({
        "schema": PREPARATION_COMPARISON_SCHEMA,
        "status": "passed",
        "candidate": first_manifest["source"].clone(),
        "release": first_manifest["release"].clone(),
        "firstManifestSha256": sha256_file(first)?,
        "secondManifestSha256": sha256_file(second)?,
        "subjects": comparisons,
        "limitations": [
            "Matching isolated outputs does not establish source correctness or artifact security.",
            "Provenance-only subjects are not described as reproducible.",
        ],
    });
    write_json(output, &report, "preparation comparison")?;
    println!("isolated release preparation comparison passed");
    Ok(())
}

fn compare_subject_pair(name: &str, first: &Value, second: &Value) -> Result<Value, String> {
    let class = first["reproducibility"]
        .as_str()
        .ok_or_else(|| format!("subject has no reproducibility class: {name}"))?;
    if second["reproducibility"] != class
        || second["mediaType"] != first["mediaType"]
        || second["platform"] != first["platform"]
    {
        return Err(format!("release subject classification differs: {name}"));
    }
    let digest_equal = first["sha256"] == second["sha256"];
    let size_equal = first["size"] == second["size"];
    let must_match = matches!(
        class,
        "byte-identical" | "deterministic-evidence" | "platform-reproducible"
    );
    if must_match && (!digest_equal || !size_equal) {
        return Err(format!(
            "{class} release subject differs between isolated preparations: {name}"
        ));
    }
    Ok(json!({
        "name": name,
        "reproducibility": class,
        "digestEqual": digest_equal,
        "sizeEqual": size_equal,
        "result": if must_match { "matched" } else { "provenance-only" },
    }))
}

fn verify_promotion(
    staged: &Path,
    request_path: &Path,
    authorization_path: &Path,
) -> Result<(), String> {
    let manifest_path = staged.join("target/release-evidence/release-manifest.json");
    let manifest = read_json(&manifest_path, "staged release manifest")?;
    validate_release_manifest_value(&manifest)?;
    validate_manifest_files(&manifest, staged)?;
    let request = read_json(request_path, "promotion request")?;
    if request["schema"] != PROMOTION_REQUEST_SCHEMA
        || request["operation"] != "promote-prepared-candidate"
        || request["candidateCommit"] != manifest["source"]["commit"]
        || request["tag"] != manifest["release"]["tag"]
        || request["manifestSha256"] != sha256_file(&manifest_path)?
        || request["destinations"] != json!(["github-prerelease"])
    {
        return Err("promotion request differs from the staged candidate".to_owned());
    }
    let authorization_digest = request["ownerAuthorizationSha256"]
        .as_str()
        .ok_or("promotion request has no owner authorization digest")?;
    validate_sha256(authorization_digest)?;
    if sha256_file(authorization_path)? != authorization_digest {
        return Err("owner authorization bytes differ from the promotion request".to_owned());
    }
    let authorization = read_canonical_owner_authorization(authorization_path)?;
    validate_owner_authorization(&authorization, &manifest, &request)?;
    if request["preparationRunId"]
        .as_str()
        .is_none_or(str::is_empty)
    {
        return Err("promotion request has no preparation run identity".to_owned());
    }
    validate_slsa_promotion_status(&manifest)?;
    println!("promotion request matches exact staged bytes; no build was performed");
    Ok(())
}

fn read_canonical_owner_authorization(path: &Path) -> Result<OwnerAuthorizationRecord, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("could not read owner authorization record: {error}"))?;
    let authorization: OwnerAuthorizationRecord = serde_json::from_slice(&bytes)
        .map_err(|error| format!("owner authorization record is not valid JSON: {error}"))?;
    let mut canonical = serde_json::to_vec(&authorization)
        .map_err(|error| format!("could not encode owner authorization record: {error}"))?;
    canonical.push(b'\n');
    if bytes != canonical {
        return Err(
            "owner authorization record is not canonical compact JSON with one trailing newline"
                .to_owned(),
        );
    }
    Ok(authorization)
}

fn validate_owner_authorization(
    authorization: &OwnerAuthorizationRecord,
    manifest: &Value,
    request: &Value,
) -> Result<(), String> {
    if authorization.schema != OWNER_AUTHORIZATION_SCHEMA
        || authorization.operation != "promote-prepared-candidate"
        || authorization.repository != RELEASE_REPOSITORY
        || authorization.authorized_by != "bordumb"
        || authorization.authorized_by_id != "3743841"
        || !is_utc_second_timestamp(&authorization.issued_at)
        || authorization.candidate_commit != manifest["source"]["commit"]
        || authorization.tag != manifest["release"]["tag"]
        || authorization.manifest_sha256 != request["manifestSha256"]
        || authorization.preparation_run_id != request["preparationRunId"]
        || authorization
            .preparation_run_id
            .parse::<u64>()
            .ok()
            .is_none_or(|run| run == 0)
        || authorization.destinations != ["github-prerelease"]
        || authorization.statement != OWNER_AUTHORIZATION_STATEMENT
    {
        return Err("owner authorization does not authorize the exact promotion".to_owned());
    }
    Ok(())
}

fn is_utc_second_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return false;
    }
    let component = |start: usize, end: usize| {
        value[start..end]
            .parse::<u32>()
            .expect("validated ASCII digits")
    };
    (1..=12).contains(&component(5, 7))
        && (1..=31).contains(&component(8, 10))
        && component(11, 13) < 24
        && component(14, 16) < 60
        && component(17, 19) < 60
}

fn validate_slsa_promotion_status(manifest: &Value) -> Result<(), String> {
    if manifest["builder"]["slsaTarget"] != SLSA_TARGET
        || manifest["builder"]["slsaAssessmentStatus"] != "passed"
    {
        return Err(
            "promotion blocked: SLSA 1.2 Build Level 3 runtime assessment has not passed"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_slsa_assessment(
    base: &Path,
    assessment_path: &str,
    builder_path: &str,
) -> Result<(), String> {
    let path = base.join(assessment_path);
    let assessment = read_json(&path, "SLSA Build Level 3 assessment")?;
    if assessment["schema"] != SLSA_ASSESSMENT_SCHEMA
        || assessment["specification"] != "https://slsa.dev/spec/v1.2/requirements"
        || assessment["target"] != SLSA_TARGET
        || assessment["status"] != "passed"
        || assessment["assessmentNature"] != "repository-owner-delegated-technical-assessment"
        || assessment["assessedBuilder"]["platform"] != "github-actions"
        || assessment["assessedBuilder"]["workflow"] != ASSESSED_BUILDER_PATH
        || assessment["assessedBuilder"]["workflowEvidence"] != ASSESSED_BUILDER_EVIDENCE_PATH
        || assessment["assessedBuilder"]["runner"] != "github-hosted/ubuntu-latest"
        || assessment["assessedBuilder"]["provenance"]
            != "github-artifact-attestations/slsa-provenance-v1"
    {
        return Err("SLSA Build Level 3 assessment metadata is incomplete".to_owned());
    }
    let expected_workflow_digest = assessment["assessedBuilder"]["workflowSha256"]
        .as_str()
        .ok_or("SLSA assessment has no workflow SHA-256")?;
    validate_sha256(expected_workflow_digest)?;
    let actual_workflow_digest = sha256_file(&base.join(builder_path))?;
    if expected_workflow_digest != actual_workflow_digest {
        return Err(
            "SLSA Build Level 3 assessment is stale: reusable builder bytes changed".to_owned(),
        );
    }
    validate_full_commit(
        assessment["runtimeEvidence"]["candidateCommit"]
            .as_str()
            .ok_or("SLSA assessment has no assessed candidate commit")?,
    )?;
    validate_sha256(
        assessment["runtimeEvidence"]["releaseManifestSha256"]
            .as_str()
            .ok_or("SLSA assessment has no release-manifest SHA-256")?,
    )?;
    for field in [
        "preparationRunId",
        "preparationRunUrl",
        "candidateTag",
        "officialAttestation",
        "reproductionAttestation",
    ] {
        if assessment["runtimeEvidence"][field]
            .as_str()
            .is_none_or(str::is_empty)
        {
            return Err(format!("SLSA assessment runtime evidence has no {field}"));
        }
    }
    let requirements = assessment["requirements"]
        .as_array()
        .ok_or("SLSA assessment has no requirements")?;
    let actual = requirements
        .iter()
        .map(|requirement| {
            let id = requirement["id"]
                .as_str()
                .ok_or("SLSA assessment requirement has no id")?;
            if requirement["status"] != "passed" {
                return Err(format!("SLSA assessment requirement did not pass: {id}"));
            }
            Ok(id)
        })
        .collect::<Result<BTreeSet<_>, String>>()?;
    let expected = REQUIRED_SLSA_REQUIREMENTS
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual != expected || requirements.len() != expected.len() {
        return Err("SLSA assessment requirement set is incomplete".to_owned());
    }
    if assessment["limitations"]
        .as_array()
        .is_none_or(|limitations| limitations.len() < 4)
    {
        return Err("SLSA assessment limitations are incomplete".to_owned());
    }
    Ok(())
}

fn validate_attestation_verification(
    path: &Path,
    expected: &BTreeMap<String, String>,
) -> Result<(), String> {
    let report = read_json(path, "attestation verification report")?;
    let entries = report
        .as_array()
        .ok_or("attestation verification report is not an array")?;
    if entries.is_empty() {
        return Err("attestation verification report is empty".to_owned());
    }
    let mut actual = BTreeMap::new();
    for entry in entries {
        let result = &entry["verificationResult"];
        if result["statement"]["predicateType"] != "https://slsa.dev/provenance/v1" {
            return Err("attestation predicate is not SLSA provenance v1".to_owned());
        }
        for subject in result["statement"]["subject"]
            .as_array()
            .ok_or("verified attestation has no subjects")?
        {
            let name = subject["name"]
                .as_str()
                .ok_or("verified attestation subject has no name")?;
            let digest = subject["digest"]["sha256"]
                .as_str()
                .ok_or("verified attestation subject has no SHA-256")?;
            validate_sha256(digest)?;
            if let Some(previous) = actual.insert(name.to_owned(), digest.to_owned())
                && previous != digest
            {
                return Err(format!(
                    "verified attestation contains conflicting digests for {name}"
                ));
            }
        }
    }
    if &actual != expected {
        return Err("verified provenance subjects differ from release subjects".to_owned());
    }
    Ok(())
}

fn validate_manifest_files(manifest: &Value, base: &Path) -> Result<(), String> {
    for subject in manifest["subjects"]
        .as_array()
        .ok_or("release manifest has no subjects")?
    {
        validate_file_digest(base, subject["name"].as_str(), subject["sha256"].as_str())?;
    }
    validate_digest_reference_file(base, &manifest["semanticFreeze"])?;
    let evidence = &manifest["evidence"];
    for field in ["spdx", "provenance", "conformance", "benchmarks"] {
        for reference in evidence[field]
            .as_array()
            .ok_or_else(|| format!("release evidence has no {field}"))?
        {
            validate_digest_reference_file(base, reference)?;
        }
    }
    for field in [
        "formalManifest",
        "releaseNotes",
        "trustedRoot",
        "attestationVerification",
    ] {
        validate_digest_reference_file(base, &evidence[field])?;
    }
    validate_digest_reference_file(base, &manifest["builder"]["slsaAssessment"])?;
    validate_digest_reference_file(base, &manifest["builder"]["slsaBuilderWorkflow"])?;
    validate_slsa_assessment(
        base,
        manifest["builder"]["slsaAssessment"]["path"]
            .as_str()
            .ok_or("release manifest has no SLSA assessment path")?,
        manifest["builder"]["slsaBuilderWorkflow"]["path"]
            .as_str()
            .ok_or("release manifest has no assessed builder path")?,
    )?;
    Ok(())
}

fn validate_digest_reference_file(base: &Path, reference: &Value) -> Result<(), String> {
    validate_file_digest(
        base,
        reference["path"].as_str(),
        reference["sha256"].as_str(),
    )
}

fn validate_file_digest(
    base: &Path,
    path: Option<&str>,
    digest: Option<&str>,
) -> Result<(), String> {
    let path = path.ok_or("digest-bound file has no path")?;
    let digest = digest.ok_or("digest-bound file has no SHA-256")?;
    validate_safe_relative_path(path)?;
    validate_sha256(digest)?;
    let actual = sha256_file(&base.join(path))?;
    if actual != digest {
        return Err(format!("digest-bound file differs from manifest: {path}"));
    }
    Ok(())
}

fn indexed_subjects(manifest: &Value) -> Result<BTreeMap<&str, &Value>, String> {
    manifest["subjects"]
        .as_array()
        .ok_or("release manifest has no subjects")?
        .iter()
        .map(|subject| {
            subject["name"]
                .as_str()
                .ok_or_else(|| "release subject has no name".to_owned())
                .map(|name| (name, subject))
        })
        .collect()
}

fn digest_reference(path: &str) -> Result<Value, String> {
    validate_safe_relative_path(path)?;
    Ok(json!({ "path": path, "sha256": sha256_file(&root().join(path))? }))
}

fn copy_evidence_file(source: &Path, destination: &Path, label: &str) -> Result<PathBuf, String> {
    if !source.is_file() {
        return Err(format!("{label} is absent: {}", source.display()));
    }
    let source_identity =
        fs::canonicalize(source).map_err(|error| format!("could not resolve {label}: {error}"))?;
    let destination_identity = fs::canonicalize(destination).ok();
    if destination_identity.as_ref() != Some(&source_identity) {
        fs::copy(source, destination).map_err(|error| {
            format!(
                "could not copy {label} to {}: {error}",
                destination.display()
            )
        })?;
    }
    destination
        .strip_prefix(root())
        .map(Path::to_path_buf)
        .map_err(|_| format!("{label} destination escaped repository"))
}

fn read_json(path: &Path, label: &str) -> Result<Value, String> {
    serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("could not read {label}: {error}"))?,
    )
    .map_err(|error| format!("{label} is not valid JSON: {error}"))
}

fn write_json(path: &Path, value: &Value, label: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not encode {label}: {error}"))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| format!("could not write {label}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(name: &str, digest: char, class: &str) -> Value {
        json!({
            "name": name,
            "mediaType": "application/octet-stream",
            "size": 1,
            "sha256": std::iter::repeat_n(digest, 64).collect::<String>(),
            "reproducibility": class,
        })
    }

    fn owner_authorization() -> OwnerAuthorizationRecord {
        OwnerAuthorizationRecord {
            schema: OWNER_AUTHORIZATION_SCHEMA.to_owned(),
            operation: "promote-prepared-candidate".to_owned(),
            repository: RELEASE_REPOSITORY.to_owned(),
            authorized_by: "bordumb".to_owned(),
            authorized_by_id: "3743841".to_owned(),
            issued_at: "2026-08-03T12:00:00Z".to_owned(),
            candidate_commit: "b".repeat(40),
            tag: "auths-v1.0.0-rc.1".to_owned(),
            manifest_sha256: "a".repeat(64),
            preparation_run_id: "30849197798".to_owned(),
            destinations: vec!["github-prerelease".to_owned()],
            statement: OWNER_AUTHORIZATION_STATEMENT.to_owned(),
        }
    }

    fn authorization_manifest_and_request() -> (Value, Value) {
        (
            json!({
                "source": {"commit": "b".repeat(40)},
                "release": {"tag": "auths-v1.0.0-rc.1"},
            }),
            json!({
                "manifestSha256": "a".repeat(64),
                "preparationRunId": "30849197798",
            }),
        )
    }

    #[test]
    fn changed_byte_identical_subject_is_terminal() {
        let first = subject("auths.crate", 'a', "byte-identical");
        let second = subject("auths.crate", 'b', "byte-identical");
        let error = compare_subject_pair("auths.crate", &first, &second)
            .expect_err("changed byte-identical subject must fail");
        assert!(error.contains("differs between isolated preparations"));
    }

    #[test]
    fn provenance_verification_rejects_wrong_subject_digest() {
        let expected = BTreeMap::from([("auths.crate".to_owned(), "a".repeat(64))]);
        let report = json!([{
            "verificationResult": {
                "statement": {
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "subject": [{"name": "auths.crate", "digest": {"sha256": "b".repeat(64)}}],
                }
            }
        }]);
        let temporary = root().join("target/release-control-test-verification.json");
        write_json(&temporary, &report, "test verification").expect("write report");
        let error = validate_attestation_verification(&temporary, &expected)
            .expect_err("wrong provenance digest must fail");
        fs::remove_file(&temporary).expect("remove report");
        assert!(error.contains("subjects differ"));
    }

    #[test]
    fn immutable_builder_identity_is_exact() {
        assert_eq!(
            EXPECTED_OIDC_SUBJECT,
            "repo:auths-dev@260513770/auths-proof@1310728509:ref:refs/heads/main"
        );
        assert_eq!(
            EXPECTED_BUILDER_WORKFLOW,
            "auths-dev/auths-proof/.github/workflows/release-builder.yml"
        );
    }

    #[test]
    fn promotion_rejects_pending_slsa_runtime_assessment() {
        let manifest = json!({
            "builder": {
                "slsaTarget": "SLSA 1.2 Build Level 3",
                "slsaAssessmentStatus": "pending-runtime-assessment",
            }
        });
        let error = validate_slsa_promotion_status(&manifest)
            .expect_err("pending runtime assessment must block promotion");
        assert!(error.contains("has not passed"));
    }

    #[test]
    fn checked_in_slsa_assessment_matches_builder_bytes() {
        validate_slsa_assessment(&root(), SLSA_ASSESSMENT_PATH, ASSESSED_BUILDER_PATH)
            .expect("checked-in assessment must be current");
    }

    #[test]
    fn slsa_assessment_rejects_changed_builder_bytes() {
        let temporary = root().join("target/release-control-slsa-staleness-test");
        fs::create_dir_all(temporary.join("release")).expect("create release test directory");
        fs::create_dir_all(temporary.join(".github/workflows"))
            .expect("create workflow test directory");
        fs::copy(
            root().join(SLSA_ASSESSMENT_PATH),
            temporary.join(SLSA_ASSESSMENT_PATH),
        )
        .expect("copy assessment");
        fs::write(
            temporary.join(ASSESSED_BUILDER_PATH),
            b"name: changed builder\n",
        )
        .expect("write changed builder");
        let error =
            validate_slsa_assessment(&temporary, SLSA_ASSESSMENT_PATH, ASSESSED_BUILDER_PATH)
                .expect_err("changed builder must stale assessment");
        fs::remove_dir_all(&temporary).expect("remove test directory");
        assert!(error.contains("assessment is stale"));
    }

    #[test]
    fn promotion_accepts_passed_slsa_runtime_assessment() {
        let manifest = json!({
            "builder": {
                "slsaTarget": SLSA_TARGET,
                "slsaAssessmentStatus": "passed",
            }
        });
        validate_slsa_promotion_status(&manifest).expect("passed assessment should promote");
    }

    #[test]
    fn exact_owner_authorization_passes() {
        let (manifest, request) = authorization_manifest_and_request();
        validate_owner_authorization(&owner_authorization(), &manifest, &request)
            .expect("exact authorization must pass");
    }

    #[test]
    fn owner_authorization_rejects_different_manifest() {
        let (manifest, mut request) = authorization_manifest_and_request();
        request["manifestSha256"] = json!("c".repeat(64));
        let error = validate_owner_authorization(&owner_authorization(), &manifest, &request)
            .expect_err("different manifest must fail");
        assert!(error.contains("exact promotion"));
    }

    #[test]
    fn owner_authorization_rejects_noncanonical_bytes() {
        let temporary = root().join("target/release-control-owner-authorization-test.json");
        write_json(
            &temporary,
            &serde_json::to_value(owner_authorization()).expect("encode authorization"),
            "test owner authorization",
        )
        .expect("write pretty authorization");
        let error = read_canonical_owner_authorization(&temporary)
            .expect_err("pretty authorization must fail");
        fs::remove_file(&temporary).expect("remove authorization");
        assert!(error.contains("not canonical compact JSON"));
    }
}
