//! The release projection reads only the gateway build's pinned root and
//! clean candidate inputs. Missing qualification does not prevent an RC;
//! it computes false and never promotes a human or production claim.

use auths_gateway::{ClockTrustState, DeploymentClock as _};
use auths_recipe_qualification::{
    GatewaySemanticClosure, GitCommit, LaunchCandidate, QualificationEvidence, QualificationInputs,
    QualificationReleaseIndex, QualificationTarget, QualificationTrustRoot,
    RecipeQualificationRecord, VerifiedQualifications, VerifierState,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{fs, io::Read as _, path::Path, process::Command};

fn bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "qualification input unavailable")?;
    if !metadata.file_type().is_file() || metadata.len() > maximum as u64 {
        return Err("qualification input invalid or oversized".to_owned());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "qualification input unavailable")?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "qualification input unavailable")?;
    if bytes.len() > maximum {
        return Err("qualification input oversized".to_owned());
    }
    Ok(bytes)
}

fn candidate(repository: &Path, commit: &str) -> Result<LaunchCandidate, String> {
    let status = Command::new("cargo")
        .args([
            "build",
            "--locked",
            "--release",
            "-p",
            "auths-gateway",
            "--bin",
            "auths-gateway",
        ])
        .current_dir(repository)
        .status()
        .map_err(|_| "candidate build unavailable")?;
    if !status.success() {
        return Err("candidate build failed".to_owned());
    }
    let executable = bounded(
        &repository.join("target/release/auths-gateway"),
        128 * 1024 * 1024,
    )?;
    let closure = GatewaySemanticClosure::from_canonical_json(&bounded(
        &repository.join("product/runtime/auths-gateway/semantic-closure.json"),
        auths_recipe_qualification::MAX_SEMANTIC_CLOSURE_BYTES,
    )?)
    .map_err(|_| "candidate closure invalid")?;
    if closure.digest().to_hex() != auths_gateway::GATEWAY_SEMANTIC_CLOSURE_SHA256 {
        return Err("candidate closure differs from compiled gateway".to_owned());
    }
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "macos",
        _ => return Err("candidate OS unsupported".to_owned()),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => return Err("candidate architecture unsupported".to_owned()),
    };
    let target: QualificationTarget = serde_json::from_value(json!({
        "os": os, "arch": arch, "gateway_package": "auths-gateway",
        "gateway_version": env!("CARGO_PKG_VERSION"),
        "gateway_build_sha256": hex::encode(Sha256::digest(&executable)),
        "store_kind": "postgresql-v1", "store_schema": auths_gateway::POSTGRES_STORE_SCHEMA,
        "credential_store_kind": "aws-secrets-manager-v1",
    }))
    .map_err(|_| "candidate target invalid")?;
    Ok(LaunchCandidate {
        commit: GitCommit::parse(commit).map_err(|_| "candidate commit invalid")?,
        gateway_semantic_closure_sha256: closure.digest(),
        target,
    })
}

fn evaluate(
    repository: &Path,
    candidate: &LaunchCandidate,
    root: &QualificationTrustRoot,
    now: u64,
) -> Result<bool, String> {
    let directory = repository
        .join("target/qualification-release")
        .join(candidate.commit.as_str());
    let index = bounded(
        &directory.join(auths_recipe_qualification::RELEASE_INDEX_FILE),
        auths_recipe_qualification::MAX_RELEASE_INDEX_BYTES,
    )?;
    let parsed_index = QualificationReleaseIndex::from_canonical_json(&index)
        .map_err(|_| "qualification index invalid")?;
    let certificate = bounded(
        &directory.join(auths_recipe_qualification::RELEASE_SIGNER_CERTIFICATE_FILE),
        auths_recipe_qualification::MAX_SIGNER_CERTIFICATE_BYTES,
    )?;
    let revocations = bounded(
        &directory.join(auths_recipe_qualification::RELEASE_REVOCATION_LIST_FILE),
        auths_recipe_qualification::MAX_REVOCATION_LIST_BYTES,
    )?;
    let mut records = Vec::new();
    let mut attestations = Vec::new();
    let mut evidence = Vec::new();
    for entry in &parsed_index.body().statement.entries {
        let name = format!("{}.json", entry.qualification_id.as_str());
        let bytes = bounded(
            &directory
                .join(auths_recipe_qualification::RELEASE_RECORDS_DIRECTORY)
                .join(&name),
            auths_recipe_qualification::MAX_RECORD_BYTES,
        )?;
        let record = RecipeQualificationRecord::from_canonical_json(&bytes)
            .map_err(|_| "qualification record invalid")?;
        for member in &record.body().evidence {
            let path = directory
                .join("evidence")
                .join(format!("{}.json", member.evidence_sha256.to_hex()));
            evidence.push(
                QualificationEvidence::from_canonical_json(&bounded(
                    &path,
                    auths_recipe_qualification::MAX_EVIDENCE_BYTES,
                )?)
                .map_err(|_| "qualification evidence invalid")?,
            );
        }
        records.push(bytes);
        attestations.push(bounded(
            &directory
                .join(auths_recipe_qualification::RELEASE_ATTESTATIONS_DIRECTORY)
                .join(name),
            auths_recipe_qualification::MAX_ATTESTATION_BYTES,
        )?);
    }
    let record_refs: Vec<&[u8]> = records.iter().map(Vec::as_slice).collect();
    let attestation_refs: Vec<&[u8]> = attestations.iter().map(Vec::as_slice).collect();
    let verified = VerifiedQualifications::verify(
        root,
        &QualificationInputs {
            signer_certificate: &certificate,
            revocation_list: &revocations,
            release_index: &index,
            records: &record_refs,
            attestations: &attestation_refs,
        },
    );
    Ok(verified.stable_launch_ready(candidate, &evidence, now, true, &VerifierState::default()))
}

pub(crate) fn projection(repository: &Path, commit: &str) -> Result<Value, String> {
    let mut report = json!({"schema": "auths.launch-readiness/1", "source_commit": commit,
        "gateway_semantic_closure_sha256": auths_gateway::GATEWAY_SEMANTIC_CLOSURE_SHA256,
        "stable_launch_ready": false, "reason": "pinned-root-unavailable",
        "human_release_review": "separate-required-gate"});
    let Some(root_bytes) = auths_gateway::PINNED_QUALIFICATION_ROOT else {
        return Ok(report);
    };
    let Ok(root) = QualificationTrustRoot::from_canonical_json(root_bytes) else {
        report["reason"] = json!("pinned-root-invalid");
        return Ok(report);
    };
    let clock = auths_gateway::SynchronizedHostClock;
    let Some(now) = clock
        .now()
        .filter(|_| clock.trust() == ClockTrustState::Trusted)
    else {
        report["reason"] = json!("release-clock-untrusted");
        return Ok(report);
    };
    let candidate = candidate(repository, commit)?;
    report["target"] =
        serde_json::to_value(&candidate.target).map_err(|_| "candidate target unencodable")?;
    match evaluate(repository, &candidate, &root, now) {
        Ok(ready) => {
            report["stable_launch_ready"] = json!(ready);
            report["reason"] = json!(if ready {
                "technical-gates-passed"
            } else {
                "qualification-gates-not-satisfied"
            });
        }
        Err(_) => {
            report["reason"] = json!("qualification-inputs-unavailable-or-invalid");
        }
    }
    Ok(report)
}
