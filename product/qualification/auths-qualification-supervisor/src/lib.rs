//! Provider-free protected qualification mechanisms.

use auths_profile_kit::QualificationReleaseBuild;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read as _;
use std::path::{Component, Path};

const RELEASE_SURFACE_SCHEMA: &str = "auths.qualification-release-surface/1";
const RELEASE_MEMBERS_SCHEMA: &str = "auths.qualification-release-members/1";
const MAX_JSON_BYTES: u64 = 262_144;
const MAX_ARTIFACT_BYTES: u64 = 536_870_912;
const ARTIFACT_ROLES: [&str; 6] = [
    "production-agent",
    "python-native",
    "python-wheel",
    "qualification-agent",
    "typescript-native",
    "typescript-package",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseSurface {
    schema: String,
    candidate_revision: String,
    policy_sha256: String,
    production_feature_set: Vec<String>,
    qualification_feature_set: Vec<String>,
    production_members: Vec<ReleaseSurfaceMember>,
    qualification_members: Vec<ReleaseSurfaceMember>,
    reviewed_difference: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseSurfaceMember {
    path: String,
    sha256: String,
    bytes: u64,
    mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseSurfacePolicy {
    schema: String,
    production_feature_set: Vec<String>,
    qualification_feature_set: Vec<String>,
    production_member_paths: Vec<String>,
    qualification_member_paths: Vec<String>,
    reviewed_difference: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseMembers {
    schema: String,
    candidate_revision: String,
    qualification_surface_sha256: String,
    artifacts: Vec<ReleaseMember>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseMember {
    role: String,
    member_path: String,
    member_sha256: String,
    bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostedReleaseMetadata {
    schema: String,
    checked_at_unix_seconds: u64,
    repository_id: String,
    workflow_path: String,
    workflow_revision: String,
    run_id: String,
    run_attempt: u32,
    retention_days: u16,
    projection: HostedArtifact,
    artifacts: Vec<HostedArtifact>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostedArtifact {
    role: String,
    name: String,
    artifact_id: String,
    uploaded_archive_sha256: String,
    size_in_bytes: u64,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    expired: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttesterToolsHostedVerification {
    schema: String,
    verified_at_unix_seconds: u64,
    repository_id: String,
    workflow_path: String,
    workflow_revision: String,
    run_id: String,
    run_attempt: u32,
    retention_days: u16,
    artifact_id: String,
    artifact_name: String,
    uploaded_archive_sha256: String,
    uploaded_archive_bytes: u64,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttesterToolsManifest {
    schema: String,
    attester_revision: String,
    gh_version: String,
    members: Vec<AttesterToolMember>,
    retention_days: u16,
    runner_image_os: String,
    runner_image_version: String,
    runner_label: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AttesterToolMember {
    path: String,
    sha256: String,
    mode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedAttesterToolsBinding {
    #[serde(flatten)]
    hosted: AttesterToolsHostedVerification,
    attester_revision: String,
    gh_version: String,
    runner_image_os: String,
    runner_image_version: String,
    runner_label: String,
    members: Vec<AttesterToolMember>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedReleaseBuildBinding {
    schema: &'static str,
    verified_at_unix_seconds: u64,
    repository_id: String,
    workflow_path: String,
    workflow_revision: String,
    run_id: String,
    run_attempt: u32,
    run_label: &'static str,
    retention_days: u16,
    projection_artifact_id: String,
    projection_artifact_name: String,
    projection_uploaded_archive_sha256: String,
    projection_uploaded_archive_bytes: u64,
    projection_created_at_unix_seconds: u64,
    projection_expires_at_unix_seconds: u64,
    release_build_sha256: String,
    qualification_surface_sha256: String,
    qualification_surface: ReleaseSurface,
    hosted_metadata_sha256: String,
    provenance_verification_sha256: String,
    provenance_bundle_sha256: String,
    trusted_root_sha256: String,
    provenance_verifier_sha256: String,
    provenance_verifier_version: String,
    release_build_verifier_sha256: String,
    attester_tools: VerifiedAttesterToolsBinding,
    artifacts: Vec<VerifiedReleaseArtifact>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedReleaseArtifact {
    role: String,
    name: String,
    artifact_id: String,
    uploaded_archive_sha256: String,
    uploaded_archive_bytes: u64,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    member_path: String,
    member_sha256: String,
    bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProvenanceVerification {
    schema: String,
    verification_tool: String,
    repository_id: String,
    source_repository_uri: String,
    source_repository_digest: String,
    source_repository_ref: String,
    signer_workflow_uri: String,
    signer_workflow_digest: String,
    oidc_issuer: String,
    runner_environment: String,
    runner_invocation_uri: String,
    predicate_type: String,
    subject_name: String,
    subject_sha256: String,
    verified_timestamps_sha256: String,
    raw_verification_sha256: String,
    provenance_bundle_sha256: String,
    trusted_root_sha256: String,
    verifier_sha256: String,
    verifier_version: String,
    release_build_verifier_sha256: String,
}

/// Verifies the exact six qualification release members and the closed
/// production-versus-qualification executable surface.
pub fn verify_release_surface(
    surface_path: &Path,
    members_path: &Path,
    artifact_root: &Path,
    candidate_repository: &Path,
    expected_commit: &str,
) -> Result<(), String> {
    validate_full_commit(expected_commit)?;
    let surface_bytes = read_canonical_file(surface_path, MAX_JSON_BYTES, "release surface")?;
    let surface: ReleaseSurface = serde_json::from_slice(&surface_bytes)
        .map_err(|error| format!("release surface is invalid: {error}"))?;
    let members_bytes = read_canonical_file(members_path, MAX_JSON_BYTES, "release members")?;
    let members: ReleaseMembers = serde_json::from_slice(&members_bytes)
        .map_err(|error| format!("release members are invalid: {error}"))?;
    let policy_bytes = include_bytes!("../../v1/release-surface-policy.json");
    let policy: ReleaseSurfacePolicy = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("trusted release-surface policy is invalid: {error}"))?;
    if surface.schema != RELEASE_SURFACE_SCHEMA
        || policy.schema != "auths.qualification-release-surface-policy/1"
        || members.schema != RELEASE_MEMBERS_SCHEMA
        || surface.candidate_revision != expected_commit
        || surface.policy_sha256 != digest_bytes(policy_bytes)
        || members.candidate_revision != expected_commit
        || members.qualification_surface_sha256 != digest_bytes(&surface_bytes)
        || surface.production_feature_set != policy.production_feature_set
        || surface.qualification_feature_set != policy.qualification_feature_set
        || surface.reviewed_difference != policy.reviewed_difference
    {
        return Err("qualification release surface identity or feature contract drifted".into());
    }
    verify_candidate_build_surface(candidate_repository)?;
    validate_surface_roster(&surface.production_members, &policy.production_member_paths)?;
    validate_surface_roster(
        &surface.qualification_members,
        &policy.qualification_member_paths,
    )?;
    if members.artifacts.len() != ARTIFACT_ROLES.len() {
        return Err("qualification release member roster is not exact".into());
    }
    for (member, expected_role) in members.artifacts.iter().zip(ARTIFACT_ROLES) {
        if member.role != expected_role
            || member.member_path.is_empty()
            || member.member_path.contains(['/', '\\'])
            || !(1..=MAX_ARTIFACT_BYTES).contains(&member.bytes)
        {
            return Err(format!(
                "invalid qualification release member row: {expected_role}"
            ));
        }
        validate_sha256(&member.member_sha256)?;
        let path = artifact_root.join(expected_role).join(&member.member_path);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("missing downloaded {expected_role} member: {error}"))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != member.bytes
            || digest_file(&path)? != member.member_sha256
        {
            return Err(format!(
                "downloaded {expected_role} member differs from its projection"
            ));
        }
    }
    let production_archive = artifact_root
        .join("production-agent")
        .join(&members.artifacts[0].member_path);
    let qualification_archive = artifact_root
        .join("qualification-agent")
        .join(&members.artifacts[3].member_path);
    let production = read_exact_archive(
        &production_archive,
        "auths-production-agent",
        &surface.production_members,
        MAX_ARTIFACT_BYTES,
    )?;
    let qualification = read_exact_archive(
        &qualification_archive,
        "auths-qualification-agent",
        &surface.qualification_members,
        MAX_ARTIFACT_BYTES,
    )?;
    let agent = production
        .get("target/release/auths")
        .ok_or("production bundle has no Auths agent")?;
    for forbidden in [
        b"/v1/authority/".as_slice(),
        b"/v1/workflows/".as_slice(),
        b"synthetic testkit agent; never production".as_slice(),
        b"qualification-source-".as_slice(),
        b"qualification-failpoint".as_slice(),
        b"qualification-after-decision-fd".as_slice(),
        b"auths.qualification-durable-decision-ack/1".as_slice(),
        b"qualification agent requires its exact crash checkpoint".as_slice(),
        b"crash-after-decision".as_slice(),
    ] {
        if agent
            .windows(forbidden.len())
            .any(|window| window == forbidden)
        {
            return Err(
                "production agent contains a forbidden remote/testkit/qualification surface".into(),
            );
        }
    }
    let qualification_agent = qualification
        .get("target/release/auths-qualification-agent")
        .ok_or("qualification bundle has no isolated qualification agent")?;
    for required in [
        b"qualification-failpoint".as_slice(),
        b"qualification-after-decision-fd".as_slice(),
        b"auths.qualification-durable-decision-ack/1".as_slice(),
        b"qualification failpoint selection is incomplete or unsupported".as_slice(),
    ] {
        if !qualification_agent
            .windows(required.len())
            .any(|window| window == required)
        {
            return Err("qualification agent omits its required crash-only surface".into());
        }
    }
    Ok(())
}

/// Reconstructs the security-relevant qualification feature and route closure
/// from the immutable candidate tree using protected verifier code.
///
/// Candidate-authored release projections remain useful mismatch oracles, but
/// they cannot establish which Cargo features or unqualified profile routes
/// the candidate actually declared.
fn verify_candidate_build_surface(repository: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(repository)
        .map_err(|error| format!("could not inspect candidate repository: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("candidate repository is not one real directory".into());
    }

    let node_manifest =
        read_candidate_file(repository, "product/runtime/auths-node/Cargo.toml", 131_072)?;
    let node: toml::Value = toml::from_str(
        std::str::from_utf8(&node_manifest)
            .map_err(|_| "candidate auths-node manifest is not UTF-8")?,
    )
    .map_err(|error| format!("candidate auths-node manifest is invalid: {error}"))?;
    let node_features = node
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or("candidate auths-node manifest has no feature table")?;
    if node_features.len() != 2
        || !toml_string_array_eq(
            node_features.get("qualification-failpoints"),
            &[
                "auths-connections/qualification-broker",
                "auths-opentofu/qualification",
                "auths-postgresql/qualification",
                "auths-stores/qualification-evidence",
                "auths-stripe/qualification",
            ],
        )
        || !toml_string_array_eq(
            node_features.get("testkit-agent"),
            &["auths-stripe/testkit-agent"],
        )
    {
        return Err("candidate auths-node feature closure is not exact".into());
    }
    let node_bins = node
        .get("bin")
        .and_then(toml::Value::as_array)
        .ok_or("candidate auths-node manifest has no binary roster")?;
    if node
        .get("package")
        .and_then(|package| package.get("autobins"))
        .and_then(toml::Value::as_bool)
        != Some(false)
    {
        return Err("candidate auths-node enables implicit binary targets".into());
    }
    require_exact_bin(node_bins, "auths", "src/bin/auths-production.rs", &[])?;
    require_exact_bin(
        node_bins,
        "auths-qualification-agent",
        "src/bin/auths-qualification-agent.rs",
        &["qualification-failpoints"],
    )?;
    require_exact_bin(
        node_bins,
        "auths-testkit-agent",
        "src/bin/auths-testkit-agent.rs",
        &["testkit-agent"],
    )?;
    if node_bins.len() != 3 {
        return Err("candidate auths-node qualification binary roster is not exact".into());
    }
    let node_store = node
        .get("dependencies")
        .and_then(|value| value.get("auths-stores"))
        .ok_or("candidate auths-node omits auths-stores")?;
    if !exact_workspace_dependency(node_store) {
        return Err("production auths-node activates qualification store APIs".into());
    }

    let node_connections = node
        .get("dependencies")
        .and_then(|value| value.get("auths-connections"))
        .ok_or("candidate auths-node omits auths-connections")?;
    if !exact_workspace_dependency(node_connections) {
        return Err("production auths-node activates qualification broker APIs".into());
    }

    let workspace = parse_candidate_manifest(repository, "Cargo.toml", "workspace")?;
    let workspace_dependencies = workspace
        .get("workspace")
        .and_then(|value| value.get("dependencies"))
        .and_then(toml::Value::as_table)
        .ok_or("candidate workspace has no dependency table")?;
    for (name, path) in [
        ("auths-connections", "product/runtime/auths-connections"),
        ("auths-stores", "product/stores/auths-stores"),
    ] {
        if !exact_workspace_path_dependency(workspace_dependencies.get(name), path) {
            return Err(format!(
                "candidate workspace qualification dependency drifted: {name}"
            ));
        }
    }
    verify_reserved_qualification_feature_roster(repository, &workspace, workspace_dependencies)?;

    let connections = parse_candidate_manifest(
        repository,
        "product/runtime/auths-connections/Cargo.toml",
        "auths-connections",
    )?;
    let connection_features = connections
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or("candidate auths-connections manifest has no feature table")?;
    if connection_features.len() != 1
        || !toml_string_array_eq(connection_features.get("qualification-broker"), &[])
    {
        return Err("candidate qualification broker feature is not one closed gate".into());
    }

    let stores = parse_candidate_manifest(
        repository,
        "product/stores/auths-stores/Cargo.toml",
        "auths-stores",
    )?;
    let store_features = stores
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or("candidate auths-stores manifest has no feature table")?;
    if store_features.len() != 1
        || !toml_string_array_eq(store_features.get("qualification-evidence"), &[])
    {
        return Err("candidate qualification store feature is not one closed gate".into());
    }
    let projection_bytes = read_candidate_file(
        repository,
        "product/runtime/auths-node/src/generated/profile_launch_projection.json",
        65_536,
    )?;
    let projection: Value = serde_json::from_slice(&projection_bytes)
        .map_err(|error| format!("candidate profile launch projection is invalid: {error}"))?;
    let canonical = serde_json_canonicalizer::to_vec(&projection)
        .map_err(|error| format!("could not canonicalize candidate launch projection: {error}"))?;
    if projection_bytes != [canonical.as_slice(), b"\n"].concat()
        || projection.get("schema").and_then(Value::as_str)
            != Some("auths.profile-launch-projection/1")
    {
        return Err("candidate profile launch projection is not exact canonical v1".into());
    }
    let profiles = projection
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or("candidate launch projection has no profile roster")?;
    let expected_profiles = [
        ("auths.opentofu.plan-preflight/1", false),
        ("auths.opentofu.saved-plan-apply/1", false),
        ("auths.postgresql.bounded-update/1", false),
        ("auths.postgresql.update-preflight/1", false),
        ("auths.stripe.refund/1", true),
    ];
    if profiles.len() != expected_profiles.len() {
        return Err("candidate qualification profile roster is not exact".into());
    }
    for (profile, (expected, testkit)) in profiles.iter().zip(expected_profiles) {
        let object = profile
            .as_object()
            .ok_or("candidate launch profile is not an object")?;
        if object.len() != 6
            || object.get("profile").and_then(Value::as_str) != Some(expected)
            || object.get("state").and_then(Value::as_str) != Some("unqualified")
            || object.get("testkitAvailable").and_then(Value::as_bool) != Some(testkit)
            || !object
                .get("targets")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            || !object
                .get("qualificationIds")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            || !object
                .get("semanticClosureSha256")
                .is_some_and(Value::is_null)
        {
            return Err("candidate launch profile carries drifted or imported authority".into());
        }
    }

    let launch_source = read_candidate_file(
        repository,
        "product/runtime/auths-node/src/profile_launch.rs",
        131_072,
    )?;
    let production_bin_source = read_candidate_file(
        repository,
        "product/runtime/auths-node/src/bin/auths-production.rs",
        2_097_152,
    )?;
    let route_source = read_candidate_file(
        repository,
        "product/runtime/auths-node/src/generated/profile_routes.rs",
        2_097_152,
    )?;
    let store_source = read_candidate_file(
        repository,
        "product/stores/auths-stores/src/operation.rs",
        4_194_304,
    )?;
    let store_root_source = read_candidate_file(
        repository,
        "product/stores/auths-stores/src/lib.rs",
        262_144,
    )?;
    let stripe_root_source = read_candidate_file(
        repository,
        "product/integrations/auths-stripe/src/lib.rs",
        262_144,
    )?;
    let connection_source = read_candidate_file(
        repository,
        "product/runtime/auths-connections/src/lib.rs",
        262_144,
    )?;
    for (bytes, required) in [
        (
            launch_source.as_slice(),
            &[
                "#[cfg(feature = \"qualification-failpoints\")]\n    Qualification",
                "LaunchFlavor::Qualification => true",
                "if flavor != LaunchFlavor::Production",
            ][..],
        ),
        (
            route_source.as_slice(),
            &[
                "pub fn built_in_qualification_local_profiles()",
                "built_in_local_profiles_for(LaunchFlavor::Qualification)",
            ][..],
        ),
        (
            production_bin_source.as_slice(),
            &[
                "!auths_connections::__QUALIFICATION_BROKER_ENABLED",
                "!auths_stores::__QUALIFICATION_EVIDENCE_ENABLED",
                "!auths_stripe::__TESTKIT_AGENT_ENABLED",
                "production auths cannot enable qualification-broker",
                "production auths cannot enable qualification-evidence",
                "production auths cannot enable testkit-agent",
            ][..],
        ),
        (
            connection_source.as_slice(),
            &[
                "pub const __QUALIFICATION_BROKER_ENABLED: bool = cfg!(feature = \"qualification-broker\");",
                "#[cfg(feature = \"qualification-broker\")]\nmod qualification;",
                "#[cfg(feature = \"qualification-broker\")]\npub use qualification::{",
                "QualificationCredentialLeaseRequest, QualificationProviderCallKind,",
            ][..],
        ),
        (
            store_root_source.as_slice(),
            &[
                "pub const __QUALIFICATION_EVIDENCE_ENABLED: bool = cfg!(feature = \"qualification-evidence\");",
            ][..],
        ),
        (
            stripe_root_source.as_slice(),
            &["pub const __TESTKIT_AGENT_ENABLED: bool = cfg!(feature = \"testkit-agent\");"][..],
        ),
        (
            store_source.as_slice(),
            &[
                "feature = \"qualification-evidence\"",
                "open_persisted_operation_snapshot_at_for_qualification",
            ][..],
        ),
    ] {
        let text =
            std::str::from_utf8(bytes).map_err(|_| "candidate surface source is not UTF-8")?;
        if required.iter().any(|marker| !text.contains(marker)) {
            return Err("candidate source omits a protected qualification surface gate".into());
        }
    }
    Ok(())
}

fn parse_candidate_manifest(
    repository: &Path,
    relative: &str,
    label: &str,
) -> Result<toml::Value, String> {
    let bytes = read_candidate_file(repository, relative, 131_072)?;
    toml::from_str(
        std::str::from_utf8(&bytes)
            .map_err(|_| format!("candidate {label} manifest is not UTF-8"))?,
    )
    .map_err(|error| format!("candidate {label} manifest is invalid: {error}"))
}

fn exact_workspace_dependency(value: &toml::Value) -> bool {
    value.as_table().is_some_and(|table| {
        table.len() == 1 && table.get("workspace").and_then(toml::Value::as_bool) == Some(true)
    })
}

fn exact_workspace_path_dependency(value: Option<&toml::Value>, path: &str) -> bool {
    value.and_then(toml::Value::as_table).is_some_and(|table| {
        table.len() == 2
            && table.get("version").and_then(toml::Value::as_str) == Some(env!("CARGO_PKG_VERSION"))
            && table.get("path").and_then(toml::Value::as_str) == Some(path)
    })
}

// The two qualification gates are reserved repository-wide. Cargo can unify a
// dependency feature through any direct, transitive, aliased, or target-
// specific edge, so verify their complete local-manifest occurrence roster
// instead of maintaining a partial package graph here.
fn verify_reserved_qualification_feature_roster(
    repository: &Path,
    workspace: &toml::Value,
    workspace_dependencies: &toml::map::Map<String, toml::Value>,
) -> Result<(), String> {
    const MAX_MANIFESTS: usize = 256;
    let mut pending = BTreeSet::new();
    pending.insert("Cargo.toml".to_owned());
    for member in workspace
        .get("workspace")
        .and_then(|value| value.get("members"))
        .and_then(toml::Value::as_array)
        .ok_or("candidate workspace has no member roster")?
    {
        let member = member
            .as_str()
            .ok_or("candidate workspace member is not a string")?;
        pending.insert(candidate_dependency_manifest("Cargo.toml", member)?);
    }
    for dependency in workspace_dependencies.values() {
        if let Some(path) = dependency.get("path").and_then(toml::Value::as_str) {
            pending.insert(candidate_dependency_manifest("Cargo.toml", path)?);
        }
    }

    let mut visited = BTreeSet::new();
    let mut occurrences = BTreeMap::<(String, String, String), usize>::new();
    while let Some(relative) = pending.pop_first() {
        if !visited.insert(relative.clone()) {
            continue;
        }
        if visited.len() > MAX_MANIFESTS {
            return Err("candidate local Cargo manifest closure exceeds its bound".into());
        }
        let manifest = parse_candidate_manifest(repository, &relative, &relative)?;
        collect_reserved_qualification_features(&manifest, &relative, &mut occurrences);
        for (name, dependency) in candidate_dependency_rows(&manifest) {
            let inherited =
                dependency.get("workspace").and_then(toml::Value::as_bool) == Some(true);
            let effective = if inherited {
                workspace_dependencies.get(name)
            } else {
                Some(dependency)
            };
            if let Some(path) = effective
                .and_then(|value| value.get("path"))
                .and_then(toml::Value::as_str)
            {
                pending.insert(candidate_dependency_manifest(
                    if inherited { "Cargo.toml" } else { &relative },
                    path,
                )?);
            }
        }
    }

    let expected = BTreeMap::from([
        (
            (
                "product/runtime/auths-node/Cargo.toml".to_owned(),
                "qualification-broker".to_owned(),
                "value".to_owned(),
            ),
            1,
        ),
        (
            (
                "product/runtime/auths-node/Cargo.toml".to_owned(),
                "qualification-evidence".to_owned(),
                "value".to_owned(),
            ),
            1,
        ),
        (
            (
                "product/runtime/auths-connections/Cargo.toml".to_owned(),
                "qualification-broker".to_owned(),
                "key".to_owned(),
            ),
            1,
        ),
        (
            (
                "product/stores/auths-stores/Cargo.toml".to_owned(),
                "qualification-evidence".to_owned(),
                "key".to_owned(),
            ),
            1,
        ),
        (
            (
                "product/qualification/auths-qualification-evidence-source/Cargo.toml".to_owned(),
                "qualification-broker".to_owned(),
                "value".to_owned(),
            ),
            1,
        ),
        (
            (
                "product/qualification/auths-qualification-evidence-source/Cargo.toml".to_owned(),
                "qualification-evidence".to_owned(),
                "value".to_owned(),
            ),
            1,
        ),
        (
            (
                "product/integrations/auths-opentofu/Cargo.toml".to_owned(),
                "qualification-broker".to_owned(),
                "value".to_owned(),
            ),
            1,
        ),
        (
            (
                "product/integrations/auths-postgresql/Cargo.toml".to_owned(),
                "qualification-broker".to_owned(),
                "value".to_owned(),
            ),
            1,
        ),
        (
            (
                "product/integrations/auths-stripe/Cargo.toml".to_owned(),
                "qualification-broker".to_owned(),
                "value".to_owned(),
            ),
            1,
        ),
        (
            (
                "product/qualification/auths-qualification-supervisor/Cargo.toml".to_owned(),
                "qualification-evidence".to_owned(),
                "value".to_owned(),
            ),
            1,
        ),
        (
            (
                "product/runtime/auths-node/Cargo.toml".to_owned(),
                "testkit-agent".to_owned(),
                "key".to_owned(),
            ),
            1,
        ),
        (
            (
                "product/runtime/auths-node/Cargo.toml".to_owned(),
                "testkit-agent".to_owned(),
                "value".to_owned(),
            ),
            2,
        ),
        (
            (
                "product/integrations/auths-stripe/Cargo.toml".to_owned(),
                "testkit-agent".to_owned(),
                "key".to_owned(),
            ),
            1,
        ),
    ]);
    if occurrences != expected {
        return Err("candidate reserved qualification feature roster drifted".into());
    }
    Ok(())
}

fn candidate_dependency_rows(manifest: &toml::Value) -> Vec<(&str, &toml::Value)> {
    let mut rows = Vec::new();
    for kind in ["dependencies", "build-dependencies", "dev-dependencies"] {
        if let Some(dependencies) = manifest.get(kind).and_then(toml::Value::as_table) {
            rows.extend(
                dependencies
                    .iter()
                    .map(|(name, value)| (name.as_str(), value)),
            );
        }
    }
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            for kind in ["dependencies", "build-dependencies", "dev-dependencies"] {
                if let Some(dependencies) = target.get(kind).and_then(toml::Value::as_table) {
                    rows.extend(
                        dependencies
                            .iter()
                            .map(|(name, value)| (name.as_str(), value)),
                    );
                }
            }
        }
    }
    rows
}

fn candidate_dependency_manifest(owner_manifest: &str, dependency: &str) -> Result<String, String> {
    let owner = Path::new(owner_manifest)
        .parent()
        .ok_or("candidate manifest has no parent")?;
    let mut normalized = Vec::new();
    for component in owner.join(dependency).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => normalized.push(
                value
                    .to_str()
                    .ok_or("candidate dependency path is not UTF-8")?
                    .to_owned(),
            ),
            Component::ParentDir if normalized.pop().is_some() => {}
            _ => return Err("candidate dependency path escapes its repository".into()),
        }
    }
    normalized.push("Cargo.toml".to_owned());
    Ok(normalized.join("/"))
}

fn collect_reserved_qualification_features(
    value: &toml::Value,
    manifest: &str,
    occurrences: &mut BTreeMap<(String, String, String), usize>,
) {
    const RESERVED: [&str; 3] = [
        "qualification-broker",
        "qualification-evidence",
        "testkit-agent",
    ];
    match value {
        toml::Value::Table(table) => {
            for (key, value) in table {
                for reserved in RESERVED {
                    if key == reserved {
                        *occurrences
                            .entry((manifest.to_owned(), reserved.to_owned(), "key".to_owned()))
                            .or_default() += 1;
                    }
                }
                collect_reserved_qualification_features(value, manifest, occurrences);
            }
        }
        toml::Value::Array(values) => {
            for value in values {
                collect_reserved_qualification_features(value, manifest, occurrences);
            }
        }
        toml::Value::String(value) => {
            for reserved in RESERVED {
                if value == reserved || value.ends_with(&format!("/{reserved}")) {
                    *occurrences
                        .entry((manifest.to_owned(), reserved.to_owned(), "value".to_owned()))
                        .or_default() += 1;
                }
            }
        }
        _ => {}
    }
}

fn toml_string_array_eq(value: Option<&toml::Value>, expected: &[&str]) -> bool {
    value.and_then(toml::Value::as_array).is_some_and(|actual| {
        actual.len() == expected.len()
            && actual
                .iter()
                .zip(expected)
                .all(|(actual, expected)| actual.as_str() == Some(*expected))
    })
}

fn require_exact_bin(
    bins: &[toml::Value],
    name: &str,
    path: &str,
    features: &[&str],
) -> Result<(), String> {
    let matches = bins
        .iter()
        .filter(|bin| bin.get("name").and_then(toml::Value::as_str) == Some(name))
        .collect::<Vec<_>>();
    let required_features_match = matches.first().is_some_and(|binary| {
        if features.is_empty() {
            binary.get("required-features").is_none()
        } else {
            toml_string_array_eq(binary.get("required-features"), features)
        }
    });
    if matches.len() != 1
        || matches[0].get("path").and_then(toml::Value::as_str) != Some(path)
        || !required_features_match
    {
        return Err(format!("candidate binary contract drifted: {name}"));
    }
    Ok(())
}

fn read_candidate_file(repository: &Path, relative: &str, maximum: u64) -> Result<Vec<u8>, String> {
    validate_safe_path(relative)?;
    let mut current = repository.to_owned();
    let components = Path::new(relative).components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            return Err(format!("candidate path is not normalized: {relative}"));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("could not inspect candidate {relative}: {error}"))?;
        let last = index + 1 == components.len();
        if metadata.file_type().is_symlink()
            || last && (!metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum)
            || !last && !metadata.is_dir()
        {
            return Err(format!(
                "candidate path is not a bounded no-symlink file: {relative}"
            ));
        }
    }
    fs::read(&current).map_err(|error| format!("could not read candidate {relative}: {error}"))
}

/// Verifies the release-build projection against the exact downloaded member
/// set after [`verify_release_surface`] succeeds.
pub fn verify_release_build(
    release_build_path: &Path,
    surface_path: &Path,
    members_path: &Path,
    artifact_root: &Path,
    candidate_repository: &Path,
    expected_commit: &str,
) -> Result<(), String> {
    verify_release_surface(
        surface_path,
        members_path,
        artifact_root,
        candidate_repository,
        expected_commit,
    )?;
    let release_build_bytes =
        read_canonical_file(release_build_path, MAX_JSON_BYTES, "release build")?;
    QualificationReleaseBuild::from_json(&release_build_bytes)
        .map_err(|error| format!("release build is invalid: {error}"))?;
    let release_build: Value = serde_json::from_slice(&release_build_bytes)
        .map_err(|error| format!("release build is invalid JSON: {error}"))?;
    let members_bytes = read_canonical_file(members_path, MAX_JSON_BYTES, "release members")?;
    let members: ReleaseMembers = serde_json::from_slice(&members_bytes)
        .map_err(|error| format!("release members are invalid: {error}"))?;
    if release_build["workflowRevision"] != expected_commit
        || release_build["qualificationSurfaceSha256"] != digest_file(surface_path)?
    {
        return Err("qualification release build candidate/surface binding drifted".into());
    }
    let artifacts = release_build["artifacts"]
        .as_array()
        .ok_or("qualification release build has no artifact roster")?;
    if artifacts.len() != members.artifacts.len() {
        return Err("qualification release build/member roster size drifted".into());
    }
    for (artifact, member) in artifacts.iter().zip(&members.artifacts) {
        if artifact["role"] != member.role
            || artifact["memberPath"] != member.member_path
            || artifact["memberSha256"] != member.member_sha256
            || artifact["bytes"] != member.bytes
        {
            return Err(format!(
                "qualification release build/member binding drifted for {}",
                member.role
            ));
        }
    }
    Ok(())
}

/// Verifies authenticated hosted-artifact metadata and emits the exact
/// canonical handoff that a later qualification attester must consume.
#[allow(clippy::too_many_arguments)]
pub fn verify_hosted_release_build(
    release_build_path: &Path,
    surface_path: &Path,
    members_path: &Path,
    artifact_root: &Path,
    candidate_repository: &Path,
    hosted_metadata_path: &Path,
    provenance_verification_path: &Path,
    attester_tools_verification_path: &Path,
    attester_tools_manifest_path: &Path,
    expected_commit: &str,
    now_unix_seconds: u64,
) -> Result<Vec<u8>, String> {
    verify_release_build(
        release_build_path,
        surface_path,
        members_path,
        artifact_root,
        candidate_repository,
        expected_commit,
    )?;
    let release_build_bytes =
        read_canonical_file(release_build_path, MAX_JSON_BYTES, "release build")?;
    let release_build: Value = serde_json::from_slice(&release_build_bytes)
        .map_err(|error| format!("release build is invalid JSON: {error}"))?;
    let surface_bytes = read_canonical_file(surface_path, MAX_JSON_BYTES, "release surface")?;
    let qualification_surface: ReleaseSurface = serde_json::from_slice(&surface_bytes)
        .map_err(|error| format!("release surface is invalid: {error}"))?;
    let metadata_bytes = read_canonical_file(
        hosted_metadata_path,
        MAX_JSON_BYTES,
        "hosted release metadata",
    )?;
    let metadata: HostedReleaseMetadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|error| format!("hosted release metadata is invalid: {error}"))?;
    if metadata.schema != "auths.qualification-release-hosted-metadata/1"
        || metadata.checked_at_unix_seconds != now_unix_seconds
        || metadata.repository_id != release_build["repositoryId"]
        || metadata.workflow_path != release_build["workflowPath"]
        || metadata.workflow_revision != expected_commit
        || metadata.workflow_revision != release_build["workflowRevision"]
        || release_build["runLabel"] != "official"
        || metadata.run_id != release_build["runId"]
        || Value::from(metadata.run_attempt) != release_build["runAttempt"]
        || metadata.artifacts.len() != ARTIFACT_ROLES.len()
        || metadata.projection.role != "release-build"
        || !(90..=365).contains(&metadata.retention_days)
    {
        return Err("hosted release metadata does not bind the release run".into());
    }
    validate_hosted_artifact(
        &metadata.projection,
        now_unix_seconds,
        &format!("auths-qualification-{expected_commit}-official-release-build"),
        16_777_216,
        metadata.retention_days,
    )?;
    let release_artifacts = release_build["artifacts"]
        .as_array()
        .ok_or("release build has no artifact roster")?;
    for ((hosted, projected), expected_role) in metadata
        .artifacts
        .iter()
        .zip(release_artifacts)
        .zip(ARTIFACT_ROLES)
    {
        validate_hosted_artifact(
            hosted,
            now_unix_seconds,
            &format!("auths-qualification-{expected_commit}-official-{expected_role}"),
            MAX_ARTIFACT_BYTES,
            metadata.retention_days,
        )?;
        if hosted.role != expected_role
            || hosted.artifact_id != projected["artifactId"]
            || hosted.uploaded_archive_sha256 != projected["uploadedArchiveSha256"]
        {
            return Err(format!(
                "hosted artifact metadata drifted for {expected_role}"
            ));
        }
    }
    let provenance = read_canonical_file(
        provenance_verification_path,
        MAX_JSON_BYTES,
        "release-build provenance verification",
    )?;
    let provenance_value: ProvenanceVerification = serde_json::from_slice(&provenance)
        .map_err(|error| format!("release-build provenance verification is not JSON: {error}"))?;
    let release_build_sha256 = digest_bytes(&release_build_bytes);
    let expected_invocation = format!(
        "https://github.com/auths-dev/auths-proof/actions/runs/{}/attempts/{}",
        metadata.run_id, metadata.run_attempt
    );
    if provenance_value.schema != "auths.qualification-release-provenance-verification/1"
        || provenance_value.verification_tool != "gh-attestation-verify"
        || provenance_value.repository_id != metadata.repository_id
        || provenance_value.source_repository_uri != "https://github.com/auths-dev/auths-proof"
        || provenance_value.source_repository_digest != expected_commit
        || provenance_value.source_repository_ref != "refs/heads/main"
        || provenance_value.signer_workflow_uri
            != "https://github.com/auths-dev/auths-proof/.github/workflows/release-builder.yml@refs/heads/main"
        || provenance_value.signer_workflow_digest != expected_commit
        || provenance_value.oidc_issuer != "https://token.actions.githubusercontent.com"
        || provenance_value.runner_environment != "github-hosted"
        || provenance_value.runner_invocation_uri != expected_invocation
        || provenance_value.predicate_type != "https://slsa.dev/provenance/v1"
        || provenance_value.subject_name != "release-build.json"
        || provenance_value.subject_sha256 != release_build_sha256
        || validate_sha256(&provenance_value.verified_timestamps_sha256).is_err()
        || validate_sha256(&provenance_value.raw_verification_sha256).is_err()
        || validate_sha256(&provenance_value.provenance_bundle_sha256).is_err()
        || validate_sha256(&provenance_value.trusted_root_sha256).is_err()
        || validate_sha256(&provenance_value.verifier_sha256).is_err()
        || provenance_value.verifier_version.is_empty()
        || provenance_value.verifier_version.len() > 64
        || validate_sha256(&provenance_value.release_build_verifier_sha256).is_err()
    {
        return Err("release-build provenance verification does not bind the trusted build".into());
    }
    let attester_tools = verify_attester_tools_binding(
        attester_tools_verification_path,
        attester_tools_manifest_path,
        &metadata.repository_id,
        now_unix_seconds,
        &provenance_value,
    )?;
    let artifacts = metadata
        .artifacts
        .iter()
        .zip(release_artifacts)
        .map(|(hosted, projected)| VerifiedReleaseArtifact {
            role: hosted.role.clone(),
            name: hosted.name.clone(),
            artifact_id: hosted.artifact_id.clone(),
            uploaded_archive_sha256: hosted.uploaded_archive_sha256.clone(),
            uploaded_archive_bytes: hosted.size_in_bytes,
            created_at_unix_seconds: hosted.created_at_unix_seconds,
            expires_at_unix_seconds: hosted.expires_at_unix_seconds,
            member_path: projected["memberPath"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            member_sha256: projected["memberSha256"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            bytes: projected["bytes"].as_u64().unwrap_or_default(),
        })
        .collect();
    let binding = VerifiedReleaseBuildBinding {
        schema: "auths.qualification-release-build-verification/1",
        verified_at_unix_seconds: now_unix_seconds,
        repository_id: metadata.repository_id,
        workflow_path: metadata.workflow_path,
        workflow_revision: metadata.workflow_revision,
        run_id: metadata.run_id,
        run_attempt: metadata.run_attempt,
        run_label: "official",
        retention_days: metadata.retention_days,
        projection_artifact_id: metadata.projection.artifact_id,
        projection_artifact_name: metadata.projection.name,
        projection_uploaded_archive_sha256: metadata.projection.uploaded_archive_sha256,
        projection_uploaded_archive_bytes: metadata.projection.size_in_bytes,
        projection_created_at_unix_seconds: metadata.projection.created_at_unix_seconds,
        projection_expires_at_unix_seconds: metadata.projection.expires_at_unix_seconds,
        release_build_sha256,
        qualification_surface_sha256: digest_bytes(&surface_bytes),
        qualification_surface,
        hosted_metadata_sha256: digest_bytes(&metadata_bytes),
        provenance_verification_sha256: digest_bytes(&provenance),
        provenance_bundle_sha256: provenance_value.provenance_bundle_sha256,
        trusted_root_sha256: provenance_value.trusted_root_sha256,
        provenance_verifier_sha256: provenance_value.verifier_sha256,
        provenance_verifier_version: provenance_value.verifier_version,
        release_build_verifier_sha256: provenance_value.release_build_verifier_sha256,
        attester_tools,
        artifacts,
    };
    serde_json_canonicalizer::to_vec(&binding)
        .map_err(|error| format!("could not canonicalize release-build verification: {error}"))
}

fn verify_attester_tools_binding(
    verification_path: &Path,
    manifest_path: &Path,
    repository_id: &str,
    now: u64,
    provenance: &ProvenanceVerification,
) -> Result<VerifiedAttesterToolsBinding, String> {
    let verification_bytes = read_canonical_file(
        verification_path,
        MAX_JSON_BYTES,
        "attester-tools hosted verification",
    )?;
    let hosted: AttesterToolsHostedVerification = serde_json::from_slice(&verification_bytes)
        .map_err(|error| format!("attester-tools hosted verification is invalid: {error}"))?;
    let manifest_bytes =
        read_canonical_file(manifest_path, MAX_JSON_BYTES, "attester-tools manifest")?;
    let manifest: AttesterToolsManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("attester-tools manifest is invalid: {error}"))?;
    let expected_paths = [
        ("auths-qualification-supervisor", "0755"),
        ("gh", "0755"),
        ("gitleaks", "0755"),
        ("qualification-agent-launcher", "0755"),
        ("qualification-attestation-signer", "0755"),
        ("qualification-crash-controller", "0755"),
        ("qualification-observation-signer", "0755"),
        ("qualification-release-build-verifier", "0755"),
        ("qualification-source-client-proxy", "0755"),
        ("qualification-source-credential-broker", "0755"),
        ("qualification-source-journal-reader", "0755"),
        ("qualification-source-profile-state-reader", "0755"),
        ("qualification-source-provider-observer", "0755"),
        ("qualification-source-provider-proxy", "0755"),
        ("qualification-source-receipt-verifier", "0755"),
        ("qualification-source-supervisor", "0755"),
        ("trusted-root.jsonl", "0600"),
        ("xtask", "0755"),
    ];
    if hosted.schema != "auths.qualification-attester-tools-verification/1"
        || hosted.verified_at_unix_seconds > now
        || now.saturating_sub(hosted.verified_at_unix_seconds) > 3_600
        || hosted.repository_id != repository_id
        || hosted.workflow_path != ".github/workflows/qualification-attester-tools.yml"
        || !validate_commit(&hosted.workflow_revision)
        || !decimal(&hosted.run_id)
        || hosted.run_attempt == 0
        || hosted.retention_days != 90
        || !decimal(&hosted.artifact_id)
        || hosted.artifact_name
            != format!(
                "auths-qualification-attester-tools-{}-attempt-{}",
                hosted.workflow_revision, hosted.run_attempt
            )
        || validate_sha256(&hosted.uploaded_archive_sha256).is_err()
        || !(1..=MAX_ARTIFACT_BYTES).contains(&hosted.uploaded_archive_bytes)
        || hosted.created_at_unix_seconds > hosted.verified_at_unix_seconds
        || now >= hosted.expires_at_unix_seconds
        || hosted.expires_at_unix_seconds
            < hosted.created_at_unix_seconds.saturating_add(90 * 86_400)
        || hosted.manifest_sha256 != digest_bytes(&manifest_bytes)
        || manifest.schema != "auths.qualification-attester-tools/1"
        || manifest.attester_revision != hosted.workflow_revision
        || manifest.retention_days != hosted.retention_days
        || manifest.runner_label != "ubuntu-24.04"
        || !printable(&manifest.runner_image_os, 128)
        || !printable(&manifest.runner_image_version, 128)
        || !semver_triplet(&manifest.gh_version)
        || manifest.gh_version != provenance.verifier_version
        || manifest.members.len() != expected_paths.len()
    {
        return Err(
            "attester-tools hosted verification does not bind the protected tool run".into(),
        );
    }
    for (actual, (path, mode)) in manifest.members.iter().zip(expected_paths) {
        if actual.path != path || actual.mode != mode || validate_sha256(&actual.sha256).is_err() {
            return Err(format!("attester-tools member binding drifted for {path}"));
        }
    }
    let digest_for = |path: &str| {
        manifest
            .members
            .iter()
            .find(|member| member.path == path)
            .map(|member| member.sha256.as_str())
    };
    if digest_for("gh") != Some(provenance.verifier_sha256.as_str())
        || digest_for("trusted-root.jsonl") != Some(provenance.trusted_root_sha256.as_str())
        || digest_for("qualification-release-build-verifier")
            != Some(provenance.release_build_verifier_sha256.as_str())
    {
        return Err(
            "attester-tools members differ from the tools used for provenance verification".into(),
        );
    }
    Ok(VerifiedAttesterToolsBinding {
        attester_revision: manifest.attester_revision,
        gh_version: manifest.gh_version,
        runner_image_os: manifest.runner_image_os,
        runner_image_version: manifest.runner_image_version,
        runner_label: manifest.runner_label,
        members: manifest.members,
        hosted,
    })
}

fn validate_hosted_artifact(
    artifact: &HostedArtifact,
    now: u64,
    expected_name: &str,
    maximum_bytes: u64,
    retention_days: u16,
) -> Result<(), String> {
    if artifact.role.is_empty()
        || artifact.name != expected_name
        || !decimal(&artifact.artifact_id)
        || validate_sha256(&artifact.uploaded_archive_sha256).is_err()
        || !(1..=maximum_bytes).contains(&artifact.size_in_bytes)
        || artifact.expired
        || artifact.created_at_unix_seconds > now
        || now >= artifact.expires_at_unix_seconds
        || artifact.expires_at_unix_seconds
            < artifact
                .created_at_unix_seconds
                .checked_add(u64::from(retention_days) * 24 * 60 * 60)
                .ok_or("hosted artifact retention overflowed")?
    {
        return Err(format!(
            "hosted artifact is unavailable or outside retention: {}",
            artifact.role
        ));
    }
    Ok(())
}

fn validate_surface_roster(
    actual: &[ReleaseSurfaceMember],
    expected: &[String],
) -> Result<(), String> {
    if actual.len() != expected.len() {
        return Err("qualification surface member roster has the wrong size".into());
    }
    for (member, expected_path) in actual.iter().zip(expected) {
        if member.path != *expected_path
            || member.mode != "0755"
            || !(1..=MAX_ARTIFACT_BYTES).contains(&member.bytes)
        {
            return Err(format!(
                "qualification surface member drifted: {expected_path}"
            ));
        }
        validate_sha256(&member.sha256)?;
    }
    Ok(())
}

fn read_exact_archive(
    path: &Path,
    prefix: &str,
    expected: &[ReleaseSurfaceMember],
    maximum_expanded_bytes: u64,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let file = fs::File::open(path)
        .map_err(|error| format!("could not open qualification agent archive: {error}"))?;
    let decoder = zstd::Decoder::new(file)
        .map_err(|error| format!("could not decode qualification agent archive: {error}"))?;
    let mut archive = tar::Archive::new(decoder);
    let mut contents = BTreeMap::new();
    let mut expanded = 0_u64;
    for entry in archive
        .entries()
        .map_err(|error| format!("could not enumerate qualification agent archive: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("could not read qualification agent entry: {error}"))?;
        if !entry.header().entry_type().is_file() {
            return Err("qualification agent archive contains a non-file entry".into());
        }
        let encoded = entry
            .path()
            .map_err(|error| format!("qualification agent archive path is invalid: {error}"))?;
        let relative = encoded
            .strip_prefix(prefix)
            .map_err(|_| "qualification agent archive prefix drifted".to_owned())?;
        let relative = relative
            .to_str()
            .ok_or("qualification archive path is not UTF-8")?
            .replace('\\', "/");
        validate_safe_path(&relative)?;
        let projected = expected
            .iter()
            .find(|member| member.path == relative)
            .ok_or_else(|| {
                format!("qualification agent archive has an extra member: {relative}")
            })?;
        if entry
            .header()
            .mode()
            .map_err(|error| format!("archive mode is invalid: {error}"))?
            != 0o755
            || entry.size() != projected.bytes
            || entry.size() > maximum_expanded_bytes
        {
            return Err(format!(
                "qualification agent archive metadata drifted: {relative}"
            ));
        }
        expanded = expanded
            .checked_add(entry.size())
            .ok_or("qualification agent archive expanded-byte total overflowed")?;
        if expanded > maximum_expanded_bytes {
            return Err(
                "qualification agent archive exceeds the aggregate expanded-byte bound".into(),
            );
        }
        let expected_length = usize::try_from(entry.size())
            .map_err(|_| format!("qualification archive member is too large: {relative}"))?;
        let mut bytes = Vec::with_capacity(expected_length);
        entry
            .take(projected.bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| format!("could not read qualification archive member: {error}"))?;
        if bytes.len() != expected_length
            || digest_bytes(&bytes) != projected.sha256
            || contents.insert(relative.clone(), bytes).is_some()
        {
            return Err(format!(
                "qualification archive member digest/identity drifted: {relative}"
            ));
        }
    }
    if contents.len() != expected.len() {
        return Err("qualification agent archive is missing a projected member".into());
    }
    Ok(contents)
}

fn read_canonical_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let bytes = read_regular_file(path, maximum, label)?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("{label} is not JSON: {error}"))?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| format!("could not canonicalize {label}: {error}"))?;
    if canonical != bytes {
        return Err(format!("{label} is not canonical JSON"));
    }
    Ok(bytes)
}

fn read_regular_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {label}: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(format!("{label} is not a bounded regular file"));
    }
    let bytes = fs::read(path).map_err(|error| format!("could not read {label}: {error}"))?;
    Ok(bytes)
}

fn digest_file(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| digest_bytes(&bytes))
        .map_err(|error| {
            format!(
                "could not read release artifact {}: {error}",
                path.display()
            )
        })
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_full_commit(value: &str) -> Result<(), String> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("candidate revision is not a full lowercase Git commit".into())
    }
}

fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("invalid SHA-256 digest: {value}"))
    }
}

fn validate_safe_path(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        Err(format!("release path escapes its root: {value}"))
    } else {
        Ok(())
    }
}

fn decimal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn validate_commit(value: &str) -> bool {
    validate_full_commit(value).is_ok()
}

fn printable(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| matches!(byte, b' '..=b'~'))
}

fn semver_triplet(value: &str) -> bool {
    let mut parts = value.split('.');
    let valid = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'))
    };
    parts.next().is_some_and(valid)
        && parts.next().is_some_and(valid)
        && parts.next().is_some_and(valid)
        && parts.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANDIDATE_FILES: [&str; 12] = [
        "Cargo.toml",
        "product/runtime/auths-node/Cargo.toml",
        "product/runtime/auths-connections/Cargo.toml",
        "product/stores/auths-stores/Cargo.toml",
        "product/runtime/auths-node/src/bin/auths-production.rs",
        "product/runtime/auths-node/src/generated/profile_launch_projection.json",
        "product/runtime/auths-node/src/profile_launch.rs",
        "product/runtime/auths-node/src/generated/profile_routes.rs",
        "product/runtime/auths-connections/src/lib.rs",
        "product/integrations/auths-stripe/src/lib.rs",
        "product/stores/auths-stores/src/lib.rs",
        "product/stores/auths-stores/src/operation.rs",
    ];

    fn repository() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap()
    }

    fn copied_candidate() -> tempfile::TempDir {
        let source = repository();
        let destination = tempfile::tempdir().unwrap();
        let mut files = CANDIDATE_FILES
            .iter()
            .map(|relative| (*relative).to_owned())
            .collect::<BTreeSet<_>>();
        let workspace: toml::Value =
            toml::from_str(&fs::read_to_string(source.join("Cargo.toml")).unwrap()).unwrap();
        for member in workspace["workspace"]["members"].as_array().unwrap() {
            files.insert(format!("{}/Cargo.toml", member.as_str().unwrap()));
        }
        for dependency in workspace["workspace"]["dependencies"]
            .as_table()
            .unwrap()
            .values()
        {
            if let Some(path) = dependency.get("path").and_then(toml::Value::as_str) {
                files.insert(format!("{path}/Cargo.toml"));
            }
        }
        for relative in files {
            let output = destination.path().join(&relative);
            fs::create_dir_all(output.parent().unwrap()).unwrap();
            fs::copy(source.join(&relative), output).unwrap();
        }
        destination
    }

    #[test]
    fn candidate_surface_reconstruction_accepts_the_checked_tree() {
        verify_candidate_build_surface(&repository()).unwrap();
    }

    #[test]
    fn candidate_surface_reconstruction_rejects_feature_or_route_authority_drift() {
        for required in [
            "    \"auths-connections/qualification-broker\",\n",
            "    \"auths-stores/qualification-evidence\",\n",
        ] {
            let candidate = copied_candidate();
            let manifest = candidate
                .path()
                .join("product/runtime/auths-node/Cargo.toml");
            let bytes = fs::read_to_string(&manifest).unwrap();
            assert!(bytes.contains(required));
            fs::write(&manifest, bytes.replacen(required, "", 1)).unwrap();
            assert!(
                verify_candidate_build_surface(candidate.path()).is_err(),
                "candidate node feature-edge removal was accepted: {required:?}"
            );
        }

        for (relative, marker) in [
            (
                "product/runtime/auths-node/src/bin/auths-production.rs",
                "!auths_connections::__QUALIFICATION_BROKER_ENABLED",
            ),
            (
                "product/runtime/auths-node/src/bin/auths-production.rs",
                "!auths_stores::__QUALIFICATION_EVIDENCE_ENABLED",
            ),
            (
                "product/runtime/auths-node/src/bin/auths-production.rs",
                "!auths_stripe::__TESTKIT_AGENT_ENABLED",
            ),
            (
                "product/runtime/auths-connections/src/lib.rs",
                "pub const __QUALIFICATION_BROKER_ENABLED",
            ),
            (
                "product/runtime/auths-connections/src/lib.rs",
                "#[cfg(feature = \"qualification-broker\")]\nmod qualification;",
            ),
            (
                "product/runtime/auths-connections/src/lib.rs",
                "#[cfg(feature = \"qualification-broker\")]\npub use qualification::{",
            ),
            (
                "product/runtime/auths-connections/src/lib.rs",
                "QualificationCredentialLeaseRequest, QualificationProviderCallKind,",
            ),
            (
                "product/stores/auths-stores/src/lib.rs",
                "pub const __QUALIFICATION_EVIDENCE_ENABLED",
            ),
            (
                "product/integrations/auths-stripe/src/lib.rs",
                "pub const __TESTKIT_AGENT_ENABLED",
            ),
            (
                "product/stores/auths-stores/src/operation.rs",
                "feature = \"qualification-evidence\"",
            ),
            (
                "product/stores/auths-stores/src/operation.rs",
                "open_persisted_operation_snapshot_at_for_qualification",
            ),
        ] {
            let candidate = copied_candidate();
            let source = candidate.path().join(relative);
            let bytes = fs::read_to_string(&source).unwrap();
            assert!(bytes.contains(marker));
            fs::write(&source, bytes.replace(marker, "removed-gate")).unwrap();
            assert!(
                verify_candidate_build_surface(candidate.path()).is_err(),
                "candidate source marker mutation was accepted: {relative}: {marker}"
            );
        }

        for (relative, feature) in [
            (
                "product/runtime/auths-connections/Cargo.toml",
                "qualification-broker = []",
            ),
            (
                "product/stores/auths-stores/Cargo.toml",
                "qualification-evidence = []",
            ),
        ] {
            let candidate = copied_candidate();
            let manifest = candidate.path().join(relative);
            let bytes = fs::read_to_string(&manifest).unwrap();
            assert!(bytes.contains(feature));
            fs::write(
                &manifest,
                bytes.replacen(feature, &feature.replace("[]", "[\"dep:zeroize\"]"), 1),
            )
            .unwrap();
            assert!(verify_candidate_build_surface(candidate.path()).is_err());
        }

        for dependency in ["auths-connections", "auths-stores"] {
            let candidate = copied_candidate();
            let manifest = candidate
                .path()
                .join("product/runtime/auths-node/Cargo.toml");
            let bytes = fs::read_to_string(&manifest).unwrap();
            let current = format!("{dependency}.workspace = true");
            assert!(bytes.contains(&current));
            fs::write(
                &manifest,
                bytes.replacen(
                    &current,
                    &format!("{dependency} = {{ workspace = true, features = [\"qualification-drift\"] }}"),
                    1,
                ),
            )
            .unwrap();
            assert!(verify_candidate_build_surface(candidate.path()).is_err());
        }

        for (dependency, feature) in [
            ("auths-connections", "qualification-broker"),
            ("auths-stores", "qualification-evidence"),
        ] {
            let candidate = copied_candidate();
            let manifest = candidate.path().join("Cargo.toml");
            let bytes = fs::read_to_string(&manifest).unwrap();
            let current = if dependency == "auths-connections" {
                "auths-connections = { version = \"1.0.0-rc.1\", path = \"product/runtime/auths-connections\" }"
            } else {
                "auths-stores = { version = \"1.0.0-rc.1\", path = \"product/stores/auths-stores\" }"
            };
            assert!(bytes.contains(current));
            let replacement =
                current.replacen(" }", &format!(", features = [\"{feature}\"] }}"), 1);
            fs::write(&manifest, bytes.replacen(current, &replacement, 1)).unwrap();
            assert!(verify_candidate_build_surface(candidate.path()).is_err());
        }

        let candidate = copied_candidate();
        let manifest = candidate
            .path()
            .join("product/runtime/auths-node/Cargo.toml");
        let mut bytes = fs::read_to_string(&manifest).unwrap();
        bytes.push_str(
            "\n[target.'cfg(target_os = \"linux\")'.dependencies]\n\
             auths-connections = { workspace = true, features = [\"qualification-broker\"] }\n",
        );
        fs::write(&manifest, bytes).unwrap();
        assert!(verify_candidate_build_surface(candidate.path()).is_err());

        let candidate = copied_candidate();
        let manifest = candidate
            .path()
            .join("product/runtime/auths-profile-runtime/Cargo.toml");
        let bytes = fs::read_to_string(&manifest).unwrap();
        let current = "auths-stores.workspace = true";
        assert!(bytes.contains(current));
        fs::write(
            &manifest,
            bytes.replacen(
                current,
                "auths-stores = { workspace = true, features = [\"qualification-evidence\"] }",
                1,
            ),
        )
        .unwrap();
        assert!(verify_candidate_build_surface(candidate.path()).is_err());

        let candidate = copied_candidate();
        let manifest = candidate
            .path()
            .join("product/runtime/auths-node/Cargo.toml");
        let mut bytes = fs::read_to_string(&manifest).unwrap();
        bytes.push_str(
            "\n[dependencies.qualification-store-alias]\n\
             package = \"auths-stores\"\n\
             path = \"../../stores/auths-stores\"\n\
             features = [\"qualification-evidence\"]\n",
        );
        fs::write(&manifest, bytes).unwrap();
        assert!(verify_candidate_build_surface(candidate.path()).is_err());

        let candidate = copied_candidate();
        let manifest = candidate
            .path()
            .join("product/runtime/auths-node/Cargo.toml");
        let mut bytes = fs::read_to_string(&manifest).unwrap();
        bytes = bytes.replacen(
            "[features]\n",
            "[features]\nundeclared-qualification-route = []\n",
            1,
        );
        fs::write(&manifest, bytes).unwrap();
        assert!(verify_candidate_build_surface(candidate.path()).is_err());

        let candidate = copied_candidate();
        let projection = candidate
            .path()
            .join("product/runtime/auths-node/src/generated/profile_launch_projection.json");
        let bytes = fs::read(&projection).unwrap();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["profiles"][0]["state"] = Value::String("qualified".into());
        let mut bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        bytes.push(b'\n');
        fs::write(&projection, bytes).unwrap();
        assert!(verify_candidate_build_surface(candidate.path()).is_err());
    }
}
