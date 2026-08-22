//! Concrete protected OpenTofu planning, artifact, apply, and reconciliation.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{Read, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use auths_profile_runtime::ProfileRuntimeError;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tempfile::{NamedTempFile, TempDir};

use crate::{
    DecisionClass, DigestHex, EvaluationContext, FixedApplyRequestV1, OpenTofuApplyResult,
    OpenTofuLocalAgentConfigurationV1, OpenTofuSavedPlanApplyInput, OpenTofuSavedPlanApplyV1,
    OpenTofuSourceBundleV1, OpenTofuStateEvidenceV1, PersistentPlanArtifactStore,
    PlanArtifactStore, SavedPlanArtifact, SavedPlanProjectionV1,
    canonical::{canonical_digest, canonical_json, sha256},
    connection::{OpenTofuConnectionDescriptor, OpenTofuConnectionSecretV1},
};

const MAX_PROCESS_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_mins(5);

/// Complete protected planning output persisted behind a prepared token.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedPlanPayloadV1 {
    pub action: OpenTofuSavedPlanApplyV1,
    pub projection: SavedPlanProjectionV1,
    pub evidence: OpenTofuStateEvidenceV1,
    pub configuration: OpenTofuLocalAgentConfigurationV1,
    pub descriptor: OpenTofuConnectionDescriptor,
    pub bundle: OpenTofuSourceBundleV1,
}

impl PreparedPlanPayloadV1 {
    pub fn validate(&self, now: u64) -> Result<(), ProfileRuntimeError> {
        self.configuration
            .validate()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        self.bundle
            .validate()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        self.evidence
            .validate()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        self.action
            .validate()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        self.projection
            .validate(self.configuration.verifier())
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        if self.descriptor.backend_identity() != self.action.backend_identity()
            || !self
                .action
                .workspace()
                .starts_with(self.descriptor.workspace_prefix())
            || self.bundle.requested_workspace != self.action.workspace()
            || !matches!(
                crate::evaluate(&EvaluationContext {
                    action: &self.action,
                    projection: &self.projection,
                    evidence: &self.evidence,
                    required_configuration: self.configuration.verifier(),
                    executed_configuration: self.configuration.verifier(),
                    request_audience: self.configuration.verifier().executor_audience(),
                    now,
                })
                .class,
                DecisionClass::Authorized
            )
        {
            return Err(ProfileRuntimeError::Invalid);
        }
        Ok(())
    }
}

/// Runs the protected planner and atomically publishes only an artifact handle.
pub fn plan(
    profile_state_root: &Path,
    credential: &[u8],
    descriptor: &OpenTofuConnectionDescriptor,
    configuration: &OpenTofuLocalAgentConfigurationV1,
    bundle: &OpenTofuSourceBundleV1,
    nonce: DigestHex,
    now: u64,
) -> Result<PreparedPlanPayloadV1, ProfileRuntimeError> {
    configuration
        .validate()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    bundle
        .validate()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    validate_bundle_policy(bundle, configuration)?;
    if descriptor.backend_identity()
        != configuration
            .verifier()
            .allowed_backend_identities()
            .iter()
            .find(|value| value.as_str() == descriptor.backend_identity())
            .map_or("", String::as_str)
        || !bundle
            .requested_workspace
            .starts_with(descriptor.workspace_prefix())
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    verify_binary(configuration)?;
    let secret = OpenTofuConnectionSecretV1::from_canonical_bytes(credential)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let workspace = ProtectedWorkspace::create(
        profile_state_root,
        descriptor,
        configuration,
        bundle,
        &secret,
    )?;
    workspace.initialize(false)?;
    let evidence = workspace.state_evidence(now)?;
    let plan_path = workspace.path().join("auths.tfplan");
    let plan_path_string = plan_path
        .to_str()
        .ok_or(ProfileRuntimeError::Invalid)?
        .to_owned();
    let plan_argv =
        substitute_plan_path(configuration.planner().fixed_plan_argv(), &plan_path_string)?;
    let planned = workspace.run(&plan_argv)?;
    if !planned.success {
        return Err(ProfileRuntimeError::Invalid);
    }
    let shown = workspace.run(&["show".into(), "-json".into(), plan_path_string.clone()])?;
    if !shown.success {
        return Err(ProfileRuntimeError::Invalid);
    }
    let projection = SavedPlanProjectionV1::from_show_json(&shown.stdout, configuration.verifier())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if projection.resource_changes.is_empty() {
        return Err(ProfileRuntimeError::Invalid);
    }
    let saved_plan = read_bounded_file(&plan_path, 256 * 1024 * 1024)?;
    let plan_digest = sha256(&saved_plan);
    let artifact_store = artifact_store(profile_state_root)?;
    let handle = artifact_store
        .put(SavedPlanArtifact::new(saved_plan).map_err(|_| ProfileRuntimeError::Invalid)?)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let (opentofu_version, platform) = workspace.tool_identity()?;
    if platform != configuration.planner().platform() {
        return Err(ProfileRuntimeError::Invalid);
    }
    let action = OpenTofuSavedPlanApplyV1::new(OpenTofuSavedPlanApplyInput {
        executor_audience: configuration.verifier().executor_audience().into(),
        opentofu_version,
        platform,
        backend_identity: descriptor.backend_identity().into(),
        workspace: bundle.requested_workspace.clone(),
        state_lineage: evidence.state_lineage.clone(),
        state_serial: evidence.state_serial,
        state_digest: evidence.state_digest.clone(),
        configuration_bundle_digest: bundle.digest().map_err(invalid)?,
        variable_commitment: canonical_digest(&bundle.variable_values).map_err(invalid)?,
        dependency_lock_digest: evidence.dependency_lock_digest.clone(),
        module_manifest_digest: evidence.module_manifest_digest.clone(),
        opaque_plan_digest: plan_digest,
        plan_projection_digest: projection.digest().map_err(invalid)?,
        plan_handle: handle,
        permitted_change_summary: change_summary(&projection),
        required_configuration: configuration.verifier().clone(),
        planned_at: now,
        expires_at: now
            .checked_add(configuration.planner().prepared_plan_lifetime_seconds())
            .ok_or(ProfileRuntimeError::Invalid)?,
        nonce,
    })
    .map_err(|_| ProfileRuntimeError::Invalid)?;
    let payload = PreparedPlanPayloadV1 {
        action,
        projection,
        evidence,
        configuration: configuration.clone(),
        descriptor: descriptor.clone(),
        bundle: bundle.clone(),
    };
    payload.validate(now)?;
    verify_artifact(profile_state_root, &payload)?;
    Ok(payload)
}

/// Verifies protected artifact metadata without opening a provider boundary.
pub fn verify_artifact(
    profile_state_root: &Path,
    payload: &PreparedPlanPayloadV1,
) -> Result<(), ProfileRuntimeError> {
    let artifact = artifact_store(profile_state_root)?
        .resolve(payload.action.plan_handle())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if sha256(artifact.bytes()) != *payload.action.opaque_plan_digest() {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(())
}

#[cfg(feature = "qualification")]
pub(crate) fn export_artifact(
    profile_state_root: &Path,
    payload: &PreparedPlanPayloadV1,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    payload.validate(payload.action.planned_at())?;
    let artifact = artifact_store(profile_state_root)?
        .resolve(payload.action.plan_handle())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if sha256(artifact.bytes()) != *payload.action.opaque_plan_digest() {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(artifact.bytes().to_vec())
}

#[cfg(feature = "qualification")]
pub(crate) fn import_artifact(
    profile_state_root: &Path,
    payload: &PreparedPlanPayloadV1,
    bytes: Vec<u8>,
) -> Result<(), ProfileRuntimeError> {
    if sha256(&bytes) != *payload.action.opaque_plan_digest() {
        return Err(ProfileRuntimeError::Invalid);
    }
    let handle = artifact_store(profile_state_root)?
        .put(SavedPlanArtifact::new(bytes).map_err(|_| ProfileRuntimeError::Invalid)?)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if &handle != payload.action.plan_handle() {
        return Err(ProfileRuntimeError::Invalid);
    }
    verify_artifact(profile_state_root, payload)
}

/// Applies exactly the stored saved-plan bytes after a fresh state equality check.
pub fn apply(
    profile_state_root: &Path,
    credential: &[u8],
    payload: &PreparedPlanPayloadV1,
    now: u64,
) -> Result<OpenTofuApplyResult, ProfileRuntimeError> {
    payload.validate(now)?;
    verify_binary(&payload.configuration)?;
    let secret = OpenTofuConnectionSecretV1::from_canonical_bytes(credential)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let workspace = ProtectedWorkspace::create(
        profile_state_root,
        &payload.descriptor,
        &payload.configuration,
        &payload.bundle,
        &secret,
    )?;
    workspace.initialize(false)?;
    let current = workspace.state_evidence(now)?;
    if !same_state(&current, &payload.evidence) {
        return Err(ProfileRuntimeError::Invalid);
    }
    let artifact = artifact_store(profile_state_root)?
        .resolve(payload.action.plan_handle())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if sha256(artifact.bytes()) != *payload.action.opaque_plan_digest() {
        return Err(ProfileRuntimeError::Invalid);
    }
    let request =
        FixedApplyRequestV1::derive(&payload.action).map_err(|_| ProfileRuntimeError::Invalid)?;
    let mut plan =
        NamedTempFile::new_in(workspace.path()).map_err(|_| ProfileRuntimeError::Invalid)?;
    plan.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    plan.write_all(artifact.bytes())
        .and_then(|()| plan.as_file().sync_all())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let plan_path = plan.path().to_str().ok_or(ProfileRuntimeError::Invalid)?;
    let argv = substitute_plan_path(
        payload.configuration.planner().fixed_apply_argv(),
        plan_path,
    )?;
    if request.argv()
        != [
            "apply",
            "-input=false",
            "-auto-approve",
            "{protected-saved-plan}",
        ]
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let output = workspace
        .run(&argv)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if !output.success {
        return Err(ProfileRuntimeError::Invalid);
    }
    let resulting = workspace.state_evidence(now.saturating_add(1))?;
    if resulting.state_lineage != payload.evidence.state_lineage
        || resulting.state_serial <= payload.evidence.state_serial
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let observed = workspace.run(&["output".into(), "-json".into()])?;
    if !observed.success {
        return Err(ProfileRuntimeError::Invalid);
    }
    let observation: serde_json::Value =
        serde_json::from_slice(&observed.stdout).map_err(|_| ProfileRuntimeError::Invalid)?;
    let provider_object_commitment = sha256(&canonical_json(&observation).map_err(invalid)?);
    Ok(OpenTofuApplyResult {
        state_lineage: resulting.state_lineage,
        prior_state_serial: payload.evidence.state_serial,
        resulting_state_serial: resulting.state_serial,
        resulting_state_digest: resulting.state_digest,
        provider_object_commitment,
        tool_build: payload.configuration.planner().binary_sha256().to_string(),
        execution_log_digest: sha256(&[output.stdout, output.stderr].concat()),
        started_at: now,
        finished_at: now.saturating_add(1),
        state_committed: true,
        postconditions_observed: true,
        converged: true,
    })
}

/// Observes current state without replaying the saved plan.
///
/// An unchanged state proves that the prepared apply did not commit. A changed
/// state is not, by itself, evidence that *this* operation committed: another
/// actor may have advanced the backend after provider entry. Until the backend
/// carries an operation-bound marker, changed state therefore remains
/// ambiguous and must stay in recovery rather than being reported as success.
pub fn reconcile(
    profile_state_root: &Path,
    credential: &[u8],
    payload: &PreparedPlanPayloadV1,
    now: u64,
) -> Result<Option<OpenTofuApplyResult>, ProfileRuntimeError> {
    verify_binary(&payload.configuration)?;
    let secret = OpenTofuConnectionSecretV1::from_canonical_bytes(credential)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let workspace = ProtectedWorkspace::create(
        profile_state_root,
        &payload.descriptor,
        &payload.configuration,
        &payload.bundle,
        &secret,
    )?;
    workspace.initialize(false)?;
    let current = workspace.state_evidence(now)?;
    if current.state_lineage != payload.evidence.state_lineage {
        return Err(ProfileRuntimeError::Invalid);
    }
    if current.state_serial == payload.evidence.state_serial
        && current.state_digest == payload.evidence.state_digest
    {
        return Ok(None);
    }
    Err(ProfileRuntimeError::Invalid)
}

/// Reads the current backend state without planning or applying. Qualification
/// uses this as the independent ProviderObserver boundary after the candidate
/// process has been reaped.
#[cfg(feature = "qualification")]
pub(crate) fn observe_state(
    profile_state_root: &Path,
    credential: &[u8],
    payload: &PreparedPlanPayloadV1,
    now: u64,
) -> Result<OpenTofuStateEvidenceV1, ProfileRuntimeError> {
    verify_binary(&payload.configuration)?;
    let secret = OpenTofuConnectionSecretV1::from_canonical_bytes(credential)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let workspace = ProtectedWorkspace::create(
        profile_state_root,
        &payload.descriptor,
        &payload.configuration,
        &payload.bundle,
        &secret,
    )?;
    workspace.initialize(false)?;
    workspace.state_evidence(now)
}

/// Creates (or selects) one exact run-owned qualification workspace and
/// returns its current backend state without planning or applying.
#[cfg(feature = "qualification")]
pub(crate) fn ensure_qualification_workspace(
    root: &Path,
    credential: &[u8],
    descriptor: &OpenTofuConnectionDescriptor,
    configuration: &OpenTofuLocalAgentConfigurationV1,
    bundle: &OpenTofuSourceBundleV1,
    now: u64,
) -> Result<OpenTofuStateEvidenceV1, ProfileRuntimeError> {
    configuration
        .validate()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    bundle
        .validate()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    validate_bundle_policy(bundle, configuration)?;
    verify_binary(configuration)?;
    let secret = OpenTofuConnectionSecretV1::from_canonical_bytes(credential)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let workspace = ProtectedWorkspace::create(root, descriptor, configuration, bundle, &secret)?;
    workspace.initialize(true)?;
    workspace.state_evidence(now)
}

/// Independently reopens one exact qualification workspace through the
/// protected observer credential.
#[cfg(feature = "qualification")]
pub(crate) fn observe_qualification_workspace(
    root: &Path,
    credential: &[u8],
    descriptor: &OpenTofuConnectionDescriptor,
    configuration: &OpenTofuLocalAgentConfigurationV1,
    bundle: &OpenTofuSourceBundleV1,
    now: u64,
) -> Result<OpenTofuStateEvidenceV1, ProfileRuntimeError> {
    configuration
        .validate()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    bundle
        .validate()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    validate_bundle_policy(bundle, configuration)?;
    verify_binary(configuration)?;
    let secret = OpenTofuConnectionSecretV1::from_canonical_bytes(credential)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let workspace = ProtectedWorkspace::create(root, descriptor, configuration, bundle, &secret)?;
    workspace.initialize(false)?;
    workspace.state_evidence(now)
}

/// Destroys and deletes every workspace in the exact run namespace, then
/// re-lists the backend to prove that no run-owned workspace remains.
#[cfg(feature = "qualification")]
pub(crate) fn cleanup_qualification_namespace(
    root: &Path,
    credential: &[u8],
    descriptor: &OpenTofuConnectionDescriptor,
    configuration: &OpenTofuLocalAgentConfigurationV1,
    probe_bundle: &OpenTofuSourceBundleV1,
    namespace: &str,
) -> Result<(), ProfileRuntimeError> {
    if namespace.is_empty()
        || namespace.len() > 128
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    configuration
        .validate()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    probe_bundle
        .validate()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    validate_bundle_policy(probe_bundle, configuration)?;
    verify_binary(configuration)?;
    let secret = OpenTofuConnectionSecretV1::from_canonical_bytes(credential)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let workspace =
        ProtectedWorkspace::create(root, descriptor, configuration, probe_bundle, &secret)?;
    let initialized = workspace.run(&[
        "init".into(),
        "-input=false".into(),
        "-lockfile=readonly".into(),
        "-backend-config=.auths-backend.hcl".into(),
    ])?;
    if !initialized.success {
        return Err(ProfileRuntimeError::Invalid);
    }
    let listed = workspace.run(&["workspace".into(), "list".into()])?;
    if !listed.success {
        return Err(ProfileRuntimeError::Invalid);
    }
    let output = std::str::from_utf8(&listed.stdout).map_err(|_| ProfileRuntimeError::Invalid)?;
    let mut names = output
        .lines()
        .map(|line| line.trim().trim_start_matches('*').trim())
        .filter(|name| name.starts_with(namespace))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    if names.len() > 128 {
        return Err(ProfileRuntimeError::Invalid);
    }
    for name in names {
        let selected = workspace.run(&["workspace".into(), "select".into(), name.clone()])?;
        if !selected.success {
            return Err(ProfileRuntimeError::Invalid);
        }
        let destroyed = workspace.run(&[
            "destroy".into(),
            "-input=false".into(),
            "-auto-approve".into(),
            "-lock=true".into(),
        ])?;
        if !destroyed.success {
            return Err(ProfileRuntimeError::Invalid);
        }
        let selected_default =
            workspace.run(&["workspace".into(), "select".into(), "default".into()])?;
        if !selected_default.success {
            return Err(ProfileRuntimeError::Invalid);
        }
        let deleted = workspace.run(&["workspace".into(), "delete".into(), name])?;
        if !deleted.success {
            return Err(ProfileRuntimeError::Invalid);
        }
    }
    let listed = workspace.run(&["workspace".into(), "list".into()])?;
    if !listed.success
        || std::str::from_utf8(&listed.stdout)
            .map_err(|_| ProfileRuntimeError::Invalid)?
            .lines()
            .map(|line| line.trim().trim_start_matches('*').trim())
            .any(|name| name.starts_with(namespace))
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(())
}

fn same_state(left: &OpenTofuStateEvidenceV1, right: &OpenTofuStateEvidenceV1) -> bool {
    left.backend_identity == right.backend_identity
        && left.workspace == right.workspace
        && left.state_lineage == right.state_lineage
        && left.state_serial == right.state_serial
        && left.state_digest == right.state_digest
        && left.dependency_lock_digest == right.dependency_lock_digest
        && left.module_manifest_digest == right.module_manifest_digest
        && left.planner_build_identity == right.planner_build_identity
}

fn artifact_store(root: &Path) -> Result<PersistentPlanArtifactStore, ProfileRuntimeError> {
    PersistentPlanArtifactStore::open(root.join("opentofu-plan-artifacts-v1"))
        .map_err(|_| ProfileRuntimeError::Invalid)
}

fn validate_bundle_policy(
    bundle: &OpenTofuSourceBundleV1,
    configuration: &OpenTofuLocalAgentConfigurationV1,
) -> Result<(), ProfileRuntimeError> {
    for module in &bundle.module_manifest {
        if !configuration.planner().module_pins().iter().any(|pin| {
            pin.source() == module.source
                && pin.version() == module.version
                && pin.digest() == &module.digest
        }) {
            return Err(ProfileRuntimeError::Invalid);
        }
    }
    for pin in configuration.planner().provider_pins() {
        if !bundle.dependency_lock_file.contains(pin.source())
            || !bundle.dependency_lock_file.contains(pin.version())
            || !bundle.dependency_lock_file.contains(pin.digest().as_str())
        {
            return Err(ProfileRuntimeError::Invalid);
        }
    }
    Ok(())
}

fn verify_binary(
    configuration: &OpenTofuLocalAgentConfigurationV1,
) -> Result<(), ProfileRuntimeError> {
    let path = Path::new(configuration.planner().binary_path());
    let metadata = fs::symlink_metadata(path).map_err(|_| ProfileRuntimeError::Invalid)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_BINARY_BYTES
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let mut file = File::open(path).map_err(|_| ProfileRuntimeError::Invalid)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if hex::encode(digest.finalize()) != configuration.planner().binary_sha256().as_str() {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(())
}

struct ProtectedWorkspace {
    directory: TempDir,
    binary: PathBuf,
    environment: BTreeMap<String, String>,
    descriptor: OpenTofuConnectionDescriptor,
    configuration: OpenTofuLocalAgentConfigurationV1,
    bundle: OpenTofuSourceBundleV1,
}

impl ProtectedWorkspace {
    fn create(
        root: &Path,
        descriptor: &OpenTofuConnectionDescriptor,
        configuration: &OpenTofuLocalAgentConfigurationV1,
        bundle: &OpenTofuSourceBundleV1,
        secret: &OpenTofuConnectionSecretV1,
    ) -> Result<Self, ProfileRuntimeError> {
        let parent = root.join("opentofu-workspaces-v1");
        if !parent.exists() {
            fs::create_dir(&parent).map_err(|_| ProfileRuntimeError::Invalid)?;
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
                .map_err(|_| ProfileRuntimeError::Invalid)?;
        }
        let directory = tempfile::Builder::new()
            .prefix("operation-")
            .tempdir_in(&parent)
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        for (relative, contents) in &bundle.root_module_files {
            let path = directory.path().join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|_| ProfileRuntimeError::Invalid)?;
            }
            write_private(&path, contents.as_bytes())?;
        }
        write_private(
            &directory.path().join(".terraform.lock.hcl"),
            bundle.dependency_lock_file.as_bytes(),
        )?;
        let backend = format!(
            "terraform {{\n  backend {:?} {{}}\n}}\n",
            descriptor.backend_kind()
        );
        write_private(
            &directory.path().join("auths-backend.tf"),
            backend.as_bytes(),
        )?;
        let mut backend_config = String::new();
        for (key, value) in secret.backend_configuration() {
            let value = serde_json::to_string(value).map_err(|_| ProfileRuntimeError::Invalid)?;
            writeln!(&mut backend_config, "{key} = {value}")
                .map_err(|_| ProfileRuntimeError::Invalid)?;
        }
        write_private(
            &directory.path().join(".auths-backend.hcl"),
            backend_config.as_bytes(),
        )?;
        let cli_config = format!(
            "provider_installation {{\n  filesystem_mirror {{ path = {} }}\n}}\n",
            serde_json::to_string(configuration.planner().dependency_mirror()).unwrap()
        );
        write_private(
            &directory.path().join(".auths-tofurc"),
            cli_config.as_bytes(),
        )?;
        let home = directory.path().join("home");
        fs::create_dir(&home).map_err(|_| ProfileRuntimeError::Invalid)?;
        let mut environment = secret.environment().clone();
        for (name, value) in &bundle.variable_values {
            environment.insert(format!("TF_VAR_{name}"), value.clone());
        }
        environment.insert("TF_IN_AUTOMATION".into(), "1".into());
        environment.insert("TF_INPUT".into(), "0".into());
        environment.insert("HOME".into(), home.to_string_lossy().into_owned());
        environment.insert(
            "TF_DATA_DIR".into(),
            directory
                .path()
                .join(".terraform")
                .to_string_lossy()
                .into_owned(),
        );
        environment.insert(
            "TF_CLI_CONFIG_FILE".into(),
            directory
                .path()
                .join(".auths-tofurc")
                .to_string_lossy()
                .into_owned(),
        );
        Ok(Self {
            directory,
            binary: PathBuf::from(configuration.planner().binary_path()),
            environment,
            descriptor: descriptor.clone(),
            configuration: configuration.clone(),
            bundle: bundle.clone(),
        })
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn initialize(&self, create_workspace: bool) -> Result<(), ProfileRuntimeError> {
        let initialized = self.run(&[
            "init".into(),
            "-input=false".into(),
            "-lockfile=readonly".into(),
            "-backend-config=.auths-backend.hcl".into(),
        ])?;
        if !initialized.success {
            return Err(ProfileRuntimeError::Invalid);
        }
        let selected = self.run(&[
            "workspace".into(),
            "select".into(),
            self.bundle.requested_workspace.clone(),
        ])?;
        if selected.success {
            return Ok(());
        }
        if !create_workspace {
            return Err(ProfileRuntimeError::Invalid);
        }
        let created = self.run(&[
            "workspace".into(),
            "new".into(),
            self.bundle.requested_workspace.clone(),
        ])?;
        if created.success {
            Ok(())
        } else {
            Err(ProfileRuntimeError::Invalid)
        }
    }

    fn state_evidence(&self, now: u64) -> Result<OpenTofuStateEvidenceV1, ProfileRuntimeError> {
        let state = self.run(&["state".into(), "pull".into()])?;
        if !state.success {
            return Err(ProfileRuntimeError::Invalid);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&state.stdout).map_err(|_| ProfileRuntimeError::Invalid)?;
        let state_lineage = value
            .get("lineage")
            .and_then(serde_json::Value::as_str)
            .ok_or(ProfileRuntimeError::Invalid)?
            .to_owned();
        let state_serial = value
            .get("serial")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ProfileRuntimeError::Invalid)?;
        let canonical = canonical_json(&value).map_err(invalid)?;
        let evidence = OpenTofuStateEvidenceV1 {
            backend_identity: self.descriptor.backend_identity().into(),
            workspace: self.bundle.requested_workspace.clone(),
            state_lineage,
            state_serial,
            state_digest: sha256(&canonical),
            lock_held: false,
            dependency_lock_digest: sha256(self.bundle.dependency_lock_file.as_bytes()),
            module_manifest_digest: canonical_digest(&self.bundle.module_manifest)
                .map_err(invalid)?,
            planner_build_identity: self.configuration.planner().binary_sha256().to_string(),
            observed_at: now,
        };
        evidence
            .validate()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        Ok(evidence)
    }

    fn tool_identity(&self) -> Result<(String, String), ProfileRuntimeError> {
        let output = self.run(&["version".into(), "-json".into()])?;
        if !output.success {
            return Err(ProfileRuntimeError::Invalid);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(|_| ProfileRuntimeError::Invalid)?;
        let version = value
            .get("opentofu_version")
            .or_else(|| value.get("terraform_version"))
            .and_then(serde_json::Value::as_str)
            .ok_or(ProfileRuntimeError::Invalid)?
            .to_owned();
        let platform = value
            .get("platform")
            .and_then(serde_json::Value::as_str)
            .ok_or(ProfileRuntimeError::Invalid)?
            .to_owned();
        Ok((version, platform))
    }

    fn run(&self, arguments: &[String]) -> Result<ProcessOutput, ProfileRuntimeError> {
        let mut command = Command::new(&self.binary);
        command
            .args(arguments)
            .current_dir(self.path())
            .env_clear()
            .envs(&self.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|_| ProfileRuntimeError::Invalid)?;
        let stdout = child.stdout.take().ok_or(ProfileRuntimeError::Invalid)?;
        let stderr = child.stderr.take().ok_or(ProfileRuntimeError::Invalid)?;
        let stdout_reader = thread::spawn(move || read_bounded(stdout));
        let stderr_reader = thread::spawn(move || read_bounded(stderr));
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|_| ProfileRuntimeError::Invalid)? {
                break status;
            }
            if started.elapsed() >= PROCESS_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(ProfileRuntimeError::Invalid);
            }
            thread::sleep(Duration::from_millis(20));
        };
        Ok(ProcessOutput {
            success: status.success(),
            stdout: stdout_reader
                .join()
                .map_err(|_| ProfileRuntimeError::Invalid)??,
            stderr: stderr_reader
                .join()
                .map_err(|_| ProfileRuntimeError::Invalid)??,
        })
    }
}

struct ProcessOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>, ProfileRuntimeError> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_PROCESS_OUTPUT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if bytes.len() > MAX_PROCESS_OUTPUT {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(bytes)
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ProfileRuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProfileRuntimeError::Invalid)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum as u64 {
        return Err(ProfileRuntimeError::Invalid);
    }
    let file = File::open(path).map_err(|_| ProfileRuntimeError::Invalid)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| ProfileRuntimeError::Invalid)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(bytes)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ProfileRuntimeError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ProfileRuntimeError::Invalid)
}

fn substitute_plan_path(
    template: &[String],
    plan_path: &str,
) -> Result<Vec<String>, ProfileRuntimeError> {
    let mut replacements = 0_usize;
    let values = template
        .iter()
        .map(|value| {
            if value == "{protected-saved-plan}" {
                replacements += 1;
                plan_path.to_owned()
            } else {
                value.clone()
            }
        })
        .collect::<Vec<_>>();
    if replacements != 1 {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(values)
}

fn change_summary(projection: &SavedPlanProjectionV1) -> crate::PermittedChangeSummaryV1 {
    let mut result = crate::PermittedChangeSummaryV1 {
        creates: 0,
        updates: 0,
        reads: 0,
        no_ops: 0,
    };
    for action in projection
        .resource_changes
        .iter()
        .flat_map(|change| &change.actions)
    {
        match action {
            crate::ResourceAction::Create => result.creates = result.creates.saturating_add(1),
            crate::ResourceAction::Update => result.updates = result.updates.saturating_add(1),
            crate::ResourceAction::Read => result.reads = result.reads.saturating_add(1),
            crate::ResourceAction::NoOp => result.no_ops = result.no_ops.saturating_add(1),
            crate::ResourceAction::Delete => {}
        }
    }
    result
}

fn invalid(_: impl core::fmt::Display) -> ProfileRuntimeError {
    ProfileRuntimeError::Invalid
}
