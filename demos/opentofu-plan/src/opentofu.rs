//! Protected fixture and no-shell `OpenTofu` CLI adapters.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use auths_opentofu::{
    CredentialProvider, DigestHex, OpenTofuApplyResult, OpenTofuCredential, OpenTofuGateway,
    OpenTofuSavedPlanApplyV1, OpenTofuStateEvidenceV1, PortError, SavedPlanArtifact,
    VerifiedSavedPlanCommand,
    canonical::{canonical_digest, canonical_json, sha256},
};
use tempfile::NamedTempFile;

const MAX_PROCESS_OUTPUT: usize = 16 * 1024 * 1024;

struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

enum BackendMode {
    Fixture {
        planning: OpenTofuStateEvidenceV1,
        current_serial: Mutex<u64>,
    },
    Cli {
        program: PathBuf,
        working_directory: PathBuf,
        timeout: Duration,
        tool_build: String,
        planning: OpenTofuStateEvidenceV1,
        configuration_bundle_digest: DigestHex,
        variable_commitment: DigestHex,
    },
}

/// Protected executor backend. The proposing agent cannot access its secret.
#[derive(Clone)]
pub struct OpenTofuBackend {
    mode: Arc<BackendMode>,
    credential: Arc<SecretBytes>,
    credential_calls: Arc<AtomicUsize>,
    apply_calls: Arc<AtomicUsize>,
}

/// Protected planning output used to construct the exact action.
pub struct LivePreparedPlan {
    pub saved_plan_bytes: Vec<u8>,
    pub show_json: Vec<u8>,
    pub evidence: OpenTofuStateEvidenceV1,
    pub opentofu_version: String,
    pub platform: String,
}

impl OpenTofuBackend {
    #[must_use]
    pub fn fixture(evidence: OpenTofuStateEvidenceV1) -> Self {
        Self {
            mode: Arc::new(BackendMode::Fixture {
                current_serial: Mutex::new(evidence.state_serial),
                planning: evidence,
            }),
            credential: Arc::new(SecretBytes(
                br#"{"AUTHS_FIXTURE_TOKEN":"protected"}"#.to_vec(),
            )),
            credential_calls: Arc::new(AtomicUsize::new(0)),
            apply_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "all protected runtime commitments remain explicit at construction"
    )]
    pub fn cli(
        program: PathBuf,
        working_directory: PathBuf,
        timeout: Duration,
        tool_build: String,
        evidence: OpenTofuStateEvidenceV1,
        credential_json: Vec<u8>,
        configuration_bundle_digest: DigestHex,
        variable_commitment: DigestHex,
    ) -> Result<Self, PortError> {
        if !program.is_absolute()
            || !working_directory.is_absolute()
            || !working_directory.is_dir()
            || !(Duration::from_secs(1)..=Duration::from_mins(10)).contains(&timeout)
        {
            return Err(PortError::InvalidConfiguration);
        }
        if committed_variables(&credential_json)? != variable_commitment
            || configuration_digest(&working_directory)? != configuration_bundle_digest
        {
            return Err(PortError::InvalidConfiguration);
        }
        Ok(Self {
            mode: Arc::new(BackendMode::Cli {
                program,
                working_directory,
                timeout,
                tool_build,
                planning: evidence,
                configuration_bundle_digest,
                variable_commitment,
            }),
            credential: Arc::new(SecretBytes(credential_json)),
            credential_calls: Arc::new(AtomicUsize::new(0)),
            apply_calls: Arc::new(AtomicUsize::new(0)),
        })
    }

    #[must_use]
    pub fn mode(&self) -> &'static str {
        match self.mode.as_ref() {
            BackendMode::Fixture { .. } => "deterministic-fixture",
            BackendMode::Cli { .. } => "live-opentofu",
        }
    }

    pub fn readiness(&self) -> Result<(), PortError> {
        match self.mode.as_ref() {
            BackendMode::Fixture { .. } => Ok(()),
            BackendMode::Cli {
                program,
                working_directory,
                timeout,
                ..
            } => {
                let output = run(
                    program,
                    working_directory,
                    &["version", "-json"],
                    &BTreeMap::new(),
                    *timeout,
                )?;
                if output.status_success {
                    Ok(())
                } else {
                    Err(PortError::EvidenceUnavailable)
                }
            }
        }
    }

    /// Runs the pinned initializer, workspace selection, planner, and JSON
    /// renderer inside the configured protected directory.
    pub fn prepare_live(&self, now: u64) -> Result<LivePreparedPlan, PortError> {
        let BackendMode::Cli {
            program,
            working_directory,
            timeout,
            planning,
            configuration_bundle_digest,
            variable_commitment,
            ..
        } = self.mode.as_ref()
        else {
            return Err(PortError::InvalidConfiguration);
        };
        if configuration_digest(working_directory)? != *configuration_bundle_digest
            || committed_variables(&self.credential.0)? != *variable_commitment
        {
            return Err(PortError::InvalidConfiguration);
        }
        let credential = OpenTofuCredential::new(self.credential.0.clone())?;
        let environment = validate_environment(credential.expose())?;
        for arguments in [
            vec!["init", "-input=false", "-lockfile=readonly"],
            vec!["workspace", "select", planning.workspace.as_str()],
        ] {
            let output = run(
                program,
                working_directory,
                &arguments,
                &environment,
                *timeout,
            )?;
            if !output.status_success {
                return Err(PortError::Execution);
            }
        }
        let plan_path = working_directory.join(format!(".auths-plan-{now}.tfplan"));
        let plan_path_string = plan_path
            .to_str()
            .ok_or(PortError::InvalidConfiguration)?
            .to_owned();
        let plan_output = run(
            program,
            working_directory,
            &[
                "plan",
                "-input=false",
                "-lock=true",
                "-refresh=true",
                "-out",
                &plan_path_string,
            ],
            &environment,
            *timeout,
        )?;
        if !plan_output.status_success {
            return Err(PortError::Execution);
        }
        let show = run(
            program,
            working_directory,
            &["show", "-json", &plan_path_string],
            &environment,
            *timeout,
        )?;
        if !show.status_success {
            return Err(PortError::Execution);
        }
        let saved_plan_bytes = fs::read(&plan_path).map_err(|_| PortError::ArtifactUnavailable)?;
        fs::remove_file(&plan_path).map_err(|_| PortError::ArtifactUnavailable)?;
        let version = run(
            program,
            working_directory,
            &["version", "-json"],
            &BTreeMap::new(),
            *timeout,
        )?;
        let version_json: serde_json::Value =
            serde_json::from_slice(&version.stdout).map_err(|_| PortError::EvidenceUnavailable)?;
        let opentofu_version = version_json
            .get("opentofu_version")
            .or_else(|| version_json.get("terraform_version"))
            .and_then(serde_json::Value::as_str)
            .ok_or(PortError::EvidenceUnavailable)?
            .to_owned();
        let platform = version_json
            .get("platform")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let mut evidence = state_pull(program, working_directory, &credential, *timeout, planning)?;
        evidence.observed_at = now;
        Ok(LivePreparedPlan {
            saved_plan_bytes,
            show_json: show.stdout,
            evidence,
            opentofu_version,
            platform,
        })
    }

    #[must_use]
    pub fn credential_calls(&self) -> usize {
        self.credential_calls.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn apply_calls(&self) -> usize {
        self.apply_calls.load(Ordering::SeqCst)
    }
}

impl CredentialProvider for OpenTofuBackend {
    fn mutation_credential(
        &self,
        _: &OpenTofuSavedPlanApplyV1,
    ) -> Result<OpenTofuCredential, PortError> {
        self.credential_calls.fetch_add(1, Ordering::SeqCst);
        OpenTofuCredential::new(self.credential.0.clone())
    }
}

impl OpenTofuGateway for OpenTofuBackend {
    fn recheck_state(
        &self,
        _: &VerifiedSavedPlanCommand,
        credential: &OpenTofuCredential,
    ) -> Result<OpenTofuStateEvidenceV1, PortError> {
        match self.mode.as_ref() {
            BackendMode::Fixture {
                planning,
                current_serial,
            } => {
                let serial = *current_serial
                    .lock()
                    .map_err(|_| PortError::EvidenceUnavailable)?;
                let mut evidence = planning.clone();
                evidence.state_serial = serial;
                evidence.state_digest = if serial == planning.state_serial {
                    planning.state_digest.clone()
                } else {
                    sha256(format!("fixture-state-{serial}").as_bytes())
                };
                Ok(evidence)
            }
            BackendMode::Cli {
                program,
                working_directory,
                timeout,
                planning,
                ..
            } => state_pull(program, working_directory, credential, *timeout, planning),
        }
    }

    fn apply_saved_plan(
        &self,
        command: &VerifiedSavedPlanCommand,
        artifact: &SavedPlanArtifact,
        credential: &OpenTofuCredential,
        now: u64,
    ) -> Result<OpenTofuApplyResult, PortError> {
        self.apply_calls.fetch_add(1, Ordering::SeqCst);
        match self.mode.as_ref() {
            BackendMode::Fixture {
                planning,
                current_serial,
            } => {
                let mut serial = current_serial.lock().map_err(|_| PortError::Execution)?;
                if *serial != command.action().state_serial()
                    || sha256(artifact.bytes()) != *command.action().opaque_plan_digest()
                {
                    return Err(PortError::Execution);
                }
                *serial = serial.saturating_add(1);
                Ok(OpenTofuApplyResult::synthetic(
                    planning.state_lineage.clone(),
                    planning.state_serial,
                    *serial,
                    now,
                ))
            }
            BackendMode::Cli {
                program,
                working_directory,
                timeout,
                tool_build,
                planning,
                configuration_bundle_digest,
                variable_commitment,
            } => {
                if command.action().configuration_bundle_digest() != configuration_bundle_digest
                    || command.action().variable_commitment() != variable_commitment
                    || configuration_digest(working_directory)? != *configuration_bundle_digest
                    || committed_variables(credential.expose())? != *variable_commitment
                {
                    return Err(PortError::ArtifactMismatch);
                }
                let mut plan =
                    NamedTempFile::new_in(working_directory).map_err(|_| PortError::Execution)?;
                plan.write_all(artifact.bytes())
                    .and_then(|()| plan.as_file().sync_all())
                    .map_err(|_| PortError::Execution)?;
                let environment = validate_environment(credential.expose())?;
                let plan_path = plan
                    .path()
                    .to_str()
                    .ok_or(PortError::InvalidConfiguration)?;
                let output = run(
                    program,
                    working_directory,
                    &["apply", "-input=false", "-auto-approve", plan_path],
                    &environment,
                    *timeout,
                )?;
                if !output.status_success {
                    return Err(PortError::Execution);
                }
                let current =
                    state_pull(program, working_directory, credential, *timeout, planning)?;
                if current.state_serial <= planning.state_serial {
                    return Err(PortError::OutcomeUnknown);
                }
                Ok(OpenTofuApplyResult {
                    state_lineage: current.state_lineage,
                    prior_state_serial: planning.state_serial,
                    resulting_state_serial: current.state_serial,
                    resulting_state_digest: current.state_digest,
                    provider_object_commitment: sha256(&output.stdout),
                    tool_build: tool_build.clone(),
                    execution_log_digest: sha256(&[output.stdout, output.stderr].concat()),
                    started_at: now,
                    finished_at: now.saturating_add(1),
                    state_committed: true,
                    postconditions_observed: true,
                    converged: true,
                })
            }
        }
    }

    fn reconcile(
        &self,
        command: &VerifiedSavedPlanCommand,
        credential: &OpenTofuCredential,
        now: u64,
    ) -> Result<OpenTofuApplyResult, PortError> {
        let current = self.recheck_state(command, credential)?;
        if current.state_serial <= command.action().state_serial() {
            return Err(PortError::OutcomeUnknown);
        }
        Ok(OpenTofuApplyResult::synthetic(
            current.state_lineage,
            command.action().state_serial(),
            current.state_serial,
            now,
        ))
    }
}

struct ProcessOutput {
    status_success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(
    program: &PathBuf,
    working_directory: &PathBuf,
    arguments: &[&str],
    environment: &BTreeMap<String, String>,
    timeout: Duration,
) -> Result<ProcessOutput, PortError> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(working_directory)
        .env_clear()
        .env("TF_IN_AUTOMATION", "1")
        .env("TF_INPUT", "0")
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| PortError::Execution)?;
    let stdout = child.stdout.take().ok_or(PortError::Execution)?;
    let stderr = child.stderr.take().ok_or(PortError::Execution)?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| PortError::Execution)? {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(PortError::OutcomeUnknown);
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stdout = stdout_reader.join().map_err(|_| PortError::Execution)??;
    let stderr = stderr_reader.join().map_err(|_| PortError::Execution)??;
    Ok(ProcessOutput {
        status_success: status.success(),
        stdout,
        stderr,
    })
}

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>, PortError> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(u64::try_from(MAX_PROCESS_OUTPUT + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| PortError::Execution)?;
    if bytes.len() > MAX_PROCESS_OUTPUT {
        return Err(PortError::LimitExceeded);
    }
    Ok(bytes)
}

fn state_pull(
    program: &PathBuf,
    working_directory: &PathBuf,
    credential: &OpenTofuCredential,
    timeout: Duration,
    planning: &OpenTofuStateEvidenceV1,
) -> Result<OpenTofuStateEvidenceV1, PortError> {
    let environment = validate_environment(credential.expose())?;
    let output = run(
        program,
        working_directory,
        &["state", "pull"],
        &environment,
        timeout,
    )?;
    if !output.status_success {
        return Err(PortError::EvidenceUnavailable);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|_| PortError::EvidenceUnavailable)?;
    let lineage = value
        .get("lineage")
        .and_then(serde_json::Value::as_str)
        .ok_or(PortError::EvidenceUnavailable)?;
    let serial = value
        .get("serial")
        .and_then(serde_json::Value::as_u64)
        .ok_or(PortError::EvidenceUnavailable)?;
    let canonical = canonical_json(&value).map_err(|_| PortError::EvidenceUnavailable)?;
    Ok(OpenTofuStateEvidenceV1 {
        state_lineage: lineage.into(),
        state_serial: serial,
        state_digest: sha256(&canonical),
        ..planning.clone()
    })
}

fn validate_environment(bytes: &[u8]) -> Result<BTreeMap<String, String>, PortError> {
    let environment: BTreeMap<String, String> =
        serde_json::from_slice(bytes).map_err(|_| PortError::InvalidConfiguration)?;
    if environment.is_empty()
        || environment.len() > 64
        || environment.iter().any(|(name, value)| {
            name.is_empty()
                || name.len() > 128
                || value.is_empty()
                || value.len() > 16 * 1024
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
                || matches!(
                    name.as_str(),
                    "PATH"
                        | "HOME"
                        | "SHELL"
                        | "TF_CLI_ARGS"
                        | "TF_CLI_CONFIG_FILE"
                        | "TF_DATA_DIR"
                )
        })
    {
        return Err(PortError::InvalidConfiguration);
    }
    Ok(environment)
}

/// Commits only explicit `OpenTofu` input variables, never provider credentials.
pub fn committed_variables(bytes: &[u8]) -> Result<DigestHex, PortError> {
    let environment = validate_environment(bytes)?;
    let variables = environment
        .into_iter()
        .filter(|(name, _)| name.starts_with("TF_VAR_"))
        .collect::<BTreeMap<_, _>>();
    if variables.is_empty() {
        return Err(PortError::InvalidConfiguration);
    }
    canonical_digest(&variables).map_err(|_| PortError::InvalidConfiguration)
}

/// Commits every top-level HCL source file by canonical path and byte digest.
pub fn configuration_digest(directory: &Path) -> Result<DigestHex, PortError> {
    let mut files = fs::read_dir(directory)
        .map_err(|_| PortError::InvalidConfiguration)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "tf")
        })
        .collect::<Vec<_>>();
    files.sort_by_key(std::fs::DirEntry::file_name);
    if files.is_empty() {
        return Err(PortError::InvalidConfiguration);
    }
    let mut projection = Vec::with_capacity(files.len());
    for entry in files {
        let bytes = fs::read(entry.path()).map_err(|_| PortError::InvalidConfiguration)?;
        projection.push((
            entry.file_name().to_string_lossy().into_owned(),
            sha256(&bytes),
        ));
    }
    canonical_digest(&projection).map_err(|_| PortError::InvalidConfiguration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_commitment_excludes_provider_secret_but_binds_inputs() {
        let first = br#"{"CLOUDFLARE_API_TOKEN":"token-a","TF_VAR_NAME":"one"}"#;
        let rotated = br#"{"CLOUDFLARE_API_TOKEN":"token-b","TF_VAR_NAME":"one"}"#;
        let changed = br#"{"CLOUDFLARE_API_TOKEN":"token-b","TF_VAR_NAME":"two"}"#;
        assert_eq!(
            committed_variables(first).unwrap(),
            committed_variables(rotated).unwrap()
        );
        assert_ne!(
            committed_variables(first).unwrap(),
            committed_variables(changed).unwrap()
        );
    }
}
