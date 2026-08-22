//! Provider-free protected controller for the crash-after-decision boundary.
//!
//! The controller accepts one durable acknowledgement directly from the
//! agent process, derives the capability-free public snapshot from the
//! protected journal, obtains distinct Supervisor and JournalReader source
//! signatures, fsyncs the signed source record, and only then kills the
//! agent's delegated cgroup.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux {
    use auths_lifecycle::OperationEffectV1;
    use auths_profile_kit::{
        QualificationCrashActionContextV1, QualificationCrashActionFactsV1,
        QualificationCrashActionRecordV1, QualificationCrashPhaseContextV1,
        QualificationCrashProcessIdentityV1, QualificationDecisionSnapshotV1,
        QualificationDurableDecisionAckV1, QualificationEffect, QualificationEvidenceEvent,
        QualificationEvidenceEventKind, QualificationEvidenceLedgerPlanV1,
        QualificationEvidenceSource, QualificationEvidenceSourceTrustRegistry,
        QualificationFailpoint, QualificationJournalDecisionContext,
        QualificationJournalDecisionContextRecord, QualificationSupervisorPhaseRequestV1,
        qualification_pre_admission_attempt_count, qualification_state_directory_commitment,
    };
    use auths_qualification_evidence_source::{
        QualificationCrashActionResponseV1, QualificationJournalBoundaryDecisionV1,
        QualificationJournalBoundaryDrainRequestV1, QualificationJournalBoundaryDrainResponseV1,
        QualificationJournalBoundaryProcessV1, QualificationProviderObserverResponseV1,
        QualificationReceiptVerifierResponseV1, QualificationSourceAppendSession,
        QualificationSourceSessionPeer, derive_qualification_decision_snapshot,
        qualification_profile_state_snapshot_path, read_bounded_session_frame_before,
        read_source_session_frame_before, write_source_session_frame_before,
    };
    use auths_stores::{
        QualificationJournalBoundaryKindV1, open_persisted_operation_snapshot_at_for_qualification,
        read_persisted_operation_record_from_qualification_snapshot,
        read_persisted_operation_records_from_qualification_snapshot,
        read_persisted_qualification_boundaries_from_snapshot,
    };
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use rustix::{
        fs::{
            AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, mkdirat, open, openat, openat2,
            renameat_with, unlinkat,
        },
        process::{Pid, PidfdFlags, pidfd_open},
    };
    use sha2::{Digest as _, Sha256};
    use std::{
        collections::{BTreeMap, BTreeSet},
        env,
        fs::{self, File},
        io::{IoSlice, Read, Seek as _, SeekFrom, Write},
        mem::MaybeUninit,
        net::Shutdown,
        os::{
            fd::{AsFd as _, OwnedFd},
            unix::{
                fs::{FileTypeExt as _, MetadataExt as _},
                net::UnixStream,
                process::ExitStatusExt as _,
            },
        },
        path::{Component, Path, PathBuf},
        process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    const MAX_ACK_BYTES: usize = 4_096;
    const MAX_TRUST_BYTES: u64 = 262_144;
    const MAX_RECEIPT_TRUST_BYTES: u64 = 262_144;
    const BEFORE_DECISION_CHECKPOINT: &[u8] = b"AUTHS-QUALIFICATION-BEFORE-DECISION/1";
    const AFTER_RESERVATION_CHECKPOINT: &[u8] = b"AUTHS-QUALIFICATION-AFTER-RESERVATION/1";
    const SOURCE_CHECKPOINT_ENROLLMENT_VERSION: u8 = 1;
    const SOURCE_CHECKPOINT_AFTER_REREAD: u8 = 1;
    const SOURCE_CHECKPOINT_AFTER_LEASE: u8 = 2;
    const SOURCE_CHECKPOINT_AFTER_REQUEST_WRITE: u8 = 3;
    const SOURCE_CHECKPOINT_PROVIDER_AUTHORIZATION: u8 = 16;
    const SOURCE_CHECKPOINT_ABORT: u8 = 0;
    const SOURCE_CHECKPOINT_CLEAN: u8 = 1;

    struct AgentServiceLaunchPolicy {
        client_proxy_reader_uid: u32,
        client_proxy_artifact_sha256: String,
        credential_broker_socket: String,
        credential_broker_reader_uid: u32,
        credential_broker_artifact_sha256: String,
        provider_proxy_socket: String,
        provider_proxy_reader_uid: u32,
        provider_proxy_artifact_sha256: String,
        source_context_sha256: String,
    }

    struct AgentLaunchPolicy<'a> {
        executable_sha256: &'a str,
        launcher_sha256: &'a str,
        ledger_plan_path: &'a str,
        recovery_key_id: &'a str,
        recovery_public_key_base64url: &'a str,
        crash_generation: Option<u32>,
        control_operation_id: Option<&'a str>,
        controller_nonce_sha256: Option<&'a str>,
    }

    impl<'a> AgentLaunchPolicy<'a> {
        fn phase(
            plan: &'a QualificationEvidenceLedgerPlanV1,
            launcher_sha256: &'a str,
            ledger_plan_path: &'a str,
            generation: u32,
            crash_identity: Option<(&'a str, &'a str)>,
        ) -> Self {
            Self {
                executable_sha256: &plan.agent_executable_sha256,
                launcher_sha256,
                ledger_plan_path,
                recovery_key_id: &plan.recovery_key_id,
                recovery_public_key_base64url: &plan.recovery_public_key_base64url,
                crash_generation: crash_identity.map(|_| generation),
                control_operation_id: crash_identity.map(|identity| identity.0),
                controller_nonce_sha256: crash_identity.map(|identity| identity.1),
            }
        }
    }

    pub(super) fn main() -> ExitCode {
        let arguments = env::args().skip(1).collect::<Vec<_>>();
        let result = match arguments.first().map(String::as_str) {
            Some("run-phase") => run_phase(&arguments),
            _ => Err(usage()),
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("qualification crash controller failed closed: {error}");
                ExitCode::FAILURE
            }
        }
    }

    /*
     * Crash execution is deliberately part of `run-phase`: the
     * immutable ledger phase selects `Option<QualificationFailpoint>` and the
     * same session owns launch, source gating, kill, restart, and completion.
     */

    struct ManagedAgent {
        child: Child,
        cgroup: Option<OwnedCgroup>,
        _pidfd: Option<OwnedFd>,
        start_time_ticks: u64,
        finished: bool,
    }

    #[derive(Clone, Copy)]
    struct AgentLaunchMode {
        generation: u32,
        failpoint: Option<QualificationFailpoint>,
        restarting: bool,
        use_restart_paths: bool,
    }

    impl AgentLaunchMode {
        const fn ordinary(generation: u32) -> Self {
            Self {
                generation,
                failpoint: None,
                restarting: false,
                use_restart_paths: false,
            }
        }

        const fn crash(generation: u32, failpoint: QualificationFailpoint) -> Self {
            Self {
                generation,
                failpoint: Some(failpoint),
                restarting: false,
                use_restart_paths: false,
            }
        }

        const fn restart(
            generation: u32,
            use_restart_paths: bool,
            failpoint: Option<QualificationFailpoint>,
        ) -> Self {
            Self {
                generation,
                failpoint,
                restarting: true,
                use_restart_paths,
            }
        }
    }

    struct OwnedCgroup {
        path: PathBuf,
        device: u64,
        inode: u64,
    }

    impl OwnedCgroup {
        fn create(path: &Path) -> Result<Self, String> {
            validate_new_cgroup_path(path)?;
            fs::create_dir(path).map_err(string_error)?;
            let metadata = fs::symlink_metadata(path).map_err(string_error)?;
            if !metadata.file_type().is_dir() {
                return Err("created qualification cgroup is not a directory".into());
            }
            Ok(Self {
                path: path.to_owned(),
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }

        fn validate_identity(&self) -> Result<(), String> {
            let metadata = fs::symlink_metadata(&self.path).map_err(string_error)?;
            if !metadata.file_type().is_dir()
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
            {
                return Err("owned qualification cgroup identity changed".into());
            }
            Ok(())
        }

        fn commitment_sha256(&self) -> Result<String, String> {
            self.validate_identity()?;
            let identity = serde_json::json!({
                "schema":"auths.qualification-cgroup-identity/1",
                "path":path_string(&self.path)?,
                "device":self.device,
                "inode":self.inode,
            });
            Ok(hex::encode(Sha256::digest(
                serde_json_canonicalizer::to_vec(&identity).map_err(string_error)?,
            )))
        }
    }

    impl ManagedAgent {
        fn launch(
            values: &BTreeMap<String, String>,
            policy: &AgentLaunchPolicy<'_>,
            agent_services: &AgentServiceLaunchPolicy,
            cgroup: &Path,
            mode: AgentLaunchMode,
        ) -> Result<Self, String> {
            let cgroup = OwnedCgroup::create(cgroup)?;
            Self::launch_with_cgroup(values, policy, agent_services, cgroup, mode)
        }

        fn restart_in_cgroup(
            values: &BTreeMap<String, String>,
            policy: &AgentLaunchPolicy<'_>,
            agent_services: &AgentServiceLaunchPolicy,
            cgroup: OwnedCgroup,
            mode: AgentLaunchMode,
        ) -> Result<Self, String> {
            cgroup.validate_identity()?;
            Self::launch_with_cgroup(values, policy, agent_services, cgroup, mode)
        }

        fn launch_with_cgroup(
            values: &BTreeMap<String, String>,
            policy: &AgentLaunchPolicy<'_>,
            agent_services: &AgentServiceLaunchPolicy,
            cgroup: OwnedCgroup,
            mode: AgentLaunchMode,
        ) -> Result<Self, String> {
            let child = launch_agent(values, policy, agent_services, mode)?;
            let mut managed = Self {
                child,
                cgroup: Some(cgroup),
                _pidfd: None,
                start_time_ticks: 0,
                finished: false,
            };
            let pid = managed.id();
            let rustix_pid = Pid::from_raw(i32::try_from(pid).map_err(string_error)?)
                .ok_or_else(|| "qualification launcher returned an invalid PID".to_owned())?;
            managed._pidfd =
                Some(pidfd_open(rustix_pid, PidfdFlags::empty()).map_err(string_error)?);
            managed.start_time_ticks = process_start_time_ticks(pid)?;
            prepare_cgroup(
                managed
                    .cgroup
                    .as_ref()
                    .ok_or_else(|| "qualification cgroup ownership was lost".to_owned())?,
                pid,
            )?;
            Ok(managed)
        }

        fn id(&self) -> u32 {
            self.child.id()
        }

        fn start_time_ticks(&self) -> u64 {
            self.start_time_ticks
        }

        fn child_mut(&mut self) -> &mut Child {
            &mut self.child
        }

        fn cgroup_sha256(&self) -> Result<String, String> {
            self.cgroup
                .as_ref()
                .ok_or_else(|| "qualification agent has no delegated cgroup".to_owned())?
                .commitment_sha256()
        }

        fn kill_and_reap(&mut self, deadline: Instant) -> Result<(), String> {
            if process_start_time_ticks(self.id())? != self.start_time_ticks {
                return Err("qualification agent identity changed before cgroup kill".into());
            }
            let cgroup = self
                .cgroup
                .as_ref()
                .ok_or_else(|| "qualification agent has no delegated cgroup".to_owned())?;
            kill_cgroup_and_reap(cgroup, &mut self.child, deadline, true)?;
            self.finished = true;
            Ok(())
        }

        fn kill_and_reap_for_restart(&mut self, deadline: Instant) -> Result<OwnedCgroup, String> {
            if process_start_time_ticks(self.id())? != self.start_time_ticks {
                return Err("qualification agent identity changed before restart kill".into());
            }
            let cgroup = self
                .cgroup
                .take()
                .ok_or_else(|| "qualification agent has no delegated cgroup".to_owned())?;
            kill_cgroup_and_reap(&cgroup, &mut self.child, deadline, false)?;
            self.finished = true;
            Ok(cgroup)
        }
    }

    impl Drop for ManagedAgent {
        fn drop(&mut self) {
            if self.finished {
                return;
            }
            if let Some(cgroup) = &self.cgroup {
                if cgroup.validate_identity().is_ok() {
                    let _ = fs::write(cgroup.path.join("cgroup.kill"), b"1");
                }
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    _ => {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        break;
                    }
                }
            }
            if let Some(cgroup) = &self.cgroup {
                if cgroup.validate_identity().is_ok() {
                    let _ = fs::remove_dir(&cgroup.path);
                }
            }
        }
    }

    fn run_phase(arguments: &[String]) -> Result<(), String> {
        let values = exact_flags(
            arguments,
            "run-phase",
            &[
                "--admin-socket",
                "--agent",
                "--agent-config",
                "--agent-gid",
                "--agent-launcher",
                "--agent-socket",
                "--agent-state-directory",
                "--agent-uid",
                "--cgroup",
                "--client-proxy-control-socket",
                "--credential-broker-checkpoint-socket",
                "--credential-broker-control-socket",
                "--credential-broker-socket",
                "--qualification-connection-store-template",
                "--decision-supervisor-socket",
                "--journal-reader-socket",
                "--launcher-ledger-plan",
                "--ledger-plan",
                "--phase-index",
                "--principal",
                "--profile-state-reader-socket",
                "--provider-proxy-socket",
                "--provider-proxy-checkpoint-socket",
                "--provider-proxy-control-socket",
                "--receipt-trust",
                "--receipt-verifier-socket",
                "--scenario",
                "--sequencer-socket",
                "--signer-socket",
                "--source-trust",
            ],
        )?;
        reject_unexpected_environment()?;
        let ledger_plan_path = Path::new(value(&values, "--ledger-plan")?);
        let launcher_ledger_plan_path = value(&values, "--launcher-ledger-plan")?;
        let plan_bytes = read_bounded(ledger_plan_path, MAX_TRUST_BYTES, true)?;
        let plan =
            QualificationEvidenceLedgerPlanV1::from_json(&plan_bytes).map_err(string_error)?;
        let common_root = common_root_for_ledger_plan(ledger_plan_path, &plan.provider_run_id)?;
        let trust_bytes = read_bounded(
            Path::new(value(&values, "--source-trust")?),
            MAX_TRUST_BYTES,
            false,
        )?;
        let trust = QualificationEvidenceSourceTrustRegistry::from_json(&trust_bytes)
            .map_err(string_error)?;
        let controller_uid = rustix::process::geteuid().as_raw();
        let controller_digest = hash_process_executable(std::process::id())?;
        if controller_uid != plan.supervisor_controller_uid
            || controller_digest != plan.supervisor_controller_artifact_sha256
            || trust.uses_process_uid(controller_uid)
            || controller_uid == plan.agent_uid
        {
            return Err(
                "ordinary phase controller differs from the immutable protected plan".into(),
            );
        }
        let scenario_id = value(&values, "--scenario")?;
        let phase_index = value(&values, "--phase-index")?
            .parse::<u8>()
            .map_err(string_error)?;
        let phase = plan
            .phases
            .iter()
            .find(|phase| phase.scenario_id == scenario_id && phase.phase_index == phase_index)
            .ok_or_else(|| "ordinary phase is absent from the immutable plan".to_owned())?;
        let crash_identity = phase
            .failpoint
            .map(|_| new_crash_control_identity(&plan, phase))
            .transpose()?;
        let agent_uid = value(&values, "--agent-uid")?
            .parse::<u32>()
            .map_err(string_error)?;
        let agent_gid = value(&values, "--agent-gid")?
            .parse::<u32>()
            .map_err(string_error)?;
        if agent_uid != plan.agent_uid
            || agent_gid != plan.agent_gid
            || agent_uid == controller_uid
            || agent_gid == rustix::process::getegid().as_raw()
            || env::var("AUTHS_QUALIFICATION_AGENT_UID").as_deref()
                != Ok(value(&values, "--agent-uid")?)
            || env::var("AUTHS_QUALIFICATION_AGENT_GID").as_deref()
                != Ok(value(&values, "--agent-gid")?)
        {
            return Err("ordinary phase agent identity differs from protected policy".into());
        }
        let agent_config_bytes = read_bounded(
            Path::new(value(&values, "--agent-config")?),
            4 * 1024 * 1024,
            false,
        )?;
        let agent_configuration_sha256 = hex::encode(Sha256::digest(&agent_config_bytes));
        if agent_configuration_sha256 != required_env("AUTHS_QUALIFICATION_AGENT_CONFIG_SHA256")? {
            return Err("ordinary phase agent config differs from protected policy".into());
        }
        let state_directory_path = Path::new(value(&values, "--agent-state-directory")?);
        let state_directory = open_protected_state_directory(state_directory_path, agent_uid)?;
        let state_metadata = state_directory.metadata().map_err(string_error)?;
        let state_sha256 = qualification_state_directory_commitment(
            path_string(state_directory_path)?,
            state_metadata.dev(),
            state_metadata.ino(),
            state_metadata.uid(),
            state_metadata.mode() & 0o777,
        )
        .map_err(string_error)?;
        if state_sha256 != required_env("AUTHS_QUALIFICATION_AGENT_STATE_DIRECTORY_SHA256")? {
            return Err("ordinary phase state directory differs from protected policy".into());
        }
        let journal_path_sha256 = hex::encode(Sha256::digest(
            path_string(&state_directory_path.join("operations.cbor"))?.as_bytes(),
        ));
        if journal_path_sha256 != required_env("AUTHS_QUALIFICATION_AGENT_JOURNAL_PATH_SHA256")? {
            return Err("ordinary phase journal path differs from protected policy".into());
        }
        let prior_profiles = plan
            .phases
            .iter()
            .filter(|candidate| {
                candidate.scenario_id == phase.scenario_id
                    && candidate.phase_index < phase.phase_index
            })
            .map(|candidate| candidate.profile.as_str())
            .collect::<BTreeSet<_>>();
        let (prior_record_sha256, prior_boundary_sha256) = if prior_profiles.is_empty() {
            match openat(
                &state_directory,
                "operations.cbor",
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            ) {
                Err(error) if error == rustix::io::Errno::NOENT => {}
                Ok(_) => return Err("first scenario phase state directory is not fresh".into()),
                Err(error) => return Err(string_error(error)),
            }
            (BTreeMap::new(), BTreeMap::new())
        } else {
            let mut prior =
                open_persisted_operation_snapshot_at_for_qualification(&state_directory, agent_uid)
                    .map_err(string_error)?;
            let records =
                read_persisted_operation_records_from_qualification_snapshot(&mut prior, agent_uid)
                    .map_err(string_error)?;
            let boundaries =
                read_persisted_qualification_boundaries_from_snapshot(&mut prior, agent_uid)
                    .map_err(string_error)?;
            let retained_profiles = records
                .iter()
                .map(|record| {
                    format!(
                        "{}/{}",
                        record.binding().profile().id(),
                        record.binding().profile().version()
                    )
                })
                .collect::<BTreeSet<_>>();
            if records.is_empty()
                || boundaries.is_empty()
                || prior_profiles
                    .iter()
                    .any(|profile| !retained_profiles.contains(*profile))
                || records.iter().any(|record| {
                    !prior_profiles.contains(
                        format!(
                            "{}/{}",
                            record.binding().profile().id(),
                            record.binding().profile().version()
                        )
                        .as_str(),
                    )
                })
                || boundaries.iter().any(|boundary| {
                    !prior_profiles.contains(
                        format!(
                            "{}/{}",
                            boundary.profile().id(),
                            boundary.profile().version()
                        )
                        .as_str(),
                    )
                })
            {
                return Err("retained scenario journal is not the exact prior-phase prefix".into());
            }
            let mut record_sha256 = BTreeMap::new();
            for record in &records {
                let bytes = serde_json_canonicalizer::to_vec(record).map_err(string_error)?;
                if record_sha256
                    .insert(
                        record.operation_id().as_str().to_owned(),
                        hex::encode(Sha256::digest(bytes)),
                    )
                    .is_some()
                {
                    return Err("retained scenario journal duplicates an operation".into());
                }
            }
            let mut boundary_sha256 = BTreeMap::new();
            for boundary in &boundaries {
                let bytes = serde_json_canonicalizer::to_vec(boundary).map_err(string_error)?;
                if boundary_sha256
                    .insert(boundary.ordinal(), hex::encode(Sha256::digest(bytes)))
                    .is_some()
                {
                    return Err("retained scenario journal duplicates a boundary ordinal".into());
                }
            }
            (record_sha256, boundary_sha256)
        };
        let now = now_unix_seconds()?;
        let (client_proxy_artifact, client_proxy_uid) =
            reader_process_binding(&trust, QualificationEvidenceSource::ClientProxy, &plan, now)?;
        let (credential_broker_artifact, credential_broker_uid) = reader_process_binding(
            &trust,
            QualificationEvidenceSource::CredentialBroker,
            &plan,
            now,
        )?;
        let (provider_proxy_artifact, provider_proxy_uid) = reader_process_binding(
            &trust,
            QualificationEvidenceSource::ProviderProxy,
            &plan,
            now,
        )?;
        if client_proxy_uid == agent_uid || client_proxy_uid == controller_uid {
            return Err("ordinary phase ClientProxy reader is not isolated".into());
        }
        if credential_broker_uid == agent_uid
            || credential_broker_uid == controller_uid
            || credential_broker_uid == client_proxy_uid
            || provider_proxy_uid == agent_uid
            || provider_proxy_uid == controller_uid
            || provider_proxy_uid == client_proxy_uid
            || provider_proxy_uid == credential_broker_uid
        {
            return Err("ordinary phase CredentialBroker reader is not isolated".into());
        }
        let agent_services = AgentServiceLaunchPolicy {
            client_proxy_reader_uid: client_proxy_uid,
            client_proxy_artifact_sha256: client_proxy_artifact,
            credential_broker_socket: value(&values, "--credential-broker-socket")?.to_owned(),
            credential_broker_reader_uid: credential_broker_uid,
            credential_broker_artifact_sha256: credential_broker_artifact,
            provider_proxy_socket: value(&values, "--provider-proxy-socket")?.to_owned(),
            provider_proxy_reader_uid: provider_proxy_uid,
            provider_proxy_artifact_sha256: provider_proxy_artifact,
            source_context_sha256: plan.source_context_sha256().map_err(string_error)?,
        };
        validate_client_bridge_socket_parent(
            Path::new(value(&values, "--agent-socket")?),
            agent_uid,
            agent_gid,
        )?;
        validate_shared_agent_socket_parent(
            Path::new(value(&values, "--credential-broker-socket")?),
            credential_broker_uid,
            agent_gid,
            "CredentialBroker",
        )?;
        validate_shared_agent_socket_parent(
            Path::new(value(&values, "--provider-proxy-socket")?),
            provider_proxy_uid,
            agent_gid,
            "ProviderProxy",
        )?;
        validate_shared_agent_socket_parent(
            Path::new(value(&values, "--provider-proxy-checkpoint-socket")?),
            provider_proxy_uid,
            agent_gid,
            "ProviderProxy checkpoint",
        )?;
        validate_shared_agent_socket_parent(
            Path::new(value(&values, "--provider-proxy-control-socket")?),
            provider_proxy_uid,
            agent_gid,
            "ProviderProxy control",
        )?;
        validate_shared_agent_socket_parent(
            Path::new(value(&values, "--client-proxy-control-socket")?),
            client_proxy_uid,
            agent_gid,
            "ClientProxy control",
        )?;
        validate_shared_agent_socket_parent(
            Path::new(value(&values, "--credential-broker-control-socket")?),
            credential_broker_uid,
            agent_gid,
            "CredentialBroker control",
        )?;
        validate_shared_agent_socket_parent(
            Path::new(value(&values, "--credential-broker-checkpoint-socket")?),
            credential_broker_uid,
            agent_gid,
            "CredentialBroker checkpoint",
        )?;
        let now = now_unix_seconds()?;
        let remaining = plan
            .deadline_at_unix_seconds
            .checked_sub(now)
            .filter(|seconds| *seconds != 0)
            .ok_or_else(|| {
                "ordinary phase started outside the protected run interval".to_owned()
            })?;
        let deadline = Instant::now() + Duration::from_secs(remaining);
        let launcher_sha256 = required_env("AUTHS_QUALIFICATION_AGENT_LAUNCHER_SHA256")?;
        let cgroup = Path::new(value(&values, "--cgroup")?);
        let crash_identity_ref = crash_identity
            .as_ref()
            .map(|(control, nonce)| (control.as_str(), nonce.as_str()));
        let launch_mode = phase
            .failpoint
            .map(|failpoint| AgentLaunchMode::crash(1, failpoint))
            .unwrap_or_else(|| AgentLaunchMode::ordinary(1));
        let source_checkpoint = match phase.failpoint {
            Some(QualificationFailpoint::AfterReread) => Some(connect_source_checkpoint(
                Path::new(value(&values, "--credential-broker-checkpoint-socket")?),
                QualificationEvidenceSource::CredentialBroker,
                SOURCE_CHECKPOINT_AFTER_REREAD,
                &trust,
                &plan,
                deadline,
            )?),
            Some(QualificationFailpoint::AfterLease) => Some(connect_source_checkpoint(
                Path::new(value(&values, "--credential-broker-checkpoint-socket")?),
                QualificationEvidenceSource::CredentialBroker,
                SOURCE_CHECKPOINT_AFTER_LEASE,
                &trust,
                &plan,
                deadline,
            )?),
            Some(QualificationFailpoint::AfterRequestWrite) => Some(connect_source_checkpoint(
                Path::new(value(&values, "--provider-proxy-checkpoint-socket")?),
                QualificationEvidenceSource::ProviderProxy,
                SOURCE_CHECKPOINT_AFTER_REQUEST_WRITE,
                &trust,
                &plan,
                deadline,
            )?),
            _ => None,
        };
        let provider_proxy_authorizer = ProviderProxyAuthorizer::start(
            Path::new(value(&values, "--provider-proxy-checkpoint-socket")?),
            &trust,
            &plan,
            state_directory.try_clone().map_err(string_error)?,
            deadline,
        )?;
        let mut agent = ManagedAgent::launch(
            &values,
            &AgentLaunchPolicy::phase(
                &plan,
                &launcher_sha256,
                launcher_ledger_plan_path,
                1,
                crash_identity_ref,
            ),
            &agent_services,
            cgroup,
            launch_mode,
        )?;
        let agent_process_id = agent.id();
        let agent_start_time_ticks = agent.start_time_ticks();
        if hash_process_executable(agent_process_id)? != launcher_sha256 {
            return Err("ordinary phase launcher differs from protected policy".into());
        }
        agent
            .child_mut()
            .stdin
            .as_mut()
            .ok_or_else(|| "qualification launcher has no release pipe".to_owned())?
            .write_all(b"AUTHS-QUALIFICATION-LAUNCH/1\n")
            .map_err(string_error)?;
        wait_for_agent_exec(
            agent.child_mut(),
            agent_process_id,
            agent_start_time_ticks,
            &plan.agent_executable_sha256,
            cgroup,
            agent_uid,
            agent_gid,
            deadline,
        )?;
        wait_for_agent_ready(
            agent.child_mut(),
            agent_process_id,
            agent_start_time_ticks,
            Path::new(value(&values, "--agent-socket")?),
            Path::new(value(&values, "--admin-socket")?),
            agent_uid,
            deadline,
        )?;

        let (_, _, signer_artifact, signer_uid) = trust
            .current_source_process_binding(
                QualificationEvidenceSource::Supervisor,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                now_unix_seconds()?,
            )
            .map_err(string_error)?;
        let signer_artifact_sha256 = signer_artifact.to_owned();
        let phase_plan = plan.clone();
        let mut phase_source = SupervisorPhaseSource {
            append: QualificationSourceAppendSession::new(
                QualificationEvidenceSource::Supervisor,
                plan.clone(),
                trust.clone(),
                PathBuf::from(value(&values, "--sequencer-socket")?),
            ),
            signer_socket: PathBuf::from(value(&values, "--signer-socket")?),
            signer_uid,
            signer_artifact_sha256,
            plan: phase_plan,
            trust: trust.clone(),
        };
        phase_source.append(
            scenario_id,
            phase_index,
            1,
            QualificationEvidenceEventKind::ScenarioStarted,
            deadline,
        )?;
        let agent_cgroup = agent
            .cgroup
            .as_ref()
            .ok_or_else(|| "ordinary qualification agent has no delegated cgroup".to_owned())?;
        let agent_cgroup_path = agent_cgroup.path.clone();
        let agent_cgroup_device = agent_cgroup.device;
        let agent_cgroup_inode = agent_cgroup.inode;
        let gate_output =
            agent.child_mut().stdout.take().ok_or_else(|| {
                "ordinary qualification agent has no journal gate output".to_owned()
            })?;
        let gate_release =
            agent.child_mut().stdin.take().ok_or_else(|| {
                "ordinary qualification agent has no journal gate release".to_owned()
            })?;
        rustix::fs::fcntl_setfl(&gate_output, OFlags::NONBLOCK).map_err(string_error)?;
        rustix::fs::fcntl_setfl(&gate_release, OFlags::NONBLOCK).map_err(string_error)?;
        let gate = OrdinaryJournalGate {
            policy: OrdinaryGatePolicy {
                plan: plan.clone(),
                phase: phase.clone(),
                trust: trust.clone(),
                state_directory: state_directory.try_clone().map_err(string_error)?,
                common_root: common_root.to_path_buf(),
                principal: value(&values, "--principal")?.to_owned(),
                receipt_trust: read_bounded(
                    Path::new(value(&values, "--receipt-trust")?),
                    MAX_RECEIPT_TRUST_BYTES,
                    false,
                )?,
                decision_supervisor_socket: PathBuf::from(value(
                    &values,
                    "--decision-supervisor-socket",
                )?),
                journal_reader_socket: PathBuf::from(value(&values, "--journal-reader-socket")?),
                profile_state_reader_socket: PathBuf::from(value(
                    &values,
                    "--profile-state-reader-socket",
                )?),
                controller_digest: controller_digest.clone(),
                agent_process_id,
                agent_generation: 1,
                crash_control_operation_id: crash_identity
                    .as_ref()
                    .map(|identity| identity.0.clone()),
                crash_controller_nonce_sha256: crash_identity
                    .as_ref()
                    .map(|identity| identity.1.clone()),
                agent_start_time_ticks,
                agent_launcher_artifact_sha256: launcher_sha256.clone(),
                agent_configuration_sha256: agent_configuration_sha256.clone(),
                agent_state_directory_sha256: state_sha256.clone(),
                agent_cgroup_sha256: agent.cgroup_sha256()?,
                agent_cgroup_path,
                agent_cgroup_device,
                agent_cgroup_inode,
                agent_boot_sha256: boot_sha256()?,
                journal_path_sha256,
                prior_record_sha256,
                prior_boundary_sha256,
            },
            decisions: BTreeMap::new(),
            boundary_processes: BTreeMap::new(),
            crash_delivered: false,
            journal_reader: None,
            profile_state_reader: None,
        };
        let ready = format!("AUTHS-QUALIFICATION-PHASE-READY/1 {scenario_id} {phase_index}\n");
        let mut output = std::io::stdout().lock();
        output.write_all(ready.as_bytes()).map_err(string_error)?;
        output.flush().map_err(string_error)?;
        let (completion, mut gate, held_gate_output, held_gate_release, mut source_checkpoint) =
            run_phase_gate(gate, gate_output, gate_release, source_checkpoint, deadline)?;
        if matches!(completion, PhaseCompletion::Completed)
            && pre_admission_rejection_scenario(&phase.scenario_id)
        {
            if !gate.decisions.is_empty() || !gate.drain(deadline)?.is_empty() {
                return Err(
                    "pre-admission rejection unexpectedly created durable journal state".into(),
                );
            }
        }
        if matches!(completion, PhaseCompletion::CrashReached) {
            let (control_operation_id, controller_nonce_sha256) = crash_identity
                .as_ref()
                .ok_or_else(|| "crash phase control identity is absent".to_owned())?;
            let crash_context = crash_context_from_ledger(
                &plan,
                phase,
                &trust,
                &launcher_sha256,
                control_operation_id,
                controller_nonce_sha256,
            )?;
            let (action_operation_id, connection_generation, durable_ack_sha256) =
                gate.crash_action_binding()?;
            let initial_process = gate.policy.crash_process_identity();
            let action_directory = common_root
                .join("ledger")
                .join(&plan.provider_run_id)
                .join("crash-action-contexts")
                .join(&action_operation_id);
            create_private_directory(&action_directory)?;
            let acknowledgement = QualificationCrashActionRecordV1 {
                schema: "auths.qualification-crash-action-record/1".into(),
                crash_context: crash_context.clone(),
                sequence: 1,
                previous_event_sha256: "0".repeat(64),
                profile: phase.profile.clone(),
                supervisor_controller_uid: controller_uid,
                supervisor_source_artifact_sha256: phase_source.signer_artifact_sha256.clone(),
                supervisor_controller_artifact_sha256: controller_digest.clone(),
                operation_id: (phase.failpoint != Some(QualificationFailpoint::BeforeDecision))
                    .then(|| action_operation_id.clone()),
                connection_generation: (phase.failpoint
                    != Some(QualificationFailpoint::BeforeDecision))
                .then(|| connection_generation.clone()),
                durable_ack_sha256: (phase.failpoint
                    != Some(QualificationFailpoint::BeforeDecision))
                .then(|| durable_ack_sha256.clone()),
                facts: QualificationCrashActionFactsV1::FailpointAcknowledged {
                    process: initial_process.clone(),
                    durable_ack_sha256: (phase.failpoint
                        != Some(QualificationFailpoint::BeforeDecision))
                    .then(|| durable_ack_sha256.clone()),
                    boundary_event_sha256: "0".repeat(64),
                },
            };
            let (acknowledgement_context, _) =
                phase_source.append_crash_action(acknowledgement, deadline)?;
            write_new(
                &action_directory.join("failpoint-acknowledged.json"),
                &acknowledgement_context,
            )?;
            let retained_cgroup = agent.kill_and_reap_for_restart(deadline)?;
            drop(held_gate_output);
            drop(held_gate_release);
            let killed = QualificationCrashActionRecordV1 {
                schema: "auths.qualification-crash-action-record/1".into(),
                crash_context: crash_context.clone(),
                sequence: 1,
                previous_event_sha256: "0".repeat(64),
                profile: phase.profile.clone(),
                supervisor_controller_uid: controller_uid,
                supervisor_source_artifact_sha256: phase_source.signer_artifact_sha256.clone(),
                supervisor_controller_artifact_sha256: controller_digest.clone(),
                operation_id: (phase.failpoint != Some(QualificationFailpoint::BeforeDecision))
                    .then(|| action_operation_id.clone()),
                connection_generation: (phase.failpoint
                    != Some(QualificationFailpoint::BeforeDecision))
                .then(|| connection_generation.clone()),
                durable_ack_sha256: (phase.failpoint
                    != Some(QualificationFailpoint::BeforeDecision))
                .then(|| durable_ack_sha256.clone()),
                facts: QualificationCrashActionFactsV1::ProcessKilled {
                    process: initial_process.clone(),
                    acknowledgement_event_sha256: "0".repeat(64),
                    signal: "SIGKILL".into(),
                    cgroup_empty_after_kill: true,
                },
            };
            let (killed_context, _) = phase_source.append_crash_action(killed, deadline)?;
            write_new(
                &action_directory.join("process-killed.json"),
                &killed_context,
            )?;
            if let Some(checkpoint) = source_checkpoint.as_mut() {
                checkpoint.peer.verify_unchanged()?;
                match checkpoint.disposition {
                    SourceCheckpointDisposition::AbortThenClean => {
                        write_source_session_frame_before(
                            &mut checkpoint.stream,
                            &[SOURCE_CHECKPOINT_ABORT],
                            deadline,
                        )?;
                        if read_source_session_frame_before(&mut checkpoint.stream, deadline)?
                            .as_deref()
                            != Some(&[SOURCE_CHECKPOINT_CLEAN])
                            || read_source_session_frame_before(&mut checkpoint.stream, deadline)?
                                .is_some()
                        {
                            return Err(
                                "source-owned crash checkpoint did not close cleanly".into()
                            );
                        }
                    }
                    SourceCheckpointDisposition::Continue => {
                        write_source_session_frame_before(
                            &mut checkpoint.stream,
                            &[SOURCE_CHECKPOINT_CLEAN],
                            deadline,
                        )?;
                        checkpoint
                            .stream
                            .shutdown(Shutdown::Write)
                            .map_err(string_error)?;
                    }
                }
                checkpoint.peer.verify_unchanged()?;
            }
            drop(source_checkpoint);
            let mut restarted = ManagedAgent::restart_in_cgroup(
                &values,
                &AgentLaunchPolicy::phase(
                    &plan,
                    &launcher_sha256,
                    launcher_ledger_plan_path,
                    2,
                    crash_identity_ref,
                ),
                &agent_services,
                retained_cgroup,
                AgentLaunchMode::restart(2, false, phase.failpoint),
            )?;
            let restarted_process_id = restarted.id();
            let restarted_start_time_ticks = restarted.start_time_ticks();
            restarted
                .child_mut()
                .stdin
                .as_mut()
                .ok_or_else(|| "qualification restart launcher has no release pipe".to_owned())?
                .write_all(b"AUTHS-QUALIFICATION-LAUNCH/1\n")
                .map_err(string_error)?;
            wait_for_agent_exec(
                restarted.child_mut(),
                restarted_process_id,
                restarted_start_time_ticks,
                &plan.agent_executable_sha256,
                cgroup,
                agent_uid,
                agent_gid,
                deadline,
            )?;
            wait_for_agent_ready(
                restarted.child_mut(),
                restarted_process_id,
                restarted_start_time_ticks,
                Path::new(value(&values, "--agent-socket")?),
                Path::new(value(&values, "--admin-socket")?),
                agent_uid,
                deadline,
            )?;
            let restarted_cgroup = restarted
                .cgroup
                .as_ref()
                .ok_or_else(|| "restarted agent has no delegated cgroup".to_owned())?;
            gate.policy.agent_generation = 2;
            gate.policy.agent_process_id = restarted_process_id;
            gate.policy.agent_start_time_ticks = restarted_start_time_ticks;
            gate.policy.agent_cgroup_sha256 = restarted.cgroup_sha256()?;
            gate.policy.agent_cgroup_path = restarted_cgroup.path.clone();
            gate.policy.agent_cgroup_device = restarted_cgroup.device;
            gate.policy.agent_cgroup_inode = restarted_cgroup.inode;
            gate.policy.agent_boot_sha256 = boot_sha256()?;
            let restarted_process = gate.policy.crash_process_identity();
            let restarted_record = QualificationCrashActionRecordV1 {
                schema: "auths.qualification-crash-action-record/1".into(),
                crash_context,
                sequence: 1,
                previous_event_sha256: "0".repeat(64),
                profile: phase.profile.clone(),
                supervisor_controller_uid: controller_uid,
                supervisor_source_artifact_sha256: phase_source.signer_artifact_sha256.clone(),
                supervisor_controller_artifact_sha256: controller_digest.clone(),
                operation_id: (phase.failpoint != Some(QualificationFailpoint::BeforeDecision))
                    .then_some(action_operation_id),
                connection_generation: (phase.failpoint
                    != Some(QualificationFailpoint::BeforeDecision))
                .then_some(connection_generation),
                durable_ack_sha256: (phase.failpoint
                    != Some(QualificationFailpoint::BeforeDecision))
                .then_some(durable_ack_sha256),
                facts: QualificationCrashActionFactsV1::ProcessRestarted {
                    killed_process: initial_process,
                    restarted_process,
                    kill_event_sha256: "0".repeat(64),
                    control_plane_ready: true,
                },
            };
            let (restarted_context, _) =
                phase_source.append_crash_action(restarted_record, deadline)?;
            write_new(
                &action_directory.join("process-restarted.json"),
                &restarted_context,
            )?;
            let restarted_output = restarted.child_mut().stdout.take().ok_or_else(|| {
                "restarted qualification agent has no journal gate output".to_owned()
            })?;
            let restarted_release = restarted.child_mut().stdin.take().ok_or_else(|| {
                "restarted qualification agent has no journal gate release".to_owned()
            })?;
            rustix::fs::fcntl_setfl(&restarted_output, OFlags::NONBLOCK).map_err(string_error)?;
            rustix::fs::fcntl_setfl(&restarted_release, OFlags::NONBLOCK).map_err(string_error)?;
            let (
                restart_completion,
                returned_gate,
                restarted_gate_output,
                restarted_gate_release,
                restarted_source_checkpoint,
            ) = run_phase_gate(gate, restarted_output, restarted_release, None, deadline)?;
            if restarted_source_checkpoint.is_some() {
                return Err("restart returned an unexpected source-owned checkpoint".into());
            }
            if !matches!(restart_completion, PhaseCompletion::Completed) {
                return Err("crash recovery reached the same checkpoint twice".into());
            }
            drop(restarted_gate_output);
            drop(restarted_gate_release);
            gate = returned_gate;
            agent = restarted;
        } else {
            drop(held_gate_output);
            drop(held_gate_release);
        }
        drop(gate);
        stop_phase_reader(
            Path::new(value(&values, "--client-proxy-control-socket")?),
            QualificationEvidenceSource::ClientProxy,
            &trust,
            &plan,
            deadline,
        )?;
        stop_phase_reader(
            Path::new(value(&values, "--credential-broker-control-socket")?),
            QualificationEvidenceSource::CredentialBroker,
            &trust,
            &plan,
            deadline,
        )?;
        provider_proxy_authorizer.stop()?;
        stop_phase_reader(
            Path::new(value(&values, "--provider-proxy-control-socket")?),
            QualificationEvidenceSource::ProviderProxy,
            &trust,
            &plan,
            deadline,
        )?;
        let mut receipt_snapshot =
            open_persisted_operation_snapshot_at_for_qualification(&state_directory, agent_uid)
                .map_err(string_error)?;
        let receipt_response = run_receipt_verifier(
            Path::new(value(&values, "--receipt-verifier-socket")?),
            &mut receipt_snapshot,
            &trust,
            &plan,
            deadline,
        )?;
        retain_receipt_verifier_response(common_root, &receipt_response)?;
        agent.kill_and_reap(deadline)?;
        let mut observer_snapshot =
            open_persisted_operation_snapshot_at_for_qualification(&state_directory, agent_uid)
                .map_err(string_error)?;
        let provider_observer_response = run_provider_observer(
            Path::new(value(&values, "--provider-observer-socket")?),
            &mut observer_snapshot,
            &trust,
            &plan,
            &phase.profile,
            deadline,
        )?;
        retain_provider_observer_response(common_root, &provider_observer_response)?;
        phase_source.append(
            scenario_id,
            phase_index,
            1,
            QualificationEvidenceEventKind::ScenarioCompleted,
            deadline,
        )?;
        Ok(())
    }

    struct OrdinaryGatePolicy {
        plan: QualificationEvidenceLedgerPlanV1,
        phase: auths_profile_kit::QualificationEvidencePhasePlanV1,
        trust: QualificationEvidenceSourceTrustRegistry,
        state_directory: File,
        common_root: PathBuf,
        principal: String,
        receipt_trust: Vec<u8>,
        decision_supervisor_socket: PathBuf,
        journal_reader_socket: PathBuf,
        profile_state_reader_socket: PathBuf,
        controller_digest: String,
        agent_process_id: u32,
        agent_generation: u32,
        crash_control_operation_id: Option<String>,
        crash_controller_nonce_sha256: Option<String>,
        agent_start_time_ticks: u64,
        agent_launcher_artifact_sha256: String,
        agent_configuration_sha256: String,
        agent_state_directory_sha256: String,
        agent_cgroup_sha256: String,
        agent_cgroup_path: PathBuf,
        agent_cgroup_device: u64,
        agent_cgroup_inode: u64,
        agent_boot_sha256: String,
        journal_path_sha256: String,
        prior_record_sha256: BTreeMap<String, String>,
        prior_boundary_sha256: BTreeMap<u32, String>,
    }

    impl OrdinaryGatePolicy {
        fn crash_process_identity(&self) -> QualificationCrashProcessIdentityV1 {
            QualificationCrashProcessIdentityV1 {
                agent_generation: self.agent_generation,
                agent_process_id: self.agent_process_id,
                agent_boot_sha256: self.agent_boot_sha256.clone(),
                agent_start_time_ticks: self.agent_start_time_ticks,
                agent_launcher_artifact_sha256: self.agent_launcher_artifact_sha256.clone(),
                agent_executable_sha256: self.plan.agent_executable_sha256.clone(),
                agent_configuration_sha256: self.agent_configuration_sha256.clone(),
                agent_state_directory_sha256: self.agent_state_directory_sha256.clone(),
                agent_cgroup_sha256: self.agent_cgroup_sha256.clone(),
            }
        }

        fn verify_agent_unchanged(&self) -> Result<(), String> {
            if process_start_time_ticks(self.agent_process_id)? != self.agent_start_time_ticks
                || hash_process_executable(self.agent_process_id)?
                    != self.plan.agent_executable_sha256
            {
                return Err("ordinary qualification agent process identity changed".into());
            }
            validate_agent_process_credentials(
                self.agent_process_id,
                self.plan.agent_uid,
                self.plan.agent_gid,
            )?;
            let cgroup = fs::symlink_metadata(&self.agent_cgroup_path).map_err(string_error)?;
            if !cgroup.file_type().is_dir()
                || cgroup.dev() != self.agent_cgroup_device
                || cgroup.ino() != self.agent_cgroup_inode
            {
                return Err("ordinary qualification agent cgroup identity changed".into());
            }
            let membership = fs::read_to_string(format!("/proc/{}/cgroup", self.agent_process_id))
                .map_err(string_error)?;
            if membership.trim() != expected_cgroup_membership(&self.agent_cgroup_path)? {
                return Err("ordinary qualification agent escaped its delegated cgroup".into());
            }
            Ok(())
        }

        fn verify_prior_journal_prefix(&self, snapshot: &mut File) -> Result<(), String> {
            let records = read_persisted_operation_records_from_qualification_snapshot(
                snapshot,
                self.plan.agent_uid,
            )
            .map_err(string_error)?;
            let mut retained_records = BTreeMap::new();
            let mut current_operations = BTreeSet::new();
            for record in records {
                if let Some(expected) = self.prior_record_sha256.get(record.operation_id().as_str())
                {
                    let bytes = serde_json_canonicalizer::to_vec(&record).map_err(string_error)?;
                    let actual = hex::encode(Sha256::digest(bytes));
                    if &actual != expected
                        || retained_records
                            .insert(record.operation_id().as_str().to_owned(), actual)
                            .is_some()
                    {
                        return Err("retained prior-phase operation record changed".into());
                    }
                } else {
                    let profile = format!(
                        "{}/{}",
                        record.binding().profile().id(),
                        record.binding().profile().version()
                    );
                    if profile != self.phase.profile
                        || !current_operations.insert(record.operation_id().as_str().to_owned())
                    {
                        return Err(
                            "journal contains an operation outside the exact current phase".into(),
                        );
                    }
                }
            }
            if retained_records != self.prior_record_sha256 {
                return Err("retained prior-phase operation roster changed".into());
            }
            let boundaries = read_persisted_qualification_boundaries_from_snapshot(
                snapshot,
                self.plan.agent_uid,
            )
            .map_err(string_error)?;
            let mut retained_boundaries = BTreeMap::new();
            for boundary in boundaries {
                if let Some(expected) = self.prior_boundary_sha256.get(&boundary.ordinal()) {
                    let bytes =
                        serde_json_canonicalizer::to_vec(&boundary).map_err(string_error)?;
                    let actual = hex::encode(Sha256::digest(bytes));
                    if &actual != expected
                        || retained_boundaries
                            .insert(boundary.ordinal(), actual)
                            .is_some()
                    {
                        return Err("retained prior-phase journal boundary changed".into());
                    }
                } else if self
                    .prior_record_sha256
                    .contains_key(boundary.operation_id().as_str())
                    || !current_operations.contains(boundary.operation_id().as_str())
                    || format!(
                        "{}/{}",
                        boundary.profile().id(),
                        boundary.profile().version()
                    ) != self.phase.profile
                {
                    return Err(
                        "journal contains a boundary outside the exact current phase".into(),
                    );
                }
            }
            if retained_boundaries != self.prior_boundary_sha256 {
                return Err("retained prior-phase boundary roster changed".into());
            }
            Ok(())
        }
    }

    struct OrdinaryJournalGate {
        policy: OrdinaryGatePolicy,
        decisions: BTreeMap<String, QualificationJournalBoundaryDecisionV1>,
        boundary_processes: BTreeMap<u32, QualificationJournalBoundaryProcessV1>,
        crash_delivered: bool,
        journal_reader: Option<(UnixStream, QualificationSourceSessionPeer)>,
        profile_state_reader: Option<(UnixStream, QualificationSourceSessionPeer)>,
    }

    impl OrdinaryJournalGate {
        fn crash_action_binding(&self) -> Result<(String, String, String), String> {
            if self.policy.phase.failpoint == Some(QualificationFailpoint::BeforeDecision) {
                return Ok((
                    self.policy
                        .crash_control_operation_id
                        .clone()
                        .ok_or_else(|| "crash control operation is absent".to_owned())?,
                    "0".into(),
                    "0".repeat(64),
                ));
            }
            if self.decisions.len() != 1 {
                return Err("crash phase does not have exactly one durable decision".into());
            }
            let decision = self
                .decisions
                .values()
                .next()
                .ok_or_else(|| "crash phase decision is absent".to_owned())?;
            let snapshot_bytes =
                Base64UrlUnpadded::decode_vec(&decision.decision_snapshot_base64url)
                    .map_err(string_error)?;
            let snapshot = QualificationDecisionSnapshotV1::from_json(&snapshot_bytes)
                .map_err(string_error)?;
            let ack = Base64UrlUnpadded::decode_vec(&decision.durable_ack_base64url)
                .map_err(string_error)?;
            Ok((
                decision.operation_id.clone(),
                snapshot.connection_generation,
                hex::encode(Sha256::digest(ack)),
            ))
        }
    }

    enum PhaseGateSignal {
        CrashReached,
    }

    enum PhaseCompletion {
        Completed,
        CrashReached,
    }

    struct SourceCheckpointWait {
        stream: UnixStream,
        peer: QualificationSourceSessionPeer,
        expected_code: u8,
        response: Vec<u8>,
        disposition: SourceCheckpointDisposition,
    }

    struct ProviderProxyAuthorizer {
        shutdown: UnixStream,
        worker: Option<thread::JoinHandle<Result<(), String>>>,
    }

    impl ProviderProxyAuthorizer {
        fn start(
            socket: &Path,
            trust: &QualificationEvidenceSourceTrustRegistry,
            plan: &QualificationEvidenceLedgerPlanV1,
            state_directory: File,
            deadline: Instant,
        ) -> Result<Self, String> {
            let mut stream = connect_before(socket, deadline, "ProviderProxy authorization")?;
            let peer = QualificationSourceSessionPeer::observe(&stream)?;
            let (reader_artifact, reader_uid) = reader_process_binding(
                trust,
                QualificationEvidenceSource::ProviderProxy,
                plan,
                now_unix_seconds()?,
            )?;
            if peer.uid() != reader_uid || peer.executable_sha256() != reader_artifact {
                return Err("ProviderProxy authorizer differs from source trust".into());
            }
            write_source_session_frame_before(
                &mut stream,
                &[
                    SOURCE_CHECKPOINT_ENROLLMENT_VERSION,
                    SOURCE_CHECKPOINT_PROVIDER_AUTHORIZATION,
                ],
                deadline,
            )?;
            peer.verify_unchanged()?;
            let shutdown = stream.try_clone().map_err(string_error)?;
            let agent_uid = plan.agent_uid;
            let worker = thread::spawn(move || {
                loop {
                    let Some(request) = read_source_session_frame_before(&mut stream, deadline)?
                    else {
                        return Ok(());
                    };
                    let Some(operation_id) =
                        request.strip_prefix(b"AUTHS-QUALIFICATION-PROVIDER-AUTHORIZATION/1\0")
                    else {
                        return Err("ProviderProxy authorization request is malformed".into());
                    };
                    let operation_id = std::str::from_utf8(operation_id).map_err(string_error)?;
                    if !matches!(
                        auths_lifecycle::OperationIdV1::parse(operation_id),
                        Ok(value) if value.as_str() == operation_id
                    ) {
                        return Err("ProviderProxy authorization operation is malformed".into());
                    }
                    peer.verify_unchanged()?;
                    let mut snapshot = open_persisted_operation_snapshot_at_for_qualification(
                        &state_directory,
                        agent_uid,
                    )
                    .map_err(string_error)?;
                    send_provider_authorization_snapshot(&mut stream, &mut snapshot)?;
                }
            });
            Ok(Self {
                shutdown,
                worker: Some(worker),
            })
        }

        fn stop(mut self) -> Result<(), String> {
            let _ = self.shutdown.shutdown(Shutdown::Both);
            self.worker
                .take()
                .ok_or_else(|| "ProviderProxy authorizer worker is absent".to_owned())?
                .join()
                .map_err(|_| "ProviderProxy authorizer panicked".to_owned())?
        }
    }

    impl Drop for ProviderProxyAuthorizer {
        fn drop(&mut self) {
            let _ = self.shutdown.shutdown(Shutdown::Both);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn send_provider_authorization_snapshot(
        stream: &mut UnixStream,
        snapshot: &mut File,
    ) -> Result<(), String> {
        snapshot.seek(SeekFrom::Start(0)).map_err(string_error)?;
        let descriptors = [snapshot.as_fd()];
        let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut ancillary_space);
        if !ancillary.push(rustix::net::SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err("ProviderProxy authorization snapshot could not be framed".into());
        }
        const RESPONSE: &[u8] = b"AUTHS-QUALIFICATION-PROVIDER-AUTHORIZED/1";
        let mut frame = Vec::with_capacity(4 + RESPONSE.len());
        frame.extend_from_slice(
            &u32::try_from(RESPONSE.len())
                .map_err(string_error)?
                .to_be_bytes(),
        );
        frame.extend_from_slice(RESPONSE);
        let sent = rustix::net::sendmsg(
            &*stream,
            &[IoSlice::new(&frame)],
            &mut ancillary,
            rustix::net::SendFlags::empty(),
        )
        .map_err(string_error)?;
        if sent == 0 || sent > frame.len() {
            return Err("ProviderProxy authorization snapshot transfer was ambiguous".into());
        }
        stream.write_all(&frame[sent..]).map_err(string_error)
    }

    #[derive(Clone, Copy)]
    enum SourceCheckpointDisposition {
        AbortThenClean,
        Continue,
    }

    impl SourceCheckpointWait {
        fn poll(&mut self) -> Result<bool, String> {
            let mut buffer = [0_u8; 16];
            loop {
                match self.stream.read(&mut buffer) {
                    Ok(0) => {
                        return Err(
                            "source-owned checkpoint closed before its durable boundary".into()
                        );
                    }
                    Ok(length) => {
                        self.response.extend_from_slice(&buffer[..length]);
                        if self.response.len() >= 4 {
                            let length = usize::try_from(u32::from_be_bytes(
                                self.response[..4]
                                    .try_into()
                                    .map_err(|_| "source checkpoint header is malformed")?,
                            ))
                            .map_err(string_error)?;
                            if length != 1 || self.response.len() > 4 + length {
                                return Err("source-owned checkpoint frame is malformed".into());
                            }
                            if self.response.len() == 4 + length {
                                if self.response[4] != self.expected_code {
                                    return Err(
                                        "source-owned checkpoint differs from the immutable phase"
                                            .into(),
                                    );
                                }
                                self.peer.verify_unchanged()?;
                                return Ok(true);
                            }
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        return Ok(false);
                    }
                    Err(error) => return Err(string_error(error)),
                }
            }
        }
    }

    fn phase_crash_boundary_reached(
        failpoint: Option<QualificationFailpoint>,
        decision_frame: bool,
        boundaries: &[QualificationJournalBoundaryKindV1],
    ) -> bool {
        let contains = |kind| boundaries.contains(&kind);
        match failpoint {
            Some(QualificationFailpoint::AfterDecision) => decision_frame,
            Some(QualificationFailpoint::AfterCommand) => {
                contains(QualificationJournalBoundaryKindV1::Command)
            }
            Some(QualificationFailpoint::AfterEntryMarker) => {
                contains(QualificationJournalBoundaryKindV1::ProviderEntry)
            }
            Some(QualificationFailpoint::AfterProviderResult) => {
                contains(QualificationJournalBoundaryKindV1::ProviderResult)
            }
            Some(QualificationFailpoint::AfterObservation) => {
                contains(QualificationJournalBoundaryKindV1::Observation)
            }
            Some(QualificationFailpoint::AfterExecutionReceipt) => {
                contains(QualificationJournalBoundaryKindV1::ExecutionReceipt)
            }
            Some(QualificationFailpoint::AfterTerminal) => {
                contains(QualificationJournalBoundaryKindV1::Terminal)
            }
            Some(
                QualificationFailpoint::BeforeDecision
                | QualificationFailpoint::AfterReservation
                | QualificationFailpoint::AfterReread
                | QualificationFailpoint::AfterLease
                | QualificationFailpoint::AfterRequestWrite,
            )
            | None => false,
        }
    }

    fn pre_admission_rejection_scenario(scenario_id: &str) -> bool {
        qualification_pre_admission_attempt_count(scenario_id).is_some()
    }

    impl OrdinaryJournalGate {
        fn run<O: Read, W: Write>(
            mut self,
            mut output: O,
            mut release: W,
            stop: &AtomicBool,
            signals: &mpsc::Sender<PhaseGateSignal>,
            deadline: Instant,
        ) -> Result<(Self, O, W), String> {
            loop {
                let Some(frame) =
                    read_gate_frame_until(&mut output, MAX_ACK_BYTES, stop, deadline)?
                else {
                    break;
                };
                if frame == BEFORE_DECISION_CHECKPOINT {
                    if self.policy.phase.failpoint != Some(QualificationFailpoint::BeforeDecision) {
                        return Err("pre-decision checkpoint is outside the immutable phase".into());
                    }
                    self.policy.verify_agent_unchanged()?;
                    if !self.crash_delivered {
                        self.crash_delivered = true;
                        signals
                            .send(PhaseGateSignal::CrashReached)
                            .map_err(string_error)?;
                        return Ok((self, output, release));
                    }
                    write_gate_frame_before(&mut release, &[1], deadline)?;
                    continue;
                }
                if frame == AFTER_RESERVATION_CHECKPOINT {
                    if self.policy.phase.failpoint != Some(QualificationFailpoint::AfterReservation)
                    {
                        return Err("reservation checkpoint is outside the immutable phase".into());
                    }
                    self.policy.verify_agent_unchanged()?;
                    let mut snapshot = open_persisted_operation_snapshot_at_for_qualification(
                        &self.policy.state_directory,
                        self.policy.plan.agent_uid,
                    )
                    .map_err(string_error)?;
                    self.policy.verify_prior_journal_prefix(&mut snapshot)?;
                    self.drain_profile_state(&mut snapshot, true, deadline)?;
                    self.policy.verify_agent_unchanged()?;
                    if !self.crash_delivered {
                        self.crash_delivered = true;
                        signals
                            .send(PhaseGateSignal::CrashReached)
                            .map_err(string_error)?;
                        return Ok((self, output, release));
                    }
                    write_gate_frame_before(&mut release, &[1], deadline)?;
                    continue;
                }
                let decision = frame != b"AUTHS-QUALIFICATION-JOURNAL-FLUSH/1";
                let boundary_kinds = if !decision {
                    self.drain(deadline)?
                } else {
                    self.record_decision(&frame, deadline)?;
                    self.drain(deadline)?
                };
                self.policy.verify_agent_unchanged()?;
                if !self.crash_delivered
                    && phase_crash_boundary_reached(
                        self.policy.phase.failpoint,
                        decision,
                        &boundary_kinds,
                    )
                {
                    self.crash_delivered = true;
                    signals
                        .send(PhaseGateSignal::CrashReached)
                        .map_err(string_error)?;
                    return Ok((self, output, release));
                }
                write_gate_frame_before(&mut release, &[1], deadline)?;
            }
            if let Some((mut reader, peer)) = self.journal_reader.take() {
                reader.shutdown(Shutdown::Write).map_err(string_error)?;
                if read_bounded_session_frame_before(&mut reader, 2_097_152, deadline)?.is_some() {
                    return Err("JournalReader sent data after the final drain".into());
                }
                peer.verify_unchanged()?;
            }
            close_profile_state_reader(&mut self.profile_state_reader, deadline)?;
            Ok((self, output, release))
        }

        #[allow(clippy::too_many_lines)]
        fn record_decision(&mut self, ack_bytes: &[u8], deadline: Instant) -> Result<(), String> {
            self.policy.verify_agent_unchanged()?;
            let ack =
                QualificationDurableDecisionAckV1::from_json(ack_bytes).map_err(string_error)?;
            if ack.agent_generation != self.policy.agent_generation
                || ack.control_operation_id != self.policy.crash_control_operation_id
                || ack.controller_nonce_sha256 != self.policy.crash_controller_nonce_sha256
            {
                return Err(
                    "durable acknowledgement differs from protected phase authority".into(),
                );
            }
            let operation = auths_lifecycle::OperationIdV1::parse(&ack.operation_id)
                .map_err(|_| "ordinary decision operation ID is malformed".to_owned())?;
            let mut snapshot = open_persisted_operation_snapshot_at_for_qualification(
                &self.policy.state_directory,
                self.policy.plan.agent_uid,
            )
            .map_err(string_error)?;
            self.policy.verify_prior_journal_prefix(&mut snapshot)?;
            let boundaries = read_persisted_qualification_boundaries_from_snapshot(
                &mut snapshot,
                self.policy.plan.agent_uid,
            )
            .map_err(string_error)?
            .into_iter()
            .filter(|boundary| {
                format!(
                    "{}/{}",
                    boundary.profile().id(),
                    boundary.profile().version()
                ) == self.policy.phase.profile
            })
            .collect::<Vec<_>>();
            let allow_empty = pre_admission_rejection_scenario(&self.policy.phase.scenario_id);
            if boundaries.is_empty() && !allow_empty {
                return Err("journal has no durable boundaries for the exact phase".into());
            }
            let mut decision_rows = boundaries.iter().filter(|boundary| {
                boundary.operation_id() == &operation
                    && boundary.kind() == QualificationJournalBoundaryKindV1::Decision
            });
            let decision_boundary = decision_rows
                .next()
                .ok_or_else(|| "ordinary decision boundary is absent".to_owned())?;
            if decision_rows.next().is_some() {
                return Err("ordinary decision boundary is duplicated".into());
            }
            let record = read_persisted_operation_record_from_qualification_snapshot(
                &mut snapshot,
                self.policy.plan.agent_uid,
                &self.policy.principal,
                &operation,
            )
            .map_err(string_error)?;
            let record_bytes = serde_json_canonicalizer::to_vec(&record).map_err(string_error)?;
            if record.revision() != 1
                || hex::encode(Sha256::digest(&record_bytes)) != ack.journal_record_sha256
            {
                return Err(
                    "ordinary acknowledgement differs from the revision-one journal".into(),
                );
            }
            let decision_snapshot = derive_qualification_decision_snapshot(
                &record,
                &self.policy.principal,
                &self.policy.receipt_trust,
                &self.policy.plan.recovery_key_id,
                &self.policy.plan.recovery_public_key_base64url,
                now_unix_seconds()?,
            )?;
            if decision_snapshot.profile != self.policy.phase.profile {
                return Err("ordinary decision profile differs from the exact phase".into());
            }
            let decision_snapshot_bytes = decision_snapshot.to_json().map_err(string_error)?;
            let journal = snapshot.metadata().map_err(string_error)?;
            let (_, supervisor_identity, supervisor_artifact, supervisor_uid) = self
                .policy
                .trust
                .current_source_process_binding(
                    QualificationEvidenceSource::Supervisor,
                    &self.policy.plan.domain,
                    self.policy.plan.started_at_unix_seconds,
                    self.policy.plan.deadline_at_unix_seconds,
                    now_unix_seconds()?,
                )
                .map_err(string_error)?;
            let (journal_key, journal_identity, journal_artifact, journal_uid) = self
                .policy
                .trust
                .current_source_process_binding(
                    QualificationEvidenceSource::JournalReader,
                    &self.policy.plan.domain,
                    self.policy.plan.started_at_unix_seconds,
                    self.policy.plan.deadline_at_unix_seconds,
                    now_unix_seconds()?,
                )
                .map_err(string_error)?;
            let context = QualificationJournalDecisionContextRecord {
                schema: "auths.qualification-journal-decision-context-record/1".into(),
                repository_id: self.policy.plan.repository_id.clone(),
                workflow_path: self.policy.plan.workflow_path.clone(),
                workflow_revision: self.policy.plan.workflow_revision.clone(),
                candidate_revision: self.policy.plan.candidate_revision.clone(),
                attester_revision: self.policy.plan.attester_revision.clone(),
                run_id: self.policy.plan.run_id.clone(),
                run_attempt: self.policy.plan.run_attempt,
                domain: self.policy.plan.domain.clone(),
                target: self.policy.plan.target,
                protected_environment: self.policy.plan.protected_environment.clone(),
                provider_run_id: self.policy.plan.provider_run_id.clone(),
                ledger_id: self.policy.plan.ledger_id.clone(),
                session_nonce_sha256: self.policy.plan.session_nonce_sha256.clone(),
                scenario_id: self.policy.phase.scenario_id.clone(),
                phase_index: self.policy.phase.phase_index,
                role: self.policy.phase.role,
                profile: self.policy.phase.profile.clone(),
                operation_plan_sha256: self.policy.phase.operation_plan_sha256.clone(),
                scenario_program_sha256: self.policy.phase.scenario_program_sha256.clone(),
                failpoint: self.policy.phase.failpoint,
                supervisor_controller_uid: self.policy.plan.supervisor_controller_uid,
                supervisor_source_uid: supervisor_uid,
                journal_reader_uid: journal_uid,
                agent_uid: self.policy.plan.agent_uid,
                agent_gid: self.policy.plan.agent_gid,
                supervisor_source_identity: supervisor_identity.to_owned(),
                supervisor_source_artifact_sha256: supervisor_artifact.to_owned(),
                supervisor_controller_artifact_sha256: self.policy.controller_digest.clone(),
                journal_reader_source_identity: journal_identity.to_owned(),
                journal_reader_source_artifact_sha256: journal_artifact.to_owned(),
                journal_reader_key_id: journal_key.to_owned(),
                source_context_sha256: self
                    .policy
                    .plan
                    .source_context_sha256()
                    .map_err(string_error)?,
                supervisor_generation: 1,
                agent_generation: self.policy.agent_generation,
                agent_process_id: self.policy.agent_process_id,
                agent_boot_sha256: self.policy.agent_boot_sha256.clone(),
                agent_start_time_ticks: self.policy.agent_start_time_ticks,
                agent_launcher_artifact_sha256: self.policy.agent_launcher_artifact_sha256.clone(),
                agent_executable_sha256: self.policy.plan.agent_executable_sha256.clone(),
                agent_configuration_sha256: self.policy.agent_configuration_sha256.clone(),
                agent_state_directory_sha256: self.policy.agent_state_directory_sha256.clone(),
                agent_cgroup_sha256: self.policy.agent_cgroup_sha256.clone(),
                journal_path_sha256: self.policy.journal_path_sha256.clone(),
                journal_device: journal.dev(),
                journal_inode: journal.ino(),
                journal_owner_uid: journal.uid(),
                journal_mode: journal.mode() & 0o777,
                journal_length: journal.len(),
                boundary_ordinal: decision_boundary.ordinal(),
                boundary_projection_sha256: hex::encode(decision_boundary.projection_sha256()),
                operation_id: ack.operation_id.clone(),
                control_operation_id: self.policy.crash_control_operation_id.clone(),
                controller_nonce_sha256: self.policy.crash_controller_nonce_sha256.clone(),
                journal_revision: 1,
                journal_record_sha256: ack.journal_record_sha256.clone(),
                decision_snapshot_sha256: hex::encode(Sha256::digest(&decision_snapshot_bytes)),
                durable_ack_sha256: hex::encode(Sha256::digest(ack_bytes)),
            };
            let context_request =
                serde_json_canonicalizer::to_vec(&context).map_err(string_error)?;
            let context_bytes = loop {
                match send_ordinary_context_to_supervisor(
                    &self.policy.decision_supervisor_socket,
                    &context_request,
                    &self.policy.trust,
                    supervisor_artifact,
                    supervisor_uid,
                    deadline,
                ) {
                    Ok(bytes) => break bytes,
                    Err(SourceRequestError::Fatal(error)) => return Err(error),
                    Err(SourceRequestError::Ambiguous(error)) => {
                        if Instant::now() >= deadline {
                            return Err(error);
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            };
            let signed = QualificationJournalDecisionContext::verify_json(
                &context_bytes,
                &self.policy.trust,
                self.policy.plan.started_at_unix_seconds,
                self.policy.plan.deadline_at_unix_seconds,
                now_unix_seconds()?,
            )
            .map_err(string_error)?;
            if signed.record() != &context {
                return Err("ordinary Supervisor returned a different decision context".into());
            }
            let material = QualificationJournalBoundaryDecisionV1 {
                operation_id: ack.operation_id.clone(),
                supervisor_context_base64url: Base64UrlUnpadded::encode_string(&context_bytes),
                decision_snapshot_base64url: Base64UrlUnpadded::encode_string(
                    &decision_snapshot_bytes,
                ),
                durable_ack_base64url: Base64UrlUnpadded::encode_string(ack_bytes),
            };
            if self
                .decisions
                .insert(ack.operation_id.clone(), material.clone())
                .is_some_and(|prior| prior != material)
            {
                return Err("ordinary decision retry changed retained evidence".into());
            }
            let ledger = self
                .policy
                .common_root
                .join("ledger")
                .join(&self.policy.plan.provider_run_id);
            write_new(
                &ledger
                    .join("supervisor-contexts")
                    .join(format!("{}.json", ack.operation_id)),
                &context_bytes,
            )?;
            write_new(
                &ledger
                    .join("decision-snapshots")
                    .join(format!("{}.json", ack.operation_id)),
                &decision_snapshot_bytes,
            )?;
            write_new(
                &ledger
                    .join("durable-acks")
                    .join(format!("{}.json", ack.operation_id)),
                ack_bytes,
            )
        }

        fn drain(
            &mut self,
            deadline: Instant,
        ) -> Result<Vec<QualificationJournalBoundaryKindV1>, String> {
            self.policy.verify_agent_unchanged()?;
            let mut snapshot = open_persisted_operation_snapshot_at_for_qualification(
                &self.policy.state_directory,
                self.policy.plan.agent_uid,
            )
            .map_err(string_error)?;
            self.policy.verify_prior_journal_prefix(&mut snapshot)?;
            self.drain_profile_state(&mut snapshot, false, deadline)?;
            let boundaries = read_persisted_qualification_boundaries_from_snapshot(
                &mut snapshot,
                self.policy.plan.agent_uid,
            )
            .map_err(string_error)?
            .into_iter()
            .filter(|boundary| {
                format!(
                    "{}/{}",
                    boundary.profile().id(),
                    boundary.profile().version()
                ) == self.policy.phase.profile
            })
            .collect::<Vec<_>>();
            if boundaries.is_empty() {
                return Err("journal has no durable boundaries for the exact phase".into());
            }
            let boundary_kinds = boundaries
                .iter()
                .map(|boundary| boundary.kind())
                .collect::<Vec<_>>();
            for boundary in &boundaries {
                self.boundary_processes
                    .entry(boundary.ordinal())
                    .or_insert_with(|| QualificationJournalBoundaryProcessV1 {
                        ordinal: boundary.ordinal(),
                        agent_generation: self.policy.agent_generation,
                        agent_process_id: self.policy.agent_process_id,
                        agent_boot_sha256: self.policy.agent_boot_sha256.clone(),
                    });
            }
            if self.boundary_processes.len() != boundaries.len()
                || self
                    .boundary_processes
                    .keys()
                    .zip(boundaries.iter().map(|boundary| boundary.ordinal()))
                    .any(|(retained, ordinal)| *retained != ordinal)
            {
                return Err("journal boundary process roster changed across drains".into());
            }
            let request = QualificationJournalBoundaryDrainRequestV1 {
                schema: "auths.qualification-journal-boundary-drain-request/1".into(),
                journal_owner_uid: self.policy.plan.agent_uid,
                principal: self.policy.principal.clone(),
                decisions: self.decisions.values().cloned().collect(),
                processes: self.boundary_processes.values().cloned().collect(),
            }
            .to_json()?;
            loop {
                if self.journal_reader.is_none() {
                    let stream = connect_before(
                        &self.policy.journal_reader_socket,
                        deadline,
                        "JournalReader boundary service",
                    )?;
                    stream.set_nonblocking(true).map_err(string_error)?;
                    let peer = QualificationSourceSessionPeer::observe(&stream)?;
                    let (_, _, artifact, uid) = self
                        .policy
                        .trust
                        .current_source_process_binding(
                            QualificationEvidenceSource::JournalReader,
                            &self.policy.plan.domain,
                            self.policy.plan.started_at_unix_seconds,
                            self.policy.plan.deadline_at_unix_seconds,
                            now_unix_seconds()?,
                        )
                        .map_err(string_error)?;
                    if peer.uid() != uid || peer.executable_sha256() != artifact {
                        return Err(
                            "JournalReader boundary service differs from source trust".into()
                        );
                    }
                    self.journal_reader = Some((stream, peer));
                }
                let attempt = (|| -> Result<(), SourceRequestError> {
                    let (stream, peer) = self.journal_reader.as_mut().ok_or_else(|| {
                        SourceRequestError::Fatal(
                            "JournalReader boundary service is absent".to_owned(),
                        )
                    })?;
                    peer.verify_unchanged().map_err(SourceRequestError::Fatal)?;
                    snapshot
                        .seek(SeekFrom::Start(0))
                        .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
                    send_framed_snapshot(stream, &request, &snapshot, deadline)
                        .map_err(SourceRequestError::Ambiguous)?;
                    let response = read_journal_drain_response_before(stream, 2_097_152, deadline)?;
                    peer.verify_unchanged().map_err(SourceRequestError::Fatal)?;
                    let response =
                        QualificationJournalBoundaryDrainResponseV1::from_json(&response)
                            .map_err(SourceRequestError::Fatal)?;
                    if response.events.len() != boundaries.len()
                        || response
                            .events
                            .iter()
                            .zip(&boundaries)
                            .any(|(event, boundary)| {
                                event.ordinal != boundary.ordinal()
                                    || event.operation_id != boundary.operation_id().as_str()
                            })
                    {
                        return Err(SourceRequestError::Fatal(
                            "JournalReader response differs from the durable boundary roster"
                                .into(),
                        ));
                    }
                    self.policy
                        .verify_agent_unchanged()
                        .map_err(SourceRequestError::Fatal)?;
                    write_source_session_frame_before(stream, &[1], deadline)
                        .map_err(SourceRequestError::Ambiguous)
                })();
                match attempt {
                    Ok(()) => return Ok(boundary_kinds),
                    Err(SourceRequestError::Fatal(error)) => return Err(error),
                    Err(SourceRequestError::Ambiguous(error)) => {
                        self.journal_reader = None;
                        if Instant::now() >= deadline {
                            return Err(error);
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }

        fn drain_profile_state(
            &mut self,
            journal_snapshot: &mut File,
            require_current_fact: bool,
            deadline: Instant,
        ) -> Result<(), String> {
            self.policy.verify_agent_unchanged()?;
            drain_profile_state_reader(
                &mut self.profile_state_reader,
                &self.policy.profile_state_reader_socket,
                &self.policy.state_directory,
                &self.policy.phase,
                journal_snapshot,
                &self.policy.trust,
                &self.policy.plan,
                require_current_fact,
                deadline,
            )?;
            self.policy.verify_agent_unchanged()
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn drain_profile_state_reader(
        reader: &mut Option<(UnixStream, QualificationSourceSessionPeer)>,
        socket: &Path,
        state_directory: &File,
        phase: &auths_profile_kit::QualificationEvidencePhasePlanV1,
        journal_snapshot: &mut File,
        trust: &QualificationEvidenceSourceTrustRegistry,
        plan: &QualificationEvidenceLedgerPlanV1,
        require_current_fact: bool,
        deadline: Instant,
    ) -> Result<(), String> {
        let store_snapshot = open_profile_state_snapshot_at_for_qualification(
            state_directory,
            &phase.profile,
            plan.agent_uid,
        )?;
        let empty_phase = store_snapshot.is_none()
            && !require_current_fact
            && pre_admission_rejection_scenario(&phase.scenario_id);
        let mut store_snapshot = match store_snapshot {
            Some(snapshot) => snapshot,
            None if empty_phase => state_directory.try_clone().map_err(string_error)?,
            None => return Ok(()),
        };
        let request = if empty_phase {
            b"AUTHS-QUALIFICATION-PROFILE-STATE-EMPTY/1".as_slice()
        } else if require_current_fact {
            b"AUTHS-QUALIFICATION-PROFILE-STATE-REQUIRE-CURRENT/1".as_slice()
        } else {
            b"AUTHS-QUALIFICATION-PROFILE-STATE/1".as_slice()
        };
        loop {
            if reader.is_none() {
                let stream = connect_before(socket, deadline, "ProfileStateReader service")?;
                stream.set_nonblocking(true).map_err(string_error)?;
                let peer = QualificationSourceSessionPeer::observe(&stream)?;
                let (_, _, artifact, uid) = trust
                    .current_source_process_binding(
                        QualificationEvidenceSource::ProfileStateReader,
                        &plan.domain,
                        plan.started_at_unix_seconds,
                        plan.deadline_at_unix_seconds,
                        now_unix_seconds()?,
                    )
                    .map_err(string_error)?;
                if peer.uid() != uid || peer.executable_sha256() != artifact {
                    return Err("ProfileStateReader service differs from source trust".into());
                }
                *reader = Some((stream, peer));
            }
            let attempt = (|| -> Result<(), SourceRequestError> {
                let (stream, peer) = reader.as_mut().ok_or_else(|| {
                    SourceRequestError::Fatal("ProfileStateReader service is absent".to_owned())
                })?;
                peer.verify_unchanged().map_err(SourceRequestError::Fatal)?;
                journal_snapshot
                    .seek(SeekFrom::Start(0))
                    .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
                store_snapshot
                    .seek(SeekFrom::Start(0))
                    .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
                send_framed_snapshots(
                    stream,
                    request,
                    &[&*journal_snapshot, &store_snapshot],
                    deadline,
                )
                .map_err(SourceRequestError::Ambiguous)?;
                let response = read_journal_drain_response_before(stream, 1, deadline)?;
                if response != [1] {
                    return Err(SourceRequestError::Fatal(
                        "ProfileStateReader returned a malformed drain response".into(),
                    ));
                }
                peer.verify_unchanged().map_err(SourceRequestError::Fatal)?;
                write_source_session_frame_before(stream, &[1], deadline)
                    .map_err(SourceRequestError::Ambiguous)
            })();
            match attempt {
                Ok(()) => return Ok(()),
                Err(SourceRequestError::Fatal(error)) => return Err(error),
                Err(SourceRequestError::Ambiguous(error)) => {
                    *reader = None;
                    if Instant::now() >= deadline {
                        return Err(error);
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    fn close_profile_state_reader(
        reader: &mut Option<(UnixStream, QualificationSourceSessionPeer)>,
        deadline: Instant,
    ) -> Result<(), String> {
        if let Some((mut stream, peer)) = reader.take() {
            stream.shutdown(Shutdown::Write).map_err(string_error)?;
            if read_bounded_session_frame_before(&mut stream, 64, deadline)?.is_some() {
                return Err("ProfileStateReader sent data after the final drain".into());
            }
            peer.verify_unchanged()?;
        }
        Ok(())
    }

    fn read_journal_drain_response_before(
        stream: &mut UnixStream,
        maximum: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, SourceRequestError> {
        let mut header = [0_u8; 4];
        read_exact_before(stream, &mut header, deadline).map_err(SourceRequestError::Ambiguous)?;
        let length = usize::try_from(u32::from_be_bytes(header))
            .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
        if length == 0 || length > maximum {
            return Err(SourceRequestError::Fatal(
                "JournalReader response frame length is outside its bound".into(),
            ));
        }
        let mut response = vec![0_u8; length];
        read_exact_before(stream, &mut response, deadline)
            .map_err(SourceRequestError::Ambiguous)?;
        Ok(response)
    }

    fn send_framed_snapshot(
        stream: &UnixStream,
        request: &[u8],
        snapshot: &File,
        deadline: Instant,
    ) -> Result<(), String> {
        send_framed_snapshots(stream, request, &[snapshot], deadline)
    }

    fn send_framed_snapshots(
        stream: &UnixStream,
        request: &[u8],
        snapshots: &[&File],
        deadline: Instant,
    ) -> Result<(), String> {
        if !(1..=2).contains(&snapshots.len()) {
            return Err("snapshot descriptor count is outside its bound".into());
        }
        let length = u32::try_from(request.len()).map_err(string_error)?;
        let mut frame = Vec::with_capacity(4 + request.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(request);
        let descriptors = snapshots
            .iter()
            .map(|snapshot| snapshot.as_fd())
            .collect::<Vec<_>>();
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut space);
        if !ancillary.push(rustix::net::SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err("snapshot descriptors could not be framed".into());
        }
        let sent = loop {
            match rustix::net::sendmsg(
                stream,
                &[IoSlice::new(&frame)],
                &mut ancillary,
                rustix::net::SendFlags::empty(),
            ) {
                Ok(sent) => break sent,
                Err(error)
                    if (error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::INTR)
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(string_error(error)),
            }
        };
        if sent == 0 || sent > frame.len() {
            return Err("snapshot descriptor transfer was incomplete".into());
        }
        let mut stream = stream;
        write_all_before(&mut stream, &frame[sent..], deadline)
    }

    fn read_gate_frame_until(
        stream: &mut impl Read,
        maximum: usize,
        stop: &AtomicBool,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, String> {
        let mut header = [0_u8; 4];
        let mut offset = 0_usize;
        while offset < header.len() {
            if Instant::now() >= deadline {
                return Err("ordinary journal gate exceeded the protected deadline".into());
            }
            match stream.read(&mut header[offset..]) {
                Ok(0) => return Err("ordinary qualification agent closed its journal gate".into()),
                Ok(length) => offset += length,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    if offset == 0 && stop.load(Ordering::Acquire) {
                        return Ok(None);
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(string_error(error)),
            }
        }
        let length = usize::try_from(u32::from_be_bytes(header)).map_err(string_error)?;
        if length == 0 || length > maximum {
            return Err("ordinary journal gate frame length is outside its bound".into());
        }
        let mut payload = vec![0_u8; length];
        read_exact_before(stream, &mut payload, deadline)?;
        Ok(Some(payload))
    }

    fn run_phase_gate(
        gate: OrdinaryJournalGate,
        gate_output: ChildStdout,
        gate_release: ChildStdin,
        mut source_checkpoint: Option<SourceCheckpointWait>,
        deadline: Instant,
    ) -> Result<
        (
            PhaseCompletion,
            OrdinaryJournalGate,
            ChildStdout,
            ChildStdin,
            Option<SourceCheckpointWait>,
        ),
        String,
    > {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let (error_tx, error_rx) = mpsc::channel::<String>();
        let (signal_tx, signal_rx) = mpsc::channel::<PhaseGateSignal>();
        let worker = thread::spawn(move || {
            let result = gate.run(
                gate_output,
                gate_release,
                &worker_stop,
                &signal_tx,
                deadline,
            );
            if let Err(error) = &result {
                let _ = error_tx.send(error.clone());
            }
            result
        });
        let completion =
            wait_for_phase_completion(deadline, &error_rx, &signal_rx, &mut source_checkpoint);
        stop.store(true, Ordering::Release);
        let (gate, gate_output, gate_release) = worker
            .join()
            .map_err(|_| "journal gate worker panicked".to_owned())??;
        let completion = completion?;
        if matches!(completion, PhaseCompletion::Completed) && source_checkpoint.is_some() {
            return Err("phase completed before its source-owned crash checkpoint".into());
        }
        Ok((
            completion,
            gate,
            gate_output,
            gate_release,
            source_checkpoint,
        ))
    }

    struct SupervisorPhaseSource {
        append: QualificationSourceAppendSession,
        signer_socket: PathBuf,
        signer_uid: u32,
        signer_artifact_sha256: String,
        plan: QualificationEvidenceLedgerPlanV1,
        trust: QualificationEvidenceSourceTrustRegistry,
    }

    impl SupervisorPhaseSource {
        fn append(
            &mut self,
            scenario_id: &str,
            phase_index: u8,
            supervisor_generation: u32,
            kind: QualificationEvidenceEventKind,
            deadline: Instant,
        ) -> Result<(QualificationEvidenceEvent, Vec<u8>), String> {
            let intent_request = QualificationSupervisorPhaseRequestV1 {
                schema: "auths.qualification-supervisor-phase-request/1".into(),
                sequence: 1,
                previous_event_sha256: "0".repeat(64),
                scenario_id: scenario_id.to_owned(),
                phase_index,
                supervisor_generation,
                kind,
            };
            let intent = hex::decode(
                intent_request
                    .intent_sha256(&self.plan)
                    .map_err(string_error)?,
            )
            .map_err(string_error)?;
            let mut signer =
                connect_before(&self.signer_socket, deadline, "Supervisor phase signer")?;
            let signer_peer = QualificationSourceSessionPeer::observe(&signer)?;
            if signer_peer.uid() != self.signer_uid
                || signer_peer.executable_sha256() != self.signer_artifact_sha256
            {
                return Err("Supervisor phase signer differs from protected source trust".into());
            }
            self.append.append(
                intent,
                false,
                deadline,
                |sequence, previous_event_sha256| {
                    let request = QualificationSupervisorPhaseRequestV1 {
                        schema: "auths.qualification-supervisor-phase-request/1".into(),
                        sequence,
                        previous_event_sha256,
                        scenario_id: scenario_id.to_owned(),
                        phase_index,
                        supervisor_generation,
                        kind,
                    };
                    write_source_session_frame_before(
                        &mut signer,
                        &request.to_json().map_err(string_error)?,
                        deadline,
                    )?;
                    signer.shutdown(Shutdown::Write).map_err(string_error)?;
                    let signed = read_source_session_frame_before(&mut signer, deadline)?
                        .ok_or_else(|| {
                            "Supervisor signer closed before returning an event".to_owned()
                        })?;
                    if read_source_session_frame_before(&mut signer, deadline)?.is_some() {
                        return Err("Supervisor signer returned more than one phase event".into());
                    }
                    signer_peer.verify_unchanged()?;
                    Ok(signed)
                },
            )
        }

        fn append_crash_action(
            &mut self,
            record: QualificationCrashActionRecordV1,
            deadline: Instant,
        ) -> Result<(Vec<u8>, Vec<u8>), String> {
            let intent =
                hex::decode(record.intent_sha256().map_err(string_error)?).map_err(string_error)?;
            let mut retained_context = None;
            let (event, event_bytes) = self.append.resume_or_append(
                intent,
                deadline,
                |sequence, previous_event_sha256| {
                    let mut ordered = record.clone();
                    bind_crash_action_order(&mut ordered, sequence, previous_event_sha256);
                    let (context, event) = run_crash_action_signer(
                        &self.signer_socket,
                        &ordered,
                        &self.trust,
                        &self.signer_artifact_sha256,
                        self.signer_uid,
                        self.plan.started_at_unix_seconds,
                        self.plan.deadline_at_unix_seconds,
                        deadline,
                    )?;
                    retained_context = Some(context);
                    Ok(event)
                },
            )?;
            let mut ordered = record;
            bind_crash_action_order(
                &mut ordered,
                event.sequence,
                event.previous_event_sha256.clone(),
            );
            let context = match retained_context {
                Some(context) => context,
                None => {
                    run_crash_action_signer(
                        &self.signer_socket,
                        &ordered,
                        &self.trust,
                        &self.signer_artifact_sha256,
                        self.signer_uid,
                        self.plan.started_at_unix_seconds,
                        self.plan.deadline_at_unix_seconds,
                        deadline,
                    )?
                    .0
                }
            };
            Ok((context, event_bytes))
        }
    }

    fn bind_crash_action_order(
        record: &mut QualificationCrashActionRecordV1,
        sequence: u32,
        previous_event_sha256: String,
    ) {
        record.sequence = sequence;
        record.previous_event_sha256 = previous_event_sha256.clone();
        match &mut record.facts {
            QualificationCrashActionFactsV1::FailpointAcknowledged {
                boundary_event_sha256,
                ..
            } => *boundary_event_sha256 = previous_event_sha256,
            QualificationCrashActionFactsV1::ProcessKilled {
                acknowledgement_event_sha256,
                ..
            } => *acknowledgement_event_sha256 = previous_event_sha256,
            QualificationCrashActionFactsV1::ProcessRestarted {
                kill_event_sha256, ..
            } => *kill_event_sha256 = previous_event_sha256,
        }
    }

    fn wait_for_phase_completion(
        deadline: Instant,
        gate_errors: &mpsc::Receiver<String>,
        gate_signals: &mpsc::Receiver<PhaseGateSignal>,
        source_checkpoint: &mut Option<SourceCheckpointWait>,
    ) -> Result<PhaseCompletion, String> {
        let mut input = std::io::stdin().lock();
        rustix::fs::fcntl_setfl(&input, OFlags::NONBLOCK).map_err(string_error)?;
        let mut marker = [0_u8; 2];
        let mut accepted = false;
        loop {
            if let Ok(error) = gate_errors.try_recv() {
                return Err(error);
            }
            if matches!(gate_signals.try_recv(), Ok(PhaseGateSignal::CrashReached)) {
                return Ok(PhaseCompletion::CrashReached);
            }
            if let Some(checkpoint) = source_checkpoint.as_mut()
                && checkpoint.poll()?
            {
                return Ok(PhaseCompletion::CrashReached);
            }
            match input.read(&mut marker) {
                Ok(1) if !accepted && marker[0] == 1 => accepted = true,
                Ok(0) if accepted => return Ok(PhaseCompletion::Completed),
                Ok(0) => {
                    return Err("ordinary phase controller input closed before completion".into());
                }
                Ok(_) => {
                    return Err("ordinary phase completion marker is not exactly one byte".into());
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    if Instant::now() >= deadline {
                        return Err("ordinary phase exceeded the protected run deadline".into());
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(string_error(error)),
            }
        }
    }

    fn connect_source_checkpoint(
        socket: &Path,
        source: QualificationEvidenceSource,
        expected_code: u8,
        trust: &QualificationEvidenceSourceTrustRegistry,
        plan: &QualificationEvidenceLedgerPlanV1,
        deadline: Instant,
    ) -> Result<SourceCheckpointWait, String> {
        let mut stream = connect_before(socket, deadline, "source-owned crash checkpoint")?;
        let peer = QualificationSourceSessionPeer::observe(&stream)?;
        let (reader_artifact, reader_uid) =
            reader_process_binding(trust, source, plan, now_unix_seconds()?)?;
        if peer.uid() != reader_uid || peer.executable_sha256() != reader_artifact {
            return Err("source-owned crash checkpoint differs from source trust".into());
        }
        write_source_session_frame_before(
            &mut stream,
            &[SOURCE_CHECKPOINT_ENROLLMENT_VERSION, expected_code],
            deadline,
        )?;
        peer.verify_unchanged()?;
        stream.set_nonblocking(true).map_err(string_error)?;
        Ok(SourceCheckpointWait {
            stream,
            peer,
            expected_code,
            response: Vec::with_capacity(5),
            disposition: if source == QualificationEvidenceSource::ProviderProxy {
                SourceCheckpointDisposition::Continue
            } else {
                SourceCheckpointDisposition::AbortThenClean
            },
        })
    }

    fn new_crash_control_identity(
        plan: &QualificationEvidenceLedgerPlanV1,
        phase: &auths_profile_kit::QualificationEvidencePhasePlanV1,
    ) -> Result<(String, String), String> {
        let mut entropy = [0_u8; 32];
        let mut random = File::open("/dev/urandom").map_err(string_error)?;
        random.read_exact(&mut entropy).map_err(string_error)?;
        let mut control_preimage = b"AUTHS-QUALIFICATION-CRASH-CONTROL\0\x01".to_vec();
        control_preimage.extend_from_slice(plan.ledger_id.as_bytes());
        control_preimage.extend_from_slice(phase.scenario_id.as_bytes());
        control_preimage.push(phase.phase_index);
        control_preimage.extend_from_slice(&entropy);
        let control_digest = Sha256::digest(&control_preimage);
        let control = format!(
            "ctl_{}",
            Base64UrlUnpadded::encode_string(&control_digest[..16])
        );
        let nonce = hex::encode(Sha256::digest(entropy));
        if !registered_token(&control) || !digest(&nonce) {
            return Err("generated crash control identity is malformed".into());
        }
        Ok((control, nonce))
    }

    fn crash_context_from_ledger(
        plan: &QualificationEvidenceLedgerPlanV1,
        phase: &auths_profile_kit::QualificationEvidencePhasePlanV1,
        trust: &QualificationEvidenceSourceTrustRegistry,
        launcher_sha256: &str,
        control_operation_id: &str,
        controller_nonce_sha256: &str,
    ) -> Result<QualificationCrashPhaseContextV1, String> {
        let now = now_unix_seconds()?;
        let (_, supervisor_identity, _, supervisor_uid) = trust
            .current_source_process_binding(
                QualificationEvidenceSource::Supervisor,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                now,
            )
            .map_err(string_error)?;
        if phase.failpoint.is_none() {
            return Err("ordinary phase has no crash context".into());
        }
        let crash = QualificationCrashPhaseContextV1 {
            schema: "auths.qualification-crash-phase-context/1".into(),
            source_context_sha256: plan.source_context_sha256().map_err(string_error)?,
            domain: plan.domain.clone(),
            phase: phase.clone(),
            supervisor_source_uid: supervisor_uid,
            agent_uid: plan.agent_uid,
            agent_gid: plan.agent_gid,
            supervisor_source_identity: supervisor_identity.to_owned(),
            supervisor_generation: 1,
            agent_generation: 1,
            agent_launcher_artifact_sha256: launcher_sha256.to_owned(),
            agent_executable_sha256: plan.agent_executable_sha256.clone(),
            control_operation_id: control_operation_id.to_owned(),
            controller_nonce_sha256: controller_nonce_sha256.to_owned(),
        };
        crash.validate().map_err(string_error)?;
        if !crash.binds_ledger_plan(plan).map_err(string_error)? {
            return Err("derived crash context differs from the immutable ledger phase".into());
        }
        Ok(crash)
    }

    fn registered_token(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
    }

    fn digest(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    }

    fn common_root_for_ledger_plan<'a>(
        ledger_plan: &'a Path,
        provider_run_id: &str,
    ) -> Result<&'a Path, String> {
        if !ledger_plan.is_absolute()
            || ledger_plan
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
            || ledger_plan.file_name().and_then(|name| name.to_str()) != Some("ledger-plan.json")
        {
            return Err("ordinary ledger plan path is not canonical".into());
        }
        let provider = ledger_plan
            .parent()
            .ok_or_else(|| "ordinary ledger plan has no provider directory".to_owned())?;
        let ledger = provider
            .parent()
            .ok_or_else(|| "ordinary ledger plan has no ledger directory".to_owned())?;
        let common = ledger
            .parent()
            .ok_or_else(|| "ordinary ledger plan has no common root".to_owned())?;
        if provider.file_name().and_then(|name| name.to_str()) != Some(provider_run_id)
            || ledger.file_name().and_then(|name| name.to_str()) != Some("ledger")
        {
            return Err("ordinary ledger plan path differs from its provider row".into());
        }
        Ok(common)
    }

    fn run_receipt_verifier(
        socket: &Path,
        snapshot: &mut File,
        source_trust: &QualificationEvidenceSourceTrustRegistry,
        plan: &QualificationEvidenceLedgerPlanV1,
        deadline: Instant,
    ) -> Result<QualificationReceiptVerifierResponseV1, String> {
        let (_, _, source_digest, _) = source_trust
            .current_source_process_binding(
                QualificationEvidenceSource::ReceiptVerifier,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                now_unix_seconds()?,
            )
            .map_err(string_error)?;
        let (_, _, _, _, reader_artifact, reader_uid) = source_trust
            .fixed_source_process_binding(
                QualificationEvidenceSource::ReceiptVerifier,
                &source_digest,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                now_unix_seconds()?,
            )
            .map_err(string_error)?;
        loop {
            match request_receipt_verifier(socket, snapshot, reader_uid, reader_artifact, deadline)
            {
                Ok(response) => return Ok(response),
                Err(SourceRequestError::Ambiguous(_)) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into_string()),
            }
        }
    }

    fn request_receipt_verifier(
        socket: &Path,
        snapshot: &mut File,
        reader_uid: u32,
        reader_artifact: &str,
        deadline: Instant,
    ) -> Result<QualificationReceiptVerifierResponseV1, SourceRequestError> {
        let mut stream = connect_before(socket, deadline, "ReceiptVerifier reader")
            .map_err(SourceRequestError::Fatal)?;
        let peer =
            QualificationSourceSessionPeer::observe(&stream).map_err(SourceRequestError::Fatal)?;
        if peer.uid() != reader_uid || peer.executable_sha256() != reader_artifact {
            return Err(SourceRequestError::Fatal(
                "ReceiptVerifier reader differs from protected source trust".into(),
            ));
        }
        snapshot
            .seek(SeekFrom::Start(0))
            .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
        let descriptors = [snapshot.as_fd()];
        let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut ancillary_space);
        if !ancillary.push(rustix::net::SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err(SourceRequestError::Fatal(
                "ReceiptVerifier snapshot descriptor could not be framed".into(),
            ));
        }
        const REQUEST: &[u8] = b"AUTHS-QUALIFICATION-RECEIPTS/1";
        let request_length = u32::try_from(REQUEST.len())
            .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
        let mut request_frame = Vec::with_capacity(4 + REQUEST.len());
        request_frame.extend_from_slice(&request_length.to_be_bytes());
        request_frame.extend_from_slice(REQUEST);
        let sent = rustix::net::sendmsg(
            &stream,
            &[IoSlice::new(&request_frame)],
            &mut ancillary,
            rustix::net::SendFlags::empty(),
        )
        .map_err(|error| SourceRequestError::Ambiguous(string_error(error)))?;
        if sent == 0 || sent > request_frame.len() {
            return Err(SourceRequestError::Ambiguous(
                "ReceiptVerifier snapshot descriptor transfer was ambiguous".into(),
            ));
        }
        stream
            .write_all(&request_frame[sent..])
            .map_err(|error| SourceRequestError::Ambiguous(string_error(error)))?;
        stream
            .set_nonblocking(true)
            .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
        let response = read_bounded_session_frame_before(&mut stream, 67_108_864, deadline)
            .map_err(SourceRequestError::Ambiguous)?
            .ok_or_else(|| {
                SourceRequestError::Ambiguous(
                    "ReceiptVerifier reader closed before returning its response".into(),
                )
            })?;
        peer.verify_unchanged().map_err(SourceRequestError::Fatal)?;
        let response = QualificationReceiptVerifierResponseV1::from_json(&response)
            .map_err(SourceRequestError::Fatal)?;
        write_source_session_frame_before(&mut stream, &[1], deadline)
            .map_err(SourceRequestError::Ambiguous)?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|error| SourceRequestError::Ambiguous(string_error(error)))?;
        if read_bounded_session_frame_before(&mut stream, 67_108_864, deadline)
            .map_err(SourceRequestError::Ambiguous)?
            .is_some()
        {
            return Err(SourceRequestError::Fatal(
                "ReceiptVerifier reader sent data after its response".into(),
            ));
        }
        Ok(response)
    }

    fn run_provider_observer(
        socket: &Path,
        snapshot: &mut File,
        source_trust: &QualificationEvidenceSourceTrustRegistry,
        plan: &QualificationEvidenceLedgerPlanV1,
        profile: &str,
        deadline: Instant,
    ) -> Result<QualificationProviderObserverResponseV1, String> {
        let (_, _, source_digest, _) = source_trust
            .current_source_process_binding(
                QualificationEvidenceSource::ProviderObserver,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                now_unix_seconds()?,
            )
            .map_err(string_error)?;
        let (_, _, _, _, reader_artifact, reader_uid) = source_trust
            .fixed_source_process_binding(
                QualificationEvidenceSource::ProviderObserver,
                &source_digest,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                now_unix_seconds()?,
            )
            .map_err(string_error)?;
        loop {
            match request_provider_observer(
                socket,
                snapshot,
                reader_uid,
                reader_artifact,
                plan.agent_uid,
                profile,
                deadline,
            ) {
                Ok(response) => return Ok(response),
                Err(SourceRequestError::Ambiguous(_)) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into_string()),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn request_provider_observer(
        socket: &Path,
        snapshot: &mut File,
        reader_uid: u32,
        reader_artifact: &str,
        agent_uid: u32,
        profile: &str,
        deadline: Instant,
    ) -> Result<QualificationProviderObserverResponseV1, SourceRequestError> {
        let mut stream = connect_before(socket, deadline, "ProviderObserver reader")
            .map_err(SourceRequestError::Fatal)?;
        let peer =
            QualificationSourceSessionPeer::observe(&stream).map_err(SourceRequestError::Fatal)?;
        if peer.uid() != reader_uid || peer.executable_sha256() != reader_artifact {
            return Err(SourceRequestError::Fatal(
                "ProviderObserver reader differs from protected source trust".into(),
            ));
        }
        snapshot
            .seek(SeekFrom::Start(0))
            .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
        let descriptors = [snapshot.as_fd()];
        let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut ancillary_space);
        if !ancillary.push(rustix::net::SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err(SourceRequestError::Fatal(
                "ProviderObserver snapshot descriptor could not be framed".into(),
            ));
        }
        const REQUEST: &[u8] = b"AUTHS-QUALIFICATION-PROVIDER-TRUTH/1";
        let request_length = u32::try_from(REQUEST.len())
            .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
        let mut request_frame = Vec::with_capacity(4 + REQUEST.len());
        request_frame.extend_from_slice(&request_length.to_be_bytes());
        request_frame.extend_from_slice(REQUEST);
        let sent = rustix::net::sendmsg(
            &stream,
            &[IoSlice::new(&request_frame)],
            &mut ancillary,
            rustix::net::SendFlags::empty(),
        )
        .map_err(|error| SourceRequestError::Ambiguous(string_error(error)))?;
        if sent == 0 || sent > request_frame.len() {
            return Err(SourceRequestError::Ambiguous(
                "ProviderObserver snapshot descriptor transfer was ambiguous".into(),
            ));
        }
        stream
            .write_all(&request_frame[sent..])
            .map_err(|error| SourceRequestError::Ambiguous(string_error(error)))?;
        stream
            .set_nonblocking(true)
            .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
        let response = read_bounded_session_frame_before(&mut stream, 16 * 1_024 * 1_024, deadline)
            .map_err(SourceRequestError::Ambiguous)?
            .ok_or_else(|| {
                SourceRequestError::Ambiguous(
                    "ProviderObserver reader closed before returning its response".into(),
                )
            })?;
        peer.verify_unchanged().map_err(SourceRequestError::Fatal)?;
        let response = QualificationProviderObserverResponseV1::from_json(&response)
            .map_err(SourceRequestError::Fatal)?;
        snapshot
            .seek(SeekFrom::Start(0))
            .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
        let records =
            read_persisted_operation_records_from_qualification_snapshot(snapshot, agent_uid)
                .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
        let expected = records
            .iter()
            .filter(|record| {
                record.provider_entered()
                    && format!(
                        "{}/{}",
                        record.binding().profile().id(),
                        record.binding().profile().version()
                    ) == profile
            })
            .map(|record| {
                let effect = match record.projection().effect() {
                    OperationEffectV1::Applied => QualificationEffect::Applied,
                    OperationEffectV1::NotApplied => QualificationEffect::NotApplied,
                    OperationEffectV1::Possible => QualificationEffect::Possible,
                };
                (record.operation_id().as_str().to_owned(), effect)
            })
            .collect::<BTreeMap<_, _>>();
        let actual = response
            .operations
            .iter()
            .map(|operation| (operation.operation_id.clone(), operation.effect))
            .collect::<BTreeMap<_, _>>();
        if expected != actual || actual.len() != response.operations.len() {
            return Err(SourceRequestError::Fatal(
                "ProviderObserver response differs from the provider-entered journal roster".into(),
            ));
        }
        write_source_session_frame_before(&mut stream, &[1], deadline)
            .map_err(SourceRequestError::Ambiguous)?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|error| SourceRequestError::Ambiguous(string_error(error)))?;
        if read_bounded_session_frame_before(&mut stream, 65_536, deadline)
            .map_err(SourceRequestError::Ambiguous)?
            .is_some()
        {
            return Err(SourceRequestError::Fatal(
                "ProviderObserver reader sent data after its response".into(),
            ));
        }
        Ok(response)
    }

    fn retain_provider_observer_response(
        common_root: &Path,
        response: &QualificationProviderObserverResponseV1,
    ) -> Result<(), String> {
        let root = common_root.join("provider-observer-facts");
        create_private_directory(&root)?;
        for operation in &response.operations {
            let facts = Base64UrlUnpadded::decode_vec(&operation.domain_facts_base64url)
                .map_err(string_error)?;
            if facts.is_empty()
                || facts.len() > 4 * 1_024 * 1_024
                || hex::encode(Sha256::digest(&facts)) != operation.provider_truth_sha256
            {
                return Err(
                    "ProviderObserver response facts differ from their signed digest".into(),
                );
            }
            write_new(
                &root.join(format!("{}.json", operation.operation_id)),
                &facts,
            )?;
        }
        Ok(())
    }

    fn retain_receipt_verifier_response(
        common_root: &Path,
        response: &QualificationReceiptVerifierResponseV1,
    ) -> Result<(), String> {
        let receipts_root = common_root.join("receipts");
        let inspection_root = common_root.join("receipt-inspection");
        create_private_directory(&receipts_root)?;
        create_private_directory(&inspection_root)?;
        for operation in &response.operations {
            let operation_root = receipts_root.join(&operation.operation_id);
            create_private_directory(&operation_root)?;
            let inspection = Base64UrlUnpadded::decode_vec(&operation.inspection_base64url)
                .map_err(string_error)?;
            write_new(
                &inspection_root.join(format!("{}.json", operation.operation_id)),
                &inspection,
            )?;
            for receipt in &operation.receipts {
                let bytes = Base64UrlUnpadded::decode_vec(&receipt.bytes_base64url)
                    .map_err(string_error)?;
                write_new(
                    &operation_root.join(format!("{}.cbor", receipt.sequence)),
                    &bytes,
                )?;
            }
        }
        Ok(())
    }

    fn connect_before(path: &Path, deadline: Instant, label: &str) -> Result<UnixStream, String> {
        loop {
            if Instant::now() >= deadline {
                return Err(format!(
                    "{label} did not become available before the deadline"
                ));
            }
            match UnixStream::connect(path) {
                Ok(stream) => {
                    stream.set_nonblocking(true).map_err(string_error)?;
                    return Ok(stream);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound
                            | std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(string_error(error)),
            }
        }
    }

    fn exact_flags(
        arguments: &[String],
        command: &str,
        flags: &[&str],
    ) -> Result<BTreeMap<String, String>, String> {
        if arguments.first().map(String::as_str) != Some(command)
            || arguments.len() != 1 + flags.len() * 2
        {
            return Err(usage());
        }
        let expected = flags.iter().copied().collect::<BTreeSet<_>>();
        let mut values = BTreeMap::new();
        for pair in arguments[1..].chunks_exact(2) {
            if !expected.contains(pair[0].as_str())
                || pair[1].is_empty()
                || values.insert(pair[0].clone(), pair[1].clone()).is_some()
            {
                return Err(usage());
            }
        }
        if values.len() != flags.len() {
            return Err(usage());
        }
        Ok(values)
    }

    fn value<'a>(values: &'a BTreeMap<String, String>, flag: &str) -> Result<&'a str, String> {
        values.get(flag).map(String::as_str).ok_or_else(usage)
    }

    fn read_stream_before<R: Read>(
        stream: &mut R,
        maximum: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 1_024];
        loop {
            if Instant::now() >= deadline {
                return Err("durable acknowledgement exceeded the total deadline".into());
            }
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(length) => {
                    if bytes
                        .len()
                        .checked_add(length)
                        .is_none_or(|total| total > maximum)
                    {
                        return Err("durable acknowledgement exceeds its byte bound".into());
                    }
                    bytes.extend_from_slice(&chunk[..length]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(string_error(error)),
            }
        }
        Ok(bytes)
    }

    fn write_gate_frame_before<W: Write>(
        stream: &mut W,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() > MAX_ACK_BYTES {
            return Err("journal gate release length is outside its bound".into());
        }
        let header = u32::try_from(bytes.len())
            .map_err(string_error)?
            .to_be_bytes();
        write_all_before(stream, &header, deadline)?;
        write_all_before(stream, bytes, deadline)
    }

    fn read_exact_before<R: Read>(
        stream: &mut R,
        mut bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<(), String> {
        while !bytes.is_empty() {
            if Instant::now() >= deadline {
                return Err("journal gate frame exceeded its total deadline".into());
            }
            match stream.read(bytes) {
                Ok(0) => return Err("journal gate frame ended before its declared length".into()),
                Ok(length) => bytes = &mut bytes[length..],
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(string_error(error)),
            }
        }
        Ok(())
    }

    fn write_all_before<W: Write>(
        stream: &mut W,
        mut bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), String> {
        while !bytes.is_empty() {
            if Instant::now() >= deadline {
                return Err("journal gate frame exceeded its total deadline".into());
            }
            match stream.write(bytes) {
                Ok(0) => return Err("journal gate frame could not be written".into()),
                Ok(length) => bytes = &bytes[length..],
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(string_error(error)),
            }
        }
        stream.flush().map_err(string_error)
    }

    fn launch_agent(
        values: &BTreeMap<String, String>,
        policy: &AgentLaunchPolicy<'_>,
        agent_services: &AgentServiceLaunchPolicy,
        mode: AgentLaunchMode,
    ) -> Result<Child, String> {
        let launcher = Path::new(value(values, "--agent-launcher")?);
        let agent = Path::new(value(values, "--agent")?);
        if executable_sha256(launcher)? != policy.launcher_sha256
            || executable_sha256(launcher)?
                != required_env("AUTHS_QUALIFICATION_AGENT_LAUNCHER_SHA256")?
            || executable_sha256(agent)? != policy.executable_sha256
        {
            return Err("qualification launch executables differ from protected policy".into());
        }
        let controller_pid = std::process::id().to_string();
        if mode.generation == 0 {
            return Err("qualification launch generation is zero".into());
        }
        let mode_name = if mode.restarting {
            mode.failpoint
                .map(|failpoint| format!("restart-crash-{}", failpoint.as_str()))
                .unwrap_or_else(|| "restart".to_owned())
        } else {
            mode.failpoint
                .map(|failpoint| format!("crash-{}", failpoint.as_str()))
                .unwrap_or_else(|| "ordinary".to_owned())
        };
        let (admin_socket, agent_socket) = if mode.use_restart_paths {
            (
                value(values, "--restart-admin-socket")?,
                value(values, "--restart-agent-socket")?,
            )
        } else {
            (
                value(values, "--admin-socket")?,
                value(values, "--agent-socket")?,
            )
        };
        let generation = mode.generation.to_string();
        let mut command = Command::new(launcher);
        command.args([
            "launch",
            "--mode",
            &mode_name,
            "--admin-socket",
            admin_socket,
            "--agent",
            value(values, "--agent")?,
            "--agent-gid",
            value(values, "--agent-gid")?,
            "--agent-generation",
            &generation,
            "--agent-sha256",
            policy.executable_sha256,
            "--agent-socket",
            agent_socket,
            "--agent-uid",
            value(values, "--agent-uid")?,
            "--config",
            value(values, "--agent-config")?,
            "--config-sha256",
            &required_env("AUTHS_QUALIFICATION_AGENT_CONFIG_SHA256")?,
            "--client-proxy-artifact-sha256",
            &agent_services.client_proxy_artifact_sha256,
            "--client-proxy-reader-uid",
            &agent_services.client_proxy_reader_uid.to_string(),
            "--controller-pid",
            &controller_pid,
            "--credential-broker-artifact-sha256",
            &agent_services.credential_broker_artifact_sha256,
            "--credential-broker-reader-uid",
            &agent_services.credential_broker_reader_uid.to_string(),
            "--credential-broker-socket",
            &agent_services.credential_broker_socket,
            "--provider-proxy-artifact-sha256",
            &agent_services.provider_proxy_artifact_sha256,
            "--provider-proxy-reader-uid",
            &agent_services.provider_proxy_reader_uid.to_string(),
            "--provider-proxy-socket",
            &agent_services.provider_proxy_socket,
            "--ledger-plan",
            policy.ledger_plan_path,
            "--qualification-connection-store-template",
            value(values, "--qualification-connection-store-template")?,
            "--recovery-key-id",
            policy.recovery_key_id,
            "--recovery-public-key-base64url",
            policy.recovery_public_key_base64url,
            "--source-context-sha256",
            &agent_services.source_context_sha256,
            "--state-directory",
            value(values, "--agent-state-directory")?,
            "--state-directory-sha256",
            &required_env("AUTHS_QUALIFICATION_AGENT_STATE_DIRECTORY_SHA256")?,
        ]);
        if mode.failpoint.is_some() {
            if policy.crash_generation != Some(mode.generation) {
                return Err("crash launch generation differs from protected policy".into());
            }
            command.args([
                "--control-operation-id",
                policy
                    .control_operation_id
                    .ok_or_else(|| "crash control operation is absent".to_owned())?,
                "--controller-nonce-sha256",
                policy
                    .controller_nonce_sha256
                    .ok_or_else(|| "crash controller nonce is absent".to_owned())?,
            ]);
        }
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(string_error)
    }

    enum SourceRequestError {
        Fatal(String),
        Ambiguous(String),
    }

    impl SourceRequestError {
        fn into_string(self) -> String {
            match self {
                Self::Fatal(error) | Self::Ambiguous(error) => error,
            }
        }
    }

    fn send_context_to_supervisor(
        socket: &Path,
        bytes: &[u8],
        source_trust: &QualificationEvidenceSourceTrustRegistry,
        expected_signer_digest: &str,
        expected_signer_uid: u32,
        deadline: Instant,
    ) -> Result<Vec<u8>, SourceRequestError> {
        let mut stream = loop {
            match UnixStream::connect(socket) {
                Ok(stream) => break stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    if Instant::now() >= deadline {
                        return Err(SourceRequestError::Fatal(
                            "supervisor source signer was not ready before the deadline".into(),
                        ));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(SourceRequestError::Fatal(string_error(error))),
            }
        };
        let peer = rustix::net::sockopt::socket_peercred(&stream)
            .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
        let peer_uid = peer.uid.as_raw();
        let peer_pid = u32::try_from(peer.pid.as_raw_pid())
            .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
        let peer_digest = hash_process_executable(peer_pid).map_err(SourceRequestError::Fatal)?;
        if peer_uid != expected_signer_uid
            || peer_digest != expected_signer_digest
            || !source_trust
                .permits_source_artifact(QualificationEvidenceSource::Supervisor, &peer_digest)
        {
            return Err(SourceRequestError::Fatal(
                "supervisor signer identity differs from protected policy".into(),
            ));
        }
        stream
            .write_all(bytes)
            .map_err(|error| SourceRequestError::Ambiguous(string_error(error)))?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|error| SourceRequestError::Ambiguous(string_error(error)))?;
        stream
            .set_nonblocking(true)
            .map_err(|error| SourceRequestError::Ambiguous(string_error(error)))?;
        let response = read_stream_before(&mut stream, 196_608, deadline)
            .map_err(SourceRequestError::Ambiguous)?;
        Ok(response)
    }

    fn send_ordinary_context_to_supervisor(
        socket: &Path,
        bytes: &[u8],
        source_trust: &QualificationEvidenceSourceTrustRegistry,
        expected_signer_digest: &str,
        expected_signer_uid: u32,
        deadline: Instant,
    ) -> Result<Vec<u8>, SourceRequestError> {
        let mut stream = loop {
            match UnixStream::connect(socket) {
                Ok(stream) => break stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    if Instant::now() >= deadline {
                        return Err(SourceRequestError::Fatal(
                            "ordinary Supervisor row signer was not ready before the deadline"
                                .into(),
                        ));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(SourceRequestError::Fatal(string_error(error))),
            }
        };
        stream
            .set_nonblocking(true)
            .map_err(|error| SourceRequestError::Fatal(string_error(error)))?;
        let peer =
            QualificationSourceSessionPeer::observe(&stream).map_err(SourceRequestError::Fatal)?;
        if peer.uid() != expected_signer_uid
            || peer.executable_sha256() != expected_signer_digest
            || !source_trust.permits_source_artifact(
                QualificationEvidenceSource::Supervisor,
                peer.executable_sha256(),
            )
        {
            return Err(SourceRequestError::Fatal(
                "ordinary Supervisor row signer differs from protected policy".into(),
            ));
        }
        write_source_session_frame_before(&mut stream, bytes, deadline)
            .map_err(SourceRequestError::Ambiguous)?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|error| SourceRequestError::Ambiguous(string_error(error)))?;
        let response = read_source_session_frame_before(&mut stream, deadline)
            .map_err(SourceRequestError::Ambiguous)?
            .ok_or_else(|| {
                SourceRequestError::Ambiguous(
                    "ordinary Supervisor row signer closed before its response".into(),
                )
            })?;
        peer.verify_unchanged().map_err(SourceRequestError::Fatal)?;
        if read_source_session_frame_before(&mut stream, deadline)
            .map_err(SourceRequestError::Ambiguous)?
            .is_some()
        {
            return Err(SourceRequestError::Fatal(
                "ordinary Supervisor row signer returned more than one response".into(),
            ));
        }
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_crash_action_signer(
        socket: &Path,
        record: &QualificationCrashActionRecordV1,
        source_trust: &QualificationEvidenceSourceTrustRegistry,
        expected_signer_digest: &str,
        expected_signer_uid: u32,
        started_at: u64,
        completed_at: u64,
        deadline: Instant,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        record.validate().map_err(string_error)?;
        let request = serde_json_canonicalizer::to_vec(record).map_err(string_error)?;
        let (context_bytes, event_bytes) = loop {
            let response = match send_context_to_supervisor(
                socket,
                &request,
                source_trust,
                expected_signer_digest,
                expected_signer_uid,
                deadline,
            ) {
                Ok(response) => response,
                Err(SourceRequestError::Ambiguous(error)) if Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) => return Err(error.into_string()),
            };
            let response = QualificationCrashActionResponseV1::from_json(&response)?;
            let context = Base64UrlUnpadded::decode_vec(&response.action_context_base64url)
                .map_err(string_error)?;
            let event =
                Base64UrlUnpadded::decode_vec(&response.event_base64url).map_err(string_error)?;
            break (context, event);
        };
        let now = now_unix_seconds()?;
        let context = QualificationCrashActionContextV1::verify_json(
            &context_bytes,
            source_trust,
            started_at,
            completed_at,
            now,
        )
        .map_err(string_error)?;
        if context.record() != record {
            return Err("supervisor signer returned a different crash action record".into());
        }
        let action_context_sha256 = hex::encode(Sha256::digest(&context_bytes));
        let event = QualificationEvidenceEvent::verify_json(
            &event_bytes,
            QualificationEvidenceSource::Supervisor,
            &record.crash_context.source_context_sha256,
            source_trust,
            &record.crash_context.domain,
            started_at,
            completed_at,
            now,
        )
        .map_err(string_error)?;
        let mut unsigned_event = event;
        unsigned_event.source_signature_base64url.clear();
        if unsigned_event
            != record.unsigned_event(context.key_id().to_owned(), action_context_sha256)
        {
            return Err("supervisor signer returned a different crash action event".into());
        }
        Ok((context_bytes, event_bytes))
    }

    fn create_private_directory(path: &Path) -> Result<(), String> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err("protected action directory is not normalized and absolute".into());
        }
        let parent = path
            .parent()
            .ok_or_else(|| "protected action directory has no parent".to_owned())?;
        let name = path
            .file_name()
            .ok_or_else(|| "protected action directory has no name".to_owned())?;
        let parent = open_directory_componentwise(parent, true)?;
        if let Err(error) = mkdirat(&parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            && error != rustix::io::Errno::EXIST
        {
            return Err(string_error(error));
        }
        let directory = File::from(
            openat(
                &parent,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let metadata = directory.metadata().map_err(string_error)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o700
        {
            return Err("protected action directory identity is invalid".into());
        }
        parent.sync_all().map_err(string_error)
    }

    fn open_protected_state_directory(path: &Path, agent_uid: u32) -> Result<File, String> {
        if !path.is_absolute()
            || path.as_os_str().as_encoded_bytes().len() > 1_024
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err("qualification state directory is not normalized and absolute".into());
        }
        let root = File::from(
            open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let relative = path.strip_prefix("/").map_err(string_error)?;
        let directory = File::from(
            openat2(
                &root,
                relative,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(string_error)?,
        );
        let metadata = directory.metadata().map_err(string_error)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != agent_uid
            || metadata.mode() & 0o777 != 0o700
        {
            return Err("qualification state directory is not one agent-owned inode".into());
        }
        Ok(directory)
    }

    fn open_profile_state_snapshot_at_for_qualification(
        state_directory: &File,
        profile: &str,
        agent_uid: u32,
    ) -> Result<Option<File>, String> {
        let relative = qualification_profile_state_snapshot_path(profile)
            .ok_or_else(|| "phase profile has no protected state snapshot".to_owned())?;
        let descriptor = match openat2(
            state_directory,
            relative,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(error) => return Err(string_error(error)),
        };
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(string_error)?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.uid() != agent_uid
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() == 0
            || metadata.len() > 64 * 1024 * 1024
        {
            return Err("profile-state snapshot identity is invalid".into());
        }
        Ok(Some(file))
    }

    fn validate_client_bridge_socket_parent(
        socket: &Path,
        agent_uid: u32,
        agent_gid: u32,
    ) -> Result<(), String> {
        validate_shared_agent_socket_parent(socket, agent_uid, agent_gid, "ClientProxy backend")
    }

    fn validate_shared_agent_socket_parent(
        socket: &Path,
        owner_uid: u32,
        agent_gid: u32,
        role: &str,
    ) -> Result<(), String> {
        if !socket.is_absolute()
            || socket
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(format!(
                "qualification {role} socket path is not normalized"
            ));
        }
        let parent = socket
            .parent()
            .ok_or_else(|| format!("qualification {role} socket has no parent"))?;
        let root = File::from(
            open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let directory = File::from(
            openat2(
                &root,
                parent.strip_prefix("/").map_err(string_error)?,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(string_error)?,
        );
        let metadata = directory.metadata().map_err(string_error)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != owner_uid
            || metadata.gid() != agent_gid
            || metadata.mode() & 0o777 != 0o710
        {
            return Err(format!(
                "qualification {role} socket parent is not the exact shared-group directory"
            ));
        }
        Ok(())
    }

    fn reader_process_binding(
        trust: &QualificationEvidenceSourceTrustRegistry,
        source: QualificationEvidenceSource,
        plan: &QualificationEvidenceLedgerPlanV1,
        now: u64,
    ) -> Result<(String, u32), String> {
        let (_, _, signer_artifact, _) = trust
            .current_source_process_binding(
                source,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                now,
            )
            .map_err(string_error)?;
        let (_, _, _, _, reader_artifact, reader_uid) = trust
            .fixed_source_process_binding(
                source,
                signer_artifact,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                now,
            )
            .map_err(string_error)?;
        Ok((reader_artifact.to_owned(), reader_uid))
    }

    fn stop_phase_reader(
        socket: &Path,
        source: QualificationEvidenceSource,
        trust: &QualificationEvidenceSourceTrustRegistry,
        plan: &QualificationEvidenceLedgerPlanV1,
        deadline: Instant,
    ) -> Result<(), String> {
        const STOP: &[u8] = b"AUTHS-QUALIFICATION-PHASE-READER-STOP/1";
        let (artifact, uid) = reader_process_binding(trust, source, plan, now_unix_seconds()?)?;
        let mut stream = connect_before(socket, deadline, "protected phase reader control")?;
        stream.set_nonblocking(true).map_err(string_error)?;
        let peer = QualificationSourceSessionPeer::observe(&stream)?;
        if peer.uid() != uid || peer.executable_sha256() != artifact {
            return Err(format!(
                "{source:?} control service differs from protected source trust"
            ));
        }
        write_source_session_frame_before(&mut stream, STOP, deadline)?;
        stream.shutdown(Shutdown::Write).map_err(string_error)?;
        let acknowledgement = read_source_session_frame_before(&mut stream, deadline)?
            .ok_or_else(|| format!("{source:?} control service returned no acknowledgement"))?;
        if acknowledgement != [1] {
            return Err(format!(
                "{source:?} control service returned a malformed acknowledgement"
            ));
        }
        peer.verify_unchanged()?;
        write_source_session_frame_before(&mut stream, &[1], deadline)?;
        stream.shutdown(Shutdown::Write).map_err(string_error)?;
        if read_source_session_frame_before(&mut stream, deadline)?.is_some() {
            return Err(format!("{source:?} control service returned trailing data"));
        }
        Ok(())
    }

    fn read_bounded(path: &Path, maximum: u64, owner_only: bool) -> Result<Vec<u8>, String> {
        let parent = path
            .parent()
            .ok_or_else(|| "crash controller input has no parent".to_owned())?;
        let name = path
            .file_name()
            .ok_or_else(|| "crash controller input has no name".to_owned())?;
        let parent = open_directory_componentwise(parent, owner_only)?;
        let mut file = File::from(
            openat(
                &parent,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let before = file.metadata().map_err(string_error)?;
        let invalid_permissions = if owner_only {
            before.mode() & 0o077 != 0
        } else {
            before.mode() & 0o022 != 0
        };
        if !before.file_type().is_file()
            || before.nlink() != 1
            || before.uid() != rustix::process::geteuid().as_raw()
            || invalid_permissions
            || before.len() > maximum
        {
            return Err("crash controller input is not a bounded trusted regular file".into());
        }
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(string_error)?;
        let after = file.metadata().map_err(string_error)?;
        if u64::try_from(bytes.len()).map_err(string_error)? > maximum
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
        {
            return Err("crash controller input changed while it was read".into());
        }
        Ok(bytes)
    }

    fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| "crash report has no parent".to_owned())?;
        let name = path
            .file_name()
            .ok_or_else(|| "crash report has no file name".to_owned())?;
        let parent_directory = open_directory_componentwise(parent, true)?;
        if let Some(existing) = read_optional_at(&parent_directory, name, bytes.len() as u64)? {
            return if existing == bytes {
                Ok(())
            } else {
                Err("crash report existing bytes differ from the protected retry".into())
            };
        }
        let stage = format!(".{}.stage", name.to_string_lossy());
        if let Some(existing) = read_optional_at(&parent_directory, &stage, bytes.len() as u64)? {
            if existing != bytes {
                unlinkat(&parent_directory, &stage, AtFlags::empty()).map_err(string_error)?;
                parent_directory.sync_all().map_err(string_error)?;
            }
        }
        let mut file = File::from(
            openat(
                &parent_directory,
                &stage,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .or_else(|error| {
                if error == rustix::io::Errno::EXIST {
                    openat(
                        &parent_directory,
                        &stage,
                        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                } else {
                    Err(error)
                }
            })
            .map_err(string_error)?,
        );
        let metadata = file.metadata().map_err(string_error)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err("crash report staging inode is not private".into());
        }
        if metadata.len() == 0 {
            file.write_all(bytes).map_err(string_error)?;
        }
        file.sync_all().map_err(string_error)?;
        match renameat_with(
            &parent_directory,
            &stage,
            &parent_directory,
            name,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => parent_directory.sync_all().map_err(string_error),
            Err(error) if error == rustix::io::Errno::EXIST => {
                let existing = read_optional_at(&parent_directory, name, bytes.len() as u64)?
                    .ok_or_else(|| "crash report disappeared during publication".to_owned())?;
                if existing != bytes {
                    return Err("crash report publication raced different bytes".into());
                }
                unlinkat(&parent_directory, &stage, AtFlags::empty()).map_err(string_error)?;
                parent_directory.sync_all().map_err(string_error)
            }
            Err(error) => Err(string_error(error)),
        }
    }

    fn read_optional_at(
        directory: &File,
        name: impl AsRef<Path>,
        maximum: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        let descriptor = match openat(
            directory,
            name.as_ref(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(error) => return Err(string_error(error)),
        };
        let file = File::from(descriptor);
        let before = file.metadata().map_err(string_error)?;
        if !before.file_type().is_file()
            || before.uid() != rustix::process::geteuid().as_raw()
            || before.mode() & 0o777 != 0o600
            || before.nlink() != 1
            || before.len() > maximum
        {
            return Err("crash report existing inode is not private and bounded".into());
        }
        let mut bytes = Vec::new();
        file.take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(string_error)?;
        if bytes.len() as u64 > maximum {
            return Err("crash report existing bytes exceed the retry bound".into());
        }
        Ok(Some(bytes))
    }

    fn open_directory_componentwise(path: &Path, owner_only: bool) -> Result<File, String> {
        if !path.is_absolute()
            || path.as_os_str().as_encoded_bytes().len() > 2_048
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err("protected directory is not normalized and absolute".into());
        }
        let root = File::from(
            open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let directory = File::from(
            openat2(
                &root,
                path.strip_prefix("/").map_err(string_error)?,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(string_error)?,
        );
        let metadata = directory.metadata().map_err(string_error)?;
        let invalid_permissions = if owner_only {
            metadata.mode() & 0o077 != 0
        } else {
            metadata.mode() & 0o022 != 0
        };
        if !metadata.file_type().is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || invalid_permissions
        {
            return Err("protected directory permissions or ownership are invalid".into());
        }
        Ok(directory)
    }

    fn hash_process_executable(pid: u32) -> Result<String, String> {
        const MAX_EXECUTABLE_BYTES: u64 = 536_870_912;
        let mut file =
            File::open(PathBuf::from(format!("/proc/{pid}/exe"))).map_err(string_error)?;
        let before = file.metadata().map_err(string_error)?;
        if !before.file_type().is_file() || before.len() == 0 || before.len() > MAX_EXECUTABLE_BYTES
        {
            return Err("process executable is not a bounded regular file".into());
        }
        let mut hasher = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 65_536];
        loop {
            let length = file.read(&mut buffer).map_err(string_error)?;
            if length == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(length).map_err(string_error)?)
                .ok_or_else(|| "process executable byte count overflow".to_owned())?;
            if total > MAX_EXECUTABLE_BYTES {
                return Err("process executable exceeds its byte bound".into());
            }
            hasher.update(&buffer[..length]);
        }
        let after = file.metadata().map_err(string_error)?;
        if total != before.len()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
        {
            return Err("process executable changed while it was read".into());
        }
        Ok(hex::encode(hasher.finalize()))
    }

    fn executable_sha256(path: &Path) -> Result<String, String> {
        let bytes = read_bounded(path, 536_870_912, false)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    fn boot_sha256() -> Result<String, String> {
        let boot = fs::read("/proc/sys/kernel/random/boot_id").map_err(string_error)?;
        if boot.is_empty() || boot.len() > 128 {
            return Err("kernel boot identity is malformed".into());
        }
        Ok(hex::encode(Sha256::digest(boot)))
    }

    fn process_start_time_ticks(pid: u32) -> Result<u64, String> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(string_error)?;
        let tail = stat
            .rsplit_once(") ")
            .ok_or_else(|| "agent process status is malformed".to_owned())?
            .1;
        tail.split_ascii_whitespace()
            .nth(19)
            .ok_or_else(|| "agent process start time is absent".to_owned())?
            .parse::<u64>()
            .map_err(string_error)
    }

    fn validate_new_cgroup_path(path: &Path) -> Result<(), String> {
        if !path.is_absolute()
            || !path.starts_with("/sys/fs/cgroup")
            || path == Path::new("/sys/fs/cgroup")
            || path.exists()
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err("qualification cgroup path is not a new delegated cgroup-v2 path".into());
        }
        let parent = path
            .parent()
            .ok_or_else(|| "qualification cgroup has no delegated parent".to_owned())?;
        let parent_metadata = fs::symlink_metadata(parent).map_err(string_error)?;
        if !parent_metadata.file_type().is_dir() {
            return Err("qualification cgroup parent is not a directory".into());
        }
        Ok(())
    }

    fn expected_cgroup_membership(path: &Path) -> Result<String, String> {
        let relative = path.strip_prefix("/sys/fs/cgroup").map_err(string_error)?;
        if relative.as_os_str().is_empty()
            || relative.components().any(|part| {
                matches!(
                    part,
                    Component::RootDir | Component::CurDir | Component::ParentDir
                )
            })
        {
            return Err("qualification cgroup path has no normalized delegated membership".into());
        }
        Ok(format!("0::/{}", relative.to_string_lossy()))
    }

    fn prepare_cgroup(cgroup: &OwnedCgroup, pid: u32) -> Result<(), String> {
        cgroup.validate_identity()?;
        fs::write(cgroup.path.join("cgroup.procs"), pid.to_string()).map_err(string_error)?;
        let expected = expected_cgroup_membership(&cgroup.path)?;
        let membership = fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(string_error)?;
        if membership.trim() != expected {
            return Err("qualification launcher did not enter the exact delegated cgroup".into());
        }
        for required in ["cgroup.kill", "cgroup.events", "cgroup.procs"] {
            if !cgroup.path.join(required).is_file() {
                return Err("qualification requires delegated cgroup v2 kill support".into());
            }
        }
        Ok(())
    }

    fn wait_for_agent_exec(
        child: &mut Child,
        pid: u32,
        start_time_ticks: u64,
        expected_digest: &str,
        cgroup: &Path,
        expected_uid: u32,
        expected_gid: u32,
        deadline: Instant,
    ) -> Result<(), String> {
        loop {
            if child.try_wait().map_err(string_error)?.is_some() {
                return Err("qualification launcher exited before agent exec".into());
            }
            if process_start_time_ticks(pid)? != start_time_ticks {
                return Err("qualification launcher process identity changed before exec".into());
            }
            if hash_process_executable(pid).is_ok_and(|digest| digest == expected_digest) {
                let membership =
                    fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(string_error)?;
                if membership.trim() != expected_cgroup_membership(cgroup)? {
                    return Err("qualification agent escaped its delegated cgroup".into());
                }
                validate_agent_process_credentials(pid, expected_uid, expected_gid)?;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("qualification launcher did not exec the expected agent".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn wait_for_agent_ready(
        child: &mut Child,
        pid: u32,
        start_time_ticks: u64,
        agent_socket: &Path,
        admin_socket: &Path,
        expected_uid: u32,
        deadline: Instant,
    ) -> Result<(), String> {
        loop {
            if child.try_wait().map_err(string_error)?.is_some()
                || process_start_time_ticks(pid)? != start_time_ticks
            {
                return Err("restarted qualification agent exited before readiness".into());
            }
            let ready = [agent_socket, admin_socket].iter().all(|path| {
                fs::symlink_metadata(path).is_ok_and(|metadata| {
                    metadata.file_type().is_socket()
                        && metadata.uid() == expected_uid
                        && metadata.mode() & 0o002 == 0
                        && UnixStream::connect(path).is_ok()
                })
            });
            if ready {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("restarted qualification agent was not ready before deadline".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn kill_cgroup_and_reap(
        cgroup: &OwnedCgroup,
        child: &mut Child,
        deadline: Instant,
        remove: bool,
    ) -> Result<(), String> {
        cgroup.validate_identity()?;
        fs::write(cgroup.path.join("cgroup.kill"), b"1").map_err(string_error)?;
        loop {
            cgroup.validate_identity()?;
            let events =
                fs::read_to_string(cgroup.path.join("cgroup.events")).map_err(string_error)?;
            let populated = events
                .lines()
                .find_map(|line| line.strip_prefix("populated "));
            if populated == Some("0") {
                break;
            }
            if Instant::now() >= deadline {
                return Err("qualification cgroup remained populated after kill".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        let status = child.wait().map_err(string_error)?;
        if status.signal() != Some(rustix::process::Signal::KILL.as_raw()) {
            return Err("qualification agent was not reaped with the exact SIGKILL status".into());
        }
        cgroup.validate_identity()?;
        if remove {
            fs::remove_dir(&cgroup.path).map_err(string_error)?;
        }
        Ok(())
    }

    fn validate_agent_process_credentials(
        pid: u32,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<(), String> {
        let status = fs::read_to_string(format!("/proc/{pid}/status")).map_err(string_error)?;
        let values = |label: &str| -> Result<Vec<u32>, String> {
            status
                .lines()
                .find_map(|line| line.strip_prefix(label))
                .ok_or_else(|| format!("qualification agent status omits {label}"))?
                .split_ascii_whitespace()
                .map(|value| value.parse::<u32>().map_err(string_error))
                .collect()
        };
        let uids = values("Uid:")?;
        let gids = values("Gid:")?;
        let groups = values("Groups:")?;
        if uids.len() != 4
            || uids.iter().any(|uid| *uid != expected_uid)
            || gids.len() != 4
            || gids.iter().any(|gid| *gid != expected_gid)
            || !groups.is_empty()
        {
            return Err(
                "qualification agent retained an unexpected uid, gid, or supplementary group"
                    .into(),
            );
        }
        Ok(())
    }

    fn reject_unexpected_environment() -> Result<(), String> {
        const ALLOWED: &[&str] = &[
            "AUTHS_QUALIFICATION_AGENT_CONFIG_SHA256",
            "AUTHS_QUALIFICATION_AGENT_GENERATION",
            "AUTHS_QUALIFICATION_AGENT_GID",
            "AUTHS_QUALIFICATION_AGENT_JOURNAL_PATH_SHA256",
            "AUTHS_QUALIFICATION_AGENT_LAUNCHER_SHA256",
            "AUTHS_QUALIFICATION_AGENT_SHA256",
            "AUTHS_QUALIFICATION_AGENT_STATE_DIRECTORY_SHA256",
            "AUTHS_QUALIFICATION_AGENT_UID",
            "AUTHS_QUALIFICATION_ATTESTER_REVISION",
            "AUTHS_QUALIFICATION_CANDIDATE_REVISION",
            "AUTHS_QUALIFICATION_CLIENT_PROXY_SOURCE_SHA256",
            "AUTHS_QUALIFICATION_CREDENTIAL_BROKER_SOURCE_SHA256",
            "AUTHS_QUALIFICATION_CONTROLLER_NONCE_SHA256",
            "AUTHS_QUALIFICATION_CONTROL_OPERATION_ID",
            "AUTHS_QUALIFICATION_CRASH_CONTROLLER_SHA256",
            "AUTHS_QUALIFICATION_DOMAIN",
            "AUTHS_QUALIFICATION_JOURNAL_READER_KEY_ID",
            "AUTHS_QUALIFICATION_JOURNAL_READER_SHA256",
            "AUTHS_QUALIFICATION_JOURNAL_READER_SOURCE_IDENTITY",
            "AUTHS_QUALIFICATION_JOURNAL_READER_UID",
            "AUTHS_QUALIFICATION_LEDGER_ID",
            "AUTHS_QUALIFICATION_PHASE_INDEX",
            "AUTHS_QUALIFICATION_PROTECTED_ENVIRONMENT",
            "AUTHS_QUALIFICATION_PROVIDER_RUN_ID",
            "AUTHS_QUALIFICATION_RECEIPT_VERIFIER_SOURCE_SHA256",
            "AUTHS_QUALIFICATION_SESSION_NONCE_SHA256",
            "AUTHS_QUALIFICATION_SOURCE_CONTEXT_SHA256",
            "AUTHS_QUALIFICATION_SUPERVISOR_GENERATION",
            "AUTHS_QUALIFICATION_SUPERVISOR_SOURCE_IDENTITY",
            "AUTHS_QUALIFICATION_SUPERVISOR_SOURCE_SHA256",
            "AUTHS_QUALIFICATION_SUPERVISOR_SOURCE_UID",
            "AUTHS_QUALIFICATION_TARGET",
            "AUTHS_QUALIFICATION_WORKFLOW_PATH",
            "AUTHS_QUALIFICATION_WORKFLOW_REVISION",
            "GITHUB_REPOSITORY_ID",
            "GITHUB_RUN_ATTEMPT",
            "GITHUB_RUN_ID",
        ];
        for (name, _) in env::vars_os() {
            let name = name
                .to_str()
                .ok_or_else(|| "non-UTF-8 inherited environment name is forbidden".to_owned())?;
            if !ALLOWED.contains(&name) {
                return Err(format!(
                    "unexpected inherited environment is forbidden: {name}"
                ));
            }
        }
        Ok(())
    }

    fn required_env(name: &str) -> Result<String, String> {
        env::var(name).map_err(|_| format!("missing protected environment value {name}"))
    }
    fn now_unix_seconds() -> Result<u64, String> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(string_error)?
            .as_secs())
    }
    fn path_string(path: &Path) -> Result<&str, String> {
        path.to_str()
            .ok_or_else(|| "protected path is not UTF-8".to_owned())
    }
    fn string_error(error: impl std::fmt::Display) -> String {
        error.to_string()
    }
    fn usage() -> String {
        "usage: qualification-crash-controller run-phase --admin-socket <path> --agent <candidate-agent> --agent-config <config> --agent-gid <protected-distinct-gid> --agent-launcher <protected-launcher> --launcher-ledger-plan <root-owned-canonical-ledger-plan> --agent-socket <path> --agent-state-directory <path> --agent-uid <protected-distinct-uid> --cgroup <new-delegated-cgroup> --client-proxy-control-socket <protected-reader-control-socket> --credential-broker-control-socket <protected-reader-control-socket> --credential-broker-socket <protected-reader-socket> --qualification-connection-store-template <broker-owned-public-store> --decision-supervisor-socket <protected-one-shot-socket> --journal-reader-socket <protected-session-socket> --ledger-plan <owner-only-canonical-ledger-plan> --phase-index <index> --principal <principal> --profile-state-reader-socket <protected-reader-socket> --provider-observer-socket <protected-reader-socket> --provider-proxy-socket <protected-reader-socket> --provider-proxy-checkpoint-socket <protected-reader-checkpoint-socket> --provider-proxy-control-socket <protected-reader-control-socket> --receipt-trust <anchors> --receipt-verifier-socket <protected-reader-socket> --scenario <id> --sequencer-socket <protected-append-socket> --signer-socket <protected-signer-socket> --source-trust <registry>".into()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn every_journal_owned_failpoint_has_one_exact_boundary() {
            use QualificationFailpoint as Failpoint;
            use QualificationJournalBoundaryKindV1 as Boundary;

            let cases = [
                (Failpoint::AfterDecision, true, None),
                (Failpoint::AfterCommand, false, Some(Boundary::Command)),
                (
                    Failpoint::AfterEntryMarker,
                    false,
                    Some(Boundary::ProviderEntry),
                ),
                (
                    Failpoint::AfterProviderResult,
                    false,
                    Some(Boundary::ProviderResult),
                ),
                (
                    Failpoint::AfterObservation,
                    false,
                    Some(Boundary::Observation),
                ),
                (
                    Failpoint::AfterExecutionReceipt,
                    false,
                    Some(Boundary::ExecutionReceipt),
                ),
                (Failpoint::AfterTerminal, false, Some(Boundary::Terminal)),
            ];
            for (failpoint, decision, boundary) in cases {
                let boundaries = boundary.into_iter().collect::<Vec<_>>();
                assert!(phase_crash_boundary_reached(
                    Some(failpoint),
                    decision,
                    &boundaries
                ));
                assert!(!phase_crash_boundary_reached(Some(failpoint), false, &[]));
            }
        }

        #[test]
        fn non_journal_failpoints_require_their_owned_checkpoint() {
            let all_boundaries = [
                QualificationJournalBoundaryKindV1::Decision,
                QualificationJournalBoundaryKindV1::Replay,
                QualificationJournalBoundaryKindV1::Command,
                QualificationJournalBoundaryKindV1::ProviderEntry,
                QualificationJournalBoundaryKindV1::ProviderResult,
                QualificationJournalBoundaryKindV1::Observation,
                QualificationJournalBoundaryKindV1::ExecutionReceipt,
                QualificationJournalBoundaryKindV1::RecoveryRequired,
                QualificationJournalBoundaryKindV1::Terminal,
                QualificationJournalBoundaryKindV1::Status,
                QualificationJournalBoundaryKindV1::Recovery,
            ];
            for failpoint in [
                QualificationFailpoint::BeforeDecision,
                QualificationFailpoint::AfterReservation,
                QualificationFailpoint::AfterReread,
                QualificationFailpoint::AfterLease,
                QualificationFailpoint::AfterRequestWrite,
            ] {
                assert!(!phase_crash_boundary_reached(
                    Some(failpoint),
                    true,
                    &all_boundaries,
                ));
            }
            assert_eq!(QualificationFailpoint::ALL.len(), 12);
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("qualification crash controller is supported only on Linux");
    std::process::ExitCode::FAILURE
}
