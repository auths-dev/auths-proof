//! Fixed-purpose protected launcher for the qualification-only local agent.
//!
//! The launcher is the controller's direct child. It blocks before executing
//! candidate code, allowing the controller to pin its pidfd and move the
//! process into the delegated cgroup. Only the exact release message permits
//! an fd-pinned qualification-agent executable to replace this process.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux {
    use auths_profile_kit::{
        QualificationEvidenceLedgerPlanV1, QualificationFailpoint,
        QualificationInstalledClientInvocation,
        qualification_plan_is_provider_free_configuration_mismatch,
        qualification_state_directory_commitment,
    };
    use auths_qualification_supervisor::{
        QualificationPythonRuntimeClosure, qualification_candidate_cgroup_binds_prefix,
        qualification_candidate_sandbox_policy_sha256, qualification_python_runtime_closure,
    };
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use rustix::{
        fs::{
            AtFlags, MemfdFlags, Mode, OFlags, RenameFlags, ResolveFlags, SealFlags, chown, fchown,
            fcntl_add_seals, fcntl_get_seals, memfd_create, open, openat, openat2, renameat_with,
            unlinkat,
        },
        io::{FdFlags, fcntl_setfd},
        mount::{
            MountFlags, MountPropagationFlags, mount, mount_bind, mount_change, mount_remount,
        },
    };
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch, apply_filter,
    };
    use sha2::{Digest as _, Sha256};
    use std::{
        collections::{BTreeMap, BTreeSet},
        env,
        fs::{self, File},
        io::{Read as _, Seek as _, SeekFrom, Write as _},
        os::{
            fd::AsRawFd as _,
            unix::{
                fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
                process::CommandExt as _,
            },
        },
        path::{Component, Path, PathBuf},
        process::{Command, ExitCode, Stdio},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    const RELEASE: &[u8] = b"AUTHS-QUALIFICATION-LAUNCH/1\n";
    const MAX_EXECUTABLE_BYTES: u64 = 536_870_912;
    const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_CONNECTION_STORE_BYTES: u64 = 4 * 1024 * 1024;
    const CONNECTION_STORE_NAME: &str = "connections.cbor";
    const CONNECTION_STORE_STAGE_NAME: &str = ".connections.cbor.qualification-stage";
    const CANDIDATE_WORKLOAD_RELEASE: &[u8] = b"AUTHS-QUALIFICATION-CANDIDATE-WORKLOAD/1\n";
    const MAX_CANDIDATE_REQUEST_BYTES: usize = 16_777_216;
    const MAX_CANDIDATE_RESULT_BYTES: usize = 16_777_216;
    const MAX_CANDIDATE_STDERR_BYTES: usize = 1_048_576;
    const MAX_WHEEL_MEMBERS: usize = 20_000;
    const MAX_WHEEL_MEMBER_BYTES: u64 = 67_108_864;
    const MAX_WHEEL_BYTES: u64 = 536_870_912;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum LaunchMode {
        Ordinary,
        Crash(QualificationFailpoint),
        Restart(Option<QualificationFailpoint>),
    }

    impl LaunchMode {
        const fn failpoint(self) -> Option<QualificationFailpoint> {
            match self {
                Self::Ordinary | Self::Restart(None) => None,
                Self::Crash(failpoint) | Self::Restart(Some(failpoint)) => Some(failpoint),
            }
        }

        const fn restarting(self) -> bool {
            matches!(self, Self::Restart(_))
        }
    }

    pub(super) fn main() -> ExitCode {
        let arguments = env::args().skip(1).collect::<Vec<_>>();
        let result = match arguments.first().map(String::as_str) {
            Some("launch") => run_agent(&arguments),
            Some("candidate-workload") => run_candidate_workload(&arguments),
            Some("candidate-init") => run_candidate_init(&arguments),
            _ => Err(usage()),
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("qualification agent launcher failed closed: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn run_agent(arguments: &[String]) -> Result<(), String> {
        let (mode, values) = launch_values(arguments)?;
        reject_secret_environment()?;
        let ledger_plan_path = Path::new(value(&values, "--ledger-plan")?);
        require_normalized_absolute(ledger_plan_path)?;
        let plan = read_protected_ledger_plan(ledger_plan_path)?;
        let controller_pid = canonical_u32(value(&values, "--controller-pid")?)?;
        let controller_start_time_ticks = authenticate_controller(&plan, controller_pid)?;
        let agent = Path::new(value(&values, "--agent")?);
        for path in [
            agent,
            Path::new(value(&values, "--config")?),
            Path::new(value(&values, "--state-directory")?),
            Path::new(value(&values, "--agent-socket")?),
            Path::new(value(&values, "--admin-socket")?),
            Path::new(value(&values, "--credential-broker-socket")?),
            Path::new(value(&values, "--provider-proxy-socket")?),
            Path::new(value(&values, "--qualification-connection-store-template")?),
        ] {
            require_normalized_absolute(path)?;
        }
        let uid = canonical_u32(value(&values, "--agent-uid")?)?;
        let gid = canonical_u32(value(&values, "--agent-gid")?)?;
        let client_proxy_uid = canonical_u32(value(&values, "--client-proxy-reader-uid")?)?;
        let credential_broker_uid =
            canonical_u32(value(&values, "--credential-broker-reader-uid")?)?;
        let provider_proxy_uid = canonical_u32(value(&values, "--provider-proxy-reader-uid")?)?;
        let expected_agent_sha256 = value(&values, "--agent-sha256")?;
        let expected_config_sha256 = value(&values, "--config-sha256")?;
        let expected_client_proxy_sha256 = value(&values, "--client-proxy-artifact-sha256")?;
        let expected_credential_broker_sha256 =
            value(&values, "--credential-broker-artifact-sha256")?;
        let expected_provider_proxy_sha256 = value(&values, "--provider-proxy-artifact-sha256")?;
        let source_context_sha256 = value(&values, "--source-context-sha256")?;
        let recovery_key_id = value(&values, "--recovery-key-id")?;
        let recovery_public_key = value(&values, "--recovery-public-key-base64url")?;
        let expected_state_directory_sha256 = value(&values, "--state-directory-sha256")?;
        let mut decoded_recovery_public_key = [0_u8; 32];
        if uid != plan.agent_uid
            || gid != plan.agent_gid
            || expected_agent_sha256 != plan.agent_executable_sha256
            || recovery_key_id != plan.recovery_key_id
            || recovery_public_key != plan.recovery_public_key_base64url
            || uid == 0
            || gid == 0
            || client_proxy_uid == 0
            || client_proxy_uid == uid
            || credential_broker_uid == 0
            || credential_broker_uid == uid
            || credential_broker_uid == client_proxy_uid
            || provider_proxy_uid == 0
            || provider_proxy_uid == uid
            || provider_proxy_uid == client_proxy_uid
            || provider_proxy_uid == credential_broker_uid
            || controller_pid == 0
            || !digest(expected_agent_sha256)
            || !digest(expected_config_sha256)
            || !digest(expected_client_proxy_sha256)
            || !digest(expected_credential_broker_sha256)
            || !digest(expected_provider_proxy_sha256)
            || !digest(source_context_sha256)
            || !registered_token(recovery_key_id)
            || Base64UrlUnpadded::decode(recovery_public_key, &mut decoded_recovery_public_key)
                .is_err()
            || !digest(expected_state_directory_sha256)
            || rustix::process::Pid::as_raw(rustix::process::getppid()) != controller_pid as i32
        {
            return Err("qualification launch identity is malformed".into());
        }
        let generation = canonical_u32(value(&values, "--agent-generation")?)?;
        if generation == 0 {
            return Err("qualification agent generation is malformed".into());
        }
        if mode.failpoint().is_some() {
            let control_id = value(&values, "--control-operation-id")?;
            let nonce_sha256 = value(&values, "--controller-nonce-sha256")?;
            if !registered_token(control_id) || !digest(nonce_sha256) {
                return Err("qualification crash identity is malformed".into());
            }
        }
        let mut source = File::from(
            open(
                agent,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let metadata = source.metadata().map_err(string_error)?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_EXECUTABLE_BYTES
        {
            return Err("qualification agent is not a bounded regular executable".into());
        }
        let mut hasher = Sha256::new();
        let mut executable = File::from(
            memfd_create(
                "auths-qualification-agent",
                MemfdFlags::ALLOW_SEALING | MemfdFlags::EXEC,
            )
            .map_err(string_error)?,
        );
        let mut total = 0_u64;
        let mut chunk = [0_u8; 65_536];
        loop {
            let length = source.read(&mut chunk).map_err(string_error)?;
            if length == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(length).map_err(string_error)?)
                .ok_or_else(|| "qualification agent byte count overflow".to_owned())?;
            if total > MAX_EXECUTABLE_BYTES {
                return Err("qualification agent exceeds its byte bound".into());
            }
            hasher.update(&chunk[..length]);
            executable
                .write_all(&chunk[..length])
                .map_err(string_error)?;
        }
        let after = source.metadata().map_err(string_error)?;
        if total != metadata.len()
            || metadata.dev() != after.dev()
            || metadata.ino() != after.ino()
            || metadata.len() != after.len()
            || hex::encode(hasher.finalize()) != expected_agent_sha256
        {
            return Err("qualification agent differs from the protected digest".into());
        }
        executable.flush().map_err(string_error)?;
        executable.sync_all().map_err(string_error)?;
        let seals = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
        fcntl_add_seals(&executable, seals).map_err(string_error)?;
        if fcntl_get_seals(&executable).map_err(string_error)? != seals {
            return Err("qualification agent executable memfd is not exactly sealed".into());
        }
        executable.seek(SeekFrom::Start(0)).map_err(string_error)?;
        let mut sealed_hasher = Sha256::new();
        let mut sealed_total = 0_u64;
        loop {
            let length = executable.read(&mut chunk).map_err(string_error)?;
            if length == 0 {
                break;
            }
            sealed_total = sealed_total
                .checked_add(u64::try_from(length).map_err(string_error)?)
                .ok_or_else(|| "sealed qualification agent byte count overflow".to_owned())?;
            sealed_hasher.update(&chunk[..length]);
        }
        if sealed_total != total || hex::encode(sealed_hasher.finalize()) != expected_agent_sha256 {
            return Err("sealed qualification agent differs from the protected digest".into());
        }

        let config_path = Path::new(value(&values, "--config")?);
        let mut config_source = File::from(
            open(
                config_path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let config_metadata = config_source.metadata().map_err(string_error)?;
        if !config_metadata.file_type().is_file()
            || config_metadata.nlink() != 1
            || config_metadata.uid() != rustix::process::geteuid().as_raw()
            || config_metadata.mode() & 0o022 != 0
            || config_metadata.len() == 0
            || config_metadata.len() > MAX_CONFIG_BYTES
        {
            return Err("qualification agent config is not one bounded protected file".into());
        }
        let mut config = File::from(
            memfd_create(
                "auths-qualification-agent-config",
                MemfdFlags::ALLOW_SEALING,
            )
            .map_err(string_error)?,
        );
        let mut config_hasher = Sha256::new();
        let mut config_total = 0_u64;
        loop {
            let length = config_source.read(&mut chunk).map_err(string_error)?;
            if length == 0 {
                break;
            }
            config_total = config_total
                .checked_add(u64::try_from(length).map_err(string_error)?)
                .ok_or_else(|| "qualification config byte count overflow".to_owned())?;
            if config_total > MAX_CONFIG_BYTES {
                return Err("qualification config exceeds its byte bound".into());
            }
            config_hasher.update(&chunk[..length]);
            config.write_all(&chunk[..length]).map_err(string_error)?;
        }
        let config_after = config_source.metadata().map_err(string_error)?;
        if config_total != config_metadata.len()
            || config_metadata.dev() != config_after.dev()
            || config_metadata.ino() != config_after.ino()
            || config_metadata.len() != config_after.len()
            || hex::encode(config_hasher.finalize()) != expected_config_sha256
        {
            return Err("qualification config differs from the protected digest".into());
        }
        config.flush().map_err(string_error)?;
        config.sync_all().map_err(string_error)?;
        fcntl_add_seals(&config, seals).map_err(string_error)?;
        if fcntl_get_seals(&config).map_err(string_error)? != seals {
            return Err("qualification config memfd is not exactly sealed".into());
        }
        config.seek(SeekFrom::Start(0)).map_err(string_error)?;
        let mut sealed_config_hasher = Sha256::new();
        let mut sealed_config_total = 0_u64;
        loop {
            let length = config.read(&mut chunk).map_err(string_error)?;
            if length == 0 {
                break;
            }
            sealed_config_total = sealed_config_total
                .checked_add(u64::try_from(length).map_err(string_error)?)
                .ok_or_else(|| "sealed qualification config byte count overflow".to_owned())?;
            sealed_config_hasher.update(&chunk[..length]);
        }
        if sealed_config_total != config_total
            || hex::encode(sealed_config_hasher.finalize()) != expected_config_sha256
        {
            return Err("sealed qualification config differs from the protected digest".into());
        }

        let state_directory_path = Path::new(value(&values, "--state-directory")?);
        let root = File::from(
            open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let relative = state_directory_path
            .strip_prefix("/")
            .map_err(string_error)?;
        let state_directory = File::from(
            openat2(
                &root,
                relative,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(string_error)?,
        );
        let state_metadata = state_directory.metadata().map_err(string_error)?;
        let state_path = state_directory_path
            .to_str()
            .ok_or_else(|| "qualification state path is not UTF-8".to_owned())?;
        let actual_state_directory_sha256 = qualification_state_directory_commitment(
            state_path,
            state_metadata.dev(),
            state_metadata.ino(),
            state_metadata.uid(),
            state_metadata.mode() & 0o777,
        )
        .map_err(string_error)?;
        if state_metadata.uid() != uid
            || state_metadata.mode() & 0o777 != 0o700
            || actual_state_directory_sha256 != expected_state_directory_sha256
        {
            return Err("qualification state directory differs from its protected identity".into());
        }
        if qualification_plan_is_provider_free_configuration_mismatch(&plan) {
            if read_agent_store_at(&state_directory, CONNECTION_STORE_NAME, uid, false)?.is_some()
                || read_agent_store_at(&state_directory, CONNECTION_STORE_STAGE_NAME, uid, true)?
                    .is_some()
            {
                return Err(
                    "provider-free qualification state contains connection material".into(),
                );
            }
        } else {
            install_public_connection_store(
                Path::new(value(&values, "--qualification-connection-store-template")?),
                &state_directory,
                credential_broker_uid,
                uid,
                gid,
            )?;
        }
        // The exact directory descriptor is intentionally the only additional
        // descriptor inherited by candidate code. Its identity is rechecked by
        // the qualification agent before any state member is opened.
        fcntl_setfd(&state_directory, FdFlags::empty()).map_err(string_error)?;

        // The launcher is deliberately single-threaded. Clear every inherited
        // supplementary group while it is still privileged so candidate code
        // cannot retain controller/source group capabilities after uid/gid
        // reduction.
        rustix::thread::set_thread_groups(&[]).map_err(string_error)?;

        let mut release = [0_u8; RELEASE.len()];
        std::io::stdin()
            .read_exact(&mut release)
            .map_err(string_error)?;
        if release != RELEASE {
            return Err("qualification launch release message is invalid".into());
        }

        let executable_path = format!("/proc/self/fd/{}", executable.as_raw_fd());
        let config_fd = config.as_raw_fd().to_string();
        let state_directory_fd = state_directory.as_raw_fd().to_string();
        if mode.restarting() {
            remove_stale_agent_socket(Path::new(value(&values, "--agent-socket")?), uid, gid)?;
            remove_stale_agent_socket(Path::new(value(&values, "--admin-socket")?), uid, gid)?;
        }
        let agent_arguments =
            build_agent_arguments(mode, &values, &config_fd, &state_directory_fd)?;
        authenticate_controller_unchanged(&plan, controller_pid, controller_start_time_ticks)?;
        let error = Command::new(executable_path)
            .args(agent_arguments)
            .env_clear()
            .gid(gid)
            .uid(uid)
            .exec();
        Err(format!("could not execute qualification agent: {error}"))
    }

    fn run_candidate_workload(arguments: &[String]) -> Result<(), String> {
        let values = exact_flags(
            arguments,
            "candidate-workload",
            &[
                "--cgroup",
                "--client-proxy-reader-uid",
                "--controller-pid",
                "--ledger-plan",
                "--phase-index",
                "--profile",
                "--python",
                "--request-sha256",
                "--sandbox-root",
                "--scenario",
                "--wheel",
                "--workload-gid",
                "--workload-uid",
            ],
        )?;
        reject_secret_environment()?;
        let plan_path = Path::new(value(&values, "--ledger-plan")?);
        let python = Path::new(value(&values, "--python")?);
        let wheel = Path::new(value(&values, "--wheel")?);
        let profile = Path::new(value(&values, "--profile")?);
        let cgroup = Path::new(value(&values, "--cgroup")?);
        let sandbox_root = Path::new(value(&values, "--sandbox-root")?);
        for path in [plan_path, python, wheel, profile, cgroup, sandbox_root] {
            require_normalized_absolute(path)?;
        }
        if !cgroup.starts_with("/sys/fs/cgroup") || cgroup == Path::new("/sys/fs/cgroup") {
            return Err("candidate workload cgroup path is outside delegated cgroup v2".into());
        }
        let plan = read_protected_ledger_plan(plan_path)?;
        if !qualification_candidate_cgroup_binds_prefix(
            cgroup,
            &plan.candidate_sandbox.linux_cgroup_prefix,
        ) {
            return Err("candidate workload cgroup is outside its signed prefix".into());
        }
        let controller_pid = canonical_u32(value(&values, "--controller-pid")?)?;
        let controller_start_time_ticks = authenticate_controller(&plan, controller_pid)?;
        let phase_index = canonical_u32(value(&values, "--phase-index")?)?;
        let phase_index = u8::try_from(phase_index).map_err(string_error)?;
        let client_proxy_reader_uid = canonical_u32(value(&values, "--client-proxy-reader-uid")?)?;
        let workload_uid = canonical_u32(value(&values, "--workload-uid")?)?;
        let workload_gid = canonical_u32(value(&values, "--workload-gid")?)?;
        let scenario = value(&values, "--scenario")?;
        let request_sha256 = value(&values, "--request-sha256")?;
        let phase = plan
            .phases
            .iter()
            .find(|phase| phase.scenario_id == scenario && phase.phase_index == phase_index)
            .ok_or_else(|| "candidate workload phase is absent from the ledger plan".to_owned())?;
        if client_proxy_reader_uid == 0
            || client_proxy_reader_uid == workload_uid
            || client_proxy_reader_uid == plan.supervisor_controller_uid
            || workload_uid != plan.candidate_sandbox.workload_uid
            || workload_gid != plan.candidate_sandbox.workload_gid
            || !digest(request_sha256)
            || qualification_candidate_sandbox_policy_sha256()
                != plan.candidate_sandbox.policy_sha256
        {
            return Err("candidate workload identity differs from the signed plan".into());
        }
        let launcher = File::open("/proc/self/exe").map_err(string_error)?;
        if sha256_reader(launcher, MAX_EXECUTABLE_BYTES)? != plan.agent_launcher_artifact_sha256 {
            return Err("candidate workload launcher differs from the signed plan".into());
        }
        let runtime = qualification_python_runtime_closure(python)?;
        if runtime.executable_sha256 != plan.candidate_sandbox.executable_sha256
            || runtime.runtime_sha256 != plan.candidate_sandbox.python_runtime_sha256
            || sha256_file(wheel, MAX_EXECUTABLE_BYTES)?
                != plan.candidate_sandbox.python_wheel_sha256
            || sha256_file(profile, MAX_EXECUTABLE_BYTES)?
                != plan.candidate_sandbox.python_profile_sha256
        {
            return Err("candidate workload artifacts differ from the signed plan".into());
        }
        let membership = std::fs::read_to_string("/proc/self/cgroup").map_err(string_error)?;
        if membership.trim() != expected_cgroup_membership(cgroup)? {
            return Err("candidate workload launcher is outside its exact cgroup".into());
        }
        for (name, expected) in [
            ("pids.max", "64"),
            ("memory.max", "536870912"),
            ("memory.swap.max", "0"),
            ("cpu.max", "60000 100000"),
        ] {
            if std::fs::read_to_string(cgroup.join(name))
                .map_err(string_error)?
                .trim()
                != expected
            {
                return Err(format!(
                    "candidate workload cgroup differs from exact {name} policy"
                ));
            }
        }
        let mut release = [0_u8; CANDIDATE_WORKLOAD_RELEASE.len()];
        std::io::stdin()
            .read_exact(&mut release)
            .map_err(string_error)?;
        if release != CANDIDATE_WORKLOAD_RELEASE {
            return Err("candidate workload release message is invalid".into());
        }
        let request = read_candidate_frame(&mut std::io::stdin(), MAX_CANDIDATE_REQUEST_BYTES)?;
        if hex::encode(Sha256::digest(&request)) != request_sha256 {
            return Err("candidate workload request differs from its protected digest".into());
        }
        let invocation =
            QualificationInstalledClientInvocation::from_json(&request).map_err(string_error)?;
        if invocation.scenario_id() != phase.scenario_id
            || invocation.phase_index() != phase.phase_index
            || invocation.role() != phase.role
        {
            return Err("candidate workload invocation differs from its immutable phase".into());
        }
        authenticate_controller_unchanged(&plan, controller_pid, controller_start_time_ticks)?;
        execute_candidate_workload(
            &plan,
            plan_path,
            python,
            wheel,
            profile,
            sandbox_root,
            &runtime,
            &invocation,
            client_proxy_reader_uid,
            controller_pid,
            controller_start_time_ticks,
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn execute_candidate_workload(
        plan: &QualificationEvidenceLedgerPlanV1,
        plan_path: &Path,
        python: &Path,
        wheel: &Path,
        profile: &Path,
        sandbox_root: &Path,
        runtime: &QualificationPythonRuntimeClosure,
        invocation: &QualificationInstalledClientInvocation,
        client_proxy_reader_uid: u32,
        controller_pid: u32,
        controller_start_time_ticks: u64,
    ) -> Result<(), String> {
        prepare_candidate_sandbox_root(sandbox_root)?;
        unshare_candidate_namespaces()?;
        mount_change(
            "/",
            MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
        )
        .map_err(string_error)?;
        mount(
            "tmpfs",
            sandbox_root,
            "tmpfs",
            MountFlags::NOSUID | MountFlags::NODEV,
            Some(c"mode=0700,size=1073741824"),
        )
        .map_err(string_error)?;

        let sandbox_python = copy_python_runtime(sandbox_root, python, runtime)?;
        install_wheel(sandbox_root, runtime, wheel)?;
        install_profile(sandbox_root, &plan.domain, profile)?;
        install_candidate_socket_pair(
            sandbox_root,
            invocation.agent_socket(),
            invocation.result_socket(),
            client_proxy_reader_uid,
            plan.candidate_sandbox.workload_gid,
        )?;
        for directory in ["proc", "tmp", "dev"] {
            create_sandbox_directory(&sandbox_root.join(directory), 0o755)?;
        }
        for (source, target) in [
            ("/dev/null", sandbox_root.join("dev/null")),
            ("/dev/urandom", sandbox_root.join("dev/urandom")),
        ] {
            create_sandbox_file(&target, 0o444)?;
            mount_bind(source, &target).map_err(string_error)?;
            mount_remount(
                &target,
                MountFlags::BIND | MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NOEXEC,
                "",
            )
            .map_err(string_error)?;
        }

        let invocation_bytes = invocation.to_json().map_err(string_error)?;
        let invocation_path = sandbox_root.join("run/auths/invocation.json");
        write_sandbox_file(&invocation_path, &invocation_bytes, 0o444)?;
        let input = invocation.canonical_input().map_err(string_error)?;
        let input_path = sandbox_root.join("run/auths/input.json");
        write_sandbox_file(&input_path, &input, 0o444)?;
        fs::set_permissions(sandbox_root, fs::Permissions::from_mode(0o555))
            .map_err(string_error)?;
        mount_remount(
            sandbox_root,
            MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
            "",
        )
        .map_err(string_error)?;

        let self_path = "/proc/self/exe";
        let candidate_cgroup = expected_cgroup_from_proc_self()?;
        let controller_pid_value = controller_pid.to_string();
        let launcher_pid = std::process::id().to_string();
        let launcher_start_time_ticks = process_start_time_ticks(std::process::id())?.to_string();
        let plan_path_value = plan_path
            .to_str()
            .ok_or_else(|| "candidate plan path is not UTF-8".to_owned())?;
        let sandbox_root_value = sandbox_root
            .to_str()
            .ok_or_else(|| "candidate sandbox root is not UTF-8".to_owned())?;
        let workload_gid = plan.candidate_sandbox.workload_gid.to_string();
        let workload_uid = plan.candidate_sandbox.workload_uid.to_string();
        let (stage, stage_sha256) = candidate_init_stage()?;
        let mut child = Command::new(self_path)
            .args([
                "candidate-init",
                "--cgroup",
                &candidate_cgroup,
                "--controller-pid",
                &controller_pid_value,
                "--input",
                "/run/auths/input.json",
                "--invocation",
                "/run/auths/invocation.json",
                "--launcher-pid",
                &launcher_pid,
                "--launcher-start-time-ticks",
                &launcher_start_time_ticks,
                "--ledger-plan",
                plan_path_value,
                "--python",
                &sandbox_python,
                "--sandbox-root",
                sandbox_root_value,
                "--stage-sha256",
                &stage_sha256,
                "--workload-gid",
                &workload_gid,
                "--workload-uid",
                &workload_uid,
            ])
            .env_clear()
            .stdin(Stdio::from(stage))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(string_error)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "candidate init has no stdout".to_owned())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "candidate init has no stderr".to_owned())?;
        let output_worker =
            thread::spawn(move || read_bounded_pipe(stdout, MAX_CANDIDATE_RESULT_BYTES));
        let error_worker =
            thread::spawn(move || read_bounded_pipe(stderr, MAX_CANDIDATE_STDERR_BYTES));
        let status = child.wait().map_err(string_error)?;
        let output = output_worker
            .join()
            .map_err(|_| "candidate output reader panicked".to_owned())??;
        let errors = error_worker
            .join()
            .map_err(|_| "candidate stderr reader panicked".to_owned())??;
        if !status.success() || output.is_empty() || !errors.is_empty() {
            return Err("candidate workload did not produce one clean bounded result".into());
        }
        authenticate_controller_unchanged(plan, controller_pid, controller_start_time_ticks)?;
        write_candidate_frame(&mut std::io::stdout(), &output)?;
        std::io::stdout().flush().map_err(string_error)?;
        let mut trailing = [0_u8; 1];
        match std::io::stdin().read(&mut trailing).map_err(string_error)? {
            0 => Err("candidate workload controller closed before cgroup teardown".into()),
            _ => Err("candidate workload controller sent a forbidden trailing frame".into()),
        }
    }

    fn run_candidate_init(arguments: &[String]) -> Result<(), String> {
        let values = exact_flags(
            arguments,
            "candidate-init",
            &[
                "--cgroup",
                "--controller-pid",
                "--input",
                "--invocation",
                "--launcher-pid",
                "--launcher-start-time-ticks",
                "--ledger-plan",
                "--python",
                "--sandbox-root",
                "--stage-sha256",
                "--workload-gid",
                "--workload-uid",
            ],
        )?;
        reject_secret_environment()?;
        let plan_path = Path::new(value(&values, "--ledger-plan")?);
        let cgroup = Path::new(value(&values, "--cgroup")?);
        for path in [plan_path, cgroup] {
            require_normalized_absolute(path)?;
        }
        let plan = read_protected_ledger_plan(plan_path)?;
        let controller_pid = canonical_u32(value(&values, "--controller-pid")?)?;
        let controller_start_time_ticks = authenticate_controller_process(&plan, controller_pid)?;
        let launcher_pid = canonical_u32(value(&values, "--launcher-pid")?)?;
        let launcher_start_time_ticks = value(&values, "--launcher-start-time-ticks")?
            .parse::<u64>()
            .map_err(string_error)?;
        if !rustix::process::geteuid().is_root() || launcher_pid == 0 {
            return Err("candidate init lacks its privileged namespace parent".into());
        }
        if hash_process_executable(launcher_pid)? != plan.agent_launcher_artifact_sha256
            || fs::read_to_string(format!("/proc/{launcher_pid}/cgroup"))
                .map_err(string_error)?
                .trim()
                != expected_cgroup_membership(cgroup)?
            || process_parent_pid(launcher_pid)? != controller_pid
            || process_parent_pid_from_status("/proc/self/status")? != launcher_pid
            || process_start_time_ticks(launcher_pid)? != launcher_start_time_ticks
            || qualification_candidate_sandbox_policy_sha256()
                != plan.candidate_sandbox.policy_sha256
        {
            return Err("candidate init parent differs from its protected launcher".into());
        }
        authenticate_candidate_init_stage(value(&values, "--stage-sha256")?)?;
        authenticate_candidate_namespaces(launcher_pid, controller_pid)?;
        if process_parent_pid_from_status("/proc/self/status")? != launcher_pid
            || process_start_time_ticks(launcher_pid)? != launcher_start_time_ticks
        {
            return Err("candidate init launcher changed before namespace setup".into());
        }
        let sandbox_root = Path::new(value(&values, "--sandbox-root")?);
        require_normalized_absolute(sandbox_root)?;
        let python = value(&values, "--python")?;
        let input = value(&values, "--input")?;
        let invocation_path = value(&values, "--invocation")?;
        for path in [python, input, invocation_path] {
            if !path.starts_with('/') || path.contains("/../") || path.contains("/./") {
                return Err("candidate init path is not one normalized sandbox path".into());
            }
        }
        let workload_uid = canonical_u32(value(&values, "--workload-uid")?)?;
        let workload_gid = canonical_u32(value(&values, "--workload-gid")?)?;
        if workload_uid == 0 || workload_gid == 0 {
            return Err("candidate init identity is privileged".into());
        }
        if workload_uid != plan.candidate_sandbox.workload_uid
            || workload_gid != plan.candidate_sandbox.workload_gid
        {
            return Err("candidate init identity differs from the signed plan".into());
        }
        if process_start_time_ticks(controller_pid)? != controller_start_time_ticks
            || hash_process_executable(controller_pid)?
                != plan.supervisor_controller_artifact_sha256
            || process_start_time_ticks(launcher_pid)? != launcher_start_time_ticks
        {
            return Err("candidate init protected process chain changed before chroot".into());
        }
        rustix::process::chroot(sandbox_root).map_err(string_error)?;
        env::set_current_dir("/").map_err(string_error)?;
        mount(
            "proc",
            "/proc",
            "proc",
            MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            None::<&std::ffi::CStr>,
        )
        .map_err(string_error)?;
        mount(
            "tmpfs",
            "/tmp",
            "tmpfs",
            MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            Some(c"mode=1777,size=67108864"),
        )
        .map_err(string_error)?;
        drop_candidate_privileges(workload_uid, workload_gid)?;
        install_candidate_seccomp()?;
        let invocation_bytes = fs::read(invocation_path).map_err(string_error)?;
        let invocation = QualificationInstalledClientInvocation::from_json(&invocation_bytes)
            .map_err(string_error)?;
        let input_bytes = fs::read(input).map_err(string_error)?;
        if invocation.canonical_input().map_err(string_error)? != input_bytes {
            return Err("candidate init input differs from its canonical invocation".into());
        }
        let input_file = File::open(input).map_err(string_error)?;
        let error = Command::new(python)
            .args(invocation.python_arguments())
            .env_clear()
            .env("PYTHONNOUSERSITE", "1")
            .env(
                "AUTHS_QUALIFICATION_CLIENT_RESULT_SOCKET",
                QualificationInstalledClientInvocation::sandbox_result_socket(),
            )
            .current_dir("/tmp")
            .stdin(Stdio::from(input_file))
            .exec();
        Err(format!("could not execute candidate Python: {error}"))
    }

    fn prepare_candidate_sandbox_root(path: &Path) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| "candidate sandbox root has no parent".to_owned())?;
        let parent_metadata = fs::symlink_metadata(parent).map_err(string_error)?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() == 0
            || parent_metadata.mode() & 0o022 != 0
        {
            return Err("candidate sandbox parent is not one protected runtime directory".into());
        }
        match fs::symlink_metadata(path) {
            Ok(_) => return Err("candidate sandbox root already exists".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(string_error(error)),
        }
        fs::create_dir(path).map_err(string_error)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(string_error)?;
        let metadata = fs::symlink_metadata(path).map_err(string_error)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o700
        {
            return Err("candidate sandbox root is not root-owned and private".into());
        }
        Ok(())
    }

    fn candidate_init_stage() -> Result<(File, String), String> {
        let mut nonce = [0_u8; 32];
        File::open("/dev/urandom")
            .map_err(string_error)?
            .read_exact(&mut nonce)
            .map_err(string_error)?;
        let mut stage = File::from(
            memfd_create(
                "auths-qualification-candidate-init-stage",
                MemfdFlags::ALLOW_SEALING,
            )
            .map_err(string_error)?,
        );
        stage.write_all(&nonce).map_err(string_error)?;
        stage.flush().map_err(string_error)?;
        stage.sync_all().map_err(string_error)?;
        let seals = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
        fcntl_add_seals(&stage, seals).map_err(string_error)?;
        if fcntl_get_seals(&stage).map_err(string_error)? != seals {
            return Err("candidate init stage is not exactly sealed".into());
        }
        Ok((stage, hex::encode(Sha256::digest(nonce))))
    }

    fn authenticate_candidate_init_stage(expected_sha256: &str) -> Result<(), String> {
        if !digest(expected_sha256) {
            return Err("candidate init stage descriptor is malformed".into());
        }
        let mut stage = File::open("/proc/self/fd/0").map_err(string_error)?;
        let metadata = stage.metadata().map_err(string_error)?;
        let seals = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.len() != 32
            || fcntl_get_seals(&stage).map_err(string_error)? != seals
        {
            return Err("candidate init stage is not one root-owned sealed memfd".into());
        }
        let mut nonce = [0_u8; 32];
        stage.read_exact(&mut nonce).map_err(string_error)?;
        let mut extra = [0_u8; 1];
        if stage.read(&mut extra).map_err(string_error)? != 0
            || hex::encode(Sha256::digest(nonce)) != expected_sha256
        {
            return Err("candidate init stage nonce differs from its handoff".into());
        }
        Ok(())
    }

    fn authenticate_candidate_namespaces(
        launcher_pid: u32,
        controller_pid: u32,
    ) -> Result<(), String> {
        if !rustix::process::getpid().is_init() {
            return Err("candidate init is not PID 1 in its private namespace".into());
        }
        for namespace in ["mnt", "net", "ipc", "uts"] {
            let current =
                fs::metadata(format!("/proc/self/ns/{namespace}")).map_err(string_error)?;
            let launcher = fs::metadata(format!("/proc/{launcher_pid}/ns/{namespace}"))
                .map_err(string_error)?;
            let controller = fs::metadata(format!("/proc/{controller_pid}/ns/{namespace}"))
                .map_err(string_error)?;
            if current.dev() != launcher.dev()
                || current.ino() != launcher.ino()
                || (current.dev() == controller.dev() && current.ino() == controller.ino())
            {
                return Err(format!(
                    "candidate init does not own one private {namespace} namespace"
                ));
            }
        }
        let current_pid = fs::metadata("/proc/self/ns/pid").map_err(string_error)?;
        let controller_pid_namespace =
            fs::metadata(format!("/proc/{controller_pid}/ns/pid")).map_err(string_error)?;
        if current_pid.dev() == controller_pid_namespace.dev()
            && current_pid.ino() == controller_pid_namespace.ino()
        {
            return Err("candidate init does not own a private PID namespace".into());
        }
        Ok(())
    }

    #[allow(deprecated)]
    fn unshare_candidate_namespaces() -> Result<(), String> {
        rustix::thread::unshare(
            rustix::thread::UnshareFlags::NEWNS
                | rustix::thread::UnshareFlags::NEWPID
                | rustix::thread::UnshareFlags::NEWNET
                | rustix::thread::UnshareFlags::NEWIPC
                | rustix::thread::UnshareFlags::NEWUTS,
        )
        .map_err(string_error)
    }

    fn copy_python_runtime(
        sandbox_root: &Path,
        python: &Path,
        runtime: &QualificationPythonRuntimeClosure,
    ) -> Result<String, String> {
        copy_runtime_tree(
            &runtime.root,
            &sandbox_root.join(relative_absolute(&runtime.root)?),
        )?;
        for external in &runtime.external_files {
            let destination = sandbox_root.join(relative_absolute(&external.sandbox_path)?);
            copy_regular_exact(
                &external.source,
                &destination,
                external.bytes,
                &external.sha256,
                0o555,
            )?;
        }
        let after = qualification_python_runtime_closure(python)?;
        if &after != runtime {
            return Err("candidate Python runtime changed while copied".into());
        }
        let sandbox_python = runtime.root.join(&runtime.executable_relative_path);
        sandbox_python
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| "candidate sandbox Python path is not UTF-8".to_owned())
    }

    fn copy_runtime_tree(source_root: &Path, target_root: &Path) -> Result<(), String> {
        create_sandbox_directory(target_root, 0o555)?;
        let mut pending = vec![PathBuf::new()];
        let mut members = 0_usize;
        while let Some(relative) = pending.pop() {
            let source_directory = source_root.join(&relative);
            let target_directory = target_root.join(&relative);
            let mut entries = fs::read_dir(&source_directory)
                .map_err(string_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(string_error)?;
            entries.sort_by_key(fs::DirEntry::file_name);
            for entry in entries {
                members = members
                    .checked_add(1)
                    .filter(|count| *count <= 100_000)
                    .ok_or_else(|| "candidate Python copy exceeds its member bound".to_owned())?;
                let name = entry.file_name();
                let name = name
                    .to_str()
                    .ok_or_else(|| "candidate Python runtime path is not UTF-8".to_owned())?;
                if name.is_empty() || name == "." || name == ".." || name.contains('\0') {
                    return Err("candidate Python runtime path is unsafe".into());
                }
                let child_relative = relative.join(name);
                let source = source_root.join(&child_relative);
                let target = target_root.join(&child_relative);
                let before = fs::symlink_metadata(&source).map_err(string_error)?;
                if before.is_dir() {
                    create_sandbox_directory(&target, 0o555)?;
                    pending.push(child_relative);
                } else if before.file_type().is_symlink() {
                    let link = fs::read_link(&source).map_err(string_error)?;
                    if link.is_absolute()
                        || link.components().any(|component| {
                            matches!(component, Component::ParentDir | Component::RootDir)
                        })
                    {
                        return Err("candidate Python runtime link escapes its prefix".into());
                    }
                    std::os::unix::fs::symlink(link, target).map_err(string_error)?;
                } else if before.is_file() && before.nlink() == 1 {
                    copy_regular_exact(
                        &source,
                        &target,
                        before.len(),
                        &sha256_file(&source, 536_870_912)?,
                        if before.mode() & 0o111 == 0 {
                            0o444
                        } else {
                            0o555
                        },
                    )?;
                } else {
                    return Err("candidate Python runtime contains an unsafe member".into());
                }
            }
        }
        Ok(())
    }

    fn copy_regular_exact(
        source: &Path,
        target: &Path,
        expected_bytes: u64,
        expected_sha256: &str,
        mode: u32,
    ) -> Result<(), String> {
        if let Some(parent) = target.parent() {
            create_sandbox_directory(parent, 0o555)?;
        }
        let mut input = File::from(
            open(
                source,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let before = input.metadata().map_err(string_error)?;
        if !before.is_file() || before.nlink() != 1 || before.len() != expected_bytes {
            return Err("candidate source member is not one exact regular file".into());
        }
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(target)
            .map_err(string_error)?;
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 65_536];
        loop {
            let length = input.read(&mut buffer).map_err(string_error)?;
            if length == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(length).map_err(string_error)?)
                .ok_or_else(|| "candidate member byte count overflow".to_owned())?;
            digest.update(&buffer[..length]);
            output.write_all(&buffer[..length]).map_err(string_error)?;
        }
        let after = input.metadata().map_err(string_error)?;
        if total != expected_bytes
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || hex::encode(digest.finalize()) != expected_sha256
        {
            return Err("candidate source member changed while copied".into());
        }
        output.flush().map_err(string_error)?;
        output.sync_all().map_err(string_error)?;
        fs::set_permissions(target, fs::Permissions::from_mode(mode)).map_err(string_error)?;
        Ok(())
    }

    fn create_sandbox_directory(path: &Path, mode: u32) -> Result<(), String> {
        let mut missing = Vec::new();
        let mut cursor = path;
        loop {
            match fs::symlink_metadata(cursor) {
                Ok(metadata) => {
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        return Err("candidate sandbox directory path is occupied".into());
                    }
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(cursor.to_path_buf());
                    cursor = cursor.parent().ok_or_else(|| {
                        "candidate sandbox directory has no existing ancestor".to_owned()
                    })?;
                }
                Err(error) => return Err(string_error(error)),
            }
        }
        for directory in missing.iter().rev() {
            fs::create_dir(directory).map_err(string_error)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o555))
                .map_err(string_error)?;
        }
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(string_error)
    }

    fn create_sandbox_file(path: &Path, mode: u32) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            create_sandbox_directory(parent, 0o755)?;
        }
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .map_err(string_error)?;
        Ok(())
    }

    fn write_sandbox_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_err(string_error)? > MAX_WHEEL_MEMBER_BYTES
        {
            return Err("candidate sandbox file exceeds its byte bound".into());
        }
        if let Some(parent) = path.parent() {
            create_sandbox_directory(parent, 0o755)?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(string_error)?;
        file.write_all(bytes).map_err(string_error)?;
        file.flush().map_err(string_error)?;
        file.sync_all().map_err(string_error)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(string_error)
    }

    fn install_candidate_socket_pair(
        sandbox_root: &Path,
        client_source: &str,
        result_source: &str,
        reader_uid: u32,
        workload_gid: u32,
    ) -> Result<(), String> {
        let client_source = Path::new(client_source);
        let result_source = Path::new(result_source);
        for source in [client_source, result_source] {
            require_normalized_absolute(source)?;
        }
        let source_parent = client_source
            .parent()
            .ok_or_else(|| "candidate client socket has no parent".to_owned())?;
        if result_source.parent() != Some(source_parent) {
            return Err("candidate workload sockets do not share one protected parent".into());
        }
        let parent_before = fs::symlink_metadata(source_parent).map_err(string_error)?;
        let client_before = fs::symlink_metadata(client_source).map_err(string_error)?;
        let result_before = fs::symlink_metadata(result_source).map_err(string_error)?;
        if !parent_before.is_dir()
            || parent_before.file_type().is_symlink()
            || parent_before.uid() != reader_uid
            || parent_before.gid() != workload_gid
            || parent_before.mode() & 0o777 != 0o710
            || !client_before.file_type().is_socket()
            || !result_before.file_type().is_socket()
            || client_before.uid() != reader_uid
            || result_before.uid() != reader_uid
            || client_before.gid() != workload_gid
            || result_before.gid() != workload_gid
            || client_before.mode() & 0o777 != 0o660
            || result_before.mode() & 0o777 != 0o660
            || client_before.nlink() != 1
            || result_before.nlink() != 1
        {
            return Err("candidate workload sockets differ from protected reader ownership".into());
        }

        let sandbox_parent = sandbox_root.join("run/auths");
        create_sandbox_directory(&sandbox_parent, 0o710)?;
        let sandbox_client = sandbox_parent.join("client.sock");
        let sandbox_result = sandbox_parent.join("result.sock");
        create_sandbox_file(&sandbox_client, 0o600)?;
        create_sandbox_file(&sandbox_result, 0o600)?;
        chown(
            &sandbox_parent,
            Some(rustix::process::Uid::from_raw(reader_uid)),
            Some(rustix::process::Gid::from_raw(workload_gid)),
        )
        .map_err(string_error)?;
        fs::set_permissions(&sandbox_parent, fs::Permissions::from_mode(0o710))
            .map_err(string_error)?;

        for (source, destination_name, source_before) in [
            (client_source, "client.sock", &client_before),
            (result_source, "result.sock", &result_before),
        ] {
            let destination = sandbox_parent.join(destination_name);
            mount_bind(source, &destination).map_err(string_error)?;
            mount_remount(
                &destination,
                MountFlags::BIND | MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                "",
            )
            .map_err(string_error)?;
            let source_after = fs::symlink_metadata(source).map_err(string_error)?;
            let destination_after = fs::symlink_metadata(&destination).map_err(string_error)?;
            if source_after.dev() != source_before.dev()
                || source_after.ino() != source_before.ino()
                || source_after.uid() != source_before.uid()
                || source_after.gid() != source_before.gid()
                || source_after.mode() != source_before.mode()
                || destination_after.dev() != source_before.dev()
                || destination_after.ino() != source_before.ino()
                || destination_after.uid() != reader_uid
                || destination_after.gid() != workload_gid
                || destination_after.mode() & 0o777 != 0o660
                || !destination_after.file_type().is_socket()
            {
                return Err("candidate workload socket changed while bind-mounted".into());
            }
        }
        let parent_after = fs::symlink_metadata(source_parent).map_err(string_error)?;
        if parent_after.dev() != parent_before.dev()
            || parent_after.ino() != parent_before.ino()
            || parent_after.uid() != parent_before.uid()
            || parent_after.gid() != parent_before.gid()
            || parent_after.mode() != parent_before.mode()
        {
            return Err("candidate workload socket parent changed during sandbox setup".into());
        }
        Ok(())
    }

    fn relative_absolute(path: &Path) -> Result<&Path, String> {
        require_normalized_absolute(path)?;
        path.strip_prefix("/").map_err(string_error)
    }

    fn read_bounded_pipe<R: Read>(mut reader: R, maximum: usize) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take(u64::try_from(maximum).map_err(string_error)? + 1)
            .read_to_end(&mut bytes)
            .map_err(string_error)?;
        if bytes.len() > maximum {
            return Err("candidate output exceeds its byte bound".into());
        }
        Ok(bytes)
    }

    fn write_candidate_frame<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() > MAX_CANDIDATE_RESULT_BYTES {
            return Err("candidate result frame exceeds its byte bound".into());
        }
        writer
            .write_all(
                &u32::try_from(bytes.len())
                    .map_err(string_error)?
                    .to_be_bytes(),
            )
            .map_err(string_error)?;
        writer.write_all(bytes).map_err(string_error)
    }

    fn install_wheel(
        sandbox_root: &Path,
        runtime: &QualificationPythonRuntimeClosure,
        wheel: &Path,
    ) -> Result<(), String> {
        let library = runtime.root.join("lib");
        let mut versions = fs::read_dir(&library)
            .map_err(string_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(string_error)?
            .into_iter()
            .filter(|entry| {
                entry.file_name().to_string_lossy().starts_with("python")
                    && entry.path().join("site-packages").is_dir()
            })
            .collect::<Vec<_>>();
        versions.sort_by_key(fs::DirEntry::file_name);
        if versions.len() != 1 {
            return Err("candidate Python runtime has no unique site-packages directory".into());
        }
        let site_packages = sandbox_root
            .join(relative_absolute(&runtime.root)?)
            .join("lib")
            .join(versions[0].file_name())
            .join("site-packages");
        let file = File::from(
            open(
                wheel,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let mut archive = zip::ZipArchive::new(file).map_err(string_error)?;
        if archive.len() == 0 || archive.len() > MAX_WHEEL_MEMBERS {
            return Err("candidate wheel member count exceeds its bound".into());
        }
        let mut names = BTreeSet::new();
        let mut total = 0_u64;
        for index in 0..archive.len() {
            let mut member = archive.by_index(index).map_err(string_error)?;
            let relative = member
                .enclosed_name()
                .ok_or_else(|| "candidate wheel member path is unsafe".to_owned())?;
            if relative.as_os_str().is_empty()
                || relative.is_absolute()
                || relative.components().any(|component| {
                    matches!(
                        component,
                        Component::RootDir | Component::CurDir | Component::ParentDir
                    )
                })
                || !names.insert(relative.clone())
                || member.is_symlink()
            {
                return Err("candidate wheel member roster is unsafe".into());
            }
            if member.is_dir() {
                create_sandbox_directory(&site_packages.join(relative), 0o555)?;
                continue;
            }
            if member
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 != 0o100000)
                || member.size() == 0
                || member.size() > MAX_WHEEL_MEMBER_BYTES
            {
                return Err("candidate wheel member is not one bounded regular file".into());
            }
            total = total
                .checked_add(member.size())
                .filter(|bytes| *bytes <= MAX_WHEEL_BYTES)
                .ok_or_else(|| "candidate wheel bytes exceed their bound".to_owned())?;
            let mut bytes =
                Vec::with_capacity(usize::try_from(member.size()).map_err(string_error)?);
            member
                .by_ref()
                .take(MAX_WHEEL_MEMBER_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(string_error)?;
            if u64::try_from(bytes.len()).map_err(string_error)? != member.size() {
                return Err("candidate wheel member changed while extracted".into());
            }
            write_sandbox_file(&site_packages.join(relative), &bytes, 0o444)?;
        }
        Ok(())
    }

    fn install_profile(sandbox_root: &Path, domain: &str, profile: &Path) -> Result<(), String> {
        if !matches!(domain, "opentofu" | "postgresql" | "stripe") {
            return Err("candidate profile domain is invalid".into());
        }
        let prefix = format!("auths-profile-{domain}/bindings/generated/{domain}/python/");
        let expected = [
            "README.md".to_owned(),
            "pyproject.toml".to_owned(),
            format!("src/auths_profiles/{domain}/__init__.py"),
            format!("src/auths_profiles/{domain}/generated.py"),
            format!("src/auths_profiles/{domain}/py.typed"),
        ];
        let archive = File::from(
            open(
                profile,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let decoder = zstd::Decoder::new(archive).map_err(string_error)?;
        let mut archive = tar::Archive::new(decoder);
        let mut files = BTreeMap::<String, Vec<u8>>::new();
        for entry in archive.entries().map_err(string_error)? {
            let entry = entry.map_err(string_error)?;
            let path = entry
                .path()
                .map_err(string_error)?
                .to_str()
                .ok_or_else(|| "candidate profile archive path is not UTF-8".to_owned())?
                .to_owned();
            let relative = path
                .strip_prefix(&prefix)
                .ok_or_else(|| "candidate profile archive prefix drifted".to_owned())?;
            if !entry.header().entry_type().is_file()
                || entry.header().mode().map_err(string_error)? != 0o644
                || !expected.iter().any(|candidate| candidate == relative)
                || files.contains_key(relative)
            {
                return Err("candidate profile archive roster is unsafe".into());
            }
            let mut bytes = Vec::new();
            entry
                .take(MAX_WHEEL_MEMBER_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(string_error)?;
            if bytes.is_empty()
                || u64::try_from(bytes.len()).map_err(string_error)? > MAX_WHEEL_MEMBER_BYTES
            {
                return Err("candidate profile member exceeds its bound".into());
            }
            files.insert(relative.to_owned(), bytes);
        }
        if files.keys().ne(expected.iter()) {
            return Err("candidate profile archive roster drifted".into());
        }
        let output = sandbox_root.join("opt/auths/profile");
        for (relative, bytes) in files {
            write_sandbox_file(&output.join(relative), &bytes, 0o444)?;
        }
        Ok(())
    }

    fn drop_candidate_privileges(uid: u32, gid: u32) -> Result<(), String> {
        use rustix::thread::{
            CapabilitiesSecureBits, CapabilitySet, CapabilitySets, set_capabilities,
            set_capabilities_secure_bits,
        };

        rustix::thread::set_thread_groups(&[]).map_err(string_error)?;
        let capability_last = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .map_err(string_error)?
            .trim()
            .parse::<u32>()
            .map_err(string_error)?;
        if capability_last >= u64::BITS {
            return Err("candidate kernel capability bound is unsupported".into());
        }
        for bit in 0..=capability_last {
            let capability = CapabilitySet::from_bits_retain(1_u64 << bit);
            rustix::thread::remove_capability_from_bounding_set(capability)
                .map_err(string_error)?;
        }
        rustix::thread::clear_ambient_capability_set().map_err(string_error)?;
        set_capabilities_secure_bits(
            CapabilitiesSecureBits::NO_ROOT
                | CapabilitiesSecureBits::NO_ROOT_LOCKED
                | CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE
                | CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE_LOCKED,
        )
        .map_err(string_error)?;
        let uid = rustix::process::Uid::from_raw(uid);
        let gid = rustix::process::Gid::from_raw(gid);
        rustix::thread::set_thread_res_gid(gid, gid, gid).map_err(string_error)?;
        rustix::thread::set_thread_res_uid(uid, uid, uid).map_err(string_error)?;
        set_capabilities(
            None,
            CapabilitySets {
                effective: CapabilitySet::empty(),
                permitted: CapabilitySet::empty(),
                inheritable: CapabilitySet::empty(),
            },
        )
        .map_err(string_error)?;
        rustix::thread::set_no_new_privs(true).map_err(string_error)?;
        Ok(())
    }

    fn install_candidate_seccomp() -> Result<(), String> {
        let mut rules = BTreeMap::new();
        for syscall in [
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_setpgid,
            libc::SYS_setsid,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_chroot,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_pidfd_open,
            libc::SYS_pidfd_getfd,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_reboot,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_kexec_load,
        ] {
            rules.insert(syscall, Vec::new());
        }
        let non_unix = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            u64::try_from(libc::AF_UNIX).map_err(string_error)?,
        )
        .map_err(string_error)?;
        rules.insert(
            libc::SYS_socket,
            vec![SeccompRule::new(vec![non_unix]).map_err(string_error)?],
        );
        let filter: BpfProgram = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(u32::try_from(libc::EPERM).map_err(string_error)?),
            TargetArch::try_from(env::consts::ARCH).map_err(string_error)?,
        )
        .map_err(string_error)?
        .try_into()
        .map_err(string_error)?;
        apply_filter(&filter).map_err(string_error)
    }

    fn read_candidate_frame<R: std::io::Read>(
        reader: &mut R,
        maximum: usize,
    ) -> Result<Vec<u8>, String> {
        let mut header = [0_u8; 4];
        reader.read_exact(&mut header).map_err(string_error)?;
        let length = usize::try_from(u32::from_be_bytes(header)).map_err(string_error)?;
        if length == 0 || length > maximum {
            return Err("candidate workload frame exceeds its byte bound".into());
        }
        let mut bytes = vec![0_u8; length];
        reader.read_exact(&mut bytes).map_err(string_error)?;
        Ok(bytes)
    }

    fn sha256_file(path: &Path, maximum: u64) -> Result<String, String> {
        let file = File::from(
            open(
                path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        sha256_reader(file, maximum)
    }

    fn sha256_reader(mut file: File, maximum: u64) -> Result<String, String> {
        let before = file.metadata().map_err(string_error)?;
        if !before.file_type().is_file() || before.len() == 0 || before.len() > maximum {
            return Err("candidate workload artifact is not one bounded regular file".into());
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
                .ok_or_else(|| "candidate workload artifact byte count overflow".to_owned())?;
            if total > maximum {
                return Err("candidate workload artifact exceeds its byte bound".into());
            }
            hasher.update(&buffer[..length]);
        }
        let after = file.metadata().map_err(string_error)?;
        if total != before.len()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
        {
            return Err("candidate workload artifact changed while read".into());
        }
        Ok(hex::encode(hasher.finalize()))
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
            return Err("candidate workload cgroup path is not normalized".into());
        }
        Ok(format!("0::/{}", relative.to_string_lossy()))
    }

    fn expected_cgroup_from_proc_self() -> Result<String, String> {
        let membership = fs::read_to_string("/proc/self/cgroup").map_err(string_error)?;
        let relative = membership
            .trim()
            .strip_prefix("0::/")
            .ok_or_else(|| "candidate launcher has no exact cgroup-v2 membership".to_owned())?;
        if relative.is_empty() || relative.contains("..") || relative.contains('\0') {
            return Err("candidate launcher cgroup membership is malformed".into());
        }
        Ok(format!("/sys/fs/cgroup/{relative}"))
    }

    fn build_agent_arguments(
        mode: LaunchMode,
        values: &BTreeMap<String, String>,
        config_fd: &str,
        state_directory_fd: &str,
    ) -> Result<Vec<String>, String> {
        let mut arguments = vec![
            "agent".to_owned(),
            "serve".to_owned(),
            "--config".to_owned(),
            format!("/proc/self/fd/{config_fd}"),
            "--state-directory".to_owned(),
            value(&values, "--state-directory")?.to_owned(),
            "--agent-socket".to_owned(),
            value(&values, "--agent-socket")?.to_owned(),
            "--admin-socket".to_owned(),
            value(&values, "--admin-socket")?.to_owned(),
            "--agent-uid".to_owned(),
            value(&values, "--agent-uid")?.to_owned(),
            "--qualification-config-fd".to_owned(),
            config_fd.to_owned(),
            "--qualification-config-sha256".to_owned(),
            value(values, "--config-sha256")?.to_owned(),
            "--qualification-state-directory-fd".to_owned(),
            state_directory_fd.to_owned(),
            "--qualification-state-directory-sha256".to_owned(),
            value(values, "--state-directory-sha256")?.to_owned(),
            "--qualification-client-proxy-uid".to_owned(),
            value(values, "--client-proxy-reader-uid")?.to_owned(),
            "--qualification-client-proxy-sha256".to_owned(),
            value(values, "--client-proxy-artifact-sha256")?.to_owned(),
            "--qualification-credential-broker-socket".to_owned(),
            value(values, "--credential-broker-socket")?.to_owned(),
            "--qualification-credential-broker-uid".to_owned(),
            value(values, "--credential-broker-reader-uid")?.to_owned(),
            "--qualification-credential-broker-sha256".to_owned(),
            value(values, "--credential-broker-artifact-sha256")?.to_owned(),
            "--qualification-provider-proxy-socket".to_owned(),
            value(values, "--provider-proxy-socket")?.to_owned(),
            "--qualification-provider-proxy-uid".to_owned(),
            value(values, "--provider-proxy-reader-uid")?.to_owned(),
            "--qualification-provider-proxy-sha256".to_owned(),
            value(values, "--provider-proxy-artifact-sha256")?.to_owned(),
            "--qualification-source-context-sha256".to_owned(),
            value(values, "--source-context-sha256")?.to_owned(),
            "--qualification-journal-gate-output-fd".to_owned(),
            "1".to_owned(),
            "--qualification-journal-gate-input-fd".to_owned(),
            "0".to_owned(),
            "--qualification-agent-generation".to_owned(),
            value(&values, "--agent-generation")?.to_owned(),
            "--qualification-controller-pid".to_owned(),
            value(&values, "--controller-pid")?.to_owned(),
            "--qualification-recovery-key-id".to_owned(),
            value(&values, "--recovery-key-id")?.to_owned(),
            "--qualification-recovery-public-key-base64url".to_owned(),
            value(&values, "--recovery-public-key-base64url")?.to_owned(),
        ];
        if let Some(failpoint) = mode.failpoint() {
            arguments.extend([
                "--qualification-failpoint".to_owned(),
                format!("crash-{}", failpoint.as_str()),
                "--qualification-control-operation-id".to_owned(),
                value(&values, "--control-operation-id")?.to_owned(),
                "--qualification-controller-nonce-sha256".to_owned(),
                value(&values, "--controller-nonce-sha256")?.to_owned(),
            ]);
        }
        Ok(arguments)
    }

    fn install_public_connection_store(
        template_path: &Path,
        state_directory: &File,
        credential_broker_uid: u32,
        agent_uid: u32,
        agent_gid: u32,
    ) -> Result<(), String> {
        let mut template = File::from(
            open(
                template_path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let before = template.metadata().map_err(string_error)?;
        if !before.file_type().is_file()
            || before.nlink() != 1
            || before.uid() != credential_broker_uid
            || before.mode() & 0o777 != 0o600
            || before.len() == 0
            || before.len() > MAX_CONNECTION_STORE_BYTES
        {
            return Err(
                "qualification public connection store is not one bounded broker-owned file".into(),
            );
        }
        let mut bytes = Vec::with_capacity(usize::try_from(before.len()).map_err(string_error)?);
        std::io::Read::by_ref(&mut template)
            .take(MAX_CONNECTION_STORE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(string_error)?;
        let after = template.metadata().map_err(string_error)?;
        if bytes.is_empty()
            || bytes.len() as u64 != before.len()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.uid() != after.uid()
            || before.mode() != after.mode()
        {
            return Err("qualification public connection store changed while pinned".into());
        }

        if let Some(existing) =
            read_agent_store_at(state_directory, CONNECTION_STORE_NAME, agent_uid, false)?
        {
            return (existing == bytes).then_some(()).ok_or_else(|| {
                "existing qualification connection store differs from broker snapshot".into()
            });
        }
        let retained_stage = read_agent_store_at(
            state_directory,
            CONNECTION_STORE_STAGE_NAME,
            agent_uid,
            true,
        )?;
        if retained_stage.as_ref().is_some_and(|stage| stage != &bytes) {
            unlinkat(
                state_directory,
                CONNECTION_STORE_STAGE_NAME,
                AtFlags::empty(),
            )
            .map_err(string_error)?;
            state_directory.sync_all().map_err(string_error)?;
        }
        let mut stage = File::from(
            openat(
                state_directory,
                CONNECTION_STORE_STAGE_NAME,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .or_else(|error| {
                if error == rustix::io::Errno::EXIST {
                    openat(
                        state_directory,
                        CONNECTION_STORE_STAGE_NAME,
                        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                } else {
                    Err(error)
                }
            })
            .map_err(string_error)?,
        );
        let stage_metadata = stage.metadata().map_err(string_error)?;
        if !stage_metadata.file_type().is_file()
            || stage_metadata.nlink() != 1
            || stage_metadata.mode() & 0o777 != 0o600
            || (stage_metadata.uid() != 0 && stage_metadata.uid() != agent_uid)
            || stage_metadata.len() > MAX_CONNECTION_STORE_BYTES
        {
            return Err("qualification connection-store stage is not private".into());
        }
        if stage_metadata.len() == 0 {
            stage.write_all(&bytes).map_err(string_error)?;
        } else {
            let retained = read_agent_store_at(
                state_directory,
                CONNECTION_STORE_STAGE_NAME,
                agent_uid,
                true,
            )?
            .ok_or_else(|| "qualification connection-store stage disappeared".to_owned())?;
            if retained != bytes {
                return Err("qualification connection-store stage differs on retry".into());
            }
        }
        fchown(
            &stage,
            Some(rustix::process::Uid::from_raw(agent_uid)),
            Some(rustix::process::Gid::from_raw(agent_gid)),
        )
        .map_err(string_error)?;
        stage.sync_all().map_err(string_error)?;
        match renameat_with(
            state_directory,
            CONNECTION_STORE_STAGE_NAME,
            state_directory,
            CONNECTION_STORE_NAME,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => state_directory.sync_all().map_err(string_error),
            Err(error) if error == rustix::io::Errno::EXIST => {
                let existing =
                    read_agent_store_at(state_directory, CONNECTION_STORE_NAME, agent_uid, false)?
                        .ok_or_else(|| {
                            "qualification connection store disappeared during publication"
                                .to_owned()
                        })?;
                if existing != bytes {
                    return Err(
                        "qualification connection-store publication raced different bytes".into(),
                    );
                }
                unlinkat(
                    state_directory,
                    CONNECTION_STORE_STAGE_NAME,
                    AtFlags::empty(),
                )
                .map_err(string_error)?;
                state_directory.sync_all().map_err(string_error)
            }
            Err(error) => Err(string_error(error)),
        }
    }

    fn read_agent_store_at(
        state_directory: &File,
        name: &str,
        agent_uid: u32,
        allow_root: bool,
    ) -> Result<Option<Vec<u8>>, String> {
        let descriptor = match openat(
            state_directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(error) => return Err(string_error(error)),
        };
        let mut file = File::from(descriptor);
        let metadata = file.metadata().map_err(string_error)?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || (metadata.uid() != agent_uid && !(allow_root && metadata.uid() == 0))
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() == 0
            || metadata.len() > MAX_CONNECTION_STORE_BYTES
        {
            return Err("qualification connection-store inode is invalid".into());
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(string_error)?);
        std::io::Read::by_ref(&mut file)
            .take(MAX_CONNECTION_STORE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(string_error)?;
        let after = file.metadata().map_err(string_error)?;
        if bytes.len() as u64 != metadata.len()
            || metadata.dev() != after.dev()
            || metadata.ino() != after.ino()
            || metadata.len() != after.len()
        {
            return Err("qualification connection-store inode changed while read".into());
        }
        Ok(Some(bytes))
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
        (values.len() == flags.len())
            .then_some(values)
            .ok_or_else(usage)
    }

    fn launch_values(
        arguments: &[String],
    ) -> Result<(LaunchMode, BTreeMap<String, String>), String> {
        let modes = arguments
            .get(1..)
            .unwrap_or_default()
            .chunks_exact(2)
            .filter(|pair| pair[0] == "--mode")
            .map(|pair| pair[1].as_str())
            .collect::<Vec<_>>();
        let mode = match modes.as_slice() {
            ["ordinary"] => LaunchMode::Ordinary,
            ["restart"] => LaunchMode::Restart(None),
            [token] if token.starts_with("restart-crash-") => token
                .strip_prefix("restart-crash-")
                .and_then(QualificationFailpoint::from_token)
                .map(|failpoint| LaunchMode::Restart(Some(failpoint)))
                .ok_or_else(usage)?,
            [token] => token
                .strip_prefix("crash-")
                .and_then(QualificationFailpoint::from_token)
                .map(LaunchMode::Crash)
                .ok_or_else(usage)?,
            _ => return Err(usage()),
        };
        let mut flags = vec![
            "--admin-socket",
            "--agent",
            "--agent-gid",
            "--agent-generation",
            "--agent-sha256",
            "--agent-socket",
            "--agent-uid",
            "--config",
            "--config-sha256",
            "--client-proxy-artifact-sha256",
            "--client-proxy-reader-uid",
            "--credential-broker-artifact-sha256",
            "--credential-broker-reader-uid",
            "--credential-broker-socket",
            "--provider-proxy-artifact-sha256",
            "--provider-proxy-reader-uid",
            "--provider-proxy-socket",
            "--controller-pid",
            "--ledger-plan",
            "--mode",
            "--qualification-connection-store-template",
            "--recovery-key-id",
            "--recovery-public-key-base64url",
            "--source-context-sha256",
            "--state-directory",
            "--state-directory-sha256",
        ];
        if mode.failpoint().is_some() {
            flags.extend(["--control-operation-id", "--controller-nonce-sha256"]);
        }
        exact_flags(arguments, "launch", &flags).map(|values| (mode, values))
    }

    fn remove_stale_agent_socket(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        let parent_path = path
            .parent()
            .ok_or_else(|| "qualification socket has no parent".to_owned())?;
        let name = path
            .file_name()
            .ok_or_else(|| "qualification socket has no fixed name".to_owned())?;
        let root = File::from(
            open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let parent = File::from(
            openat2(
                &root,
                parent_path.strip_prefix("/").map_err(string_error)?,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(string_error)?,
        );
        let parent_metadata = parent.metadata().map_err(string_error)?;
        if !parent_metadata.file_type().is_dir()
            || parent_metadata.uid() != uid
            || parent_metadata.gid() != gid
            || parent_metadata.mode() & 0o777 != 0o710
        {
            return Err("qualification socket parent differs from agent policy".into());
        }
        let socket = match openat(
            &parent,
            Path::new(name),
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(socket) => File::from(socket),
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
            Err(error) => return Err(string_error(error)),
        };
        let metadata = socket.metadata().map_err(string_error)?;
        if !metadata.file_type().is_socket()
            || metadata.nlink() != 1
            || metadata.uid() != uid
            || metadata.gid() != gid
            || metadata.mode() & 0o777 != 0o660
        {
            return Err("stale qualification socket identity is invalid".into());
        }
        unlinkat(&parent, Path::new(name), AtFlags::empty()).map_err(string_error)?;
        parent.sync_all().map_err(string_error)
    }

    fn value<'a>(values: &'a BTreeMap<String, String>, flag: &str) -> Result<&'a str, String> {
        values.get(flag).map(String::as_str).ok_or_else(usage)
    }

    fn require_normalized_absolute(path: &Path) -> Result<(), String> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err("qualification launch path is not normalized and absolute".into());
        }
        Ok(())
    }

    fn canonical_u32(value: &str) -> Result<u32, String> {
        if value.is_empty()
            || value.len() > 10
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value != "0" && value.starts_with('0'))
        {
            return Err("qualification launch integer is noncanonical".into());
        }
        value.parse::<u32>().map_err(string_error)
    }

    fn read_protected_ledger_plan(
        path: &Path,
    ) -> Result<QualificationEvidenceLedgerPlanV1, String> {
        let root = File::from(
            open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let relative = path.strip_prefix("/").map_err(string_error)?;
        let mut file = File::from(
            openat2(
                &root,
                relative,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(string_error)?,
        );
        let before = file.metadata().map_err(string_error)?;
        if !before.file_type().is_file()
            || before.nlink() != 1
            || before.uid() != 0
            || before.gid() != 0
            || before.mode() & 0o777 != 0o600
            || before.len() == 0
            || before.len() > 262_144
        {
            return Err("qualification ledger policy is not one root-owned immutable file".into());
        }
        let mut bytes = Vec::with_capacity(usize::try_from(before.len()).map_err(string_error)?);
        std::io::Read::by_ref(&mut file)
            .take(262_145)
            .read_to_end(&mut bytes)
            .map_err(string_error)?;
        let after = file.metadata().map_err(string_error)?;
        if bytes.len() as u64 != before.len()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
        {
            return Err("qualification ledger policy changed while read".into());
        }
        let plan = QualificationEvidenceLedgerPlanV1::from_json(&bytes).map_err(string_error)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(string_error)?
            .as_secs();
        if now < plan.started_at_unix_seconds || now >= plan.deadline_at_unix_seconds {
            return Err("qualification ledger policy is outside its immutable interval".into());
        }
        Ok(plan)
    }

    fn authenticate_controller(
        plan: &QualificationEvidenceLedgerPlanV1,
        controller_pid: u32,
    ) -> Result<u64, String> {
        if rustix::process::geteuid().as_raw() != 0
            || rustix::process::getuid().as_raw() != plan.supervisor_controller_uid
            || rustix::process::Pid::as_raw(rustix::process::getppid()) != controller_pid as i32
            || hash_process_executable(controller_pid)?
                != plan.supervisor_controller_artifact_sha256
        {
            return Err("qualification launcher caller is not the protected controller".into());
        }
        process_start_time_ticks(controller_pid)
    }

    fn authenticate_controller_process(
        plan: &QualificationEvidenceLedgerPlanV1,
        controller_pid: u32,
    ) -> Result<u64, String> {
        let process = fs::metadata(format!("/proc/{controller_pid}")).map_err(string_error)?;
        if rustix::process::geteuid().as_raw() != 0
            || rustix::process::getuid().as_raw() != plan.supervisor_controller_uid
            || process.uid() != plan.supervisor_controller_uid
            || hash_process_executable(controller_pid)?
                != plan.supervisor_controller_artifact_sha256
        {
            return Err("candidate init controller differs from the signed plan".into());
        }
        process_start_time_ticks(controller_pid)
    }

    fn authenticate_controller_unchanged(
        plan: &QualificationEvidenceLedgerPlanV1,
        controller_pid: u32,
        start_time_ticks: u64,
    ) -> Result<(), String> {
        if rustix::process::getuid().as_raw() != plan.supervisor_controller_uid
            || rustix::process::Pid::as_raw(rustix::process::getppid()) != controller_pid as i32
            || process_start_time_ticks(controller_pid)? != start_time_ticks
            || hash_process_executable(controller_pid)?
                != plan.supervisor_controller_artifact_sha256
        {
            return Err("qualification launcher controller changed before agent exec".into());
        }
        Ok(())
    }

    fn hash_process_executable(pid: u32) -> Result<String, String> {
        let file = File::open(format!("/proc/{pid}/exe")).map_err(string_error)?;
        sha256_reader(file, MAX_EXECUTABLE_BYTES)
    }

    fn process_parent_pid(pid: u32) -> Result<u32, String> {
        process_parent_pid_from_status(&format!("/proc/{pid}/status"))
    }

    fn process_parent_pid_from_status(path: &str) -> Result<u32, String> {
        let status = fs::read_to_string(path).map_err(string_error)?;
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .ok_or_else(|| "protected process parent identity is absent".to_owned())?
            .trim();
        canonical_u32(value)
    }

    fn process_start_time_ticks(pid: u32) -> Result<u64, String> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(string_error)?;
        let end = stat
            .rfind(')')
            .ok_or_else(|| "protected controller stat is malformed".to_owned())?;
        stat.get(end + 2..)
            .ok_or_else(|| "protected controller stat is malformed".to_owned())?
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| "protected controller start time is absent".to_owned())?
            .parse::<u64>()
            .map_err(string_error)
    }

    fn reject_secret_environment() -> Result<(), String> {
        for (name, _) in env::vars_os() {
            let name = name.to_string_lossy().to_ascii_uppercase();
            if [
                "TOKEN",
                "SECRET",
                "CREDENTIAL",
                "PASSWORD",
                "PRIVATE",
                "SEED",
            ]
            .iter()
            .any(|part| name.contains(part))
            {
                return Err(format!(
                    "secret-bearing inherited environment is forbidden: {name}"
                ));
            }
        }
        Ok(())
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

    fn string_error(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    fn usage() -> String {
        concat!(
            "usage:\n",
            "  qualification-agent-launcher launch --mode <ordinary|crash-after-decision> ",
            "--admin-socket <path> --agent <path> --agent-gid <gid> ",
            "--agent-sha256 <digest> --agent-socket <path> --agent-uid <uid> ",
            "--client-proxy-artifact-sha256 <digest> --client-proxy-reader-uid <uid> ",
            "--config <path> --config-sha256 <digest> --controller-pid <pid> ",
            "--credential-broker-artifact-sha256 <digest> ",
            "--credential-broker-reader-uid <uid> --credential-broker-socket <path> ",
            "--ledger-plan <root-owned-policy> ",
            "--qualification-connection-store-template <broker-owned-path> ",
            "--recovery-key-id <id> --recovery-public-key-base64url <key> ",
            "--source-context-sha256 <digest> --state-directory <path> ",
            "--state-directory-sha256 <digest> ",
            "[--agent-generation <u32> --control-operation-id <id> ",
            "--controller-nonce-sha256 <digest>]\n",
            "  qualification-agent-launcher candidate-workload --cgroup <path> ",
            "--controller-pid <pid> --ledger-plan <root-owned-policy> ",
            "--phase-index <u8> --profile <path> --python <path> ",
            "--request-sha256 <digest> --sandbox-root <path> --scenario <id> ",
            "--wheel <path> --workload-gid <gid> --workload-uid <uid>\n",
            "  candidate-init is an authenticated internal namespace stage and cannot be ",
            "invoked directly"
        )
        .into()
    }

    #[cfg(test)]
    mod tests {
        use super::{LaunchMode, build_agent_arguments, launch_values};
        use auths_profile_kit::QualificationFailpoint;

        fn common(mode: &str) -> Vec<String> {
            [
                "launch",
                "--admin-socket",
                "/run/auths/admin.sock",
                "--agent",
                "/opt/auths/auths-qualification-agent",
                "--agent-gid",
                "1004",
                "--agent-generation",
                "1",
                "--agent-sha256",
                &"a".repeat(64),
                "--agent-socket",
                "/run/auths/agent.sock",
                "--agent-uid",
                "1003",
                "--config",
                "/run/auths/agent.toml",
                "--config-sha256",
                &"b".repeat(64),
                "--client-proxy-artifact-sha256",
                &"e".repeat(64),
                "--client-proxy-reader-uid",
                "1005",
                "--credential-broker-artifact-sha256",
                &"6".repeat(64),
                "--credential-broker-reader-uid",
                "1006",
                "--credential-broker-socket",
                "/run/auths/credential-broker.sock",
                "--controller-pid",
                "77",
                "--ledger-plan",
                "/run/auths/policy/ledger-plan.json",
                "--mode",
                mode,
                "--qualification-connection-store-template",
                "/run/auths/credential-broker-store/connections.cbor",
                "--recovery-key-id",
                "recovery-v1",
                "--recovery-public-key-base64url",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "--source-context-sha256",
                &"f".repeat(64),
                "--state-directory",
                "/run/auths/state",
                "--state-directory-sha256",
                &"d".repeat(64),
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        }

        #[test]
        fn launch_modes_have_exact_non_mixable_arguments() {
            let ordinary = common("ordinary");
            let (ordinary_mode, ordinary_values) = launch_values(&ordinary).unwrap();
            assert_eq!(ordinary_mode, LaunchMode::Ordinary);
            let ordinary_argv =
                build_agent_arguments(ordinary_mode, &ordinary_values, "11", "12").unwrap();
            assert_eq!(
                ordinary_argv,
                [
                    "agent",
                    "serve",
                    "--config",
                    "/proc/self/fd/11",
                    "--state-directory",
                    "/run/auths/state",
                    "--agent-socket",
                    "/run/auths/agent.sock",
                    "--admin-socket",
                    "/run/auths/admin.sock",
                    "--agent-uid",
                    "1003",
                    "--qualification-config-fd",
                    "11",
                    "--qualification-config-sha256",
                    &"b".repeat(64),
                    "--qualification-state-directory-fd",
                    "12",
                    "--qualification-state-directory-sha256",
                    &"d".repeat(64),
                    "--qualification-client-proxy-uid",
                    "1005",
                    "--qualification-client-proxy-sha256",
                    &"e".repeat(64),
                    "--qualification-credential-broker-socket",
                    "/run/auths/credential-broker.sock",
                    "--qualification-credential-broker-uid",
                    "1006",
                    "--qualification-credential-broker-sha256",
                    &"6".repeat(64),
                    "--qualification-source-context-sha256",
                    &"f".repeat(64),
                    "--qualification-journal-gate-output-fd",
                    "1",
                    "--qualification-journal-gate-input-fd",
                    "0",
                    "--qualification-agent-generation",
                    "1",
                    "--qualification-controller-pid",
                    "77",
                    "--qualification-recovery-key-id",
                    "recovery-v1",
                    "--qualification-recovery-public-key-base64url",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
            );

            let mut crash = common("crash-after-decision");
            crash.extend([
                "--control-operation-id".into(),
                "ctl_example".into(),
                "--controller-nonce-sha256".into(),
                "c".repeat(64),
            ]);
            let (crash_mode, crash_values) = launch_values(&crash).unwrap();
            assert_eq!(
                crash_mode,
                LaunchMode::Crash(QualificationFailpoint::AfterDecision)
            );
            let crash_argv = build_agent_arguments(crash_mode, &crash_values, "11", "12").unwrap();
            assert_eq!(
                &crash_argv[ordinary_argv.len()..],
                [
                    "--qualification-failpoint",
                    "crash-after-decision",
                    "--qualification-control-operation-id",
                    "ctl_example",
                    "--qualification-controller-nonce-sha256",
                    &"c".repeat(64),
                ]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
            );

            let mut mixed = ordinary;
            mixed.extend(["--control-operation-id".into(), "ctl_example".into()]);
            assert!(launch_values(&mixed).is_err());
            let partial = common("crash-after-decision");
            assert!(launch_values(&partial).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("qualification agent launcher is supported only on Linux");
    std::process::ExitCode::FAILURE
}
