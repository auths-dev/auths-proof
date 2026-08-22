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
        qualification_state_directory_commitment,
    };
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use rustix::{
        fs::{
            AtFlags, MemfdFlags, Mode, OFlags, RenameFlags, ResolveFlags, SealFlags, fchown,
            fcntl_add_seals, fcntl_get_seals, memfd_create, open, openat, openat2, renameat_with,
            unlinkat,
        },
        io::{FdFlags, fcntl_setfd},
    };
    use sha2::{Digest as _, Sha256};
    use std::{
        collections::{BTreeMap, BTreeSet},
        env,
        fs::File,
        io::{Read as _, Seek as _, SeekFrom, Write as _},
        os::{
            fd::AsRawFd as _,
            unix::{
                fs::{FileTypeExt as _, MetadataExt as _},
                process::CommandExt as _,
            },
        },
        path::{Component, Path},
        process::{Command, ExitCode},
        time::{SystemTime, UNIX_EPOCH},
    };

    const RELEASE: &[u8] = b"AUTHS-QUALIFICATION-LAUNCH/1\n";
    const MAX_EXECUTABLE_BYTES: u64 = 536_870_912;
    const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_CONNECTION_STORE_BYTES: u64 = 4 * 1024 * 1024;
    const CONNECTION_STORE_NAME: &str = "connections.cbor";
    const CONNECTION_STORE_STAGE_NAME: &str = ".connections.cbor.qualification-stage";

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
        match run(&env::args().skip(1).collect::<Vec<_>>()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("qualification agent launcher failed closed: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn run(arguments: &[String]) -> Result<(), String> {
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
        install_public_connection_store(
            Path::new(value(&values, "--qualification-connection-store-template")?),
            &state_directory,
            credential_broker_uid,
            uid,
            gid,
        )?;
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
        flags: &[&str],
    ) -> Result<BTreeMap<String, String>, String> {
        if arguments.first().map(String::as_str) != Some("launch")
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
        exact_flags(arguments, &flags).map(|values| (mode, values))
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
        let mut file = File::open(format!("/proc/{pid}/exe")).map_err(string_error)?;
        let metadata = file.metadata().map_err(string_error)?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_EXECUTABLE_BYTES
        {
            return Err("protected controller executable is invalid".into());
        }
        let mut hasher = Sha256::new();
        let mut total = 0_u64;
        let mut chunk = [0_u8; 65_536];
        loop {
            let length = file.read(&mut chunk).map_err(string_error)?;
            if length == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(length).map_err(string_error)?)
                .ok_or_else(|| "protected controller byte count overflow".to_owned())?;
            if total > MAX_EXECUTABLE_BYTES {
                return Err("protected controller executable exceeds its bound".into());
            }
            hasher.update(&chunk[..length]);
        }
        (total == metadata.len())
            .then(|| hex::encode(hasher.finalize()))
            .ok_or_else(|| "protected controller executable changed while read".to_owned())
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
        "usage: qualification-agent-launcher launch --mode <ordinary|crash-after-decision> --admin-socket <path> --agent <path> --agent-gid <gid> --agent-sha256 <digest> --agent-socket <path> --agent-uid <uid> --client-proxy-artifact-sha256 <digest> --client-proxy-reader-uid <uid> --config <path> --config-sha256 <digest> --controller-pid <pid> --credential-broker-artifact-sha256 <digest> --credential-broker-reader-uid <uid> --credential-broker-socket <path> --ledger-plan <root-owned-policy> --qualification-connection-store-template <broker-owned-path> --recovery-key-id <id> --recovery-public-key-base64url <key> --source-context-sha256 <digest> --state-directory <path> --state-directory-sha256 <digest> [--agent-generation <u32> --control-operation-id <id> --controller-nonce-sha256 <digest>]".into()
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
