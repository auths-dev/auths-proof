//! Retained-identity OpenTofu subprocess execution.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, path::Path};

use auths_profile_runtime::ProfileRuntimeError;
#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha256};
#[cfg(target_os = "linux")]
use std::{
    fs::File,
    io::{Read, Seek as _, SeekFrom, Write as _},
    os::unix::process::CommandExt as _,
    os::{fd::AsRawFd as _, unix::fs::MetadataExt as _},
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_PROCESS_OUTPUT: usize = 16 * 1024 * 1024;
#[cfg(target_os = "linux")]
const PROCESS_TIMEOUT: Duration = Duration::from_mins(5);

#[cfg(target_os = "linux")]
pub(crate) struct ProtectedOpenTofuExecutor {
    executable: File,
    executable_path: PathBuf,
}

#[cfg(not(target_os = "linux"))]
pub(crate) struct ProtectedOpenTofuExecutor;

impl ProtectedOpenTofuExecutor {
    pub(crate) fn open(path: &Path, expected_sha256: &str) -> Result<Self, ProfileRuntimeError> {
        #[cfg(target_os = "linux")]
        {
            return Self::open_linux(path, expected_sha256);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, expected_sha256);
            Err(ProfileRuntimeError::Invalid)
        }
    }

    #[cfg(target_os = "linux")]
    fn open_linux(path: &Path, expected_sha256: &str) -> Result<Self, ProfileRuntimeError> {
        if !path.is_absolute() {
            return Err(ProfileRuntimeError::Invalid);
        }
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
        let mut source = File::from(descriptor);
        let metadata = source
            .metadata()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_BINARY_BYTES
            || metadata.mode() & 0o111 == 0
        {
            return Err(ProfileRuntimeError::Invalid);
        }

        let mut executable = File::from(
            rustix::fs::memfd_create(
                "auths-opentofu-executable",
                rustix::fs::MemfdFlags::ALLOW_SEALING | rustix::fs::MemfdFlags::EXEC,
            )
            .map_err(|_| ProfileRuntimeError::Invalid)?,
        );
        let mut digest = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        let mut total = 0_u64;
        loop {
            let count = source
                .read(&mut buffer)
                .map_err(|_| ProfileRuntimeError::Invalid)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(count).map_err(|_| ProfileRuntimeError::Invalid)?)
                .ok_or(ProfileRuntimeError::Invalid)?;
            if total > MAX_BINARY_BYTES {
                return Err(ProfileRuntimeError::Invalid);
            }
            digest.update(&buffer[..count]);
            executable
                .write_all(&buffer[..count])
                .map_err(|_| ProfileRuntimeError::Invalid)?;
        }
        let after = source
            .metadata()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        if total != metadata.len()
            || metadata.dev() != after.dev()
            || metadata.ino() != after.ino()
            || metadata.len() != after.len()
            || hex::encode(digest.finalize()) != expected_sha256
        {
            return Err(ProfileRuntimeError::Invalid);
        }
        executable
            .flush()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        executable
            .sync_all()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        let seals = rustix::fs::SealFlags::SEAL
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::WRITE;
        rustix::fs::fcntl_add_seals(&executable, seals)
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        if rustix::fs::fcntl_get_seals(&executable).map_err(|_| ProfileRuntimeError::Invalid)?
            != seals
        {
            return Err(ProfileRuntimeError::Invalid);
        }
        executable
            .seek(SeekFrom::Start(0))
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        let mut sealed_digest = Sha256::new();
        let mut sealed_total = 0_u64;
        loop {
            let count = executable
                .read(&mut buffer)
                .map_err(|_| ProfileRuntimeError::Invalid)?;
            if count == 0 {
                break;
            }
            sealed_total = sealed_total
                .checked_add(u64::try_from(count).map_err(|_| ProfileRuntimeError::Invalid)?)
                .ok_or(ProfileRuntimeError::Invalid)?;
            sealed_digest.update(&buffer[..count]);
        }
        if sealed_total != total || hex::encode(sealed_digest.finalize()) != expected_sha256 {
            return Err(ProfileRuntimeError::Invalid);
        }
        executable
            .seek(SeekFrom::Start(0))
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        // The kernel resolves this descriptor during exec. The later sandbox
        // owns the child's exact descriptor-closing policy.
        rustix::io::fcntl_setfd(&executable, rustix::io::FdFlags::empty())
            .map_err(|_| ProfileRuntimeError::Invalid)?;

        let executable_path = retained_descriptor_path(executable.as_raw_fd());
        let retained_metadata =
            std::fs::metadata(&executable_path).map_err(|_| ProfileRuntimeError::Invalid)?;
        if !retained_metadata.is_file() || retained_metadata.len() != total {
            return Err(ProfileRuntimeError::Invalid);
        }
        Ok(Self {
            executable,
            executable_path,
        })
    }

    pub(crate) fn run(
        &self,
        arguments: &[String],
        current_directory: &Path,
        environment: &BTreeMap<String, String>,
    ) -> Result<ProcessOutput, ProfileRuntimeError> {
        #[cfg(target_os = "linux")]
        {
            return self.run_linux(arguments, current_directory, environment);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (arguments, current_directory, environment);
            Err(ProfileRuntimeError::Invalid)
        }
    }

    #[cfg(target_os = "linux")]
    fn run_linux(
        &self,
        arguments: &[String],
        current_directory: &Path,
        environment: &BTreeMap<String, String>,
    ) -> Result<ProcessOutput, ProfileRuntimeError> {
        let retained_metadata = self
            .executable
            .metadata()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        let execution_metadata =
            std::fs::metadata(&self.executable_path).map_err(|_| ProfileRuntimeError::Invalid)?;
        let seals = rustix::fs::SealFlags::SEAL
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::WRITE;
        if retained_metadata.dev() != execution_metadata.dev()
            || retained_metadata.ino() != execution_metadata.ino()
            || rustix::fs::fcntl_get_seals(&self.executable)
                .map_err(|_| ProfileRuntimeError::Invalid)?
                != seals
        {
            return Err(ProfileRuntimeError::Invalid);
        }

        let mut command = Command::new(&self.executable_path);
        command
            .args(arguments)
            .current_dir(current_directory)
            .process_group(0)
            .env_clear()
            .envs(environment)
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
            if child_exited_without_reaping(&child)? {
                terminate_process_group(&child)?;
                break child.wait().map_err(|_| ProfileRuntimeError::Invalid)?;
            }
            if started.elapsed() >= PROCESS_TIMEOUT {
                terminate_process_group(&child)?;
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

#[cfg(target_os = "linux")]
fn retained_descriptor_path(descriptor: i32) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{descriptor}"))
}

#[cfg(target_os = "linux")]
fn child_exited_without_reaping(child: &std::process::Child) -> Result<bool, ProfileRuntimeError> {
    let pid = child_pid(child)?;
    rustix::process::waitid(
        rustix::process::WaitId::Pid(pid),
        rustix::process::WaitIdOptions::EXITED
            | rustix::process::WaitIdOptions::NOHANG
            | rustix::process::WaitIdOptions::NOWAIT,
    )
    .map(|status| status.is_some())
    .map_err(|_| ProfileRuntimeError::Invalid)
}

#[cfg(target_os = "linux")]
fn terminate_process_group(child: &std::process::Child) -> Result<(), ProfileRuntimeError> {
    match rustix::process::kill_process_group(child_pid(child)?, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(_) => Err(ProfileRuntimeError::Invalid),
    }
}

#[cfg(target_os = "linux")]
fn child_pid(child: &std::process::Child) -> Result<rustix::process::Pid, ProfileRuntimeError> {
    rustix::process::Pid::from_raw(
        i32::try_from(child.id()).map_err(|_| ProfileRuntimeError::Invalid)?,
    )
    .ok_or(ProfileRuntimeError::Invalid)
}

pub(crate) struct ProcessOutput {
    pub(crate) success: bool,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

#[cfg(target_os = "linux")]
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

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::fs;

    #[cfg(target_os = "linux")]
    use sha2::{Digest as _, Sha256};
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[cfg(target_os = "linux")]
    fn installed_binary() -> &'static Path {
        Path::new("/bin/sh")
    }

    #[cfg(target_os = "linux")]
    fn digest(path: &Path) -> String {
        let bytes = fs::read(path).unwrap();
        hex::encode(Sha256::digest(bytes))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_executable_survives_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("tofu");
        fs::copy(installed_binary(), &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let executor = ProtectedOpenTofuExecutor::open(&binary, &digest(&binary)).unwrap();
        let retained = directory.path().join("retained");
        fs::rename(&binary, retained).unwrap();
        fs::write(&binary, b"not the reviewed executable").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();

        let output = executor
            .run(
                &["-c".into(), "printf pinned".into()],
                directory.path(),
                &BTreeMap::new(),
            )
            .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, b"pinned");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_executable_survives_same_inode_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("tofu");
        fs::copy(installed_binary(), &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let executor = ProtectedOpenTofuExecutor::open(&binary, &digest(&binary)).unwrap();
        fs::write(&binary, b"mutated in place").unwrap();

        let output = executor
            .run(
                &["-c".into(), "printf sealed".into()],
                directory.path(),
                &BTreeMap::new(),
            )
            .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, b"sealed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_symlink_directory_digest_mismatch_and_non_executable() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("tofu");
        fs::copy(installed_binary(), &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(ProtectedOpenTofuExecutor::open(&binary, &"0".repeat(64)).is_err());
        assert!(
            ProtectedOpenTofuExecutor::open(directory.path(), &digest(installed_binary())).is_err()
        );
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&binary, &link).unwrap();
        assert!(ProtectedOpenTofuExecutor::open(&link, &digest(&binary)).is_err());
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ProtectedOpenTofuExecutor::open(&binary, &digest(&binary)).is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn executor_is_explicitly_linux_only() {
        assert!(ProtectedOpenTofuExecutor::open(Path::new("/bin/sh"), &"0".repeat(64)).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_runner_kills_descendants_after_the_direct_child_exits() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("tofu");
        fs::copy(installed_binary(), &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let executor = ProtectedOpenTofuExecutor::open(&binary, &digest(&binary)).unwrap();
        let output = executor
            .run(
                &[
                    "-c".into(),
                    "sleep 60 >/dev/null 2>&1 & printf '%s\\n' \"$!\"".into(),
                ],
                directory.path(),
                &BTreeMap::new(),
            )
            .unwrap();
        assert!(output.success);
        let descendant = rustix::process::Pid::from_raw(
            String::from_utf8(output.stdout)
                .unwrap()
                .trim()
                .parse()
                .unwrap(),
        )
        .unwrap();
        for _ in 0..100 {
            if matches!(
                rustix::process::test_kill_process(descendant),
                Err(rustix::io::Errno::SRCH)
            ) {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("OpenTofu descendant survived process-group cleanup");
    }
}
