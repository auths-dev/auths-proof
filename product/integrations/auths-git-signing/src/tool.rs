//! Process-boundary support shared by the `auths-git` and `auths-git-sign`
//! binaries: local state, Git subprocesses, trust material, and the enabled
//! principal methods.
//!
//! Local state lives under `$AUTHS_GIT_HOME`, or `$HOME/.auths-git` when that
//! is unset:
//!
//! ```text
//! keys/<label>.seed     owner-only software key (see `custody`)
//! grants/<label>.json   the delegation installed for that key
//! ```
//!
//! Trust material for a repository is a directory, normally `.auths/git` on
//! a protected branch:
//!
//! ```text
//! trust.cbor            canonical trusted context
//! revocations/*.sig     root-signed revocation records
//! ```

use crate::action::RepositoryId;
use crate::custody::{CustodyError, SoftwareKey};
use crate::files::decode_delegation;
use crate::sign::Delegation;
use crate::verify::{GitTrust, TrustError};
use auths_did_key::DidKeyMethod;
use auths_model::Timestamp;
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_registries::ImmutableRegistries;
use auths_signature::Ed25519Suite;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Path of the trust material inside a repository tree.
pub const TRUST_DIRECTORY: &str = ".auths/git";
/// Trusted-context file name inside the trust directory.
pub const TRUST_FILE: &str = "trust.cbor";
/// Revocation directory name inside the trust directory.
pub const REVOCATIONS_DIRECTORY: &str = "revocations";
/// Maximum trust file size in bytes.
pub const MAX_TRUST_FILE_BYTES: usize = 1024 * 1024;
/// Maximum number of revocation records read.
pub const MAX_REVOCATIONS: usize = 4096;
/// Maximum revocation record size in bytes.
pub const MAX_REVOCATION_BYTES: usize = 200 * 1024;

/// A failure at the process boundary.
#[derive(Debug, Error)]
pub enum ToolError {
    /// Local state could not be located or created.
    #[error("{0}")]
    State(String),
    /// A key could not be created or loaded.
    #[error("key: {0}")]
    Custody(#[from] CustodyError),
    /// A Git command failed.
    #[error("git {command}: {detail}")]
    Git {
        /// The Git subcommand.
        command: String,
        /// Git's error output.
        detail: String,
    },
    /// Trust material is missing, oversized, or invalid.
    #[error("trust: {0}")]
    Trust(String),
    /// A delegation file is invalid.
    #[error("the installed grant is invalid")]
    Delegation,
}

impl From<TrustError> for ToolError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error.code().to_owned())
    }
}

/// Returns the local state directory, creating it with mode 0700.
///
/// # Errors
///
/// Returns [`ToolError::State`] when no home directory is known or the
/// directory cannot be created.
pub fn state_home() -> Result<PathBuf, ToolError> {
    let home = std::env::var_os("AUTHS_GIT_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".auths-git")))
        .ok_or_else(|| ToolError::State("set AUTHS_GIT_HOME or HOME".to_owned()))?;
    for directory in [home.clone(), home.join("keys"), home.join("grants")] {
        create_private_directory(&directory)?;
    }
    Ok(home)
}

fn create_private_directory(directory: &Path) -> Result<(), ToolError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(directory)
        .map_err(|error| ToolError::State(format!("{}: {error}", directory.display())))
}

/// Returns the seed path for `label`.
#[must_use]
pub fn key_path(home: &Path, label: &str) -> PathBuf {
    home.join("keys").join(format!("{label}.seed"))
}

/// Returns the installed-grant path for `label`.
#[must_use]
pub fn grant_path(home: &Path, label: &str) -> PathBuf {
    home.join("grants").join(format!("{label}.json"))
}

/// Loads the key for `label`.
///
/// # Errors
///
/// Returns [`ToolError::Custody`] when the key is missing or unsafe.
pub fn load_key(home: &Path, label: &str) -> Result<SoftwareKey, ToolError> {
    Ok(SoftwareKey::load(&key_path(home, label))?)
}

/// Loads the delegation installed for `label`.
///
/// # Errors
///
/// Returns [`ToolError::Delegation`] when it is missing or invalid.
pub fn load_delegation(home: &Path, label: &str) -> Result<Delegation, ToolError> {
    let bytes = fs::read(grant_path(home, label)).map_err(|_| ToolError::Delegation)?;
    decode_delegation(&bytes).map_err(|_| ToolError::Delegation)
}

/// Runs `git` with `arguments` and returns stdout.
///
/// # Errors
///
/// Returns [`ToolError::Git`] when Git cannot run or exits non-zero.
pub fn git<I, S>(arguments: I) -> Result<Vec<u8>, ToolError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let arguments: Vec<_> = arguments
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect();
    let command = arguments
        .first()
        .map(|argument| argument.to_string_lossy().into_owned())
        .unwrap_or_default();
    let output = Command::new("git")
        .args(&arguments)
        .output()
        .map_err(|error| ToolError::Git {
            command: command.clone(),
            detail: error.to_string(),
        })?;
    if !output.status.success() {
        return Err(ToolError::Git {
            command,
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(output.stdout)
}

/// Returns a Git configuration value, or `None` when it is unset.
#[must_use]
pub fn git_config(key: &str) -> Option<String> {
    git(["config", "--get", key])
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Returns the configured repository (`git config auths.repository`).
///
/// # Errors
///
/// Returns [`ToolError::State`] when unset or invalid.
pub fn configured_repository() -> Result<RepositoryId, ToolError> {
    let value = git_config("auths.repository").ok_or_else(|| {
        ToolError::State("set `git config auths.repository <host/owner/name>`".to_owned())
    })?;
    RepositoryId::parse(&value)
        .map_err(|_| ToolError::State(format!("auths.repository is invalid: {value}")))
}

/// Returns the current Unix time in seconds.
#[must_use]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Raw trust material: the trusted context and revocation records.
#[derive(Clone, Debug)]
pub struct TrustMaterial {
    /// Canonical trusted-context bytes.
    pub context: Vec<u8>,
    /// Armored revocation records.
    pub revocations: Vec<Vec<u8>>,
}

impl TrustMaterial {
    /// Reads trust material from a directory on disk.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Trust`] for missing, oversized, or excessive
    /// material.
    pub fn from_directory(directory: &Path) -> Result<Self, ToolError> {
        let context = read_bounded(&directory.join(TRUST_FILE), MAX_TRUST_FILE_BYTES)?;
        let mut revocations = Vec::new();
        let revocation_directory = directory.join(REVOCATIONS_DIRECTORY);
        if revocation_directory.is_dir() {
            let mut paths: Vec<PathBuf> = fs::read_dir(&revocation_directory)
                .map_err(|error| ToolError::Trust(error.to_string()))?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|extension| extension == "sig"))
                .collect();
            paths.sort();
            if paths.len() > MAX_REVOCATIONS {
                return Err(ToolError::Trust("git.status-set-too-large".to_owned()));
            }
            for path in paths {
                revocations.push(read_bounded(&path, MAX_REVOCATION_BYTES)?);
            }
        }
        Ok(Self {
            context,
            revocations,
        })
    }

    /// Reads trust material from the tree of a Git commit.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError`] when the commit or files cannot be read.
    pub fn from_commit(commit: &str) -> Result<Self, ToolError> {
        let context = git(["show", &format!("{commit}:{TRUST_DIRECTORY}/{TRUST_FILE}")])?;
        if context.len() > MAX_TRUST_FILE_BYTES {
            return Err(ToolError::Trust("trust file exceeds its limit".to_owned()));
        }
        let listing = git([
            "ls-tree",
            "--name-only",
            commit,
            &format!("{TRUST_DIRECTORY}/{REVOCATIONS_DIRECTORY}/"),
        ])?;
        let names: Vec<String> = String::from_utf8_lossy(&listing)
            .lines()
            .filter(|name| {
                Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension == "sig")
            })
            .map(str::to_owned)
            .collect();
        if names.len() > MAX_REVOCATIONS {
            return Err(ToolError::Trust("git.status-set-too-large".to_owned()));
        }
        let mut revocations = Vec::with_capacity(names.len());
        for name in names {
            let record = git(["show", &format!("{commit}:{name}")])?;
            if record.len() > MAX_REVOCATION_BYTES {
                return Err(ToolError::Trust("revocation exceeds its limit".to_owned()));
            }
            revocations.push(record);
        }
        Ok(Self {
            context,
            revocations,
        })
    }

    /// Returns the lowercase SHA-256 of the trusted-context bytes.
    #[must_use]
    pub fn digest(&self) -> String {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(&self.context))
    }
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ToolError> {
    let metadata = fs::metadata(path)
        .map_err(|error| ToolError::Trust(format!("{}: {error}", path.display())))?;
    if usize::try_from(metadata.len()).map_or(true, |length| length > limit) {
        return Err(ToolError::Trust(format!(
            "{} exceeds its limit",
            path.display()
        )));
    }
    fs::read(path).map_err(|error| ToolError::Trust(format!("{}: {error}", path.display())))
}

/// The principal methods and signature suites this build can execute.
///
/// This is the only place that names them. Trust built with
/// [`EnabledMethods::with_registries`] commits to exactly this set, and a
/// verifier running a different set fails the configuration check.
pub struct EnabledMethods {
    did_key: DidKeyMethod,
    ed25519: Ed25519Suite,
}

impl EnabledMethods {
    /// Constructs the compiled method set.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::State`] if a compiled registry identifier is
    /// invalid.
    pub fn new() -> Result<Self, ToolError> {
        let invalid = |_| ToolError::State("invalid compiled registry".to_owned());
        Ok(Self {
            did_key: DidKeyMethod::new().map_err(invalid)?,
            ed25519: Ed25519Suite::new().map_err(invalid)?,
        })
    }

    /// Runs `use_sets` with the method and suite slices.
    pub fn with_sets<R>(
        &self,
        use_sets: impl FnOnce(&[&dyn PrincipalMethod], &[&dyn SignatureSuite]) -> R,
    ) -> R {
        let methods = [&self.did_key as &dyn PrincipalMethod];
        let suites = [&self.ed25519 as &dyn SignatureSuite];
        use_sets(&methods, &suites)
    }

    /// Runs `check` with the executable registries.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::State`] if the registries cannot be assembled.
    pub fn with_registries<R>(
        &self,
        check: impl FnOnce(&ImmutableRegistries<'_>) -> R,
    ) -> Result<R, ToolError> {
        self.with_sets(|methods, suites| {
            ImmutableRegistries::new(methods, suites)
                .map(|registries| check(&registries))
                .map_err(|_| ToolError::State("could not assemble registries".to_owned()))
        })
    }

    /// Decodes trust material and applies its revocations.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Trust`] for invalid trust or any invalid
    /// revocation.
    pub fn load_trust(&self, material: &TrustMaterial) -> Result<GitTrust, ToolError> {
        let trust = GitTrust::decode(&material.context)?;
        Ok(self.with_registries(|registries| {
            trust.with_revocations(&material.revocations, registries)
        })??)
    }
}

/// Returns `seconds` as a timestamp.
#[must_use]
pub const fn timestamp(seconds: u64) -> Timestamp {
    Timestamp::new(seconds)
}
