//! Deployment-owned profile verifier configuration loaded before credentials.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use auths_config::AgentConfig;
use auths_profile_runtime::ProfileConfigurationBinding;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read as _,
    path::{Component, Path},
    sync::Arc,
};
use thiserror::Error;

const MAX_TOTAL_CONFIGURATION_BYTES: usize = 16 * 1024 * 1024;

/// Immutable all-or-nothing profile-configuration snapshot.
#[derive(Clone, Debug, Default)]
pub struct ProfileConfigurationSnapshot {
    values: Arc<BTreeMap<String, Arc<ProfileConfigurationBinding>>>,
}

impl ProfileConfigurationSnapshot {
    /// Loads and hashes every exact configured file before socket bind.
    #[cfg(unix)]
    pub fn load(
        config: &AgentConfig,
        agent_uid: u32,
        mutable_state_root: &Path,
    ) -> Result<Self, ProfileConfigurationError> {
        let mut total = 0_usize;
        let mut values = BTreeMap::new();
        for (profile, source) in config.profile_configurations() {
            let path = Path::new(source.path());
            if path.starts_with(mutable_state_root) {
                return Err(ProfileConfigurationError::UnsafePath);
            }
            let (bytes, identity) =
                read_absolute(path, agent_uid, source.maximum_bytes() as usize)?;
            total = total
                .checked_add(bytes.len())
                .filter(|value| *value <= MAX_TOTAL_CONFIGURATION_BYTES)
                .ok_or(ProfileConfigurationError::Limit)?;
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            if hex::encode(digest) != source.sha256() {
                return Err(ProfileConfigurationError::DigestMismatch);
            }
            let binding = ProfileConfigurationBinding::from_loader(
                profile.clone(),
                source.format().to_owned(),
                Arc::from(bytes),
                digest,
                path.to_owned(),
                source.maximum_bytes() as usize,
                identity.device,
                identity.inode,
                identity.length,
                identity.modified_nanoseconds,
            );
            if values.insert(profile.clone(), Arc::new(binding)).is_some() {
                return Err(ProfileConfigurationError::InvalidBinding);
            }
        }
        Ok(Self {
            values: Arc::new(values),
        })
    }

    /// Returns the binding for one exact profile reference.
    #[must_use]
    pub fn get(&self, profile: &str) -> Option<Arc<ProfileConfigurationBinding>> {
        self.values.get(profile).cloned()
    }

    /// Iterates exact byte-sorted profile bindings.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &ProfileConfigurationBinding)> {
        self.values
            .iter()
            .map(|(profile, binding)| (profile.as_str(), binding.as_ref()))
    }
}

/// Securely re-reads one startup-validated binding immediately before a
/// credential lease and proves that neither the file nor its bytes changed.
#[cfg(unix)]
pub(crate) fn revalidate_binding(
    binding: &ProfileConfigurationBinding,
) -> Result<(), ProfileConfigurationError> {
    let agent_uid = rustix::process::geteuid().as_raw();
    let (bytes, identity) = read_absolute(binding.path(), agent_uid, binding.maximum_bytes())?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if bytes != binding.canonical_bytes()
        || digest != binding.sha256()
        || identity.device != binding.file_device()
        || identity.inode != binding.file_inode()
        || identity.length != binding.file_length()
        || identity.modified_nanoseconds != binding.file_modified_nanoseconds()
    {
        return Err(ProfileConfigurationError::DigestMismatch);
    }
    Ok(())
}

/// Closed deployment profile-configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProfileConfigurationError {
    #[error("unsafe profile configuration path")]
    UnsafePath,
    #[error("unsafe profile configuration storage")]
    UnsafeStorage,
    #[error("profile configuration exceeds its bound")]
    Limit,
    #[error("profile configuration digest mismatch")]
    DigestMismatch,
    #[error("invalid profile configuration binding")]
    InvalidBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_nanoseconds: i128,
}

#[cfg(unix)]
fn read_absolute(
    path: &Path,
    agent_uid: u32,
    maximum: usize,
) -> Result<(Vec<u8>, FileIdentity), ProfileConfigurationError> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;

    if !path.is_absolute() || maximum == 0 || maximum > 524_288 {
        return Err(ProfileConfigurationError::UnsafePath);
    }
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(value) => Some(Ok(value)),
            _ => Some(Err(ProfileConfigurationError::UnsafePath)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err(ProfileConfigurationError::UnsafePath);
    }
    let root_fd = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProfileConfigurationError::UnsafePath)?;
    let mut directory: File = root_fd.into();
    for component in &components[..components.len() - 1] {
        let fd = rustix::fs::openat(
            &directory,
            Path::new(component),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ProfileConfigurationError::UnsafePath)?;
        let next: File = fd.into();
        let metadata = next
            .metadata()
            .map_err(|_| ProfileConfigurationError::UnsafePath)?;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != agent_uid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(ProfileConfigurationError::UnsafeStorage);
        }
        directory = next;
    }
    let fd = rustix::fs::openat(
        &directory,
        Path::new(components[components.len() - 1]),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProfileConfigurationError::UnsafePath)?;
    let mut file: File = fd.into();
    let before = file
        .metadata()
        .map_err(|_| ProfileConfigurationError::UnsafePath)?;
    if !before.is_file()
        || before.nlink() != 1
        || (before.uid() != 0 && before.uid() != agent_uid)
        || before.mode() & 0o022 != 0
        || before.len() == 0
        || before.len() > maximum as u64
    {
        return Err(ProfileConfigurationError::UnsafeStorage);
    }
    let capacity =
        usize::try_from(before.len()).map_err(|_| ProfileConfigurationError::UnsafeStorage)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProfileConfigurationError::UnsafePath)?;
    let after = file
        .metadata()
        .map_err(|_| ProfileConfigurationError::UnsafePath)?;
    let identity = |value: &std::fs::Metadata| FileIdentity {
        device: value.dev(),
        inode: value.ino(),
        length: value.len(),
        modified_nanoseconds: i128::from(value.mtime()) * 1_000_000_000
            + i128::from(value.mtime_nsec()),
    };
    let before_identity = identity(&before);
    if bytes.is_empty()
        || bytes.len() > maximum
        || before_identity != identity(&after)
        || bytes.len() as u64 != before.len()
    {
        return Err(ProfileConfigurationError::UnsafeStorage);
    }
    Ok((bytes, before_identity))
}
