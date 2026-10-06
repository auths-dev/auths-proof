//! Host-local anti-rollback witness retained independently of database backups.
//! It records only a generation and the digest of the exact connection record.

use auths_connections::ConnectionRecord;
use auths_recipe_qualification::Sha256Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    num::NonZeroU64,
    path::PathBuf,
};

/// A durable floor for the one connection an installed gateway serves.
/// Retain this file and its qualification floors independently of restores.
#[derive(Clone)]
pub struct GenerationFloor {
    directory: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Accepted {
    schema: String,
    generation: NonZeroU64,
    record_sha256: Sha256Digest,
}

impl GenerationFloor {
    /// Names the already-private installation directory. The gateway CLI
    /// checks ownership and rejects symlink paths before using it.
    #[must_use]
    pub const fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// Creates the floor during a fresh installation. An existing floor is
    /// checked rather than replaced; runtime startup never initializes one.
    ///
    /// # Errors
    /// Returns the restore-rollback code if the floor cannot be persisted.
    pub fn initialize(&self, record: &ConnectionRecord) -> Result<(), &'static str> {
        self.persist(record, true)
            .map_err(|()| "gateway.connection.restore-rollback")
    }

    /// Accepts an equal or newer exact record, durably recording a newer one
    /// before it can authorize a lease. A missing floor refuses; a
    /// malformed, inaccessible, older or substituted floor fails closed.
    ///
    /// # Errors
    /// Returns `gateway.connection.restore-rollback`; no secret is leased.
    pub fn accept(&self, record: &ConnectionRecord) -> Result<(), &'static str> {
        self.persist(record, false)
            .map_err(|()| "gateway.connection.restore-rollback")
    }

    #[cfg(unix)]
    fn persist(&self, record: &ConnectionRecord, initialize: bool) -> Result<(), ()> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(i32::from_ne_bytes(
                rustix::fs::OFlags::NOFOLLOW.bits().to_ne_bytes(),
            ));
        let lock = options
            .open(self.directory.join("connection-floor.lock"))
            .map_err(|_| ())?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).map_err(|_| ())?;
        let path = self.directory.join("connection-floor.json");
        let digest = Sha256Digest::from_bytes(
            Sha256::digest(record.to_canonical_cbor().map_err(|_| ())?).into(),
        );
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.permissions().mode() & 0o077 != 0
                    || metadata.len() > 1024
                {
                    return Err(());
                }
                let mut bytes = Vec::new();
                OpenOptions::new()
                    .read(true)
                    .custom_flags(i32::from_ne_bytes(
                        rustix::fs::OFlags::NOFOLLOW.bits().to_ne_bytes(),
                    ))
                    .open(&path)
                    .map_err(|_| ())?
                    .take(1025)
                    .read_to_end(&mut bytes)
                    .map_err(|_| ())?;
                if bytes.len() > 1024 {
                    return Err(());
                }
                let old: Accepted = serde_json::from_slice(&bytes).map_err(|_| ())?;
                if old.schema != "auths.gateway-generation-floor/1"
                    || old.generation > record.generation()
                {
                    return Err(());
                }
                if old.generation == record.generation() {
                    return if old.record_sha256 == digest {
                        Ok(())
                    } else {
                        Err(())
                    };
                }
            }
            Err(error) if initialize && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(()),
        }
        let bytes = serde_json::to_vec(&Accepted {
            schema: "auths.gateway-generation-floor/1".to_owned(),
            generation: record.generation(),
            record_sha256: digest,
        })
        .map_err(|_| ())?;
        let mut pending = tempfile::NamedTempFile::new_in(&self.directory).map_err(|_| ())?;
        pending
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| ())?;
        pending
            .write_all(&bytes)
            .and_then(|()| pending.as_file().sync_all())
            .map_err(|_| ())?;
        pending.persist(path).map_err(|_| ())?;
        File::open(&self.directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| ())
    }

    #[cfg(not(unix))]
    fn persist(&self, _record: &ConnectionRecord, _initialize: bool) -> Result<(), ()> {
        Err(())
    }
}
