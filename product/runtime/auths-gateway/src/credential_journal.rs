//! Durable exact-generation cleanup notes. These contain no credential or
//! external location and are retained independently of database restores.

use auths_connections::ConnectionId;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    num::NonZeroU64,
    path::PathBuf,
};

const MAX_GENERATIONS: usize = 64;
const MAX_BYTES: u64 = 4096;
const CODE: &str = "gateway.admin.credential-journal-unavailable";

/// The private host's exact credential-generation cleanup notes.
#[derive(Clone)]
pub struct CredentialJournal {
    directory: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Notes {
    schema: String,
    connection_id: String,
    generations: Vec<NonZeroU64>,
}

impl CredentialJournal {
    /// Names a private installation directory validated by the gateway CLI.
    #[must_use]
    pub const fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// Initializes a fresh installation's journal before storing a secret.
    ///
    /// # Errors
    /// Refuses an existing journal for another connection or invalid state.
    pub fn initialize(&self, id: &ConnectionId) -> Result<(), &'static str> {
        self.change(id, true, |_| Ok(())).map(|_| ())
    }

    /// Records an exact generation before a custody mutation can create it.
    ///
    /// # Errors
    /// Missing, malformed, oversized or full journals stop the mutation.
    pub fn register(&self, id: &ConnectionId, generation: NonZeroU64) -> Result<(), &'static str> {
        self.change(id, false, |notes| {
            if !notes.generations.contains(&generation) {
                notes.generations.push(generation);
                notes.generations.sort_unstable();
            }
            if notes.generations.len() > MAX_GENERATIONS {
                return Err(CODE);
            }
            Ok(())
        })
        .map(|_| ())
    }

    /// Reads the bounded set of exact known generations, never a remote list.
    ///
    /// # Errors
    /// Missing or damaged state is refused, not treated as an empty journal.
    pub fn generations(&self, id: &ConnectionId) -> Result<Vec<NonZeroU64>, &'static str> {
        self.change(id, false, |_| Ok(()))
    }

    /// Removes a note only after exact deletion succeeded.
    ///
    /// # Errors
    /// An unavailable journal retains the cleanup obligation.
    pub fn forget(&self, id: &ConnectionId, generation: NonZeroU64) -> Result<(), &'static str> {
        self.change(id, false, |notes| {
            notes.generations.retain(|known| *known != generation);
            Ok(())
        })
        .map(|_| ())
    }

    #[cfg(unix)]
    fn change(
        &self,
        id: &ConnectionId,
        initialize: bool,
        update: impl FnOnce(&mut Notes) -> Result<(), &'static str>,
    ) -> Result<Vec<NonZeroU64>, &'static str> {
        let flags = i32::from_ne_bytes(rustix::fs::OFlags::NOFOLLOW.bits().to_ne_bytes());
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(flags)
            .open(self.directory.join("credential-journal.lock"))
            .map_err(|_| CODE)?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).map_err(|_| CODE)?;
        let path = self.directory.join("credential-journal.json");
        let mut notes = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.permissions().mode() & 0o077 != 0
                    || metadata.len() > MAX_BYTES
                {
                    return Err(CODE);
                }
                let mut bytes = Vec::new();
                OpenOptions::new()
                    .read(true)
                    .custom_flags(flags)
                    .open(&path)
                    .map_err(|_| CODE)?
                    .take(MAX_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| CODE)?;
                if bytes.len() as u64 > MAX_BYTES {
                    return Err(CODE);
                }
                serde_json::from_slice::<Notes>(&bytes).map_err(|_| CODE)?
            }
            Err(error) if initialize && error.kind() == std::io::ErrorKind::NotFound => Notes {
                schema: "auths.gateway-credential-journal/1".to_owned(),
                connection_id: id.as_str().to_owned(),
                generations: Vec::new(),
            },
            Err(_) => return Err(CODE),
        };
        if notes.schema != "auths.gateway-credential-journal/1"
            || notes.connection_id != id.as_str()
            || notes.generations.len() > MAX_GENERATIONS
            || !notes.generations.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(CODE);
        }
        update(&mut notes)?;
        let bytes = serde_json::to_vec(&notes).map_err(|_| CODE)?;
        let mut pending = tempfile::NamedTempFile::new_in(&self.directory).map_err(|_| CODE)?;
        pending
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| CODE)?;
        pending
            .write_all(&bytes)
            .and_then(|()| pending.as_file().sync_all())
            .map_err(|_| CODE)?;
        pending.persist(path).map_err(|_| CODE)?;
        File::open(&self.directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| CODE)?;
        Ok(notes.generations)
    }

    #[cfg(not(unix))]
    fn change(
        &self,
        _id: &ConnectionId,
        _initialize: bool,
        _update: impl FnOnce(&mut Notes) -> Result<(), &'static str>,
    ) -> Result<Vec<NonZeroU64>, &'static str> {
        Err(CODE)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn notes_survive_restart_and_refuse_missing_corrupt_full_or_foreign_state() {
        let directory = tempfile::tempdir().expect("directory");
        let id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").expect("id");
        let journal = CredentialJournal::new(directory.path().to_path_buf());
        assert_eq!(journal.generations(&id), Err(CODE));
        journal.initialize(&id).expect("initialize");
        for generation in 1..=64 {
            journal
                .register(&id, NonZeroU64::new(generation).expect("generation"))
                .expect("note");
        }
        assert_eq!(
            journal.register(&id, NonZeroU64::new(65).expect("generation")),
            Err(CODE)
        );
        let reopened = CredentialJournal::new(directory.path().to_path_buf());
        assert_eq!(reopened.generations(&id).expect("notes").len(), 64);
        let foreign = ConnectionId::parse("conn_BBBBBBBBBBBBBBBBBBBBBB").expect("id");
        assert_eq!(reopened.generations(&foreign), Err(CODE));
        reopened
            .forget(&id, NonZeroU64::MIN)
            .expect("deleted generation");
        assert_eq!(reopened.generations(&id).expect("notes").len(), 63);
        fs::write(directory.path().join("credential-journal.json"), b"corrupt").expect("corrupt");
        assert_eq!(reopened.generations(&id), Err(CODE));
    }
}
