//! Durable exact-generation cleanup notes. These contain no credential or
//! external location and are retained independently of database restores.

use auths_connections::ConnectionId;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    num::NonZeroU64,
    path::PathBuf,
};

const MAX_GENERATIONS: usize = 64;
const MAX_BYTES: u64 = 16_384;
const CODE: &str = "gateway.admin.credential-journal-unavailable";

/// The private host's exact credential-generation cleanup notes.
#[derive(Clone)]
pub struct CredentialJournal {
    directory: PathBuf,
}

/// Exact-generation obligation state; no state here authorizes publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialCleanupPhase {
    /// A completed custody mutation may have left this generation present.
    Retained,
    /// Custody creation is in progress or its completion is unconfirmed.
    /// Collection cannot forget this obligation merely because revoke is absent.
    MutationPending,
    /// Exact deletion may have been entered; repeating it is idempotent.
    DeletionPending,
    /// A deletion reported failure; its actual external effect remains uncertain.
    DeletionIncomplete,
    /// Exact deletion acknowledged; only durable note removal remains.
    DeletionConfirmed,
}

/// One bounded exact-generation cleanup obligation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialCleanupNote {
    /// Exact immutable custody generation.
    pub generation: NonZeroU64,
    /// Durable cleanup/mutation completion knowledge, never entry authority.
    pub phase: CredentialCleanupPhase,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalContents {
    schema: String,
    connection_id: String,
    notes: Vec<CredentialCleanupNote>,
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
            if !notes.notes.iter().any(|note| note.generation == generation) {
                notes.notes.push(CredentialCleanupNote {
                    generation,
                    phase: CredentialCleanupPhase::Retained,
                });
                notes.notes.sort_unstable_by_key(|note| note.generation);
            }
            if notes.notes.len() > MAX_GENERATIONS {
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
            .map(|notes| notes.into_iter().map(|note| note.generation).collect())
    }

    /// Removes a note only after exact deletion succeeded.
    ///
    /// # Errors
    /// An unavailable journal retains the cleanup obligation.
    pub fn forget(&self, id: &ConnectionId, generation: NonZeroU64) -> Result<(), &'static str> {
        self.change(id, false, |notes| {
            if notes.notes.iter().any(|note| {
                note.generation == generation
                    && note.phase != CredentialCleanupPhase::DeletionConfirmed
            }) {
                return Err(CODE);
            }
            notes.notes.retain(|known| known.generation != generation);
            Ok(())
        })
        .map(|_| ())
    }

    /// Reads phase-bearing obligations without treating an unreadable set as empty.
    ///
    /// # Errors
    /// Refuses missing, malformed or mismatched journals.
    pub fn notes(&self, id: &ConnectionId) -> Result<Vec<CredentialCleanupNote>, &'static str> {
        self.change(id, false, |_| Ok(()))
    }

    /// Claims one generation before custody creation. Competing/uncertain
    /// creation is not overwritten and cannot race confirmed cleanup.
    ///
    /// # Errors
    /// Refuses a missing note or a generation already pending mutation/deletion.
    pub fn begin_mutation(
        &self,
        id: &ConnectionId,
        generation: NonZeroU64,
    ) -> Result<(), &'static str> {
        self.phase(
            id,
            generation,
            &[CredentialCleanupPhase::Retained],
            CredentialCleanupPhase::MutationPending,
        )
    }

    /// Records acknowledged completion of this owner's custody creation.
    ///
    /// # Errors
    /// Refuses an unmatched generation or an unavailable journal.
    pub fn confirm_mutation(
        &self,
        id: &ConnectionId,
        generation: NonZeroU64,
    ) -> Result<(), &'static str> {
        self.phase(
            id,
            generation,
            &[CredentialCleanupPhase::MutationPending],
            CredentialCleanupPhase::Retained,
        )
    }

    /// Claims exact deletion only after the caller checked native generation
    /// and elapsed retirement delay. Pending creation is never collectible.
    ///
    /// # Errors
    /// Refuses unconfirmed custody creation or unavailable state.
    pub fn begin_deletion(
        &self,
        id: &ConnectionId,
        generation: NonZeroU64,
    ) -> Result<(), &'static str> {
        self.phase(
            id,
            generation,
            &[
                CredentialCleanupPhase::Retained,
                CredentialCleanupPhase::DeletionPending,
                CredentialCleanupPhase::DeletionIncomplete,
            ],
            CredentialCleanupPhase::DeletionPending,
        )
    }

    /// Retains a failed/ambiguous exact deletion for an explicit later attempt.
    ///
    /// # Errors
    /// Refuses invalid phase or unavailable durable state.
    pub fn fail_deletion(
        &self,
        id: &ConnectionId,
        generation: NonZeroU64,
    ) -> Result<(), &'static str> {
        self.phase(
            id,
            generation,
            &[CredentialCleanupPhase::DeletionPending],
            CredentialCleanupPhase::DeletionIncomplete,
        )
    }

    /// Persists exact deletion acknowledgement before removal of the obligation.
    ///
    /// # Errors
    /// Refuses invalid phase or unavailable durable state.
    pub fn confirm_deletion(
        &self,
        id: &ConnectionId,
        generation: NonZeroU64,
    ) -> Result<(), &'static str> {
        self.phase(
            id,
            generation,
            &[
                CredentialCleanupPhase::DeletionPending,
                CredentialCleanupPhase::DeletionConfirmed,
            ],
            CredentialCleanupPhase::DeletionConfirmed,
        )
    }

    fn phase(
        &self,
        id: &ConnectionId,
        generation: NonZeroU64,
        allowed: &[CredentialCleanupPhase],
        next: CredentialCleanupPhase,
    ) -> Result<(), &'static str> {
        self.change(id, false, |notes| {
            let note = notes
                .notes
                .iter_mut()
                .find(|note| note.generation == generation)
                .ok_or(CODE)?;
            if !allowed.contains(&note.phase) {
                return Err("gateway.admin.credential-operation-unconfirmed");
            }
            note.phase = next;
            Ok(())
        })
        .map(|_| ())
    }

    #[cfg(unix)]
    fn change(
        &self,
        id: &ConnectionId,
        initialize: bool,
        update: impl FnOnce(&mut JournalContents) -> Result<(), &'static str>,
    ) -> Result<Vec<CredentialCleanupNote>, &'static str> {
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
        let lock_metadata = lock.metadata().map_err(|_| CODE)?;
        if !lock_metadata.is_file()
            || lock_metadata.permissions().mode() & 0o077 != 0
            || lock_metadata.uid() != rustix::process::geteuid().as_raw()
            || lock_metadata.nlink() != 1
        {
            return Err(CODE);
        }
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).map_err(|_| CODE)?;
        let path = self.directory.join("credential-journal.json");
        let mut notes = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.permissions().mode() & 0o077 != 0
                    || metadata.uid() != rustix::process::geteuid().as_raw()
                    || metadata.nlink() != 1
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
                serde_json::from_slice::<JournalContents>(&bytes).map_err(|_| CODE)?
            }
            Err(error) if initialize && error.kind() == std::io::ErrorKind::NotFound => {
                JournalContents {
                    schema: "auths.gateway-credential-journal/2".to_owned(),
                    connection_id: id.as_str().to_owned(),
                    notes: Vec::new(),
                }
            }
            Err(_) => return Err(CODE),
        };
        if notes.schema != "auths.gateway-credential-journal/2"
            || notes.connection_id != id.as_str()
            || notes.notes.len() > MAX_GENERATIONS
            || !notes
                .notes
                .windows(2)
                .all(|pair| pair[0].generation < pair[1].generation)
        {
            return Err(CODE);
        }
        crate::admin_fault::boundary("credential-journal.before-update");
        update(&mut notes)?;
        let bytes = serde_json::to_vec(&notes).map_err(|_| CODE)?;
        let mut pending = tempfile::NamedTempFile::new_in(&self.directory).map_err(|_| CODE)?;
        pending
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| CODE)?;
        crate::admin_fault::boundary("credential-journal.before-file-write");
        pending.write_all(&bytes).map_err(|_| CODE)?;
        crate::admin_fault::boundary("credential-journal.after-file-content");
        pending.as_file().sync_all().map_err(|_| CODE)?;
        crate::admin_fault::boundary("credential-journal.after-file-sync");
        pending.persist(path).map_err(|_| CODE)?;
        crate::admin_fault::boundary("credential-journal.after-replacement");
        File::open(&self.directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| CODE)?;
        crate::admin_fault::boundary("credential-journal.after-parent-sync");
        Ok(notes.notes)
    }

    #[cfg(not(unix))]
    fn change(
        &self,
        _id: &ConnectionId,
        _initialize: bool,
        _update: impl FnOnce(&mut JournalContents) -> Result<(), &'static str>,
    ) -> Result<Vec<CredentialCleanupNote>, &'static str> {
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
        let foreign = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAQ").expect("foreign id");
        assert_eq!(reopened.generations(&foreign), Err(CODE));
        reopened
            .begin_deletion(&id, NonZeroU64::MIN)
            .expect("claim exact deletion");
        reopened
            .confirm_deletion(&id, NonZeroU64::MIN)
            .expect("acknowledged exact deletion");
        reopened
            .forget(&id, NonZeroU64::MIN)
            .expect("deleted generation");
        assert_eq!(reopened.generations(&id).expect("notes").len(), 63);
        fs::write(directory.path().join("credential-journal.json"), b"corrupt").expect("corrupt");
        assert_eq!(reopened.generations(&id), Err(CODE));
    }

    #[test]
    fn unconfirmed_creation_survives_restart_and_cannot_be_forgotten_or_deleted() {
        let directory = tempfile::tempdir().expect("private root");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private mode");
        let id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").expect("id");
        let journal = CredentialJournal::new(directory.path().to_path_buf());
        journal.initialize(&id).expect("initialize");
        journal.register(&id, NonZeroU64::MIN).expect("write ahead");
        journal
            .begin_mutation(&id, NonZeroU64::MIN)
            .expect("claim mutation");
        let reopened = CredentialJournal::new(directory.path().to_path_buf());
        assert_eq!(
            reopened.notes(&id).expect("notes")[0].phase,
            CredentialCleanupPhase::MutationPending
        );
        assert!(reopened.begin_deletion(&id, NonZeroU64::MIN).is_err());
        assert!(reopened.forget(&id, NonZeroU64::MIN).is_err());
        assert!(reopened.begin_mutation(&id, NonZeroU64::MIN).is_err());
        reopened
            .register(&id, NonZeroU64::MIN)
            .expect("register cannot revive");
        assert_eq!(
            reopened.notes(&id).expect("retained pending")[0].phase,
            CredentialCleanupPhase::MutationPending
        );
        // Only the operation owner can acknowledge its completed I/O. Merely
        // observing current absence is deliberately not a completion API.
        journal
            .confirm_mutation(&id, NonZeroU64::MIN)
            .expect("owner settled");
        reopened
            .begin_deletion(&id, NonZeroU64::MIN)
            .expect("safe claim");
        reopened
            .fail_deletion(&id, NonZeroU64::MIN)
            .expect("uncertain delete");
        assert_eq!(
            reopened.notes(&id).expect("uncertain note")[0].phase,
            CredentialCleanupPhase::DeletionIncomplete
        );
        reopened
            .begin_deletion(&id, NonZeroU64::MIN)
            .expect("explicit idempotent retry");
        reopened
            .confirm_deletion(&id, NonZeroU64::MIN)
            .expect("exact delete ack");
        let reopened = CredentialJournal::new(directory.path().to_path_buf());
        assert_eq!(
            reopened.notes(&id).expect("confirmed after restart")[0].phase,
            CredentialCleanupPhase::DeletionConfirmed
        );
        reopened
            .forget(&id, NonZeroU64::MIN)
            .expect("durable removal");
        assert!(reopened.notes(&id).expect("confirmed empty").is_empty());
    }

    #[test]
    fn competing_custody_creation_and_cleanup_cannot_both_claim_one_generation() {
        use std::sync::{Arc, Barrier};
        for _ in 0..16 {
            let directory = tempfile::tempdir().expect("private root");
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("private mode");
            let id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").expect("id");
            let journal = CredentialJournal::new(directory.path().to_path_buf());
            journal.initialize(&id).expect("initialize");
            journal.register(&id, NonZeroU64::MIN).expect("note");
            let barrier = Arc::new(Barrier::new(3));
            let mut workers = Vec::new();
            for mutate in [true, false] {
                let journal = journal.clone();
                let id = id.clone();
                let barrier = Arc::clone(&barrier);
                workers.push(std::thread::spawn(move || {
                    barrier.wait();
                    if mutate {
                        journal.begin_mutation(&id, NonZeroU64::MIN)
                    } else {
                        journal.begin_deletion(&id, NonZeroU64::MIN)
                    }
                }));
            }
            barrier.wait();
            let outcomes: Vec<_> = workers
                .into_iter()
                .map(|worker| worker.join().expect("worker"))
                .collect();
            assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        }
    }

    #[test]
    fn obsolete_optional_generation_notes_are_not_a_compatibility_reader() {
        let directory = tempfile::tempdir().expect("private root");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private mode");
        let id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").expect("id");
        fs::write(directory.path().join("credential-journal.json"),
            br#"{"schema":"auths.gateway-credential-journal/1","connection_id":"conn_AAAAAAAAAAAAAAAAAAAAAA","generations":[1]}"#).expect("obsolete input");
        let journal = CredentialJournal::new(directory.path().to_path_buf());
        assert_eq!(journal.notes(&id), Err(CODE));
        assert_eq!(journal.initialize(&id), Err(CODE));
    }
}
