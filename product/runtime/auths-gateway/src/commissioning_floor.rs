//! Host-retained commissioning witness, outside the database restore set.
//!
//! A host lock spans reading the prior floor, claiming shared capacity and
//! durably replacing the witness. No successful claim is returned until the
//! witness and its directory have been synchronized. A crash or failed write
//! can burn a unit; it cannot refund one. Runtime never initializes a floor.

use crate::commissioning_budget::{
    CommissioningBudget, CommissioningBudgetRefusal, CommissioningBudgetSnapshot,
    CommissioningBudgetUpdate, MAX_COMMISSIONING_BUDGET_BYTES,
};
use auths_recipe_qualification::{
    CommissioningBinding, CommissioningRequest, VerifiedCommissioningPermit, VerifierState,
};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::PathBuf,
};

/// One host's monotone witness for an exact commissioning run/family.
/// The authenticated operator supplies an already-private installation
/// directory, retained independently of database backups. This object grants
/// no application access or credential authority.
#[derive(Clone)]
pub struct CommissioningFloor {
    directory: PathBuf,
    binding: CommissioningBinding,
    leaf: String,
}

impl CommissioningFloor {
    /// Names the floor using the renewal-stable run/family budget key.
    ///
    /// # Errors
    /// Refuses invalid bindings. Does not create files or database state.
    pub fn new(
        directory: PathBuf,
        binding: CommissioningBinding,
    ) -> Result<Self, CommissioningBudgetRefusal> {
        binding
            .validate()
            .map_err(|_| CommissioningBudgetRefusal::BindingMismatch)?;
        let leaf = format!(
            "commissioning-{}",
            binding
                .budget_key()
                .map_err(|_| CommissioningBudgetRefusal::BindingMismatch)?
                .to_hex()
        );
        Ok(Self {
            directory,
            binding,
            leaf,
        })
    }

    /// Fresh authenticated setup retains the registered database snapshot.
    /// An existing witness is never reset or overwritten by older state.
    ///
    /// # Errors
    /// Refuses inaccessible, unsafe, corrupt, substituted or decreasing state.
    /// Runtime startup and permit renewal must never use this initializer.
    #[cfg(unix)]
    pub fn initialize(
        &self,
        registered: &CommissioningBudgetSnapshot,
    ) -> Result<(), CommissioningBudgetRefusal> {
        let _lock = self.lock()?;
        CommissioningBudgetSnapshot::from_canonical_json(
            registered.canonical_bytes(),
            &self.binding,
        )?;
        match self.read() {
            Ok(previous) if !registered.not_below(&previous) => {
                return Err(CommissioningBudgetRefusal::Rollback);
            }
            Ok(_) | Err(CommissioningBudgetRefusal::Missing) => {}
            Err(error) => return Err(error),
        }
        self.persist(registered)
    }

    /// Loads an existing host witness under its private lock.
    ///
    /// # Errors
    /// Missing or unsafe witnesses refuse; no state is recreated.
    #[cfg(unix)]
    pub fn load(&self) -> Result<CommissioningBudgetSnapshot, CommissioningBudgetRefusal> {
        let _lock = self.lock()?;
        self.read()
    }

    /// Claims shared capacity and durably retains the result before returning.
    /// The private operator session must inspect `refusal` before custody.
    /// Denial still remembers authenticated revocations. The host lock makes
    /// concurrent submissions unable to overwrite a newer local witness.
    ///
    /// # Errors
    /// Returns a typed refusal without authorizing custody. A failed witness
    /// write after the database commit leaves its unit consumed permanently.
    #[cfg(unix)]
    pub fn claim(
        &self,
        budget: &CommissioningBudget,
        authority: &VerifiedCommissioningPermit,
        request: &CommissioningRequest<'_>,
        now: u64,
        clock_trusted: bool,
        state: &VerifierState,
    ) -> Result<CommissioningBudgetUpdate, CommissioningBudgetRefusal> {
        let _lock = self.lock()?;
        let previous = self.read().map_err(|error| match error {
            CommissioningBudgetRefusal::Missing => CommissioningBudgetRefusal::Rollback,
            other => other,
        })?;
        let update = budget.claim(authority, request, now, clock_trusted, &previous, state)?;
        self.persist(update.snapshot())?;
        Ok(update)
    }

    #[cfg(unix)]
    fn lock(&self) -> Result<File, CommissioningBudgetRefusal> {
        let directory = fs::symlink_metadata(&self.directory)
            .map_err(|_| CommissioningBudgetRefusal::Rollback)?;
        if !directory.is_dir()
            || directory.permissions().mode() & 0o077 != 0
            || directory.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(CommissioningBudgetRefusal::Rollback);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nofollow())
            .open(self.directory.join(format!("{}.lock", self.leaf)))
            .map_err(|_| CommissioningBudgetRefusal::Rollback)?;
        let metadata = file
            .metadata()
            .map_err(|_| CommissioningBudgetRefusal::Rollback)?;
        if !safe_file(&metadata) {
            return Err(CommissioningBudgetRefusal::Rollback);
        }
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|_| CommissioningBudgetRefusal::Rollback)?;
        Ok(file)
    }

    #[cfg(unix)]
    fn read(&self) -> Result<CommissioningBudgetSnapshot, CommissioningBudgetRefusal> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nofollow())
            .open(self.directory.join(format!("{}.json", self.leaf)))
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    CommissioningBudgetRefusal::Missing
                } else {
                    CommissioningBudgetRefusal::Rollback
                }
            })?;
        let metadata = file
            .metadata()
            .map_err(|_| CommissioningBudgetRefusal::Rollback)?;
        if !safe_file(&metadata) || metadata.len() > MAX_COMMISSIONING_BUDGET_BYTES as u64 {
            return Err(CommissioningBudgetRefusal::Rollback);
        }
        let mut bytes = Vec::new();
        file.take(MAX_COMMISSIONING_BUDGET_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| CommissioningBudgetRefusal::Rollback)?;
        CommissioningBudgetSnapshot::from_canonical_json(&bytes, &self.binding)
    }

    #[cfg(unix)]
    fn persist(
        &self,
        snapshot: &CommissioningBudgetSnapshot,
    ) -> Result<(), CommissioningBudgetRefusal> {
        let mut pending = tempfile::NamedTempFile::new_in(&self.directory)
            .map_err(|_| CommissioningBudgetRefusal::Rollback)?;
        pending
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| CommissioningBudgetRefusal::Rollback)?;
        pending
            .write_all(snapshot.canonical_bytes())
            .and_then(|()| pending.as_file().sync_all())
            .map_err(|_| CommissioningBudgetRefusal::Rollback)?;
        pending
            .persist(self.directory.join(format!("{}.json", self.leaf)))
            .map_err(|_| CommissioningBudgetRefusal::Rollback)?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| CommissioningBudgetRefusal::Rollback)
    }
}

#[cfg(unix)]
fn nofollow() -> i32 {
    i32::from_ne_bytes(rustix::fs::OFlags::NOFOLLOW.bits().to_ne_bytes())
}

#[cfg(unix)]
#[allow(
    clippy::verbose_bit_mask,
    reason = "octal permission bits name the exact forbidden Unix access"
)]
fn safe_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && metadata.permissions().mode() & 0o077 == 0
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.nlink() == 1
}

#[cfg(all(test, unix))]
mod tests;
