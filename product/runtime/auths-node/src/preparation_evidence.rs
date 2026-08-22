//! Durable, opaque preparation-evidence leases for manifest-declared profile companions.

#![forbid(unsafe_code)]

use auths_connections::ConnectionBinding;
use auths_lifecycle::OperationProfileV1;
use auths_production_client::{PreparationEvidenceLease, PrepareOperationRequest};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File},
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    path::Path,
};

const LEASE_SCHEMA: &str = "auths.preparation-evidence-lease/1";
const MAX_LEASES: usize = 1_024;
const MAX_LEASE_BYTES: usize = 1_048_576;
const MAX_TOTAL_BYTES: u64 = 67_108_864;
const LEASE_TTL_SECONDS: u64 = 120;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LeaseRecord {
    schema: String,
    binding_sha256: String,
    semantic_binding_sha256: String,
    handle_sha256: String,
    handle_base64url: String,
    principal_sha256: String,
    profile_id: String,
    profile_version: u16,
    runtime_contract_sha256: String,
    workflow_id: String,
    request_id_base64url: String,
    idempotency_sha256: Option<String>,
    profile_input_sha256: String,
    connection_id: String,
    connection_generation: u64,
    connection_descriptor_sha256: String,
    connection_account_sha256: String,
    configuration_sha256: String,
    authority_sha256: String,
    evidence_sha256: String,
    evidence_base64url: String,
    accepted_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

pub(crate) struct LeaseBinding<'a> {
    pub principal: &'a str,
    pub profile: &'a OperationProfileV1,
    pub workflow_id: &'a str,
    pub request: &'a PrepareOperationRequest,
    pub connection: &'a ConnectionBinding,
    pub configuration_sha256: [u8; 32],
    pub authority_sha256: [u8; 32],
    pub authority_artifact_sha256: [u8; 32],
}

pub(crate) struct ResolvedPreparationEvidence {
    pub bytes: Vec<u8>,
    pub commitment: [u8; 32],
    pub expires_at_unix_seconds: u64,
    pub authority_sha256: [u8; 32],
    pub intent_sha256: [u8; 32],
}

pub(crate) struct PreparationEvidenceLeaseStore {
    directory: File,
}

impl PreparationEvidenceLeaseStore {
    pub(crate) fn open(profile_state_root: &Path) -> Result<Self, ()> {
        let root = profile_state_root.join("preparation-evidence-leases-v1");
        ensure_private_directory(profile_state_root)?;
        #[cfg(unix)]
        let creation = {
            use std::os::unix::fs::DirBuilderExt as _;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(&root)
        };
        #[cfg(not(unix))]
        let creation = fs::create_dir(&root);
        match creation {
            Ok(()) => {
                set_private_permissions(&root)?;
                sync_directory(profile_state_root)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(()),
        }
        ensure_private_directory(&root)?;
        let directory = open_private_directory(&root)?;
        let store = Self { directory };
        store.cleanup_temporary_files()?;
        Ok(store)
    }

    pub(crate) fn issue(
        &self,
        binding: &LeaseBinding<'_>,
        evidence: &[u8],
        accepted_at_unix_seconds: u64,
    ) -> Result<PreparationEvidenceLease, ()> {
        if evidence.is_empty() || evidence.len() > MAX_LEASE_BYTES || accepted_at_unix_seconds == 0
        {
            return Err(());
        }
        self.collect_expired(accepted_at_unix_seconds)?;
        let binding_sha256 = binding_sha256(binding);
        let final_name = format!("{}.json", hex::encode(binding_sha256));
        if let Some(record) = self.read_record_optional(&final_name)? {
            validate_record(&record, binding, accepted_at_unix_seconds)?;
            let handle = find_handle_for_record(&record)?;
            return PreparationEvidenceLease::new(
                binding.request.request_id(),
                handle,
                decode_digest(&record.evidence_sha256)?,
                record.expires_at_unix_seconds,
            )
            .map_err(|_| ());
        }
        let mut handle = [0_u8; 32];
        getrandom::fill(&mut handle).map_err(|_| ())?;
        let evidence_sha256: [u8; 32] = Sha256::digest(evidence).into();
        let expires_at_unix_seconds = accepted_at_unix_seconds
            .checked_add(LEASE_TTL_SECONDS)
            .ok_or(())?;
        let record = record_from(
            binding,
            binding_sha256,
            &handle,
            evidence,
            evidence_sha256,
            accepted_at_unix_seconds,
            expires_at_unix_seconds,
        );
        let bytes = serde_json_canonicalizer::to_vec(&record).map_err(|_| ())?;
        if bytes.len() > MAX_LEASE_BYTES {
            return Err(());
        }
        self.enforce_capacity(bytes.len())?;
        self.publish_new(&final_name, &bytes)?;
        PreparationEvidenceLease::new(
            binding.request.request_id(),
            handle,
            evidence_sha256,
            expires_at_unix_seconds,
        )
        .map_err(|_| ())
    }

    /// Returns an exact live replay before the caller performs any protected
    /// provider read. A missing binding is the only state that permits fresh
    /// evidence acquisition.
    pub(crate) fn lookup(
        &self,
        binding: &LeaseBinding<'_>,
        now_unix_seconds: u64,
    ) -> Result<Option<PreparationEvidenceLease>, ()> {
        self.collect_expired(now_unix_seconds)?;
        let name = format!("{}.json", hex::encode(binding_sha256(binding)));
        let Some(record) = self.read_record_optional(&name)? else {
            return replay_record_or_reject_conflict(self, binding, now_unix_seconds)?
                .map(|record| {
                    PreparationEvidenceLease::new(
                        binding.request.request_id(),
                        find_handle_for_record(&record)?,
                        decode_digest(&record.evidence_sha256)?,
                        record.expires_at_unix_seconds,
                    )
                    .map_err(|_| ())
                })
                .transpose();
        };
        validate_record(&record, binding, now_unix_seconds)?;
        Ok(Some(
            PreparationEvidenceLease::new(
                binding.request.request_id(),
                find_handle_for_record(&record)?,
                decode_digest(&record.evidence_sha256)?,
                record.expires_at_unix_seconds,
            )
            .map_err(|_| ())?,
        ))
    }

    pub(crate) fn resolve(
        &self,
        binding: &LeaseBinding<'_>,
        handle: &[u8],
        now_unix_seconds: u64,
    ) -> Result<ResolvedPreparationEvidence, ()> {
        if handle.len() != 32 {
            return Err(());
        }
        let name = format!("{}.json", hex::encode(binding_sha256(binding)));
        let record = if let Some(record) = self.read_record_optional(&name)? {
            validate_record(&record, binding, now_unix_seconds)?;
            record
        } else {
            replay_record_or_reject_conflict(self, binding, now_unix_seconds)?.ok_or(())?
        };
        let handle_sha256: [u8; 32] = Sha256::digest(handle).into();
        if decode_digest(&record.handle_sha256)? != handle_sha256 {
            return Err(());
        }
        let bytes = Base64UrlUnpadded::decode_vec(&record.evidence_base64url).map_err(|_| ())?;
        let commitment: [u8; 32] = Sha256::digest(&bytes).into();
        if commitment != decode_digest(&record.evidence_sha256)? {
            return Err(());
        }
        Ok(ResolvedPreparationEvidence {
            bytes,
            commitment,
            expires_at_unix_seconds: record.expires_at_unix_seconds,
            authority_sha256: decode_digest(&record.authority_sha256)?,
            intent_sha256: decode_digest(&record.semantic_binding_sha256)?,
        })
    }

    fn collect_expired(&self, now: u64) -> Result<(), ()> {
        for name in self.lease_names()? {
            let record = self.read_record(&name)?;
            if record.expires_at_unix_seconds <= now {
                unlink_name(&self.directory, &name)?;
            }
        }
        self.directory.sync_all().map_err(|_| ())
    }

    fn enforce_capacity(&self, added: usize) -> Result<(), ()> {
        let names = self.lease_names()?;
        let total = names.iter().try_fold(0_u64, |sum, name| {
            let record = self.read_record(name)?;
            let bytes = serde_json_canonicalizer::to_vec(&record).map_err(|_| ())?;
            sum.checked_add(u64::try_from(bytes.len()).map_err(|_| ())?)
                .ok_or(())
        })?;
        if names.len() >= MAX_LEASES
            || total
                .checked_add(u64::try_from(added).map_err(|_| ())?)
                .ok_or(())?
                > MAX_TOTAL_BYTES
        {
            return Err(());
        }
        Ok(())
    }

    #[cfg(unix)]
    fn entry_names(&self) -> Result<Vec<String>, ()> {
        let mut directory = rustix::fs::Dir::read_from(&self.directory).map_err(|_| ())?;
        let mut names = Vec::new();
        while let Some(entry) = directory.read() {
            let entry = entry.map_err(|_| ())?;
            let name = entry.file_name().to_str().map_err(|_| ())?;
            if matches!(name, "." | "..") {
                continue;
            }
            if names.len() >= MAX_LEASES.saturating_mul(2) {
                return Err(());
            }
            names.push(name.to_owned());
        }
        names.sort();
        Ok(names)
    }

    #[cfg(not(unix))]
    fn entry_names(&self) -> Result<Vec<String>, ()> {
        Err(())
    }

    fn cleanup_temporary_files(&self) -> Result<(), ()> {
        let mut changed = false;
        for name in self.entry_names()? {
            if !name.starts_with('.') {
                continue;
            }
            if !valid_temporary_name(&name) {
                return Err(());
            }
            let file = self.open_record_file(&name)?.ok_or(())?;
            checked_private_file(&file.metadata().map_err(|_| ())?)?;
            drop(file);
            unlink_name(&self.directory, &name)?;
            changed = true;
        }
        if changed {
            self.directory.sync_all().map_err(|_| ())?;
        }
        Ok(())
    }

    fn lease_names(&self) -> Result<Vec<String>, ()> {
        let names = self.entry_names()?;
        if names.len() > MAX_LEASES || names.iter().any(|name| !valid_lease_name(name)) {
            return Err(());
        }
        Ok(names)
    }

    #[cfg(unix)]
    fn open_record_file(&self, name: &str) -> Result<Option<File>, ()> {
        use rustix::fs::{Mode, OFlags};
        let fd = match rustix::fs::openat(
            &self.directory,
            Path::new(name),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(()),
        };
        Ok(Some(fd.into()))
    }

    #[cfg(not(unix))]
    fn open_record_file(&self, _name: &str) -> Result<Option<File>, ()> {
        Err(())
    }

    fn read_record_optional(&self, name: &str) -> Result<Option<LeaseRecord>, ()> {
        let Some(mut file) = self.open_record_file(name)? else {
            return Ok(None);
        };
        let before = file.metadata().map_err(|_| ())?;
        checked_private_file(&before)?;
        if before.len() == 0 || before.len() > MAX_LEASE_BYTES as u64 {
            return Err(());
        }
        let mut bytes = Vec::with_capacity(usize::try_from(before.len()).map_err(|_| ())?);
        std::io::Read::by_ref(&mut file)
            .take((MAX_LEASE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ())?;
        let after = file.metadata().map_err(|_| ())?;
        if bytes.len() > MAX_LEASE_BYTES || !same_file_identity(&before, &after) {
            return Err(());
        }
        file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
        let mut repeated = Vec::with_capacity(bytes.len());
        std::io::Read::by_ref(&mut file)
            .take((MAX_LEASE_BYTES + 1) as u64)
            .read_to_end(&mut repeated)
            .map_err(|_| ())?;
        let final_metadata = file.metadata().map_err(|_| ())?;
        if repeated != bytes || !same_file_identity(&after, &final_metadata) {
            return Err(());
        }
        let record: LeaseRecord = serde_json::from_slice(&bytes).map_err(|_| ())?;
        if serde_json_canonicalizer::to_vec(&record).map_err(|_| ())? != bytes {
            return Err(());
        }
        Ok(Some(record))
    }

    fn read_record(&self, name: &str) -> Result<LeaseRecord, ()> {
        self.read_record_optional(name)?.ok_or(())
    }

    #[cfg(unix)]
    fn publish_new(&self, final_name: &str, bytes: &[u8]) -> Result<(), ()> {
        use rustix::fs::{Mode, OFlags, RenameFlags};
        if !valid_lease_name(final_name) || bytes.is_empty() || bytes.len() > MAX_LEASE_BYTES {
            return Err(());
        }
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| ())?;
        let temporary_name = format!(".{}.tmp", hex::encode(random));
        let fd = rustix::fs::openat(
            &self.directory,
            Path::new(&temporary_name),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| ())?;
        let mut file: File = fd.into();
        let write_result = file.write_all(bytes).and_then(|()| file.sync_all());
        drop(file);
        if write_result.is_err() {
            let _ = unlink_name(&self.directory, &temporary_name);
            return Err(());
        }
        if rustix::fs::renameat_with(
            &self.directory,
            Path::new(&temporary_name),
            &self.directory,
            Path::new(final_name),
            RenameFlags::NOREPLACE,
        )
        .is_err()
        {
            let _ = unlink_name(&self.directory, &temporary_name);
            return Err(());
        }
        self.directory.sync_all().map_err(|_| ())
    }

    #[cfg(not(unix))]
    fn publish_new(&self, _final_name: &str, _bytes: &[u8]) -> Result<(), ()> {
        Err(())
    }
}

pub(crate) fn preparation_evidence_intent_commitment(binding: &LeaseBinding<'_>) -> [u8; 32] {
    semantic_binding_sha256(binding)
}

fn replay_record_or_reject_conflict(
    store: &PreparationEvidenceLeaseStore,
    binding: &LeaseBinding<'_>,
    now: u64,
) -> Result<Option<LeaseRecord>, ()> {
    let principal_sha256 = hex::encode(Sha256::digest(binding.principal.as_bytes()));
    let request_id = Base64UrlUnpadded::encode_string(binding.request.request_id().as_bytes());
    let runtime = hex::encode(binding.profile.runtime_contract_digest());
    let idempotency_sha256 = binding
        .request
        .idempotency_key()
        .map(|value| hex::encode(Sha256::digest(value.as_bytes())));
    let semantic_binding = semantic_binding_sha256(binding);
    for name in store.lease_names()? {
        let record = store.read_record(&name)?;
        let same_scope = record.principal_sha256 == principal_sha256
            && record.profile_id == binding.profile.id()
            && record.profile_version == binding.profile.version()
            && record.runtime_contract_sha256 == runtime;
        if !same_scope {
            continue;
        }
        let same_request = record.request_id_base64url == request_id;
        let same_idempotency = idempotency_sha256
            .as_ref()
            .is_some_and(|value| record.idempotency_sha256.as_ref() == Some(value));
        if !same_request && !same_idempotency {
            continue;
        }
        validate_stored_record(&record, now)?;
        if decode_digest(&record.semantic_binding_sha256)? != semantic_binding {
            return Err(());
        }
        return Ok(Some(record));
    }
    Ok(None)
}

fn binding_sha256(binding: &LeaseBinding<'_>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-PREPARATION-EVIDENCE-BINDING\0\x01");
    for part in [
        binding.principal.as_bytes(),
        binding.profile.id().as_bytes(),
        &binding.profile.version().to_be_bytes(),
        binding.profile.runtime_contract_digest(),
        binding.workflow_id.as_bytes(),
        binding.request.request_id().as_bytes(),
        binding.request.idempotency_key().unwrap_or("").as_bytes(),
        binding.request.profile_input(),
        binding.connection.connection_id().as_str().as_bytes(),
        &binding.connection.generation().get().to_be_bytes(),
        binding.connection.descriptor_commitment(),
        binding.connection.account_commitment(),
        &binding.configuration_sha256,
        &binding.authority_sha256,
        &binding.authority_artifact_sha256,
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

fn semantic_binding_sha256(binding: &LeaseBinding<'_>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-PREPARATION-EVIDENCE-SEMANTIC-BINDING\0\x01");
    for part in [
        binding.principal.as_bytes(),
        binding.profile.id().as_bytes(),
        &binding.profile.version().to_be_bytes(),
        binding.profile.runtime_contract_digest(),
        binding.workflow_id.as_bytes(),
        binding.request.idempotency_key().unwrap_or("").as_bytes(),
        binding.request.profile_input(),
        binding.connection.connection_id().as_str().as_bytes(),
        &binding.connection.generation().get().to_be_bytes(),
        binding.connection.descriptor_commitment(),
        binding.connection.account_commitment(),
        &binding.configuration_sha256,
        &binding.authority_sha256,
        &binding.authority_artifact_sha256,
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

fn record_from(
    binding: &LeaseBinding<'_>,
    binding_sha256: [u8; 32],
    handle: &[u8; 32],
    evidence: &[u8],
    evidence_sha256: [u8; 32],
    accepted: u64,
    expires: u64,
) -> LeaseRecord {
    LeaseRecord {
        schema: LEASE_SCHEMA.into(),
        binding_sha256: hex::encode(binding_sha256),
        semantic_binding_sha256: hex::encode(semantic_binding_sha256(binding)),
        handle_sha256: hex::encode(Sha256::digest(handle)),
        handle_base64url: Base64UrlUnpadded::encode_string(handle),
        principal_sha256: hex::encode(Sha256::digest(binding.principal.as_bytes())),
        profile_id: binding.profile.id().into(),
        profile_version: binding.profile.version(),
        runtime_contract_sha256: hex::encode(binding.profile.runtime_contract_digest()),
        workflow_id: binding.workflow_id.into(),
        request_id_base64url: Base64UrlUnpadded::encode_string(
            binding.request.request_id().as_bytes(),
        ),
        idempotency_sha256: binding
            .request
            .idempotency_key()
            .map(|value| hex::encode(Sha256::digest(value.as_bytes()))),
        profile_input_sha256: hex::encode(Sha256::digest(binding.request.profile_input())),
        connection_id: binding.connection.connection_id().as_str().into(),
        connection_generation: binding.connection.generation().get(),
        connection_descriptor_sha256: hex::encode(binding.connection.descriptor_commitment()),
        connection_account_sha256: hex::encode(binding.connection.account_commitment()),
        configuration_sha256: hex::encode(binding.configuration_sha256),
        authority_sha256: hex::encode(binding.authority_sha256),
        evidence_sha256: hex::encode(evidence_sha256),
        evidence_base64url: Base64UrlUnpadded::encode_string(evidence),
        accepted_at_unix_seconds: accepted,
        expires_at_unix_seconds: expires,
    }
}

fn validate_record(record: &LeaseRecord, binding: &LeaseBinding<'_>, now: u64) -> Result<(), ()> {
    let expected = binding_sha256(binding);
    if record.schema != LEASE_SCHEMA
        || decode_digest(&record.binding_sha256)? != expected
        || decode_digest(&record.semantic_binding_sha256)? != semantic_binding_sha256(binding)
        || record.expires_at_unix_seconds <= now
        || record.accepted_at_unix_seconds == 0
        || record
            .expires_at_unix_seconds
            .saturating_sub(record.accepted_at_unix_seconds)
            != LEASE_TTL_SECONDS
    {
        return Err(());
    }
    Ok(())
}

fn validate_stored_record(record: &LeaseRecord, now: u64) -> Result<(), ()> {
    if record.schema != LEASE_SCHEMA
        || record.expires_at_unix_seconds <= now
        || record.accepted_at_unix_seconds == 0
        || record
            .expires_at_unix_seconds
            .saturating_sub(record.accepted_at_unix_seconds)
            != LEASE_TTL_SECONDS
    {
        return Err(());
    }
    decode_digest(&record.binding_sha256)?;
    decode_digest(&record.semantic_binding_sha256)?;
    let handle = find_handle_for_record(record)?;
    let evidence = Base64UrlUnpadded::decode_vec(&record.evidence_base64url).map_err(|_| ())?;
    let evidence_sha256: [u8; 32] = Sha256::digest(&evidence).into();
    let handle_sha256: [u8; 32] = Sha256::digest(handle).into();
    if decode_digest(&record.evidence_sha256)? != evidence_sha256
        || decode_digest(&record.handle_sha256)? != handle_sha256
    {
        return Err(());
    }
    Ok(())
}

fn find_handle_for_record(record: &LeaseRecord) -> Result<[u8; 32], ()> {
    let mut handle = [0_u8; 32];
    let decoded_len = Base64UrlUnpadded::decode(&record.handle_base64url, &mut handle)
        .map_err(|_| ())?
        .len();
    let handle_sha256: [u8; 32] = Sha256::digest(handle).into();
    if decoded_len != handle.len() || decode_digest(&record.handle_sha256)? != handle_sha256 {
        return Err(());
    }
    Ok(handle)
}

fn decode_digest(value: &str) -> Result<[u8; 32], ()> {
    let bytes = hex::decode(value).map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
}

fn valid_lease_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 69
        && &bytes[64..] == b".json"
        && bytes[..64]
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_temporary_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 37
        && bytes[0] == b'.'
        && &bytes[33..] == b".tmp"
        && bytes[1..33]
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(unix)]
fn open_private_directory(path: &Path) -> Result<File, ()> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    let file: File = fd.into();
    ensure_private_directory_file(&file)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_directory(_path: &Path) -> Result<File, ()> {
    Err(())
}

#[cfg(unix)]
fn ensure_private_directory_file(file: &File) -> Result<(), ()> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(());
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_identity(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.nlink() == after.nlink()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_identity(_before: &fs::Metadata, _after: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn unlink_name(directory: &File, name: &str) -> Result<(), ()> {
    rustix::fs::unlinkat(directory, Path::new(name), rustix::fs::AtFlags::empty()).map_err(|_| ())
}

#[cfg(not(unix))]
fn unlink_name(_directory: &File, _name: &str) -> Result<(), ()> {
    Err(())
}

#[cfg(unix)]
fn ensure_private_directory(path: &Path) -> Result<(), ()> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(());
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_directory(_path: &Path) -> Result<(), ()> {
    Err(())
}

#[cfg(unix)]
fn checked_private_file(metadata: &fs::Metadata) -> Result<(), ()> {
    use std::os::unix::fs::MetadataExt as _;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(());
    }
    Ok(())
}

#[cfg(not(unix))]
fn checked_private_file(_metadata: &fs::Metadata) -> Result<(), ()> {
    Err(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), ()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if path.is_dir() { 0o700 } else { 0o600 }),
    )
    .map_err(|_| ())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), ()> {
    Err(())
}

fn sync_directory(path: &Path) -> Result<(), ()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| ())
}
