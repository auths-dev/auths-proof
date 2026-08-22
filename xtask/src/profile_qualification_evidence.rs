use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek as _, Write};

const MAX_COMPRESSED_BYTES: u64 = 536_870_912;
const MAX_UNCOMPRESSED_BYTES: u64 = 1_073_741_824;
const MAX_TAR_BYTES: u64 =
    MAX_UNCOMPRESSED_BYTES + MAX_MANIFEST_BYTES as u64 + MAX_MEMBERS as u64 * 1_023 + 1_024;
const MAX_MEMBER_BYTES: u64 = 16_777_216;
const MAX_MANIFEST_BYTES: usize = 1_048_576;
const MAX_MEMBERS: usize = 4_096;
const REQUIRED_REPORTS: &[&str] = &[
    "reports/cleanup.json",
    "reports/counters.json",
    "reports/gitleaks.json",
    "reports/installed-packages.json",
    "reports/provider-truth.json",
    "reports/protected-observation.json",
    "reports/provenance.json",
    "reports/receipt-trust-anchors.json",
    "reports/receipts-python.json",
    "reports/receipts-rust.json",
    "reports/receipts-typescript.json",
    "reports/redaction.json",
    "reports/typed-forbidden-fields.json",
];

const EVIDENCE_SOURCE_ROLES: &[&str] = &[
    "client-proxy",
    "credential-broker",
    "journal-reader",
    "profile-state-reader",
    "provider-observer",
    "provider-proxy",
    "receipt-verifier",
    "supervisor",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceManifest {
    schema: String,
    members: Vec<EvidenceMember>,
    member_count: u32,
    uncompressed_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceMember {
    path: String,
    bytes: u64,
    sha256: String,
}

pub(crate) struct VerifiedEvidence {
    directory: tempfile::TempDir,
    manifest: EvidenceManifest,
    manifest_bytes: Vec<u8>,
    compressed_bytes: u64,
    compressed_sha256: String,
}

impl VerifiedEvidence {
    pub(crate) fn compressed_bytes(&self) -> u64 {
        self.compressed_bytes
    }

    pub(crate) fn compressed_sha256(&self) -> &str {
        &self.compressed_sha256
    }

    pub(crate) fn member_names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.manifest
            .members
            .iter()
            .map(|member| member.path.as_str())
    }

    pub(crate) fn scan_member_names(&self) -> impl Iterator<Item = &str> {
        std::iter::once("manifest.json").chain(self.member_names())
    }

    pub(crate) fn extracted_directory(&self) -> &Path {
        self.directory.path()
    }

    pub(crate) fn read_member(&self, path: &str, maximum: usize) -> Result<Vec<u8>, String> {
        if path == "manifest.json" {
            if self.manifest_bytes.len() > maximum {
                return Err("qualification manifest exceeds caller bound".into());
            }
            return Ok(self.manifest_bytes.clone());
        }
        let member = self
            .manifest
            .members
            .binary_search_by(|candidate| candidate.path.as_str().cmp(path))
            .ok()
            .map(|index| &self.manifest.members[index])
            .ok_or_else(|| format!("qualification evidence member is absent: {path}"))?;
        if member.bytes > u64::try_from(maximum).map_err(string_error)? {
            return Err(format!(
                "qualification evidence member exceeds caller bound: {path}"
            ));
        }
        read_stable_regular(&self.directory.path().join(path), maximum)
    }
}

pub(crate) fn pack_final_evidence(
    source: &Path,
    destination: &Path,
) -> Result<(u64, String), String> {
    let files = collect_closed_source(source)?;
    let manifest = manifest_for(&files)?;
    let manifest_bytes = serde_json_canonicalizer::to_vec(&manifest).map_err(string_error)?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err("qualification evidence manifest exceeds 1 MiB".into());
    }

    let parent = destination
        .parent()
        .ok_or_else(|| "qualification archive has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(string_error)?;
    let temporary = tempfile::Builder::new()
        .prefix(".qualification-evidence-")
        .tempfile_in(parent)
        .map_err(string_error)?;
    let output = temporary.reopen().map_err(string_error)?;
    let mut encoder = zstd::Encoder::new(output, 19).map_err(string_error)?;
    encoder.include_checksum(true).map_err(string_error)?;
    let mut archive = tar::Builder::new(encoder);
    append_member(&mut archive, "manifest.json", &manifest_bytes)?;
    for (path, bytes) in &files {
        append_member(&mut archive, path, bytes)?;
    }
    archive.finish().map_err(string_error)?;
    let encoder = archive.into_inner().map_err(string_error)?;
    let output = encoder.finish().map_err(string_error)?;
    output.sync_all().map_err(string_error)?;
    drop(output);
    let (bytes, digest) = hash_stable_regular(temporary.path(), MAX_COMPRESSED_BYTES)?;
    temporary
        .persist_noclobber(destination)
        .map_err(string_error)?;
    sync_parent(parent)?;
    Ok((bytes, digest))
}

pub(crate) fn verify_and_extract(archive_path: &Path) -> Result<VerifiedEvidence, String> {
    let snapshot_directory = tempfile::tempdir().map_err(string_error)?;
    let snapshot_path = snapshot_directory.path().join("uploaded-evidence.tar.zst");
    let (compressed_bytes, compressed_sha256) =
        snapshot_untrusted_regular(archive_path, &snapshot_path, MAX_COMPRESSED_BYTES)?;
    let output = tempfile::Builder::new()
        .prefix("auths-qualification-evidence-")
        .tempdir()
        .map_err(string_error)?;
    let mut tar_file = tempfile::tempfile().map_err(string_error)?;

    let compressed = fs::File::open(&snapshot_path).map_err(string_error)?;
    let buffer = std::io::BufReader::with_capacity(1, compressed);
    let mut decoder = zstd::Decoder::with_buffer(buffer)
        .map_err(string_error)?
        .single_frame();
    copy_bounded(&mut decoder, &mut tar_file, MAX_TAR_BYTES)?;
    let mut remainder = decoder.finish();
    let mut trailing = [0_u8; 1];
    if remainder.read(&mut trailing).map_err(string_error)? != 0 {
        return Err("qualification evidence contains multiple or trailing zstd frames".into());
    }
    tar_file.sync_all().map_err(string_error)?;
    let tar_bytes = tar_file.metadata().map_err(string_error)?.len();
    tar_file.rewind().map_err(string_error)?;

    let mut seen = BTreeSet::new();
    let mut expected_tar_end = 0_u64;
    let mut manifest_bytes = None;
    let mut archive = tar::Archive::new(&mut tar_file);
    for entry in archive.entries().map_err(string_error)?.raw(true) {
        let mut entry = entry.map_err(string_error)?;
        if seen.len() >= MAX_MEMBERS {
            return Err("qualification evidence has too many members".into());
        }
        let header = entry.header();
        if !header.entry_type().is_file()
            || header.mode().map_err(string_error)? != 0o400
            || header.uid().map_err(string_error)? != 0
            || header.gid().map_err(string_error)? != 0
            || header.mtime().map_err(string_error)? != 0
            || header.username().map_err(string_error)?.unwrap_or("") != ""
            || header.groupname().map_err(string_error)?.unwrap_or("") != ""
        {
            return Err("qualification evidence contains non-canonical tar metadata".into());
        }
        let path = std::str::from_utf8(entry.path_bytes().as_ref())
            .map_err(string_error)?
            .to_owned();
        if !safe_member_path(&path) || !seen.insert(path.clone()) {
            return Err("qualification evidence contains an unsafe or duplicate path".into());
        }
        let size = entry.size();
        if size == 0 || size > MAX_MEMBER_BYTES {
            return Err(format!(
                "qualification evidence member is out of bounds: {path}"
            ));
        }
        expected_tar_end = entry
            .raw_file_position()
            .checked_add(align_tar(size)?)
            .ok_or_else(|| "qualification tar length overflow".to_owned())?;
        let bytes = read_entry_bounded(&mut entry, size)?;
        if path == "manifest.json" {
            if bytes.len() > MAX_MANIFEST_BYTES {
                return Err("qualification evidence manifest exceeds 1 MiB".into());
            }
            manifest_bytes = Some(bytes);
        } else {
            write_private_member(output.path(), &path, &bytes)?;
        }
    }
    drop(archive);
    let expected_tar_bytes = expected_tar_end
        .checked_add(1_024)
        .ok_or_else(|| "qualification tar length overflow".to_owned())?;
    if tar_bytes != expected_tar_bytes {
        return Err(
            "qualification tar is missing its exact terminator or has trailing data".into(),
        );
    }
    let manifest_bytes =
        manifest_bytes.ok_or_else(|| "qualification manifest is absent".to_owned())?;
    let manifest: EvidenceManifest =
        serde_json::from_slice(&manifest_bytes).map_err(string_error)?;
    if serde_json_canonicalizer::to_vec(&manifest).map_err(string_error)? != manifest_bytes {
        return Err("qualification manifest is not canonical JCS".into());
    }
    validate_manifest(&manifest, output.path(), &seen)?;
    let canonical_directory = tempfile::tempdir().map_err(string_error)?;
    let canonical_archive = canonical_directory.path().join("evidence.tar.zst");
    pack_final_evidence(output.path(), &canonical_archive)?;
    if !files_equal(&snapshot_path, &canonical_archive)? {
        return Err("qualification evidence is not the exact canonical tar.zst encoding".into());
    }
    write_private_member(output.path(), "manifest.json", &manifest_bytes)?;
    Ok(VerifiedEvidence {
        directory: output,
        manifest,
        manifest_bytes,
        compressed_bytes,
        compressed_sha256,
    })
}

/// Reads one untrusted regular file through a single no-follow snapshot.
///
/// The returned bytes and digest describe the same opened file identity; the
/// caller never reopens the attacker-controlled path.
pub(crate) fn read_untrusted_regular(
    path: &Path,
    maximum: u64,
) -> Result<(Vec<u8>, String), String> {
    let snapshot_directory = tempfile::tempdir().map_err(string_error)?;
    let snapshot_path = snapshot_directory.path().join("untrusted-input");
    let (length, digest) = snapshot_untrusted_regular(path, &snapshot_path, maximum)?;
    let bytes = read_stable_regular(
        &snapshot_path,
        usize::try_from(maximum).map_err(string_error)?,
    )?;
    if u64::try_from(bytes.len()).map_err(string_error)? != length {
        return Err("qualification input snapshot length changed".into());
    }
    Ok((bytes, digest))
}

fn collect_closed_source(source: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let metadata = fs::symlink_metadata(source).map_err(string_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("qualification evidence source is not a regular directory".into());
    }
    let mut files = BTreeMap::new();
    collect_directory(source, source, &mut files)?;
    if files.len() + 1 > MAX_MEMBERS {
        return Err("qualification evidence has too many members".into());
    }
    validate_closed_layout(files.keys().map(String::as_str))?;
    Ok(files)
}

/// Validates the exact evidence layout immediately before the independently
/// signed protected-observation envelope is inserted.
pub(crate) fn validate_pre_observation_source(source: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(string_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("qualification evidence source is not a regular directory".into());
    }
    let mut files = BTreeMap::new();
    collect_directory(source, source, &mut files)?;
    if files.contains_key("reports/protected-observation.json") || files.len() + 2 > MAX_MEMBERS {
        return Err(
            "pre-observation evidence contains a signed observation or too many members".into(),
        );
    }
    let protected_observation = "reports/protected-observation.json".to_owned();
    let mut paths = files.keys().map(String::as_str).collect::<Vec<_>>();
    paths.push(&protected_observation);
    validate_closed_layout(paths.into_iter())
}

/// Takes one owner-private immutable snapshot of a completely assembled
/// pre-sign evidence tree for protected semantic verification.
pub(crate) fn snapshot_pre_observation_source(source: &Path) -> Result<VerifiedEvidence, String> {
    validate_pre_observation_source(source)?;
    let mut files = BTreeMap::new();
    collect_directory(source, source, &mut files)?;
    let output = tempfile::tempdir().map_err(string_error)?;
    for (path, bytes) in &files {
        write_private_member(output.path(), path, bytes)?;
    }
    let manifest = manifest_for(&files)?;
    let manifest_bytes = serde_json_canonicalizer::to_vec(&manifest).map_err(string_error)?;
    Ok(VerifiedEvidence {
        directory: output,
        manifest,
        manifest_bytes,
        compressed_bytes: 0,
        compressed_sha256: String::new(),
    })
}

fn collect_directory(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(string_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(string_error)?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(string_error)?;
        if metadata.file_type().is_symlink() {
            return Err("qualification evidence source contains a symlink".into());
        }
        if metadata.is_dir() {
            collect_directory(root, &path, files)?;
            continue;
        }
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_MEMBER_BYTES {
            return Err(
                "qualification evidence source contains a non-regular or oversized file".into(),
            );
        }
        let relative = path.strip_prefix(root).map_err(string_error)?;
        let relative = relative
            .to_str()
            .ok_or_else(|| "qualification evidence path is not UTF-8".to_owned())?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if !safe_member_path(&relative) || relative == "manifest.json" {
            return Err("qualification evidence source contains a forbidden path".into());
        }
        let bytes = read_stable_regular(&path, MAX_MEMBER_BYTES as usize)?;
        if files.insert(relative, bytes).is_some() {
            return Err("qualification evidence source contains a duplicate path".into());
        }
    }
    Ok(())
}

fn manifest_for(files: &BTreeMap<String, Vec<u8>>) -> Result<EvidenceManifest, String> {
    let mut total = 0_u64;
    let members = files
        .iter()
        .map(|(path, bytes)| {
            let length = u64::try_from(bytes.len()).map_err(string_error)?;
            total = total
                .checked_add(length)
                .ok_or_else(|| "qualification evidence aggregate length overflow".to_owned())?;
            Ok(EvidenceMember {
                path: path.clone(),
                bytes: length,
                sha256: hex::encode(Sha256::digest(bytes)),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if total == 0 || total > MAX_UNCOMPRESSED_BYTES {
        return Err("qualification evidence aggregate is out of bounds".into());
    }
    Ok(EvidenceManifest {
        schema: "auths.profile-qualification-evidence-manifest/1".into(),
        member_count: u32::try_from(members.len()).map_err(string_error)?,
        uncompressed_bytes: total,
        members,
    })
}

fn validate_manifest(
    manifest: &EvidenceManifest,
    root: &Path,
    seen: &BTreeSet<String>,
) -> Result<(), String> {
    if manifest.schema != "auths.profile-qualification-evidence-manifest/1"
        || usize::try_from(manifest.member_count).map_err(string_error)? != manifest.members.len()
        || manifest.members.is_empty()
        || manifest.members.len() + 1 != seen.len()
        || manifest.uncompressed_bytes == 0
        || manifest.uncompressed_bytes > MAX_UNCOMPRESSED_BYTES
    {
        return Err("qualification evidence manifest shape is invalid".into());
    }
    validate_closed_layout(manifest.members.iter().map(|member| member.path.as_str()))?;
    let mut previous: Option<&str> = None;
    let mut total = 0_u64;
    for member in &manifest.members {
        if previous.is_some_and(|path| path >= member.path.as_str())
            || !safe_member_path(&member.path)
            || member.bytes == 0
            || member.bytes > MAX_MEMBER_BYTES
            || !digest(&member.sha256)
            || !seen.contains(&member.path)
        {
            return Err("qualification evidence manifest member is invalid".into());
        }
        let (bytes, sha256) = hash_stable_regular(&root.join(&member.path), MAX_MEMBER_BYTES)?;
        if bytes != member.bytes || sha256 != member.sha256 {
            return Err("qualification evidence member does not match its manifest".into());
        }
        total = total
            .checked_add(bytes)
            .ok_or_else(|| "qualification evidence aggregate length overflow".to_owned())?;
        previous = Some(&member.path);
    }
    if total != manifest.uncompressed_bytes {
        return Err("qualification evidence aggregate does not match its manifest".into());
    }
    Ok(())
}

fn validate_closed_layout<'a>(paths: impl Iterator<Item = &'a str>) -> Result<(), String> {
    let paths = paths.collect::<BTreeSet<_>>();
    for required in REQUIRED_REPORTS {
        if !paths.contains(required) {
            return Err(format!(
                "qualification evidence is missing required member: {required}"
            ));
        }
    }
    let mut scenarios = 0_usize;
    let mut common_phases = BTreeMap::<&str, BTreeSet<(&str, u8)>>::new();
    let mut receipts = 0_usize;
    let mut inspections = 0_usize;
    let mut ledgers = BTreeMap::<
        &str,
        (
            BTreeSet<&str>,
            BTreeMap<&str, BTreeSet<u32>>,
            BTreeSet<&str>,
            BTreeSet<&str>,
            BTreeSet<&str>,
            BTreeSet<String>,
        ),
    >::new();
    for path in &paths {
        if REQUIRED_REPORTS.contains(path) {
            continue;
        }
        if let Some(id) = path
            .strip_prefix("reports/scenarios/")
            .and_then(|value| value.strip_suffix(".json"))
        {
            if !registered_token(id) {
                return Err("qualification scenario report path is invalid".into());
            }
            scenarios += 1;
            continue;
        }
        if let Some(value) = path
            .strip_prefix("common-phases/")
            .and_then(|value| value.strip_suffix(".json"))
        {
            let components = value.split('/').collect::<Vec<_>>();
            let [provider_run, scenario, phase_text] = components.as_slice() else {
                return Err("qualification common-phase path is invalid".into());
            };
            let phase = phase_text.parse::<u8>().map_err(string_error)?;
            if !registered_token(provider_run)
                || !registered_token(scenario)
                || phase == 0
                || *phase_text != phase.to_string()
                || !common_phases
                    .entry(provider_run)
                    .or_default()
                    .insert((scenario, phase))
            {
                return Err("qualification common-phase path is invalid".into());
            }
            continue;
        }
        if let Some(value) = path
            .strip_prefix("receipts/")
            .and_then(|value| value.strip_suffix(".cbor"))
        {
            let Some((operation, sequence)) = value.split_once('/') else {
                return Err("qualification receipt path is invalid".into());
            };
            if !registered_token(operation) || !canonical_decimal(sequence) {
                return Err("qualification receipt path is invalid".into());
            }
            receipts += 1;
            continue;
        }
        if let Some(operation) = path
            .strip_prefix("receipt-inspection/")
            .and_then(|value| value.strip_suffix(".json"))
        {
            if !registered_token(operation) {
                return Err("qualification receipt-inspection path is invalid".into());
            }
            inspections += 1;
            continue;
        }
        if let Some(value) = path.strip_prefix("ledger/") {
            let components = value.split('/').collect::<Vec<_>>();
            let Some(provider_run_id) = components.first().copied() else {
                return Err("qualification ledger path is invalid".into());
            };
            if !registered_token(provider_run_id) {
                return Err("qualification ledger provider-run path is invalid".into());
            }
            let entry = ledgers.entry(provider_run_id).or_default();
            match components.as_slice() {
                [
                    _,
                    file @ ("evidence-ledger-trust.json"
                    | "evidence-source-trust.json"
                    | "ledger.json"),
                ] => {
                    entry.0.insert(file);
                }
                [_, "source-records", role, sequence] if EVIDENCE_SOURCE_ROLES.contains(role) => {
                    let Some(sequence) = sequence.strip_suffix(".json") else {
                        return Err("qualification source-record path is invalid".into());
                    };
                    if !canonical_decimal(sequence) || sequence == "0" {
                        return Err("qualification source-record sequence is invalid".into());
                    }
                    let sequence = sequence.parse::<u32>().map_err(string_error)?;
                    entry.1.entry(role).or_default().insert(sequence);
                }
                [_, "supervisor-contexts", operation] if operation.ends_with(".json") => {
                    let operation = operation.trim_end_matches(".json");
                    if !registered_token(operation) || !entry.2.insert(operation) {
                        return Err("qualification supervisor-context path is invalid".into());
                    }
                }
                [_, "decision-snapshots", operation] if operation.ends_with(".json") => {
                    let operation = operation.trim_end_matches(".json");
                    if !registered_token(operation) || !entry.3.insert(operation) {
                        return Err("qualification decision-snapshot path is invalid".into());
                    }
                }
                [_, "durable-acks", operation] if operation.ends_with(".json") => {
                    let operation = operation.trim_end_matches(".json");
                    if !registered_token(operation) || !entry.4.insert(operation) {
                        return Err("qualification durable-ack path is invalid".into());
                    }
                }
                [_, "crash-action-contexts", operation, action]
                    if matches!(
                        *action,
                        "failpoint-acknowledged.json"
                            | "process-killed.json"
                            | "process-restarted.json"
                    ) =>
                {
                    if !registered_token(operation)
                        || !entry.5.insert(format!("{operation}/{action}"))
                    {
                        return Err("qualification crash-action context path is invalid".into());
                    }
                }
                _ => return Err("qualification ledger path is invalid".into()),
            }
            continue;
        }
        return Err(format!(
            "qualification evidence contains an undeclared member: {path}"
        ));
    }
    if scenarios == 0
        || common_phases.is_empty()
        || receipts == 0
        || inspections == 0
        || ledgers.is_empty()
        || common_phases.keys().copied().collect::<BTreeSet<_>>()
            != ledgers.keys().copied().collect::<BTreeSet<_>>()
        || common_phases.values().any(BTreeSet::is_empty)
    {
        return Err(
            "qualification evidence lacks scenarios, common phases, receipts, receipt inspections, or ledgers".into(),
        );
    }
    let exact_ledger_files = BTreeSet::from([
        "evidence-ledger-trust.json",
        "evidence-source-trust.json",
        "ledger.json",
    ]);
    for (provider_run_id, (files, records, contexts, snapshots, acknowledgements, crash_actions)) in
        ledgers
    {
        let crash_operations = crash_actions
            .iter()
            .filter_map(|path| path.split_once('/').map(|(operation, _)| operation))
            .collect::<BTreeSet<_>>();
        let expected_crash_actions = crash_operations
            .iter()
            .flat_map(|operation| {
                [
                    "failpoint-acknowledged.json",
                    "process-killed.json",
                    "process-restarted.json",
                ]
                .map(|action| format!("{operation}/{action}"))
            })
            .collect::<BTreeSet<_>>();
        if files != exact_ledger_files
            || contexts.is_empty()
            || contexts != snapshots
            || contexts != acknowledgements
            || crash_actions != expected_crash_actions
            || !crash_operations
                .iter()
                .all(|operation| contexts.contains(*operation))
            || records.len() != EVIDENCE_SOURCE_ROLES.len()
            || EVIDENCE_SOURCE_ROLES.iter().any(|role| {
                records.get(role).is_none_or(|sequences| {
                    sequences.is_empty()
                        || sequences
                            .iter()
                            .copied()
                            .ne(1..=u32::try_from(sequences.len()).unwrap_or(u32::MAX))
                })
            })
        {
            return Err(format!(
                "qualification ledger {provider_run_id} is incomplete or non-canonical"
            ));
        }
    }
    Ok(())
}

fn append_member<W: Write>(
    archive: &mut tar::Builder<W>,
    path: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let mut header = tar::Header::new_ustar();
    header.set_size(u64::try_from(bytes.len()).map_err(string_error)?);
    header.set_mode(0o400);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_username("").map_err(string_error)?;
    header.set_groupname("").map_err(string_error)?;
    header.set_cksum();
    archive
        .append_data(&mut header, path, bytes)
        .map_err(string_error)
}

fn copy_bounded<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    maximum: u64,
) -> Result<u64, String> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = reader.read(&mut buffer).map_err(string_error)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(string_error)?)
            .ok_or_else(|| "qualification evidence length overflow".to_owned())?;
        if total > maximum {
            return Err("qualification evidence exceeds its decompressed byte bound".into());
        }
        writer.write_all(&buffer[..read]).map_err(string_error)?;
    }
    if total == 0 {
        return Err("qualification evidence is empty".into());
    }
    Ok(total)
}

fn read_entry_bounded<R: Read>(entry: &mut R, size: u64) -> Result<Vec<u8>, String> {
    let capacity = usize::try_from(size).map_err(string_error)?;
    let mut bytes = Vec::with_capacity(capacity);
    entry
        .take(size + 1)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    if bytes.len() != capacity {
        return Err("qualification evidence member length mismatch".into());
    }
    Ok(bytes)
}

fn read_stable_regular(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path).map_err(string_error)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() == 0
        || before.len() > u64::try_from(maximum).map_err(string_error)?
    {
        return Err(format!(
            "qualification evidence file is invalid: {}",
            path.display()
        ));
    }
    let file = fs::File::open(path).map_err(string_error)?;
    let opened = file.metadata().map_err(string_error)?;
    if !same_file_identity(&before, &opened) {
        return Err("qualification evidence changed while opening".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).map_err(string_error)?);
    file.take(u64::try_from(maximum).map_err(string_error)? + 1)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    let after_path = fs::symlink_metadata(path).map_err(string_error)?;
    if bytes.len() != usize::try_from(before.len()).map_err(string_error)?
        || !same_file_identity(&before, &after_path)
    {
        return Err("qualification evidence changed while reading".into());
    }
    Ok(bytes)
}

fn hash_stable_regular(path: &Path, maximum: u64) -> Result<(u64, String), String> {
    let bytes = read_stable_regular(path, usize::try_from(maximum).map_err(string_error)?)?;
    Ok((
        u64::try_from(bytes.len()).map_err(string_error)?,
        hex::encode(Sha256::digest(&bytes)),
    ))
}

#[cfg(unix)]
fn snapshot_untrusted_regular(
    source: &Path,
    destination: &Path,
    maximum: u64,
) -> Result<(u64, String), String> {
    use rustix::fs::{Mode, OFlags};
    let before = fs::symlink_metadata(source).map_err(string_error)?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() == 0 {
        return Err("qualification upload is not a regular file".into());
    }
    let fd = rustix::fs::open(
        source,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(string_error)?;
    let mut input: fs::File = fd.into();
    let opened = input.metadata().map_err(string_error)?;
    if !same_file_identity(&before, &opened) || opened.len() > maximum {
        return Err("qualification upload changed while opening or exceeds its bound".into());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "qualification snapshot has no parent".to_owned())?;
    let parent_fd = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(string_error)?;
    let name = destination
        .file_name()
        .ok_or_else(|| "qualification snapshot has no file name".to_owned())?;
    let output_fd = rustix::fs::openat(
        &parent_fd,
        Path::new(name),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o400),
    )
    .map_err(string_error)?;
    let mut output: fs::File = output_fd.into();
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = input.read(&mut buffer).map_err(string_error)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(string_error)?)
            .ok_or_else(|| "qualification upload length overflow".to_owned())?;
        if total > maximum {
            return Err("qualification upload exceeds its bound".into());
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read]).map_err(string_error)?;
    }
    let after = input.metadata().map_err(string_error)?;
    if total != opened.len() || !same_file_identity(&opened, &after) {
        return Err("qualification upload changed while copying".into());
    }
    output.sync_all().map_err(string_error)?;
    let parent: fs::File = parent_fd.into();
    parent.sync_all().map_err(string_error)?;
    Ok((total, hex::encode(hasher.finalize())))
}

#[cfg(not(unix))]
fn snapshot_untrusted_regular(
    source: &Path,
    destination: &Path,
    maximum: u64,
) -> Result<(u64, String), String> {
    let bytes = read_stable_regular(source, usize::try_from(maximum).map_err(string_error)?)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(string_error)?;
    output.write_all(&bytes).map_err(string_error)?;
    output.sync_all().map_err(string_error)?;
    Ok((
        u64::try_from(bytes.len()).map_err(string_error)?,
        hex::encode(Sha256::digest(bytes)),
    ))
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.is_file() && right.is_file() && left.len() == right.len()
}

fn sync_parent(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(string_error)
}

#[cfg(unix)]
fn write_private_member(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), String> {
    use rustix::fs::{Mode, OFlags};
    let components = Path::new(relative)
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => Ok(value),
            _ => Err("qualification evidence path component is unsafe".to_owned()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let root_fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(string_error)?;
    let mut directory: fs::File = root_fd.into();
    for component in &components[..components.len() - 1] {
        match rustix::fs::mkdirat(
            &directory,
            Path::new(component),
            Mode::from_bits_truncate(0o700),
        ) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => return Err(error.to_string()),
        }
        let fd = rustix::fs::openat(
            &directory,
            Path::new(component),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(string_error)?;
        directory = fd.into();
    }
    let fd = rustix::fs::openat(
        &directory,
        Path::new(components[components.len() - 1]),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o400),
    )
    .map_err(string_error)?;
    let mut file: fs::File = fd.into();
    file.write_all(bytes).map_err(string_error)?;
    file.sync_all().map_err(string_error)?;
    directory.sync_all().map_err(string_error)
}

#[cfg(not(unix))]
fn write_private_member(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), String> {
    let destination = root.join(relative);
    let parent = destination
        .parent()
        .ok_or_else(|| "qualification evidence destination has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(string_error)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(string_error)?;
    file.write_all(bytes).map_err(string_error)?;
    file.sync_all().map_err(string_error)
}

fn files_equal(left: &Path, right: &Path) -> Result<bool, String> {
    let mut left = fs::File::open(left).map_err(string_error)?;
    let mut right = fs::File::open(right).map_err(string_error)?;
    if left.metadata().map_err(string_error)?.len() != right.metadata().map_err(string_error)?.len()
    {
        return Ok(false);
    }
    let mut left_buffer = [0_u8; 65_536];
    let mut right_buffer = [0_u8; 65_536];
    loop {
        let left_read = left.read(&mut left_buffer).map_err(string_error)?;
        let right_read = right.read(&mut right_buffer).map_err(string_error)?;
        if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

fn align_tar(size: u64) -> Result<u64, String> {
    size.checked_add(511)
        .map(|value| value / 512 * 512)
        .ok_or_else(|| "qualification tar length overflow".to_owned())
}

fn safe_member_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && !path.contains('\\')
        && path.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component.len() <= 128
                && component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
                })
        })
}

fn registered_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 10
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_source(root: &Path) {
        for report in REQUIRED_REPORTS {
            let path = root.join(report);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"{}").unwrap();
        }
        fs::create_dir_all(root.join("reports/scenarios")).unwrap();
        fs::write(root.join("reports/scenarios/happy-path.json"), b"{}").unwrap();
        fs::create_dir_all(root.join("receipts/op-1")).unwrap();
        fs::write(root.join("receipts/op-1/0.cbor"), b"x").unwrap();
        fs::create_dir_all(root.join("receipt-inspection")).unwrap();
        fs::write(root.join("receipt-inspection/op-1.json"), b"{}").unwrap();
        let common_phase = root.join("common-phases/provider-run/happy-path");
        fs::create_dir_all(&common_phase).unwrap();
        fs::write(common_phase.join("1.json"), b"{}").unwrap();
        let ledger = root.join("ledger/provider-run");
        fs::create_dir_all(&ledger).unwrap();
        for file in [
            "evidence-ledger-trust.json",
            "evidence-source-trust.json",
            "ledger.json",
        ] {
            fs::write(ledger.join(file), b"{}").unwrap();
        }
        for role in EVIDENCE_SOURCE_ROLES {
            let records = ledger.join("source-records").join(role);
            fs::create_dir_all(&records).unwrap();
            fs::write(records.join("1.json"), b"{}").unwrap();
        }
        fs::create_dir_all(ledger.join("supervisor-contexts")).unwrap();
        fs::write(ledger.join("supervisor-contexts/op-1.json"), b"{}").unwrap();
        fs::create_dir_all(ledger.join("decision-snapshots")).unwrap();
        fs::write(ledger.join("decision-snapshots/op-1.json"), b"{}").unwrap();
        fs::create_dir_all(ledger.join("durable-acks")).unwrap();
        fs::write(ledger.join("durable-acks/op-1.json"), b"{}").unwrap();
    }

    #[test]
    fn deterministic_archive_round_trips_closed_layout() {
        let source = tempfile::tempdir().unwrap();
        seed_source(source.path());
        let output = tempfile::tempdir().unwrap();
        let first = output.path().join("first.tar.zst");
        let second = output.path().join("second.tar.zst");
        let one = pack_final_evidence(source.path(), &first).unwrap();
        let two = pack_final_evidence(source.path(), &second).unwrap();
        assert_eq!(one, two);
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        let verified = verify_and_extract(&first).unwrap();
        assert_eq!(verified.compressed_sha256(), one.1);
        assert_eq!(
            verified.scan_member_names().count(),
            verified.member_names().len() + 1
        );
        assert_eq!(verified.scan_member_names().next(), Some("manifest.json"));
        assert_eq!(
            verified
                .read_member("manifest.json", MAX_MANIFEST_BYTES)
                .unwrap(),
            verified.manifest_bytes
        );
        assert!(
            verified
                .member_names()
                .any(|path| path == "reports/cleanup.json")
        );
    }

    #[test]
    fn rejects_cache_or_undeclared_files() {
        let source = tempfile::tempdir().unwrap();
        seed_source(source.path());
        fs::create_dir_all(source.path().join("__pycache__")).unwrap();
        fs::write(source.path().join("__pycache__/cached.pyc"), b"x").unwrap();
        let output = tempfile::tempdir().unwrap().path().join("evidence.tar.zst");
        assert!(pack_final_evidence(source.path(), &output).is_err());
    }

    #[test]
    fn rejects_incomplete_or_gapped_ledger_records() {
        let source = tempfile::tempdir().unwrap();
        seed_source(source.path());
        fs::remove_file(
            source
                .path()
                .join("ledger/provider-run/source-records/provider-proxy/1.json"),
        )
        .unwrap();
        let output = tempfile::tempdir().unwrap().path().join("evidence.tar.zst");
        assert!(pack_final_evidence(source.path(), &output).is_err());
    }

    #[test]
    fn rejects_missing_or_orphaned_decision_context_snapshots_and_acks() {
        let source = tempfile::tempdir().unwrap();
        seed_source(source.path());
        fs::remove_file(
            source
                .path()
                .join("ledger/provider-run/decision-snapshots/op-1.json"),
        )
        .unwrap();
        let output = tempfile::tempdir().unwrap().path().join("evidence.tar.zst");
        assert!(pack_final_evidence(source.path(), &output).is_err());

        let source = tempfile::tempdir().unwrap();
        seed_source(source.path());
        fs::remove_file(
            source
                .path()
                .join("ledger/provider-run/durable-acks/op-1.json"),
        )
        .unwrap();
        let output = tempfile::tempdir().unwrap().path().join("evidence.tar.zst");
        assert!(pack_final_evidence(source.path(), &output).is_err());

        let source = tempfile::tempdir().unwrap();
        seed_source(source.path());
        fs::write(
            source
                .path()
                .join("ledger/provider-run/supervisor-contexts/op-extra.json"),
            b"{}",
        )
        .unwrap();
        let output = tempfile::tempdir().unwrap().path().join("evidence.tar.zst");
        assert!(pack_final_evidence(source.path(), &output).is_err());

        let source = tempfile::tempdir().unwrap();
        seed_source(source.path());
        fs::write(
            source
                .path()
                .join("ledger/provider-run/durable-acks/op-extra.json"),
            b"{}",
        )
        .unwrap();
        let output = tempfile::tempdir().unwrap().path().join("evidence.tar.zst");
        assert!(pack_final_evidence(source.path(), &output).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_source_member() {
        use std::os::unix::fs::symlink;
        let source = tempfile::tempdir().unwrap();
        seed_source(source.path());
        symlink("cleanup.json", source.path().join("reports/escape.json")).unwrap();
        let output = tempfile::tempdir().unwrap().path().join("evidence.tar.zst");
        assert!(pack_final_evidence(source.path(), &output).is_err());
    }
}
