//! Minimal sign-only boundary for a fully verified qualification record.
//!
//! This executable parses no proposal, archive, report, ledger, provider
//! response, or candidate checkout. Its one attestation seed arrives only on
//! stdin and is zeroized after the no-clobber attestation write completes.

#![forbid(unsafe_code)]

use auths_profile_kit::{
    QualificationAttestation, QualificationRecord, QualificationTrustRegistry,
    QualificationVerifiedRecordBinding,
};
use rustix::fs::{Mode, OFlags, open, openat};
use std::{
    env,
    fs::File,
    io::{Read as _, Write as _},
    os::unix::fs::MetadataExt as _,
    path::Path,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const MAX_RECORD_BYTES: u64 = 262_144;
const MAX_BINDING_BYTES: u64 = 16_384;
const MAX_TRUST_BYTES: u64 = 65_536;
const MAX_SEED_BYTES: u64 = 128;

fn main() -> ExitCode {
    match run(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification attestation signer failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        record_flag,
        record_path,
        binding_flag,
        binding_path,
        trust_flag,
        trust_path,
        output_flag,
        output_path,
        key_flag,
        key_id,
    ] = arguments
    else {
        return Err(usage());
    };
    if command != "sign-verified"
        || record_flag != "--record"
        || binding_flag != "--binding"
        || trust_flag != "--trust"
        || output_flag != "--output"
        || key_flag != "--key-id"
    {
        return Err(usage());
    }
    reject_secret_environment()?;
    let record_bytes = read_bounded(Path::new(record_path), MAX_RECORD_BYTES, true)?;
    let record = QualificationRecord::from_json(&record_bytes).map_err(string_error)?;
    let binding_bytes = read_bounded(Path::new(binding_path), MAX_BINDING_BYTES, true)?;
    let binding =
        QualificationVerifiedRecordBinding::from_json(&binding_bytes).map_err(string_error)?;
    binding
        .require_matches_record(&record)
        .map_err(string_error)?;
    let trust_bytes = read_bounded(Path::new(trust_path), MAX_TRUST_BYTES, false)?;
    let trust = QualificationTrustRegistry::from_json(&trust_bytes).map_err(string_error)?;
    let mut seed = Zeroizing::new(String::new());
    std::io::stdin()
        .take(MAX_SEED_BYTES + 1)
        .read_to_string(&mut seed)
        .map_err(string_error)?;
    if u64::try_from(seed.len()).map_err(string_error)? > MAX_SEED_BYTES {
        return Err("attestation signing seed exceeds its hard bound".into());
    }
    let seed = seed.trim_end_matches(['\r', '\n']);
    let attestation =
        QualificationAttestation::sign_json(record, key_id, seed).map_err(string_error)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    QualificationAttestation::verify_json(&attestation, &trust, now).map_err(string_error)?;
    write_new(Path::new(output_path), &attestation)
}

fn reject_secret_environment() -> Result<(), String> {
    const FORBIDDEN: [&str; 6] = [
        "CREDENTIAL",
        "PASSWORD",
        "PRIVATE_KEY",
        "SECRET",
        "SEED",
        "TOKEN",
    ];
    if env::vars_os().any(|(name, _)| {
        let name = name.to_string_lossy().to_ascii_uppercase();
        FORBIDDEN.iter().any(|part| name.contains(part))
    }) {
        return Err("attestation signer inherited a forbidden secret environment slot".into());
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64, owner_only: bool) -> Result<Vec<u8>, String> {
    let mut file: File = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(string_error)?
    .into();
    let before = file.metadata().map_err(string_error)?;
    let permissions_invalid = if owner_only {
        before.mode() & 0o077 != 0
    } else {
        before.mode() & 0o022 != 0
    };
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != rustix::process::geteuid().as_raw()
        || permissions_invalid
        || before.len() == 0
        || before.len() > maximum
    {
        return Err("attestation signer input is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    let after = file.metadata().map_err(string_error)?;
    if u64::try_from(bytes.len()).map_err(string_error)? > maximum
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.len() != u64::try_from(bytes.len()).map_err(string_error)?
    {
        return Err("attestation signer input changed while it was read".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "attestation output has no parent".to_owned())?;
    let name = path
        .file_name()
        .ok_or_else(|| "attestation output has no file name".to_owned())?;
    let parent_directory = File::from(
        open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    let parent_metadata = parent_directory.metadata().map_err(string_error)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != rustix::process::geteuid().as_raw()
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err("attestation output parent is not owner-only".into());
    }
    let mut file = File::from(
        openat(
            &parent_directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(string_error)?,
    );
    file.write_all(bytes).map_err(string_error)?;
    file.sync_all().map_err(string_error)?;
    parent_directory.sync_all().map_err(string_error)
}

fn usage() -> String {
    "usage: qualification-attestation-signer sign-verified --record <verified-record> --binding <verified-binding> --trust <registry> --output <new-attestation> --key-id <id>; the one attestation seed is read only from stdin".into()
}

fn string_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    };

    #[test]
    fn verified_record_input_is_stable_and_output_never_clobbers() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let record = directory.path().join("record.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&record)
            .unwrap();
        file.write_all(b"{}").unwrap();
        file.sync_all().unwrap();
        assert_eq!(read_bounded(&record, 2, true).unwrap(), b"{}");
        let output = directory.path().join("attestation.json");
        write_new(&output, b"first").unwrap();
        assert!(write_new(&output, b"second").is_err());
    }
}
