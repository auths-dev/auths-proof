//! Minimal sign-only boundary for one protected aggregate observation.
//!
//! This executable accepts no provider response, credential, cleanup handle,
//! candidate archive, or arbitrary signed envelope. The observer seed arrives
//! only on stdin after a no-secret process has constructed and validated the
//! closed observation record.

#![forbid(unsafe_code)]

use auths_profile_kit::{
    QualificationObservation, QualificationObservationRecord, QualificationObserverTrustRegistry,
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
const MAX_TRUST_BYTES: u64 = 65_536;
const MAX_SEED_BYTES: u64 = 128;

fn main() -> ExitCode {
    match run(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification observation signer failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        record_flag,
        record_path,
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
    if command != "sign-observation"
        || record_flag != "--record"
        || trust_flag != "--trust"
        || output_flag != "--output"
        || key_flag != "--key-id"
    {
        return Err(usage());
    }
    reject_secret_environment()?;
    let record_bytes = read_bounded(Path::new(record_path), MAX_RECORD_BYTES, true)?;
    let record = QualificationObservationRecord::from_json(&record_bytes).map_err(string_error)?;
    let trust_bytes = read_bounded(Path::new(trust_path), MAX_TRUST_BYTES, false)?;
    let trust =
        QualificationObserverTrustRegistry::from_json(&trust_bytes).map_err(string_error)?;
    let mut seed = Zeroizing::new(String::new());
    std::io::stdin()
        .take(MAX_SEED_BYTES + 1)
        .read_to_string(&mut seed)
        .map_err(string_error)?;
    if u64::try_from(seed.len()).map_err(string_error)? > MAX_SEED_BYTES {
        return Err("observer signing seed exceeds its hard bound".into());
    }
    let observation =
        QualificationObservation::sign_json(record, key_id, seed.trim_end_matches(['\r', '\n']))
            .map_err(string_error)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    QualificationObservation::verify_json(&observation, &trust, now).map_err(string_error)?;
    write_new(Path::new(output_path), &observation)
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
        return Err("observation signer inherited a forbidden secret environment slot".into());
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
        return Err("observation signer input is not a bounded regular file".into());
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
        return Err("observation signer input changed while it was read".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "observation output has no parent".to_owned())?;
    let name = path
        .file_name()
        .ok_or_else(|| "observation output has no file name".to_owned())?;
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
        return Err("observation output parent is not owner-only".into());
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
    "usage: qualification-observation-signer sign-observation --record <observation-record> --trust <registry> --output <new-observation> --key-id <id>; the one observer seed is read only from stdin".into()
}

fn string_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt as _};

    #[test]
    fn output_never_clobbers() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let output = directory.path().join("observation.json");
        write_new(&output, b"first").unwrap();
        assert!(write_new(&output, b"second").is_err());
    }
}
