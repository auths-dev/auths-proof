//! The signing program Git runs for `gpg.format = x509`.
//!
//! Configure a repository with:
//!
//! ```text
//! git config gpg.format x509
//! git config gpg.x509.program auths-git-sign
//! git config user.signingkey auths:<label>
//! git config auths.repository <host/owner/name>
//! git config auths.trustDir <path to trust material>   # for verify-commit
//! ```
//!
//! Signing never writes the `SIG_CREATED` status unless a signature was
//! produced, so Git refuses to create the object on any failure. Verifying
//! reports `GOODSIG` only for a verified result.

use auths_git_signing::object::{MAX_PAYLOAD_BYTES, UnsignedPayload};
use auths_git_signing::program::{ProgramRequest, parse_arguments, sign_created_status};
use auths_git_signing::sign::{check_coverage, sign_payload};
use auths_git_signing::tool::{
    EnabledMethods, TrustMaterial, configured_repository, git_config, load_delegation, load_key,
    now, state_home, timestamp,
};
use auths_git_signing::verify::{GitVerification, verify_signature};
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

fn read_stdin(limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read the payload: {error}"))?;
    if bytes.len() > limit {
        return Err("git.payload-too-large".to_owned());
    }
    Ok(bytes)
}

fn sign(label: &str) -> Result<(), String> {
    let payload = UnsignedPayload::parse(read_stdin(MAX_PAYLOAD_BYTES)?)
        .map_err(|error| error.code().to_owned())?;
    let repository = configured_repository().map_err(|error| error.to_string())?;
    let home = state_home().map_err(|error| error.to_string())?;
    let key = load_key(&home, label).map_err(|error| error.to_string())?;
    let delegation = load_delegation(&home, label).map_err(|error| error.to_string())?;
    check_coverage(&delegation, &payload, &repository, now()).map_err(|error| error.to_string())?;
    let envelope = sign_payload(&payload, &repository, &key, &delegation)
        .map_err(|error| error.to_string())?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(envelope.to_armored().as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|error| error.to_string())?;
    std::io::stderr()
        .write_all(sign_created_status())
        .map_err(|error| error.to_string())
}

fn verify(signature: &PathBuf) -> Result<GitVerification, String> {
    let armored = std::fs::read(signature).map_err(|error| error.to_string())?;
    let payload = UnsignedPayload::parse(read_stdin(MAX_PAYLOAD_BYTES)?)
        .map_err(|error| error.code().to_owned())?;
    let directory = git_config("auths.trustDir")
        .ok_or_else(|| "set `git config auths.trustDir <trust material directory>`".to_owned())?;
    let material = TrustMaterial::from_directory(&PathBuf::from(directory))
        .map_err(|error| error.to_string())?;
    let methods = EnabledMethods::new().map_err(|error| error.to_string())?;
    let trust = methods
        .load_trust(&material)
        .map_err(|error| error.to_string())?;
    methods
        .with_registries(|registries| {
            verify_signature(&payload, &armored, &trust, registries, timestamp(now()))
        })
        .map_err(|error| error.to_string())
}

fn main() -> ExitCode {
    match parse_arguments(std::env::args_os().skip(1)) {
        Ok(ProgramRequest::Sign { key }) => match sign(key.label()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("auths-git-sign: {message}");
                ExitCode::FAILURE
            }
        },
        Ok(ProgramRequest::Verify { signature }) => {
            let (status, detail) = match verify(&signature) {
                Ok(verification) => {
                    let detail = match &verification {
                        GitVerification::Verified(verified) => format!(
                            "verified: {} <- {}",
                            verified.signer().as_str(),
                            verified
                                .chain()
                                .iter()
                                .map(auths_model::PrincipalId::as_str)
                                .collect::<Vec<_>>()
                                .join(" <- ")
                        ),
                        GitVerification::Denied(code) => format!("denied: {code}"),
                        GitVerification::Indeterminate(code) => format!("indeterminate: {code}"),
                    };
                    (verification.status(), detail)
                }
                Err(message) => (
                    auths_git_signing::program::VerifyStatus::Error("git.trust-unavailable"),
                    message,
                ),
            };
            let _ = std::io::stdout().write_all(&status.status_lines());
            eprintln!("auths-git-sign: {detail}");
            ExitCode::from(u8::try_from(status.exit_code()).unwrap_or(2))
        }
        Err(error) => {
            eprintln!("auths-git-sign: {error}");
            ExitCode::from(2)
        }
    }
}
