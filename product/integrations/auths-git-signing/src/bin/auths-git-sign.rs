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
//! git config auths.signer did-key                       # the default
//! ```
//!
//! The signing label names the installed grant (`$AUTHS_GIT_HOME/grants/
//! <label>.json`) and, for `did-key`, the local key.
//!
//! A GitHub Actions job signs as its OIDC workload identity instead:
//!
//! ```text
//! # The job needs `permissions: id-token: write`.
//! auths-git workload-principal --github-actions   # the principal to grant
//! auths-git install-grant --workload --label ci ci.grant.json
//! git config user.signingkey auths:ci
//! git config auths.signer oidc-workload
//! ```
//!
//! Each signature then uses a fresh in-memory Ed25519 key and a token from
//! `ACTIONS_ID_TOKEN_REQUEST_URL` whose audience commits to that key. The
//! token is embedded in the signature as evidence and is never printed.
//! Verifiers accept such a signature only while the token is live (a few
//! minutes), so this signer is for gates that verify as the job runs.
//!
//! `auths.signer sigstore-keyless` signs through public-good Sigstore
//! instead. Each signature uses a fresh in-memory P-256 key: a token with
//! audience `sigstore` obtains a Fulcio certificate for it, and the exact
//! signature is recorded in Rekor. The certificate chain and the Rekor
//! entry are embedded as evidence, so verification is offline and does not
//! expire with the token. Its principal is the same `oidc-workload:`
//! principal `workload-principal --github-actions` prints: Fulcio copies the
//! token's `iss` and `sub` into the certificate.
//!
//! Signing never writes the `SIG_CREATED` status unless a signature was
//! produced, so Git refuses to create the object on any failure. Verifying
//! reports `GOODSIG` only for a verified result.

use auths_git_signing::object::{MAX_PAYLOAD_BYTES, UnsignedPayload};
use auths_git_signing::program::{ProgramRequest, parse_arguments, sign_created_status};
use auths_git_signing::sign::{check_coverage, sign_payload};
use auths_git_signing::sigstore_client::HttpSigstoreClient;
use auths_git_signing::tool::{
    EnabledMethods, SignerKind, TrustMaterial, configured_repository, git_config, load_delegation,
    load_key, now, state_home, timestamp,
};
use auths_git_signing::verify::{GitVerification, verify_signature};
use auths_git_signing::workload::{
    GithubActionsTokenSource, OidcWorkloadSigner, SigstoreKeylessSigner,
};
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
    let kind = SignerKind::configured().map_err(|error| error.to_string())?;
    let delegation = load_delegation(&home, label).map_err(|error| error.to_string())?;
    let signed_at = now();
    check_coverage(&delegation, &payload, &repository, signed_at)
        .map_err(|error| error.to_string())?;
    let envelope = match kind {
        SignerKind::DidKey => {
            let key = load_key(&home, label).map_err(|error| error.to_string())?;
            sign_payload(&payload, &repository, &key, &delegation, signed_at)
        }
        SignerKind::OidcWorkload => {
            let tokens = GithubActionsTokenSource::from_env().map_err(|error| error.to_string())?;
            let signer = OidcWorkloadSigner::acquire(&tokens).map_err(|error| error.to_string())?;
            sign_payload(&payload, &repository, &signer, &delegation, signed_at)
        }
        SignerKind::SigstoreKeyless => {
            let tokens = GithubActionsTokenSource::from_env().map_err(|error| error.to_string())?;
            let client = HttpSigstoreClient::public_good().map_err(|error| error.to_string())?;
            let signer = SigstoreKeylessSigner::acquire(&tokens, &client)
                .map_err(|error| error.to_string())?;
            sign_payload(&payload, &repository, &signer, &delegation, signed_at)
        }
    }
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
    let methods = EnabledMethods::from_material(&material).map_err(|error| error.to_string())?;
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
