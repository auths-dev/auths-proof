//! Operator commands for Git signing: keys, repository trust, grants,
//! revocation, and verification.
//!
//! Exit codes: 0 when every object verified, 1 when any was denied, 2 for an
//! indeterminate result or an operational error.
//!
//! `trust init --methods <file>` enables the OIDC workload and Sigstore
//! keyless methods described in that file (see the library's `methods`
//! module). The file is copied into the trust directory as `methods.json`,
//! and the trusted context commits to the exact configuration, so every
//! verifier must read the same file next to `trust.cbor`.
//!
//! A CI workload is granted by its workload principal. `workload-principal`
//! prints it, either from an explicit issuer and subject or from the
//! running GitHub Actions job's token.

use auths_codec::{encode_verifier_context, grant_id};
use auths_did_key::DID_KEY_V1;
use auths_git_signing::action::RepositoryId;
use auths_git_signing::custody::SoftwareKey;
use auths_git_signing::files::{decode_delegation, encode_delegation};
use auths_git_signing::methods::{MAX_METHODS_FILE_BYTES, METHODS_FILE};
use auths_git_signing::revoke::sign_revocation;
use auths_git_signing::sign::GitProofSigner as _;
use auths_git_signing::tool::{
    EnabledMethods, REVOCATIONS_DIRECTORY, TRUST_FILE, TrustMaterial, git, grant_path, key_path,
    load_key, now, state_home, timestamp,
};
use auths_git_signing::trust::{GitCapability, issue_grant, repository_trust, window_from};
use auths_git_signing::verify::{GitVerification, verify_object};
use auths_git_signing::workload::{GithubActionsTokenSource, TokenIdentity, TokenSource as _};
use auths_model::{GrantId, PrincipalId, PrincipalMethodId};
use clap::{Parser, Subcommand};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Maximum number of objects one `verify` call reads.
const MAX_RANGE: usize = 10_000;
/// Default repository trust lifetime: five years.
const DEFAULT_TRUST_SECONDS: u64 = 5 * 365 * 24 * 60 * 60;

#[derive(Parser)]
#[command(
    name = "auths-git",
    about = "Git signing under Auths delegated authority"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create or show a local did:key signing key.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Write repository trust pinned to a root key.
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
    /// Issue a grant from a root key to a subject principal.
    Grant {
        /// Label of the root key.
        #[arg(long)]
        root: String,
        /// Principal receiving the grant.
        #[arg(long)]
        subject: String,
        /// Repository, as host/owner/name.
        #[arg(long)]
        repository: String,
        /// Comma-separated: sign-commit, sign-tag.
        #[arg(long, value_delimiter = ',')]
        capability: Vec<String>,
        /// Grant lifetime in seconds.
        #[arg(long)]
        expires_in: u64,
        /// Delegation file to write.
        #[arg(long)]
        out: PathBuf,
    },
    /// Install a delegation file for a local key, or for a CI workload
    /// with `--workload`.
    InstallGrant {
        /// Label of the local key the grant was issued to, or the signing
        /// label of a workload.
        #[arg(long)]
        label: String,
        /// Install a grant to an OIDC workload principal; no local key is
        /// involved.
        #[arg(long)]
        workload: bool,
        /// Delegation file.
        file: PathBuf,
    },
    /// Print an OIDC workload principal to grant to. The same principal
    /// names the workload under `oidc-workload` and `sigstore-keyless`:
    /// Fulcio copies the token's issuer and subject into the certificate.
    WorkloadPrincipal {
        /// Issuer URL; requires `--subject`.
        #[arg(long, requires = "subject", conflicts_with = "github_actions")]
        issuer: Option<String>,
        /// Exact `sub` claim.
        #[arg(long, requires = "issuer")]
        subject: Option<String>,
        /// Read the issuer and subject from the running GitHub Actions job's
        /// token.
        #[arg(long)]
        github_actions: bool,
    },
    /// Write a root-signed revocation record for a grant.
    Revoke {
        /// Label of the root key.
        #[arg(long)]
        root: String,
        /// Repository, as host/owner/name.
        #[arg(long)]
        repository: String,
        /// Delegation file whose terminal grant is revoked.
        #[arg(long)]
        grant: PathBuf,
        /// Revocation record to write, normally under
        /// `.auths/git/revocations/`.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify commits and tags against pinned trust.
    Verify {
        /// Revisions: a single object (HEAD, v1.0.0) or a range (a..b).
        #[arg(required = true)]
        revisions: Vec<String>,
        /// Read trust from this commit's `.auths/git`; refused when the
        /// commit is inside the verified range.
        #[arg(long, conflicts_with = "trust_dir")]
        trust_from_ref: Option<String>,
        /// Read trust from a directory.
        #[arg(long)]
        trust_dir: Option<PathBuf>,
        /// Evaluation time in Unix seconds (default: now).
        #[arg(long)]
        at: Option<u64>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Generate a key; prints its did:key principal.
    Init {
        /// Local label.
        #[arg(long)]
        label: String,
    },
    /// Print a key's did:key principal.
    Show {
        /// Local label.
        #[arg(long)]
        label: String,
    },
}

#[derive(Subcommand)]
enum TrustCommand {
    /// Write `<out>/trust.cbor` pinned to a root key.
    Init {
        /// Label of the root key.
        #[arg(long)]
        root: String,
        /// Repository, as host/owner/name.
        #[arg(long)]
        repository: String,
        /// Trust directory, normally `.auths/git`.
        #[arg(long)]
        out: PathBuf,
        /// Trust lifetime in seconds.
        #[arg(long, default_value_t = DEFAULT_TRUST_SECONDS)]
        valid_for: u64,
        /// Workload method configuration to enable and commit to; copied
        /// to `<out>/methods.json`.
        #[arg(long)]
        methods: Option<PathBuf>,
    },
}

enum Failure {
    Denied,
    Indeterminate(String),
}

fn repository(value: &str) -> Result<RepositoryId, Failure> {
    RepositoryId::parse(value)
        .map_err(|_| Failure::Indeterminate(format!("invalid repository: {value}")))
}

fn fail(error: impl std::fmt::Display) -> Failure {
    Failure::Indeterminate(error.to_string())
}

fn run(command: Command) -> Result<(), Failure> {
    match command {
        Command::Key { command } => key(command),
        Command::Trust {
            command:
                TrustCommand::Init {
                    root,
                    repository,
                    out,
                    valid_for,
                    methods,
                },
        } => trust_init(&root, &repository, &out, valid_for, methods.as_deref()),
        Command::Grant {
            root,
            subject,
            repository,
            capability,
            expires_in,
            out,
        } => grant(&root, &subject, &repository, &capability, expires_in, &out),
        Command::InstallGrant {
            label,
            workload,
            file,
        } => install_grant(&label, workload, &file),
        Command::WorkloadPrincipal {
            issuer,
            subject,
            github_actions,
        } => workload_principal(issuer.as_deref(), subject.as_deref(), github_actions),
        Command::Revoke {
            root,
            repository,
            grant,
            out,
        } => revoke(&root, &repository, &grant, &out),
        Command::Verify {
            revisions,
            trust_from_ref,
            trust_dir,
            at,
            json,
        } => verify(&revisions, trust_from_ref.as_deref(), trust_dir, at, json),
    }
}

fn key(command: KeyCommand) -> Result<(), Failure> {
    let home = state_home().map_err(fail)?;
    let key = match command {
        KeyCommand::Init { label } => {
            SoftwareKey::generate(&key_path(&home, &label)).map_err(fail)?
        }
        KeyCommand::Show { label } => load_key(&home, &label).map_err(fail)?,
    };
    println!("{}", key.principal().as_str());
    Ok(())
}

fn trust_init(
    root: &str,
    repo: &str,
    out: &Path,
    valid_for: u64,
    methods_file: Option<&Path>,
) -> Result<(), Failure> {
    let home = state_home().map_err(fail)?;
    let root = load_key(&home, root).map_err(fail)?;
    let repo = repository(repo)?;
    let configuration = methods_file
        .map(|path| {
            let bytes = std::fs::read(path).map_err(fail)?;
            if bytes.len() > MAX_METHODS_FILE_BYTES {
                return Err(fail("the methods file exceeds its size limit"));
            }
            Ok(bytes)
        })
        .transpose()?;
    let methods = EnabledMethods::from_configuration(configuration.as_deref()).map_err(fail)?;
    let context = methods.with_sets(|methods, suites, claims| {
        repository_trust(
            &root.principal(),
            &PrincipalMethodId::parse(DID_KEY_V1).map_err(fail)?,
            &repo,
            methods,
            suites,
            claims,
            window_from(now().saturating_sub(60), valid_for).map_err(fail)?,
        )
        .map_err(fail)
    });
    let context = context.map_err(fail)??;
    std::fs::create_dir_all(out.join(REVOCATIONS_DIRECTORY)).map_err(fail)?;
    let methods_path = out.join(METHODS_FILE);
    match configuration {
        Some(bytes) => std::fs::write(&methods_path, bytes).map_err(fail)?,
        None if methods_path.exists() => std::fs::remove_file(&methods_path).map_err(fail)?,
        None => {}
    }
    std::fs::write(
        out.join(TRUST_FILE),
        encode_verifier_context(&context).map_err(|_| fail("could not encode trust"))?,
    )
    .map_err(fail)?;
    println!("wrote {}", out.join(TRUST_FILE).display());
    Ok(())
}

fn grant(
    root: &str,
    subject: &str,
    repo: &str,
    capability: &[String],
    expires_in: u64,
    out: &Path,
) -> Result<(), Failure> {
    let home = state_home().map_err(fail)?;
    let root = load_key(&home, root).map_err(fail)?;
    let capabilities = capability
        .iter()
        .map(|value| GitCapability::parse(value.trim()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(fail)?;
    let delegation = issue_grant(
        &root,
        PrincipalId::parse(subject).map_err(|_| fail("invalid subject principal"))?,
        &repository(repo)?,
        &capabilities,
        window_from(now().saturating_sub(60), expires_in).map_err(fail)?,
    )
    .map_err(fail)?;
    std::fs::write(out, encode_delegation(&delegation).map_err(fail)?).map_err(fail)?;
    let terminal = delegation.terminal().map_err(fail)?;
    let identifier = grant_id(terminal.statement()).map_err(|_| fail("grant id"))?;
    println!("grant {}", hex::encode(identifier.as_bytes()));
    println!("wrote {}", out.display());
    Ok(())
}

fn install_grant(label: &str, workload: bool, file: &Path) -> Result<(), Failure> {
    let home = state_home().map_err(fail)?;
    let bytes = std::fs::read(file).map_err(fail)?;
    let delegation = decode_delegation(&bytes).map_err(fail)?;
    let subject = delegation.terminal().map_err(fail)?.statement().subject();
    if workload {
        if !subject.as_str().starts_with("oidc-workload:") {
            return Err(fail(format!(
                "--workload needs a grant to an oidc-workload principal, not {}",
                subject.as_str()
            )));
        }
        std::fs::write(grant_path(&home, label), bytes).map_err(fail)?;
        println!("installed workload grant for {label}: {}", subject.as_str());
        return Ok(());
    }
    let key = load_key(&home, label).map_err(fail)?;
    if subject != &key.principal() {
        return Err(fail(format!(
            "the grant was issued to {}, not to key {label} ({})",
            subject.as_str(),
            key.principal().as_str()
        )));
    }
    std::fs::write(grant_path(&home, label), bytes).map_err(fail)?;
    println!("installed grant for {label}");
    Ok(())
}

fn workload_principal(
    issuer: Option<&str>,
    subject: Option<&str>,
    github_actions: bool,
) -> Result<(), Failure> {
    use auths_oidc_workload::identity::{IssuerUrl, Subject};
    let principal = match (issuer, subject, github_actions) {
        (Some(issuer), Some(subject), false) => auths_oidc_workload::principal(
            &IssuerUrl::parse(issuer).map_err(|_| fail("invalid issuer URL"))?,
            &Subject::parse(subject).map_err(|_| fail("invalid subject"))?,
        )
        .map_err(|_| fail("the workload principal is too long"))?,
        (None, None, true) => {
            const AUDIENCE: &str = "auths-git-workload-principal";
            let token = GithubActionsTokenSource::from_env()
                .and_then(|source| source.token(AUDIENCE))
                .map_err(fail)?;
            TokenIdentity::read(token.as_bytes(), AUDIENCE)
                .map_err(fail)?
                .principal
        }
        _ => return Err(fail("pass --issuer and --subject, or --github-actions")),
    };
    println!("{}", principal.as_str());
    Ok(())
}

fn revoke(root: &str, repo: &str, grant: &Path, out: &Path) -> Result<(), Failure> {
    let home = state_home().map_err(fail)?;
    let root = load_key(&home, root).map_err(fail)?;
    let delegation = decode_delegation(&std::fs::read(grant).map_err(fail)?).map_err(fail)?;
    let identifier: GrantId =
        grant_id(delegation.terminal().map_err(fail)?.statement()).map_err(|_| fail("grant id"))?;
    let record = sign_revocation(&repository(repo)?, identifier, &root, now()).map_err(fail)?;
    std::fs::write(out, record.to_armored()).map_err(fail)?;
    println!("revoked grant {}", hex::encode(identifier.as_bytes()));
    println!("wrote {}", out.display());
    Ok(())
}

fn objects(revisions: &[String]) -> Result<Vec<String>, Failure> {
    let mut objects = Vec::new();
    for revision in revisions {
        let listed = if revision.contains("..") {
            git(["rev-list", revision.as_str()]).map_err(fail)?
        } else {
            git(["rev-parse", "--verify", &format!("{revision}^{{object}}")]).map_err(fail)?
        };
        for line in String::from_utf8_lossy(&listed).lines() {
            objects.push(line.trim().to_owned());
            if objects.len() > MAX_RANGE {
                return Err(Failure::Indeterminate("git.range-too-large".to_owned()));
            }
        }
    }
    Ok(objects)
}

fn trust_material(
    objects: &[String],
    trust_from_ref: Option<&str>,
    trust_dir: Option<PathBuf>,
) -> Result<TrustMaterial, Failure> {
    match (trust_from_ref, trust_dir) {
        (Some(reference), None) => {
            let commit = String::from_utf8_lossy(
                &git(["rev-parse", "--verify", &format!("{reference}^{{commit}}")])
                    .map_err(fail)?,
            )
            .trim()
            .to_owned();
            let range: BTreeSet<&str> = objects.iter().map(String::as_str).collect();
            if range.contains(commit.as_str()) {
                return Err(Failure::Indeterminate(
                    "git.trust-from-verified-range".to_owned(),
                ));
            }
            TrustMaterial::from_commit(&commit).map_err(fail)
        }
        (None, Some(directory)) => TrustMaterial::from_directory(&directory).map_err(fail),
        _ => Err(Failure::Indeterminate(
            "pass --trust-from-ref <ref> or --trust-dir <dir>".to_owned(),
        )),
    }
}

fn verify(
    revisions: &[String],
    trust_from_ref: Option<&str>,
    trust_dir: Option<PathBuf>,
    at: Option<u64>,
    json: bool,
) -> Result<(), Failure> {
    let objects = objects(revisions)?;
    let material = trust_material(&objects, trust_from_ref, trust_dir)?;
    let methods = EnabledMethods::from_material(&material).map_err(fail)?;
    let trust = methods.load_trust(&material).map_err(fail)?;
    let evaluation_time = at.unwrap_or_else(now);

    let mut denied = false;
    let mut indeterminate = false;
    let mut report = Vec::new();
    for object in &objects {
        let kind = String::from_utf8_lossy(&git(["cat-file", "-t", object]).map_err(fail)?)
            .trim()
            .to_owned();
        let raw = git(["cat-file", &kind, object]).map_err(fail)?;
        let verification = methods
            .with_registries(|registries| {
                verify_object(&raw, &trust, registries, timestamp(evaluation_time))
            })
            .map_err(fail)?;
        let short = &object[..object.len().min(12)];
        match &verification {
            GitVerification::Verified(verified) => {
                let chain: Vec<&str> = verified.chain().iter().map(PrincipalId::as_str).collect();
                if !json {
                    println!(
                        "{short}  verified  {} <- {}",
                        verified.signer().as_str(),
                        chain.join(" <- ")
                    );
                }
                report.push(serde_json::json!({
                    "object": object,
                    "result": "verified",
                    "signer": verified.signer().as_str(),
                    "chain": chain,
                    "tag_name": verified.tag_name(),
                }));
            }
            GitVerification::Denied(code) => {
                denied = true;
                if !json {
                    println!("{short}  denied  {code}");
                }
                report
                    .push(serde_json::json!({"object": object, "result": "denied", "code": code}));
            }
            GitVerification::Indeterminate(code) => {
                indeterminate = true;
                if !json {
                    println!("{short}  indeterminate  {code}");
                }
                report.push(
                    serde_json::json!({"object": object, "result": "indeterminate", "code": code}),
                );
            }
        }
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "trusted_context_sha256": material.digest(),
                "repository": trust.repository().as_str(),
                "evaluation_time": evaluation_time,
                "objects": report,
            })
        );
    } else {
        println!(
            "{} objects; trust sha256 {}; evaluated at {evaluation_time}",
            objects.len(),
            material.digest()
        );
    }
    if indeterminate {
        Err(Failure::Indeterminate(String::new()))
    } else if denied {
        Err(Failure::Denied)
    } else {
        Ok(())
    }
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Denied) => ExitCode::from(1),
        Err(Failure::Indeterminate(message)) => {
            if !message.is_empty() {
                eprintln!("auths-git: {message}");
            }
            ExitCode::from(2)
        }
    }
}
