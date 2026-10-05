//! Release tooling for recipe qualifications: the root ceremony, evidence
//! assembly, signing, and the same verification a gateway performs.
//!
//! Every failure prints one stable token first. A key is read from and
//! written to a private file and is never an argument or printed.

use auths_recipe_qualification::{
    EvidenceMemberKind, GitCommit, LiveEffects, MAX_INDEX_ENTRIES, ProviderContract,
    QualificationId, QualificationInputs, QualificationRootId, QualificationSignerCertificate,
    QualificationSignerId, QualificationTrustRoot, QualificationTuple,
    RELEASE_ATTESTATIONS_DIRECTORY, RELEASE_INDEX_FILE, RELEASE_RECORDS_DIRECTORY,
    RELEASE_REVOCATION_LIST_FILE, RELEASE_SIGNER_CERTIFICATE_FILE, VerifiedQualifications,
    VerifierState,
};
use auths_recipe_qualification_issuance::{
    CaseReport, CertificateRequest, IssuanceError, QualificationProposal, RecordDraft,
    ReleaseSigner, RootSigner, SigningSeed, evidence, stages,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use clap::{Parser, Subcommand};
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

/// The largest file this tool reads.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const RECORD_FILE: &str = "record.json";
const EVIDENCE_DIRECTORY: &str = "evidence";

#[derive(Parser)]
#[command(
    name = "auths-qualification",
    about = "Recipe qualification release tooling"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Offline ceremony: create a trust root and its private key file.
    RootInit {
        #[arg(long)]
        root_id: String,
        #[arg(long)]
        key_out: PathBuf,
        #[arg(long)]
        root_out: PathBuf,
    },
    /// Create a release signer key file and print its public key.
    SignerInit {
        #[arg(long)]
        key_out: PathBuf,
    },
    /// Offline ceremony: certify a release signer.
    Certify {
        #[arg(long)]
        root_key: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        issued_at: Option<u64>,
        #[arg(long)]
        not_before: u64,
        #[arg(long)]
        not_after: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Offline ceremony: issue the next revocation list.
    Revoke {
        #[arg(long)]
        root_key: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        issued_at: Option<u64>,
        #[arg(long)]
        next_update: u64,
        #[arg(long = "signer")]
        signers: Vec<String>,
        #[arg(long = "qualification")]
        qualifications: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Build one member's evidence artifact from reported cases.
    Evidence {
        #[arg(long)]
        member: String,
        #[arg(long)]
        commit: String,
        #[arg(long)]
        tuple: PathBuf,
        #[arg(long)]
        cases: Vec<PathBuf>,
        #[arg(long)]
        live_entered: Option<u32>,
        #[arg(long)]
        live_confirmed: Option<u32>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Assemble an unsigned proposal from a draft and ten evidence artifacts.
    Assemble {
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        evidence_dir: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Re-verify each proposal's evidence closure, attest it, and sign the
    /// release index that lists exactly those proposals.
    Sign {
        #[arg(long = "proposal-dir", required = true)]
        proposal_dirs: Vec<PathBuf>,
        #[arg(long)]
        signer_key: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        issued_at: Option<u64>,
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Verify a release directory under a trust root, as a gateway does.
    Verify {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        now: Option<u64>,
    },
    /// Run the signer-rotation and freshness stages for a tuple on this
    /// build's release machinery.
    StageTrust {
        #[arg(long)]
        tuple: PathBuf,
        #[arg(long)]
        now: Option<u64>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Run the freshness stage over a release directory.
    StageFreshness {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        now: Option<u64>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Scan files for planted canaries, one canary per line of the canary
    /// file.
    StageRedaction {
        #[arg(long)]
        canaries: PathBuf,
        /// A source as `<kind>=<path>`, where the kind is `log`, `trace`,
        /// `metric`, `support-bundle`, or `evidence`.
        #[arg(long = "source", required = true)]
        sources: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the identifier of a provider contract.
    ContractId {
        #[arg(long)]
        contract: PathBuf,
    },
}

/// A failure: its stable token and what it concerns. Never a key.
struct Failure(String);

impl From<IssuanceError> for Failure {
    fn from(error: IssuanceError) -> Self {
        Self(format!("qualification.{} {error}", error.as_str()))
    }
}

fn failure(token: &str, path: &Path) -> Failure {
    Failure(format!("qualification.{token} path={}", path.display()))
}

fn read(path: &Path) -> Result<Vec<u8>, Failure> {
    let unreadable = || failure("unreadable", path);
    let metadata = fs::metadata(path).map_err(|_| unreadable())?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err(unreadable());
    }
    fs::read(path).map_err(|_| unreadable())
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|_| failure("unwritable", path))?;
    }
    fs::write(path, bytes).map_err(|_| failure("unwritable", path))
}

/// Writes a new key file readable only by its owner; an existing file is
/// never replaced.
fn write_key(path: &Path, seed: &SigningSeed) -> Result<(), Failure> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let encoded = Zeroizing::new(Base64UrlUnpadded::encode_string(seed.expose()));
    let mut file = options
        .open(path)
        .map_err(|_| failure("key-unwritable", path))?;
    file.write_all(encoded.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| failure("key-unwritable", path))
}

fn read_key(path: &Path) -> Result<SigningSeed, Failure> {
    let invalid = || failure("key-unreadable", path);
    #[cfg(unix)]
    {
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &fs::metadata(path).map_err(|_| invalid())?.permissions(),
        );
        if mode & 0o077 != 0 {
            return Err(failure("key-not-private", path));
        }
    }
    let text = Zeroizing::new(read(path)?);
    let trimmed = text.trim_ascii_end();
    let mut seed = Zeroizing::new([0_u8; 32]);
    let decoded = Base64UrlUnpadded::decode(trimmed, seed.as_mut_slice()).map_err(|_| invalid())?;
    if decoded.len() != 32 {
        return Err(invalid());
    }
    Ok(SigningSeed::from_bytes(seed))
}

fn now(explicit: Option<u64>) -> Result<u64, Failure> {
    explicit
        .or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|elapsed| elapsed.as_secs())
        })
        .ok_or_else(|| Failure("qualification.clock-unavailable".to_owned()))
}

fn parsed<T, E>(value: Result<T, E>, token: &str) -> Result<T, Failure> {
    value.map_err(|_| Failure(format!("qualification.invalid-{token}")))
}

fn json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Failure> {
    serde_json::from_slice(&read(path)?).map_err(|_| failure("malformed", path))
}

fn member(token: &str) -> Result<EvidenceMemberKind, Failure> {
    parsed(
        serde_json::from_value(serde_json::Value::String(token.to_owned())),
        "member",
    )
}

/// The files of a directory in name order, at most `limit`.
fn files(directory: &Path, limit: usize) -> Result<Vec<PathBuf>, Failure> {
    let unreadable = || failure("unreadable", directory);
    let mut paths = fs::read_dir(directory)
        .map_err(|_| unreadable())?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| unreadable())?;
    if paths.len() > limit {
        return Err(failure("too-many-files", directory));
    }
    paths.sort();
    Ok(paths)
}

fn read_all(directory: &Path, limit: usize) -> Result<Vec<Vec<u8>>, Failure> {
    files(directory, limit)?
        .iter()
        .map(|path| read(path))
        .collect()
}

fn proposal(directory: &Path) -> Result<QualificationProposal, Failure> {
    let evidence = read_all(
        &directory.join(EVIDENCE_DIRECTORY),
        EvidenceMemberKind::ALL.len(),
    )?;
    let evidence: Vec<&[u8]> = evidence.iter().map(Vec::as_slice).collect();
    Ok(QualificationProposal::from_parts(
        &read(&directory.join(RECORD_FILE))?,
        &evidence,
    )?)
}

/// A release directory's bytes.
struct Release {
    certificate: Vec<u8>,
    list: Vec<u8>,
    index: Vec<u8>,
    records: Vec<Vec<u8>>,
    attestations: Vec<Vec<u8>>,
}

impl Release {
    fn read(directory: &Path) -> Result<Self, Failure> {
        Ok(Self {
            certificate: read(&directory.join(RELEASE_SIGNER_CERTIFICATE_FILE))?,
            list: read(&directory.join(RELEASE_REVOCATION_LIST_FILE))?,
            index: read(&directory.join(RELEASE_INDEX_FILE))?,
            records: read_all(
                &directory.join(RELEASE_RECORDS_DIRECTORY),
                MAX_INDEX_ENTRIES,
            )?,
            attestations: read_all(
                &directory.join(RELEASE_ATTESTATIONS_DIRECTORY),
                MAX_INDEX_ENTRIES,
            )?,
        })
    }

    fn with_inputs<T>(&self, use_inputs: impl FnOnce(&QualificationInputs<'_>) -> T) -> T {
        let records: Vec<&[u8]> = self.records.iter().map(Vec::as_slice).collect();
        let attestations: Vec<&[u8]> = self.attestations.iter().map(Vec::as_slice).collect();
        use_inputs(&QualificationInputs {
            signer_certificate: &self.certificate,
            revocation_list: &self.list,
            release_index: &self.index,
            records: &records,
            attestations: &attestations,
        })
    }
}

fn trust_root(path: &Path) -> Result<QualificationTrustRoot, Failure> {
    QualificationTrustRoot::from_canonical_json(&read(path)?)
        .map_err(|_| failure("invalid-trust-root", path))
}

fn write_cases(path: &Path, cases: &[CaseReport]) -> Result<(), Failure> {
    let failed = cases.iter().filter(|case| !case.passed).count();
    write(
        path,
        &serde_json::to_vec_pretty(cases).map_err(|_| failure("unwritable", path))?,
    )?;
    if failed == 0 {
        println!("cases={} failed=0", cases.len());
        Ok(())
    } else {
        Err(Failure(format!(
            "qualification.case-failed cases={} failed={failed}",
            cases.len()
        )))
    }
}

fn sign(
    proposal_dirs: &[PathBuf],
    signer_key: &Path,
    certificate: &Path,
    issued_at: u64,
    out_dir: &Path,
) -> Result<(), Failure> {
    let certificate_bytes = read(certificate)?;
    let certificate = QualificationSignerCertificate::from_canonical_json(&certificate_bytes)
        .map_err(|_| failure("invalid-certificate", certificate))?;
    let signer = ReleaseSigner::open(&read_key(signer_key)?, certificate)?;
    let proposals = proposal_dirs
        .iter()
        .map(|directory| proposal(directory))
        .collect::<Result<Vec<_>, _>>()?;
    let mut attestations = Vec::with_capacity(proposals.len());
    for proposal in &proposals {
        let record = proposal.record().body();
        attestations.push(signer.attest(
            proposal,
            issued_at,
            record.not_before.max(issued_at),
            record.not_after,
        )?);
    }
    let listed: Vec<_> = proposals
        .iter()
        .map(QualificationProposal::record)
        .zip(&attestations)
        .collect();
    let index = signer.index(issued_at, &listed)?;
    for (record, attestation) in &listed {
        let name = format!("{}.json", record.body().qualification_id.as_str());
        write(
            &out_dir.join(RELEASE_RECORDS_DIRECTORY).join(&name),
            record.canonical_bytes(),
        )?;
        write(
            &out_dir.join(RELEASE_ATTESTATIONS_DIRECTORY).join(&name),
            attestation.canonical_bytes(),
        )?;
    }
    write(
        &out_dir.join(RELEASE_SIGNER_CERTIFICATE_FILE),
        &certificate_bytes,
    )?;
    write(&out_dir.join(RELEASE_INDEX_FILE), index.canonical_bytes())?;
    println!("signed={} index={}", listed.len(), index.digest().to_hex());
    Ok(())
}

fn ceremony(command: Command) -> Result<(), Failure> {
    match command {
        Command::RootInit {
            root_id,
            key_out,
            root_out,
        } => {
            let seed = SigningSeed::generate()?;
            let root = RootSigner::create(
                &seed,
                parsed(QualificationRootId::parse(root_id), "root-id")?,
            )?;
            write_key(&key_out, &seed)?;
            write(&root_out, root.trust_root().canonical_bytes())?;
            println!("root={}", root.trust_root().digest().to_hex());
            Ok(())
        }
        Command::SignerInit { key_out } => {
            let seed = SigningSeed::generate()?;
            write_key(&key_out, &seed)?;
            println!("public_key={}", seed.public_key().as_str());
            Ok(())
        }
        Command::Certify {
            root_key,
            root,
            signer_id,
            public_key,
            issued_at,
            not_before,
            not_after,
            out,
        } => {
            let root = RootSigner::open(&read_key(&root_key)?, trust_root(&root)?)?;
            let certificate = root.certify(CertificateRequest {
                signer_id: parsed(QualificationSignerId::parse(signer_id), "signer-id")?,
                public_key_b64: parsed(public_key.try_into(), "public-key")?,
                issued_at: now(issued_at)?,
                not_before,
                not_after,
            })?;
            write(&out, certificate.canonical_bytes())
        }
        Command::Revoke {
            root_key,
            root,
            sequence,
            issued_at,
            next_update,
            signers,
            qualifications,
            out,
        } => {
            let root = RootSigner::open(&read_key(&root_key)?, trust_root(&root)?)?;
            let signers = signers
                .into_iter()
                .map(|signer| parsed(QualificationSignerId::parse(signer), "signer-id"))
                .collect::<Result<Vec<_>, _>>()?;
            let qualifications = qualifications
                .into_iter()
                .map(|id| parsed(QualificationId::parse(id), "qualification-id"))
                .collect::<Result<Vec<_>, _>>()?;
            let list = root.revoke(
                sequence,
                now(issued_at)?,
                next_update,
                signers,
                qualifications,
            )?;
            write(&out, list.canonical_bytes())
        }
        _ => Err(Failure("qualification.not-a-ceremony".to_owned())),
    }
}

fn build(command: Command) -> Result<(), Failure> {
    match command {
        Command::Evidence {
            member: token,
            commit,
            tuple,
            cases,
            live_entered,
            live_confirmed,
            out,
        } => {
            let mut reported = Vec::new();
            for path in &cases {
                reported.extend(json::<Vec<CaseReport>>(path)?);
            }
            let live_effects = match (live_entered, live_confirmed) {
                (Some(entered), Some(confirmed_by_read_back)) => Some(LiveEffects {
                    entered,
                    confirmed_by_read_back,
                }),
                (None, None) => None,
                _ => return Err(Failure("qualification.invalid-live-effects".to_owned())),
            };
            let artifact = evidence(
                member(&token)?,
                &parsed(GitCommit::parse(commit), "commit")?,
                &json::<QualificationTuple>(&tuple)?,
                reported,
                live_effects,
            )?;
            println!("evidence={}", artifact.digest().to_hex());
            write(&out, artifact.canonical_bytes())
        }
        Command::Assemble {
            draft,
            evidence_dir,
            out_dir,
        } => {
            let evidence = read_all(&evidence_dir, EvidenceMemberKind::ALL.len())?
                .iter()
                .map(|bytes| {
                    auths_recipe_qualification::QualificationEvidence::from_canonical_json(bytes)
                        .map_err(IssuanceError::from)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let proposal = QualificationProposal::assemble(json::<RecordDraft>(&draft)?, evidence)?;
            for (index, artifact) in proposal.evidence().iter().enumerate() {
                write(
                    &out_dir
                        .join(EVIDENCE_DIRECTORY)
                        .join(format!("{index:02}.json")),
                    artifact.canonical_bytes(),
                )?;
            }
            write(
                &out_dir.join(RECORD_FILE),
                proposal.record().canonical_bytes(),
            )?;
            println!("record={}", proposal.record().digest().to_hex());
            Ok(())
        }
        _ => Err(Failure("qualification.not-a-build".to_owned())),
    }
}

fn stage(command: Command) -> Result<(), Failure> {
    match command {
        Command::StageTrust {
            tuple,
            now: at,
            out,
        } => write_cases(
            &out,
            &stages::trust_transitions(&json::<QualificationTuple>(&tuple)?, now(at)?)?,
        ),
        Command::StageFreshness {
            root,
            release_dir,
            deployment,
            now: at,
            out,
        } => {
            let root = trust_root(&root)?;
            let deployment = json::<QualificationTuple>(&deployment)?;
            let at = now(at)?;
            let mut state = VerifierState::default();
            let release = Release::read(&release_dir)?;
            let cases = release.with_inputs(|inputs| {
                VerifiedQualifications::verify(&root, inputs).remember(&mut state);
                stages::freshness(&root, inputs, &deployment, &state, at)
            })?;
            write_cases(&out, &cases)
        }
        Command::StageRedaction {
            canaries,
            sources,
            out,
        } => {
            let canaries = Zeroizing::new(read(&canaries)?);
            let canaries: Vec<&[u8]> = canaries
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .collect();
            let mut named = Vec::with_capacity(sources.len());
            for source in &sources {
                let (kind, path) = source
                    .split_once('=')
                    .and_then(|(kind, path)| Some((stages::SourceKind::parse(kind)?, path)))
                    .ok_or_else(|| Failure("qualification.invalid-source".to_owned()))?;
                let path = Path::new(path);
                let name = path
                    .file_name()
                    .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
                named.push((kind, name, read(path)?));
            }
            let scanned: Vec<stages::ScanSource<'_>> = named
                .iter()
                .map(|(kind, name, bytes)| stages::ScanSource {
                    kind: *kind,
                    name,
                    bytes,
                })
                .collect();
            write_cases(&out, &stages::redaction(&canaries, &scanned)?)
        }
        Command::ContractId { contract } => {
            let contract = ProviderContract::from_canonical_json(&read(&contract)?)
                .map_err(|_| failure("invalid-contract", &contract))?;
            println!("{}", contract.contract_id().digest().to_hex());
            Ok(())
        }
        _ => Err(Failure("qualification.not-a-stage".to_owned())),
    }
}

fn run(command: Command) -> Result<(), Failure> {
    match command {
        Command::RootInit { .. }
        | Command::SignerInit { .. }
        | Command::Certify { .. }
        | Command::Revoke { .. } => ceremony(command),
        Command::Evidence { .. } | Command::Assemble { .. } => build(command),
        Command::StageTrust { .. }
        | Command::StageFreshness { .. }
        | Command::StageRedaction { .. }
        | Command::ContractId { .. } => stage(command),
        Command::Sign {
            proposal_dirs,
            signer_key,
            certificate,
            issued_at,
            out_dir,
        } => sign(
            &proposal_dirs,
            &signer_key,
            &certificate,
            now(issued_at)?,
            &out_dir,
        ),
        Command::Verify {
            root,
            release_dir,
            deployment,
            now: at,
        } => {
            let root = trust_root(&root)?;
            let release = Release::read(&release_dir)?;
            let verified =
                release.with_inputs(|inputs| VerifiedQualifications::verify(&root, inputs));
            let mut state = VerifierState::default();
            verified.remember(&mut state);
            let verdict = verified.evaluate(
                &json::<QualificationTuple>(&deployment)?,
                now(at)?,
                true,
                &state,
            );
            let code = verdict.refusal.map_or("none", |refusal| refusal.as_str());
            let line = format!(
                "state={} code={code} lease={}",
                verdict.state.as_str(),
                verdict.permits_lease()
            );
            if verdict.permits_lease() {
                println!("{line}");
                Ok(())
            } else {
                Err(Failure(format!("qualification.not-qualified {line}")))
            }
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure(line)) => {
            eprintln!("{line}");
            ExitCode::FAILURE
        }
    }
}
