#![allow(clippy::too_many_lines)]

use std::{
    io::{BufRead as _, BufReader, Read},
    process::{ExitStatus, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::Instant,
};

use crate::*;

pub(crate) const FUZZ_TARGETS: [&str; 7] = [
    "target_codec",
    "target_portable_codecs",
    "target_model_state",
    "target_composition",
    "target_registry_handlers",
    "target_principal_parsers",
    "target_portable_abi",
];
pub(crate) const PRODUCT_FUZZ_TARGETS: [&str; 1] = ["target_bounded_policy"];

/// The nightly toolchain the scheduled campaign builds fuzz targets with. The
/// repository's `rust-toolchain.toml` outranks rustup's default toolchain, so
/// the campaign names this pin explicitly; `fuzz_inventory` keeps the Fuzz
/// workflow on the same pin.
pub(crate) const FUZZ_TOOLCHAIN: &str = "nightly-2026-07-20";
/// The cargo-fuzz release the Fuzz workflow installs.
const CARGO_FUZZ_VERSION: &str = "0.13.1";
/// Scheduled shards; `CAMPAIGN_TARGETS[i]` runs on shard `i % CAMPAIGN_SHARDS`.
const CAMPAIGN_SHARDS: usize = 2;
/// Upper bound on the per-target fuzzing time a caller may request.
const MAX_CAMPAIGN_SECONDS: u64 = 3_600;
const CORE_FUZZ_DIR: &str = "core/fuzz";
const BOUNDED_POLICY_FUZZ_DIR: &str = "product/policy/auths-bounded-policy/fuzz";
const CORE_FIXTURES: &str = "core/fixtures/v1";
const CAMPAIGN_OUTPUT: &str = "target/fuzz-campaign";
const FUZZ_CAMPAIGN_USAGE: &str =
    "usage: cargo xtask fuzz-campaign --shard <0|1> --seconds <1..=3600> [--toolchain <name>]";
/// libFuzzer and sanitizer lines that mean the run found or hit a failure.
const FAILURE_MARKERS: [&str; 3] = [
    "ERROR: libFuzzer:",
    "ERROR: AddressSanitizer:",
    "ERROR: LeakSanitizer:",
];

/// One role of a canonical core fixture case.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum FixtureRole {
    Proof,
    Action,
    Context,
    Result,
    Body,
}

impl FixtureRole {
    const ALL: [Self; 5] = [
        Self::Proof,
        Self::Action,
        Self::Context,
        Self::Result,
        Self::Body,
    ];

    const fn suffix(self) -> &'static str {
        match self {
            Self::Proof => ".proof.cbor",
            Self::Action => ".action.cbor",
            Self::Context => ".context.cbor",
            Self::Result => ".result.cbor",
            Self::Body => ".body.cbor",
        }
    }
}

/// How a target's seeds are derived from the canonical core corpus.
#[derive(Clone, Copy, Debug)]
enum FixtureSeeds {
    /// The fixture files of these roles, unchanged.
    Roles(&'static [FixtureRole]),
    /// The principal evidence objects carried inside decodable fixture proofs,
    /// which are exactly the bytes the principal parsers decode.
    ProofEvidence,
    /// `APF1`-framed proof, action and context tuples. Each decodable context
    /// is re-bound to the target's registry configuration, so a tuple reaches
    /// the verifier stages behind the configuration check instead of stopping
    /// there.
    FramedAbiTuples,
}

struct CampaignTarget {
    name: &'static str,
    fuzz_dir: &'static str,
    seeds: FixtureSeeds,
}

/// Every scheduled target, in the order that fixes its shard.
static CAMPAIGN_TARGETS: [CampaignTarget; 8] = [
    CampaignTarget {
        name: "target_codec",
        fuzz_dir: CORE_FUZZ_DIR,
        seeds: FixtureSeeds::Roles(&[FixtureRole::Proof, FixtureRole::Context]),
    },
    CampaignTarget {
        name: "target_portable_codecs",
        fuzz_dir: CORE_FUZZ_DIR,
        seeds: FixtureSeeds::Roles(&[
            FixtureRole::Action,
            FixtureRole::Context,
            FixtureRole::Result,
        ]),
    },
    CampaignTarget {
        name: "target_model_state",
        fuzz_dir: CORE_FUZZ_DIR,
        seeds: FixtureSeeds::Roles(&[FixtureRole::Action, FixtureRole::Body]),
    },
    CampaignTarget {
        name: "target_composition",
        fuzz_dir: CORE_FUZZ_DIR,
        seeds: FixtureSeeds::Roles(&[FixtureRole::Body]),
    },
    CampaignTarget {
        name: "target_registry_handlers",
        fuzz_dir: CORE_FUZZ_DIR,
        seeds: FixtureSeeds::Roles(&[FixtureRole::Body]),
    },
    CampaignTarget {
        name: "target_principal_parsers",
        fuzz_dir: CORE_FUZZ_DIR,
        seeds: FixtureSeeds::ProofEvidence,
    },
    CampaignTarget {
        name: "target_portable_abi",
        fuzz_dir: CORE_FUZZ_DIR,
        seeds: FixtureSeeds::FramedAbiTuples,
    },
    CampaignTarget {
        name: "target_bounded_policy",
        fuzz_dir: BOUNDED_POLICY_FUZZ_DIR,
        seeds: FixtureSeeds::Roles(&[FixtureRole::Body]),
    },
];

fn shard_targets(shard: usize) -> impl Iterator<Item = &'static CampaignTarget> {
    CAMPAIGN_TARGETS
        .iter()
        .enumerate()
        .filter(move |(index, _)| index % CAMPAIGN_SHARDS == shard)
        .map(|(_, target)| target)
}

#[derive(Debug, Eq, PartialEq)]
struct CampaignOptions {
    shard: usize,
    seconds: u64,
    toolchain: String,
}

impl CampaignOptions {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut shard = None;
        let mut seconds = None;
        let mut toolchain = None;
        let mut index = 0;
        while index < arguments.len() {
            let flag = arguments[index].as_str();
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| format!("{flag} requires a value; {FUZZ_CAMPAIGN_USAGE}"))?;
            let duplicate = match flag {
                "--shard" => shard
                    .replace(
                        value
                            .parse::<usize>()
                            .ok()
                            .filter(|shard| *shard < CAMPAIGN_SHARDS)
                            .ok_or_else(|| {
                                format!("--shard must be below {CAMPAIGN_SHARDS}; got {value}")
                            })?,
                    )
                    .is_some(),
                "--seconds" => seconds
                    .replace(
                        value
                            .parse::<u64>()
                            .ok()
                            .filter(|seconds| (1..=MAX_CAMPAIGN_SECONDS).contains(seconds))
                            .ok_or_else(|| {
                                format!(
                                    "--seconds must be between 1 and {MAX_CAMPAIGN_SECONDS}; got {value}"
                                )
                            })?,
                    )
                    .is_some(),
                "--toolchain" => {
                    if value.is_empty()
                        || !value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                        })
                    {
                        return Err(format!("--toolchain is not a toolchain name: {value}"));
                    }
                    toolchain.replace(value.clone()).is_some()
                }
                _ => {
                    return Err(format!(
                        "unknown fuzz-campaign argument {flag}; {FUZZ_CAMPAIGN_USAGE}"
                    ));
                }
            };
            if duplicate {
                return Err(format!("{flag} is given more than once"));
            }
            index += 2;
        }
        Ok(Self {
            shard: shard.ok_or_else(|| format!("--shard is required; {FUZZ_CAMPAIGN_USAGE}"))?,
            seconds: seconds
                .ok_or_else(|| format!("--seconds is required; {FUZZ_CAMPAIGN_USAGE}"))?,
            toolchain: toolchain.unwrap_or_else(|| FUZZ_TOOLCHAIN.to_owned()),
        })
    }
}

/// Runs one scheduled shard of the fuzz campaign.
///
/// Every target on the shard runs even after another fails, so one crash
/// cannot hide the rest; the shard fails if any target failed or reported no
/// executed inputs. Each target starts from its committed corpus plus seeds
/// derived from the canonical core fixtures. Logs, evidence, reproducers and
/// newly discovered units go under `target/fuzz-campaign/`; the committed
/// corpora are passed read-only and never modified.
pub(crate) fn fuzz_campaign(arguments: &[String]) -> Result<(), String> {
    let options = CampaignOptions::parse(arguments)?;
    let root = root();
    let output = root.join(CAMPAIGN_OUTPUT);
    let logs = output.join("logs");
    fs::create_dir_all(&logs)
        .map_err(|error| format!("could not create {}: {error}", logs.display()))?;
    let corpus = FixtureCorpus::load(&root.join(CORE_FIXTURES))?;
    let mut outcomes = Vec::new();
    for target in shard_targets(options.shard) {
        println!(
            "fuzz campaign: {} for {} seconds with {}",
            target.name, options.seconds, options.toolchain
        );
        let outcome = run_campaign_target(&root, &output, &corpus, target, &options);
        write_target_evidence(&logs, &outcome)?;
        println!("fuzz campaign: {} {}", outcome.name, outcome.verdict);
        outcomes.push(outcome);
    }
    let summary = shard_summary(options.shard, &outcomes);
    let summary_path = logs.join(format!("shard-{}-summary.txt", options.shard));
    fs::write(&summary_path, &summary)
        .map_err(|error| format!("could not write {}: {error}", summary_path.display()))?;
    print!("{summary}");
    let failed = outcomes
        .iter()
        .filter(|outcome| !matches!(outcome.verdict, FuzzVerdict::Executed { .. }))
        .collect::<Vec<_>>();
    for outcome in &failed {
        println!("::error::{} {}", outcome.name, outcome.verdict);
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "fuzz shard {} failed: {}",
            options.shard,
            failed
                .iter()
                .map(|outcome| outcome.name)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// How one target's run ended.
#[derive(Clone, Debug, Eq, PartialEq)]
enum FuzzVerdict {
    /// The run finished cleanly and libFuzzer reported executed inputs.
    Executed { executions: u64 },
    /// The fuzzer, a sanitizer or the target failed, or the run never started.
    Failed {
        reason: String,
        reproducers: Vec<String>,
    },
    /// The run finished cleanly but reported no executed inputs.
    NoExecutionEvidence,
}

impl std::fmt::Display for FuzzVerdict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Executed { executions } => write!(formatter, "executed {executions} inputs"),
            Self::Failed {
                reason,
                reproducers,
            } if reproducers.is_empty() => write!(formatter, "failed: {reason}"),
            Self::Failed {
                reason,
                reproducers,
            } => write!(
                formatter,
                "failed: {reason}; reproducers: {}",
                reproducers.join(", ")
            ),
            Self::NoExecutionEvidence => {
                write!(formatter, "produced no nonzero execution evidence")
            }
        }
    }
}

/// Classifies one run from its exit status and combined log.
///
/// A failure is decided before execution evidence is read: a crashing run
/// still prints libFuzzer's final statistics with a nonzero execution count,
/// so that count must never make a failed run pass.
fn classify_fuzz_run(exited_cleanly: bool, exit: &str, log: &str) -> FuzzVerdict {
    let reproducers = written_test_units(log);
    let marker = log
        .lines()
        .find(|line| FAILURE_MARKERS.iter().any(|marker| line.contains(marker)));
    if !exited_cleanly || marker.is_some() || !reproducers.is_empty() {
        let reason = marker.map_or_else(
            || format!("cargo fuzz {exit}"),
            |line| format!("{} (cargo fuzz {exit})", line.trim()),
        );
        return FuzzVerdict::Failed {
            reason,
            reproducers,
        };
    }
    match executed_units(log) {
        Some(executions) if executions > 0 => FuzzVerdict::Executed { executions },
        _ => FuzzVerdict::NoExecutionEvidence,
    }
}

/// The last `stat::number_of_executed_units` libFuzzer printed, if it parses.
fn executed_units(log: &str) -> Option<u64> {
    log.lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix("stat::number_of_executed_units:"))
        .and_then(|value| value.trim().parse().ok())
}

/// Paths libFuzzer reported writing a crashing, leaking, timed-out or
/// out-of-memory unit to.
fn written_test_units(log: &str) -> Vec<String> {
    log.lines()
        .filter_map(|line| {
            line.split_once("Test unit written to ")
                .map(|(_, path)| path.trim().to_owned())
        })
        .collect()
}

#[derive(Default)]
struct SeedSummary {
    sha256: String,
    committed: usize,
    fixtures: usize,
}

struct TargetOutcome {
    name: &'static str,
    verdict: FuzzVerdict,
    seeds: SeedSummary,
    exit: String,
    duration_seconds: u64,
}

struct TargetRun {
    exited_cleanly: bool,
    exit: String,
    log: String,
    seeds: SeedSummary,
}

fn run_campaign_target(
    root: &Path,
    output: &Path,
    corpus: &FixtureCorpus,
    target: &CampaignTarget,
    options: &CampaignOptions,
) -> TargetOutcome {
    let started = Instant::now();
    let run = fuzz_one_target(root, output, corpus, target, options);
    let duration_seconds = started.elapsed().as_secs();
    match run {
        Ok(run) => TargetOutcome {
            name: target.name,
            verdict: classify_fuzz_run(run.exited_cleanly, &run.exit, &run.log),
            seeds: run.seeds,
            exit: run.exit,
            duration_seconds,
        },
        Err(reason) => TargetOutcome {
            name: target.name,
            verdict: FuzzVerdict::Failed {
                reason,
                reproducers: Vec::new(),
            },
            seeds: SeedSummary::default(),
            exit: "not started".to_owned(),
            duration_seconds,
        },
    }
}

fn fuzz_one_target(
    root: &Path,
    output: &Path,
    corpus: &FixtureCorpus,
    target: &CampaignTarget,
    options: &CampaignOptions,
) -> Result<TargetRun, String> {
    let fuzz_dir = root.join(target.fuzz_dir);
    let committed = fuzz_dir.join("corpus").join(target.name);
    let committed_files = read_seed_directory(&committed)?;
    let seeds = fixture_seeds(corpus, target.seeds)?;
    let seed_dir = output.join("seeds").join(target.name);
    replace_directory(&seed_dir)?;
    for (name, bytes) in &seeds {
        let path = seed_dir.join(name);
        fs::write(&path, bytes)
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    }
    let summary = SeedSummary {
        sha256: seed_digest(&committed_files, &seeds),
        committed: committed_files.len(),
        fixtures: seeds.len(),
    };
    let discovered = output.join("corpus").join(target.name);
    fs::create_dir_all(&discovered)
        .map_err(|error| format!("could not create {}: {error}", discovered.display()))?;
    let artifacts = output.join("artifacts").join(target.name);
    replace_directory(&artifacts)?;
    let log_path = output.join("logs").join(format!("{}.log", target.name));

    // libFuzzer writes new units into the first corpus directory only.
    let mut command = Command::new("cargo");
    command
        .arg(format!("+{}", options.toolchain))
        .args(["fuzz", "run", "--fuzz-dir"])
        .arg(fuzz_dir)
        .arg(target.name)
        .arg(discovered)
        .arg(committed)
        .arg(seed_dir)
        .arg("--")
        .arg(format!("-max_total_time={}", options.seconds))
        .arg("-print_final_stats=1")
        .arg(format!("-artifact_prefix={}/", artifacts.display()))
        .current_dir(root);
    let status = run_logged(command, &log_path)?;
    let log = String::from_utf8_lossy(
        &fs::read(&log_path)
            .map_err(|error| format!("could not read {}: {error}", log_path.display()))?,
    )
    .into_owned();
    Ok(TargetRun {
        exited_cleanly: status.success(),
        exit: status.to_string(),
        log,
        seeds: summary,
    })
}

/// Runs `command`, copying its standard output and error into `log` while
/// still streaming both to this process.
fn run_logged(mut command: Command, log: &Path) -> Result<ExitStatus, String> {
    let file = fs::File::create(log)
        .map_err(|error| format!("could not create {}: {error}", log.display()))?;
    let sink = Arc::new(Mutex::new(file));
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start cargo fuzz: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or("cargo fuzz standard output was not captured")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("cargo fuzz standard error was not captured")?;
    let copiers = [
        copy_lines(stdout, Arc::clone(&sink), false),
        copy_lines(stderr, Arc::clone(&sink), true),
    ];
    let status = child
        .wait()
        .map_err(|error| format!("could not wait for cargo fuzz: {error}"))?;
    for copier in copiers {
        copier
            .join()
            .map_err(|_| "a cargo fuzz log copier panicked".to_owned())??;
    }
    Ok(status)
}

fn copy_lines(
    stream: impl Read + Send + 'static,
    sink: Arc<Mutex<fs::File>>,
    to_stderr: bool,
) -> thread::JoinHandle<Result<(), String>> {
    thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = reader
                .read_until(b'\n', &mut line)
                .map_err(|error| format!("could not read cargo fuzz output: {error}"))?;
            if read == 0 {
                return Ok(());
            }
            sink.lock()
                .map_err(|_| "the cargo fuzz log is poisoned".to_owned())?
                .write_all(&line)
                .map_err(|error| format!("could not write the cargo fuzz log: {error}"))?;
            let echoed = if to_stderr {
                std::io::stderr().write_all(&line)
            } else {
                std::io::stdout().write_all(&line)
            };
            echoed.map_err(|error| format!("could not echo cargo fuzz output: {error}"))?;
        }
    })
}

fn replace_directory(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_dir_all(path)
            .map_err(|error| format!("could not clear {}: {error}", path.display()))?;
    }
    fs::create_dir_all(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))
}

fn read_seed_directory(directory: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("could not read {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| {
            format!(
                "could not read an entry of {}: {error}",
                directory.display()
            )
        })?;
        let path = entry.path();
        if path.is_file() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let bytes = fs::read(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?;
            files.push((name, bytes));
        }
    }
    files.sort();
    Ok(files)
}

/// Digest over every starting input, so evidence names exactly what a run was
/// seeded with.
fn seed_digest(committed: &[(String, Vec<u8>)], fixtures: &BTreeMap<String, Vec<u8>>) -> String {
    let mut digest = Sha256::new();
    let inputs = committed
        .iter()
        .map(|(name, bytes)| ("corpus", name.as_str(), bytes.as_slice()))
        .chain(
            fixtures
                .iter()
                .map(|(name, bytes)| ("fixtures", name.as_str(), bytes.as_slice())),
        );
    for (origin, name, bytes) in inputs {
        digest.update(origin.as_bytes());
        digest.update([0]);
        digest.update(name.as_bytes());
        digest.update([0]);
        digest.update(bytes);
        digest.update([0xff]);
    }
    hex::encode(digest.finalize())
}

/// Canonical core fixture files, grouped by case.
struct FixtureCorpus {
    /// Case path relative to the corpus root, without its role suffix.
    cases: BTreeMap<String, BTreeMap<FixtureRole, Vec<u8>>>,
}

impl FixtureCorpus {
    fn load(root: &Path) -> Result<Self, String> {
        let mut files = Vec::new();
        collect_fixture_files(root, &mut files)?;
        let mut cases: BTreeMap<String, BTreeMap<FixtureRole, Vec<u8>>> = BTreeMap::new();
        for path in files {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| format!("fixture escapes the corpus: {}", path.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            let Some((case, role)) = FixtureRole::ALL.iter().find_map(|role| {
                relative
                    .strip_suffix(role.suffix())
                    .map(|case| (case.to_owned(), *role))
            }) else {
                return Err(format!("core fixture has no known role: {relative}"));
            };
            let bytes =
                fs::read(&path).map_err(|error| format!("could not read {relative}: {error}"))?;
            cases.entry(case).or_default().insert(role, bytes);
        }
        if cases.is_empty() {
            return Err(format!("no core fixtures under {}", root.display()));
        }
        Ok(Self { cases })
    }
}

fn collect_fixture_files(directory: &Path, found: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("could not read {}: {error}", directory.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!(
                "could not read an entry of {}: {error}",
                directory.display()
            )
        })?;
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_fixture_files(&path, found)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "cbor")
        {
            found.push(path);
        }
    }
    Ok(())
}

/// Seeds for one target, named by content digest so the set is deterministic
/// and duplicate-free.
fn fixture_seeds(
    corpus: &FixtureCorpus,
    seeds: FixtureSeeds,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut derived = Vec::new();
    match seeds {
        FixtureSeeds::Roles(roles) => {
            for files in corpus.cases.values() {
                derived.extend(roles.iter().filter_map(|role| files.get(role)).cloned());
            }
        }
        FixtureSeeds::ProofEvidence => {
            let limits = auths_model::VerifierLimits::hard();
            for files in corpus.cases.values() {
                let Some(proof) = files.get(&FixtureRole::Proof) else {
                    continue;
                };
                if let Ok(bundle) = auths_codec::decode_bundle(proof, &limits) {
                    derived.extend(
                        bundle
                            .evidence()
                            .iter()
                            .map(|evidence| evidence.bytes().to_vec()),
                    );
                }
            }
        }
        FixtureSeeds::FramedAbiTuples => {
            let configuration = portable_abi_configuration()?;
            for files in corpus.cases.values() {
                let (Some(proof), Some(action), Some(context)) = (
                    files.get(&FixtureRole::Proof),
                    files.get(&FixtureRole::Action),
                    files.get(&FixtureRole::Context),
                ) else {
                    continue;
                };
                derived.push(framed_abi_tuple(
                    proof,
                    action,
                    &rebound_context(context, configuration),
                )?);
            }
        }
    }
    Ok(derived
        .into_iter()
        .filter(|seed| !seed.is_empty())
        .map(|seed| (hex::encode(Sha256::digest(&seed)), seed))
        .collect())
}

/// The registry configuration `target_portable_abi` verifies under: the same
/// principal methods and signature suites the target constructs.
fn portable_abi_configuration() -> Result<auths_model::VerifierConfigurationId, String> {
    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(|error| error.to_string())?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn auths_ports::PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .map_err(|error| error.to_string())?;
    Ok(registries.configuration_id())
}

/// Re-binds a decodable context to `configuration`; a context that does not
/// decode is kept as it is, so its decode failure remains a seed.
fn rebound_context(context: &[u8], configuration: auths_model::VerifierConfigurationId) -> Vec<u8> {
    auths_codec::decode_verifier_context(context)
        .ok()
        .and_then(|decoded| decoded.with_configuration(configuration).ok())
        .and_then(|rebound| auths_codec::encode_verifier_context(&rebound).ok())
        .unwrap_or_else(|| context.to_vec())
}

/// The `APF1` frame `target_portable_abi` parses: a magic tag, three
/// big-endian `u32` lengths, then the proof, action and context bytes.
fn framed_abi_tuple(proof: &[u8], action: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
    let mut framed = Vec::with_capacity(16 + proof.len() + action.len() + context.len());
    framed.extend_from_slice(b"APF1");
    for part in [proof, action, context] {
        let length = u32::try_from(part.len())
            .map_err(|_| "a fixture part exceeds the APF1 length field".to_owned())?;
        framed.extend_from_slice(&length.to_be_bytes());
    }
    for part in [proof, action, context] {
        framed.extend_from_slice(part);
    }
    Ok(framed)
}

fn write_target_evidence(logs: &Path, outcome: &TargetOutcome) -> Result<(), String> {
    let (status, executions, reproducers) = match &outcome.verdict {
        FuzzVerdict::Executed { executions } => ("executed", executions.to_string(), String::new()),
        FuzzVerdict::Failed { reproducers, .. } => {
            ("failed", "unknown".to_owned(), reproducers.join(" "))
        }
        FuzzVerdict::NoExecutionEvidence => {
            ("no-execution-evidence", "0".to_owned(), String::new())
        }
    };
    let evidence = format!(
        "target={}\nstatus={status}\nverdict={}\nseed_sha256={}\ncommitted_seeds={}\nfixture_seeds={}\nduration_seconds={}\nexecutions={executions}\nexit={}\nartifacts={CAMPAIGN_OUTPUT}/artifacts/{}/\nreproducers={reproducers}\n",
        outcome.name,
        outcome.verdict,
        outcome.seeds.sha256,
        outcome.seeds.committed,
        outcome.seeds.fixtures,
        outcome.duration_seconds,
        outcome.exit,
        outcome.name,
    );
    let path = logs.join(format!("{}-evidence.txt", outcome.name));
    fs::write(&path, evidence)
        .map_err(|error| format!("could not write {}: {error}", path.display()))
}

fn shard_summary(shard: usize, outcomes: &[TargetOutcome]) -> String {
    let executions = outcomes
        .iter()
        .map(|outcome| match outcome.verdict {
            FuzzVerdict::Executed { executions } => executions,
            _ => 0,
        })
        .fold(0_u64, u64::saturating_add);
    let mut summary = format!(
        "Shard {shard} executed {executions} inputs across {} targets.\n",
        outcomes.len()
    );
    for outcome in outcomes {
        let _ = writeln!(summary, "{}: {}", outcome.name, outcome.verdict);
    }
    summary
}

pub(crate) fn fuzz_smoke() -> Result<(), String> {
    fuzz_inventory()?;
    cargo(&["check", "--manifest-path", "core/fuzz/Cargo.toml", "--bins"])?;
    for target in FUZZ_TARGETS {
        let corpus = format!("core/fuzz/corpus/{target}");
        cargo(&[
            "run",
            "--manifest-path",
            "core/fuzz/Cargo.toml",
            "--bin",
            target,
            "--",
            &corpus,
            "-runs=8",
            "-max_len=4096",
            "-timeout=5",
        ])?;
    }
    for target in PRODUCT_FUZZ_TARGETS {
        let corpus = format!("product/policy/auths-bounded-policy/fuzz/corpus/{target}");
        cargo(&[
            "run",
            "--manifest-path",
            "product/policy/auths-bounded-policy/fuzz/Cargo.toml",
            "--bin",
            target,
            "--",
            &corpus,
            "-runs=8",
            "-max_len=4096",
            "-timeout=5",
        ])?;
    }
    Ok(())
}

/// Checks that every fuzz target is declared, seeded and scheduled by a
/// campaign the pinned tools can run.
pub(crate) fn fuzz_inventory() -> Result<(), String> {
    let manifest = fs::read_to_string(root().join("core/fuzz/Cargo.toml"))
        .map_err(|error| format!("could not read fuzz manifest: {error}"))?;
    let manifest_targets: BTreeSet<_> = manifest
        .lines()
        .filter_map(|line| line.trim().strip_prefix("name = \""))
        .filter_map(|value| value.strip_suffix('"'))
        .filter(|name| name.starts_with("target_"))
        .collect();
    let expected: BTreeSet<_> = FUZZ_TARGETS.into_iter().collect();
    if manifest_targets != expected {
        return Err(format!(
            "fuzz manifest and authoritative inventory differ: manifest={manifest_targets:?}, expected={expected:?}"
        ));
    }

    let product_manifest =
        fs::read_to_string(root().join("product/policy/auths-bounded-policy/fuzz/Cargo.toml"))
            .map_err(|error| format!("could not read bounded-policy fuzz manifest: {error}"))?;
    let product_manifest_targets: BTreeSet<_> = product_manifest
        .lines()
        .filter_map(|line| line.trim().strip_prefix("name = \""))
        .filter_map(|value| value.strip_suffix('"'))
        .filter(|name| name.starts_with("target_"))
        .collect();
    let expected_product: BTreeSet<_> = PRODUCT_FUZZ_TARGETS.into_iter().collect();
    if product_manifest_targets != expected_product {
        return Err(format!(
            "bounded-policy fuzz manifest and inventory differ: manifest={product_manifest_targets:?}, expected={expected_product:?}"
        ));
    }
    for (path, source) in [
        ("core/fuzz/Cargo.toml", &manifest),
        (
            "product/policy/auths-bounded-policy/fuzz/Cargo.toml",
            &product_manifest,
        ),
    ] {
        require_cargo_fuzz_manifest(path, source)?;
    }

    let scheduled = CAMPAIGN_TARGETS
        .iter()
        .map(|target| target.name)
        .collect::<BTreeSet<_>>();
    let inventory = FUZZ_TARGETS
        .into_iter()
        .chain(PRODUCT_FUZZ_TARGETS)
        .collect::<BTreeSet<_>>();
    if scheduled.len() != CAMPAIGN_TARGETS.len() || scheduled != inventory {
        return Err(format!(
            "scheduled fuzz campaign and inventory differ: scheduled={scheduled:?}, inventory={inventory:?}"
        ));
    }
    for target in &CAMPAIGN_TARGETS {
        let expected_dir = if FUZZ_TARGETS.contains(&target.name) {
            CORE_FUZZ_DIR
        } else {
            BOUNDED_POLICY_FUZZ_DIR
        };
        if target.fuzz_dir != expected_dir {
            return Err(format!(
                "scheduled fuzz target {} names fuzz directory {} instead of {expected_dir}",
                target.name, target.fuzz_dir
            ));
        }
        let corpus = root()
            .join(target.fuzz_dir)
            .join("corpus")
            .join(target.name);
        if !corpus.is_dir() {
            return Err(format!(
                "missing structured seed directory {}",
                corpus.display()
            ));
        }
    }

    let workflow = fs::read_to_string(root().join(".github/workflows/fuzz.yml"))
        .map_err(|error| format!("could not read fuzz workflow: {error}"))?;
    validate_fuzz_workflow(&workflow)?;
    println!(
        "all {} fuzz targets are synchronized",
        FUZZ_TARGETS.len() + PRODUCT_FUZZ_TARGETS.len()
    );
    Ok(())
}

fn require_cargo_fuzz_manifest(path: &str, source: &str) -> Result<(), String> {
    let manifest: toml::Value =
        toml::from_str(source).map_err(|error| format!("invalid {path}: {error}"))?;
    let marked = manifest
        .get("package")
        .and_then(|package| package.get("metadata"))
        .and_then(|metadata| metadata.get("cargo-fuzz"))
        .and_then(toml::Value::as_bool);
    if marked == Some(true) {
        Ok(())
    } else {
        Err(format!(
            "{path} lacks `[package.metadata] cargo-fuzz = true`, so cargo fuzz refuses it"
        ))
    }
}

/// The Fuzz workflow must run this campaign on every shard with the pinned
/// toolchain and cargo-fuzz release.
fn validate_fuzz_workflow(workflow: &str) -> Result<(), String> {
    let shards = (0..CAMPAIGN_SHARDS)
        .map(|shard| shard.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    for required in [
        format!("shard: [{shards}]"),
        "cargo xtask fuzz-campaign --shard \"$AUTHS_FUZZ_SHARD\" --seconds \"$AUTHS_FUZZ_SECONDS\""
            .to_owned(),
        format!("toolchain: {FUZZ_TOOLCHAIN}"),
        format!("cargo install cargo-fuzz --version {CARGO_FUZZ_VERSION} --locked"),
    ] {
        if !workflow.contains(&required) {
            return Err(format!(
                "scheduled fuzz workflow does not run the pinned campaign: missing `{required}`"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from `cargo fuzz run` (cargo-fuzz 0.13.1, libfuzzer-sys
    /// 0.4.13) on `target_bounded_policy` with `-max_total_time=3`. Paths are
    /// shortened, trailing blanks trimmed and most REDUCE lines elided.
    const CAPTURED_RUN: &str = "
   Compiling libfuzzer-sys v0.4.13
   Compiling auths-bounded-policy-fuzz v1.0.0-rc.1 (product/policy/auths-bounded-policy/fuzz)
    Finished `release` profile [optimized + debuginfo] target(s) in 7.09s
    Finished `release` profile [optimized + debuginfo] target(s) in 0.14s
     Running `target/aarch64-apple-darwin/release/target_bounded_policy -artifact_prefix=product/policy/auths-bounded-policy/fuzz/artifacts/target_bounded_policy/ -max_total_time=3 -print_final_stats=1 -artifact_prefix=target/fuzz-campaign/artifacts/target_bounded_policy/ target/fuzz-campaign/corpus/target_bounded_policy`
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3275662128
INFO: Loaded 1 modules   (2124 inline 8-bit counters): 2124 [0x1030a24e0, 0x1030a2d2c),
INFO: Loaded 1 PC tables (2124 PCs): 2124 [0x1030a2d30,0x1030ab1f0),
INFO:        1 files found in target/fuzz-campaign/corpus/target_bounded_policy
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: seed corpus: files: 1 min: 17b max: 17b total: 17b rss: 36Mb
#2\tINITED cov: 40 ft: 40 corp: 1/17b exec/s: 0 rss: 36Mb
#2097152\tpulse  cov: 65 ft: 220 corp: 53/950b lim: 4096 exec/s: 699050 rss: 286Mb
#2346188\tREDUCE cov: 65 ft: 221 corp: 54/1078b lim: 4096 exec/s: 782062 rss: 315Mb L: 128/129 MS: 1 InsertRepeatedBytes-
#2578273\tDONE   cov: 65 ft: 221 corp: 54/1078b lim: 4096 exec/s: 644568 rss: 342Mb
###### Recommended dictionary. ######
\"\\000\\000\\000\\000\" # Uses: 37640
###### End of recommended dictionary. ######
Done 2578273 runs in 4 second(s)
stat::number_of_executed_units: 2578273
stat::average_exec_per_sec:     644568
stat::new_units_added:          260
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              342
";

    /// Captured from `cargo fuzz run` (cargo-fuzz 0.13.1, libfuzzer-sys
    /// 0.4.13) on a probe target that panics on its seed. Paths are shortened
    /// and most stack frames and the closing separator elided.
    const CAPTURED_CRASH: &str = "\
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3344904542
INFO:        1 files found in target/fuzz-campaign/corpus/target_probe
INFO: seed corpus: files: 1 min: 5b max: 5b total: 5b rss: 35Mb

thread '<unnamed>' (28381401) panicked at fuzz_targets/target_probe.rs:6:9:
probe crash
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
==86859== ERROR: libFuzzer: deadly signal
    #0 0x00010579b59c in __sanitizer_print_stack_trace+0x28 (librustc-nightly_rt.asan.dylib:arm64+0x8759c)
    #18 0x000104f9f320 in LLVMFuzzerTestOneInput+0x16c (target_probe:arm64+0x100003320)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 0 ; base unit: 0000000000000000000000000000000000000000
0x61,0x75,0x74,0x68,0x73,
auths
artifact_prefix='target/fuzz-campaign/artifacts/target_probe/'; Test unit written to target/fuzz-campaign/artifacts/target_probe/crash-4379c00b35e8cd0eb7e4c75a4013a0a5500e4d21
Base64: YXV0aHM=
stat::number_of_executed_units: 2
stat::average_exec_per_sec:     0
stat::new_units_added:          0
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              37

Error: Fuzz target exited with exit status: 77
";

    #[test]
    fn captured_run_reports_its_final_execution_count() {
        assert_eq!(executed_units(CAPTURED_RUN), Some(2_578_273));
        assert_eq!(
            classify_fuzz_run(true, "exit status: 0", CAPTURED_RUN),
            FuzzVerdict::Executed {
                executions: 2_578_273
            }
        );
    }

    #[test]
    fn crash_is_decided_before_execution_evidence() {
        // The crashing run still reports executed inputs.
        assert_eq!(executed_units(CAPTURED_CRASH), Some(2));
        let reproducer = "target/fuzz-campaign/artifacts/target_probe/crash-4379c00b35e8cd0eb7e4c75a4013a0a5500e4d21";
        for exited_cleanly in [false, true] {
            let FuzzVerdict::Failed {
                reason,
                reproducers,
            } = classify_fuzz_run(exited_cleanly, "exit status: 1", CAPTURED_CRASH)
            else {
                panic!("a crash must never pass on its execution count");
            };
            assert!(
                reason.contains("ERROR: libFuzzer: deadly signal"),
                "{reason}"
            );
            assert_eq!(reproducers, [reproducer]);
        }
    }

    #[test]
    fn a_failed_invocation_or_missing_count_is_not_execution_evidence() {
        let rejected = "error: unexpected argument '--manifest-path' found\n";
        assert!(matches!(
            classify_fuzz_run(false, "exit status: 2", rejected),
            FuzzVerdict::Failed { .. }
        ));
        assert_eq!(
            classify_fuzz_run(true, "exit status: 0", "Done 0 runs in 0 second(s)\n"),
            FuzzVerdict::NoExecutionEvidence
        );
        assert_eq!(
            classify_fuzz_run(
                true,
                "exit status: 0",
                "stat::number_of_executed_units: 0\n"
            ),
            FuzzVerdict::NoExecutionEvidence
        );
        assert_eq!(
            classify_fuzz_run(
                true,
                "exit status: 0",
                "stat::number_of_executed_units: many\n"
            ),
            FuzzVerdict::NoExecutionEvidence
        );
    }

    #[test]
    fn shards_keep_the_scheduled_split() {
        let names = |shard| {
            shard_targets(shard)
                .map(|target| target.name)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(0),
            [
                "target_codec",
                "target_model_state",
                "target_registry_handlers",
                "target_portable_abi"
            ]
        );
        assert_eq!(
            names(1),
            [
                "target_portable_codecs",
                "target_composition",
                "target_principal_parsers",
                "target_bounded_policy"
            ]
        );
        assert_eq!(shard_targets(CAMPAIGN_SHARDS).count(), 0);
    }

    #[test]
    fn campaign_options_are_bounded() {
        let parse = |arguments: &[&str]| {
            CampaignOptions::parse(
                &arguments
                    .iter()
                    .map(|argument| (*argument).to_owned())
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(
            parse(&["--shard", "1", "--seconds", "600"]).expect("valid options"),
            CampaignOptions {
                shard: 1,
                seconds: 600,
                toolchain: FUZZ_TOOLCHAIN.to_owned()
            }
        );
        assert_eq!(
            parse(&["--seconds", "5", "--shard", "0", "--toolchain", "nightly"])
                .expect("local toolchain")
                .toolchain,
            "nightly"
        );
        for invalid in [
            &["--shard", "2", "--seconds", "5"][..],
            &["--shard", "0", "--seconds", "0"],
            &["--shard", "0", "--seconds", "3601"],
            &["--shard", "0", "--seconds", "soon"],
            &["--shard", "0"],
            &["--seconds", "5"],
            &["--shard", "0", "--seconds", "5", "--shard", "1"],
            &["--shard", "0", "--seconds", "5", "--toolchain", "+nightly"],
            &["--shard", "0", "--seconds", "5", "--jobs", "4"],
            &["--shard"],
        ] {
            assert!(parse(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    /// Parses a seed exactly as `target_portable_abi` frames its input.
    fn split_framed(data: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
        if data.get(..4)? != b"APF1" {
            return None;
        }
        let length = |range: std::ops::Range<usize>| -> Option<usize> {
            usize::try_from(u32::from_be_bytes(data.get(range)?.try_into().ok()?)).ok()
        };
        let proof_end = 16_usize.checked_add(length(4..8)?)?;
        let action_end = proof_end.checked_add(length(8..12)?)?;
        let context_end = action_end.checked_add(length(12..16)?)?;
        (context_end == data.len()).then(|| {
            (
                &data[16..proof_end],
                &data[proof_end..action_end],
                &data[action_end..context_end],
            )
        })
    }

    #[test]
    fn every_target_is_seeded_from_the_core_fixture_corpus() {
        let corpus = FixtureCorpus::load(&root().join(CORE_FIXTURES)).expect("core fixtures");
        for target in &CAMPAIGN_TARGETS {
            let seeds = fixture_seeds(&corpus, target.seeds).expect("fixture seeds");
            assert!(!seeds.is_empty(), "{} has no fixture seeds", target.name);
            assert_eq!(
                seeds,
                fixture_seeds(&corpus, target.seeds).expect("repeatable seeds"),
                "{} seeds are not deterministic",
                target.name
            );
        }

        let configuration = portable_abi_configuration().expect("fuzz target registries");
        let framed = fixture_seeds(&corpus, FixtureSeeds::FramedAbiTuples).expect("framed");
        let mut rebound = 0_usize;
        for seed in framed.values() {
            let (_, _, context) =
                split_framed(seed).expect("every framed seed parses as the target frames it");
            if let Ok(decoded) = auths_codec::decode_verifier_context(context) {
                assert_eq!(decoded.configuration(), configuration);
                rebound += 1;
            }
        }
        assert!(rebound > 0, "no framed context reaches the verifier stages");
    }

    #[test]
    fn portable_abi_seeds_use_the_fuzz_target_registries() {
        let source =
            fs::read_to_string(root().join("core/fuzz/fuzz_targets/target_portable_abi.rs"))
                .expect("fuzz target source");
        for construction in [
            "auths_raw_key::RawKeyMethod::new()",
            "auths_did_key::DidKeyMethod::new()",
            "auths_did_keri::DidKeriMethod::new()",
            "auths_signature::Ed25519Suite::new()",
            "auths_signature::P256Sha256Suite::new()",
            "[&dyn PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri]",
            "[&dyn SignatureSuite; 2] = [&ed25519, &p256]",
        ] {
            assert!(
                source.contains(construction),
                "target_portable_abi no longer builds `{construction}`; update portable_abi_configuration"
            );
        }
    }

    #[test]
    fn repository_fuzz_schedule_is_runnable() {
        fuzz_inventory().expect("fuzz targets are declared, seeded and scheduled");
    }

    #[test]
    fn a_workflow_without_the_campaign_is_rejected() {
        let workflow =
            fs::read_to_string(root().join(".github/workflows/fuzz.yml")).expect("fuzz workflow");
        validate_fuzz_workflow(&workflow).expect("repository workflow");
        let error = validate_fuzz_workflow(&workflow.replace(
            "cargo xtask fuzz-campaign",
            "cargo fuzz --manifest-path \"$manifest\" run",
        ))
        .expect_err("a workflow that bypasses the campaign must fail");
        assert!(error.contains("fuzz-campaign"), "{error}");
        assert!(
            require_cargo_fuzz_manifest("fuzz/Cargo.toml", "[package]\nname = \"fuzz\"\n").is_err()
        );
    }
}
