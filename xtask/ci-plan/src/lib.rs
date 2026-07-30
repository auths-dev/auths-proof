#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env, fs,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

const DEFAULT_MANIFEST: &str = ".github/ci/phase-ownership.toml";
const DEFAULT_BASELINE: &str = ".github/ci/baseline.json";
const PLAN_SCHEMA: &str = "auths-proof-ci-plan/v1";
pub const SOURCE_CLOSURE_SCHEMA: &str = "auths-proof-translation-source-closure/v2";

#[derive(Debug)]
pub enum Command {
    Check(Options),
    Plan(Options),
    FormalSourceClosure {
        update: bool,
        root: PathBuf,
        output: PathBuf,
    },
}

#[derive(Debug)]
pub struct Options {
    root: PathBuf,
    manifest: PathBuf,
    base: Option<String>,
    head: Option<String>,
    event: String,
    workflow: String,
    output: PathBuf,
    github_output: Option<PathBuf>,
    summary: Option<PathBuf>,
}

impl Command {
    pub fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut arguments = arguments.into_iter();
        let command = arguments.next().unwrap_or_else(|| "help".to_owned());
        if command == "help" || command == "--help" || command == "-h" {
            return Err(usage().to_owned());
        }
        if command == "formal-source-closure" {
            let action = arguments.next().ok_or_else(|| usage().to_owned())?;
            if action != "check" && action != "update" {
                return Err(format!(
                    "formal-source-closure action must be check or update; {}",
                    usage()
                ));
            }
            let root =
                env::current_dir().map_err(|error| format!("could not resolve cwd: {error}"))?;
            let mut selected_root = root.clone();
            let mut output = root.join("target/formal/source-closure.expected.json");
            let values: Vec<_> = arguments.collect();
            let mut index = 0;
            while index < values.len() {
                let flag = values[index].as_str();
                let value = values
                    .get(index + 1)
                    .ok_or_else(|| format!("{flag} requires a value"))?;
                match flag {
                    "--root" => selected_root = PathBuf::from(value),
                    "--output" => output = PathBuf::from(value),
                    _ => return Err(format!("unknown argument {flag}; {}", usage())),
                }
                index += 2;
            }
            if output.is_relative() {
                output = selected_root.join(output);
            }
            return Ok(Self::FormalSourceClosure {
                update: action == "update",
                root: selected_root,
                output,
            });
        }
        if command != "check" && command != "plan" {
            return Err(format!("unknown command {command}; {}", usage()));
        }

        let root = env::current_dir().map_err(|error| format!("could not resolve cwd: {error}"))?;
        let mut options = Options {
            manifest: root.join(DEFAULT_MANIFEST),
            output: root.join("target/ci/plan.json"),
            base: env::var("AUTHS_CI_BASE_SHA").ok(),
            head: env::var("AUTHS_CI_HEAD_SHA").ok(),
            event: env::var("GITHUB_EVENT_NAME").unwrap_or_else(|_| "pull_request".to_owned()),
            workflow: "ci".to_owned(),
            github_output: env::var_os("GITHUB_OUTPUT").map(PathBuf::from),
            summary: env::var_os("GITHUB_STEP_SUMMARY").map(PathBuf::from),
            root,
        };

        let values: Vec<_> = arguments.collect();
        let mut index = 0;
        while index < values.len() {
            let flag = values[index].as_str();
            let value = values
                .get(index + 1)
                .ok_or_else(|| format!("{flag} requires a value"))?;
            match flag {
                "--root" => options.root = PathBuf::from(value),
                "--manifest" => options.manifest = PathBuf::from(value),
                "--base" => options.base = Some(value.clone()),
                "--head" => options.head = Some(value.clone()),
                "--event" => options.event.clone_from(value),
                "--workflow" => options.workflow.clone_from(value),
                "--output" => options.output = PathBuf::from(value),
                "--github-output" => options.github_output = Some(PathBuf::from(value)),
                "--summary" => options.summary = Some(PathBuf::from(value)),
                _ => return Err(format!("unknown argument {flag}; {}", usage())),
            }
            index += 2;
        }

        if options.manifest.is_relative() {
            options.manifest = options.root.join(&options.manifest);
        }
        if options.output.is_relative() {
            options.output = options.root.join(&options.output);
        }
        options.github_output = options.github_output.map(|path| {
            if path.is_relative() {
                options.root.join(path)
            } else {
                path
            }
        });
        options.summary = options.summary.map(|path| {
            if path.is_relative() {
                options.root.join(path)
            } else {
                path
            }
        });

        Ok(if command == "check" {
            Self::Check(options)
        } else {
            Self::Plan(options)
        })
    }
}

fn usage() -> &'static str {
    "usage: auths-ci-plan <check|plan> [--root PATH] [--manifest PATH] [--base SHA] [--head SHA] [--event EVENT] [--workflow ID] [--output PATH] [--github-output PATH] [--summary PATH]\n       auths-ci-plan formal-source-closure <check|update> [--root PATH] [--output PATH]"
}

pub fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Check(options) => {
            let loaded = LoadedManifest::load(&options.manifest)?;
            CostBaseline::load(&options.root.join(DEFAULT_BASELINE))?;
            let model = RepositoryModel::load(&options.root)?;
            validate_repository(&options.root, &loaded.manifest, &model)?;
            println!(
                "CI ownership manifest: PASS ({} phases; {} rules; {} workspace packages)",
                loaded.manifest.phases.len(),
                loaded.manifest.rules.len(),
                model.workspace_packages.len()
            );
            Ok(())
        }
        Command::Plan(options) => generate_plan(&options),
        Command::FormalSourceClosure {
            update,
            root,
            output,
        } => synchronize_formal_source_closure(&root, &output, update),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    version: u32,
    comprehensive_events: Vec<String>,
    always_required_phases: Vec<String>,
    phases: Vec<PhaseDefinition>,
    rules: Vec<Rule>,
    package_phase_roots: Vec<PackagePhaseRoots>,
    workflow_jobs: Vec<WorkflowJob>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseDefinition {
    id: String,
    workflows: Vec<String>,
    baseline_minutes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    kind: RuleKind,
    value: String,
    phases: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuleKind {
    Exact,
    Prefix,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackagePhaseRoots {
    phase: String,
    packages: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowJob {
    file: String,
    job: String,
    phase: String,
    gate: bool,
}

struct LoadedManifest {
    manifest: Manifest,
    digest: String,
}

impl LoadedManifest {
    fn load(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        let manifest: Manifest = toml::from_str(
            std::str::from_utf8(&bytes)
                .map_err(|error| format!("{} is not UTF-8: {error}", path.display()))?,
        )
        .map_err(|error| format!("invalid CI manifest {}: {error}", path.display()))?;
        Ok(Self {
            digest: hex::encode(Sha256::digest(&bytes)),
            manifest,
        })
    }
}

#[derive(Deserialize)]
struct CostBaselineDocument {
    schema: String,
    comprehensive_ci_runner_minutes: f64,
    release_candidate_runner_minutes: f64,
    scheduled_fuzz: ScheduledFuzzBaseline,
    projected_schedules: Vec<ProjectedSchedule>,
    regression_policy: RegressionPolicy,
}

#[derive(Deserialize)]
struct ScheduledFuzzBaseline {
    runner_minutes: f64,
}

#[derive(Deserialize)]
struct ProjectedSchedule {
    workflow: String,
    runs_per_month: f64,
    minutes_per_run: f64,
}

#[derive(Deserialize)]
struct RegressionPolicy {
    material_increase_percent: f64,
}

struct CostBaseline {
    schema: String,
    digest: String,
    comprehensive_ci_runner_minutes: f64,
    release_candidate_runner_minutes: f64,
    scheduled_fuzz_runner_minutes: f64,
    projected_schedules: Vec<ProjectedSchedule>,
    material_increase_percent: f64,
}

impl CostBaseline {
    fn load(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        let document: CostBaselineDocument = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid CI baseline {}: {error}", path.display()))?;
        if document.schema != "auths-proof-ci-cost-baseline/v1"
            || document.comprehensive_ci_runner_minutes <= 0.0
            || document.scheduled_fuzz.runner_minutes <= 0.0
            || document.release_candidate_runner_minutes <= 0.0
            || document.projected_schedules.iter().any(|schedule| {
                schedule.workflow.trim().is_empty()
                    || schedule.runs_per_month <= 0.0
                    || schedule.minutes_per_run <= 0.0
            })
            || document.regression_policy.material_increase_percent <= 0.0
        {
            return Err(
                "CI cost baseline is unversioned or contains invalid measurements".to_owned(),
            );
        }
        Ok(Self {
            schema: document.schema,
            digest: hex::encode(Sha256::digest(&bytes)),
            comprehensive_ci_runner_minutes: document.comprehensive_ci_runner_minutes,
            release_candidate_runner_minutes: document.release_candidate_runner_minutes,
            scheduled_fuzz_runner_minutes: document.scheduled_fuzz.runner_minutes,
            projected_schedules: document.projected_schedules,
            material_increase_percent: document.regression_policy.material_increase_percent,
        })
    }

    fn observed_minutes(&self, workflow: &str) -> Result<f64, String> {
        match workflow {
            "ci" => Ok(self.comprehensive_ci_runner_minutes),
            "fuzz" => Ok(self.scheduled_fuzz_runner_minutes),
            "release" => Ok(self.release_candidate_runner_minutes),
            _ => Err(format!("CI baseline omits workflow {workflow}")),
        }
    }

    fn projected_monthly_minutes(&self, workflow: &str) -> f64 {
        self.projected_schedules
            .iter()
            .filter(|schedule| schedule.workflow == workflow)
            .map(|schedule| schedule.runs_per_month * schedule.minutes_per_run)
            .sum()
    }

    fn regression_warning(&self, workflow: &str, projected: u64) -> Result<Option<String>, String> {
        let observed = self.observed_minutes(workflow)?;
        let increase_percent = ((projected as f64 - observed) / observed) * 100.0;
        Ok((increase_percent > self.material_increase_percent).then(|| {
            format!(
                "projected {workflow} cost increased {increase_percent:.1}% over the observed baseline (warning threshold {:.1}%)",
                self.material_increase_percent
            )
        }))
    }
}

impl Rule {
    fn matches(&self, path: &str) -> bool {
        match self.kind {
            RuleKind::Exact => path == self.value,
            RuleKind::Prefix => path.starts_with(&self.value),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct Change {
    status: String,
    old_path: Option<String>,
    path: String,
}

#[derive(Debug, Default)]
struct PhaseAccumulator {
    required: bool,
    reasons: BTreeSet<String>,
    paths: BTreeSet<String>,
    rules: BTreeSet<String>,
    packages: BTreeSet<String>,
}

impl PhaseAccumulator {
    fn require(
        &mut self,
        reason: impl Into<String>,
        path: Option<&str>,
        rule: Option<&str>,
        package: Option<&str>,
    ) {
        self.required = true;
        self.reasons.insert(reason.into());
        if let Some(path) = path {
            self.paths.insert(path.to_owned());
        }
        if let Some(rule) = rule {
            self.rules.insert(rule.to_owned());
        }
        if let Some(package) = package {
            self.packages.insert(package.to_owned());
        }
    }
}

#[derive(Debug, Serialize)]
struct PhasePlan {
    required: bool,
    reason: String,
    matched_paths: Vec<String>,
    matched_rules: Vec<String>,
    dependency_packages: Vec<String>,
    baseline_minutes: u64,
}

#[derive(Debug, Serialize)]
struct Plan {
    schema: &'static str,
    manifest_version: u32,
    manifest_sha256: String,
    baseline_schema: String,
    baseline_sha256: String,
    event: String,
    workflow: String,
    base_sha: String,
    head_sha: String,
    classification: String,
    classification_errors: Vec<String>,
    changes: Vec<Change>,
    changed_packages: Vec<String>,
    phases: BTreeMap<String, PhasePlan>,
    projected_runner_minutes: u64,
    comprehensive_runner_minutes: u64,
    observed_comprehensive_runner_minutes: f64,
    projected_savings_runner_minutes: f64,
    projected_monthly_scheduled_runner_minutes: f64,
    regression_warning: Option<String>,
}

fn generate_plan(options: &Options) -> Result<(), String> {
    let loaded = LoadedManifest::load(&options.manifest)?;
    let baseline = CostBaseline::load(&options.root.join(DEFAULT_BASELINE))?;
    let model = RepositoryModel::load(&options.root)?;
    validate_manifest(&loaded.manifest)?;

    let comprehensive = loaded
        .manifest
        .comprehensive_events
        .iter()
        .any(|event| event == &options.event);
    let base = options.base.clone().unwrap_or_else(|| "none".to_owned());
    let head = options
        .head
        .clone()
        .or_else(|| git_stdout(&options.root, &["rev-parse", "HEAD"]).ok())
        .unwrap_or_else(|| "unknown".to_owned());
    let mut errors = Vec::new();
    let changes = if comprehensive {
        Vec::new()
    } else if base == "none" || head == "unknown" {
        errors.push("base or head SHA is unavailable".to_owned());
        Vec::new()
    } else {
        match diff_changes(&options.root, &base, &head) {
            Ok(changes) => changes,
            Err(error) => {
                errors.push(error);
                Vec::new()
            }
        }
    };

    if let Err(error) = validate_repository(&options.root, &loaded.manifest, &model) {
        errors.push(error);
    }

    let active_phase_ids: BTreeSet<_> = loaded
        .manifest
        .phases
        .iter()
        .filter(|phase| phase.workflows.contains(&options.workflow))
        .map(|phase| phase.id.clone())
        .collect();
    if active_phase_ids.is_empty() {
        errors.push(format!(
            "workflow {} has no declared CI phases",
            options.workflow
        ));
    }
    let mut phases: BTreeMap<String, PhaseAccumulator> = loaded
        .manifest
        .phases
        .iter()
        .filter(|phase| active_phase_ids.contains(&phase.id))
        .map(|phase| (phase.id.clone(), PhaseAccumulator::default()))
        .collect();

    for phase in &loaded.manifest.always_required_phases {
        if !phases.contains_key(phase) {
            continue;
        }
        require_phase(
            &mut phases,
            phase,
            "phase is configured as always required",
            None,
            None,
            None,
        )?;
    }

    if comprehensive {
        require_all(
            &mut phases,
            &format!("{} events require the comprehensive sweep", options.event),
        );
    } else if !errors.is_empty() {
        require_all(
            &mut phases,
            "classification uncertainty requires every phase",
        );
    }

    let mut changed_package_names = BTreeSet::new();
    if !comprehensive && errors.is_empty() {
        for change in &changes {
            for path in change
                .old_path
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(change.path.as_str()))
            {
                let matching: Vec<_> = loaded
                    .manifest
                    .rules
                    .iter()
                    .filter(|rule| rule.matches(path))
                    .collect();
                if matching.is_empty() {
                    errors.push(format!("changed path has no ownership rule: {path}"));
                    continue;
                }
                for rule in matching {
                    for phase in &rule.phases {
                        if !phases.contains_key(phase) {
                            continue;
                        }
                        require_phase(
                            &mut phases,
                            phase,
                            format!("path matched rule {}", rule.id),
                            Some(path),
                            Some(&rule.id),
                            None,
                        )?;
                    }
                }
                if let Some(package) = model.package_for_path(path) {
                    changed_package_names.insert(package.to_owned());
                }
            }
        }

        let changed_paths: BTreeSet<_> = changes
            .iter()
            .flat_map(|change| {
                change
                    .old_path
                    .iter()
                    .map(String::as_str)
                    .chain(std::iter::once(change.path.as_str()))
            })
            .collect();
        if changed_paths.contains("Cargo.lock") {
            match semantic_lock_changes(&options.root, &base) {
                Ok(names) => changed_package_names.extend(names),
                Err(error) => errors.push(error),
            }
        }
        if changed_paths.contains("Cargo.toml") {
            match semantic_workspace_dependency_changes(&options.root, &base) {
                Ok(WorkspaceDependencyChanges {
                    package_names,
                    globally_formal_relevant,
                }) => {
                    changed_package_names.extend(package_names);
                    if globally_formal_relevant && phases.contains_key("formal_translation") {
                        require_phase(
                            &mut phases,
                            "formal_translation",
                            "root Cargo configuration can change translated semantics",
                            Some("Cargo.toml"),
                            None,
                            None,
                        )?;
                    }
                }
                Err(error) => errors.push(error),
            }
        }

        if !errors.is_empty() {
            require_all(
                &mut phases,
                "classification uncertainty requires every phase",
            );
        } else {
            apply_dependency_closure(
                &loaded.manifest,
                &model,
                &changed_package_names,
                &mut phases,
                &mut errors,
            )?;
            if !errors.is_empty() {
                require_all(&mut phases, "dependency uncertainty requires every phase");
            }
        }
    }

    let phase_baselines: BTreeMap<_, _> = loaded
        .manifest
        .phases
        .iter()
        .filter(|phase| active_phase_ids.contains(&phase.id))
        .map(|phase| (phase.id.as_str(), phase.baseline_minutes))
        .collect();
    let mut projected = 0;
    let mut comprehensive_minutes = 0;
    let phase_plans = phases
        .into_iter()
        .map(|(id, accumulator)| {
            let minutes = *phase_baselines.get(id.as_str()).unwrap_or(&0);
            comprehensive_minutes += minutes;
            if accumulator.required {
                projected += minutes;
            }
            let reason = if accumulator.required {
                accumulator
                    .reasons
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            } else {
                "no dependency or policy closure reached".to_owned()
            };
            (
                id,
                PhasePlan {
                    required: accumulator.required,
                    reason,
                    matched_paths: accumulator.paths.into_iter().collect(),
                    matched_rules: accumulator.rules.into_iter().collect(),
                    dependency_packages: accumulator.packages.into_iter().collect(),
                    baseline_minutes: minutes,
                },
            )
        })
        .collect();

    let observed_minutes = baseline.observed_minutes(&options.workflow)?;
    let monthly_minutes = baseline.projected_monthly_minutes(&options.workflow);
    let plan = Plan {
        schema: PLAN_SCHEMA,
        manifest_version: loaded.manifest.version,
        manifest_sha256: loaded.digest,
        baseline_schema: baseline.schema.clone(),
        baseline_sha256: baseline.digest.clone(),
        event: options.event.clone(),
        workflow: options.workflow.clone(),
        base_sha: base,
        head_sha: head,
        classification: if errors.is_empty() {
            "complete".to_owned()
        } else {
            "fail-closed".to_owned()
        },
        classification_errors: errors,
        changes,
        changed_packages: changed_package_names.into_iter().collect(),
        phases: phase_plans,
        projected_runner_minutes: projected,
        comprehensive_runner_minutes: comprehensive_minutes,
        observed_comprehensive_runner_minutes: round_tenth(observed_minutes),
        projected_savings_runner_minutes: round_tenth(
            (observed_minutes - projected as f64).max(0.0),
        ),
        projected_monthly_scheduled_runner_minutes: round_tenth(monthly_minutes),
        regression_warning: baseline.regression_warning(&options.workflow, projected)?,
    };
    write_json(&options.output, &plan)?;
    if let Some(path) = &options.github_output {
        write_github_output(path, &plan, &options.output)?;
    }
    if let Some(path) = &options.summary {
        write_summary(path, &plan)?;
    }
    println!(
        "CI plan: {} ({} projected runner-minutes; {} comprehensive)",
        plan.classification, plan.projected_runner_minutes, plan.comprehensive_runner_minutes
    );
    if let Some(warning) = &plan.regression_warning {
        println!("CI cost warning: {warning}");
    }
    Ok(())
}

fn round_tenth(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn require_all(phases: &mut BTreeMap<String, PhaseAccumulator>, reason: &str) {
    for phase in phases.values_mut() {
        phase.require(reason, None, None, None);
    }
}

fn require_phase(
    phases: &mut BTreeMap<String, PhaseAccumulator>,
    phase: &str,
    reason: impl Into<String>,
    path: Option<&str>,
    rule: Option<&str>,
    package: Option<&str>,
) -> Result<(), String> {
    phases
        .get_mut(phase)
        .ok_or_else(|| format!("unknown phase {phase}"))?
        .require(reason, path, rule, package);
    Ok(())
}

fn apply_dependency_closure(
    manifest: &Manifest,
    model: &RepositoryModel,
    changed_names: &BTreeSet<String>,
    phases: &mut BTreeMap<String, PhaseAccumulator>,
    errors: &mut Vec<String>,
) -> Result<(), String> {
    let mut changed_ids = BTreeSet::new();
    for name in changed_names {
        let ids = model.ids_by_name.get(name);
        if let Some(ids) = ids {
            changed_ids.extend(ids.iter().cloned());
        } else {
            errors.push(format!(
                "changed dependency package {name} is absent from head metadata"
            ));
        }
    }
    if !errors.is_empty() {
        return Ok(());
    }

    let reverse = model.reverse_closure(&changed_ids);
    for roots in &manifest.package_phase_roots {
        if !phases.contains_key(&roots.phase) {
            continue;
        }
        for package in &roots.packages {
            let Some(ids) = model.ids_by_name.get(package) else {
                errors.push(format!(
                    "phase {} names absent package root {package}",
                    roots.phase
                ));
                continue;
            };
            if ids.iter().any(|id| reverse.contains(id)) {
                require_phase(
                    phases,
                    &roots.phase,
                    format!("changed package dependency reaches {package}"),
                    None,
                    None,
                    Some(package),
                )?;
            }
        }
    }

    let formal_roots: BTreeSet<_> = manifest
        .package_phase_roots
        .iter()
        .filter(|roots| roots.phase == "formal_translation")
        .flat_map(|roots| roots.packages.iter())
        .filter_map(|name| model.ids_by_name.get(name))
        .flatten()
        .cloned()
        .collect();
    let formal_dependencies = model.forward_closure(&formal_roots);
    if phases.contains_key("formal_translation")
        && changed_ids
            .iter()
            .any(|id| formal_dependencies.contains(id))
    {
        require_phase(
            phases,
            "formal_translation",
            "translated package dependency closure changed",
            None,
            None,
            None,
        )?;
    }
    Ok(())
}

struct RepositoryModel {
    workspace_packages: BTreeMap<String, String>,
    ids_by_name: BTreeMap<String, BTreeSet<String>>,
    dependencies: BTreeMap<String, BTreeSet<String>>,
    reverse_dependencies: BTreeMap<String, BTreeSet<String>>,
}

impl RepositoryModel {
    fn load(root: &Path) -> Result<Self, String> {
        let output = ProcessCommand::new("cargo")
            .args(["metadata", "--locked", "--format-version", "1"])
            .current_dir(root)
            .output()
            .map_err(|error| format!("could not run cargo metadata: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "cargo metadata failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Self::from_metadata(root, &output.stdout)
    }

    fn from_metadata(root: &Path, bytes: &[u8]) -> Result<Self, String> {
        let metadata: Value = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid cargo metadata: {error}"))?;
        let workspace_members: BTreeSet<_> = metadata["workspace_members"]
            .as_array()
            .ok_or("cargo metadata omits workspace_members")?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let packages = metadata["packages"]
            .as_array()
            .ok_or("cargo metadata omits packages")?;
        let mut workspace_packages = BTreeMap::new();
        let mut ids_by_name: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for package in packages {
            let id = required_json_string(package, "id")?;
            let name = required_json_string(package, "name")?;
            ids_by_name
                .entry(name.to_owned())
                .or_default()
                .insert(id.to_owned());
            if workspace_members.contains(id) {
                let manifest = PathBuf::from(required_json_string(package, "manifest_path")?);
                let directory = manifest
                    .parent()
                    .ok_or_else(|| format!("manifest has no parent: {}", manifest.display()))?;
                let relative = directory
                    .strip_prefix(root)
                    .map_err(|_| {
                        format!(
                            "workspace package {} is outside repository root",
                            directory.display()
                        )
                    })?
                    .to_string_lossy()
                    .replace('\\', "/");
                workspace_packages.insert(name.to_owned(), relative);
            }
        }
        let mut dependencies: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut reverse_dependencies: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for node in metadata["resolve"]["nodes"]
            .as_array()
            .ok_or("cargo metadata omits resolve.nodes")?
        {
            let id = required_json_string(node, "id")?.to_owned();
            let deps: BTreeSet<_> = node["dependencies"]
                .as_array()
                .ok_or("cargo metadata node omits dependencies")?
                .iter()
                .map(|dependency| {
                    dependency
                        .as_str()
                        .ok_or_else(|| "cargo dependency ID is not a string".to_owned())
                        .map(str::to_owned)
                })
                .collect::<Result<_, _>>()?;
            for dependency in &deps {
                reverse_dependencies
                    .entry(dependency.clone())
                    .or_default()
                    .insert(id.clone());
            }
            dependencies.insert(id, deps);
        }
        Ok(Self {
            workspace_packages,
            ids_by_name,
            dependencies,
            reverse_dependencies,
        })
    }

    fn package_for_path(&self, path: &str) -> Option<&str> {
        self.workspace_packages
            .iter()
            .filter(|(_, directory)| {
                path == format!("{directory}/Cargo.toml")
                    || path.starts_with(&format!("{directory}/"))
            })
            .max_by_key(|(_, directory)| directory.len())
            .map(|(name, _)| name.as_str())
    }

    fn forward_closure(&self, starts: &BTreeSet<String>) -> BTreeSet<String> {
        graph_closure(starts, &self.dependencies)
    }

    fn reverse_closure(&self, starts: &BTreeSet<String>) -> BTreeSet<String> {
        graph_closure(starts, &self.reverse_dependencies)
    }
}

fn graph_closure(
    starts: &BTreeSet<String>,
    edges: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut result = starts.clone();
    let mut queue: VecDeque<_> = starts.iter().cloned().collect();
    while let Some(id) = queue.pop_front() {
        if let Some(neighbors) = edges.get(&id) {
            for neighbor in neighbors {
                if result.insert(neighbor.clone()) {
                    queue.push_back(neighbor.clone());
                }
            }
        }
    }
    result
}

fn validate_manifest(manifest: &Manifest) -> Result<(), String> {
    if manifest.schema != "auths-proof-ci-phase-ownership/v1" || manifest.version == 0 {
        return Err("unsupported or unversioned CI ownership manifest".to_owned());
    }
    let phases: BTreeSet<_> = manifest
        .phases
        .iter()
        .map(|phase| phase.id.as_str())
        .collect();
    if phases.len() != manifest.phases.len() || phases.is_empty() {
        return Err("CI phases must be unique and non-empty".to_owned());
    }
    if manifest
        .phases
        .iter()
        .any(|phase| phase.workflows.is_empty())
    {
        return Err("every CI phase must name at least one owning workflow".to_owned());
    }
    let mut rule_ids = BTreeSet::new();
    for rule in &manifest.rules {
        if !rule_ids.insert(rule.id.as_str())
            || rule.id.trim().is_empty()
            || rule.value.trim().is_empty()
            || rule.phases.is_empty()
        {
            return Err("CI rules must have unique IDs, values, and phases".to_owned());
        }
        for phase in &rule.phases {
            if !phases.contains(phase.as_str()) {
                return Err(format!("rule {} refers to unknown phase {phase}", rule.id));
            }
        }
    }
    for phase in &manifest.always_required_phases {
        if !phases.contains(phase.as_str()) {
            return Err(format!("always-required phase is unknown: {phase}"));
        }
    }
    for roots in &manifest.package_phase_roots {
        if !phases.contains(roots.phase.as_str()) || roots.packages.is_empty() {
            return Err(format!(
                "package phase roots are invalid for {}",
                roots.phase
            ));
        }
    }
    for phase in &manifest.phases {
        if !manifest
            .workflow_jobs
            .iter()
            .any(|job| job.phase == phase.id && job.gate)
        {
            return Err(format!("phase {} has no stable gate job", phase.id));
        }
    }
    let mut jobs = BTreeSet::new();
    for workflow in &manifest.workflow_jobs {
        if !jobs.insert((workflow.file.as_str(), workflow.job.as_str())) {
            return Err(format!(
                "workflow job is declared more than once: {} {}",
                workflow.file, workflow.job
            ));
        }
        if workflow.phase == "planner" {
            continue;
        }
        let workflow_id = Path::new(&workflow.file)
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| format!("workflow path has no UTF-8 file stem: {}", workflow.file))?;
        let phase = manifest
            .phases
            .iter()
            .find(|phase| phase.id == workflow.phase)
            .ok_or_else(|| {
                format!(
                    "workflow job {} maps to unknown phase {}",
                    workflow.job, workflow.phase
                )
            })?;
        if !phase.workflows.iter().any(|owner| owner == workflow_id) {
            return Err(format!(
                "workflow job {} is in {workflow_id} but phase {} owns {:?}",
                workflow.job, phase.id, phase.workflows
            ));
        }
    }
    Ok(())
}

fn validate_repository(
    root: &Path,
    manifest: &Manifest,
    model: &RepositoryModel,
) -> Result<(), String> {
    validate_manifest(manifest)?;
    let tracked = git_stdout_bytes(root, &["ls-files", "-z"])?;
    let uncovered: Vec<_> = tracked
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .filter(|path| !manifest.rules.iter().any(|rule| rule.matches(path)))
        .collect();
    if !uncovered.is_empty() {
        return Err(format!(
            "tracked paths lack CI ownership: {}",
            uncovered.join(", ")
        ));
    }
    for (package, directory) in &model.workspace_packages {
        let manifest_path = format!("{directory}/Cargo.toml");
        if !manifest
            .rules
            .iter()
            .any(|rule| rule.matches(&manifest_path))
        {
            return Err(format!(
                "workspace package {package} is not represented by CI ownership"
            ));
        }
    }
    for roots in &manifest.package_phase_roots {
        for package in &roots.packages {
            let Some(directory) = model.workspace_packages.get(package) else {
                return Err(format!(
                    "phase {} names non-workspace package root {package}",
                    roots.phase
                ));
            };
            let manifest_path = format!("{directory}/Cargo.toml");
            if !manifest.rules.iter().any(|rule| {
                rule.matches(&manifest_path)
                    && rule.phases.iter().any(|phase| phase == &roots.phase)
            }) {
                return Err(format!(
                    "phase {} package root {package} has no matching ownership rule",
                    roots.phase
                ));
            }
        }
    }
    for workflow in &manifest.workflow_jobs {
        if workflow.phase != "planner"
            && !manifest
                .phases
                .iter()
                .any(|phase| phase.id == workflow.phase)
        {
            return Err(format!(
                "workflow job {} maps to unknown phase {}",
                workflow.job, workflow.phase
            ));
        }
        let source = fs::read_to_string(root.join(&workflow.file))
            .map_err(|error| format!("could not read {}: {error}", workflow.file))?;
        let needle = format!("\n  {}:\n", workflow.job);
        if !source.contains(&needle) {
            return Err(format!(
                "workflow {} omits declared job {}",
                workflow.file, workflow.job
            ));
        }
        if workflow.gate && workflow.phase != "planner" {
            let expected = format!("name: {}", workflow.job);
            if !source.contains(&expected) {
                return Err(format!(
                    "stable gate {} lacks explicit name in {}",
                    workflow.job, workflow.file
                ));
            }
        }
    }
    let workflow_files: BTreeSet<_> = manifest
        .workflow_jobs
        .iter()
        .map(|workflow| workflow.file.as_str())
        .collect();
    for workflow_file in workflow_files {
        let source = fs::read_to_string(root.join(workflow_file))
            .map_err(|error| format!("could not read {workflow_file}: {error}"))?;
        let actual_jobs = workflow_job_ids(&source);
        let declared_jobs: BTreeSet<_> = manifest
            .workflow_jobs
            .iter()
            .filter(|workflow| workflow.file == workflow_file)
            .map(|workflow| workflow.job.as_str())
            .collect();
        if actual_jobs != declared_jobs {
            return Err(format!(
                "workflow {workflow_file} job map drifted: actual={actual_jobs:?}, declared={declared_jobs:?}"
            ));
        }
    }
    Ok(())
}

fn workflow_job_ids(source: &str) -> BTreeSet<&str> {
    let mut in_jobs = false;
    let mut jobs = BTreeSet::new();
    for line in source.lines() {
        if line == "jobs:" {
            in_jobs = true;
            continue;
        }
        if !in_jobs {
            continue;
        }
        if !line.starts_with(' ') && !line.trim().is_empty() {
            break;
        }
        if line.starts_with("  ")
            && !line.starts_with("    ")
            && let Some(job) = line
                .strip_prefix("  ")
                .and_then(|line| line.strip_suffix(':'))
        {
            jobs.insert(job);
        }
    }
    jobs
}

fn diff_changes(root: &Path, base: &str, head: &str) -> Result<Vec<Change>, String> {
    let range = format!("{base}..{head}");
    let bytes = git_stdout_bytes(
        root,
        &["diff", "--name-status", "-z", "--find-renames", &range],
    )?;
    parse_name_status(&bytes)
}

fn parse_name_status(bytes: &[u8]) -> Result<Vec<Change>, String> {
    let fields: Vec<_> = bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .map(|field| {
            std::str::from_utf8(field)
                .map(str::to_owned)
                .map_err(|error| format!("git diff path is not UTF-8: {error}"))
        })
        .collect::<Result<_, _>>()?;
    let mut index = 0;
    let mut changes = Vec::new();
    while index < fields.len() {
        let status = fields[index].clone();
        index += 1;
        let kind = status.chars().next().ok_or("git diff status is empty")?;
        if matches!(kind, 'R' | 'C') {
            let old_path = fields
                .get(index)
                .ok_or("rename/copy omits old path")?
                .clone();
            let path = fields
                .get(index + 1)
                .ok_or("rename/copy omits new path")?
                .clone();
            index += 2;
            changes.push(Change {
                status,
                old_path: Some(old_path),
                path,
            });
        } else {
            let path = fields
                .get(index)
                .ok_or("git diff status omits path")?
                .clone();
            index += 1;
            changes.push(Change {
                status,
                old_path: None,
                path,
            });
        }
    }
    Ok(changes)
}

fn semantic_lock_changes(root: &Path, base: &str) -> Result<BTreeSet<String>, String> {
    let previous = git_show(root, base, "Cargo.lock")?;
    let current = fs::read(root.join("Cargo.lock"))
        .map_err(|error| format!("could not read Cargo.lock: {error}"))?;
    changed_lock_package_names(&previous, &current)
}

fn changed_lock_package_names(previous: &[u8], current: &[u8]) -> Result<BTreeSet<String>, String> {
    let previous = lock_packages(previous)?;
    let current = lock_packages(current)?;
    let keys: BTreeSet<_> = previous.keys().chain(current.keys()).cloned().collect();
    Ok(keys
        .into_iter()
        .filter(|key| previous.get(key) != current.get(key))
        .filter_map(|key| key.split('\u{1f}').next().map(str::to_owned))
        .collect())
}

fn lock_packages(bytes: &[u8]) -> Result<BTreeMap<String, Value>, String> {
    let value: toml::Value = toml::from_str(
        std::str::from_utf8(bytes).map_err(|error| format!("Cargo.lock is not UTF-8: {error}"))?,
    )
    .map_err(|error| format!("invalid Cargo.lock: {error}"))?;
    let packages = value
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or("Cargo.lock omits package inventory")?;
    let mut result = BTreeMap::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or("Cargo.lock package omits name")?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or("Cargo.lock package omits version")?;
        let source = package
            .get("source")
            .and_then(toml::Value::as_str)
            .unwrap_or("workspace");
        let key = format!("{name}\u{1f}{version}\u{1f}{source}");
        let json = serde_json::to_value(package)
            .map_err(|error| format!("could not normalize Cargo.lock package: {error}"))?;
        result.insert(key, json);
    }
    Ok(result)
}

struct WorkspaceDependencyChanges {
    package_names: BTreeSet<String>,
    globally_formal_relevant: bool,
}

fn semantic_workspace_dependency_changes(
    root: &Path,
    base: &str,
) -> Result<WorkspaceDependencyChanges, String> {
    let previous = git_show(root, base, "Cargo.toml")?;
    let current = fs::read(root.join("Cargo.toml"))
        .map_err(|error| format!("could not read Cargo.toml: {error}"))?;
    workspace_dependency_changes(&previous, &current)
}

fn workspace_dependency_changes(
    previous: &[u8],
    current: &[u8],
) -> Result<WorkspaceDependencyChanges, String> {
    let previous = parse_toml(previous, "base Cargo.toml")?;
    let current = parse_toml(current, "head Cargo.toml")?;
    let previous_dependencies = table_at(&previous, &["workspace", "dependencies"]);
    let current_dependencies = table_at(&current, &["workspace", "dependencies"]);
    let keys: BTreeSet<_> = previous_dependencies
        .keys()
        .chain(current_dependencies.keys())
        .cloned()
        .collect();
    let package_names = keys
        .into_iter()
        .filter(|key| previous_dependencies.get(key) != current_dependencies.get(key))
        .map(|key| {
            current_dependencies
                .get(&key)
                .or_else(|| previous_dependencies.get(&key))
                .and_then(|value| value.get("package"))
                .and_then(toml::Value::as_str)
                .unwrap_or(&key)
                .to_owned()
        })
        .collect();
    let globally_formal_relevant = ["patch", "replace", "profile"]
        .iter()
        .any(|key| previous.get(*key) != current.get(*key))
        || table_at(&previous, &["workspace", "package"])
            != table_at(&current, &["workspace", "package"]);
    Ok(WorkspaceDependencyChanges {
        package_names,
        globally_formal_relevant,
    })
}

fn parse_toml(bytes: &[u8], label: &str) -> Result<toml::Value, String> {
    toml::from_str(
        std::str::from_utf8(bytes).map_err(|error| format!("{label} is not UTF-8: {error}"))?,
    )
    .map_err(|error| format!("invalid {label}: {error}"))
}

fn table_at<'a>(value: &'a toml::Value, path: &[&str]) -> &'a toml::map::Map<String, toml::Value> {
    let mut value = value;
    for key in path {
        let Some(next) = value.get(*key) else {
            return empty_toml_table();
        };
        value = next;
    }
    match value.as_table() {
        Some(table) => table,
        None => empty_toml_table(),
    }
}

fn empty_toml_table() -> &'static toml::map::Map<String, toml::Value> {
    static EMPTY: std::sync::OnceLock<toml::map::Map<String, toml::Value>> =
        std::sync::OnceLock::new();
    EMPTY.get_or_init(toml::map::Map::new)
}

#[derive(Deserialize)]
struct FormalClosureQualification {
    source_closure: String,
    source_files: Vec<String>,
    translations: Vec<FormalTranslationRoot>,
    #[serde(flatten)]
    _other: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize)]
struct FormalTranslationRoot {
    crate_name: String,
}

fn synchronize_formal_source_closure(
    root: &Path,
    output: &Path,
    update: bool,
) -> Result<(), String> {
    let qualification_path = root.join("formal/qualification/aeneas/qualification.toml");
    let qualification: FormalClosureQualification =
        toml::from_str(&fs::read_to_string(&qualification_path).map_err(|error| {
            format!("could not read {}: {error}", qualification_path.display())
        })?)
        .map_err(|error| format!("invalid {}: {error}", qualification_path.display()))?;
    let translation_roots: Vec<_> = qualification
        .translations
        .iter()
        .map(|translation| translation.crate_name.clone())
        .collect();
    let expected =
        formal_source_closure_json(root, &qualification.source_files, &translation_roots)?;
    write_json(output, &expected)?;
    let committed = root.join(&qualification.source_closure);
    if update {
        write_json(&committed, &expected)?;
        println!(
            "Formal source closure: UPDATED ({})",
            expected["digest"].as_str().unwrap_or("unknown")
        );
        return Ok(());
    }
    let actual: Value = serde_json::from_slice(
        &fs::read(&committed)
            .map_err(|error| format!("could not read {}: {error}", committed.display()))?,
    )
    .map_err(|error| format!("invalid {}: {error}", committed.display()))?;
    if actual != expected {
        return Err(format!(
            "production translation source closure drifted; expected artifact written to {}; run `cargo run -p auths-ci-plan -- formal-source-closure update` (computed digest {})",
            output.display(),
            expected["digest"].as_str().unwrap_or("unknown")
        ));
    }
    println!(
        "Formal source closure: PASS ({})",
        expected["digest"].as_str().unwrap_or("unknown")
    );
    Ok(())
}

pub fn formal_source_closure_json(
    root: &Path,
    paths: &[String],
    translation_roots: &[String],
) -> Result<Value, String> {
    let semantic_cargo = semantic_formal_cargo_inputs(root, translation_roots)?;
    let mut ordered = paths.to_vec();
    ordered.sort();
    ordered.dedup();
    if ordered.len() != paths.len() {
        return Err("production translation source paths must be unique".to_owned());
    }

    let mut aggregate = Sha256::new();
    let mut entries = Vec::with_capacity(ordered.len());
    for relative in ordered {
        let (bytes, normalization) = match relative.as_str() {
            "Cargo.toml" => (
                semantic_cargo.workspace_manifest.as_slice(),
                Some("translated-cargo-closure-v1"),
            ),
            "Cargo.lock" => (
                semantic_cargo.resolved_dependencies.as_slice(),
                Some("translated-cargo-closure-v1"),
            ),
            _ => {
                let path = root.join(&relative);
                if !path.is_file() {
                    return Err(format!(
                        "production translation source is absent: {}",
                        path.display()
                    ));
                }
                let bytes = fs::read(&path)
                    .map_err(|error| format!("could not read {}: {error}", path.display()))?;
                let sha256 = hex::encode(Sha256::digest(&bytes));
                aggregate.update(relative.as_bytes());
                aggregate.update([0]);
                aggregate.update(&bytes);
                aggregate.update([0xff]);
                entries.push(serde_json::json!({"path": relative, "sha256": sha256}));
                continue;
            }
        };
        let sha256 = hex::encode(Sha256::digest(bytes));
        aggregate.update(relative.as_bytes());
        aggregate.update([0]);
        aggregate.update(bytes);
        aggregate.update([0xff]);
        entries.push(serde_json::json!({
            "path": relative,
            "sha256": sha256,
            "normalization": normalization.expect("Cargo inputs have a normalization")
        }));
    }
    Ok(serde_json::json!({
        "schema": SOURCE_CLOSURE_SCHEMA,
        "digest": hex::encode(aggregate.finalize()),
        "files": entries,
    }))
}

struct SemanticCargoInputs {
    workspace_manifest: Vec<u8>,
    resolved_dependencies: Vec<u8>,
}

fn semantic_formal_cargo_inputs(
    root: &Path,
    translation_roots: &[String],
) -> Result<SemanticCargoInputs, String> {
    let output = ProcessCommand::new("cargo")
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("could not run cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("invalid cargo metadata: {error}"))?;
    let mut semantic_roots = translation_roots.to_vec();
    semantic_roots.push("auths-ci-plan".to_owned());
    semantic_roots.sort();
    semantic_roots.dedup();
    semantic_formal_cargo_inputs_from_values(
        root,
        &metadata,
        &parse_toml(
            &fs::read(root.join("Cargo.toml"))
                .map_err(|error| format!("could not read Cargo.toml: {error}"))?,
            "Cargo.toml",
        )?,
        &semantic_roots,
    )
}

fn semantic_formal_cargo_inputs_from_values(
    root: &Path,
    metadata: &Value,
    workspace_manifest: &toml::Value,
    translation_roots: &[String],
) -> Result<SemanticCargoInputs, String> {
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata omits packages")?;
    let mut ids_by_name: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut package_by_id = BTreeMap::new();
    for package in packages {
        let id = required_json_string(package, "id")?.to_owned();
        let name = required_json_string(package, "name")?.to_owned();
        ids_by_name.entry(name).or_default().insert(id.clone());
        package_by_id.insert(id, package);
    }
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("cargo metadata omits resolve.nodes")?;
    let mut dependencies = BTreeMap::new();
    let mut node_by_id = BTreeMap::new();
    for node in nodes {
        let id = required_json_string(node, "id")?.to_owned();
        let deps = node["dependencies"]
            .as_array()
            .ok_or("cargo metadata node omits dependencies")?
            .iter()
            .map(|dependency| {
                dependency
                    .as_str()
                    .ok_or_else(|| "cargo dependency ID is not a string".to_owned())
                    .map(str::to_owned)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        dependencies.insert(id.clone(), deps);
        node_by_id.insert(id, node);
    }
    let mut roots = BTreeSet::new();
    for name in translation_roots {
        let package_name = name.replace('_', "-");
        let ids = ids_by_name
            .get(&package_name)
            .ok_or_else(|| format!("translation root package is absent: {name}"))?;
        if ids.len() != 1 {
            return Err(format!(
                "translation root package {name} resolves to {} package IDs",
                ids.len()
            ));
        }
        roots.extend(ids.iter().cloned());
    }
    let closure = graph_closure(&roots, &dependencies);
    let closure_names: BTreeSet<_> = closure
        .iter()
        .filter_map(|id| package_by_id.get(id))
        .filter_map(|package| package["name"].as_str())
        .map(str::to_owned)
        .collect();

    let mut normalized_packages = Vec::new();
    for id in &closure {
        let package = package_by_id
            .get(id)
            .ok_or_else(|| format!("resolved dependency package is absent: {id}"))?;
        let node = node_by_id
            .get(id)
            .ok_or_else(|| format!("resolved dependency node is absent: {id}"))?;
        let manifest_path = PathBuf::from(required_json_string(package, "manifest_path")?);
        let normalized_manifest = manifest_path
            .strip_prefix(root)
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| "<registry-or-git>".to_owned());
        let mut package_dependencies = package["dependencies"]
            .as_array()
            .ok_or("cargo metadata package omits dependencies")?
            .iter()
            .map(normalize_dependency)
            .collect::<Result<Vec<_>, _>>()?;
        package_dependencies.sort_by_key(canonical_json);
        let mut enabled_features = node["features"]
            .as_array()
            .ok_or("cargo metadata node omits enabled features")?
            .clone();
        enabled_features.sort_by_key(canonical_json);
        normalized_packages.push(serde_json::json!({
            "name": package["name"],
            "version": package["version"],
            "source": package["source"],
            "manifest": normalized_manifest,
            "dependencies": package_dependencies,
            "enabled_features": enabled_features,
        }));
    }
    normalized_packages.sort_by_key(canonical_json);

    let workspace = workspace_manifest
        .get("workspace")
        .and_then(toml::Value::as_table)
        .ok_or("Cargo.toml omits [workspace]")?;
    let workspace_package = workspace
        .get("package")
        .cloned()
        .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()));
    let mut relevant_workspace_dependencies = toml::map::Map::new();
    if let Some(dependencies) = workspace
        .get("dependencies")
        .and_then(toml::Value::as_table)
    {
        for (key, value) in dependencies {
            let package_name = value
                .get("package")
                .and_then(toml::Value::as_str)
                .unwrap_or(key);
            if closure_names.contains(package_name) {
                relevant_workspace_dependencies.insert(key.clone(), value.clone());
            }
        }
    }
    let normalized_workspace = serde_json::json!({
        "workspace_package": workspace_package,
        "workspace_dependencies": relevant_workspace_dependencies,
    });
    Ok(SemanticCargoInputs {
        workspace_manifest: canonical_json(&normalized_workspace).into_bytes(),
        resolved_dependencies: canonical_json(&serde_json::json!({
            "translation_roots": translation_roots,
            "packages": normalized_packages,
        }))
        .into_bytes(),
    })
}

fn normalize_dependency(value: &Value) -> Result<Value, String> {
    Ok(serde_json::json!({
        "name": required_json_string(value, "name")?,
        "rename": value["rename"],
        "source": value["source"],
        "requirement": value["req"],
        "kind": value["kind"],
        "optional": value["optional"],
        "uses_default_features": value["uses_default_features"],
        "features": value["features"],
        "target": value["target"],
    }))
}

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).expect("serializing an in-memory JSON value cannot fail")
}

fn git_show(root: &Path, revision: &str, path: &str) -> Result<Vec<u8>, String> {
    git_stdout_bytes(root, &["show", &format!("{revision}:{path}")])
}

fn git_stdout(root: &Path, arguments: &[&str]) -> Result<String, String> {
    String::from_utf8(git_stdout_bytes(root, arguments)?)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("git emitted non-UTF-8 output: {error}"))
}

fn git_stdout_bytes(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let output = ProcessCommand::new("git")
        .args(arguments)
        .current_dir(root)
        .output()
        .map_err(|error| format!("could not run git {}: {error}", arguments.join(" ")))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn required_json_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("JSON object omits string field {field}"))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not encode {}: {error}", path.display()))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| format!("could not write {}: {error}", path.display()))
}

fn write_github_output(path: &Path, plan: &Plan, plan_path: &Path) -> Result<(), String> {
    let mut output = String::new();
    for (phase, decision) in &plan.phases {
        output.push_str(&format!("{phase}_required={}\n", decision.required));
        output.push_str(&format!(
            "{phase}_reason={}\n",
            decision.reason.replace(['\n', '\r'], " ")
        ));
    }
    output.push_str(&format!("classification={}\n", plan.classification));
    output.push_str(&format!("plan_path={}\n", plan_path.display()));
    append_file(path, output.as_bytes())
}

fn write_summary(path: &Path, plan: &Plan) -> Result<(), String> {
    let mut summary = format!(
        "## Auths Proof CI plan\n\nClassification: `{}`  \nProjected runner-minutes: **{} / {}**  \nObserved pre-optimization comprehensive run: **{:.1}m**  \nProjected savings for this run: **{:.1}m**  \nProjected scheduled cost: **{:.1} runner-minutes/month**\n\n| Phase | Decision | Baseline | Reason |\n| --- | --- | ---: | --- |\n",
        plan.classification,
        plan.projected_runner_minutes,
        plan.comprehensive_runner_minutes,
        plan.observed_comprehensive_runner_minutes,
        plan.projected_savings_runner_minutes,
        plan.projected_monthly_scheduled_runner_minutes
    );
    for (phase, decision) in &plan.phases {
        summary.push_str(&format!(
            "| `{phase}` | {} | {}m | {} |\n",
            if decision.required { "run" } else { "skip" },
            decision.baseline_minutes,
            decision.reason.replace('|', "\\|")
        ));
    }
    if !plan.classification_errors.is_empty() {
        summary.push_str("\n### Fail-closed classification errors\n\n");
        for error in &plan.classification_errors {
            summary.push_str(&format!("- {error}\n"));
        }
    }
    if let Some(warning) = &plan.regression_warning {
        summary.push_str(&format!("\n> [!WARNING]\n> {warning}\n"));
    }
    append_file(path, summary.as_bytes())
}

fn append_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("could not open {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("could not write {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rename_and_delete_without_losing_old_paths() {
        let changes = parse_name_status(b"R100\0docs/old.md\0docs/new.md\0D\0core/old.rs\0")
            .expect("valid diff");
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].old_path.as_deref(), Some("docs/old.md"));
        assert_eq!(changes[0].path, "docs/new.md");
        assert_eq!(changes[1].status, "D");
    }

    #[test]
    fn lock_diff_reports_only_changed_package_names() {
        let previous = br#"version = 4
[[package]]
name = "same"
version = "1.0.0"
[[package]]
name = "changed"
version = "1.0.0"
checksum = "a"
"#;
        let current = br#"version = 4
[[package]]
name = "same"
version = "1.0.0"
[[package]]
name = "changed"
version = "1.0.0"
checksum = "b"
"#;
        assert_eq!(
            changed_lock_package_names(previous, current).expect("valid locks"),
            BTreeSet::from(["changed".to_owned()])
        );
    }

    #[test]
    fn workspace_membership_does_not_imply_formal_dependency_drift() {
        let previous = br#"[workspace]
members = ["core"]
[workspace.dependencies]
serde = "1"
"#;
        let current = br#"[workspace]
members = ["core", "demos/new"]
[workspace.dependencies]
serde = "1"
"#;
        let changes = workspace_dependency_changes(previous, current).expect("valid manifests");
        assert!(changes.package_names.is_empty());
        assert!(!changes.globally_formal_relevant);
    }

    #[test]
    fn workspace_dependency_change_is_semantic() {
        let previous = br#"[workspace]
[workspace.dependencies]
serde = "1"
"#;
        let current = br#"[workspace]
[workspace.dependencies]
serde = "2"
"#;
        let changes = workspace_dependency_changes(previous, current).expect("valid manifests");
        assert_eq!(changes.package_names, BTreeSet::from(["serde".to_owned()]));
    }

    #[test]
    fn graph_closure_is_transitive() {
        let edges = BTreeMap::from([
            ("a".to_owned(), BTreeSet::from(["b".to_owned()])),
            ("b".to_owned(), BTreeSet::from(["c".to_owned()])),
        ]);
        assert_eq!(
            graph_closure(&BTreeSet::from(["a".to_owned()]), &edges),
            BTreeSet::from(["a".to_owned(), "b".to_owned(), "c".to_owned()])
        );
    }

    #[test]
    fn exact_and_prefix_rules_do_not_overmatch() {
        let exact = Rule {
            id: "exact".to_owned(),
            kind: RuleKind::Exact,
            value: "Cargo.lock".to_owned(),
            phases: vec!["dependencies".to_owned()],
        };
        let prefix = Rule {
            id: "docs".to_owned(),
            kind: RuleKind::Prefix,
            value: "docs/".to_owned(),
            phases: vec!["secrets".to_owned()],
        };
        assert!(exact.matches("Cargo.lock"));
        assert!(!exact.matches("nested/Cargo.lock"));
        assert!(prefix.matches("docs/specs/example.md"));
        assert!(!prefix.matches("documentation/file"));
    }

    #[test]
    fn command_parser_rejects_unknown_flags() {
        let error = Command::parse(["plan".to_owned(), "--wat".to_owned(), "x".to_owned()])
            .expect_err("unknown flag");
        assert!(error.contains("unknown argument --wat"));
    }

    #[test]
    fn help_text_is_stable() {
        assert_eq!(
            usage(),
            "usage: auths-ci-plan <check|plan> [--root PATH] [--manifest PATH] [--base SHA] [--head SHA] [--event EVENT] [--workflow ID] [--output PATH] [--github-output PATH] [--summary PATH]\n       auths-ci-plan formal-source-closure <check|update> [--root PATH] [--output PATH]"
        );
    }

    #[test]
    fn unrelated_workspace_and_lock_packages_do_not_drift_formal_closure() {
        let root = Path::new("/repo");
        let manifest: toml::Value = toml::from_str(
            r#"[workspace]
members = ["core/crates/auths-model", "demos/one"]
[workspace.package]
edition = "2024"
[workspace.dependencies]
serde = "1"
unrelated = "9"
"#,
        )
        .expect("valid manifest");
        let first = formal_metadata("1.0.0", "9.0.0");
        let second = formal_metadata("1.0.0", "10.0.0");
        let roots = ["auths-model".to_owned()];
        let first = semantic_formal_cargo_inputs_from_values(root, &first, &manifest, &roots)
            .expect("first closure");
        let second = semantic_formal_cargo_inputs_from_values(root, &second, &manifest, &roots)
            .expect("second closure");
        assert_eq!(first.workspace_manifest, second.workspace_manifest);
        assert_eq!(first.resolved_dependencies, second.resolved_dependencies);
    }

    #[test]
    fn translated_dependency_change_drifts_formal_closure() {
        let root = Path::new("/repo");
        let manifest: toml::Value = toml::from_str(
            r#"[workspace]
[workspace.dependencies]
serde = "1"
"#,
        )
        .expect("valid manifest");
        let roots = ["auths-model".to_owned()];
        let first = semantic_formal_cargo_inputs_from_values(
            root,
            &formal_metadata("1.0.0", "9.0.0"),
            &manifest,
            &roots,
        )
        .expect("first closure");
        let second = semantic_formal_cargo_inputs_from_values(
            root,
            &formal_metadata("2.0.0", "9.0.0"),
            &manifest,
            &roots,
        )
        .expect("second closure");
        assert_ne!(first.resolved_dependencies, second.resolved_dependencies);
    }

    #[test]
    fn records_only_path_does_not_schedule_other_domains_or_formal_translation() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("ci-plan lives at xtask/ci-plan");
        let loaded =
            LoadedManifest::load(&root.join(DEFAULT_MANIFEST)).expect("repository manifest");
        let phases: BTreeSet<_> = loaded
            .manifest
            .rules
            .iter()
            .filter(|rule| rule.matches("demos/rest-api-authorization/src/main.rs"))
            .flat_map(|rule| rule.phases.iter().map(String::as_str))
            .collect();
        assert!(phases.contains("records_api_live"));
        assert!(!phases.contains("opentofu_live"));
        assert!(!phases.contains("postgresql_live"));
        assert!(!phases.contains("formal_translation"));
    }

    #[test]
    fn representative_path_rules_preserve_expected_isolation() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("ci-plan lives at xtask/ci-plan");
        let loaded =
            LoadedManifest::load(&root.join(DEFAULT_MANIFEST)).expect("repository manifest");
        let phases_for = |path: &str| -> BTreeSet<&str> {
            loaded
                .manifest
                .rules
                .iter()
                .filter(|rule| rule.matches(path))
                .flat_map(|rule| rule.phases.iter().map(String::as_str))
                .collect()
        };

        assert_eq!(
            phases_for("docs/research/note.md"),
            BTreeSet::from(["secrets"])
        );

        let formal = phases_for("formal/Auths/Authority.lean");
        assert!(formal.contains("formal_translation"));
        assert!(!formal.contains("opentofu_live"));
        assert!(!formal.contains("postgresql_live"));
        assert!(!formal.contains("records_api_live"));

        let opentofu = phases_for("demos/opentofu-plan/web/app.js");
        assert!(opentofu.contains("opentofu_live"));
        assert!(!opentofu.contains("postgresql_live"));
        assert!(!opentofu.contains("records_api_live"));

        let control_plane = phases_for(".github/actions/setup-rust-cache/action.yml");
        for phase in &loaded.manifest.phases {
            assert!(control_plane.contains(phase.id.as_str()));
        }

        assert!(phases_for("new-unowned-root/file.txt").is_empty());
    }

    fn formal_metadata(serde_version: &str, unrelated_version: &str) -> Value {
        serde_json::json!({
            "packages": [
                {
                    "id": "path+file:///repo/core/crates/auths-model#0.1.0",
                    "name": "auths-model",
                    "version": "0.1.0",
                    "source": null,
                    "manifest_path": "/repo/core/crates/auths-model/Cargo.toml",
                    "dependencies": [{
                        "name": "serde",
                        "rename": null,
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                        "req": "^1",
                        "kind": null,
                        "optional": false,
                        "uses_default_features": false,
                        "features": [],
                        "target": null
                    }]
                },
                {
                    "id": format!("registry+serde#{serde_version}"),
                    "name": "serde",
                    "version": serde_version,
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "manifest_path": "/cargo/registry/serde/Cargo.toml",
                    "dependencies": []
                },
                {
                    "id": format!("registry+unrelated#{unrelated_version}"),
                    "name": "unrelated",
                    "version": unrelated_version,
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "manifest_path": "/cargo/registry/unrelated/Cargo.toml",
                    "dependencies": []
                }
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "path+file:///repo/core/crates/auths-model#0.1.0",
                        "dependencies": [format!("registry+serde#{serde_version}")],
                        "features": ["default"]
                    },
                    {
                        "id": format!("registry+serde#{serde_version}"),
                        "dependencies": [],
                        "features": []
                    },
                    {
                        "id": format!("registry+unrelated#{unrelated_version}"),
                        "dependencies": [],
                        "features": []
                    }
                ]
            }
        })
    }
}
