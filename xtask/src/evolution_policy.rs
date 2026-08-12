use crate::*;

const POLICY_PATH: &str = "release/evolution-policy-v1.json";

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum VersionFloor {
    Patch,
    Minor,
    Major,
}

impl VersionFloor {
    const fn label(self) -> &'static str {
        match self {
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvolutionPolicy {
    schema: String,
    lifecycle: String,
    stable_launch: StableLaunch,
    axes: Vec<VersionAxis>,
    diff_rules: Vec<DiffRule>,
    support: SupportPolicy,
    registries: Registries,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StableLaunch {
    ready: bool,
    blockers: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VersionAxis {
    id: String,
    owner: String,
    artifacts: Vec<String>,
    rule: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DiffRule {
    prefix: String,
    axis: String,
    floor: VersionFloor,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SupportPolicy {
    profile_verification_majors: u64,
    profile_verification_minimum_months: u64,
    profile_authoring_minimum_months: u64,
    retirement_notice_minimum_days: u64,
    stable_error_removal_floor: VersionFloor,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Registries {
    lifecycle: String,
    mixed_version_fixtures: String,
    mock_releases: String,
    migration_harness: String,
    generated_support_page: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LifecycleRegistry {
    schema: String,
    profiles: Vec<ProfileLifecycle>,
    errors: Vec<ErrorLifecycle>,
    conformance_suites: Vec<ConformanceLifecycle>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileLifecycle {
    id: String,
    version: u64,
    status: String,
    successor: Option<String>,
    verification_support_until: Option<String>,
    authoring_support_until: Option<String>,
    retirement_announced_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ErrorLifecycle {
    code: String,
    status: String,
    replacement: Option<String>,
    final_producing_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConformanceLifecycle {
    id: String,
    version: u64,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MixedVersionFixtures {
    schema: String,
    cases: Vec<MixedVersionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MixedVersionCase {
    id: String,
    package: String,
    abi: String,
    semantic_subject: String,
    profile: String,
    receipt_schema: String,
    state_schema: String,
    expected: String,
    stage: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MockReleases {
    schema: String,
    releases: Vec<MockRelease>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MockRelease {
    id: String,
    kind: String,
    changed_paths: Vec<String>,
    expected_floor: VersionFloor,
    expected_axes: Vec<String>,
    new_semantic_subject: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MigrationHarness {
    schema: String,
    owner: String,
    contract: MigrationContract,
    migrations: Vec<Migration>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MigrationContract {
    crash_safe: bool,
    idempotent: bool,
    preserves_original_commitment: bool,
    auditable_before_after: bool,
    binding_authored: bool,
    required_crash_points: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Migration {
    id: String,
    from_schema: String,
    to_schema: String,
    rust_implementation: String,
    fixture: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PackageVersion {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: bool,
}

pub(crate) fn evolution_policy(update: bool) -> Result<(), String> {
    let policy: EvolutionPolicy = read_typed(POLICY_PATH)?;
    validate_policy(&policy)?;
    let lifecycle: LifecycleRegistry = read_typed(&policy.registries.lifecycle)?;
    validate_lifecycle(&lifecycle)?;
    validate_mixed_versions(&read_typed(&policy.registries.mixed_version_fixtures)?)?;
    validate_mock_releases(&policy, &read_typed(&policy.registries.mock_releases)?)?;
    validate_migration_harness(&read_typed(&policy.registries.migration_harness)?)?;
    validate_stable_launch(&policy)?;
    validate_authoritative_diff(&policy)?;

    let support_page = render_support_page(&policy, &lifecycle);
    let support_path = root().join(&policy.registries.generated_support_page);
    if update {
        fs::write(&support_path, support_page)
            .map_err(|error| format!("could not write {}: {error}", support_path.display()))?;
        println!("evolution compatibility page updated");
    } else {
        let committed = fs::read_to_string(&support_path)
            .map_err(|error| format!("could not read {}: {error}", support_path.display()))?;
        if committed != support_page {
            return Err(
                "evolution compatibility page drifted; run `cargo xtask evolution-policy --update`"
                    .to_owned(),
            );
        }
        println!(
            "evolution policy passed ({} axes, {} mock releases, stable launch ready: {})",
            policy.axes.len(),
            read_typed::<MockReleases>(&policy.registries.mock_releases)?
                .releases
                .len(),
            policy.stable_launch.ready
        );
    }
    Ok(())
}

fn validate_policy(policy: &EvolutionPolicy) -> Result<(), String> {
    if policy.schema != "auths.evolution-policy/1" || policy.lifecycle != "prelaunch" {
        return Err("unsupported evolution policy".to_owned());
    }
    let expected = BTreeSet::from([
        "abi",
        "conformance",
        "package",
        "profile",
        "semantic-subject",
    ]);
    let actual: BTreeSet<_> = policy.axes.iter().map(|axis| axis.id.as_str()).collect();
    if actual != expected || policy.axes.len() != expected.len() {
        return Err("evolution policy must assign exactly the five version axes".to_owned());
    }
    for axis in &policy.axes {
        bounded_token(&axis.owner, "axis owner")?;
        bounded_token(&axis.rule, "axis rule")?;
        if axis.artifacts.is_empty() {
            return Err(format!(
                "evolution axis {} has no authoritative artifact",
                axis.id
            ));
        }
        for artifact in &axis.artifacts {
            if !root().join(artifact).exists() {
                return Err(format!("evolution artifact does not exist: {artifact}"));
            }
        }
    }
    if policy.diff_rules.is_empty() {
        return Err("evolution policy has no authoritative diff rules".to_owned());
    }
    for rule in &policy.diff_rules {
        if rule.prefix.is_empty() || !expected.contains(rule.axis.as_str()) {
            return Err("evolution diff rule is invalid".to_owned());
        }
    }
    let support = &policy.support;
    if support.profile_verification_majors < 2
        || support.profile_verification_minimum_months < 12
        || support.profile_authoring_minimum_months < 12
        || support.retirement_notice_minimum_days < 90
        || support.stable_error_removal_floor != VersionFloor::Major
    {
        return Err("evolution support windows are weaker than the stable contract".to_owned());
    }
    if policy.stable_launch.ready && !policy.stable_launch.blockers.is_empty() {
        return Err("stable launch cannot be ready with unresolved blockers".to_owned());
    }
    Ok(())
}

fn validate_lifecycle(registry: &LifecycleRegistry) -> Result<(), String> {
    if registry.schema != "auths.evolution-lifecycle/1" {
        return Err("unsupported evolution lifecycle registry".to_owned());
    }
    let errors: Value = read_typed("product/errors/v1/registry.json")?;
    let registered: BTreeSet<_> = errors["definitions"]
        .as_array()
        .ok_or("error registry definitions are missing")?
        .iter()
        .map(|definition| {
            definition["code"]
                .as_str()
                .ok_or_else(|| "error registry code is missing".to_owned())
                .map(str::to_owned)
        })
        .collect::<Result<_, _>>()?;
    let lifecycle: BTreeSet<_> = registry
        .errors
        .iter()
        .map(|entry| entry.code.clone())
        .collect();
    let active: BTreeSet<_> = registry
        .errors
        .iter()
        .filter(|entry| entry.status == "active")
        .map(|entry| entry.code.clone())
        .collect();
    if registered != active || lifecycle.len() != registry.errors.len() {
        return Err(
            "active error lifecycle metadata does not exactly cover the Rust registry".to_owned(),
        );
    }
    for error in &registry.errors {
        match error.status.as_str() {
            "active" if error.replacement.is_none() && error.final_producing_version.is_none() => {}
            "retired" if error.replacement.is_some() && error.final_producing_version.is_some() => {
            }
            _ => {
                return Err(format!(
                    "invalid lifecycle metadata for error {}",
                    error.code
                ));
            }
        }
    }
    let profile: Value = read_typed("product/profiles/auths-profile-mcp/profile-v1.json")?;
    let mcp = registry
        .profiles
        .iter()
        .find(|entry| entry.id == profile["profile"] && entry.version == profile["profileVersion"])
        .ok_or("MCP profile lifecycle metadata is missing")?;
    if mcp.status == "retired"
        && (mcp.successor.is_none()
            || mcp.verification_support_until.is_none()
            || mcp.authoring_support_until.is_none()
            || mcp.retirement_announced_at.is_none())
    {
        return Err("retired profile metadata is incomplete".to_owned());
    }
    let mut suites = BTreeSet::new();
    for suite in &registry.conformance_suites {
        bounded_token(&suite.id, "conformance suite")?;
        bounded_token(&suite.status, "conformance status")?;
        if suite.version == 0 || !suites.insert((&suite.id, suite.version)) {
            return Err("invalid or duplicate conformance lifecycle".to_owned());
        }
    }
    Ok(())
}

fn validate_mixed_versions(fixtures: &MixedVersionFixtures) -> Result<(), String> {
    if fixtures.schema != "auths.mixed-version-fixtures/1" || fixtures.cases.len() < 8 {
        return Err("mixed-version fixture coverage is incomplete".to_owned());
    }
    let mut ids = BTreeSet::new();
    for case in &fixtures.cases {
        if !ids.insert(&case.id) {
            return Err(format!("duplicate mixed-version fixture: {}", case.id));
        }
        for value in [
            &case.package,
            &case.abi,
            &case.semantic_subject,
            &case.profile,
            &case.receipt_schema,
            &case.state_schema,
        ] {
            bounded_token(value, "mixed-version value")?;
        }
        match case.expected.as_str() {
            "compatible" if case.id == "coherent-current" && case.stage == "complete" => {}
            "verify-only" if case.stage == "receipt-verify" => {}
            "reject"
                if matches!(
                    case.stage.as_str(),
                    "initialization" | "profile-selection" | "receipt-decode" | "state-decode"
                ) => {}
            _ => return Err(format!("invalid mixed-version outcome: {}", case.id)),
        }
        let derived = derived_mixed_outcome(case);
        if derived != (case.expected.as_str(), case.stage.as_str()) {
            return Err(format!(
                "mixed-version behavior is not derived from its inputs: {}",
                case.id
            ));
        }
        if case.stage == "initialization" && case.expected != "reject" {
            return Err("mixed semantic or ABI subjects must fail at initialization".to_owned());
        }
    }
    Ok(())
}

fn validate_mock_releases(policy: &EvolutionPolicy, fixtures: &MockReleases) -> Result<(), String> {
    if fixtures.schema != "auths.mock-releases/1" || fixtures.releases.len() < 7 {
        return Err("mock release coverage is incomplete".to_owned());
    }
    let mut ids = BTreeSet::new();
    for release in &fixtures.releases {
        if !ids.insert(&release.id) {
            return Err(format!("duplicate mock release: {}", release.id));
        }
        let (floor, axes) = if release.kind == "emergency" {
            if !release.new_semantic_subject {
                return Err("emergency semantic rejection requires a new subject".to_owned());
            }
            (
                VersionFloor::Patch,
                BTreeSet::from(["semantic-subject".to_owned()]),
            )
        } else if release.kind == "normal" {
            classify_paths(policy, &release.changed_paths)
        } else {
            return Err(format!("unknown mock release kind: {}", release.kind));
        };
        let expected_axes: BTreeSet<_> = release.expected_axes.iter().cloned().collect();
        if floor != release.expected_floor || axes != expected_axes {
            return Err(format!(
                "mock release classification drifted: {}",
                release.id
            ));
        }
        if release.id.contains("profile-successor") && !release.new_semantic_subject {
            return Err("profile successor mock must create a semantic subject".to_owned());
        }
    }
    Ok(())
}

fn validate_migration_harness(harness: &MigrationHarness) -> Result<(), String> {
    if harness.schema != "auths.migration-harness/1"
        || harness.owner != "Rust"
        || !harness.contract.crash_safe
        || !harness.contract.idempotent
        || !harness.contract.preserves_original_commitment
        || !harness.contract.auditable_before_after
        || harness.contract.binding_authored
        || harness.contract.required_crash_points
            != [
                "before-write",
                "after-write-before-sync",
                "after-sync-before-commit",
            ]
    {
        return Err("persisted-state migration contract is unsafe".to_owned());
    }
    let mut ids = BTreeSet::new();
    for migration in &harness.migrations {
        if !ids.insert(&migration.id)
            || migration.from_schema == migration.to_schema
            || !migration.rust_implementation.ends_with(".rs")
            || !root().join(&migration.rust_implementation).is_file()
            || !root().join(&migration.fixture).is_file()
        {
            return Err("persisted-state migration entry is invalid".to_owned());
        }
    }
    Ok(())
}

fn derived_mixed_outcome(case: &MixedVersionCase) -> (&'static str, &'static str) {
    if case.id == "old-receipt-verification" && case.receipt_schema == "auths.receipt/1" {
        return ("verify-only", "receipt-verify");
    }
    if case.abi != "authoring/1" || case.semantic_subject != "auths-v1" {
        return ("reject", "initialization");
    }
    if case.profile != "auths.mcp/1" {
        return ("reject", "profile-selection");
    }
    if case.receipt_schema != "auths.receipt/1" {
        return ("reject", "receipt-decode");
    }
    if case.state_schema != "auths.state/1" {
        return ("reject", "state-decode");
    }
    ("compatible", "complete")
}

fn validate_stable_launch(policy: &EvolutionPolicy) -> Result<(), String> {
    let versions = current_package_versions()?;
    if stable_launch_is_blocked(policy.stable_launch.ready, &versions) {
        return Err(format!(
            "stable publication is blocked by: {}",
            policy.stable_launch.blockers.join(", ")
        ));
    }
    Ok(())
}

fn stable_launch_is_blocked(ready: bool, versions: &[(&str, PackageVersion)]) -> bool {
    !ready && versions.iter().any(|(_, version)| !version.prerelease)
}

fn validate_authoritative_diff(policy: &EvolutionPolicy) -> Result<(), String> {
    let Some(base) = diff_base()? else {
        return Ok(());
    };
    let output = Command::new("git")
        .args(["diff", "--name-only", &format!("{base}..HEAD")])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not inspect authoritative evolution diff: {error}"))?;
    if !output.status.success() {
        return Err("could not compute authoritative evolution diff".to_owned());
    }
    let paths: Vec<_> = String::from_utf8(output.stdout)
        .map_err(|_| "authoritative evolution diff is not UTF-8".to_owned())?
        .lines()
        .map(str::to_owned)
        .collect();
    if paths.is_empty() {
        return Ok(());
    }
    let (floor, axes) = classify_authoritative_paths(policy, &base, &paths)?;
    println!(
        "evolution diff requires at least {} across axes: {}",
        floor.label(),
        axes.into_iter().collect::<Vec<_>>().join(", ")
    );
    let current = current_package_versions()?;
    if current.iter().all(|(_, version)| version.prerelease) {
        return Ok(());
    }
    validate_stable_immutables(&base, &paths)?;
    for (path, version) in current {
        let prior = package_version_from_git(&base, path)?;
        if !satisfies_floor(prior, version, floor) {
            return Err(format!(
                "{path} is under-versioned for a {} change",
                floor.label()
            ));
        }
    }
    Ok(())
}

fn classify_authoritative_paths(
    policy: &EvolutionPolicy,
    base: &str,
    paths: &[String],
) -> Result<(VersionFloor, BTreeSet<String>), String> {
    let without_freeze: Vec<_> = paths
        .iter()
        .filter(|path| path.as_str() != "release/semantic-freeze.json")
        .cloned()
        .collect();
    let (mut floor, mut axes) = classify_paths(policy, &without_freeze);
    if paths
        .iter()
        .any(|path| path == "release/semantic-freeze.json")
        && semantic_meaning_changed(base)?
    {
        floor = floor.max(VersionFloor::Minor);
        axes.insert("semantic-subject".to_owned());
    }
    if axes.is_empty() {
        axes.insert("package".to_owned());
    }
    Ok((floor, axes))
}

fn semantic_meaning_changed(base: &str) -> Result<bool, String> {
    let Some(prior) = git_json(base, "release/semantic-freeze.json")? else {
        return Ok(true);
    };
    let current: Value = read_typed("release/semantic-freeze.json")?;
    Ok(frozen_meaning_entries(&prior)? != frozen_meaning_entries(&current)?)
}

fn frozen_meaning_entries(value: &Value) -> Result<BTreeMap<String, (u64, String)>, String> {
    value["entries"]
        .as_array()
        .ok_or("semantic freeze entries are missing")?
        .iter()
        .filter(|entry| entry["classification"] == "frozen-meaning")
        .map(|entry| {
            Ok((
                entry["id"]
                    .as_str()
                    .ok_or("semantic freeze entry id is missing")?
                    .to_owned(),
                (
                    entry["version"]
                        .as_u64()
                        .ok_or("semantic freeze entry version is missing")?,
                    entry["sha256"]
                        .as_str()
                        .ok_or("semantic freeze entry digest is missing")?
                        .to_owned(),
                ),
            ))
        })
        .collect()
}

fn validate_stable_immutables(base: &str, paths: &[String]) -> Result<(), String> {
    for path in paths {
        if path.starts_with("product/profiles/")
            && path.contains("/profile-v")
            && let Some(prior) = git_bytes(base, path)?
        {
            let current = fs::read(root().join(path))
                .map_err(|error| format!("could not read stable profile {path}: {error}"))?;
            if prior != current {
                return Err(format!(
                    "existing stable profile identity is immutable: {path}"
                ));
            }
        }
    }
    if paths
        .iter()
        .any(|path| path == "product/errors/v1/registry.json")
        && let Some(prior) = git_json(base, "product/errors/v1/registry.json")?
    {
        let current: Value = read_typed("product/errors/v1/registry.json")?;
        reject_changed_existing_ids(&prior["definitions"], &current["definitions"], "error code")?;
    }
    for path in [
        "product/conformance/v1/mechanism-profile-conformance.json",
        "product/conformance/v1/simplified-product-waist.json",
    ] {
        if paths.iter().any(|changed| changed == path)
            && let Some(prior) = git_json(base, path)?
        {
            let current: Value = read_typed(path)?;
            reject_changed_conformance_cases(&prior, &current)?;
        }
    }
    Ok(())
}

fn reject_changed_existing_ids(prior: &Value, current: &Value, label: &str) -> Result<(), String> {
    let prior = values_by_id(prior)?;
    let current = values_by_id(current)?;
    for (id, value) in prior {
        if current
            .get(&id)
            .is_some_and(|candidate| candidate != &value)
        {
            return Err(format!("existing stable {label} changed meaning: {id}"));
        }
    }
    Ok(())
}

fn reject_changed_conformance_cases(prior: &Value, current: &Value) -> Result<(), String> {
    let prior = leaf_values_by_id(prior);
    let current = leaf_values_by_id(current);
    for (id, value) in prior {
        if current
            .get(&id)
            .is_some_and(|candidate| candidate != &value)
        {
            return Err(format!(
                "existing stable conformance case changed meaning: {id}"
            ));
        }
    }
    Ok(())
}

fn values_by_id(value: &Value) -> Result<BTreeMap<String, Value>, String> {
    value
        .as_array()
        .ok_or("versioned registry entries are missing")?
        .iter()
        .map(|entry| {
            Ok((
                entry["code"]
                    .as_str()
                    .or_else(|| entry["id"].as_str())
                    .ok_or("versioned registry entry id is missing")?
                    .to_owned(),
                entry.clone(),
            ))
        })
        .collect()
}

fn leaf_values_by_id(value: &Value) -> BTreeMap<String, Value> {
    let mut output = BTreeMap::new();
    collect_leaf_values(value, &mut output);
    output
}

fn collect_leaf_values(value: &Value, output: &mut BTreeMap<String, Value>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_leaf_values(value, output);
            }
        }
        Value::Object(fields) => {
            if !fields.contains_key("cases")
                && let Some(id) = fields.get("id").and_then(Value::as_str)
            {
                let mut semantic = fields.clone();
                semantic.remove("evidence");
                output.insert(id.to_owned(), Value::Object(semantic));
            }
            for value in fields.values() {
                collect_leaf_values(value, output);
            }
        }
        _ => {}
    }
}

fn classify_paths(policy: &EvolutionPolicy, paths: &[String]) -> (VersionFloor, BTreeSet<String>) {
    let mut floor = VersionFloor::Patch;
    let mut axes = BTreeSet::new();
    for path in paths {
        let rule = policy
            .diff_rules
            .iter()
            .filter(|rule| path.starts_with(&rule.prefix))
            .max_by_key(|rule| rule.prefix.len());
        if let Some(rule) = rule {
            floor = floor.max(rule.floor);
            axes.insert(rule.axis.clone());
        } else {
            axes.insert("package".to_owned());
        }
    }
    (floor, axes)
}

fn render_support_page(policy: &EvolutionPolicy, lifecycle: &LifecycleRegistry) -> String {
    let mut output = String::from(
        "# Compatibility and support\n\nThis page is generated from the Auths evolution policy and lifecycle registry.\n\n",
    );
    writeln!(
        output,
        "Stable publication: **{}**\n",
        if policy.stable_launch.ready {
            "ready"
        } else {
            "blocked"
        }
    )
    .expect("writing to a string cannot fail");
    if !policy.stable_launch.blockers.is_empty() {
        writeln!(
            output,
            "Current blockers: {}.\n",
            policy.stable_launch.blockers.join(", ")
        )
        .expect("writing to a string cannot fail");
    }
    output.push_str("## Version axes\n\n| Axis | Owner | Rule | Authoritative artifacts |\n| --- | --- | --- | --- |\n");
    for axis in &policy.axes {
        writeln!(
            output,
            "| `{}` | `{}` | `{}` | {} |",
            axis.id,
            axis.owner,
            axis.rule,
            axis.artifacts
                .iter()
                .map(|path| format!("`{path}`"))
                .collect::<Vec<_>>()
                .join("<br>")
        )
        .expect("writing to a string cannot fail");
    }
    writeln!(
        output,
        "\n## Stable support windows\n\n- Profile verification: current and next package major, for at least {} months.\n- Profile authoring and execution after a successor: at least {} months.\n- Retirement notice: at least {} days.\n- Stable error removal: {} release only.\n",
        policy.support.profile_verification_minimum_months,
        policy.support.profile_authoring_minimum_months,
        policy.support.retirement_notice_minimum_days,
        policy.support.stable_error_removal_floor.label(),
    )
    .expect("writing to a string cannot fail");
    output.push_str("## Profiles\n\n| Profile | Status | Successor | Verification until | Authoring until |\n| --- | --- | --- | --- | --- |\n");
    for profile in &lifecycle.profiles {
        writeln!(
            output,
            "| `{}/{}` | {} | {} | {} | {} |",
            profile.id,
            profile.version,
            profile.status,
            display_optional(&profile.successor),
            display_optional(&profile.verification_support_until),
            display_optional(&profile.authoring_support_until),
        )
        .expect("writing to a string cannot fail");
    }
    output.push_str("\n## Error lifecycle\n\n| Code | Status | Replacement | Final producing version |\n| --- | --- | --- | --- |\n");
    for error in &lifecycle.errors {
        writeln!(
            output,
            "| `{}` | {} | {} | {} |",
            error.code,
            error.status,
            display_optional(&error.replacement),
            display_optional(&error.final_producing_version),
        )
        .expect("writing to a string cannot fail");
    }
    output.push_str(
        "\n## Conformance suites\n\n| Suite | Version | Status |\n| --- | ---: | --- |\n",
    );
    for suite in &lifecycle.conformance_suites {
        writeln!(
            output,
            "| `{}` | {} | {} |",
            suite.id, suite.version, suite.status
        )
        .expect("writing to a string cannot fail");
    }
    output
}

fn display_optional(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("—")
}

fn diff_base() -> Result<Option<String>, String> {
    let Some(base) = env::var_os("AUTHS_EVOLUTION_BASE_SHA") else {
        return Ok(None);
    };
    let base = base.to_string_lossy().trim().to_owned();
    if base.is_empty() || base.chars().all(|character| character == '0') {
        Ok(None)
    } else {
        Ok(Some(base))
    }
}

fn git_bytes(base: &str, path: &str) -> Result<Option<Vec<u8>>, String> {
    let output = Command::new("git")
        .args(["show", &format!("{base}:{path}")])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not read {path} at evolution base: {error}"))?;
    if output.status.success() {
        Ok(Some(output.stdout))
    } else {
        Ok(None)
    }
}

fn git_json(base: &str, path: &str) -> Result<Option<Value>, String> {
    git_bytes(base, path)?
        .map(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|error| format!("could not parse {path} at evolution base: {error}"))
        })
        .transpose()
}

fn current_package_versions() -> Result<[(&'static str, PackageVersion); 3], String> {
    Ok([
        (
            "Cargo.toml",
            cargo_version(
                &fs::read_to_string(root().join("Cargo.toml"))
                    .map_err(|error| error.to_string())?,
            )?,
        ),
        (
            "bindings/typescript/package.json",
            npm_version(
                &fs::read_to_string(root().join("bindings/typescript/package.json"))
                    .map_err(|error| error.to_string())?,
            )?,
        ),
        (
            "bindings/python/pyproject.toml",
            python_version(
                &fs::read_to_string(root().join("bindings/python/pyproject.toml"))
                    .map_err(|error| error.to_string())?,
            )?,
        ),
    ])
}

fn package_version_from_git(base: &str, path: &str) -> Result<PackageVersion, String> {
    let output = Command::new("git")
        .args(["show", &format!("{base}:{path}")])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not read prior package version: {error}"))?;
    if !output.status.success() {
        return Err(format!("could not read {path} at evolution base {base}"));
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| "prior package manifest is not UTF-8".to_owned())?;
    match path {
        "Cargo.toml" => cargo_version(&value),
        "bindings/typescript/package.json" => npm_version(&value),
        "bindings/python/pyproject.toml" => python_version(&value),
        _ => Err("unknown package manifest".to_owned()),
    }
}

fn cargo_version(value: &str) -> Result<PackageVersion, String> {
    let parsed: toml::Value = toml::from_str(value).map_err(|error| error.to_string())?;
    parse_package_version(
        parsed["workspace"]["package"]["version"]
            .as_str()
            .ok_or("workspace package version is missing")?,
    )
}

fn npm_version(value: &str) -> Result<PackageVersion, String> {
    let parsed: Value = serde_json::from_str(value).map_err(|error| error.to_string())?;
    parse_package_version(
        parsed["version"]
            .as_str()
            .ok_or("npm package version is missing")?,
    )
}

fn python_version(value: &str) -> Result<PackageVersion, String> {
    let parsed: toml::Value = toml::from_str(value).map_err(|error| error.to_string())?;
    parse_package_version(
        parsed["project"]["version"]
            .as_str()
            .ok_or("Python package version is missing")?,
    )
}

fn parse_package_version(value: &str) -> Result<PackageVersion, String> {
    let stable = value.split(['-', '+']).next().unwrap_or(value);
    let prerelease = stable.contains("rc") || stable != value;
    let stable = stable.split("rc").next().unwrap_or(stable);
    let values: Vec<_> = stable.split('.').collect();
    if values.len() != 3 {
        return Err(format!("invalid package version: {value}"));
    }
    Ok(PackageVersion {
        major: values[0]
            .parse()
            .map_err(|_| format!("invalid package version: {value}"))?,
        minor: values[1]
            .parse()
            .map_err(|_| format!("invalid package version: {value}"))?,
        patch: values[2]
            .parse()
            .map_err(|_| format!("invalid package version: {value}"))?,
        prerelease,
    })
}

fn satisfies_floor(prior: PackageVersion, current: PackageVersion, floor: VersionFloor) -> bool {
    match floor {
        VersionFloor::Major => current.major > prior.major,
        VersionFloor::Minor => {
            current.major > prior.major
                || (current.major == prior.major && current.minor > prior.minor)
        }
        VersionFloor::Patch => {
            current.major > prior.major
                || (current.major == prior.major && current.minor > prior.minor)
                || (current.major == prior.major
                    && current.minor == prior.minor
                    && current.patch > prior.patch)
        }
    }
}

fn bounded_token(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "._:/-".contains(character)))
    {
        return Err(format!("invalid {label}: {value}"));
    }
    Ok(())
}

fn read_typed<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    serde_json::from_slice(
        &fs::read(root().join(path)).map_err(|error| format!("could not read {path}: {error}"))?,
    )
    .map_err(|error| format!("could not parse {path}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_floors_distinguish_patch_minor_and_major() {
        let base = parse_package_version("1.2.3").unwrap();
        assert!(satisfies_floor(
            base,
            parse_package_version("1.2.4").unwrap(),
            VersionFloor::Patch
        ));
        assert!(!satisfies_floor(
            base,
            parse_package_version("1.2.4").unwrap(),
            VersionFloor::Minor
        ));
        assert!(satisfies_floor(
            base,
            parse_package_version("1.3.0").unwrap(),
            VersionFloor::Minor
        ));
        assert!(satisfies_floor(
            base,
            parse_package_version("2.0.0").unwrap(),
            VersionFloor::Major
        ));
    }

    #[test]
    fn migration_contract_rejects_binding_owned_meaning() {
        let harness = MigrationHarness {
            schema: "auths.migration-harness/1".to_owned(),
            owner: "Rust".to_owned(),
            contract: MigrationContract {
                crash_safe: true,
                idempotent: true,
                preserves_original_commitment: true,
                auditable_before_after: true,
                binding_authored: true,
                required_crash_points: vec![
                    "before-write".to_owned(),
                    "after-write-before-sync".to_owned(),
                    "after-sync-before-commit".to_owned(),
                ],
            },
            migrations: vec![],
        };
        assert!(validate_migration_harness(&harness).is_err());
    }

    #[test]
    fn stable_artifact_is_blocked_until_the_launch_contract_is_ready() {
        let stable = parse_package_version("1.0.0").unwrap();
        let candidate = parse_package_version("1.0.0-rc.1").unwrap();
        assert!(stable_launch_is_blocked(false, &[("npm", stable)]));
        assert!(!stable_launch_is_blocked(false, &[("npm", candidate)]));
        assert!(!stable_launch_is_blocked(true, &[("npm", stable)]));
    }
}
