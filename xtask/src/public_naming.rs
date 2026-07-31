#![allow(clippy::too_many_lines)]

use crate::*;

const INVENTORY_PATH: &str = "release/public-naming.toml";
const INVENTORY_SCHEMA: &str = "auths.public-naming/v1";
const FORBIDDEN_STALE_NAMES: [&str; 11] = [
    concat!("auths-proof", "-sdk"),
    concat!("@auths-dev", "/proof"),
    concat!("pypi:", "auths-proof"),
    concat!("auths-proof", "-v1.0.0"),
    concat!("auths-proof", "-v<"),
    concat!("auths-proof", "-v*"),
    concat!("auths-proof", "-release-evidence-"),
    concat!("auths-proof", "-release-evidence/v1"),
    concat!("auths-proof", "-platform/v1"),
    "heading:Auths Proof product",
    "install:legacy-public-coordinate",
];
const PREDECESSOR_CRATES: [&str; 33] = [
    "auths",
    "auths-anchor",
    "auths-api",
    "auths-cli",
    "auths-core",
    "auths-crypto",
    "auths-evidence",
    "auths-id",
    "auths-index",
    "auths-infra-git",
    "auths-infra-http",
    "auths-infra-rekor",
    "auths-jwt",
    "auths-keri",
    "auths-mcp-core",
    "auths-mcp-gateway",
    "auths-mcp-server",
    "auths-oidc-port",
    "auths-pairing-daemon",
    "auths-pairing-protocol",
    "auths-policy",
    "auths-receipts",
    "auths-rp",
    "auths-scim",
    "auths-scim-server",
    "auths-sdk",
    "auths-storage",
    "auths-telemetry",
    "auths-transparency",
    "auths-utils",
    "auths-verifier",
    "auths-witness",
    "auths-witness-node",
];
const CONTINUE_CRATES: [&str; 4] = ["auths", "auths-receipts", "auths-sdk", "auths-verifier"];
const REPLACE_CRATES: [&str; 10] = [
    "auths-core",
    "auths-crypto",
    "auths-evidence",
    "auths-id",
    "auths-index",
    "auths-keri",
    "auths-mcp-core",
    "auths-policy",
    "auths-rp",
    "auths-storage",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamingInventory {
    schema: String,
    snapshot_date: String,
    authority: String,
    governing_issue: String,
    governing_spec: String,
    product: String,
    website: String,
    first_rc_tag: String,
    registry_evidence: RegistryEvidence,
    surfaces: Vec<NamingSurface>,
    release_order: Vec<ReleaseTier>,
    predecessor_crates: Vec<PredecessorCrate>,
    deletion_policy: DeletionPolicy,
    stale_name_allowances: Vec<StaleNameAllowance>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryEvidence {
    crates_owner_id: u64,
    crates_owner: String,
    crates_snapshot: String,
    crates_policy: String,
    npm_sdk: String,
    python_sdk: String,
    limitations: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamingSurface {
    id: String,
    kind: String,
    current: String,
    target: String,
    state: String,
    compatibility: String,
    owner_pr: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseTier {
    tier: u64,
    packages: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PredecessorCrate {
    name: String,
    owner: String,
    latest_version: String,
    downloads_total: u64,
    downloads_recent: u64,
    reverse_dependencies: Vec<String>,
    classification: String,
    replacement: Vec<String>,
    deletion_eligible: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletionPolicy {
    default_eligible: bool,
    reason: String,
    destructive_actions_authorized: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct StaleNameAllowance {
    path: String,
    token: String,
    reason: String,
}

pub(crate) fn public_naming() -> Result<(), String> {
    let path = root().join(INVENTORY_PATH);
    let inventory: NamingInventory = toml::from_str(
        &fs::read_to_string(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("invalid {}: {error}", path.display()))?;

    validate_identity(&inventory)?;
    validate_surfaces(&inventory.surfaces)?;
    validate_predecessors(&inventory)?;
    validate_release_order(&inventory.release_order)?;
    validate_current_coordinates()?;
    validate_stale_names(&inventory.stale_name_allowances)?;
    println!(
        "public naming passed ({} surfaces, {} predecessor crates, {} publication tiers)",
        inventory.surfaces.len(),
        inventory.predecessor_crates.len(),
        inventory.release_order.len()
    );
    Ok(())
}

fn validate_identity(inventory: &NamingInventory) -> Result<(), String> {
    let expected = [
        ("schema", inventory.schema.as_str(), INVENTORY_SCHEMA),
        ("product", inventory.product.as_str(), "Auths"),
        ("website", inventory.website.as_str(), "https://auths.dev"),
        (
            "first_rc_tag",
            inventory.first_rc_tag.as_str(),
            "auths-v1.0.0-rc.1",
        ),
        (
            "governing_issue",
            inventory.governing_issue.as_str(),
            "https://github.com/auths-dev/auths-proof/issues/54",
        ),
        (
            "governing_spec",
            inventory.governing_spec.as_str(),
            "docs/specs/0034-auths-public-naming-consolidation.md",
        ),
    ];
    for (field, actual, value) in expected {
        if actual != value {
            return Err(format!(
                "public naming {field} is {actual:?}; expected {value:?}"
            ));
        }
    }
    if inventory.snapshot_date != "2026-07-31" || inventory.authority.trim().is_empty() {
        return Err("public naming snapshot date or authority is incomplete".to_owned());
    }
    let evidence = &inventory.registry_evidence;
    if evidence.crates_owner_id != 345_389
        || evidence.crates_owner != "bordumb"
        || evidence.crates_snapshot.trim().is_empty()
        || evidence.crates_policy != "https://doc.rust-lang.org/cargo/reference/publishing.html"
        || evidence.npm_sdk != "https://registry.npmjs.org/@auths-dev%2fsdk"
        || evidence.python_sdk != "https://pypi.org/pypi/auths/json"
        || evidence.limitations.trim().is_empty()
    {
        return Err("public naming registry evidence is incomplete or changed".to_owned());
    }
    let policy = &inventory.deletion_policy;
    if policy.default_eligible
        || policy.destructive_actions_authorized
        || policy.reason.trim().is_empty()
    {
        return Err("predecessor deletion must remain unauthorized and ineligible".to_owned());
    }
    Ok(())
}

fn validate_surfaces(surfaces: &[NamingSurface]) -> Result<(), String> {
    let expected_targets = BTreeMap::from([
        ("product", "Auths"),
        ("website", "https://auths.dev"),
        ("repository-current", "auths-dev/auths-proof"),
        ("repository-predecessor", "archived-predecessor"),
        ("rust-core", "auths"),
        ("rust-proof-component", "auths-proof"),
        ("rust-sdk", "auths-sdk"),
        ("npm-sdk", "@auths-dev/sdk"),
        ("python-sdk", "auths"),
        ("rc-tag", "auths-v<version>"),
        (
            "release-evidence-artifact",
            "auths-release-evidence-<run>-<attempt>",
        ),
        ("source-archive", "auths-<version>-source.tar.zst"),
        (
            "assurance-bundle",
            "auths-<version>-assurance.tar.zst",
        ),
        ("release-schema", "auths.release-manifest/1"),
        ("release-evidence-schema", "auths.release-evidence/1"),
        ("platform-artifact-schema", "auths.platform/1"),
        (
            "github-attestation-subject",
            "repo:auths-dev@260513770/auths-proof@1310728509:environment:release-candidate",
        ),
        (
            "rust-api-docs",
            "https://docs.rs/auths and https://docs.rs/auths-sdk",
        ),
        ("internal-wasm-crate", "auths-proof-wasm"),
        ("internal-python-crate", "auths-proof-python"),
        ("proof-exchange-family", "auths-proof-exchange-*"),
        ("container-images", "ghcr.io/auths-dev/auths-*"),
        (
            "deployment-names",
            "auths-* applications with auths.dev/docs.auths.dev as user-facing product links",
        ),
    ]);
    let mut actual = BTreeMap::new();
    for surface in surfaces {
        if surface.kind.trim().is_empty()
            || surface.current.trim().is_empty()
            || surface.state.trim().is_empty()
            || surface.compatibility.trim().is_empty()
            || surface.owner_pr.trim().is_empty()
        {
            return Err(format!("public naming surface {} is incomplete", surface.id));
        }
        if actual
            .insert(surface.id.as_str(), surface.target.as_str())
            .is_some()
        {
            return Err(format!("duplicate public naming surface: {}", surface.id));
        }
    }
    if actual != expected_targets {
        return Err(format!(
            "public naming surfaces drifted; expected={expected_targets:?}, actual={actual:?}"
        ));
    }
    Ok(())
}

fn validate_predecessors(inventory: &NamingInventory) -> Result<(), String> {
    let expected = PREDECESSOR_CRATES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let continuing = CONTINUE_CRATES.into_iter().collect::<BTreeSet<_>>();
    let replacing = REPLACE_CRATES.into_iter().collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for predecessor in &inventory.predecessor_crates {
        if !actual.insert(predecessor.name.clone()) {
            return Err(format!(
                "duplicate predecessor crate disposition: {}",
                predecessor.name
            ));
        }
        let expected_classification = if continuing.contains(predecessor.name.as_str()) {
            "Continue"
        } else if replacing.contains(predecessor.name.as_str()) {
            "Replace"
        } else {
            "Retire"
        };
        let expected_version = if predecessor.name == "auths-witness" {
            "0.1.12"
        } else {
            "0.1.16"
        };
        if predecessor.owner != "bordumb"
            || predecessor.latest_version != expected_version
            || predecessor.classification != expected_classification
            || predecessor.deletion_eligible
            || predecessor.downloads_recent > predecessor.downloads_total
        {
            return Err(format!(
                "predecessor crate disposition is invalid: {}",
                predecessor.name
            ));
        }
        let mut reverse_dependencies = predecessor.reverse_dependencies.clone();
        reverse_dependencies.sort();
        reverse_dependencies.dedup();
        if reverse_dependencies != predecessor.reverse_dependencies {
            return Err(format!(
                "predecessor reverse dependencies must be sorted and unique: {}",
                predecessor.name
            ));
        }
        match expected_classification {
            "Retire" if !predecessor.replacement.is_empty() => {
                return Err(format!(
                    "retired predecessor must not claim a replacement: {}",
                    predecessor.name
                ));
            }
            "Continue" | "Replace" if predecessor.replacement.is_empty() => {
                return Err(format!(
                    "continued or replaced predecessor must name its target: {}",
                    predecessor.name
                ));
            }
            _ => {}
        }
    }
    if actual != expected {
        return Err(naming_set_drift("predecessor crate inventory", &expected, &actual));
    }
    Ok(())
}

fn validate_release_order(tiers: &[ReleaseTier]) -> Result<(), String> {
    if tiers.len() != 9 {
        return Err(format!(
            "public Rust release order has {} tiers; expected 9",
            tiers.len()
        ));
    }
    let mut tier_by_package = BTreeMap::new();
    for (expected_tier, release_tier) in tiers.iter().enumerate() {
        if release_tier.tier != expected_tier as u64 || release_tier.packages.is_empty() {
            return Err(format!(
                "release tier {} is absent, out of order, or empty",
                expected_tier
            ));
        }
        for package in &release_tier.packages {
            if tier_by_package
                .insert(package.clone(), release_tier.tier)
                .is_some()
            {
                return Err(format!("package appears in multiple release tiers: {package}"));
            }
        }
    }

    let semantic_path = root().join("release/semantic-freeze.json");
    let semantic: Value = serde_json::from_slice(
        &fs::read(&semantic_path)
            .map_err(|error| format!("could not read {}: {error}", semantic_path.display()))?,
    )
    .map_err(|error| format!("invalid {}: {error}", semantic_path.display()))?;
    let expected = semantic["publicSurface"]["rustPublishableClosure"]
        .as_array()
        .ok_or("semantic freeze has no public Rust closure")?
        .iter()
        .map(|name| {
            name.as_str()
                .ok_or_else(|| "semantic freeze Rust package is not a string".to_owned())
                .map(str::to_owned)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let actual = tier_by_package.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(naming_set_drift("public Rust release order", &expected, &actual));
    }
    for root_name in ["auths", "auths-sdk"] {
        if tier_by_package.get(root_name) != Some(&8) {
            return Err(format!("public Rust root is not in final release tier: {root_name}"));
        }
    }

    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--locked",
        ])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not inspect release-order dependencies: {error}"))?;
    if !output.status.success() {
        return Err("cargo metadata failed while validating release order".to_owned());
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("invalid cargo metadata: {error}"))?;
    let names_by_id = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages")?
        .iter()
        .map(|package| {
            Ok((
                package["id"]
                    .as_str()
                    .ok_or_else(|| "cargo package has no id".to_owned())?
                    .to_owned(),
                package["name"]
                    .as_str()
                    .ok_or_else(|| "cargo package has no name".to_owned())?
                    .to_owned(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    for node in metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("cargo metadata has no resolve nodes")?
    {
        let source_id = node["id"].as_str().ok_or("cargo resolve node has no id")?;
        let Some(source_name) = names_by_id.get(source_id) else {
            continue;
        };
        let Some(source_tier) = tier_by_package.get(source_name) else {
            continue;
        };
        for dependency in node["deps"]
            .as_array()
            .ok_or("cargo resolve dependencies are not an array")?
        {
            let kinds = dependency["dep_kinds"]
                .as_array()
                .ok_or("cargo dependency kinds are not an array")?;
            let is_normal = kinds.is_empty()
                || kinds
                    .iter()
                    .any(|kind| kind["kind"].is_null() || kind["kind"] == "normal");
            if !is_normal {
                continue;
            }
            let dependency_id = dependency["pkg"]
                .as_str()
                .ok_or("cargo dependency has no package id")?;
            let Some(dependency_name) = names_by_id.get(dependency_id) else {
                continue;
            };
            let Some(dependency_tier) = tier_by_package.get(dependency_name) else {
                continue;
            };
            if dependency_tier >= source_tier {
                return Err(format!(
                    "release order is invalid: {source_name} (tier {source_tier}) depends on \
                     {dependency_name} (tier {dependency_tier})"
                ));
            }
        }
    }
    Ok(())
}

fn validate_stale_names(allowances: &[StaleNameAllowance]) -> Result<(), String> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not inventory tracked files: {error}"))?;
    if !output.status.success() {
        return Err("git ls-files failed while checking public names".to_owned());
    }
    let mut contents = BTreeMap::new();
    for bytes in output.stdout.split(|byte| *byte == 0).filter(|path| !path.is_empty()) {
        let path = String::from_utf8(bytes.to_vec())
            .map_err(|error| format!("tracked path is not UTF-8: {error}"))?;
        contents.insert(
            path.clone(),
            fs::read(root().join(&path))
                .map_err(|error| format!("could not read tracked file {path}: {error}"))?,
        );
    }
    validate_stale_contents(&contents, allowances)
}

fn validate_stale_contents(
    contents: &BTreeMap<String, Vec<u8>>,
    allowances: &[StaleNameAllowance],
) -> Result<(), String> {
    let known_tokens = FORBIDDEN_STALE_NAMES.into_iter().collect::<BTreeSet<_>>();
    let mut allowed = BTreeSet::new();
    for allowance in allowances {
        if allowance.reason.trim().is_empty()
            || !known_tokens.contains(allowance.token.as_str())
            || !contents.contains_key(&allowance.path)
        {
            return Err(format!("invalid stale-name allowance: {allowance:?}"));
        }
        let key = (allowance.path.clone(), allowance.token.clone());
        if !allowed.insert(key.clone()) {
            return Err(format!("duplicate stale-name allowance: {key:?}"));
        }
        let occurs = stale_name_occurs(&contents[&allowance.path], &allowance.token);
        if !occurs {
            return Err(format!(
                "stale-name allowance is no longer needed: {} contains no {:?}",
                allowance.path, allowance.token
            ));
        }
    }
    for (path, bytes) in contents {
        for token in FORBIDDEN_STALE_NAMES {
            let occurs = stale_name_occurs(bytes, token);
            if occurs && !allowed.contains(&(path.clone(), token.to_owned())) {
                return Err(format!(
                    "forbidden stale public name {token:?} occurs in {path}; add an exact \
                     justified allowance only for historical or negative documentation"
                ));
            }
        }
    }
    Ok(())
}

fn stale_name_occurs(bytes: &[u8], token: &str) -> bool {
    match token {
        "heading:Auths Proof product" => String::from_utf8_lossy(bytes).lines().any(|line| {
            let line = line.trim_start();
            let Some(rest) = line.strip_prefix('#') else {
                return false;
            };
            let rest = rest.trim_start_matches('#');
            rest.strip_prefix(' ').is_some_and(|title| {
                title.contains("Auths Proof")
                    && !title.contains("Auths Proof Protocol")
                    && !title.contains("Auths Proof Exchange")
            })
        }),
        "install:legacy-public-coordinate" => {
            let commands = [
                concat!("cargo add ", "auths-proof"),
                concat!("pip install ", "auths-proof"),
                concat!("npm install ", "@auths-dev/proof"),
                concat!("npm add ", "@auths-dev/proof"),
            ];
            commands.iter().any(|command| {
                bytes
                    .windows(command.len())
                    .any(|window| window == command.as_bytes())
            })
        }
        _ => bytes
            .windows(token.len())
            .any(|window| window == token.as_bytes()),
    }
}

fn validate_current_coordinates() -> Result<(), String> {
    let typescript_path = root().join("bindings/typescript/package.json");
    let typescript: Value = serde_json::from_slice(
        &fs::read(&typescript_path)
            .map_err(|error| format!("could not read {}: {error}", typescript_path.display()))?,
    )
    .map_err(|error| format!("invalid {}: {error}", typescript_path.display()))?;
    if typescript["name"] != "@auths-dev/sdk" {
        return Err("TypeScript package name must be @auths-dev/sdk".to_owned());
    }

    let python_path = root().join("bindings/python/pyproject.toml");
    let python: toml::Value = toml::from_str(
        &fs::read_to_string(&python_path)
            .map_err(|error| format!("could not read {}: {error}", python_path.display()))?,
    )
    .map_err(|error| format!("invalid {}: {error}", python_path.display()))?;
    let python_name = python
        .get("project")
        .and_then(toml::Value::as_table)
        .and_then(|project| project.get("name"))
        .and_then(toml::Value::as_str);
    if python_name != Some("auths") {
        return Err("Python distribution name must be auths".to_owned());
    }

    let semantic_path = root().join("release/semantic-freeze.json");
    let semantic: Value = serde_json::from_slice(
        &fs::read(&semantic_path)
            .map_err(|error| format!("could not read {}: {error}", semantic_path.display()))?,
    )
    .map_err(|error| format!("invalid {}: {error}", semantic_path.display()))?;
    if semantic["publicSurface"]["rustRoots"] != json!(["auths", "auths-sdk"])
        || semantic["publicSurface"]["releaseArtifactFamilies"]
            != json!([
                "source-archive",
                "rust-crates",
                "npm:@auths-dev/sdk",
                "pypi:auths",
                "assurance-bundle"
            ])
    {
        return Err("semantic-freeze public coordinates disagree with naming authority".to_owned());
    }

    let workflow_path = root().join(".github/workflows/release.yml");
    let workflow = fs::read_to_string(&workflow_path)
        .map_err(|error| format!("could not read {}: {error}", workflow_path.display()))?;
    for required in [
        "tags: [\"auths-v*\"]",
        "name: auths-release-evidence-${{ github.run_id }}-${{ github.run_attempt }}",
    ] {
        if !workflow.contains(required) {
            return Err(format!(
                "release workflow is missing inventory-governed coordinate: {required}"
            ));
        }
    }
    Ok(())
}

fn naming_set_drift(
    label: &str,
    expected: &BTreeSet<String>,
    actual: &BTreeSet<String>,
) -> String {
    let missing = expected.difference(actual).cloned().collect::<Vec<_>>();
    let extra = actual.difference(expected).cloned().collect::<Vec<_>>();
    format!("{label} drifted; missing={missing:?}, extra={extra:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_unallowed_stale_name_fails() {
        for token in FORBIDDEN_STALE_NAMES {
            let bytes = match token {
                "heading:Auths Proof product" => b"## Auths Proof\n".to_vec(),
                "install:legacy-public-coordinate" => {
                    concat!("cargo add ", "auths-proof").as_bytes().to_vec()
                }
                _ => token.as_bytes().to_vec(),
            };
            let contents = BTreeMap::from([("README.md".to_owned(), bytes)]);
            let error =
                validate_stale_contents(&contents, &[]).expect_err("stale name must fail");
            assert!(error.contains("forbidden stale public name"));
        }
    }

    #[test]
    fn exact_stale_name_allowance_passes() {
        let token = FORBIDDEN_STALE_NAMES[0].to_owned();
        let contents = BTreeMap::from([("history.md".to_owned(), token.as_bytes().to_vec())]);
        let allowances = [StaleNameAllowance {
            path: "history.md".to_owned(),
            token,
            reason: "Historical record".to_owned(),
        }];
        validate_stale_contents(&contents, &allowances).expect("exact allowance should pass");
    }

    #[test]
    fn unused_stale_name_allowance_fails() {
        let contents = BTreeMap::from([("history.md".to_owned(), b"Auths".to_vec())]);
        let allowances = [StaleNameAllowance {
            path: "history.md".to_owned(),
            token: FORBIDDEN_STALE_NAMES[0].to_owned(),
            reason: "Historical record".to_owned(),
        }];
        let error = validate_stale_contents(&contents, &allowances)
            .expect_err("unused allowance must fail");
        assert!(error.contains("no longer needed"));
    }
}
