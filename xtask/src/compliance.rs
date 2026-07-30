#![allow(clippy::too_many_lines)]

use crate::*;

pub(crate) fn compliance() -> Result<(), String> {
    let inventory = compliance_inventory()?;
    arch(false)?;
    layer_check("product")?;
    abi()?;
    exchange_conformance()?;
    product_conformance()?;
    product_fixtures(false)?;
    stripe_profiles()?;
    bounded_domains()?;
    matrix()?;
    bindings_check()?;
    package_check()?;
    live_demo()?;
    write_compliance_report(&inventory)
}

pub(crate) const COMPLIANCE_ROLES: [&str; 16] = [
    "configuration-compiler",
    "core-api-consumer",
    "core-wire-consumer",
    "core-wire-producer",
    "demo-conformance-fixture",
    "independent-semantic-implementation",
    "language-binding",
    "operational-diagnostics",
    "principal-evidence-integration",
    "profile-canonicalizer",
    "profile-contract",
    "proof-author-or-assembler",
    "receipt-producer-consumer",
    "runtime-enforcement-boundary",
    "stateful-replay-budget-component",
    "verification-cache",
];

pub(crate) const COMPLIANCE_SURFACES: [&str; 10] = [
    "configuration_inputs",
    "core_apis",
    "fixture_suites",
    "principal_families",
    "profiles",
    "protocol_versions",
    "security_state",
    "signature_families",
    "transports",
    "wire_objects",
];

pub(crate) fn compliance_inventory() -> Result<Value, String> {
    let manifest_path = root().join("compliance.toml");
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("could not read {}: {error}", manifest_path.display()))?;
    let manifest_source = String::from_utf8(manifest_bytes.clone())
        .map_err(|error| format!("compliance.toml is not UTF-8: {error}"))?;
    let document: toml::Value = toml::from_str(&manifest_source)
        .map_err(|error| format!("invalid compliance.toml: {error}"))?;
    if document.get("schema").and_then(toml::Value::as_integer) != Some(1) {
        return Err("compliance.toml must declare schema = 1".to_owned());
    }
    let canonical_corpus = document
        .get("canonical_corpus")
        .and_then(toml::Value::as_str)
        .ok_or("compliance.toml has no canonical_corpus")?;
    let portable_abi_version = document
        .get("portable_abi_version")
        .and_then(toml::Value::as_integer)
        .ok_or("compliance.toml has no portable_abi_version")?;
    let report_schema = document
        .get("report_schema")
        .and_then(toml::Value::as_str)
        .ok_or("compliance.toml has no report_schema")?;
    let scope_layers = compliance_strings(
        document
            .get("scope_layers")
            .ok_or("compliance.toml has no scope_layers")?,
        "scope_layers",
    )?;
    let policy = load_architecture_policy()?;
    for layer in &scope_layers {
        if !policy.layers.contains_key(layer) {
            return Err(format!("compliance scope names unknown layer {layer}"));
        }
    }

    let metadata_output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not inspect compliance packages: {error}"))?;
    if !metadata_output.status.success() {
        return Err("cargo metadata failed while building compliance inventory".to_owned());
    }
    let metadata: Value = serde_json::from_slice(&metadata_output.stdout)
        .map_err(|error| format!("invalid cargo metadata JSON: {error}"))?;
    let metadata_packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages")?;
    let cargo_packages: BTreeMap<_, _> = metadata_packages
        .iter()
        .map(|package| {
            package["name"]
                .as_str()
                .map(|name| (name.to_owned(), package))
                .ok_or_else(|| "cargo metadata package has no name".to_owned())
        })
        .collect::<Result<_, _>>()?;
    let expected_cargo: BTreeSet<_> = policy
        .packages
        .iter()
        .filter(|(_, layer)| scope_layers.contains(*layer))
        .map(|(name, _)| name.clone())
        .collect();
    let package_table = document
        .get("packages")
        .and_then(toml::Value::as_table)
        .ok_or("compliance.toml has no packages table")?;
    let mut declared_cargo = BTreeSet::new();
    let mut declared_external = BTreeMap::new();
    let mut records = Vec::new();

    for (name, value) in package_table {
        let table = value
            .as_table()
            .ok_or_else(|| format!("compliance package {name} is not a table"))?;
        let kind = required_toml_string(table, "kind", name)?;
        let layer = required_toml_string(table, "layer", name)?;
        let path = required_toml_string(table, "path", name)?;
        if !scope_layers.contains(&layer) {
            return Err(format!(
                "compliance package {name} is in out-of-scope layer {layer}"
            ));
        }
        let mut surfaces = BTreeMap::new();
        for field in COMPLIANCE_SURFACES {
            let values = compliance_strings(
                table
                    .get(field)
                    .ok_or_else(|| format!("compliance package {name} omits {field}"))?,
                &format!("packages.{name}.{field}"),
            )?;
            surfaces.insert(field, values);
        }
        if surfaces["protocol_versions"].is_empty() {
            return Err(format!(
                "compliance package {name} declares no protocol version"
            ));
        }
        let claims = table
            .get("claims")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("compliance package {name} has no claims table"))?;
        if claims.is_empty() {
            return Err(format!("compliance package {name} has no claims"));
        }
        let mut claim_records = BTreeMap::new();
        for (role, evidence_value) in claims {
            if !COMPLIANCE_ROLES.contains(&role.as_str()) {
                return Err(format!(
                    "compliance package {name} declares unknown role {role}"
                ));
            }
            let evidence =
                compliance_strings(evidence_value, &format!("packages.{name}.claims.{role}"))?;
            if evidence.is_empty() {
                return Err(format!(
                    "compliance package {name} role {role} has no test evidence"
                ));
            }
            for anchor in &evidence {
                validate_compliance_evidence(name, anchor)?;
            }
            validate_compliance_role(name, role, &surfaces)?;
            claim_records.insert(role.clone(), evidence);
        }

        match kind.as_str() {
            "cargo" => {
                let package = cargo_packages.get(name).ok_or_else(|| {
                    format!("declared Cargo package {name} is not in the workspace")
                })?;
                let expected_layer = policy
                    .packages
                    .get(name)
                    .ok_or_else(|| format!("Cargo package {name} has no architecture layer"))?;
                if expected_layer != &layer {
                    return Err(format!(
                        "compliance package {name} layer {layer} disagrees with architecture layer \
                         {expected_layer}"
                    ));
                }
                let manifest = Path::new(
                    package["manifest_path"]
                        .as_str()
                        .ok_or_else(|| format!("Cargo package {name} has no manifest path"))?,
                );
                let actual_path = manifest
                    .parent()
                    .ok_or_else(|| format!("Cargo package {name} manifest has no parent"))?
                    .strip_prefix(root())
                    .map_err(|_| format!("Cargo package {name} is outside the repository"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                if actual_path != path {
                    return Err(format!(
                        "compliance package {name} path {path} disagrees with {actual_path}"
                    ));
                }
                let actual_core_apis: BTreeSet<_> = package["dependencies"]
                    .as_array()
                    .ok_or_else(|| format!("Cargo package {name} dependencies are not an array"))?
                    .iter()
                    .filter_map(|dependency| dependency["name"].as_str())
                    .filter(|dependency| {
                        policy.packages.get(*dependency).map(String::as_str) == Some("core")
                    })
                    .map(str::to_owned)
                    .collect();
                if actual_core_apis != surfaces["core_apis"] {
                    return Err(format!(
                        "compliance package {name} core API declaration drifted; \
                         declared={:?}, actual={actual_core_apis:?}",
                        surfaces["core_apis"]
                    ));
                }
                declared_cargo.insert(name.clone());
            }
            "npm" | "go" => {
                if declared_external
                    .insert(name.clone(), (kind.clone(), path.clone()))
                    .is_some()
                {
                    return Err(format!("duplicate external compliance package {name}"));
                }
            }
            _ => {
                return Err(format!(
                    "compliance package {name} has unsupported kind {kind}"
                ));
            }
        }

        records.push(json!({
            "name": name,
            "kind": kind,
            "layer": layer,
            "path": path,
            "surfaces": surfaces,
            "claims": claim_records,
        }));
    }

    if declared_cargo != expected_cargo {
        let missing: Vec<_> = expected_cargo.difference(&declared_cargo).collect();
        let stale: Vec<_> = declared_cargo.difference(&expected_cargo).collect();
        return Err(format!(
            "Cargo compliance inventory drift; missing={missing:?}, stale={stale:?}"
        ));
    }
    let discovered_external = discover_external_compliance_packages(&scope_layers, &policy)?;
    if declared_external != discovered_external {
        return Err(format!(
            "external compliance inventory drift; declared={declared_external:?}, \
             discovered={discovered_external:?}"
        ));
    }
    records.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));

    let corpus_path = root().join(canonical_corpus);
    let architecture_path = root().join("architecture/dependency-graph.json");
    let inventory = json!({
        "schema": report_schema,
        "kind": "inventory",
        "portable_abi_version": portable_abi_version,
        "scope_layers": scope_layers,
        "inputs": {
            "compliance_manifest": {
                "path": "compliance.toml",
                "sha256": hex::encode(Sha256::digest(&manifest_bytes)),
            },
            "architecture_snapshot": {
                "path": "architecture/dependency-graph.json",
                "sha256": sha256_file(&architecture_path)?,
            },
            "canonical_corpus": {
                "path": canonical_corpus,
                "sha256": sha256_file(&corpus_path)?,
            },
        },
        "packages": records,
    });
    let output = root().join("target/compliance/inventory.json");
    write_pretty_json(&output, &inventory)?;
    println!(
        "compliance inventory covers {} declared product surfaces",
        inventory["packages"].as_array().map_or(0, Vec::len)
    );
    Ok(inventory)
}

pub(crate) fn compliance_strings(
    value: &toml::Value,
    owner: &str,
) -> Result<BTreeSet<String>, String> {
    let values = value
        .as_array()
        .ok_or_else(|| format!("{owner} must be an array"))?;
    let parsed: Vec<_> = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("{owner} contains a non-string or empty value"))
        })
        .collect::<Result<_, _>>()?;
    let result: BTreeSet<_> = parsed.iter().cloned().collect();
    if result.len() != parsed.len() {
        return Err(format!("{owner} contains duplicate values"));
    }
    Ok(result)
}

pub(crate) fn validate_compliance_role(
    package: &str,
    role: &str,
    surfaces: &BTreeMap<&str, BTreeSet<String>>,
) -> Result<(), String> {
    let require = |field: &'static str| {
        if surfaces[field].is_empty() {
            Err(format!(
                "compliance package {package} role {role} requires a non-empty {field}"
            ))
        } else {
            Ok(())
        }
    };
    match role {
        "core-api-consumer" => require("core_apis")?,
        "core-wire-consumer" | "core-wire-producer" | "language-binding" => {
            require("wire_objects")?;
            require("fixture_suites")?;
        }
        "independent-semantic-implementation" => {
            require("wire_objects")?;
            require("fixture_suites")?;
            require("configuration_inputs")?;
        }
        "profile-canonicalizer" | "profile-contract" => require("profiles")?,
        "proof-author-or-assembler" | "receipt-producer-consumer" => require("wire_objects")?,
        "principal-evidence-integration" => require("principal_families")?,
        "runtime-enforcement-boundary" => {
            require("configuration_inputs")?;
        }
        "stateful-replay-budget-component" | "verification-cache" => {
            require("configuration_inputs")?;
            require("security_state")?;
        }
        "configuration-compiler" | "operational-diagnostics" => {
            require("configuration_inputs")?;
        }
        "demo-conformance-fixture" => require("fixture_suites")?,
        _ => {}
    }
    Ok(())
}

pub(crate) fn validate_compliance_evidence(package: &str, anchor: &str) -> Result<(), String> {
    let (relative, marker) = anchor.split_once('#').ok_or_else(|| {
        format!("compliance package {package} evidence must use '<path>#<test>': {anchor}")
    })?;
    if marker.is_empty() {
        return Err(format!(
            "compliance package {package} has an empty evidence marker"
        ));
    }
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        || relative_path.extension().and_then(|value| value.to_str()) == Some("md")
    {
        return Err(format!(
            "compliance package {package} has invalid evidence path {relative}"
        ));
    }
    let path = root().join(relative_path);
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("could not read compliance evidence {relative}: {error}"))?;
    let extension = relative_path
        .extension()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("compliance evidence {relative} has no extension"))?;
    let is_test = match extension {
        "rs" => {
            (contents.contains("#[test]") || contents.contains("#[tokio::test]"))
                && (contents.contains(&format!("fn {marker}("))
                    || contents.contains(&format!("fn {marker}<")))
        }
        "js" | "cjs" | "mjs" | "ts" => contents.contains("test(") && contents.contains(marker),
        "py" => marker.starts_with("test_") && contents.contains(&format!("def {marker}(")),
        "go" => marker.starts_with("Test") && contents.contains(&format!("func {marker}(")),
        _ => false,
    };
    if !is_test {
        return Err(format!(
            "compliance package {package} evidence is not an executable test anchor: {anchor}"
        ));
    }
    Ok(())
}

pub(crate) fn discover_external_compliance_packages(
    scope_layers: &BTreeSet<String>,
    policy: &ArchitecturePolicy,
) -> Result<BTreeMap<String, (String, String)>, String> {
    let scoped_paths: Vec<_> = scope_layers
        .iter()
        .filter_map(|layer| policy.layers.get(layer))
        .map(|layer| layer.path.trim_end_matches('/').to_owned())
        .collect();
    let mut discovered = BTreeMap::new();
    for path in repository_files(&root())? {
        let relative = path
            .strip_prefix(root())
            .map_err(|_| format!("repository file escaped root: {}", path.display()))?;
        let relative_text = relative.to_string_lossy().replace('\\', "/");
        if !scoped_paths.iter().any(|prefix| {
            relative_text == *prefix || relative_text.starts_with(&format!("{prefix}/"))
        }) {
            continue;
        }
        match path.file_name().and_then(|value| value.to_str()) {
            Some("go.mod") => {
                let source = fs::read_to_string(&path)
                    .map_err(|error| format!("could not read {}: {error}", path.display()))?;
                let name = source
                    .lines()
                    .find_map(|line| line.strip_prefix("module "))
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| format!("{} has no Go module name", path.display()))?;
                let package_path = relative
                    .parent()
                    .ok_or_else(|| format!("{} has no parent", path.display()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                discovered.insert(name.to_owned(), ("go".to_owned(), package_path));
            }
            Some("package.json") => {
                let source = fs::read(&path)
                    .map_err(|error| format!("could not read {}: {error}", path.display()))?;
                let package: Value = serde_json::from_slice(&source)
                    .map_err(|error| format!("invalid {}: {error}", path.display()))?;
                if package["private"].as_bool() == Some(true) {
                    continue;
                }
                let directory = path
                    .parent()
                    .ok_or_else(|| format!("{} has no parent", path.display()))?;
                let mut ancestor = directory.parent();
                let mut nested = false;
                while let Some(candidate) = ancestor {
                    if candidate == root() {
                        break;
                    }
                    if candidate.join("package.json").is_file() {
                        nested = true;
                        break;
                    }
                    ancestor = candidate.parent();
                }
                if nested {
                    continue;
                }
                let name = package["name"]
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| format!("{} has no npm package name", path.display()))?;
                package["version"]
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| format!("{} has no npm package version", path.display()))?;
                let package_path = directory
                    .strip_prefix(root())
                    .map_err(|_| format!("npm package {} escaped root", path.display()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                discovered.insert(name.to_owned(), ("npm".to_owned(), package_path));
            }
            _ => {}
        }
    }
    Ok(discovered)
}

pub(crate) fn write_compliance_report(inventory: &Value) -> Result<(), String> {
    let inventory_path = root().join("target/compliance/inventory.json");
    let semantic_digest = semantic_digest_value()?;
    let package_count = inventory["packages"].as_array().map_or(0, Vec::len);
    let claim_count = inventory["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|package| package["claims"].as_object())
        .map(serde_json::Map::len)
        .sum::<usize>();
    let checks = [
        "abi-schema-and-canonical-corpus",
        "architecture-and-core-api-declarations",
        "built-language-packages",
        "compliance-inventory",
        "differential-semantic-agreement",
        "exchange-transport-conformance",
        "product-profile-fixtures",
        "product-runtime-and-state-machines",
        "receipt-and-audit-invariants",
    ];
    let report = json!({
        "schema": inventory["schema"],
        "kind": "report",
        "status": "passed",
        "inventory_sha256": sha256_file(&inventory_path)?,
        "semantic_digest": semantic_digest,
        "summary": {
            "packages": package_count,
            "claims": claim_count,
            "checks": checks.len(),
        },
        "checks": checks.iter().map(|name| json!({
            "name": name,
            "status": "passed",
        })).collect::<Vec<_>>(),
    });
    let directory = root().join("target/compliance");
    write_pretty_json(&directory.join("report.json"), &report)?;
    let summary = format!(
        "Auths product/core compliance: PASSED\n\
         Packages: {package_count}\n\
         Claims: {claim_count}\n\
         Checks: {}\n\
         Semantic digest: {semantic_digest}\n",
        checks.len()
    );
    fs::write(directory.join("summary.txt"), summary)
        .map_err(|error| format!("could not write compliance summary: {error}"))?;
    println!(
        "product/core compliance passed: {package_count} packages, {claim_count} claims, {} checks",
        checks.len()
    );
    Ok(())
}

pub(crate) fn write_pretty_json(path: &Path, value: &Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not encode JSON: {error}"))?;
    bytes.push(b'\n');
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    fs::write(path, bytes).map_err(|error| format!("could not write {}: {error}", path.display()))
}
