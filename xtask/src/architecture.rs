#![allow(clippy::too_many_lines)]

use crate::*;

#[derive(Clone)]
pub(crate) struct ArchitectureLayer {
    pub(crate) path: String,
    pub(crate) allowed_dependencies: BTreeSet<String>,
    pub(crate) owners: BTreeSet<String>,
}

pub(crate) struct ArchitecturePolicy {
    pub(crate) layers: BTreeMap<String, ArchitectureLayer>,
    pub(crate) packages: BTreeMap<String, String>,
    pub(crate) workspace_edition: String,
    pub(crate) workspace_resolver: String,
    pub(crate) workspace_msrv: String,
    pub(crate) development_toolchain: String,
    pub(crate) core_forbidden_dependencies: BTreeSet<String>,
    pub(crate) core_default_feature_exceptions: BTreeSet<String>,
    pub(crate) approved_build_scripts: BTreeSet<String>,
    pub(crate) no_std_packages: BTreeSet<String>,
}

pub(crate) fn arch(update: bool) -> Result<(), String> {
    let policy = load_architecture_policy()?;
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not run cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err("cargo metadata failed".into());
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("invalid cargo metadata JSON: {error}"))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages")?;

    let workspace_names: BTreeSet<String> = packages
        .iter()
        .map(|package| {
            package["name"]
                .as_str()
                .ok_or_else(|| "workspace package has no name".to_owned())
                .map(str::to_owned)
        })
        .collect::<Result<_, _>>()?;
    let classified: BTreeSet<_> = policy.packages.keys().cloned().collect();
    if workspace_names != classified {
        let missing: Vec<_> = workspace_names.difference(&classified).cloned().collect();
        let stale: Vec<_> = classified.difference(&workspace_names).cloned().collect();
        return Err(format!(
            "architecture package classification drift; missing={missing:?}, stale={stale:?}"
        ));
    }

    check_workspace_rust_policy(&policy, packages)?;
    check_codeowners(&policy)?;
    let mut package_records = Vec::new();
    let mut dependency_records = Vec::new();
    let mut internal_edges = BTreeMap::<String, BTreeSet<String>>::new();
    for package in packages {
        let name = package["name"]
            .as_str()
            .ok_or("workspace package has no name")?;
        let layer_name = policy
            .packages
            .get(name)
            .ok_or_else(|| format!("package {name} is not classified"))?;
        let layer = policy
            .layers
            .get(layer_name)
            .ok_or_else(|| format!("package {name} names unknown layer {layer_name}"))?;
        let manifest = Path::new(
            package["manifest_path"]
                .as_str()
                .ok_or("workspace package has no manifest path")?,
        );
        let relative_manifest = manifest
            .strip_prefix(root())
            .map_err(|_| format!("package {name} is outside the repository"))?;
        let relative_directory = relative_manifest
            .parent()
            .ok_or_else(|| format!("package {name} has no package directory"))?;
        let relative_text = relative_directory.to_string_lossy().replace('\\', "/");
        let layer_path = layer.path.trim_end_matches('/');
        if relative_text != layer_path && !relative_text.starts_with(&format!("{layer_path}/")) {
            return Err(format!(
                "package {name} is classified as {layer_name} but lives at {relative_text}"
            ));
        }
        let has_build_script = package["targets"].as_array().is_some_and(|targets| {
            targets.iter().any(|target| {
                target["kind"].as_array().is_some_and(|kinds| {
                    kinds
                        .iter()
                        .any(|kind| kind.as_str() == Some("custom-build"))
                })
            })
        });
        if has_build_script && !policy.approved_build_scripts.contains(name) {
            return Err(format!(
                "workspace package {name} has an unapproved build script"
            ));
        }
        package_records.push(json!({
            "name": name,
            "layer": layer_name,
            "path": relative_text,
        }));
        internal_edges.entry(name.to_owned()).or_default();
        let dependencies = package["dependencies"]
            .as_array()
            .ok_or("package dependencies are not an array")?;
        for dependency in dependencies {
            let dependency_name = dependency["name"]
                .as_str()
                .ok_or("dependency has no name")?;
            let dependency_layer = policy.packages.get(dependency_name);
            if let Some(dependency_layer) = dependency_layer {
                if !layer.allowed_dependencies.contains(dependency_layer) {
                    return Err(format!(
                        "forbidden {layer_name} -> {dependency_layer} dependency: \
                         {name} -> {dependency_name}"
                    ));
                }
                internal_edges
                    .entry(name.to_owned())
                    .or_default()
                    .insert(dependency_name.to_owned());
            }
            if layer_name == "core"
                && dependency_layer.is_none()
                && policy.core_forbidden_dependencies.iter().any(|forbidden| {
                    dependency_name == forbidden
                        || dependency_name.starts_with(&format!("{forbidden}-"))
                })
            {
                return Err(format!(
                    "core capability dependency is forbidden: {name} -> {dependency_name}"
                ));
            }
            let kind = dependency["kind"].as_str().unwrap_or("normal");
            let uses_default_features = dependency["uses_default_features"]
                .as_bool()
                .unwrap_or(true);
            if layer_name == "core"
                && dependency_layer.is_none()
                && kind != "dev"
                && uses_default_features
                && !policy
                    .core_default_feature_exceptions
                    .contains(dependency_name)
            {
                return Err(format!(
                    "core dependency enables unapproved default features: \
                     {name} -> {dependency_name}"
                ));
            }
            let mut features: Vec<_> = dependency["features"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            features.sort();
            dependency_records.push((
                format!(
                    "{name}\0{dependency_name}\0{kind}\0{}\0{}",
                    dependency["target"].as_str().unwrap_or_default(),
                    dependency["optional"].as_bool().unwrap_or(false)
                ),
                json!({
                    "source": name,
                    "source_layer": layer_name,
                    "target": dependency_name,
                    "target_layer": dependency_layer,
                    "scope": if dependency_layer.is_some() { "internal" } else { "external" },
                    "kind": kind,
                    "target_condition": dependency["target"].as_str(),
                    "optional": dependency["optional"].as_bool().unwrap_or(false),
                    "default_features": uses_default_features,
                    "features": features,
                }),
            ));
        }
    }

    reject_dependency_cycles(&internal_edges)?;
    package_records.sort_by(|left, right| {
        left["name"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["name"].as_str().unwrap_or_default())
    });
    dependency_records.sort_by(|left, right| left.0.cmp(&right.0));
    let dependencies: Vec<_> = dependency_records
        .into_iter()
        .map(|(_, value)| value)
        .collect();
    let snapshot = json!({
        "schema": 1,
        "packages": package_records,
        "dependencies": dependencies,
    });
    let mut snapshot_bytes =
        serde_json::to_vec_pretty(&snapshot).map_err(|error| error.to_string())?;
    snapshot_bytes.push(b'\n');
    let dot = architecture_dot(&snapshot)?;
    let architecture_directory = root().join("architecture");
    let json_path = architecture_directory.join("dependency-graph.json");
    let dot_path = architecture_directory.join("dependency-graph.dot");
    if update {
        fs::create_dir_all(&architecture_directory)
            .map_err(|error| format!("could not create architecture directory: {error}"))?;
        fs::write(&json_path, &snapshot_bytes)
            .map_err(|error| format!("could not write {}: {error}", json_path.display()))?;
        fs::write(&dot_path, dot)
            .map_err(|error| format!("could not write {}: {error}", dot_path.display()))?;
        println!("architecture dependency snapshots updated");
        return Ok(());
    }
    let committed = fs::read(&json_path).map_err(|error| {
        format!(
            "could not read {}: {error}; run `cargo xtask arch --update`",
            json_path.display()
        )
    })?;
    if committed != snapshot_bytes {
        let previous: Value =
            serde_json::from_slice(&committed).map_err(|error| error.to_string())?;
        return Err(architecture_snapshot_diff(&previous, &snapshot));
    }
    let committed_dot = fs::read_to_string(&dot_path)
        .map_err(|error| format!("could not read {}: {error}", dot_path.display()))?;
    if committed_dot != dot {
        return Err(
            "architecture DOT snapshot drifted; run `cargo xtask arch --update`".to_owned(),
        );
    }
    println!("architecture policy and dependency snapshots passed");
    Ok(())
}

pub(crate) fn load_architecture_policy() -> Result<ArchitecturePolicy, String> {
    let source = fs::read_to_string(root().join("architecture.toml"))
        .map_err(|error| format!("could not read architecture.toml: {error}"))?;
    let document: toml::Value =
        toml::from_str(&source).map_err(|error| format!("invalid architecture.toml: {error}"))?;
    if document.get("schema").and_then(toml::Value::as_integer) != Some(1) {
        return Err("architecture.toml must declare schema = 1".to_owned());
    }
    let layer_table = document
        .get("layers")
        .and_then(toml::Value::as_table)
        .ok_or("architecture.toml has no layers table")?;
    let mut layers = BTreeMap::new();
    for (name, value) in layer_table {
        let table = value
            .as_table()
            .ok_or_else(|| format!("layer {name} is not a table"))?;
        layers.insert(
            name.clone(),
            ArchitectureLayer {
                path: required_toml_string(table, "path", name)?,
                allowed_dependencies: required_toml_strings(table, "allowed_dependencies", name)?,
                owners: required_toml_strings(table, "owners", name)?,
            },
        );
    }
    for (name, layer) in &layers {
        for allowed in &layer.allowed_dependencies {
            if !layers.contains_key(allowed) {
                return Err(format!("layer {name} allows unknown layer {allowed}"));
            }
        }
        if layer.owners.is_empty() {
            return Err(format!("layer {name} has no owners"));
        }
    }
    let packages = document
        .get("packages")
        .and_then(toml::Value::as_table)
        .ok_or("architecture.toml has no packages table")?
        .iter()
        .map(|(name, layer)| {
            let layer = layer
                .as_str()
                .ok_or_else(|| format!("package {name} layer is not a string"))?;
            if !layers.contains_key(layer) {
                return Err(format!("package {name} names unknown layer {layer}"));
            }
            Ok((name.clone(), layer.to_owned()))
        })
        .collect::<Result<_, String>>()?;
    let policy = document
        .get("policy")
        .and_then(toml::Value::as_table)
        .ok_or("architecture.toml has no policy table")?;
    let exceptions = document
        .get("exceptions")
        .and_then(toml::Value::as_table)
        .ok_or("architecture.toml has no exceptions table")?;
    if let Some((name, exception)) = exceptions.iter().next() {
        let table = exception
            .as_table()
            .ok_or_else(|| format!("architecture exception {name} is not a table"))?;
        for field in ["owner", "reason", "issue", "expires"] {
            required_toml_string(table, field, name)?;
        }
        return Err(format!(
            "architecture exception {name} exists; exception expiry validation must be \
             implemented before exceptions are accepted"
        ));
    }
    Ok(ArchitecturePolicy {
        layers,
        packages,
        workspace_edition: required_toml_string(policy, "workspace_edition", "policy")?,
        workspace_resolver: required_toml_string(policy, "workspace_resolver", "policy")?,
        workspace_msrv: required_toml_string(policy, "workspace_msrv", "policy")?,
        development_toolchain: required_toml_string(policy, "development_toolchain", "policy")?,
        core_forbidden_dependencies: required_toml_strings(
            policy,
            "core_forbidden_dependencies",
            "policy",
        )?,
        core_default_feature_exceptions: required_toml_strings(
            policy,
            "core_default_feature_exceptions",
            "policy",
        )?,
        approved_build_scripts: required_toml_strings(policy, "approved_build_scripts", "policy")?,
        no_std_packages: required_toml_strings(policy, "no_std_packages", "policy")?,
    })
}

pub(crate) fn check_workspace_rust_policy(
    policy: &ArchitecturePolicy,
    packages: &[Value],
) -> Result<(), String> {
    let workspace_source = fs::read_to_string(root().join("Cargo.toml"))
        .map_err(|error| format!("could not read workspace Cargo.toml: {error}"))?;
    let workspace_document: toml::Value = toml::from_str(&workspace_source)
        .map_err(|error| format!("invalid workspace Cargo.toml: {error}"))?;
    let workspace = workspace_document
        .get("workspace")
        .and_then(toml::Value::as_table)
        .ok_or("root Cargo.toml has no workspace table")?;
    let resolver = required_toml_string(workspace, "resolver", "workspace")?;
    if resolver != policy.workspace_resolver {
        return Err(format!(
            "workspace resolver must be {}, found {resolver}",
            policy.workspace_resolver
        ));
    }
    let package_policy = workspace
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or("root Cargo.toml has no workspace.package table")?;
    let edition = required_toml_string(package_policy, "edition", "workspace.package")?;
    if edition != policy.workspace_edition {
        return Err(format!(
            "workspace edition must be {}, found {edition}",
            policy.workspace_edition
        ));
    }
    let msrv = required_toml_string(package_policy, "rust-version", "workspace.package")?;
    if msrv != policy.workspace_msrv {
        return Err(format!(
            "workspace rust-version must be {}, found {msrv}",
            policy.workspace_msrv
        ));
    }

    for package in packages {
        let name = package["name"]
            .as_str()
            .ok_or("workspace package has no name")?;
        if package["edition"].as_str() != Some(policy.workspace_edition.as_str()) {
            return Err(format!(
                "package {name} does not resolve to edition {}",
                policy.workspace_edition
            ));
        }
        if package["rust_version"].as_str() != Some(policy.workspace_msrv.as_str()) {
            return Err(format!(
                "package {name} does not resolve to rust-version {}",
                policy.workspace_msrv
            ));
        }
        let manifest_path = Path::new(
            package["manifest_path"]
                .as_str()
                .ok_or("workspace package has no manifest path")?,
        );
        let manifest_source = fs::read_to_string(manifest_path)
            .map_err(|error| format!("could not read {}: {error}", manifest_path.display()))?;
        let manifest: toml::Value = toml::from_str(&manifest_source)
            .map_err(|error| format!("invalid {}: {error}", manifest_path.display()))?;
        let package_table = manifest
            .get("package")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("package {name} manifest has no package table"))?;
        for field in ["edition", "rust-version"] {
            let inherited = package_table
                .get(field)
                .and_then(toml::Value::as_table)
                .and_then(|value| value.get("workspace"))
                .and_then(toml::Value::as_bool)
                == Some(true);
            if !inherited {
                return Err(format!(
                    "package {name} must declare {field}.workspace = true"
                ));
            }
        }
    }

    let toolchain_source = fs::read_to_string(root().join("rust-toolchain.toml"))
        .map_err(|error| format!("could not read rust-toolchain.toml: {error}"))?;
    let toolchain_document: toml::Value = toml::from_str(&toolchain_source)
        .map_err(|error| format!("invalid rust-toolchain.toml: {error}"))?;
    let channel = toolchain_document
        .get("toolchain")
        .and_then(toml::Value::as_table)
        .and_then(|toolchain| toolchain.get("channel"))
        .and_then(toml::Value::as_str)
        .ok_or("rust-toolchain.toml has no toolchain.channel")?;
    if channel != policy.development_toolchain {
        return Err(format!(
            "development toolchain must be {}, found {channel}",
            policy.development_toolchain
        ));
    }

    let required_toolchains = [
        policy.development_toolchain.clone(),
        format!("{}.0", policy.workspace_msrv),
    ];
    for workflow in ["ci.yml", "release.yml"] {
        let path = root().join(".github/workflows").join(workflow);
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        for toolchain in &required_toolchains {
            let declaration = format!("toolchain: {toolchain}");
            let additional = format!("additional-toolchains: {toolchain}");
            if !source.lines().any(
                |line| matches!(line.trim(), value if value == declaration || value == additional),
            ) {
                return Err(format!(
                    "{} must install Rust toolchain {toolchain}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn required_toml_string(
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
    owner: &str,
) -> Result<String, String> {
    table
        .get(field)
        .and_then(toml::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("{owner}.{field} must be a non-empty string"))
}

pub(crate) fn required_toml_strings(
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
    owner: &str,
) -> Result<BTreeSet<String>, String> {
    table
        .get(field)
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("{owner}.{field} must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("{owner}.{field} contains a non-string or empty value"))
        })
        .collect()
}

pub(crate) fn check_codeowners(policy: &ArchitecturePolicy) -> Result<(), String> {
    let codeowners = fs::read_to_string(root().join(".github/CODEOWNERS"))
        .map_err(|error| format!("could not read CODEOWNERS: {error}"))?;
    for layer in policy.layers.values() {
        let pattern = if layer.path == "xtask" {
            "/xtask/".to_owned()
        } else {
            format!("/{}/", layer.path.trim_end_matches('/'))
        };
        let line = codeowners
            .lines()
            .find(|line| line.starts_with(&pattern))
            .ok_or_else(|| format!("CODEOWNERS has no entry for {pattern}"))?;
        for owner in &layer.owners {
            if !line.split_whitespace().any(|candidate| candidate == owner) {
                return Err(format!("CODEOWNERS entry {pattern} omits {owner}"));
            }
        }
    }
    Ok(())
}

pub(crate) fn reject_dependency_cycles(
    edges: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), String> {
    let mut remaining = edges.clone();
    loop {
        if remaining.is_empty() {
            return Ok(());
        }
        let removable: Vec<_> = remaining
            .iter()
            .filter(|(_, dependencies)| {
                dependencies
                    .iter()
                    .all(|dependency| !remaining.contains_key(dependency))
            })
            .map(|(name, _)| name.clone())
            .collect();
        if removable.is_empty() {
            return Err(format!(
                "workspace dependency cycle detected among {:?}",
                remaining.keys().collect::<Vec<_>>()
            ));
        }
        for name in removable {
            remaining.remove(&name);
        }
    }
}

pub(crate) fn architecture_dot(snapshot: &Value) -> Result<String, String> {
    let mut output = String::from("digraph auths_architecture {\n  rankdir=LR;\n");
    for package in snapshot["packages"]
        .as_array()
        .ok_or("architecture snapshot has no packages")?
    {
        let name = package["name"].as_str().ok_or("package has no name")?;
        let layer = package["layer"].as_str().ok_or("package has no layer")?;
        output.push_str(&format!("  \"{name}\" [group=\"{layer}\"];\n"));
    }
    for dependency in snapshot["dependencies"]
        .as_array()
        .ok_or("architecture snapshot has no dependencies")?
    {
        if dependency["scope"].as_str() != Some("internal") {
            continue;
        }
        let source = dependency["source"].as_str().ok_or("edge has no source")?;
        let target = dependency["target"].as_str().ok_or("edge has no target")?;
        let kind = dependency["kind"].as_str().ok_or("edge has no kind")?;
        output.push_str(&format!(
            "  \"{source}\" -> \"{target}\" [label=\"{kind}\"];\n"
        ));
    }
    output.push_str("}\n");
    Ok(output)
}

pub(crate) fn architecture_snapshot_diff(previous: &Value, current: &Value) -> String {
    fn edges(value: &Value) -> BTreeSet<String> {
        value["dependencies"]
            .as_array()
            .into_iter()
            .flatten()
            .map(Value::to_string)
            .collect()
    }
    let previous = edges(previous);
    let current = edges(current);
    let added: Vec<_> = current.difference(&previous).cloned().collect();
    let removed: Vec<_> = previous.difference(&current).cloned().collect();
    format!(
        "architecture dependency snapshot drifted\nadded={added:#?}\nremoved={removed:#?}\n\
         run `cargo xtask arch --update` after reviewing every edge"
    )
}

pub(crate) fn core_boundary() -> Result<(), String> {
    arch(false)?;
    let policy = load_architecture_policy()?;
    let package_paths = workspace_package_paths()?;
    for package in &policy.no_std_packages {
        if policy.packages.get(package).map(String::as_str) != Some("core") {
            return Err(format!(
                "no_std package {package} is missing or is not classified as core"
            ));
        }
        let package_root = package_paths
            .get(package)
            .ok_or_else(|| format!("no_std package {package} has no workspace path"))?;
        scan_restricted_core_source(package, &package_root.join("src"))?;
        let status = Command::new("cargo")
            .args(["check", "-p", package, "--no-default-features", "--locked"])
            .env("CARGO_NET_OFFLINE", "true")
            .current_dir(root())
            .status()
            .map_err(|error| format!("could not check no_std package {package}: {error}"))?;
        if !status.success() {
            return Err(format!(
                "no_std/offline build failed for {package} with {status}"
            ));
        }
    }
    for package in policy
        .packages
        .iter()
        .filter(|(_, layer)| layer.as_str() == "core")
        .map(|(name, _)| name)
    {
        let package_root = package_paths
            .get(package)
            .ok_or_else(|| format!("core package {package} has no workspace path"))?;
        let manifest = fs::read_to_string(package_root.join("Cargo.toml"))
            .map_err(|error| format!("could not read {package} manifest: {error}"))?;
        for line in manifest.lines().filter(|line| line.contains("path")) {
            if line.contains("../..") {
                return Err(format!(
                    "core manifest {package} has a path escaping core/: {line}"
                ));
            }
        }
    }
    repository_hygiene()?;
    println!("core offline, no_std, source, and repository boundaries passed");
    Ok(())
}

pub(crate) fn workspace_package_paths() -> Result<BTreeMap<String, PathBuf>, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not run cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err("cargo metadata failed".to_owned());
    }
    let metadata: Value =
        serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    metadata["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages")?
        .iter()
        .map(|package| {
            let name = package["name"]
                .as_str()
                .ok_or("workspace package has no name")?;
            let manifest = PathBuf::from(
                package["manifest_path"]
                    .as_str()
                    .ok_or("workspace package has no manifest")?,
            );
            let directory = manifest
                .parent()
                .ok_or("workspace manifest has no parent")?
                .to_path_buf();
            Ok((name.to_owned(), directory))
        })
        .collect()
}

pub(crate) fn scan_restricted_core_source(package: &str, source: &Path) -> Result<(), String> {
    const FORBIDDEN: [&str; 10] = [
        "std::env",
        "std::fs",
        "std::net",
        "std::process",
        "hyper::",
        "iroh::",
        "reqwest::",
        "rmcp::",
        "tokio::net",
        "tokio::process",
    ];
    for path in files_with_extension(source, "rs")? {
        let contents = fs::read_to_string(&path)
            .map_err(|error| format!("could not scan {}: {error}", path.display()))?;
        for forbidden in FORBIDDEN {
            if contents.contains(forbidden) {
                return Err(format!(
                    "restricted core package {package} uses {forbidden} in {}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn repository_hygiene() -> Result<(), String> {
    let repository = root();
    let mut locks = Vec::new();
    let mut nested_workspaces = Vec::new();
    let mut sibling_references = Vec::new();
    let mut canonical_corpus_manifests = Vec::new();
    for path in repository_files(&repository)? {
        let relative = path
            .strip_prefix(&repository)
            .map_err(|_| "repository traversal escaped root")?;
        if relative.file_name().and_then(|name| name.to_str()) == Some("Cargo.lock") {
            locks.push(relative.to_path_buf());
        }
        if relative.file_name().and_then(|name| name.to_str()) == Some("manifest.json")
            && relative
                .components()
                .any(|component| component.as_os_str() == "fixtures")
        {
            let manifest: Value = serde_json::from_slice(
                &fs::read(&path)
                    .map_err(|error| format!("could not read {}: {error}", path.display()))?,
            )
            .map_err(|error| format!("invalid fixture manifest {}: {error}", path.display()))?;
            if manifest["protocol"] == "Auths Proof Protocol V1"
                && manifest["protocol_major"] == 1
                && manifest["fixture_set"] == "target-v1"
            {
                canonical_corpus_manifests.push(relative.to_path_buf());
            }
        }
        if relative.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml")
            && relative != Path::new("Cargo.toml")
        {
            let manifest = fs::read_to_string(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?;
            if manifest.lines().any(|line| line.trim() == "[workspace]") {
                nested_workspaces.push(relative.to_path_buf());
            }
        }
        let scannable = matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("cjs" | "go" | "js" | "json" | "py" | "rs" | "toml" | "ts" | "yaml" | "yml")
        );
        if scannable {
            let contents = fs::read_to_string(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?;
            let sibling_needles = [
                ["..", "auths-proof", ""].join("/"),
                ["..", "auths-proof-apps", ""].join("/"),
                ["..", "auths-proof-exchange", ""].join("/"),
                ["auths-proof-apps", ""].join("/"),
            ];
            if sibling_needles
                .iter()
                .any(|needle| contents.contains(needle))
            {
                sibling_references.push(relative.to_path_buf());
            }
        }
    }
    if locks != [PathBuf::from("Cargo.lock")] {
        return Err(format!(
            "repository must contain exactly one root Cargo.lock, found {locks:?}"
        ));
    }
    if !nested_workspaces.is_empty() {
        return Err(format!(
            "nested Cargo workspaces are forbidden: {nested_workspaces:?}"
        ));
    }
    if canonical_corpus_manifests != [PathBuf::from("core/fixtures/v1/manifest.json")] {
        return Err(format!(
            "canonical fixture manifest must have one core owner, found \
             {canonical_corpus_manifests:?}"
        ));
    }
    if !sibling_references.is_empty() {
        return Err(format!(
            "sibling-repository path assumptions remain: {sibling_references:?}"
        ));
    }
    let tracked = command_output_in("git", &["ls-files"], &repository, None)?;
    let generated: Vec<_> = tracked
        .lines()
        .filter(|path| {
            repository.join(path).exists()
                && (path.contains("/node_modules/")
                    || path.contains("/__pycache__/")
                    || path.ends_with(".so")
                    || path.starts_with("bindings/typescript/dist/")
                    || path.starts_with("bindings/typescript/wasm/"))
        })
        .collect();
    if !generated.is_empty() {
        return Err(format!(
            "generated build outputs are tracked and must be recreated: {generated:?}"
        ));
    }
    check_workflow_action_pins()?;
    Ok(())
}

pub(crate) fn check_workflow_action_pins() -> Result<(), String> {
    let mut action_sources = Vec::new();
    for directory in [".github/workflows", ".github/actions"] {
        let directory = root().join(directory);
        action_sources.extend(files_with_extension(&directory, "yml")?);
        action_sources.extend(files_with_extension(&directory, "yaml")?);
    }
    action_sources.sort();
    for path in action_sources {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        for (index, line) in source.lines().enumerate() {
            let Some(reference) = line.trim().strip_prefix("- uses: ") else {
                continue;
            };
            if reference.starts_with("./") {
                continue;
            }
            let revision = reference
                .split('#')
                .next()
                .unwrap_or(reference)
                .trim()
                .rsplit_once('@')
                .map(|(_, revision)| revision)
                .ok_or_else(|| {
                    format!(
                        "{}:{} action has no revision",
                        path.display(),
                        index.saturating_add(1)
                    )
                })?;
            if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!(
                    "{}:{} action is not pinned to an immutable commit: {reference}",
                    path.display(),
                    index.saturating_add(1)
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn repository_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
    fn visit(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(directory)
            .map_err(|error| format!("could not read {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|value| value.to_str());
                if matches!(
                    name,
                    Some(
                        ".git"
                            | ".lake"
                            | ".pytest_cache"
                            | "__pycache__"
                            | "node_modules"
                            | "target"
                    )
                ) {
                    continue;
                }
                visit(&path, output)?;
            } else {
                output.push(path);
            }
        }
        Ok(())
    }
    let mut output = Vec::new();
    visit(directory, &mut output)?;
    output.sort();
    Ok(output)
}

pub(crate) fn files_with_extension(
    directory: &Path,
    extension: &str,
) -> Result<Vec<PathBuf>, String> {
    let mut files: Vec<_> = repository_files(directory)?
        .into_iter()
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some(extension))
        .collect();
    files.sort();
    Ok(files)
}
