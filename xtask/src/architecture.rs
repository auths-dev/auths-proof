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
    pub(crate) dependency_boundaries: BTreeMap<String, DependencyBoundary>,
    pub(crate) workspace_edition: String,
    pub(crate) workspace_resolver: String,
    pub(crate) workspace_msrv: String,
    pub(crate) development_toolchain: String,
    pub(crate) core_forbidden_dependencies: BTreeSet<String>,
    pub(crate) core_default_feature_exceptions: BTreeSet<String>,
    pub(crate) approved_build_scripts: BTreeSet<String>,
    pub(crate) no_std_packages: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DependencyBoundary {
    pub(crate) roots: BTreeSet<String>,
    pub(crate) allowed_workspace_dependencies: BTreeSet<String>,
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
            const PRINCIPAL_ADAPTERS: [&str; 5] = [
                "auths-hsm-attested",
                "auths-oidc-workload",
                "auths-sigstore-keyless",
                "auths-spiffe-x509",
                "auths-webauthn",
            ];
            const PRINCIPAL_CRYPTO_DEPENDENCIES: [&str; 7] = [
                "ed25519-dalek",
                "p256",
                "ring",
                "rsa",
                "rustls-pki-types",
                "rustls-webpki",
                "webpki",
            ];
            let kind = dependency["kind"].as_str().unwrap_or("normal");
            if kind != "dev"
                && PRINCIPAL_ADAPTERS.contains(&name)
                && PRINCIPAL_CRYPTO_DEPENDENCIES.contains(&dependency_name)
            {
                return Err(format!(
                    "principal adapter owns a forbidden crypto/path dependency: \
                     {name} -> {dependency_name}"
                ));
            }
            if let Some(dependency_layer) = dependency_layer {
                if !layer.allowed_dependencies.contains(dependency_layer) {
                    return Err(format!(
                        "forbidden {layer_name} -> {dependency_layer} dependency: \
                         {name} -> {dependency_name}"
                    ));
                }
                if kind != "dev" {
                    internal_edges
                        .entry(name.to_owned())
                        .or_default()
                        .insert(dependency_name.to_owned());
                }
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
    check_dependency_boundaries(&policy, &internal_edges)?;
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
    let packages: BTreeMap<String, String> = document
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
    let dependency_boundaries = document
        .get("dependency_boundaries")
        .and_then(toml::Value::as_table)
        .ok_or("architecture.toml has no dependency_boundaries table")?
        .iter()
        .map(|(name, value)| {
            let table = value
                .as_table()
                .ok_or_else(|| format!("dependency boundary {name} is not a table"))?;
            let boundary = DependencyBoundary {
                roots: required_toml_strings(table, "roots", name)?,
                allowed_workspace_dependencies: required_toml_strings(
                    table,
                    "allowed_workspace_dependencies",
                    name,
                )?,
            };
            if boundary.roots.is_empty() {
                return Err(format!("dependency boundary {name} has no roots"));
            }
            for package in boundary
                .roots
                .iter()
                .chain(&boundary.allowed_workspace_dependencies)
            {
                if !packages.contains_key(package) {
                    return Err(format!(
                        "dependency boundary {name} names unknown package {package}"
                    ));
                }
            }
            Ok((name.clone(), boundary))
        })
        .collect::<Result<_, String>>()?;
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
        dependency_boundaries,
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

pub(crate) fn check_dependency_boundaries(
    policy: &ArchitecturePolicy,
    edges: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), String> {
    for (name, boundary) in &policy.dependency_boundaries {
        for root in &boundary.roots {
            let mut pending = edges.get(root).cloned().unwrap_or_default();
            let mut reachable = BTreeSet::new();
            while let Some(package) = pending.pop_first() {
                if !reachable.insert(package.clone()) {
                    continue;
                }
                if let Some(dependencies) = edges.get(&package) {
                    pending.extend(dependencies.iter().cloned());
                }
            }
            let forbidden: Vec<_> = reachable
                .difference(&boundary.allowed_workspace_dependencies)
                .cloned()
                .collect();
            if !forbidden.is_empty() {
                return Err(format!(
                    "dependency boundary {name} forbids transitive workspace dependencies from \
                     {root}: {forbidden:?}"
                ));
            }
        }
    }
    Ok(())
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
        let manifest: toml::Value = toml::from_str(&manifest)
            .map_err(|error| format!("could not parse {package} manifest: {error}"))?;
        let mut dependency_paths = Vec::new();
        collect_dependency_paths(&manifest, &mut dependency_paths);
        let core_root = fs::canonicalize(root().join("core"))
            .map_err(|error| format!("could not resolve core boundary: {error}"))?;
        for dependency_path in dependency_paths {
            let dependency_path = Path::new(dependency_path);
            if dependency_path.is_absolute() {
                return Err(format!(
                    "core manifest {package} has an absolute dependency path: {}",
                    dependency_path.display()
                ));
            }
            let resolved =
                fs::canonicalize(package_root.join(dependency_path)).map_err(|error| {
                    format!(
                        "core manifest {package} has an unresolved dependency path {}: {error}",
                        dependency_path.display()
                    )
                })?;
            if !resolved.starts_with(&core_root) {
                return Err(format!(
                    "core manifest {package} has a dependency path escaping core/: {}",
                    dependency_path.display()
                ));
            }
        }
    }
    repository_hygiene()?;
    println!("core offline, no_std, source, and repository boundaries passed");
    Ok(())
}

fn collect_dependency_paths<'a>(value: &'a toml::Value, paths: &mut Vec<&'a str>) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, nested) in table {
        if matches!(
            key.as_str(),
            "dependencies" | "dev-dependencies" | "build-dependencies"
        ) {
            if let Some(dependencies) = nested.as_table() {
                paths.extend(dependencies.values().filter_map(|dependency| {
                    dependency
                        .as_table()
                        .and_then(|specification| specification.get("path"))
                        .and_then(toml::Value::as_str)
                }));
            }
        } else {
            collect_dependency_paths(nested, paths);
        }
    }
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
                    || path.starts_with("bindings/typescript/wasm/")
                    || (path.starts_with("bindings/")
                        && (path.ends_with(".tgz") || path.ends_with(".whl"))))
        })
        .collect();
    if !generated.is_empty() {
        return Err(format!(
            "generated build outputs are tracked and must be recreated: {generated:?}"
        ));
    }
    check_workflow_action_pins()?;
    check_workflow_script_expressions()?;
    Ok(())
}

fn workflow_sources() -> Result<Vec<PathBuf>, String> {
    let mut sources = Vec::new();
    for directory in [".github/workflows", ".github/actions"] {
        let directory = root().join(directory);
        sources.extend(files_with_extension(&directory, "yml")?);
        sources.extend(files_with_extension(&directory, "yaml")?);
    }
    sources.sort();
    Ok(sources)
}

/// Requires every action and reusable workflow to be pinned: each step's and
/// each job's `uses` names a local path or a full 40-hex commit. `uses` is
/// found by the structural step reader, wherever it sits among a step's keys.
pub(crate) fn check_workflow_action_pins() -> Result<(), String> {
    for path in workflow_sources()? {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        check_action_pins(&source).map_err(|error| format!("{}:{error}", path.display()))?;
    }
    Ok(())
}

fn check_action_pins(source: &str) -> Result<(), String> {
    let lines = workflow_lines(source)?;
    for job in workflow_jobs(&lines)? {
        for fields in std::iter::once(&job.fields).chain(&job.steps) {
            let Some(uses) = unique_entry(fields, "uses")? else {
                continue;
            };
            let reference = unquoted(uses.inline);
            if reference.starts_with("./") {
                continue;
            }
            let revision = reference
                .rsplit_once('@')
                .map(|(_, revision)| revision)
                .ok_or_else(|| format!("{}: action has no revision", uses.number))?;
            if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!(
                    "{}: action is not pinned to an immutable commit: {reference}",
                    uses.number
                ));
            }
        }
    }
    Ok(())
}

/// Property names whose values a contributor, pull-request author or workflow
/// dispatcher chooses: refs and branch names, titles, bodies, commit messages,
/// labels and commit authors. A `workflow_ref` ends in the ref the run started
/// from.
const UNTRUSTED_EXPRESSION_PROPERTIES: [&str; 15] = [
    "author",
    "base_ref",
    "body",
    "committer",
    "default_branch",
    "display_title",
    "head_branch",
    "head_ref",
    "label",
    "message",
    "page_name",
    "ref",
    "ref_name",
    "title",
    "workflow_ref",
];

/// Refuses `${{ ... }}` expressions that Actions would splice into step
/// source. Actions substitutes expressions into a step before it runs, so the
/// value becomes JavaScript inside an `actions/github-script` `script` and
/// shell inside a `run` script; values must reach both through the step's
/// `env`.
///
/// A `script` may contain no expression at all. A `run` script may not read a
/// property named in `UNTRUSTED_EXPRESSION_PROPERTIES` at any depth, or the
/// whole `github` or `github.event` object. Steps are found structurally
/// under `jobs.<id>.steps` and `runs.steps`; a workflow outside the
/// block-style YAML this reader understands is refused, not skipped.
pub(crate) fn check_workflow_script_expressions() -> Result<(), String> {
    for path in workflow_sources()? {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        check_step_script_expressions(&source)
            .map_err(|error| format!("{}:{error}", path.display()))?;
    }
    Ok(())
}

/// One workflow line: its 1-based number, indentation and remaining text.
#[derive(Clone, Copy)]
struct WorkflowLine<'a> {
    number: usize,
    indent: usize,
    text: &'a str,
}

impl WorkflowLine<'_> {
    fn is_trivia(self) -> bool {
        self.text.is_empty() || self.text.starts_with('#')
    }
}

/// One block-mapping entry and every line nested under it.
struct WorkflowEntry<'s, 'a> {
    number: usize,
    key: &'a str,
    inline: &'a str,
    body: &'s [WorkflowLine<'a>],
}

/// The keys of one job, or of a composite action's `runs`, and the keys of
/// each of its steps.
struct WorkflowJob<'s, 'a> {
    fields: Vec<WorkflowEntry<'s, 'a>>,
    steps: Vec<Vec<WorkflowEntry<'s, 'a>>>,
}

fn workflow_lines(source: &str) -> Result<Vec<WorkflowLine<'_>>, String> {
    source
        .lines()
        .enumerate()
        .map(|(index, line)| {
            let text = line.trim_start_matches(' ');
            if text.starts_with('\t') {
                return Err(format!("{}: tab indentation is not supported", index + 1));
            }
            Ok(WorkflowLine {
                number: index + 1,
                indent: line.len() - text.len(),
                text: text.trim_end(),
            })
        })
        .collect()
}

/// Reads jobs from `jobs.<id>` and a composite action's `runs`, and their
/// steps from `steps`. A shape this reader does not understand is an error,
/// so a check built on it cannot skip a step.
fn workflow_jobs<'s, 'a>(
    lines: &'s [WorkflowLine<'a>],
) -> Result<Vec<WorkflowJob<'s, 'a>>, String> {
    let mut jobs = Vec::new();
    for entry in block_mapping(None, lines)? {
        let owners = match entry.key {
            "jobs" => block_mapping(None, nested(&entry)?)?,
            "runs" => vec![entry],
            _ => continue,
        };
        for owner in owners {
            let fields = block_mapping(None, nested(&owner)?)?;
            let mut steps = Vec::new();
            if let Some(sequence) = unique_entry(&fields, "steps")? {
                for (head, rest) in block_sequence(nested(sequence)?)? {
                    steps.push(block_mapping(head, rest)?);
                }
            }
            jobs.push(WorkflowJob { fields, steps });
        }
    }
    Ok(jobs)
}

fn check_step_script_expressions(source: &str) -> Result<(), String> {
    let lines = workflow_lines(source)?;
    for job in workflow_jobs(&lines)? {
        for step in &job.steps {
            check_step(step)?;
        }
    }
    Ok(())
}

fn check_step(fields: &[WorkflowEntry<'_, '_>]) -> Result<(), String> {
    if let Some(run) = unique_entry(fields, "run")? {
        check_run_expressions(run)?;
    }
    let github_script = unique_entry(fields, "uses")?.is_some_and(|uses| {
        unquoted(uses.inline)
            .to_ascii_lowercase()
            .starts_with("actions/github-script@")
    });
    if !github_script {
        return Ok(());
    }
    let step = fields.first().map_or(0, |field| field.number);
    let missing = || format!("{step}: actions/github-script step has no block `with.script`");
    let inputs = block_mapping(
        None,
        nested(unique_entry(fields, "with")?.ok_or_else(missing)?)?,
    )?;
    let script = unique_entry(&inputs, "script")?.ok_or_else(missing)?;
    if let Some((number, _)) = scalar_lines(script).find(|(_, text)| text.contains("${{")) {
        return Err(format!(
            "{number}: actions/github-script source contains a `${{{{ }}}}` expression; \
             pass the value through the step's env and read process.env"
        ));
    }
    Ok(())
}

fn check_run_expressions(run: &WorkflowEntry<'_, '_>) -> Result<(), String> {
    let mut source = String::new();
    let mut line_starts = Vec::new();
    for (number, text) in scalar_lines(run) {
        line_starts.push((source.len(), number));
        source.push_str(text);
        source.push('\n');
    }
    let line_at = |offset: usize| {
        line_starts
            .iter()
            .rev()
            .find(|(start, _)| *start <= offset)
            .map_or(run.number, |(_, number)| *number)
    };
    let mut cursor = 0;
    while let Some(found) = source[cursor..].find("${{") {
        let open = cursor + found;
        let close = expression_end(source.as_bytes(), open + 3)
            .ok_or_else(|| format!("{}: unterminated `${{{{` expression", line_at(open)))?;
        let expression = &source[open + 3..close];
        if untrusted_expression(expression) {
            return Err(format!(
                "{}: run script interpolates the contributor-controlled expression `{}`; \
                 pass it through the step's env",
                line_at(open),
                expression.trim()
            ));
        }
        cursor = close + 2;
    }
    Ok(())
}

/// The offset of the `}}` that closes an expression whose body starts at
/// `start`. Single-quoted literals may contain `}}`, so they are skipped.
fn expression_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    while let Some(byte) = bytes.get(index).copied() {
        match byte {
            b'\'' => index = string_literal(bytes, index).1,
            b'}' if bytes.get(index + 1).copied() == Some(b'}') => return Some(index),
            _ => index += 1,
        }
    }
    None
}

fn untrusted_expression(expression: &str) -> bool {
    expression_property_paths(expression).iter().any(|path| {
        let whole_context = path.first().is_some_and(|root| root == "github")
            && (path.len() == 1 || (path.len() == 2 && path[1] == "event"));
        whole_context
            || path
                .iter()
                .any(|segment| UNTRUSTED_EXPRESSION_PROPERTIES.contains(&segment.as_str()))
    })
}

/// Property paths an expression reads, lower-cased because Actions contexts
/// are case-insensitive: `github.event.commits[0]['message']` reads
/// `github`, `event`, `commits`, `*`, `message`. Function names and string
/// literals are not paths.
fn expression_property_paths(expression: &str) -> Vec<Vec<String>> {
    let bytes = expression.as_bytes();
    let mut paths = Vec::new();
    let mut index = 0;
    while let Some(byte) = bytes.get(index).copied() {
        if byte == b'\'' {
            index = string_literal(bytes, index).1;
        } else if byte.is_ascii_alphabetic() || byte == b'_' {
            let (path, end) = property_path(bytes, index);
            if bytes.get(end).copied() != Some(b'(') {
                paths.push(path);
            }
            index = end;
        } else if byte.is_ascii_digit() {
            index = identifier_end(bytes, index);
        } else {
            index += 1;
        }
    }
    paths
}

fn property_path(bytes: &[u8], start: usize) -> (Vec<String>, usize) {
    let mut end = identifier_end(bytes, start);
    let mut path = vec![String::from_utf8_lossy(&bytes[start..end]).to_ascii_lowercase()];
    loop {
        match (bytes.get(end).copied(), bytes.get(end + 1).copied()) {
            (Some(b'.'), Some(b'*')) => {
                path.push("*".to_owned());
                end += 2;
            }
            (Some(b'.'), Some(next)) if next.is_ascii_alphabetic() || next == b'_' => {
                let segment_end = identifier_end(bytes, end + 1);
                path.push(
                    String::from_utf8_lossy(&bytes[end + 1..segment_end]).to_ascii_lowercase(),
                );
                end = segment_end;
            }
            (Some(b'['), Some(b'\'')) => {
                let (literal, after) = string_literal(bytes, end + 1);
                if bytes.get(after).copied() != Some(b']') {
                    break;
                }
                path.push(literal.to_ascii_lowercase());
                end = after + 1;
            }
            (Some(b'['), Some(next)) if next == b'*' || next.is_ascii_digit() => {
                let Some(close) = bytes[end..].iter().position(|byte| *byte == b']') else {
                    break;
                };
                path.push("*".to_owned());
                end += close + 1;
            }
            _ => break,
        }
    }
    (path, end)
}

fn identifier_end(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .position(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
        .map_or(bytes.len(), |length| start + length)
}

/// Decodes the single-quoted literal opening at `quote` and returns it with
/// the index after its closing quote.
fn string_literal(bytes: &[u8], quote: usize) -> (String, usize) {
    let mut content = Vec::new();
    let mut index = quote + 1;
    while let Some(byte) = bytes.get(index).copied() {
        if byte == b'\'' {
            if bytes.get(index + 1).copied() != Some(b'\'') {
                return (String::from_utf8_lossy(&content).into_owned(), index + 1);
            }
            index += 1;
        }
        content.push(byte);
        index += 1;
    }
    (String::from_utf8_lossy(&content).into_owned(), index)
}

/// Splits a block mapping whose keys share one indentation. `head` is the
/// entry written after a sequence item's dash, when there is one.
fn block_mapping<'s, 'a>(
    head: Option<WorkflowLine<'a>>,
    lines: &'s [WorkflowLine<'a>],
) -> Result<Vec<WorkflowEntry<'s, 'a>>, String> {
    let Some(indent) = head
        .or_else(|| lines.iter().copied().find(|line| !line.is_trivia()))
        .map(|line| line.indent)
    else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    let mut open = head
        .map(|line| key_value(line).map(|pair| (line.number, pair, 0)))
        .transpose()?;
    for (index, line) in lines.iter().copied().enumerate() {
        if line.is_trivia() || line.indent > indent {
            continue;
        }
        if line.indent < indent {
            return Err(format!(
                "{}: indentation does not match its mapping",
                line.number
            ));
        }
        // A block sequence may sit at its key's own indentation.
        let sequence_item = line.text == "-" || line.text.starts_with("- ");
        if sequence_item && open.is_some_and(|(_, (_, inline), _)| inline.is_empty()) {
            continue;
        }
        if let Some((number, (key, inline), start)) = open.take() {
            entries.push(WorkflowEntry {
                number,
                key,
                inline,
                body: &lines[start..index],
            });
        }
        open = Some((line.number, key_value(line)?, index + 1));
    }
    if let Some((number, (key, inline), start)) = open {
        entries.push(WorkflowEntry {
            number,
            key,
            inline,
            body: &lines[start..],
        });
    }
    Ok(entries)
}

/// The text after an item's dash, as a line at the column where it starts,
/// and the lines nested under the item.
type SequenceItem<'s, 'a> = (Option<WorkflowLine<'a>>, &'s [WorkflowLine<'a>]);

/// Splits a block sequence whose dashes share one indentation into items.
fn block_sequence<'s, 'a>(
    lines: &'s [WorkflowLine<'a>],
) -> Result<Vec<SequenceItem<'s, 'a>>, String> {
    let Some(indent) = lines
        .iter()
        .find(|line| !line.is_trivia())
        .map(|line| line.indent)
    else {
        return Ok(Vec::new());
    };
    let mut items = Vec::new();
    let mut open: Option<(Option<WorkflowLine<'a>>, usize)> = None;
    for (index, line) in lines.iter().copied().enumerate() {
        if line.is_trivia() || line.indent > indent {
            continue;
        }
        let after_dash = line
            .text
            .strip_prefix('-')
            .filter(|rest| line.indent == indent && (rest.is_empty() || rest.starts_with(' ')))
            .ok_or_else(|| format!("{}: expected a `- ` sequence item", line.number))?;
        if let Some((head, start)) = open.take() {
            items.push((head, &lines[start..index]));
        }
        let text = after_dash.trim_start_matches(' ');
        let head = (!text.is_empty() && !text.starts_with('#')).then_some(WorkflowLine {
            number: line.number,
            indent: line.indent + 1 + (after_dash.len() - text.len()),
            text,
        });
        open = Some((head, index + 1));
    }
    if let Some((head, start)) = open {
        items.push((head, &lines[start..]));
    }
    Ok(items)
}

/// Parses `key: value` with a plain key. Anchors, aliases and tags are refused
/// because they can move a step's real content out of sight.
fn key_value(line: WorkflowLine<'_>) -> Result<(&str, &str), String> {
    let unreadable = || format!("{}: expected a plain `key: value` entry", line.number);
    let (key, rest) = line.text.split_once(':').ok_or_else(unreadable)?;
    if key.is_empty()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        || !(rest.is_empty() || rest.starts_with(' '))
    {
        return Err(unreadable());
    }
    let inline = rest.trim();
    let inline = if inline.starts_with('#') { "" } else { inline };
    if inline.starts_with(['&', '*', '!']) {
        return Err(format!(
            "{}: YAML anchors, aliases and tags are not supported",
            line.number
        ));
    }
    Ok((key, inline))
}

fn nested<'s, 'a>(entry: &WorkflowEntry<'s, 'a>) -> Result<&'s [WorkflowLine<'a>], String> {
    if entry.inline.is_empty() {
        Ok(entry.body)
    } else {
        Err(format!(
            "{}: `{}` must be a block collection, not an inline value",
            entry.number, entry.key
        ))
    }
}

fn unique_entry<'e, 's, 'a>(
    entries: &'e [WorkflowEntry<'s, 'a>],
    key: &str,
) -> Result<Option<&'e WorkflowEntry<'s, 'a>>, String> {
    let mut matches = entries.iter().filter(|entry| entry.key == key);
    let first = matches.next();
    if let Some(duplicate) = matches.next() {
        return Err(format!("{}: duplicate `{key}` key", duplicate.number));
    }
    Ok(first)
}

/// An entry's scalar text by line: the inline value, then every nested line.
fn scalar_lines<'e>(entry: &'e WorkflowEntry<'_, '_>) -> impl Iterator<Item = (usize, &'e str)> {
    std::iter::once((entry.number, entry.inline))
        .chain(entry.body.iter().map(|line| (line.number, line.text)))
}

/// A scalar without its trailing comment or surrounding quotes.
fn unquoted(inline: &str) -> &str {
    let value = inline
        .split_once(" #")
        .map_or(inline, |(value, _)| value)
        .trim();
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value)
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
                            | ".venv"
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

#[cfg(test)]
mod dependency_path_tests {
    use super::*;

    #[test]
    fn dependency_paths_are_collected_from_top_level_and_target_tables() {
        let manifest: toml::Value = toml::from_str(
            r#"
                [dependencies]
                local = { path = "../local" }
                registry = "1"

                [target.'cfg(unix)'.dev-dependencies]
                support = { path = "../../testkit/support", features = ["std"] }

                [package.metadata.example]
                path = "not-a-dependency"
            "#,
        )
        .unwrap();
        let mut paths = Vec::new();
        collect_dependency_paths(&manifest, &mut paths);
        paths.sort();
        assert_eq!(paths, ["../../testkit/support", "../local"]);
    }
}

#[cfg(test)]
mod dependency_boundary_tests {
    use super::*;

    fn policy(boundary: DependencyBoundary) -> ArchitecturePolicy {
        ArchitecturePolicy {
            layers: BTreeMap::new(),
            packages: BTreeMap::new(),
            dependency_boundaries: BTreeMap::from([("identity".into(), boundary)]),
            workspace_edition: String::new(),
            workspace_resolver: String::new(),
            workspace_msrv: String::new(),
            development_toolchain: String::new(),
            core_forbidden_dependencies: BTreeSet::new(),
            core_default_feature_exceptions: BTreeSet::new(),
            approved_build_scripts: BTreeSet::new(),
            no_std_packages: BTreeSet::new(),
        }
    }

    #[test]
    fn transitive_dependency_boundaries_reject_hidden_coupling() {
        let edges = BTreeMap::from([
            (
                "identity-transport".into(),
                BTreeSet::from(["raw-key".into()]),
            ),
            ("raw-key".into(), BTreeSet::from(["capabilities".into()])),
            ("capabilities".into(), BTreeSet::new()),
        ]);
        let result = check_dependency_boundaries(
            &policy(DependencyBoundary {
                roots: BTreeSet::from(["identity-transport".into()]),
                allowed_workspace_dependencies: BTreeSet::from(["raw-key".into()]),
            }),
            &edges,
        );
        assert!(result.unwrap_err().contains("capabilities"));
    }

    #[test]
    fn transitive_dependency_boundaries_accept_declared_identity_layers() {
        let edges = BTreeMap::from([
            (
                "identity-transport".into(),
                BTreeSet::from(["raw-key".into()]),
            ),
            ("raw-key".into(), BTreeSet::from(["model".into()])),
            ("model".into(), BTreeSet::new()),
        ]);
        check_dependency_boundaries(
            &policy(DependencyBoundary {
                roots: BTreeSet::from(["identity-transport".into()]),
                allowed_workspace_dependencies: BTreeSet::from(["raw-key".into(), "model".into()]),
            }),
            &edges,
        )
        .unwrap();
    }
}

#[cfg(test)]
mod workflow_expression_tests {
    use super::*;

    fn run_step(expression: &str) -> String {
        format!(
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Build\n        \
             run: |\n          set -eu\n          echo \"${{{{ {expression} }}}}\"\n"
        )
    }

    #[test]
    fn github_script_source_admits_no_expression() {
        let interpolated = "\
jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - name: Start CI on the repaired commit
        uses: actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd # v8
        with:
          script: |
            await github.rest.actions.createWorkflowDispatch({
              ref: '${{ steps.authorize.outputs.head_ref }}',
            });
";
        let error = check_step_script_expressions(interpolated).unwrap_err();
        assert!(
            error.starts_with("10: actions/github-script source"),
            "{error}"
        );

        let through_env = "\
jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - name: Start CI on the repaired commit
        uses: actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd # v8
        # Data, not source.
        env:
          AUTHS_HEAD_REF: ${{ steps.authorize.outputs.head_ref }}
        with:
          script: |
            const ref = process.env.AUTHS_HEAD_REF ?? '';
";
        check_step_script_expressions(through_env).unwrap();

        // Composite actions, sequences at their key's indentation, the
        // case-insensitive action name and trusted contexts are all covered.
        let composite = "\
runs:
  using: composite
  steps:
  - uses: Actions/GitHub-Script@ed597411d8f924073f98dfc5c65a23a2325f34cd
    with:
      script: core.info('${{ github.run_id }}')
";
        let error = check_step_script_expressions(composite).unwrap_err();
        assert!(
            error.starts_with("6: actions/github-script source"),
            "{error}"
        );
    }

    #[test]
    fn run_scripts_refuse_contributor_controlled_expressions() {
        for expression in [
            "github.head_ref",
            "GitHub.Head_Ref",
            "github.ref",
            "github.ref_name",
            "github.base_ref",
            "github.workflow_ref",
            "steps.authorize.outputs.head_ref",
            "github.event.pull_request.title",
            "github.event.pull_request['title']",
            "github.event.pull_request.head.ref",
            "github.event.issue.body",
            "github.event.commits[0].message",
            "github.event.head_commit.author.email",
            "github.event.workflow_run.head_branch",
            "format('{0}', github.event.comment.body)",
            "format('}}', github.head_ref)",
            "toJSON(github.event)",
        ] {
            let error = check_step_script_expressions(&run_step(expression)).unwrap_err();
            assert!(
                error.starts_with("8: run script interpolates"),
                "{expression}: {error}"
            );
        }
        for expression in [
            "github.run_id",
            "github.event_name",
            "github.ref_type",
            "github.event.pull_request.head.sha",
            "steps.build.outputs.digest",
            "contains(github.event_name, 'body')",
        ] {
            check_step_script_expressions(&run_step(expression)).unwrap();
        }
        let through_env = "\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build
        env:
          HEAD_REF: ${{ github.head_ref }}
        run: echo \"$HEAD_REF\"
";
        check_step_script_expressions(through_env).unwrap();
    }

    #[test]
    fn unreadable_steps_fail_closed() {
        let script_step = "jobs:\n  a:\n    steps:\n      - uses: actions/github-script@\
                           ed597411d8f924073f98dfc5c65a23a2325f34cd\n";
        for (source, reason) in [
            (
                format!("{script_step}        with: {{script: x}}\n"),
                "flow inputs",
            ),
            (script_step.to_owned(), "no script"),
            (
                format!("{script_step}        with:\n          script: *shared\n"),
                "alias",
            ),
            (
                format!("{script_step}        with:\n          script: a\n          script: b\n"),
                "duplicate key",
            ),
            (
                "jobs:\n  a:\n    steps:\n      - run: echo \"${{ github.run_id\"\n".to_owned(),
                "unterminated expression",
            ),
            (
                "jobs:\n  a:\n    steps:\n      - {run: echo}\n".to_owned(),
                "flow step",
            ),
            (
                "jobs:\n  a:\n    steps: [{run: echo}]\n".to_owned(),
                "flow steps",
            ),
            ("jobs:\n  a:\n    steps:\n\t- run: echo\n".to_owned(), "tab"),
        ] {
            assert!(check_step_script_expressions(&source).is_err(), "{reason}");
        }
    }

    #[test]
    fn repository_workflows_splice_no_untrusted_expression_into_step_source() {
        check_workflow_script_expressions().unwrap();
    }
}

#[cfg(test)]
mod workflow_action_pin_tests {
    use super::*;

    const PINNED: &str = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683";

    #[test]
    fn every_uses_is_pin_checked_wherever_it_sits() {
        for (source, line) in [
            (
                "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
                4,
            ),
            (
                "jobs:\n  a:\n    steps:\n      - name: Check out\n        uses: actions/checkout@v4\n",
                5,
            ),
            (
                "runs:\n  using: composite\n  steps:\n  - name: Cache\n    uses: actions/cache@v4\n",
                5,
            ),
            (
                "jobs:\n  call:\n    uses: octo-org/example/.github/workflows/build.yml@main\n",
                3,
            ),
        ] {
            let error = check_action_pins(source).unwrap_err();
            assert!(
                error.starts_with(&format!("{line}: action is not pinned")),
                "{error}"
            );
        }
        let error = check_action_pins(
            "jobs:\n  a:\n    steps:\n      - name: Check out\n        uses: actions/checkout\n",
        )
        .unwrap_err();
        assert!(error.starts_with("5: action has no revision"), "{error}");
        // A step the structural reader cannot read is refused, not skipped.
        check_action_pins("jobs:\n  a:\n    steps:\n      - {uses: actions/checkout@v4}\n")
            .unwrap_err();
    }

    #[test]
    fn pinned_and_local_references_pass() {
        let source = format!(
            "\
jobs:
  a:
    steps:
      - name: Check out
        uses: {PINNED} # v4.2.2
      - uses: \"{PINNED}\"
      - uses: ./.github/actions/setup-rust-cache
  call:
    uses: ./.github/workflows/release-builder.yml
"
        );
        check_action_pins(&source).unwrap();
    }

    #[test]
    fn repository_workflows_pin_every_action() {
        check_workflow_action_pins().unwrap();
    }
}
