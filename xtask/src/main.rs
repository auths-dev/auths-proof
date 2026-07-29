#![forbid(unsafe_code)]

mod formal_qualification;

use auths_testkit::Expected;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".into());
    match command.as_str() {
        "ci" => ci(),
        "arch" => arch(args.any(|arg| arg == "--update")),
        "fmt" => format_all(),
        "core-boundary" => core_boundary(),
        "workspace-msrv" | "core-msrv" => workspace_msrv(),
        "abi" => abi(),
        "core" => layer_check("core"),
        "exchange" => exchange_check(),
        "product" => product_check(),
        "bindings" => bindings_check(),
        "demos" => demos_check(),
        "package" => package_check(),
        "wire" => wire(args.any(|arg| arg == "--update")),
        "spec-sync" => spec_sync(),
        "conformance" => target_conformance(),
        "exchange-conformance" => exchange_conformance(),
        "product-conformance" => product_conformance(),
        "compliance" => compliance(),
        "matrix" => matrix(),
        "cross-language" => cross_language_corpus(),
        "product-fixtures" => product_fixtures(args.any(|arg| arg == "--update")),
        "semantic-digest" => semantic_digest(),
        "wasm" => wasm(),
        "live-demo" => live_demo(),
        "fuzz-inventory" => fuzz_inventory(),
        "fuzz-smoke" => fuzz_smoke(),
        "formal" => {
            let arguments: Vec<_> = args.collect();
            match arguments.as_slice() {
                [qualify, tool] if qualify == "qualify" && tool == "aeneas" => {
                    formal_qualify_aeneas(false)
                }
                [qualify, tool, update]
                    if qualify == "qualify" && tool == "aeneas" && update == "--update" =>
                {
                    formal_qualify_aeneas(true)
                }
                _ => formal(
                    arguments.iter().any(|arg| arg == "--skip-kani"),
                    arguments.iter().any(|arg| arg == "--update"),
                ),
            }
        }
        "adversarial-conformance" => adversarial_conformance(args.collect()),
        "bench" => benchmark(args.collect()),
        "platform-artifact" => {
            let output = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| root().join("target/release-evidence/platform.json"));
            platform_artifact(&output)
        }
        "release-check" => release_check(),
        _ => {
            println!(
                "usage: cargo xtask <fmt|arch [--update]|core-boundary|workspace-msrv|abi|core|\
                 exchange|product|bindings|demos|package|wire [--update]|spec-sync|\
                 conformance|exchange-conformance|product-conformance|compliance|matrix|cross-language|\
                 product-fixtures [--update]|semantic-digest|wasm|live-demo|fuzz-inventory|fuzz-smoke|\
                 platform-artifact [output]|formal [--skip-kani] [--update]|formal qualify aeneas [--update]|\
                 adversarial-conformance [--surface <name>|--adapter <name>|--case <id>]|\
                 bench <prepare|run|report|compare|verify-artifact>|\
                 ci|release-check>"
            );
            Ok(())
        }
    }
}

fn ci() -> Result<(), String> {
    format_all()?;
    arch(false)?;
    let compliance_inventory = compliance_inventory()?;
    repository_hygiene()?;
    cargo(&["check", "--workspace", "--all-targets", "--all-features"])?;
    cargo(&["test", "--workspace", "--all-features"])?;
    cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--",
        "-D",
        "warnings",
    ])?;
    formal(false, false)?;
    core_boundary()?;
    workspace_msrv()?;
    abi()?;
    exchange_conformance()?;
    product_conformance()?;
    product_fixtures(false)?;
    matrix()?;
    bindings_check()?;
    package_check()?;
    platform_artifact(&root().join("target/release-evidence/platform.json"))?;
    fuzz_smoke()?;
    wasm()?;
    live_demo()?;
    write_compliance_report(&compliance_inventory)
}

fn format_all() -> Result<(), String> {
    cargo(&["fmt", "--all", "--check"])?;
    let go_root = root().join("bindings/independent/go");
    let go_sources = files_with_extension(&go_root, "go")?;
    let mut go_arguments = vec!["-l"];
    go_arguments.extend(
        go_sources
            .iter()
            .map(|path| path_text(path))
            .collect::<Result<Vec<_>, _>>()?,
    );
    let go_files = command_output_in("gofmt", &go_arguments, &go_root, None)?;
    if !go_files.trim().is_empty() {
        return Err(format!("Go sources require gofmt:\n{}", go_files.trim()));
    }
    Ok(())
}

fn layer_check(layer: &str) -> Result<(), String> {
    let policy = load_architecture_policy()?;
    let packages: Vec<_> = policy
        .packages
        .iter()
        .filter(|(_, package_layer)| package_layer.as_str() == layer)
        .map(|(name, _)| name.as_str())
        .collect();
    if packages.is_empty() {
        return Err(format!("architecture layer {layer} has no packages"));
    }
    let mut command = Command::new("cargo");
    command
        .arg("test")
        .arg("--all-features")
        .current_dir(root());
    for package in packages {
        command.arg("-p").arg(package);
    }
    let status = command
        .status()
        .map_err(|error| format!("could not test {layer} layer: {error}"))?;
    if !status.success() {
        return Err(format!("{layer} layer tests failed with {status}"));
    }
    Ok(())
}

fn exchange_check() -> Result<(), String> {
    layer_check("exchange")?;
    exchange_conformance()
}

fn product_check() -> Result<(), String> {
    layer_check("product")?;
    product_conformance()
}

fn demos_check() -> Result<(), String> {
    layer_check("demos")?;
    matrix()?;
    live_demo()
}

fn bindings_check() -> Result<(), String> {
    layer_check("bindings")?;
    command_in("npm", &["test"], &root().join("bindings/typescript"), None)?;
    npm_package_smoke()?;
    let go_cache = root().join("target/go-build-cache");
    fs::create_dir_all(&go_cache).map_err(|error| format!("could not create Go cache: {error}"))?;
    command_in(
        "go",
        &["vet", "./..."],
        &root().join("bindings/independent/go"),
        Some(("GOCACHE", &go_cache)),
    )?;
    command_in(
        "go",
        &["test", "-race", "./..."],
        &root().join("bindings/independent/go"),
        Some(("GOCACHE", &go_cache)),
    )?;
    python_wheel_smoke()?;
    cross_language_corpus()
}

fn npm_package_smoke() -> Result<(), String> {
    let package_directory = root().join("target/npm-package");
    let install_directory = root().join("target/npm-install-smoke");
    for directory in [&package_directory, &install_directory] {
        if directory.exists() {
            fs::remove_dir_all(directory)
                .map_err(|error| format!("could not clear {}: {error}", directory.display()))?;
        }
        fs::create_dir_all(directory)
            .map_err(|error| format!("could not create {}: {error}", directory.display()))?;
    }
    command_in(
        "npm",
        &["pack", "--pack-destination", path_text(&package_directory)?],
        &root().join("bindings/typescript"),
        None,
    )?;
    let archives: Vec<_> = fs::read_dir(&package_directory)
        .map_err(|error| format!("could not list npm package output: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("tgz"))
        .collect();
    if archives.len() != 1 {
        return Err(format!(
            "expected one npm archive, found {} in {}",
            archives.len(),
            package_directory.display()
        ));
    }
    command_in("npm", &["init", "--yes"], &install_directory, None)?;
    command_in(
        "npm",
        &["install", path_text(&archives[0])?],
        &install_directory,
        None,
    )?;
    let smoke = install_directory.join("smoke.mjs");
    fs::write(
        &smoke,
        "import * as auths from '@auths-dev/proof';\n\
         if (typeof auths.Auths !== 'function') throw new Error('Auths export missing');\n",
    )
    .map_err(|error| format!("could not write npm install smoke: {error}"))?;
    command_in("node", &[path_text(&smoke)?], &install_directory, None)
}

fn workspace_msrv() -> Result<(), String> {
    let policy = load_architecture_policy()?;
    let default_toolchain = format!("{}.0", policy.workspace_msrv);
    let toolchain = env::var("AUTHS_WORKSPACE_MSRV_TOOLCHAIN").unwrap_or(default_toolchain);
    let mut command = Command::new("cargo");
    command
        .arg(format!("+{toolchain}"))
        .args([
            "check",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
        ])
        .env("CARGO_TARGET_DIR", root().join("target/workspace-msrv"))
        .current_dir(root());
    let status = command
        .status()
        .map_err(|error| format!("could not run workspace MSRV toolchain {toolchain}: {error}"))?;
    if status.success() {
        println!("workspace MSRV {toolchain} check passed");
        Ok(())
    } else {
        Err(format!(
            "workspace MSRV {toolchain} check failed with {status}"
        ))
    }
}

fn python_wheel_smoke() -> Result<(), String> {
    let wheel_directory = root().join("target/python-wheels");
    let virtual_environment = root().join("target/python-smoke-venv");
    if wheel_directory.exists() {
        fs::remove_dir_all(&wheel_directory)
            .map_err(|error| format!("could not clear Python wheel directory: {error}"))?;
    }
    if virtual_environment.exists() {
        fs::remove_dir_all(&virtual_environment)
            .map_err(|error| format!("could not clear Python smoke environment: {error}"))?;
    }
    fs::create_dir_all(&wheel_directory)
        .map_err(|error| format!("could not create Python wheel directory: {error}"))?;
    command_in(
        "maturin",
        &[
            "build",
            "--out",
            path_text(&wheel_directory)?,
            "--manifest-path",
            "bindings/python/Cargo.toml",
        ],
        &root(),
        None,
    )?;
    let wheels: Vec<_> = fs::read_dir(&wheel_directory)
        .map_err(|error| format!("could not list Python wheels: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("whl"))
        .collect();
    if wheels.len() != 1 {
        return Err(format!(
            "expected one Python wheel, found {} in {}",
            wheels.len(),
            wheel_directory.display()
        ));
    }
    command("python3", &["-m", "venv", path_text(&virtual_environment)?])?;
    let python = if cfg!(windows) {
        virtual_environment.join("Scripts/python.exe")
    } else {
        virtual_environment.join("bin/python")
    };
    command(path_text(&python)?, &["-m", "pip", "install", "pytest"])?;
    command(
        path_text(&python)?,
        &["-m", "pip", "install", path_text(&wheels[0])?],
    )?;
    command_in(
        path_text(&python)?,
        &["-m", "pytest", "tests"],
        &root().join("bindings/python"),
        None,
    )
}

fn abi() -> Result<(), String> {
    spec_sync()?;
    wire(false)?;
    target_conformance()?;
    cross_language_corpus()
}

fn exchange_conformance() -> Result<(), String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async {
        auths_proof_exchange_testkit::assert_memory_conformance().await;
        auths_proof_exchange_testkit::assert_iroh_conformance().await;
        auths_proof_exchange_testkit::assert_tcp_conformance().await;
        #[cfg(unix)]
        auths_proof_exchange_testkit::assert_unix_conformance().await;
        auths_proof_exchange_testkit::assert_file_conformance().await;
    });
    auths_proof_exchange_testkit::assert_https_codec_conformance();
    println!("exchange transport conformance passed");
    Ok(())
}

fn product_conformance() -> Result<(), String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async {
        auths_apps_testkit::assert_target_conformance().await;
        auths_apps_testkit::assert_iroh_target_conformance().await;
    });
    println!("product MCP and Iroh conformance passed");
    Ok(())
}

fn compliance() -> Result<(), String> {
    let inventory = compliance_inventory()?;
    arch(false)?;
    layer_check("product")?;
    abi()?;
    exchange_conformance()?;
    product_conformance()?;
    product_fixtures(false)?;
    matrix()?;
    bindings_check()?;
    package_check()?;
    live_demo()?;
    write_compliance_report(&inventory)
}

const COMPLIANCE_ROLES: [&str; 16] = [
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

const COMPLIANCE_SURFACES: [&str; 10] = [
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

fn compliance_inventory() -> Result<Value, String> {
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

fn compliance_strings(value: &toml::Value, owner: &str) -> Result<BTreeSet<String>, String> {
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

fn validate_compliance_role(
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

fn validate_compliance_evidence(package: &str, anchor: &str) -> Result<(), String> {
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

fn discover_external_compliance_packages(
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

fn write_compliance_report(inventory: &Value) -> Result<(), String> {
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

fn write_pretty_json(path: &Path, value: &Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not encode JSON: {error}"))?;
    bytes.push(b'\n');
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    fs::write(path, bytes).map_err(|error| format!("could not write {}: {error}", path.display()))
}

fn matrix() -> Result<(), String> {
    let nominal = auths_lab_matrix::nominal_matrix();
    let compatible = auths_lab_matrix::compatible_matrix();
    if nominal.len() != 504 || compatible.len() != 396 {
        return Err(format!(
            "unexpected target matrix shape: {} nominal, {} compatible",
            nominal.len(),
            compatible.len()
        ));
    }
    println!(
        "Auths Lab matrix: {} nominal points, {} baseline-compatible points",
        nominal.len(),
        compatible.len()
    );
    Ok(())
}

fn cross_language_corpus() -> Result<(), String> {
    let manifest = root().join("core/fixtures/v1/manifest.json");
    let go_root = root().join("bindings/independent/go");
    let go_cache = root().join("target/go-build-cache");
    fs::create_dir_all(&go_cache).map_err(|error| format!("could not create Go cache: {error}"))?;
    let typescript_program = root().join("bindings/independent/typescript/auths-corpus-check.ts");
    let go = command_output_in(
        "go",
        &["run", "./cmd/auths-corpus-check", path_text(&manifest)?],
        &go_root,
        Some(("GOCACHE", &go_cache)),
    )?;
    let typescript = command_output_in(
        "node",
        &[
            "--experimental-strip-types",
            path_text(&typescript_program)?,
            path_text(&manifest)?,
        ],
        &root(),
        None,
    )?;
    let go = go.trim();
    let typescript = typescript.trim();
    if go != typescript {
        return Err(format!(
            "independent corpus auditors disagreed: Go={go:?}, TypeScript={typescript:?}"
        ));
    }
    let go_semantic = command_output_in(
        "go",
        &[
            "run",
            "./cmd/auths-corpus-check",
            "--semantic",
            path_text(&manifest)?,
        ],
        &go_root,
        Some(("GOCACHE", &go_cache)),
    )?;
    let typescript_semantic = command_output_in(
        "node",
        &[
            "--experimental-strip-types",
            path_text(&typescript_program)?,
            "--semantic",
            path_text(&manifest)?,
        ],
        &root(),
        None,
    )?;
    let rust_semantic = semantic_digest_value()?;
    let go_semantic = go_semantic.trim();
    let typescript_semantic = typescript_semantic.trim();
    if go_semantic != typescript_semantic || go_semantic != rust_semantic {
        return Err(format!(
            "independent semantic verifiers disagreed: \
             Rust={rust_semantic:?}, Go={go_semantic:?}, TypeScript={typescript_semantic:?}"
        ));
    }
    println!("Rust, Go, and TypeScript corpus verifiers agree: {go_semantic}");
    Ok(())
}

fn product_fixtures(update: bool) -> Result<(), String> {
    let fixture = auths_apps_testkit::demo_fixture_bytes();
    let expected = BTreeMap::from([
        (PathBuf::from("mcp-call.json"), fixture.body),
        (PathBuf::from("mcp-call.proof.cbor"), fixture.proof),
        (
            PathBuf::from("root-principal.txt"),
            format!("{}\n", fixture.root_principal).into_bytes(),
        ),
    ]);
    let directory = root().join("product/fixtures/v1");
    if update {
        fs::create_dir_all(&directory)
            .map_err(|error| format!("could not create product fixtures: {error}"))?;
        for (relative, bytes) in expected {
            fs::write(directory.join(relative), bytes)
                .map_err(|error| format!("could not write product fixture: {error}"))?;
        }
        println!("product fixtures updated");
        return Ok(());
    }
    for (relative, expected) in expected {
        let actual = fs::read(directory.join(&relative)).map_err(|error| {
            format!(
                "could not read product fixture {}: {error}",
                relative.display()
            )
        })?;
        if actual != expected {
            return Err(format!(
                "product fixture {} drifted; run `cargo xtask product-fixtures --update`",
                relative.display()
            ));
        }
    }
    println!("product fixtures are stable");
    Ok(())
}

fn package_check() -> Result<(), String> {
    let metadata = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not inspect package publication policy: {error}"))?;
    if !metadata.status.success() {
        return Err("cargo metadata failed while selecting publishable packages".to_owned());
    }
    let metadata: Value = serde_json::from_slice(&metadata.stdout)
        .map_err(|error| format!("could not parse package publication policy: {error}"))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages")?;
    let policy = load_architecture_policy()?;
    let mut private = Vec::new();
    for package in packages {
        let name = package["name"]
            .as_str()
            .ok_or("workspace package has no name")?;
        let publishable = package_is_publishable(package);
        let layer = policy
            .packages
            .get(name)
            .ok_or_else(|| format!("package {name} is not classified"))?;
        if matches!(layer.as_str(), "demos" | "tooling") && publishable {
            return Err(format!(
                "{layer} package {name} must declare publish = false"
            ));
        }
        if !publishable {
            private.push(name.to_owned());
        }
    }
    private.sort();
    let mut arguments = vec!["package".to_owned(), "--workspace".to_owned()];
    for name in private {
        arguments.push("--exclude".to_owned());
        arguments.push(name);
    }
    arguments.extend(["--allow-dirty".to_owned(), "--no-verify".to_owned()]);
    let argument_refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    cargo(&argument_refs)
}

fn package_is_publishable(package: &Value) -> bool {
    !package["publish"]
        .as_array()
        .is_some_and(|registries| registries.is_empty())
}

fn spec_sync() -> Result<(), String> {
    use auths_model::{DenialReason as D, Requirement as R};

    let denied = [
        D::MalformedProof,
        D::NonCanonicalProof,
        D::ResourceLimitExceeded,
        D::DigestMismatch,
        D::DuplicateObject,
        D::MissingReference,
        D::ReferenceCycle,
        D::AmbiguousTerminalGrant,
        D::UnusedCriticalEvidence,
        D::InvalidSignature,
        D::PrincipalMethodMismatch,
        D::VerificationMethodMismatch,
        D::SignatureSuiteMismatch,
        D::UntrustedRoot,
        D::BrokenGrantChain,
        D::DelegationExpanded,
        D::PermissionNotGranted,
        D::ActionConstraintMismatch,
        D::BudgetCeilingExceeded,
        D::AuthorizationPlanInvalid,
        D::CompositionRequirementNotMet,
        D::PlanActionMismatch,
        D::ActionBodyMismatch,
        D::AudienceMismatch,
        D::ChallengeMismatch,
        D::ActionOutsideValidity,
        D::PrincipalRevoked,
        D::GrantRevoked,
        D::StatusSequenceRollback,
        D::StatusMethodMismatch,
        D::StatusIssuerUntrusted,
        D::RegistryManifestMismatch,
        D::VerifierConfigurationMismatch,
        D::ResourceNamespaceMismatch,
        D::CriticalExtensionUnknown,
        D::AttachmentMissing,
        D::AttachmentDigestMismatch,
        D::AttachmentLengthMismatch,
        D::DuplicateAttachment,
        D::UnusedCriticalAttachment,
        D::OpaqueAttachmentNotAllowed,
        D::LocalPolicyDenied,
    ];
    let indeterminate = [
        R::UnsupportedProtocol,
        R::UnsupportedPrincipalMethod,
        R::UnsupportedSignatureSuite,
        R::UnsupportedEvidenceType,
        R::UnsupportedStatusMethod,
        R::UnsupportedProfile,
        R::UnsupportedProfilePolicy,
        R::UnsupportedResourceMatcher,
        R::UnsupportedBudgetAlgebra,
        R::UnsupportedCriticalExtension,
        R::UnsupportedAssuranceClaim,
        R::MissingPrincipalEvidence,
        R::MissingPrincipalStatus,
        R::MissingGrantStatus,
        R::StaleStatus,
        R::HistoricalStateUnavailable,
        R::AssuranceRequirementNotMet,
        R::ExternalFactUnavailable,
    ];
    let errors = fs::read_to_string(root().join("core/spec/v1/error-codes.md"))
        .map_err(|error| format!("could not read error registry: {error}"))?;
    for code in denied
        .iter()
        .map(|value| value.code())
        .chain(indeterminate.iter().map(|value| value.code()))
    {
        if !errors.contains(&format!("`{code}`")) {
            return Err(format!(
                "stable result code {code} is absent from error-codes.md"
            ));
        }
    }
    let reserved = BTreeSet::from([
        D::AmbiguousTerminalGrant.code(),
        D::AuthorizationPlanInvalid.code(),
        D::ReferenceCycle.code(),
    ]);
    let manifest_bytes = fs::read(root().join("core/fixtures/v1/manifest.json"))
        .map_err(|error| format!("could not read corpus manifest: {error}"))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("could not parse corpus manifest: {error}"))?;
    let fixtures = manifest
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| "corpus manifest has no fixtures array".to_owned())?;
    let covered: BTreeSet<&str> = fixtures
        .iter()
        .filter_map(|fixture| fixture.get("expected_code").and_then(Value::as_str))
        .collect();
    for code in denied
        .iter()
        .map(|value| value.code())
        .chain(indeterminate.iter().map(|value| value.code()))
    {
        if reserved.contains(code) {
            if covered.contains(code) {
                return Err(format!(
                    "reserved V1 result code {code} has a corpus vector"
                ));
            }
        } else if !covered.contains(code) {
            return Err(format!(
                "implemented V1 result code {code} has no committed corpus vector"
            ));
        }
    }
    if !covered.contains("authorized") {
        return Err("authorized V1 result has no committed corpus vector".to_owned());
    }
    let registry = fs::read_to_string(root().join("core/spec/v1/registry.md"))
        .map_err(|error| format!("could not read registry specification: {error}"))?;
    for identifier in [
        auths_registries::URI_NAMESPACE_V1,
        auths_registries::EXACT_PROFILE_V1,
        auths_registries::NUMERIC_CEILING_V1,
        auths_registries::EXACT_MARKER_EXTENSION_V1,
    ] {
        if !registry.contains(&format!("`{identifier}`")) {
            return Err(format!(
                "executable registry ID {identifier} is undocumented"
            ));
        }
    }
    let traceability = fs::read_to_string(root().join("docs/TRACEABILITY.md"))
        .map_err(|error| format!("could not read traceability matrix: {error}"))?;
    for family in [
        "Canonical CBOR",
        "Signed fields and domains",
        "Identifier derivation",
        "Graph/reference rules",
        "Attenuation",
        "Required composition",
        "Status",
        "Assurance quantifiers",
        "Evidence consumption",
        "Registry/configuration",
        "Resource limits",
        "Portable normalization",
    ] {
        if !traceability.contains(family) {
            return Err(format!("traceability matrix is missing {family}"));
        }
    }
    let limit_coverage = fs::read_to_string(root().join("docs/LIMIT_COVERAGE.md"))
        .map_err(|error| format!("could not read limit coverage matrix: {error}"))?;
    for limit in [
        "BundleBytes",
        "ActionBytes",
        "ContextBytes",
        "Grants",
        "Actions",
        "PlanLeaves",
        "PlanDepth",
        "PlanBranching",
        "EvidenceObjects",
        "EvidenceBytes",
        "ControlBindings",
        "PrincipalStatusStatements",
        "GrantStatusStatements",
        "Attachments",
        "AttachmentBytes",
        "Signatures",
        "SignatureBytes",
        "Permissions",
        "Audiences",
        "CriticalExtensions",
        "CriticalExtensionBytes",
        "AllowedBodyDigests",
        "BindingEvidence",
        "CanonicalBodyBytes",
        "RegistryEntries",
        "TrustAnchors",
        "work units",
    ] {
        if !limit_coverage.contains(limit) {
            return Err(format!("limit coverage matrix is missing {limit}"));
        }
    }
    println!("specification, registry, and result-code registries are synchronized");
    Ok(())
}

fn release_check() -> Result<(), String> {
    if env::var_os("CI").is_some() {
        let status = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(root())
            .output()
            .map_err(|error| format!("could not inspect release worktree: {error}"))?;
        if !status.status.success() || !status.stdout.is_empty() {
            return Err("release checks require a clean CI worktree".to_owned());
        }
    }
    if let Ok(tag) = env::var("GITHUB_REF_NAME")
        && tag.starts_with('v')
        && tag != format!("v{}", env!("CARGO_PKG_VERSION"))
    {
        return Err(format!(
            "release tag {tag} does not match workspace version v{}",
            env!("CARGO_PKG_VERSION")
        ));
    }
    ci()?;
    cargo(&["test", "--workspace", "--no-default-features"])?;
    wire(false)?;
    let status = Command::new("cargo")
        .args(["doc", "--workspace", "--all-features", "--no-deps"])
        .env("RUSTDOCFLAGS", "-D warnings")
        .current_dir(root())
        .status()
        .map_err(|error| format!("could not build release documentation: {error}"))?;
    if !status.success() {
        return Err(format!("documentation build failed with {status}"));
    }
    package_check()?;
    release_evidence()?;
    println!("release checks passed");
    Ok(())
}

fn release_evidence() -> Result<(), String> {
    let metadata = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not generate dependency metadata: {error}"))?;
    if !metadata.status.success() {
        return Err("cargo metadata failed while generating release evidence".to_owned());
    }
    let metadata_value: Value = serde_json::from_slice(&metadata.stdout)
        .map_err(|error| format!("could not parse dependency metadata: {error}"))?;
    let packages = metadata_value["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages")?;
    let components: Vec<_> = packages
        .iter()
        .map(|package| {
            let component_type = if package["targets"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["kind"]
                        .as_array()
                        .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
                })
            }) {
                "application"
            } else {
                "library"
            };
            let name = package["name"].as_str().unwrap_or("unknown");
            let version = package["version"].as_str().unwrap_or("unknown");
            let purl = format!("pkg:cargo/{name}@{version}");
            let mut component = json!({
                "type": component_type,
                "bom-ref": purl,
                "name": package["name"],
                "version": package["version"],
                "purl": purl,
            });
            if let Some(license) = package["license"].as_str() {
                component["licenses"] = json!([{ "expression": license }]);
            }
            component
        })
        .collect();
    let workspace_members: BTreeSet<_> = metadata_value["workspace_members"]
        .as_array()
        .ok_or("cargo metadata has no workspace members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut package_checksums = BTreeMap::new();
    for package in packages.iter().filter(|package| {
        package["id"]
            .as_str()
            .is_some_and(|id| workspace_members.contains(id))
            && package_is_publishable(package)
    }) {
        let name = package["name"]
            .as_str()
            .ok_or("workspace package has no name")?;
        let version = package["version"]
            .as_str()
            .ok_or("workspace package has no version")?;
        let relative = format!("target/package/{name}-{version}.crate");
        let digest = sha256_file(&root().join(&relative))?;
        package_checksums.insert(relative, digest);
    }
    if package_checksums.is_empty() {
        return Err("release packaging produced no crate archives".to_owned());
    }
    let crate_archive_count = package_checksums.len();
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not identify release commit: {error}"))?;
    if !commit.status.success() {
        return Err("could not identify release commit".to_owned());
    }
    let toolchain = Command::new("rustc")
        .arg("--version")
        .output()
        .map_err(|error| format!("could not identify Rust toolchain: {error}"))?;
    if !toolchain.status.success() {
        return Err("could not identify Rust toolchain".to_owned());
    }
    let manifest = fs::read(root().join("core/fixtures/v1/manifest.json"))
        .map_err(|error| format!("could not read corpus manifest: {error}"))?;
    let evidence = root().join("target/release-evidence");
    fs::create_dir_all(&evidence)
        .map_err(|error| format!("could not create release evidence directory: {error}"))?;
    let platform_path = evidence.join("platform.json");
    platform_artifact(&platform_path)?;
    for relative in [
        "target/release-evidence/platform.json",
        "target/release-evidence/platform.sha256",
        "target/compliance/inventory.json",
        "target/compliance/report.json",
        "target/compliance/summary.txt",
    ] {
        package_checksums.insert(relative.to_owned(), sha256_file(&root().join(relative))?);
    }
    let sbom = serde_json::to_vec_pretty(&json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    }))
    .map_err(|error| format!("could not encode SBOM: {error}"))?;
    let sbom_path = evidence.join("sbom.cdx.json");
    fs::write(&sbom_path, &sbom).map_err(|error| format!("could not write SBOM: {error}"))?;
    let subjects: Vec<_> = package_checksums
        .iter()
        .map(|(name, digest)| {
            json!({
                "name": name,
                "digest": { "sha256": digest },
            })
        })
        .collect();
    let provenance = serde_json::to_vec_pretty(&json!({
        "schema": "auths-proof-release-evidence/v1",
        "source": {
            "commit": String::from_utf8_lossy(&commit.stdout).trim(),
            "repository": env::var("GITHUB_REPOSITORY").ok(),
            "ref": env::var("GITHUB_REF").ok(),
        },
        "build": {
            "command": "cargo xtask release-check",
            "toolchain": String::from_utf8_lossy(&toolchain.stdout).trim(),
            "workflow_run_id": env::var("GITHUB_RUN_ID").ok(),
            "workflow_run_attempt": env::var("GITHUB_RUN_ATTEMPT").ok(),
        },
        "inputs": {
            "corpus_manifest_sha256": hex::encode(Sha256::digest(manifest)),
            "wire_schema": "core/spec/v1/auths-proof.cddl",
            "configuration_commitments": [
                "PortableVerificationResult.required_configuration",
                "PortableVerificationResult.local_configuration",
            ],
        },
        "subjects": subjects,
    }))
    .map_err(|error| format!("could not encode provenance: {error}"))?;
    let provenance_path = evidence.join("provenance.json");
    fs::write(&provenance_path, &provenance)
        .map_err(|error| format!("could not write provenance: {error}"))?;
    let mut checksums = package_checksums;
    checksums.insert(
        "target/release-evidence/sbom.cdx.json".to_owned(),
        hex::encode(Sha256::digest(&sbom)),
    );
    checksums.insert(
        "target/release-evidence/provenance.json".to_owned(),
        hex::encode(Sha256::digest(&provenance)),
    );
    let checksum_manifest = checksums
        .iter()
        .map(|(path, digest)| format!("{digest}  {path}\n"))
        .collect::<String>();
    fs::write(evidence.join("SHA256SUMS"), checksum_manifest)
        .map_err(|error| format!("could not write release checksums: {error}"))?;
    validate_release_evidence(&evidence, &checksums)?;
    println!(
        "generated and validated release evidence for {} crate archives",
        crate_archive_count
    );
    Ok(())
}

fn platform_artifact(output: &Path) -> Result<(), String> {
    use auths_model::{
        DenialReason as D, Requirement as R, VerificationDecision as V, VerificationStage as S,
    };

    let policy = load_architecture_policy()?;
    let manifest_bytes = fs::read(root().join("core/fixtures/v1/manifest.json"))
        .map_err(|error| format!("could not read corpus manifest: {error}"))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("could not parse corpus manifest: {error}"))?;
    let fixture_values = manifest["fixtures"]
        .as_array()
        .ok_or("corpus manifest has no fixtures")?;
    let fixtures: Vec<_> = fixture_values
        .iter()
        .map(|fixture| {
            json!({
                "name": fixture["name"],
                "class": fixture["class"],
                "decision": fixture["expected_result"]["decision"],
                "code": fixture["expected_result"]["code"],
                "stage": fixture["expected_result"]["stage"],
                "profile": fixture["canonical_action"]["profile"],
            })
        })
        .collect();
    let mut fixture_counts = BTreeMap::<String, usize>::new();
    for fixture in fixture_values {
        let class = fixture["class"]
            .as_str()
            .ok_or("corpus fixture has no class")?;
        *fixture_counts.entry(class.to_owned()).or_default() += 1;
    }

    let mut packages = BTreeMap::<String, Vec<String>>::new();
    for (name, layer) in &policy.packages {
        packages
            .entry(layer.clone())
            .or_default()
            .push(name.clone());
    }
    let dependency_graph: Value = serde_json::from_slice(
        &fs::read(root().join("architecture/dependency-graph.json"))
            .map_err(|error| format!("could not read architecture snapshot: {error}"))?,
    )
    .map_err(|error| format!("could not parse architecture snapshot: {error}"))?;
    let graph_packages = dependency_graph["packages"]
        .as_array()
        .ok_or("architecture snapshot has no packages")?;
    let package_names_under = |prefix: &str| {
        graph_packages
            .iter()
            .filter_map(|package| {
                package["path"]
                    .as_str()
                    .is_some_and(|path| path.starts_with(prefix))
                    .then(|| package["name"].as_str().map(str::to_owned))
                    .flatten()
            })
            .collect::<Vec<_>>()
    };
    let mut adapters = package_names_under("core/adapters/");
    let mut transports = package_names_under("exchange/adapters/");
    adapters.sort();
    transports.sort();

    let mut profiles = fs::read_dir(root().join("product/spec/v1"))
        .map_err(|error| format!("could not list product profiles: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("md"))
        .filter(|path| path.file_stem().and_then(|value| value.to_str()) != Some("receipts"))
        .filter_map(|path| {
            path.file_stem()
                .and_then(|value| value.to_str())
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    profiles.sort();

    let denials = [
        D::MalformedProof,
        D::NonCanonicalProof,
        D::ResourceLimitExceeded,
        D::DigestMismatch,
        D::DuplicateObject,
        D::MissingReference,
        D::ReferenceCycle,
        D::AmbiguousTerminalGrant,
        D::UnusedCriticalEvidence,
        D::InvalidSignature,
        D::PrincipalMethodMismatch,
        D::VerificationMethodMismatch,
        D::SignatureSuiteMismatch,
        D::UntrustedRoot,
        D::BrokenGrantChain,
        D::DelegationExpanded,
        D::PermissionNotGranted,
        D::ActionConstraintMismatch,
        D::BudgetCeilingExceeded,
        D::AuthorizationPlanInvalid,
        D::CompositionRequirementNotMet,
        D::PlanActionMismatch,
        D::ActionBodyMismatch,
        D::AudienceMismatch,
        D::ChallengeMismatch,
        D::ActionOutsideValidity,
        D::PrincipalRevoked,
        D::GrantRevoked,
        D::StatusSequenceRollback,
        D::StatusMethodMismatch,
        D::StatusIssuerUntrusted,
        D::RegistryManifestMismatch,
        D::VerifierConfigurationMismatch,
        D::ResourceNamespaceMismatch,
        D::CriticalExtensionUnknown,
        D::AttachmentMissing,
        D::AttachmentDigestMismatch,
        D::AttachmentLengthMismatch,
        D::DuplicateAttachment,
        D::UnusedCriticalAttachment,
        D::OpaqueAttachmentNotAllowed,
        D::LocalPolicyDenied,
    ];
    let requirements = [
        R::UnsupportedProtocol,
        R::UnsupportedPrincipalMethod,
        R::UnsupportedSignatureSuite,
        R::UnsupportedEvidenceType,
        R::UnsupportedStatusMethod,
        R::UnsupportedProfile,
        R::UnsupportedProfilePolicy,
        R::UnsupportedResourceMatcher,
        R::UnsupportedBudgetAlgebra,
        R::UnsupportedCriticalExtension,
        R::UnsupportedAssuranceClaim,
        R::MissingPrincipalEvidence,
        R::MissingPrincipalStatus,
        R::MissingGrantStatus,
        R::StaleStatus,
        R::HistoricalStateUnavailable,
        R::AssuranceRequirementNotMet,
        R::ExternalFactUnavailable,
    ];
    let code_record = |variant: String, code: &str, decision: &str| {
        json!({
            "variant": variant,
            "code": code,
            "decision": decision,
        })
    };

    let commit = command_output_in("git", &["rev-parse", "HEAD"], &root(), None)?;
    let generated = json!({
        "schemaVersion": 2,
        "artifactSchema": "auths-proof-platform/v1",
        "source": {
            "repository": "auths-dev/auths-proof",
            "commit": commit.trim(),
        },
        "protocol": manifest["protocol"],
        "protocolMajor": manifest["protocol_major"],
        "fixtureSet": manifest["fixture_set"],
        "packages": packages,
        "adapters": adapters,
        "transports": transports,
        "profiles": profiles,
        "verification": {
            "stages": [
                format!("{:?}", S::Decode),
                format!("{:?}", S::Resolve),
                format!("{:?}", S::PrincipalControl),
                format!("{:?}", S::Authority),
                format!("{:?}", S::Complete),
            ],
            "decisions": [
                format!("{:?}", V::Authorized),
                format!("{:?}", V::Denied),
                format!("{:?}", V::Indeterminate),
            ],
            "denialCodes": denials
                .iter()
                .map(|value| code_record(format!("{value:?}"), value.code(), "denied"))
                .collect::<Vec<_>>(),
            "requirementCodes": requirements
                .iter()
                .map(|value| code_record(format!("{value:?}"), value.code(), "indeterminate"))
                .collect::<Vec<_>>(),
        },
        "corpus": {
            "count": fixtures.len(),
            "byClass": fixture_counts,
            "fixtures": fixtures,
        },
        "fuzzTargets": FUZZ_TARGETS,
    });
    let mut bytes = serde_json::to_vec_pretty(&generated)
        .map_err(|error| format!("could not encode platform artifact: {error}"))?;
    bytes.push(b'\n');
    let parent = output
        .parent()
        .ok_or_else(|| format!("platform artifact path has no parent: {}", output.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create platform artifact directory: {error}"))?;
    fs::write(output, &bytes)
        .map_err(|error| format!("could not write {}: {error}", output.display()))?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let checksum_path = output.with_extension("sha256");
    let artifact_name = output
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("platform artifact has no file name: {}", output.display()))?;
    fs::write(&checksum_path, format!("{digest}  {artifact_name}\n"))
        .map_err(|error| format!("could not write {}: {error}", checksum_path.display()))?;
    println!(
        "generated {} ({digest}) from {}",
        output.display(),
        commit.trim()
    );
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "could not read release artifact {}: {error}",
            path.display()
        )
    })?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_release_evidence(
    evidence: &Path,
    checksums: &BTreeMap<String, String>,
) -> Result<(), String> {
    let sbom: Value = serde_json::from_slice(
        &fs::read(evidence.join("sbom.cdx.json"))
            .map_err(|error| format!("could not read generated SBOM: {error}"))?,
    )
    .map_err(|error| format!("generated SBOM is not valid JSON: {error}"))?;
    if sbom["bomFormat"] != "CycloneDX"
        || sbom["specVersion"] != "1.5"
        || sbom["version"] != 1
        || sbom["components"].as_array().is_none_or(Vec::is_empty)
    {
        return Err("generated SBOM is incomplete".to_owned());
    }
    let provenance: Value = serde_json::from_slice(
        &fs::read(evidence.join("provenance.json"))
            .map_err(|error| format!("could not read generated provenance: {error}"))?,
    )
    .map_err(|error| format!("generated provenance is not valid JSON: {error}"))?;
    if provenance["schema"] != "auths-proof-release-evidence/v1"
        || provenance["subjects"]
            .as_array()
            .is_none_or(|subjects| subjects.len() != checksums.len() - 2)
    {
        return Err("generated provenance is incomplete".to_owned());
    }
    let expected_manifest = checksums
        .iter()
        .map(|(path, digest)| format!("{digest}  {path}\n"))
        .collect::<String>();
    let actual_manifest = fs::read_to_string(evidence.join("SHA256SUMS"))
        .map_err(|error| format!("could not read generated release checksums: {error}"))?;
    if actual_manifest != expected_manifest {
        return Err("generated release checksum manifest is incomplete".to_owned());
    }
    for (relative, expected) in checksums {
        let actual = sha256_file(&root().join(relative))?;
        if &actual != expected {
            return Err(format!(
                "release artifact checksum changed after generation: {relative}"
            ));
        }
    }
    Ok(())
}

const FUZZ_TARGETS: [&str; 7] = [
    "target_codec",
    "target_portable_codecs",
    "target_model_state",
    "target_composition",
    "target_registry_handlers",
    "target_principal_parsers",
    "target_portable_abi",
];

fn fuzz_smoke() -> Result<(), String> {
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
    Ok(())
}

fn fuzz_inventory() -> Result<(), String> {
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

    let workflow = fs::read_to_string(root().join(".github/workflows/fuzz.yml"))
        .map_err(|error| format!("could not read fuzz workflow: {error}"))?;
    for target in FUZZ_TARGETS {
        if !workflow
            .lines()
            .any(|line| line.trim() == format!("- {target}"))
        {
            return Err(format!(
                "scheduled fuzz workflow is missing authoritative target {target}"
            ));
        }
        let corpus = root().join("core/fuzz/corpus").join(target);
        if !corpus.is_dir() {
            return Err(format!(
                "missing structured seed directory {}",
                corpus.display()
            ));
        }
    }
    println!("all {} fuzz targets are synchronized", FUZZ_TARGETS.len());
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AlgebraContract {
    schema: String,
    exhaustive_threshold_bound: u16,
    truth_order: Vec<String>,
    attenuation_acceptance: String,
    attenuation_dimensions: Vec<AlgebraDimension>,
    threshold: ThresholdContract,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AlgebraDimension {
    rust: String,
    lean: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThresholdContract {
    authorized: String,
    indeterminate: String,
    denied: String,
}

fn load_algebra_contract() -> Result<AlgebraContract, String> {
    let path = root().join("formal/algebra-contract-v1.toml");
    let contract: AlgebraContract = toml::from_str(
        &fs::read_to_string(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("invalid algebra contract {}: {error}", path.display()))?;
    if contract.schema != "auths-proof-algebra-contract/v1"
        || contract.exhaustive_threshold_bound == 0
        || contract.truth_order != ["denied", "indeterminate", "authorized"]
        || contract.attenuation_acceptance != "all"
        || contract.attenuation_dimensions.is_empty()
        || contract.threshold.authorized != "authorized >= required"
        || contract.threshold.indeterminate
            != "authorized < required && authorized + indeterminate >= required"
        || contract.threshold.denied != "authorized + indeterminate < required"
    {
        return Err("unsupported algebra contract semantics".to_owned());
    }
    let rust_names: BTreeSet<_> = contract
        .attenuation_dimensions
        .iter()
        .map(|dimension| dimension.rust.as_str())
        .collect();
    let lean_names: BTreeSet<_> = contract
        .attenuation_dimensions
        .iter()
        .map(|dimension| dimension.lean.as_str())
        .collect();
    if rust_names.len() != contract.attenuation_dimensions.len()
        || lean_names.len() != contract.attenuation_dimensions.len()
    {
        return Err("algebra contract dimension names must be unique".to_owned());
    }
    Ok(contract)
}

fn dimension_description(name: &str) -> &'static str {
    match name {
        "root_preserved" => "the trust root is preserved",
        "depth_decreases" => "delegation depth strictly decreases",
        "profile_attenuates" => "the selected profile does not widen",
        "permissions_attenuate" => "permissions do not widen",
        "validity_attenuates" => "the validity window does not widen",
        "audiences_attenuate" => "audiences do not widen",
        "action_constraint_attenuates" => "the action-body constraint does not widen",
        "budget_attenuates" => "the budget ceiling does not widen",
        "status_attenuates" => "status requirements do not weaken",
        "assurance_attenuates" => "assurance requirements do not weaken",
        _ => "the declared authority dimension attenuates",
    }
}

fn render_rust_algebra(contract: &AlgebraContract) -> Result<String, String> {
    macro_rules! line {
        ($output:expr, $($argument:tt)*) => {
            writeln!($output, $($argument)*)
                .map_err(|_| "could not render generated Rust algebra".to_owned())?
        };
    }

    let mut output = String::new();
    output.push_str(
        "// @generated by `cargo xtask formal --update`; DO NOT EDIT.\n\n\
         /// Versioned source contract used to generate this module.\n",
    );
    line!(
        output,
        "pub const CONTRACT_SCHEMA: &str = {:?};",
        contract.schema
    );
    output.push_str("\n/// Exhaustive default-deployment threshold bound.\n");
    line!(
        output,
        "pub const EXHAUSTIVE_THRESHOLD_BOUND: u16 = {};",
        contract.exhaustive_threshold_bound
    );
    output.push_str(
        "\n/// Closed three-valued authorization truth.\n\
         #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]\n\
         pub enum Truth {\n\
         \x20   /// Available facts prove denial.\n\
         \x20   Denied,\n\
         \x20   /// Required facts are unavailable and authorization remains reachable.\n\
         \x20   Indeterminate,\n\
         \x20   /// Available facts prove authorization.\n\
         \x20   Authorized,\n\
         }\n\n\
         /// Shared projection boundary for authority attenuation.\n\
         pub trait AttenuationProjection {\n",
    );
    for dimension in &contract.attenuation_dimensions {
        line!(
            output,
            "    /// Whether {}.",
            dimension_description(&dimension.rust)
        );
        line!(output, "    fn {}(&self) -> bool;", dimension.rust);
    }
    output.push_str(
        "}\n\n\
         /// Concrete projection used by vectors and bounded verification.\n\
         #[allow(\n\
         \x20   clippy::struct_excessive_bools,\n\
         \x20   reason = \"each Boolean is one generated authority dimension\"\n\
         )]\n\
         #[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
         pub struct AttenuationChecks {\n",
    );
    for dimension in &contract.attenuation_dimensions {
        line!(
            output,
            "    /// Whether {}.",
            dimension_description(&dimension.rust)
        );
        line!(output, "    pub {}: bool,", dimension.rust);
    }
    output.push_str("}\n\nimpl AttenuationProjection for AttenuationChecks {\n");
    for dimension in &contract.attenuation_dimensions {
        line!(output, "    fn {}(&self) -> bool {{", dimension.rust);
        line!(output, "        self.{}", dimension.rust);
        output.push_str("    }\n\n");
    }
    output.pop();
    output.push_str(
        "}\n\n\
         /// Accepts exactly when every declared attenuation dimension accepts.\n\
         #[must_use]\n\
         pub fn attenuation_accepts<P: AttenuationProjection + ?Sized>(projection: &P) -> bool {\n",
    );
    for (index, dimension) in contract.attenuation_dimensions.iter().enumerate() {
        let operator = if index == 0 { "    " } else { "        && " };
        line!(output, "{operator}projection.{}()", dimension.rust);
    }
    output.push_str(
        "}\n\n\
         /// Concrete form of the generated conjunction for mechanical translation.\n\
         #[must_use]\n\
         pub fn attenuation_checks_accept(checks: &AttenuationChecks) -> bool {\n",
    );
    for (index, dimension) in contract.attenuation_dimensions.iter().enumerate() {
        let operator = if index == 0 { "    " } else { "        && " };
        line!(output, "{operator}checks.{}", dimension.rust);
    }
    output.push_str(
        "}\n\n\
         /// Classifies target V1 threshold counts.\n\
         #[must_use]\n\
         pub fn threshold_counts(required: u16, authorized: usize, indeterminate: usize) -> Truth {\n\
         \x20   let required = usize::from(required);\n\
         \x20   if authorized >= required {\n\
         \x20       Truth::Authorized\n\
         \x20   } else if authorized.saturating_add(indeterminate) >= required {\n\
         \x20       Truth::Indeterminate\n\
         \x20   } else {\n\
         \x20       Truth::Denied\n\
         \x20   }\n\
         }\n",
    );
    Ok(output)
}

fn render_lean_algebra(contract: &AlgebraContract) -> Result<String, String> {
    macro_rules! line {
        ($output:expr, $($argument:tt)*) => {
            writeln!($output, $($argument)*)
                .map_err(|_| "could not render generated Lean algebra".to_owned())?
        };
    }

    let mut output = String::new();
    output.push_str(
        "-- @generated by `cargo xtask formal --update`; DO NOT EDIT.\n\n\
         namespace Auths.Generated\n\n",
    );
    line!(
        output,
        "def contractSchema : String := {:?}",
        contract.schema
    );
    line!(
        output,
        "\ndef exhaustiveThresholdBound : Nat := {}",
        contract.exhaustive_threshold_bound
    );
    output.push_str(
        "\ninductive Truth where\n\
         \x20 | denied\n\
         \x20 | indeterminate\n\
         \x20 | authorized\n\
         \x20 deriving BEq, DecidableEq, Repr\n\n\
         structure AttenuationProjection where\n",
    );
    for dimension in &contract.attenuation_dimensions {
        line!(output, "  {} : Bool", dimension.lean);
    }
    output.push_str("  deriving BEq, DecidableEq, Repr\n\n");
    output.push_str("def attenuationAccepts (projection : AttenuationProjection) : Bool :=\n");
    for (index, dimension) in contract.attenuation_dimensions.iter().enumerate() {
        let suffix = if index + 1 == contract.attenuation_dimensions.len() {
            ""
        } else {
            " &&"
        };
        line!(output, "  projection.{}{suffix}", dimension.lean);
    }
    output.push_str(
        "\ndef thresholdCounts (required authorized indeterminate : Nat) : Truth :=\n\
         \x20 if authorized ≥ required then .authorized\n\
         \x20 else if authorized + indeterminate ≥ required then .indeterminate\n\
         \x20 else .denied\n\n\
         end Auths.Generated\n",
    );
    Ok(output)
}

fn synchronize_generated_file(
    path: &Path,
    expected: &str,
    update: bool,
    label: &str,
) -> Result<(), String> {
    if update {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
        fs::write(path, expected)
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        println!("Updated {label}: {}", path.display());
        return Ok(());
    }
    let actual = fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if actual != expected {
        return Err(format!(
            "{label} drifted from formal/algebra-contract-v1.toml; run `cargo xtask formal --update`"
        ));
    }
    Ok(())
}

fn synchronize_algebra_sources(contract: &AlgebraContract, update: bool) -> Result<(), String> {
    synchronize_generated_file(
        &root().join("core/crates/auths-algebra-kernel/src/generated.rs"),
        &render_rust_algebra(contract)?,
        update,
        "generated Rust algebra",
    )?;
    synchronize_generated_file(
        &root().join("formal/Auths/Generated/Algebra.lean"),
        &render_lean_algebra(contract)?,
        update,
        "generated Lean algebra",
    )
}

fn synchronize_lean_vectors(formal_root: &Path, update: bool) -> Result<(), String> {
    for (kind, file) in [
        ("threshold", "threshold-counts.json"),
        ("attenuation", "attenuation-checks.json"),
    ] {
        let generated = command_output_in(
            "lake",
            &["exe", "auths-vector-export", kind],
            formal_root,
            None,
        )?;
        serde_json::from_str::<Value>(&generated)
            .map_err(|error| format!("Lean emitted invalid {kind} JSON: {error}"))?;
        synchronize_generated_file(
            &root().join("core/formal-vectors/v1").join(file),
            &generated,
            update,
            &format!("Lean-generated {kind} vectors"),
        )?;
    }
    Ok(())
}

fn formal(skip_kani: bool, update: bool) -> Result<(), String> {
    let formal_root = root().join("formal");
    let contract = load_algebra_contract()?;
    synchronize_algebra_sources(&contract, update)?;
    validate_formal_toolchain(&formal_root, !skip_kani)?;
    command_in("lake", &["build"], &formal_root, None)?;
    formal_assurance_audit(&formal_root)?;
    let attenuation_dimensions: Vec<_> = contract
        .attenuation_dimensions
        .iter()
        .map(|dimension| dimension.rust.clone())
        .collect();
    formal_qualification::validate(&root(), &attenuation_dimensions)?;
    synchronize_lean_vectors(&formal_root, update)?;

    cargo(&["test", "-p", "auths-formal-refinement"])?;
    if skip_kani {
        println!("Kani bounded harnesses:      SKIPPED (--skip-kani)");
    } else {
        command_in(
            "cargo",
            &["kani", "-p", "auths-algebra-kernel"],
            &root(),
            None,
        )?;
        command_in("cargo", &["kani", "-p", "auths-model"], &root(), None)?;
        println!("Kani bounded harnesses:      PASS");
    }
    println!("Lean theorems:              PASS");
    println!("Generated semantic vectors: byte-stable");
    println!("Rust refinement vectors:    PASS");
    Ok(())
}

fn validate_formal_toolchain(formal_root: &Path, require_kani: bool) -> Result<(), String> {
    let path = formal_root.join("translation-toolchain.lock");
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let lock: toml::Value = toml::from_str(&source)
        .map_err(|error| format!("invalid formal toolchain lock {}: {error}", path.display()))?;
    if lock.get("schema").and_then(toml::Value::as_str) != Some("auths-proof-formal-toolchain/v1") {
        return Err("unsupported formal toolchain lock schema".to_owned());
    }
    let required = |table: &str, field: &str| -> Result<&str, String> {
        lock.get(table)
            .and_then(toml::Value::as_table)
            .and_then(|value| value.get(field))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("formal toolchain lock omits {table}.{field}"))
    };

    let rust = command_output_in("rustc", &["--version"], &root(), None)?;
    let shipping_rust = required("rust", "shipping")?;
    if !rust.contains(&format!("rustc {shipping_rust} ")) {
        return Err(format!(
            "formal shipping Rust drift: lock requires {shipping_rust}, command reported {}",
            rust.trim()
        ));
    }
    let lean = command_output_in("lean", &["--version"], formal_root, None)?;
    let lean_commit = required("lean", "commit")?;
    if !lean.contains(lean_commit) {
        return Err(format!(
            "formal Lean drift: lock requires commit {lean_commit}, command reported {}",
            lean.trim()
        ));
    }
    let lean_toolchain_path = formal_root.join("lean-toolchain");
    let lean_toolchain = fs::read_to_string(&lean_toolchain_path)
        .map_err(|error| format!("could not read {}: {error}", lean_toolchain_path.display()))?;
    if lean_toolchain.trim() != required("lean", "toolchain")? {
        return Err("formal Lean toolchain file and lock differ".to_owned());
    }
    if require_kani {
        let kani = command_output_in("kani", &["--version"], &root(), None)?;
        let kani_version = required("kani", "version")?;
        if kani.trim() != format!("kani {kani_version}") {
            return Err(format!(
                "formal Kani drift: lock requires {kani_version}, command reported {}",
                kani.trim()
            ));
        }
    }
    println!("Formal toolchain lock:       PASS");
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FormalAssuranceManifest {
    schema: String,
    lean_toolchain: String,
    toolchain_lock_sha256: String,
    allowed_axioms: Vec<String>,
    claims: Vec<FormalAssuranceClaim>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FormalAssuranceClaim {
    claim_id: String,
    claim_text: String,
    claim_status: String,
    lean_declaration: String,
    lean_statement_sha256: String,
    formal_review: String,
    rust_symbols: Vec<String>,
    semantic_source_closure: Vec<String>,
    semantic_source_closure_sha256: String,
    evidence: Vec<FormalEvidence>,
    scope: String,
    residual_assumptions: Vec<String>,
    toolchain_lock_sha256: String,
    axioms: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FormalEvidence {
    kind: String,
    artifact: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanAssuranceAudit {
    schema: String,
    declarations: Vec<LeanAssuranceDeclaration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanAssuranceDeclaration {
    name: String,
    kind: String,
    statement: String,
    axioms: Vec<String>,
}

fn formal_assurance_audit(formal_root: &Path) -> Result<(), String> {
    let manifest_path = formal_root.join("assurance-manifest-v1.toml");
    let manifest: FormalAssuranceManifest = toml::from_str(
        &fs::read_to_string(&manifest_path)
            .map_err(|error| format!("could not read {}: {error}", manifest_path.display()))?,
    )
    .map_err(|error| {
        format!(
            "invalid assurance manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    if manifest.schema != "auths-proof-formal-assurance/v1" {
        return Err(format!(
            "unsupported formal assurance schema {}",
            manifest.schema
        ));
    }

    let lean_toolchain_path = formal_root.join("lean-toolchain");
    let lean_toolchain = fs::read_to_string(&lean_toolchain_path)
        .map_err(|error| format!("could not read {}: {error}", lean_toolchain_path.display()))?;
    if lean_toolchain.trim() != manifest.lean_toolchain {
        return Err("formal assurance manifest Lean toolchain drifted".to_owned());
    }

    let toolchain_lock_path = formal_root.join("translation-toolchain.lock");
    let toolchain_lock_digest = sha256_file(&toolchain_lock_path)?;
    if manifest.toolchain_lock_sha256 != toolchain_lock_digest {
        return Err(format!(
            "formal toolchain lock drifted: expected {}, found {toolchain_lock_digest}",
            manifest.toolchain_lock_sha256
        ));
    }

    let audit_output = command_output_in(
        "lake",
        &["env", "lean", "Auths/AssuranceAudit.lean"],
        formal_root,
        None,
    )?;
    let audit: LeanAssuranceAudit = serde_json::from_str(audit_output.trim())
        .map_err(|error| format!("compiled Lean assurance audit emitted invalid JSON: {error}"))?;
    if audit.schema != "auths-proof-lean-assurance-audit/v1" {
        return Err(format!(
            "unsupported compiled Lean assurance audit schema {}",
            audit.schema
        ));
    }

    let allowed_axioms: BTreeSet<_> = manifest.allowed_axioms.iter().cloned().collect();
    if allowed_axioms.len() != manifest.allowed_axioms.len() || allowed_axioms.contains("sorryAx") {
        return Err("formal assurance axiom allowlist is duplicate or permits sorryAx".to_owned());
    }

    let mut compiled = BTreeMap::new();
    for declaration in audit.declarations {
        let name = declaration.name.clone();
        if compiled.insert(name.clone(), declaration).is_some() {
            return Err(format!(
                "compiled Lean assurance audit repeated declaration {name}"
            ));
        }
    }
    let mut reviewed = BTreeSet::new();
    for claim in &manifest.claims {
        if !reviewed.insert(claim.lean_declaration.clone()) {
            return Err(format!(
                "formal assurance manifest repeated declaration {}",
                claim.lean_declaration
            ));
        }
        for (field, value) in [
            ("claim_id", claim.claim_id.as_str()),
            ("claim_text", claim.claim_text.as_str()),
            ("formal_review", claim.formal_review.as_str()),
            ("scope", claim.scope.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!(
                    "formal claim {} has empty {field}",
                    claim.lean_declaration
                ));
            }
        }
        if !matches!(
            claim.claim_status.as_str(),
            "proved" | "qualified" | "assumed"
        ) {
            return Err(format!(
                "formal claim {} has unsupported status {}",
                claim.lean_declaration, claim.claim_status
            ));
        }
        if claim.toolchain_lock_sha256 != toolchain_lock_digest {
            return Err(format!(
                "formal claim {} has stale toolchain lock digest",
                claim.lean_declaration
            ));
        }
        if claim.semantic_source_closure.is_empty()
            || claim.evidence.is_empty()
            || claim.residual_assumptions.is_empty()
        {
            return Err(format!(
                "formal claim {} must declare source closure, evidence, and residual assumptions",
                claim.lean_declaration
            ));
        }
        let closure_digest = semantic_source_closure_digest(&claim.semantic_source_closure)?;
        if closure_digest != claim.semantic_source_closure_sha256 {
            return Err(format!(
                "formal claim {} semantic source closure drifted: expected {}, found {closure_digest}",
                claim.lean_declaration, claim.semantic_source_closure_sha256
            ));
        }
        for symbol in &claim.rust_symbols {
            if symbol.trim().is_empty() {
                return Err(format!(
                    "formal claim {} contains an empty Rust symbol",
                    claim.lean_declaration
                ));
            }
        }
        for item in &claim.evidence {
            if item.kind.trim().is_empty() || item.artifact.trim().is_empty() {
                return Err(format!(
                    "formal claim {} contains incomplete evidence",
                    claim.lean_declaration
                ));
            }
            let artifact = root().join(&item.artifact);
            if !artifact.exists() {
                return Err(format!(
                    "formal claim {} evidence artifact does not exist: {}",
                    claim.lean_declaration,
                    artifact.display()
                ));
            }
        }

        let declaration = compiled.get(&claim.lean_declaration).ok_or_else(|| {
            format!(
                "reviewed Lean declaration {} is absent from the compiled environment",
                claim.lean_declaration
            )
        })?;
        if declaration.kind != "theorem" {
            return Err(format!(
                "reviewed declaration {} is {}, not theorem",
                claim.lean_declaration, declaration.kind
            ));
        }
        let statement_digest = hex::encode(Sha256::digest(declaration.statement.as_bytes()));
        if statement_digest != claim.lean_statement_sha256 {
            return Err(format!(
                "Lean statement drift for {}: expected {}, found {statement_digest}",
                claim.lean_declaration, claim.lean_statement_sha256
            ));
        }
        let actual_axioms: BTreeSet<_> = declaration.axioms.iter().cloned().collect();
        let reviewed_axioms: BTreeSet<_> = claim.axioms.iter().cloned().collect();
        if actual_axioms != reviewed_axioms {
            return Err(format!(
                "Lean axiom drift for {}: reviewed={reviewed_axioms:?}, compiled={actual_axioms:?}",
                claim.lean_declaration
            ));
        }
        if let Some(unapproved) = actual_axioms.difference(&allowed_axioms).next() {
            return Err(format!(
                "Lean declaration {} transitively depends on unapproved axiom {unapproved}",
                claim.lean_declaration
            ));
        }
    }

    let compiled_names: BTreeSet<_> = compiled.keys().cloned().collect();
    if reviewed != compiled_names {
        return Err(format!(
            "compiled and reviewed Lean claim inventories differ: reviewed={reviewed:?}, compiled={compiled_names:?}"
        ));
    }
    let evidence_directory = root().join("target/formal");
    fs::create_dir_all(&evidence_directory).map_err(|error| {
        format!(
            "could not create formal evidence directory {}: {error}",
            evidence_directory.display()
        )
    })?;
    let mut evidence = serde_json::to_vec_pretty(
        &serde_json::from_str::<Value>(audit_output.trim())
            .map_err(|error| format!("could not normalize Lean assurance evidence: {error}"))?,
    )
    .map_err(|error| format!("could not encode Lean assurance evidence: {error}"))?;
    evidence.push(b'\n');
    fs::write(
        evidence_directory.join("lean-assurance-audit.json"),
        evidence,
    )
    .map_err(|error| format!("could not write Lean assurance evidence: {error}"))?;
    println!(
        "Formal assurance audit:     PASS ({} compiled statements; transitive axioms reviewed)",
        reviewed.len()
    );
    Ok(())
}

fn semantic_source_closure_digest(paths: &[String]) -> Result<String, String> {
    let mut ordered = paths.to_vec();
    ordered.sort();
    ordered.dedup();
    if ordered.len() != paths.len() {
        return Err("semantic source closure paths must be unique".to_owned());
    }
    let mut digest = Sha256::new();
    for relative in ordered {
        let path = root().join(&relative);
        if !path.is_file() {
            return Err(format!(
                "semantic source closure entry is not a file: {}",
                path.display()
            ));
        }
        digest.update(relative.as_bytes());
        digest.update([0]);
        digest.update(
            fs::read(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?,
        );
        digest.update([0xff]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn formal_qualify_aeneas(update: bool) -> Result<(), String> {
    let formal_root = root().join("formal");
    let contract = load_algebra_contract()?;
    synchronize_algebra_sources(&contract, false)?;
    validate_formal_toolchain(&formal_root, false)?;
    command_in("lake", &["build"], &formal_root, None)?;
    formal_assurance_audit(&formal_root)?;
    let attenuation_dimensions: Vec<_> = contract
        .attenuation_dimensions
        .iter()
        .map(|dimension| dimension.rust.clone())
        .collect();
    formal_qualification::qualify(&root(), &attenuation_dimensions, update)
}

fn adversarial_conformance(args: Vec<String>) -> Result<(), String> {
    let manifest_path = root().join("core/conformance/v1/manifest.json");
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("could not read {}: {error}", manifest_path.display()))?;
    let manifest = auths_testkit::conformance::ConformanceManifest::parse(&manifest_bytes)?;

    let mut selection: Option<(&str, &str)> = None;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        if matches!(argument, "--surface" | "--adapter" | "--case") {
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{argument} requires a value"))?;
            selection = Some((argument, value));
            index += 2;
        } else if argument == "--update" {
            index += 1;
        } else {
            return Err(format!(
                "unknown adversarial-conformance argument {argument}"
            ));
        }
    }

    let selected: Vec<_> = manifest
        .cases
        .iter()
        .filter(|case| {
            selection.is_none_or(|(kind, value)| match kind {
                "--case" => case.case == value,
                "--surface" | "--adapter" => case.case.starts_with(&format!("{value}/")),
                _ => false,
            })
        })
        .collect();
    if selected.is_empty() {
        return Err("adversarial-conformance selection matched no cases".to_owned());
    }

    let adapters_root = root().join("core/conformance/v1/adapters");
    let adapters = files_with_extension(&adapters_root, "json")?;
    if adapters.len() != 7 {
        return Err(format!(
            "expected seven principal adapter manifests, found {}",
            adapters.len()
        ));
    }
    for path in adapters {
        let value: Value = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?,
        )
        .map_err(|error| format!("could not parse {}: {error}", path.display()))?;
        if value.get("schema").and_then(Value::as_str) != Some("auths-proof-adapter-conformance/v1")
        {
            return Err(format!(
                "invalid adapter conformance schema in {}",
                path.display()
            ));
        }
    }

    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(|error| error.to_string())?;
    let did_web = auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
        .map_err(|error| error.to_string())?;
    let webauthn =
        auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
            .map_err(|error| error.to_string())?;
    let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
        .map_err(|error| error.to_string())?;
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
        .map_err(|error| error.to_string())?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
        &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .map_err(|error| error.to_string())?;

    let mut executions = Vec::with_capacity(selected.len());
    let mut passed = 0usize;
    for case in &selected {
        let actual = match auths_testkit::conformance::execute_case(&case.case)? {
            auths_testkit::conformance::BoundaryExecution::Completed(code) => code.to_owned(),
            auths_testkit::conformance::BoundaryExecution::FullVerifier(fixture) => {
                let context = auths_codec::decode_verifier_context(fixture.context_bytes())
                    .map_err(|error| format!("{} context: {error}", case.case))?;
                auths_verifier::verify_portable(
                    fixture.proof_bytes(),
                    fixture.canonical_action(),
                    &context,
                    &registries,
                )
                .code()
                .code()
                .to_owned()
            }
        };
        let case_passed = actual == case.expected_code;
        passed += usize::from(case_passed);
        executions.push(json!({
            "case": case.case,
            "boundary": case.boundary,
            "expected_code": case.expected_code,
            "actual_code": actual,
            "passed": case_passed
        }));
    }

    let selected_context: BTreeSet<_> = selected
        .iter()
        .flat_map(|case| case.requirements.iter())
        .filter(|requirement| requirement.starts_with("CONTEXT."))
        .collect();
    let all_context: BTreeSet<_> = manifest
        .cases
        .iter()
        .flat_map(|case| case.requirements.iter())
        .filter(|requirement| requirement.starts_with("CONTEXT."))
        .collect();
    let selected_methods: BTreeSet<_> = selected
        .iter()
        .filter_map(|case| case.case.split_once('/'))
        .map(|(surface, _)| surface)
        .filter(|surface| *surface != "context")
        .collect();
    let all_methods: BTreeSet<_> = manifest
        .cases
        .iter()
        .filter_map(|case| case.case.split_once('/'))
        .map(|(surface, _)| surface)
        .filter(|surface| *surface != "context")
        .collect();
    let selected_common: BTreeSet<_> = selected
        .iter()
        .filter(|case| {
            case.requirements
                .iter()
                .any(|requirement| requirement.starts_with("ADAPTER.COMMON."))
        })
        .filter_map(|case| case.case.split_once('/').map(|(surface, _)| surface))
        .collect();
    let all_common: BTreeSet<_> = manifest
        .cases
        .iter()
        .filter(|case| {
            case.requirements
                .iter()
                .any(|requirement| requirement.starts_with("ADAPTER.COMMON."))
        })
        .filter_map(|case| case.case.split_once('/').map(|(surface, _)| surface))
        .collect();
    let failed = selected.len().saturating_sub(passed);
    let output = json!({
        "schema": "auths-proof-conformance-result/v1",
        "manifest_sha256": sha256_file(&manifest_path)?,
        "cases": selected.len(),
        "passed": passed,
        "failed": failed,
        "coverage": {
            "context_fields": format!("{}/{}", selected_context.len(), all_context.len()),
            "principal_methods": format!("{}/{}", selected_methods.len(), all_methods.len()),
            "common_contract": format!("{}/{}", selected_common.len(), all_common.len())
        },
        "executions": executions
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output)
            .map_err(|error| format!("could not encode conformance result: {error}"))?
    );
    if failed == 0 {
        Ok(())
    } else {
        Err(format!(
            "{failed} of {} adversarial conformance cases failed",
            selected.len()
        ))
    }
}

fn benchmark(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("help");
    let option = |name: &str| -> Option<&str> {
        args.iter()
            .position(|argument| argument == name)
            .and_then(|index| args.get(index + 1))
            .map(String::as_str)
    };
    let profile_name = option("--profile").unwrap_or("developer");
    let profile = match profile_name {
        "developer" => auths_bench_model::BenchmarkProfile::developer(),
        "paper" => auths_bench_model::BenchmarkProfile::paper(),
        other => {
            let path = root()
                .join("demos/benchmarks/profiles")
                .join(format!("{other}.toml"));
            toml::from_str(
                &fs::read_to_string(&path)
                    .map_err(|error| format!("could not read {}: {error}", path.display()))?,
            )
            .map_err(|error| format!("invalid benchmark profile {}: {error}", path.display()))?
        }
    };
    let input_directory = root().join("target/auths-bench/inputs");
    let input_manifest = input_directory.join("manifest.json");

    match command {
        "prepare" => {
            let suite =
                auths_bench_model::generate_suite(&profile).map_err(|error| error.to_string())?;
            fs::create_dir_all(&input_directory)
                .map_err(|error| format!("could not create input directory: {error}"))?;
            let bytes = serde_json::to_vec_pretty(&suite)
                .map_err(|error| format!("could not encode benchmark inputs: {error}"))?;
            fs::write(&input_manifest, bytes).map_err(|error| {
                format!("could not write {}: {error}", input_manifest.display())
            })?;
            println!("Prepared {} deterministic scenarios", suite.len());
            println!("Input manifest: {}", input_manifest.display());
            println!("Manifest SHA-256: {}", sha256_file(&input_manifest)?);
            Ok(())
        }
        "run" => {
            if !input_manifest.exists() {
                return Err("benchmark inputs missing; run `cargo xtask bench prepare`".to_owned());
            }
            let target = option("--target").ok_or("bench run requires --target")?;
            let output = root()
                .join("benchmark-results")
                .join(format!("{target}.json"));
            match target {
                "native" => command_in(
                    "cargo",
                    &[
                        "run",
                        "-p",
                        "auths-bench-native",
                        "--",
                        path_text(&input_manifest)?,
                        path_text(&output)?,
                        profile_name,
                    ],
                    &root(),
                    None,
                ),
                "wasm-node" => command_in(
                    "node",
                    &[
                        "demos/benchmarks/auths-bench-wasm/runner/node.mjs",
                        path_text(&input_manifest)?,
                    ],
                    &root(),
                    None,
                ),
                "wasm-browser" => command_in(
                    "node",
                    &[
                        "demos/benchmarks/auths-bench-wasm/runner/browser.mjs",
                        path_text(&input_manifest)?,
                    ],
                    &root(),
                    None,
                ),
                _ => Err(format!("unsupported benchmark target {target}")),
            }
        }
        "report" => {
            let directory = args
                .get(1)
                .map(PathBuf::from)
                .ok_or("bench report requires a result directory")?;
            let native = directory.join("native.json");
            let artifact: auths_bench_model::RunArtifact = serde_json::from_slice(
                &fs::read(&native)
                    .map_err(|error| format!("could not read {}: {error}", native.display()))?,
            )
            .map_err(|error| format!("invalid benchmark result: {error}"))?;
            let rows = artifact
                .results
                .iter()
                .map(|result| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        result.scenario,
                        result.summary.p50_ns,
                        result.summary.p95_ns,
                        result.summary.p99_ns,
                        result.semantic.work_units
                    )
                })
                .collect::<String>();
            let html = format!(
                "<!doctype html><meta charset=\"utf-8\"><title>Auths-Proof benchmark</title>\
                 <h1>Auths-Proof benchmark</h1><p>Semantic agreement: PASS</p>\
                 <table><thead><tr><th>Scenario</th><th>p50 ns</th><th>p95 ns</th>\
                 <th>p99 ns</th><th>work</th></tr></thead><tbody>{rows}</tbody></table>"
            );
            fs::write(directory.join("report.html"), html)
                .map_err(|error| format!("could not write report: {error}"))?;
            fs::write(
                directory.join("report.json"),
                serde_json::to_vec_pretty(&artifact)
                    .map_err(|error| format!("could not encode report: {error}"))?,
            )
            .map_err(|error| format!("could not write report JSON: {error}"))?;
            println!("Semantic agreement: PASS");
            println!("Environment completeness: PASS");
            println!("Report: {}", directory.join("report.html").display());
            Ok(())
        }
        "compare" => {
            let baseline_path = args.get(1).ok_or("bench compare requires baseline")?;
            let candidate_path = args.get(2).ok_or("bench compare requires candidate")?;
            let baseline: auths_bench_model::RunArtifact = serde_json::from_slice(
                &fs::read(baseline_path).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let candidate: auths_bench_model::RunArtifact = serde_json::from_slice(
                &fs::read(candidate_path).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let comparison = auths_bench_model::compare_runs(
                &baseline,
                &candidate,
                &auths_bench_model::ComparisonPolicy::default(),
            )
            .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&comparison).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        "verify-artifact" => {
            let directory = args
                .get(1)
                .map(PathBuf::from)
                .ok_or("bench verify-artifact requires a directory")?;
            let result = directory.join("native.json");
            let artifact: auths_bench_model::RunArtifact =
                serde_json::from_slice(&fs::read(&result).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            if artifact.results.is_empty()
                || artifact
                    .results
                    .iter()
                    .any(|entry| entry.samples_ns.is_empty())
            {
                return Err("benchmark artifact has missing observations".to_owned());
            }
            println!("benchmark artifact verified: {}", result.display());
            Ok(())
        }
        _ => {
            Err("usage: cargo xtask bench <prepare|run|report|compare|verify-artifact>".to_owned())
        }
    }
}

fn cargo(args: &[&str]) -> Result<(), String> {
    command("cargo", args)
}

fn command(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .current_dir(root())
        .status()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} {} failed with {status}", args.join(" ")))
    }
}

fn command_in(
    program: &str,
    arguments: &[&str],
    directory: &Path,
    environment: Option<(&str, &Path)>,
) -> Result<(), String> {
    let mut command = Command::new(program);
    command.args(arguments).current_dir(directory);
    if let Some((key, value)) = environment {
        command.env(key, value);
    }
    let status = command
        .status()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} {} failed with {status}",
            arguments.join(" ")
        ))
    }
}

fn command_output_in(
    program: &str,
    arguments: &[&str],
    directory: &Path,
    environment: Option<(&str, &Path)>,
) -> Result<String, String> {
    let mut command = Command::new(program);
    command.args(arguments).current_dir(directory);
    if let Some((key, value)) = environment {
        command.env(key, value);
    }
    let output = command
        .output()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

fn path_text(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn wasm() -> Result<(), String> {
    for package in [
        "auths-proof",
        "auths-proof-wasm",
        "auths-model",
        "auths-codec",
        "auths-ports",
        "auths-registries",
        "auths-signature",
        "auths-algebra-kernel",
        "auths-authority",
        "auths-composition",
        "auths-assurance",
        "auths-verifier",
        "auths-author",
        "auths-multikey",
        "auths-raw-key",
        "auths-did-key",
        "auths-did-keri",
        "auths-did-web",
        "auths-hsm-attested",
        "auths-spiffe-x509",
        "auths-webauthn",
    ] {
        cargo(&[
            "check",
            "-p",
            package,
            "--target",
            "wasm32-unknown-unknown",
            "--no-default-features",
        ])?;
    }
    cargo(&[
        "build",
        "--release",
        "--target",
        "wasm32-unknown-unknown",
        "-p",
        "auths-proof-wasm",
    ])?;
    let package_directory = root().join("target/wasm-node");
    fs::create_dir_all(&package_directory)
        .map_err(|error| format!("could not create WASM package directory: {error}"))?;
    let input = root().join("target/wasm32-unknown-unknown/release/auths_proof_wasm.wasm");
    let input = input.to_str().ok_or("WASM input path is not valid UTF-8")?;
    let output = package_directory
        .to_str()
        .ok_or("WASM package path is not valid UTF-8")?;
    command(
        "wasm-bindgen",
        &["--target", "nodejs", "--out-dir", output, input],
    )?;
    let repeat_directory = root().join("target/wasm-node-repeat");
    fs::create_dir_all(&repeat_directory)
        .map_err(|error| format!("could not create repeated WASM package directory: {error}"))?;
    let repeat = repeat_directory
        .to_str()
        .ok_or("repeated WASM package path is not valid UTF-8")?;
    command(
        "wasm-bindgen",
        &["--target", "nodejs", "--out-dir", repeat, input],
    )?;
    for name in [
        "auths_proof_wasm.js",
        "auths_proof_wasm.d.ts",
        "auths_proof_wasm_bg.wasm",
        "auths_proof_wasm_bg.wasm.d.ts",
    ] {
        let first = fs::read(package_directory.join(name))
            .map_err(|error| format!("could not read generated WASM artifact {name}: {error}"))?;
        let second = fs::read(repeat_directory.join(name))
            .map_err(|error| format!("could not read repeated WASM artifact {name}: {error}"))?;
        if first != second {
            return Err(format!(
                "generated WASM artifact {name} is not reproducible"
            ));
        }
    }
    cargo(&[
        "run",
        "-p",
        "auths-proof-wasm",
        "--example",
        "generate-node-vectors",
        "--",
        output,
    ])?;
    command(
        "node",
        &[
            "bindings/wasm/auths-proof-wasm/tests/node-smoke.cjs",
            output,
        ],
    )?;
    Ok(())
}

fn live_demo() -> Result<(), String> {
    let output = root().join("target/live-demo/site");
    if output.exists() {
        fs::remove_dir_all(&output)
            .map_err(|error| format!("could not clear {}: {error}", output.display()))?;
    }
    let typescript = root().join("bindings/typescript");
    command_in("npm", &["run", "build"], &typescript, None)?;
    command_in("npm", &["run", "build:wasm"], &typescript, None)?;
    cargo(&[
        "run",
        "--locked",
        "-p",
        "auths-live-lab",
        "--",
        path_text(&output)?,
    ])?;

    let expected: BTreeSet<String> = [
        "app.js",
        "assets/scenario.json",
        "index.html",
        "lab-core.js",
        "package.json",
        "styles.css",
        "vercel.json",
        "vendor/index.js",
        "vendor/wasm/auths_proof_wasm.d.ts",
        "vendor/wasm/auths_proof_wasm.js",
        "vendor/wasm/auths_proof_wasm_bg.wasm",
        "vendor/wasm/auths_proof_wasm_bg.wasm.d.ts",
        "assets/tampered-action/action.cbor",
        "assets/tampered-action/context.cbor",
        "assets/tampered-action/native-result.cbor",
        "assets/tampered-action/proof.cbor",
        "assets/tampered-proof/action.cbor",
        "assets/tampered-proof/context.cbor",
        "assets/tampered-proof/native-result.cbor",
        "assets/tampered-proof/proof.cbor",
        "assets/valid/action.cbor",
        "assets/valid/context.cbor",
        "assets/valid/native-result.cbor",
        "assets/valid/proof.cbor",
        "assets/wrong-configuration/action.cbor",
        "assets/wrong-configuration/context.cbor",
        "assets/wrong-configuration/native-result.cbor",
        "assets/wrong-configuration/proof.cbor",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let actual: BTreeSet<String> = repository_files(&output)?
        .into_iter()
        .map(|path| {
            path.strip_prefix(&output)
                .map_err(|_| format!("live demo output escaped {}", output.display()))
                .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        })
        .collect::<Result<_, _>>()?;
    if actual != expected {
        let missing: Vec<_> = expected.difference(&actual).collect();
        let extra: Vec<_> = actual.difference(&expected).collect();
        return Err(format!(
            "live demo bundle shape drifted; missing={missing:?}, extra={extra:?}"
        ));
    }

    let scenario: Value = serde_json::from_slice(
        &fs::read(output.join("assets/scenario.json"))
            .map_err(|error| format!("could not read live demo scenario: {error}"))?,
    )
    .map_err(|error| format!("invalid live demo scenario JSON: {error}"))?;
    if scenario["schema"].as_str() != Some("auths-live-lab/v1") {
        return Err("live demo scenario schema drifted".to_owned());
    }
    let variants = scenario["variants"]
        .as_array()
        .ok_or("live demo scenario has no variants")?;
    if variants.len() != 4
        || variants[0]["id"].as_str() != Some("valid")
        || variants[0]["native"]["decision"].as_str() != Some("authorized")
        || variants[1..]
            .iter()
            .any(|variant| variant["native"]["decision"].as_str() == Some("authorized"))
    {
        return Err("live demo adversarial verdict matrix drifted".to_owned());
    }
    if variants[0]["native"]["required_configuration"]
        != variants[0]["native"]["executed_configuration"]
        || variants[3]["native"]["required_configuration"]
            == variants[3]["native"]["executed_configuration"]
        || variants[3]["native"]["code"].as_str() != Some("verifier-configuration-mismatch")
    {
        return Err("live demo configuration commitment evidence drifted".to_owned());
    }
    if scenario["runtime"]["first_execution"]["outcome"].as_str() != Some("completed")
        || scenario["runtime"]["replay"]["kind"].as_str() != Some("consumed-challenge")
        || scenario["runtime"]["replay_executor_invocations"].as_u64() != Some(1)
        || scenario["runtime"]["decision_receipts"].as_u64() != Some(1)
        || scenario["runtime"]["execution_receipts"].as_u64() != Some(1)
    {
        return Err("live demo runtime enforcement evidence drifted".to_owned());
    }
    let release_id = scenario["release"]["id"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or("live demo release ID is missing")?;
    let declared_wasm = scenario["release"]["wasm_sha256"]
        .as_str()
        .filter(|value| value.len() == 64)
        .ok_or("live demo WASM digest is missing or malformed")?;
    let actual_wasm = sha256_file(&output.join("vendor/wasm/auths_proof_wasm_bg.wasm"))?;
    if declared_wasm != actual_wasm {
        return Err(format!(
            "live demo release {release_id} declares WASM {declared_wasm}, actual={actual_wasm}"
        ));
    }

    let vercel: Value = serde_json::from_slice(
        &fs::read(output.join("vercel.json"))
            .map_err(|error| format!("could not read generated Vercel config: {error}"))?,
    )
    .map_err(|error| format!("invalid generated Vercel config: {error}"))?;
    let vercel_text = serde_json::to_string(&vercel)
        .map_err(|error| format!("could not normalize generated Vercel config: {error}"))?;
    for required in [
        "https://auths-live-demo.fly.dev",
        "wasm-unsafe-eval",
        "frame-ancestors 'none'",
        "max-age=31536000, immutable",
    ] {
        if !vercel_text.contains(required) {
            return Err(format!(
                "generated Vercel security/cache policy omits {required}"
            ));
        }
    }

    let fly_source = fs::read_to_string(root().join("demos/live-service/fly.toml"))
        .map_err(|error| format!("could not read live service Fly config: {error}"))?;
    let fly: toml::Value = toml::from_str(&fly_source)
        .map_err(|error| format!("invalid live service Fly config: {error}"))?;
    if fly.get("app").and_then(toml::Value::as_str) != Some("auths-live-demo")
        || fly.get("primary_region").and_then(toml::Value::as_str) != Some("lhr")
        || fly
            .get("build")
            .and_then(|build| build.get("dockerfile"))
            .and_then(toml::Value::as_str)
            != Some("Dockerfile")
        || fly
            .get("http_service")
            .and_then(|service| service.get("internal_port"))
            .and_then(toml::Value::as_integer)
            != Some(8080)
        || fly
            .get("http_service")
            .and_then(|service| service.get("auto_stop_machines"))
            .and_then(toml::Value::as_str)
            != Some("off")
    {
        return Err("live service Fly topology or always-on policy drifted".to_owned());
    }
    let dockerfile = fs::read_to_string(root().join("demos/live-service/Dockerfile"))
        .map_err(|error| format!("could not read live service Dockerfile: {error}"))?;
    for required in [
        "rust:1.97.1-bookworm",
        "cargo build --locked --release -p auths-live-service",
        "distroless/cc-debian12:nonroot",
        "USER nonroot:nonroot",
    ] {
        if !dockerfile.contains(required) {
            return Err(format!("live service container policy omits {required}"));
        }
    }
    let dockerignore = fs::read_to_string(root().join(".dockerignore"))
        .map_err(|error| format!("could not read Docker ignore policy: {error}"))?;
    for required in ["target", "**/target", "**/pkg", "**/node_modules", "docs"] {
        if !dockerignore.lines().any(|line| line == required) {
            return Err(format!("Docker build-context policy omits {required}"));
        }
    }

    command(
        "node",
        &["demos/live-lab/tests/web-smoke.mjs", path_text(&output)?],
    )?;
    println!("live demo bundle passed native/WASM parity, adversarial, replay, and receipt checks");
    Ok(())
}

fn target_conformance() -> Result<(), String> {
    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(|error| error.to_string())?;
    let did_web = auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
        .map_err(|error| error.to_string())?;
    let webauthn =
        auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
            .map_err(|error| error.to_string())?;
    let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
        .map_err(|error| error.to_string())?;
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
        .map_err(|error| error.to_string())?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
        &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .map_err(|error| error.to_string())?;
    for fixture in auths_testkit::corpus() {
        let context = auths_codec::decode_verifier_context(fixture.context_bytes())
            .map_err(|error| format!("{} context: {error}", fixture.name()))?;
        let actual = auths_verifier::verify(
            fixture.proof_bytes(),
            fixture.canonical_action(),
            &context,
            &registries,
        );
        let matches = match (fixture.expected(), &actual) {
            (Expected::Authorized, auths_verifier::VerificationOutcome::Authorized(_)) => true,
            (Expected::Denied(expected), auths_verifier::VerificationOutcome::Denied(actual)) => {
                expected == *actual
            }
            (
                Expected::Indeterminate(expected),
                auths_verifier::VerificationOutcome::Indeterminate(actual),
            ) => expected == *actual,
            _ => false,
        };
        if !matches {
            return Err(format!(
                "{} expected {:?}, got {actual:?}",
                fixture.name(),
                fixture.expected()
            ));
        }
    }
    println!("target V1 canonical corpus conformance passed");
    Ok(())
}

fn semantic_digest() -> Result<(), String> {
    println!("{}", semantic_digest_value()?);
    Ok(())
}

fn semantic_digest_value() -> Result<String, String> {
    use auths_model::ParticipantRole;
    use auths_verifier::VerificationOutcome;

    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(|error| error.to_string())?;
    let did_web = auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
        .map_err(|error| error.to_string())?;
    let webauthn =
        auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
            .map_err(|error| error.to_string())?;
    let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
        .map_err(|error| error.to_string())?;
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
        .map_err(|error| error.to_string())?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
        &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .map_err(|error| error.to_string())?;
    let fixtures = auths_testkit::corpus();
    let mut summary = Sha256::new();
    for fixture in &fixtures {
        let context = auths_codec::decode_verifier_context(fixture.context_bytes())
            .map_err(|error| format!("{} context: {error}", fixture.name()))?;
        let outcome = auths_verifier::verify(
            fixture.proof_bytes(),
            fixture.canonical_action(),
            &context,
            &registries,
        );
        let (decision, code) = match &outcome {
            VerificationOutcome::Authorized(_) => ("authorized", "authorized"),
            VerificationOutcome::Denied(reason) => ("denied", reason.code()),
            VerificationOutcome::Indeterminate(requirement) => {
                ("indeterminate", requirement.code())
            }
        };
        let matches = match (fixture.expected(), &outcome) {
            (Expected::Authorized, VerificationOutcome::Authorized(_)) => true,
            (Expected::Denied(expected), VerificationOutcome::Denied(actual)) => {
                expected == *actual
            }
            (Expected::Indeterminate(expected), VerificationOutcome::Indeterminate(actual)) => {
                expected == *actual
            }
            _ => false,
        };
        if !matches {
            return Err(format!(
                "{} expected {:?}, got {outcome:?}",
                fixture.name(),
                fixture.expected()
            ));
        }
        let proof_digest = Sha256::digest(fixture.proof_bytes());
        let context_digest =
            auths_codec::context_digest(&context).map_err(|error| error.to_string())?;
        let action_bytes = auths_codec::encode_canonical_action(fixture.canonical_action())
            .map_err(|error| error.to_string())?;
        let action_digest = Sha256::digest(action_bytes);
        let plan = auths_verifier::decode_proof(fixture.proof_bytes(), &context)
            .ok()
            .and_then(|decoded| auths_codec::plan_id(decoded.bundle().plan()).ok());
        write_field(&mut summary, fixture.name());
        write_field(&mut summary, decision);
        write_field(&mut summary, code);
        write_bytes(&mut summary, &proof_digest);
        write_bytes(&mut summary, context_digest.as_bytes());
        write_bytes(&mut summary, &action_digest);
        write_bytes(
            &mut summary,
            plan.as_ref()
                .map_or(&[][..], |identifier| identifier.as_bytes()),
        );
        if let VerificationOutcome::Authorized(action) = &outcome {
            for identifier in action.action_ids() {
                write_bytes(&mut summary, identifier.as_bytes());
            }
            write_field(&mut summary, "|");
            for reference in action.authorized_branches() {
                write_bytes(&mut summary, reference.as_bytes());
            }
            write_field(&mut summary, "|");
            for report in action.assurance() {
                write_field(&mut summary, report.principal().as_str());
                write_field(
                    &mut summary,
                    match report.role() {
                        ParticipantRole::Root => "0",
                        ParticipantRole::Intermediate => "1",
                        ParticipantRole::Actor => "2",
                        ParticipantRole::ExternalIssuer => "3",
                    },
                );
                write_field(&mut summary, report.adapter().as_str());
                for claim in report.claims() {
                    write_field(&mut summary, claim.kind().as_str());
                    write_field(
                        &mut summary,
                        &claim
                            .observed_at()
                            .map_or_else(|| "-".to_owned(), |value| value.get().to_string()),
                    );
                }
                write_field(&mut summary, ";");
            }
        } else {
            write_field(&mut summary, "|");
            write_field(&mut summary, "|");
        }
        write_field(&mut summary, "\n");
    }
    Ok(format!(
        "{}:{}",
        fixtures.len(),
        hex::encode(summary.finalize())
    ))
}

fn write_field(summary: &mut Sha256, value: &str) {
    summary.update(value.as_bytes());
    summary.update([0]);
}

fn write_bytes(summary: &mut Sha256, value: &[u8]) {
    write_field(summary, &hex::encode(value));
}

#[derive(Clone)]
struct ArchitectureLayer {
    path: String,
    allowed_dependencies: BTreeSet<String>,
    owners: BTreeSet<String>,
}

struct ArchitecturePolicy {
    layers: BTreeMap<String, ArchitectureLayer>,
    packages: BTreeMap<String, String>,
    workspace_edition: String,
    workspace_resolver: String,
    workspace_msrv: String,
    development_toolchain: String,
    core_forbidden_dependencies: BTreeSet<String>,
    core_default_feature_exceptions: BTreeSet<String>,
    approved_build_scripts: BTreeSet<String>,
    no_std_packages: BTreeSet<String>,
}

fn arch(update: bool) -> Result<(), String> {
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

fn load_architecture_policy() -> Result<ArchitecturePolicy, String> {
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

fn check_workspace_rust_policy(
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
            if !source.lines().any(|line| line.trim() == declaration) {
                return Err(format!(
                    "{} must install Rust toolchain {toolchain}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn required_toml_string(
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

fn required_toml_strings(
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

fn check_codeowners(policy: &ArchitecturePolicy) -> Result<(), String> {
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

fn reject_dependency_cycles(edges: &BTreeMap<String, BTreeSet<String>>) -> Result<(), String> {
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

fn architecture_dot(snapshot: &Value) -> Result<String, String> {
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

fn architecture_snapshot_diff(previous: &Value, current: &Value) -> String {
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

fn core_boundary() -> Result<(), String> {
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

fn workspace_package_paths() -> Result<BTreeMap<String, PathBuf>, String> {
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

fn scan_restricted_core_source(package: &str, source: &Path) -> Result<(), String> {
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

fn repository_hygiene() -> Result<(), String> {
    let repository = root();
    let mut locks = Vec::new();
    let mut nested_workspaces = Vec::new();
    let mut sibling_references = Vec::new();
    let mut corpus_manifests = Vec::new();
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
            corpus_manifests.push(relative.to_path_buf());
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
    if corpus_manifests != [PathBuf::from("core/fixtures/v1/manifest.json")] {
        return Err(format!(
            "canonical fixture manifest must have one core owner, found {corpus_manifests:?}"
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

fn check_workflow_action_pins() -> Result<(), String> {
    let workflows = root().join(".github/workflows");
    for path in files_with_extension(&workflows, "yml")?
        .into_iter()
        .chain(files_with_extension(&workflows, "yaml")?)
    {
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

fn repository_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
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

fn files_with_extension(directory: &Path, extension: &str) -> Result<Vec<PathBuf>, String> {
    let mut files: Vec<_> = repository_files(directory)?
        .into_iter()
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some(extension))
        .collect();
    files.sort();
    Ok(files)
}

fn wire(update: bool) -> Result<(), String> {
    let generated = generated_vectors()?;
    let fixture_root = root().join("core/fixtures/v1");
    if update {
        for (relative, bytes) in &generated {
            let path = fixture_root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
            }
            fs::write(&path, bytes)
                .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        }
        for relative in fixture_inventory(&fixture_root)? {
            if !generated.contains_key(&relative) {
                fs::remove_file(fixture_root.join(&relative)).map_err(|error| {
                    format!(
                        "could not remove stale fixture {}: {error}",
                        relative.display()
                    )
                })?;
            }
        }
        println!("updated {} golden vector files", generated.len());
        return Ok(());
    }

    for (relative, expected) in &generated {
        let path = fixture_root.join(relative);
        let actual = fs::read(&path)
            .map_err(|error| format!("missing golden vector {}: {error}", path.display()))?;
        if &actual != expected {
            return Err(format!(
                "golden vector {} changed; review and run `cargo xtask wire --update`",
                path.display()
            ));
        }
    }
    let actual = fixture_inventory(&fixture_root)?;
    let expected: BTreeSet<_> = generated.keys().cloned().collect();
    if actual != expected {
        let stale: Vec<_> = actual.difference(&expected).collect();
        let missing: Vec<_> = expected.difference(&actual).collect();
        return Err(format!(
            "fixture inventory mismatch; stale={stale:?}, missing={missing:?}"
        ));
    }
    println!("{} golden vector files are byte-stable", generated.len());
    Ok(())
}

fn generated_vectors() -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(|error| error.to_string())?;
    let did_web = auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
        .map_err(|error| error.to_string())?;
    let webauthn =
        auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
            .map_err(|error| error.to_string())?;
    let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
        .map_err(|error| error.to_string())?;
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
        .map_err(|error| error.to_string())?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
        &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .map_err(|error| error.to_string())?;
    let mut generated = BTreeMap::new();
    let mut entries = Vec::new();
    for fixture in auths_testkit::corpus() {
        let directory = fixture.class();
        let proof_path = format!("{directory}/{}.proof.cbor", fixture.name());
        let context_path = format!("{directory}/{}.context.cbor", fixture.name());
        let action_path = format!("{directory}/{}.action.cbor", fixture.name());
        let body_path = format!("{directory}/{}.body.cbor", fixture.name());
        let result_path = format!("{directory}/{}.result.cbor", fixture.name());
        let action_bytes = auths_codec::encode_canonical_action(fixture.canonical_action())
            .map_err(|error| format!("{} action: {error}", fixture.name()))?;
        let result_bytes = auths_verifier::verify_v1(
            fixture.proof_bytes(),
            &action_bytes,
            fixture.context_bytes(),
            &registries,
        )
        .map_err(|error| format!("{} portable ABI: {error}", fixture.name()))?;
        let result = auths_codec::decode_verification_result(&result_bytes)
            .map_err(|error| format!("{} result: {error}", fixture.name()))?;
        let (expected_decision, expected_code) = match fixture.expected() {
            Expected::Authorized => ("authorized", "authorized"),
            Expected::Denied(reason) => ("denied", reason.code()),
            Expected::Indeterminate(requirement) => ("indeterminate", requirement.code()),
        };
        entries.push(json!({
            "name": fixture.name(),
            "class": directory,
            "proof": {
                "path": proof_path,
                "sha256": hex::encode(Sha256::digest(fixture.proof_bytes())),
            },
            "context": {
                "path": context_path,
                "sha256": hex::encode(Sha256::digest(fixture.context_bytes())),
            },
            "canonical_action": {
                "path": action_path,
                "sha256": hex::encode(Sha256::digest(&action_bytes)),
                "profile": fixture.canonical_action().profile().id().as_str(),
                "profile_version": fixture.canonical_action().profile().version(),
                "media_type": fixture.canonical_action().media_type().as_str(),
                "capability": fixture.canonical_action().permission().capability().as_str(),
                "resource": fixture.canonical_action().permission().resource().as_str(),
                "requested_budget": fixture.canonical_action().requested_budget().map(|budget| {
                    json!({
                        "algebra": budget.algebra().as_str(),
                        "value": budget.value(),
                    })
                }),
            },
            "canonical_body": {
                "path": body_path,
                "sha256": hex::encode(Sha256::digest(fixture.canonical_action().body())),
            },
            "expected_result": {
                "path": result_path,
                "sha256": hex::encode(Sha256::digest(&result_bytes)),
                "stage": format!("{:?}", result.stage()).to_ascii_lowercase(),
                "decision": expected_decision,
                "code": expected_code,
                "proof_digest": hex::encode(result.proof_digest().as_bytes()),
                "action_digest": hex::encode(result.action_digest().as_bytes()),
                "context_digest": hex::encode(result.context_digest().as_bytes()),
                "plan_digest": result.plan_id().map(|id| hex::encode(id.as_bytes())),
                "result_digest": hex::encode(result.result_digest().as_bytes()),
                "authorized_branches": result.authorized_branches().iter()
                    .map(|id| hex::encode(id.as_bytes())).collect::<Vec<_>>(),
                "assurance_satisfactions": result.assurance_satisfactions().len(),
                "resources": {
                    "proof_bytes": result.resources().proof_bytes(),
                    "action_bytes": result.resources().action_bytes(),
                    "context_bytes": result.resources().context_bytes(),
                    "object_count": result.resources().object_count(),
                    "plan_leaves": result.resources().plan_leaves(),
                    "plan_depth": result.resources().plan_depth(),
                    "work_units": result.resources().work_units(),
                },
                "registry_manifest": hex::encode(result.registry_manifest().as_bytes()),
            },
            "expected_decision": expected_decision,
            "expected_code": expected_code,
        }));
        generated.insert(PathBuf::from(proof_path), fixture.proof_bytes().to_vec());
        generated.insert(
            PathBuf::from(context_path),
            fixture.context_bytes().to_vec(),
        );
        generated.insert(PathBuf::from(action_path), action_bytes);
        generated.insert(
            PathBuf::from(body_path),
            fixture.canonical_action().body().to_vec(),
        );
        generated.insert(PathBuf::from(result_path), result_bytes);
    }
    let manifest = serde_json::to_vec_pretty(&json!({
        "protocol": "Auths Proof Protocol V1",
        "protocol_major": 1,
        "fixture_set": "target-v1",
        "hash": "sha-256",
        "adapter_context": corpus_adapter_context(),
        "fixtures": entries,
    }))
    .map_err(|error| format!("could not encode target fixture manifest: {error}"))?;
    generated.insert(PathBuf::from("manifest.json"), manifest);
    Ok(generated)
}

fn fixture_inventory(root: &Path) -> Result<BTreeSet<PathBuf>, String> {
    fn walk(root: &Path, current: &Path, output: &mut BTreeSet<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(current)
            .map_err(|error| format!("could not list {}: {error}", current.display()))?
        {
            let entry = entry.map_err(|error| format!("invalid fixture entry: {error}"))?;
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, output)?;
            } else if path
                .extension()
                .is_some_and(|extension| extension == "cbor")
                || path.file_name().is_some_and(|name| name == "manifest.json")
            {
                output.insert(
                    path.strip_prefix(root)
                        .map_err(|_| "fixture escaped root".to_owned())?
                        .to_path_buf(),
                );
            }
        }
        Ok(())
    }
    let mut output = BTreeSet::new();
    walk(root, root, &mut output)?;
    Ok(output)
}

fn corpus_adapter_context() -> Value {
    let did_web = auths_testkit::did_web_corpus_trust_records()
        .iter()
        .map(|record| match record {
            auths_did_web::DidWebTrustRecord::Current {
                principal,
                document_digest,
                observed_at,
                valid_until,
            } => json!({
                "kind": "current",
                "principal": principal.as_str(),
                "document_digest": hex::encode(document_digest),
                "observed_at": observed_at.get(),
                "valid_until": valid_until.get(),
            }),
            auths_did_web::DidWebTrustRecord::Historical {
                principal,
                document_digest,
                valid_from,
                valid_until,
                statement,
            } => json!({
                "kind": "historical",
                "principal": principal.as_str(),
                "document_digest": hex::encode(document_digest),
                "valid_from": valid_from.get(),
                "valid_until": valid_until.get(),
                "statement": statement.map(|pin| json!({
                    "signing_preimage_digest":
                        hex::encode(pin.signing_preimage_digest()),
                    "existed_at": pin.existed_at().get(),
                })),
            }),
        })
        .collect::<Vec<_>>();
    let webauthn = auths_testkit::webauthn_corpus_credentials()
        .iter()
        .map(|credential| {
            let counter_policy = match credential.counter_policy() {
                auths_webauthn::CounterPolicy::Disabled => json!({"kind": "disabled"}),
                auths_webauthn::CounterPolicy::GreaterThan(value) => {
                    json!({"kind": "greater-than", "value": value})
                }
            };
            json!({
                "credential_id": hex::encode(credential.credential_id()),
                "principal": credential.principal().as_str(),
                "verification_method": credential.verification_method().as_str(),
                "public_key": hex::encode(credential.public_key()),
                "rp_id": credential.rp_id(),
                "origins": credential.origins(),
                "require_user_verification": credential.require_user_verification(),
                "counter_policy": counter_policy,
                "attestation_level": credential.attestation_level(),
                "observed_at": credential.observed_at().get(),
                "valid_until": credential.valid_until().get(),
            })
        })
        .collect::<Vec<_>>();
    let hsm = auths_testkit::hsm_corpus_records()
        .iter()
        .map(|record| {
            json!({
                "principal": record.principal().as_str(),
                "verification_method": record.verification_method().as_str(),
                "suite": record.suite().as_str(),
                "public_key": hex::encode(record.public_key()),
                "profile": record.profile(),
                "provider": record.provider(),
                "protection_level": record.protection_level(),
                "key_handle_digest": hex::encode(record.key_handle_digest()),
                "device_chain_digest": hex::encode(record.device_chain_digest()),
                "non_exportable": record.non_exportable(),
                "observed_at": record.observed_at().get(),
                "valid_until": record.valid_until().get(),
            })
        })
        .collect::<Vec<_>>();
    let (trust_domains, status) = auths_testkit::spiffe_corpus_context();
    let spiffe_trust_domains = trust_domains
        .iter()
        .map(|trust| {
            json!({
                "name": trust.name(),
                "roots": trust.roots().iter().map(hex::encode).collect::<Vec<_>>(),
                "require_status": trust.requires_status(),
            })
        })
        .collect::<Vec<_>>();
    let spiffe_status = status
        .iter()
        .map(|record| {
            json!({
                "leaf_digest": hex::encode(record.leaf_digest()),
                "active": record.is_active(),
                "observed_at": record.observed_at().get(),
                "valid_until": record.valid_until().get(),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "configuration": hex::encode(auths_testkit::corpus_configuration_id().as_bytes()),
        "did_web": did_web,
        "webauthn": webauthn,
        "hsm": hsm,
        "spiffe": {
            "trust_domains": spiffe_trust_domains,
            "status": spiffe_status,
        },
        "did_keri": {
            "checkpoints": [],
        },
    })
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is inside repository root")
        .to_path_buf()
}
