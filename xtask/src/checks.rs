#![allow(clippy::too_many_lines)]

use crate::*;

pub(crate) fn ci() -> Result<(), String> {
    ci_authoritative()?;
    formal(false, false)?;
    ci_compliance()
}

pub(crate) fn ci_authoritative() -> Result<(), String> {
    format_all()?;
    arch(false)?;
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
    core_boundary()?;
    workspace_msrv()?;
    platform_artifact(&root().join("target/release-evidence/platform.json"))?;
    fuzz_smoke()
}

pub(crate) fn ci_compliance() -> Result<(), String> {
    let compliance_inventory = compliance_inventory()?;
    abi()?;
    exchange_conformance()?;
    product_conformance()?;
    product_fixtures(false)?;
    stripe_profiles()?;
    bounded_domains()?;
    matrix()?;
    bindings_conformance()?;
    package_check()?;
    wasm()?;
    live_demo()?;
    write_compliance_report(&compliance_inventory)
}

pub(crate) fn format_all() -> Result<(), String> {
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

pub(crate) fn layer_check(layer: &str) -> Result<(), String> {
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

pub(crate) fn exchange_check() -> Result<(), String> {
    layer_check("exchange")?;
    exchange_conformance()
}

pub(crate) fn product_check() -> Result<(), String> {
    layer_check("product")?;
    product_conformance()
}

pub(crate) fn demos_check() -> Result<(), String> {
    layer_check("demos")?;
    matrix()?;
    live_demo()
}

pub(crate) fn bindings_check() -> Result<(), String> {
    layer_check("bindings")?;
    bindings_conformance()
}

pub(crate) fn bindings_conformance() -> Result<(), String> {
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

pub(crate) fn npm_package_smoke() -> Result<(), String> {
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

pub(crate) fn workspace_msrv() -> Result<(), String> {
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

pub(crate) fn python_wheel_smoke() -> Result<(), String> {
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

pub(crate) fn abi() -> Result<(), String> {
    spec_sync()?;
    wire(false)?;
    target_conformance()?;
    cross_language_corpus()
}

pub(crate) fn exchange_conformance() -> Result<(), String> {
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

pub(crate) fn product_conformance() -> Result<(), String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async {
        auths_apps_testkit::assert_target_conformance().await;
        auths_apps_testkit::assert_iroh_target_conformance().await;
    });
    println!("product MCP and Iroh conformance passed");
    Ok(())
}
