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
    crate::binding_semantics::binding_semantics()?;
    semantic_freeze(false)?;
    sdk_experience(false)?;
    sdk_vocabulary()?;
    product_waist_conformance(false)?;
    public_naming()?;
    release_contract()?;
    repository_hygiene()?;
    cargo(&["check", "--workspace", "--all-targets", "--all-features"])?;
    cargo(&["test", "--workspace", "--all-features"])?;
    release_preflight()?;
    cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--",
        "-D",
        "warnings",
    ])?;
    release_documentation()?;
    core_boundary()?;
    workspace_msrv()?;
    platform_artifact(&root().join("target/release-evidence/platform.json"))?;
    fuzz_smoke()
}

/// Runs the deterministic compilation-profile and canonical-byte gates that
/// release preparation depends on in addition to the all-features workspace
/// suite.
///
/// Keep this in authoritative pull-request CI. A release candidate must not be
/// the first place that no-default-features compilation or wire drift is
/// discovered.
pub(crate) fn release_preflight() -> Result<(), String> {
    sdk_experience(false)?;
    cargo(&["test", "--workspace", "--no-default-features"])?;
    wire(false)
}

pub(crate) fn release_documentation() -> Result<(), String> {
    let status = Command::new("cargo")
        .args(["doc", "--workspace", "--all-features", "--no-deps"])
        .env("RUSTDOCFLAGS", "-D warnings")
        .current_dir(root())
        .status()
        .map_err(|error| format!("could not build release documentation: {error}"))?;
    if status.success() {
        println!("release documentation passed");
        Ok(())
    } else {
        Err(format!("documentation build failed with {status}"))
    }
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
    // Fails before the long conformance run: a binding that holds protocol
    // meaning is an architecture defect, not a test failure.
    crate::binding_semantics::binding_semantics()?;
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
        "import * as auths from '@auths-dev/sdk';\n\
         import * as verify from '@auths-dev/sdk/verify';\n\
         import * as diagnostics from '@auths-dev/sdk/diagnostics';\n\
         if (typeof auths.loadAuths !== 'function') throw new Error('loadAuths export missing');\n\
         if (typeof verify.Verifier !== 'function') throw new Error('Verifier export missing');\n\
         if (typeof verify.loadVerifier !== 'function') throw new Error('loadVerifier export missing');\n\
         if (typeof diagnostics.createDiagnosticVerifier !== 'function') throw new Error('createDiagnosticVerifier export missing');\n\
         if ('Verifier' in auths) throw new Error('raw verifier leaked onto the root entry point');\n\
         if ('loadVerifier' in auths) throw new Error('raw loader leaked onto the root entry point');\n\
         if ('createDiagnosticVerifier' in auths) throw new Error('diagnostic verifier leaked onto the root entry point');\n",
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
    let reproduction_directory = root().join("target/python-wheels-reproduction");
    let virtual_environment = root().join("target/python-smoke-venv");
    for directory in [&wheel_directory, &reproduction_directory] {
        if directory.exists() {
            fs::remove_dir_all(directory)
                .map_err(|error| format!("could not clear Python wheel directory: {error}"))?;
        }
        fs::create_dir_all(directory)
            .map_err(|error| format!("could not create Python wheel directory: {error}"))?;
    }
    if virtual_environment.exists() {
        fs::remove_dir_all(&virtual_environment)
            .map_err(|error| format!("could not clear Python smoke environment: {error}"))?;
    }
    let source_date_epoch = release_source_date_epoch()?;
    build_python_wheel(&wheel_directory, &source_date_epoch)?;
    build_python_wheel(&reproduction_directory, &source_date_epoch)?;
    let wheel = single_python_wheel(&wheel_directory)?;
    let reproduction = single_python_wheel(&reproduction_directory)?;
    let wheel_digest = sha256_file(&wheel)?;
    let reproduction_digest = sha256_file(&reproduction)?;
    if wheel_digest != reproduction_digest {
        return Err(format!(
            "Python wheel is not reproducible for SOURCE_DATE_EPOCH={source_date_epoch}: {wheel_digest} != {reproduction_digest}"
        ));
    }
    println!(
        "Python wheel reproducibility passed for SOURCE_DATE_EPOCH={source_date_epoch}: {wheel_digest}"
    );
    command("python3", &["-m", "venv", path_text(&virtual_environment)?])?;
    let python = if cfg!(windows) {
        virtual_environment.join("Scripts/python.exe")
    } else {
        virtual_environment.join("bin/python")
    };
    command(
        path_text(&python)?,
        &[
            "-m",
            "pip",
            "install",
            "pytest==9.0.2",
            "pytest-asyncio==1.3.0",
        ],
    )?;
    command(
        path_text(&python)?,
        &["-m", "pip", "install", path_text(&wheel)?],
    )?;
    command(
        path_text(&python)?,
        &["bindings/python/tools/check_wheel.py", path_text(&wheel)?],
    )?;
    command(
        path_text(&python)?,
        &["bindings/python/tools/check_public_api.py"],
    )?;
    command(
        path_text(&python)?,
        &[
            "bindings/python/external/full_workflow_consumer.py",
            "target/binding-vectors",
        ],
    )?;
    command_in(
        path_text(&python)?,
        &["-m", "pytest", "tests"],
        &root().join("bindings/python"),
        None,
    )
}

fn build_python_wheel(output: &Path, source_date_epoch: &str) -> Result<(), String> {
    let status = Command::new("maturin")
        .args([
            "build",
            "--out",
            path_text(output)?,
            "--manifest-path",
            "bindings/python/Cargo.toml",
        ])
        .env("SOURCE_DATE_EPOCH", source_date_epoch)
        .current_dir(root())
        .status()
        .map_err(|error| format!("could not run maturin: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("maturin build failed with {status}"))
    }
}

fn single_python_wheel(directory: &Path) -> Result<PathBuf, String> {
    let wheels: Vec<_> = fs::read_dir(directory)
        .map_err(|error| format!("could not list Python wheels: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("whl"))
        .collect();
    if wheels.len() != 1 {
        return Err(format!(
            "expected one Python wheel, found {} in {}",
            wheels.len(),
            directory.display()
        ));
    }
    Ok(wheels[0].clone())
}

fn release_source_date_epoch() -> Result<String, String> {
    let output = Command::new("git")
        .args(["show", "-s", "--format=%ct", "HEAD"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not identify release source timestamp: {error}"))?;
    if !output.status.success() {
        return Err("could not identify release source timestamp".to_owned());
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|error| format!("release source timestamp is not UTF-8: {error}"))?;
    validate_source_date_epoch(value.trim())
}

fn validate_source_date_epoch(value: &str) -> Result<String, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("invalid release SOURCE_DATE_EPOCH: {value}"));
    }
    let epoch = value
        .parse::<u64>()
        .map_err(|error| format!("invalid release SOURCE_DATE_EPOCH {value}: {error}"))?;
    // ZIP timestamps cannot represent dates before 1980-01-01. Every repository
    // commit is newer, but reject an invalid clock instead of relying on a
    // packager-specific clamp.
    if epoch < 315_532_800 {
        return Err(format!(
            "release SOURCE_DATE_EPOCH predates the ZIP timestamp domain: {value}"
        ));
    }
    Ok(value.to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_date_epoch_accepts_zip_representable_commit_time() {
        assert_eq!(
            validate_source_date_epoch("1785776427").expect("valid commit timestamp"),
            "1785776427"
        );
    }

    #[test]
    fn source_date_epoch_rejects_non_numeric_input() {
        let error = validate_source_date_epoch("not-a-timestamp")
            .expect_err("non-numeric timestamp must fail closed");
        assert!(error.contains("invalid release SOURCE_DATE_EPOCH"));
    }

    #[test]
    fn source_date_epoch_rejects_pre_zip_timestamp() {
        let error = validate_source_date_epoch("315532799")
            .expect_err("pre-ZIP timestamp must fail closed");
        assert!(error.contains("predates the ZIP timestamp domain"));
    }
}
