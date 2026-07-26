#![forbid(unsafe_code)]

use auths_testkit::Expected;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
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
        "matrix" => matrix(),
        "cross-language" => cross_language_corpus(),
        "product-fixtures" => product_fixtures(args.any(|arg| arg == "--update")),
        "semantic-digest" => semantic_digest(),
        "wasm" => wasm(),
        "fuzz-inventory" => fuzz_inventory(),
        "fuzz-smoke" => fuzz_smoke(),
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
                 conformance|exchange-conformance|product-conformance|matrix|cross-language|\
                 product-fixtures [--update]|semantic-digest|wasm|fuzz-inventory|fuzz-smoke|\
                 platform-artifact [output]|ci|release-check>"
            );
            Ok(())
        }
    }
}

fn ci() -> Result<(), String> {
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
    abi()?;
    exchange_conformance()?;
    product_conformance()?;
    product_fixtures(false)?;
    matrix()?;
    bindings_check()?;
    package_check()?;
    platform_artifact(&root().join("target/release-evidence/platform.json"))?;
    fuzz_smoke()?;
    wasm()
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
    matrix()
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
                    Some(".git" | ".pytest_cache" | "__pycache__" | "node_modules" | "target")
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
