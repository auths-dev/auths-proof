#![allow(clippy::too_many_lines)]

use crate::*;

pub(crate) fn wasm() -> Result<(), String> {
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

pub(crate) fn live_demo() -> Result<(), String> {
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

    let mut expected: BTreeSet<String> = [
        "app.js",
        "assets/scenario.json",
        "index.html",
        "lab-core.js",
        "package.json",
        "styles.css",
        "vercel.json",
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
    let dist = typescript.join("dist");
    for path in repository_files(&dist)? {
        if path.extension().and_then(|extension| extension.to_str()) != Some("js") {
            continue;
        }
        let relative = path
            .strip_prefix(&dist)
            .map_err(|_| format!("TypeScript build output escaped {}", dist.display()))?;
        expected.insert(format!(
            "vendor/{}",
            relative.to_string_lossy().replace('\\', "/")
        ));
    }
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
