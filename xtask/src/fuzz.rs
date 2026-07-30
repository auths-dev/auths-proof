#![allow(clippy::too_many_lines)]

use crate::*;

pub(crate) const FUZZ_TARGETS: [&str; 7] = [
    "target_codec",
    "target_portable_codecs",
    "target_model_state",
    "target_composition",
    "target_registry_handlers",
    "target_principal_parsers",
    "target_portable_abi",
];
pub(crate) const PRODUCT_FUZZ_TARGETS: [&str; 1] = ["target_bounded_policy"];

pub(crate) fn fuzz_smoke() -> Result<(), String> {
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
    for target in PRODUCT_FUZZ_TARGETS {
        let corpus = format!("product/policy/auths-bounded-policy/fuzz/corpus/{target}");
        cargo(&[
            "run",
            "--manifest-path",
            "product/policy/auths-bounded-policy/fuzz/Cargo.toml",
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

pub(crate) fn fuzz_inventory() -> Result<(), String> {
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

    let product_manifest =
        fs::read_to_string(root().join("product/policy/auths-bounded-policy/fuzz/Cargo.toml"))
            .map_err(|error| format!("could not read bounded-policy fuzz manifest: {error}"))?;
    let product_manifest_targets: BTreeSet<_> = product_manifest
        .lines()
        .filter_map(|line| line.trim().strip_prefix("name = \""))
        .filter_map(|value| value.strip_suffix('"'))
        .filter(|name| name.starts_with("target_"))
        .collect();
    let expected_product: BTreeSet<_> = PRODUCT_FUZZ_TARGETS.into_iter().collect();
    if product_manifest_targets != expected_product {
        return Err(format!(
            "bounded-policy fuzz manifest and inventory differ: manifest={product_manifest_targets:?}, expected={expected_product:?}"
        ));
    }

    let workflow = fs::read_to_string(root().join(".github/workflows/fuzz.yml"))
        .map_err(|error| format!("could not read fuzz workflow: {error}"))?;
    for target in FUZZ_TARGETS {
        if !workflow
            .lines()
            .any(|line| line.trim().contains(&format!("\"{target}:")))
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
    for target in PRODUCT_FUZZ_TARGETS {
        if !workflow
            .lines()
            .any(|line| matches!(line.trim(), value if value.contains(target)))
        {
            return Err(format!(
                "scheduled fuzz workflow is missing bounded-policy target {target}"
            ));
        }
        let corpus = root()
            .join("product/policy/auths-bounded-policy/fuzz/corpus")
            .join(target);
        if !corpus.is_dir() {
            return Err(format!(
                "missing bounded-policy structured seed directory {}",
                corpus.display()
            ));
        }
    }
    println!(
        "all {} fuzz targets are synchronized",
        FUZZ_TARGETS.len() + PRODUCT_FUZZ_TARGETS.len()
    );
    Ok(())
}
