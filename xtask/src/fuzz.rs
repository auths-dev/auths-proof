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

    let workflow = fs::read_to_string(root().join(".github/workflows/fuzz.yml"))
        .map_err(|error| format!("could not read fuzz workflow: {error}"))?;
    for target in FUZZ_TARGETS {
        if !workflow
            .lines()
            .any(|line| matches!(line.trim(), value if value == target || value == format!("- {target}")))
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
