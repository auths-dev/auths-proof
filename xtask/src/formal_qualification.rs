#![allow(clippy::too_many_lines)]

use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const QUALIFICATION_PATH: &str = "formal/qualification/aeneas/qualification.toml";
const QUALIFICATION_SCHEMA: &str = "auths-proof-aeneas-qualification/v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Qualification {
    schema: String,
    decision: String,
    adr: String,
    source_closure: String,
    production_features: Vec<String>,
    semantic_cfg: Vec<String>,
    extraction_cfg: Vec<String>,
    shipping_target: String,
    extraction_target: String,
    translation_warnings: Vec<String>,
    required_compiled_external_axioms: usize,
    source_files: Vec<String>,
    generated_files: Vec<String>,
    case_modules: Vec<String>,
    tools: QualificationTools,
    external_models: Vec<ExternalModel>,
    warning_inventory: Vec<WarningInventory>,
    translations: Vec<TranslationExpectation>,
    template_axioms: Vec<TemplateAxiomInventory>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationTools {
    shipping_rust: String,
    extraction_rust: String,
    charon: String,
    charon_commit: String,
    aeneas_commit: String,
    lean_toolchain: String,
    kani: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalModel {
    id: String,
    kind: String,
    artifact: String,
    rust_symbols: Vec<String>,
    authority_semantics: bool,
    reviewed: bool,
    axiom: bool,
    scope: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WarningInventory {
    id: String,
    artifact: String,
    upstream_lines: Vec<usize>,
    classification: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TranslationExpectation {
    crate_name: String,
    translation_json: String,
    local_functions: usize,
    external_functions: usize,
    opaque_local_functions: usize,
    required_symbols: Vec<String>,
    allowed_external_symbols: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateAxiomInventory {
    artifact: String,
    count: usize,
    compiled: bool,
}

#[derive(Deserialize)]
struct TranslationReport {
    aeneas_version: String,
    charon_version: String,
    #[serde(rename = "crate")]
    crate_name: String,
    functions: Vec<TranslationFunction>,
}

#[derive(Deserialize)]
struct TranslationFunction {
    rust_name: String,
    is_local: bool,
    is_opaque: bool,
}

pub(crate) fn validate(root: &Path, attenuation_dimensions: &[String]) -> Result<String, String> {
    let qualification = load_qualification(root)?;
    validate_manifest(root, &qualification)?;
    let closure_digest = synchronize_source_closure(root, &qualification, false)?;
    synchronize_reviewed_bridges(root, attenuation_dimensions, false)?;
    validate_generated_inventory(root, &qualification)?;
    validate_translation_reports(root, &qualification)?;
    validate_workflow_gates(root)?;
    build_qualification_cases(root, &qualification)?;
    validate_warning_inventory(root, &qualification)?;
    write_evidence(root, &qualification, &closure_digest, false)?;
    println!(
        "Aeneas qualification:       PASS ({} reviewed external links; 0 compiled external axioms)",
        qualification.external_models.len()
    );
    Ok(closure_digest)
}

pub(crate) fn validate_source_closure(root: &Path) -> Result<String, String> {
    let qualification = load_qualification(root)?;
    validate_manifest(root, &qualification)?;
    synchronize_source_closure(root, &qualification, false)
}

pub(crate) fn qualify(
    root: &Path,
    attenuation_dimensions: &[String],
    update: bool,
) -> Result<(), String> {
    let qualification = load_qualification(root)?;
    validate_manifest(root, &qualification)?;
    if !update {
        synchronize_source_closure(root, &qualification, false)?;
    }
    ensure_clean_extraction_environment(&qualification)?;
    let charon = required_tool("AUTHS_CHARON_BIN", "charon")?;
    let aeneas = required_tool("AUTHS_AENEAS_BIN", "aeneas")?;
    validate_translation_tool_versions(&charon, &aeneas, &qualification)?;

    let work = root.join("target/formal/qualification-reproduction");
    recreate_directory(&work)?;
    let first = work.join("run-1");
    let second = work.join("run-2");
    let stable_llbc = work.join("stable-llbc");
    reproduce(root, &charon, &aeneas, &stable_llbc, &first)?;
    reproduce(root, &charon, &aeneas, &stable_llbc, &second)?;

    let first_files = collect_files(&first)?;
    let second_files = collect_files(&second)?;
    if first_files != second_files {
        return Err(format!(
            "Aeneas clean reproduction is not byte-identical; compare {} and {}",
            first.display(),
            second.display()
        ));
    }

    synchronize_aeneas_output(root, &first, update)?;
    synchronize_reviewed_bridges(root, attenuation_dimensions, update)?;
    let closure_digest = synchronize_source_closure(root, &qualification, update)?;

    validate_generated_inventory(root, &qualification)?;
    validate_translation_reports(root, &qualification)?;
    validate_workflow_gates(root)?;
    build_qualification_cases(root, &qualification)?;
    validate_warning_inventory(root, &qualification)?;
    run_rust_qualification_cases(root)?;
    write_evidence(root, &qualification, &closure_digest, true)?;

    println!("Existing claim audit:              PASS");
    println!("Hosted/release formal gate:        CONFIGURED");
    println!("Production source closure:         {closure_digest}");
    println!("Shipping/extraction cfg parity:    PASS");
    println!("Lean/Aeneas compatibility:         PASS");
    println!(
        "External models and axioms:        {} reviewed, 0 unreviewed",
        qualification.external_models.len()
    );
    println!(
        "Qualification cases:               {}/{} PASS",
        qualification.case_modules.len() + 1,
        qualification.case_modules.len() + 1
    );
    println!("Clean reproduction:                byte-identical");
    println!(
        "Decision:                           {}",
        qualification.decision
    );
    println!("ADR:                                {}", qualification.adr);
    Ok(())
}

fn load_qualification(root: &Path) -> Result<Qualification, String> {
    let path = root.join(QUALIFICATION_PATH);
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    toml::from_str(&source)
        .map_err(|error| format!("invalid Aeneas qualification {}: {error}", path.display()))
}

fn validate_manifest(root: &Path, qualification: &Qualification) -> Result<(), String> {
    if qualification.schema != QUALIFICATION_SCHEMA {
        return Err(format!(
            "unsupported Aeneas qualification schema {}",
            qualification.schema
        ));
    }
    if qualification.decision != "GO-AENEAS-WITH-PRODUCTION-RESHAPE" {
        return Err(format!(
            "qualification decision must be GO-AENEAS-WITH-PRODUCTION-RESHAPE, found {}",
            qualification.decision
        ));
    }
    if qualification.production_features != ["default"]
        || !qualification.semantic_cfg.is_empty()
        || !qualification.extraction_cfg.is_empty()
        || qualification.shipping_target != "workspace-host"
        || qualification.extraction_target != "workspace-host"
        || !qualification.translation_warnings.is_empty()
        || qualification.required_compiled_external_axioms != 0
    {
        return Err(
            "Aeneas qualification changed features, cfg, targets, warnings, or axiom policy"
                .to_owned(),
        );
    }
    if qualification.case_modules.len() != 3
        || qualification.translations.len() != 3
        || qualification.external_models.len() != 4
        || qualification.warning_inventory.len() != 2
        || qualification.template_axioms.len() != 3
    {
        return Err("Aeneas qualification inventory cardinality drifted".to_owned());
    }

    for path in [
        qualification.adr.as_str(),
        qualification.source_closure.as_str(),
    ] {
        if !root.join(path).is_file() && path != qualification.source_closure {
            return Err(format!("Aeneas qualification artifact is absent: {path}"));
        }
    }
    require_unique_nonempty("source files", &qualification.source_files)?;
    require_unique_nonempty("generated files", &qualification.generated_files)?;
    require_unique_nonempty("case modules", &qualification.case_modules)?;

    let mut external_ids = BTreeSet::new();
    for model in &qualification.external_models {
        if !external_ids.insert(model.id.as_str())
            || model.id.trim().is_empty()
            || model.kind.trim().is_empty()
            || model.scope.trim().is_empty()
            || model.rust_symbols.is_empty()
            || !model.reviewed
            || model.axiom
        {
            return Err(format!(
                "external model {} is duplicate, incomplete, unreviewed, or axiomatic",
                model.id
            ));
        }
        if !root.join(&model.artifact).is_file() {
            return Err(format!(
                "reviewed external model artifact is absent: {}",
                model.artifact
            ));
        }
        require_unique_nonempty(
            &format!("external model {} Rust symbols", model.id),
            &model.rust_symbols,
        )?;
        let _ = model.authority_semantics;
    }

    for warning in &qualification.warning_inventory {
        if warning.id.trim().is_empty()
            || warning.artifact.trim().is_empty()
            || warning.upstream_lines.is_empty()
            || warning.classification.trim().is_empty()
        {
            return Err("Aeneas runtime warning inventory is incomplete".to_owned());
        }
    }
    validate_locked_tools(root, &qualification.tools)
}

fn validate_warning_inventory(root: &Path, qualification: &Qualification) -> Result<(), String> {
    for warning in &qualification.warning_inventory {
        let path = root.join(&warning.artifact);
        let source = fs::read_to_string(&path).map_err(|error| {
            format!(
                "could not read pinned Aeneas warning source {}: {error}",
                path.display()
            )
        })?;
        let lines: Vec<_> = source.lines().collect();
        for line in &warning.upstream_lines {
            let source_line = line
                .checked_sub(1)
                .and_then(|index| lines.get(index))
                .ok_or_else(|| {
                    format!(
                        "warning {} points outside {} at line {line}",
                        warning.id, warning.artifact
                    )
                })?;
            if !source_line.contains("sorry") {
                return Err(format!(
                    "warning {} no longer identifies an upstream `sorry` at {}:{line}; review and update the inventory",
                    warning.id, warning.artifact
                ));
            }
        }
    }
    Ok(())
}

fn validate_locked_tools(root: &Path, tools: &QualificationTools) -> Result<(), String> {
    let path = root.join("formal/translation-toolchain.lock");
    let lock: toml::Value = toml::from_str(
        &fs::read_to_string(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("invalid formal toolchain lock: {error}"))?;
    let field = |table: &str, name: &str| -> Result<&str, String> {
        lock.get(table)
            .and_then(toml::Value::as_table)
            .and_then(|value| value.get(name))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("formal toolchain lock omits {table}.{name}"))
    };
    for (actual, table, name) in [
        (tools.shipping_rust.as_str(), "rust", "shipping"),
        (tools.extraction_rust.as_str(), "charon", "toolchain"),
        (tools.charon.as_str(), "charon", "version"),
        (tools.charon_commit.as_str(), "charon", "commit"),
        (tools.aeneas_commit.as_str(), "aeneas", "commit"),
        (tools.lean_toolchain.as_str(), "lean", "toolchain"),
        (tools.kani.as_str(), "kani", "version"),
    ] {
        if field(table, name)? != actual {
            return Err(format!(
                "qualification tool {table}.{name} differs from translation-toolchain.lock"
            ));
        }
    }
    Ok(())
}

fn require_unique_nonempty(label: &str, values: &[String]) -> Result<(), String> {
    let unique: BTreeSet<_> = values.iter().map(String::as_str).collect();
    if unique.len() != values.len() || values.iter().any(|value| value.trim().is_empty()) {
        return Err(format!("{label} must be unique and non-empty"));
    }
    Ok(())
}

fn synchronize_source_closure(
    root: &Path,
    qualification: &Qualification,
    update: bool,
) -> Result<String, String> {
    let translation_roots: Vec<_> = qualification
        .translations
        .iter()
        .map(|translation| translation.crate_name.clone())
        .collect();
    let expected = auths_ci_plan::formal_source_closure_json(
        root,
        &qualification.source_files,
        &translation_roots,
    )?;
    let digest = expected["digest"]
        .as_str()
        .ok_or("formal source closure omits digest")?
        .to_owned();
    let path = root.join(&qualification.source_closure);
    if update {
        write_pretty_json(&path, &expected)?;
    } else {
        let actual: Value = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?,
        )
        .map_err(|error| format!("invalid source closure {}: {error}", path.display()))?;
        if actual != expected {
            return Err(format!(
                "production translation source closure drifted; run `cargo xtask formal qualify aeneas --update` (computed digest {digest})"
            ));
        }
    }
    Ok(digest)
}

fn synchronize_reviewed_bridges(
    root: &Path,
    attenuation_dimensions: &[String],
    update: bool,
) -> Result<(), String> {
    for (relative, expected) in [
        (
            "formal/qualification/aeneas/generated/model/FunsExternal.lean",
            render_model_external(),
        ),
        (
            "formal/qualification/aeneas/generated/authority/TypesExternal.lean",
            render_authority_types_external(),
        ),
        (
            "formal/qualification/aeneas/generated/authority/FunsExternal.lean",
            render_authority_functions_external(attenuation_dimensions),
        ),
    ] {
        let path = root.join(relative);
        if update {
            fs::write(&path, expected)
                .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        } else {
            let actual = fs::read_to_string(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?;
            if actual != expected {
                return Err(format!(
                    "reviewed Aeneas bridge drifted: {relative}; run `cargo xtask formal qualify aeneas --update`"
                ));
            }
        }
    }
    Ok(())
}

fn render_model_external() -> String {
    "-- REVIEWED TRANSPARENT MODEL FOR AN AENEAS STANDARD-LIBRARY EXTERNAL.\n\
--\n\
-- Rust `String::as_bytes` is represented by Aeneas' exact UTF-8 `Str`\n\
-- conversion. This file contains no authority semantics and no axiom.\n\
import Aeneas\n\
import qualification.aeneas.generated.model.Types\n\
\n\
open Aeneas Aeneas.Std Result ControlFlow Error\n\
\n\
set_option linter.dupNamespace false\n\
set_option linter.hashCommand false\n\
set_option linter.unusedVariables false\n\
set_option maxHeartbeats 1000000\n\
set_option maxRecDepth 2048\n\
\n\
@[rust_fun \"alloc::string::{alloc::string::String}::as_bytes\"]\n\
def alloc.string.String.as_bytes (value : String) : Result (Slice Std.U8) :=\n\
  if h : value.toByteArray.size ≤ U32.max then\n\
    ok (Aeneas.Std.toStr value h)\n\
  else\n\
    fail .panic\n"
        .to_owned()
}

fn render_authority_types_external() -> String {
    "-- REVIEWED TYPE LINK FOR AENEAS-GENERATED PRODUCTION AUTHORITY CODE.\n\
--\n\
-- All external authority carriers are the mechanically translated\n\
-- `auths-model` carriers. No opaque type or axiom is introduced here.\n\
import qualification.aeneas.generated.model.Types\n"
        .to_owned()
}

fn render_authority_functions_external(dimensions: &[String]) -> String {
    let mut output =
        "-- REVIEWED TRANSPARENT LINKS FOR AENEAS-GENERATED PRODUCTION AUTHORITY CODE.\n\
--\n\
-- Every rich leaf predicate below is imported from the mechanically\n\
-- translated `auths-model` production source. The sole local definition is\n\
-- the ten-field conjunction generated from `formal/algebra-contract-v1.toml`;\n\
-- `cargo xtask formal` rejects drift from that contract.\n\
import Aeneas\n\
import qualification.aeneas.generated.authority.Types\n\
import qualification.aeneas.generated.model.Funs\n\
\n\
open Aeneas Aeneas.Std Result ControlFlow Error\n\
\n\
set_option linter.dupNamespace false\n\
set_option linter.hashCommand false\n\
set_option linter.unusedVariables false\n\
set_option maxHeartbeats 1000000\n\
set_option maxRecDepth 2048\n\
\n\
open auths_authority\n\
\n\
@[rust_fun \"auths_algebra_kernel::generated::attenuation_checks_accept\"]\n\
def auths_algebra_kernel.generated.attenuation_checks_accept\n\
    (checks : auths_algebra_kernel.generated.AttenuationChecks) : Result Bool := do\n"
            .to_owned();
    if let Some((last, prefix)) = dimensions.split_last() {
        let mut indent = 2;
        for dimension in prefix {
            output.push_str(&format!(
                "{}if checks.{dimension} then\n",
                " ".repeat(indent)
            ));
            indent += 2;
        }
        output.push_str(&format!("{}ok checks.{last}\n", " ".repeat(indent)));
        for _ in prefix.iter().rev() {
            indent -= 2;
            output.push_str(&format!("{}else ok false\n", " ".repeat(indent)));
        }
    }
    output
}

fn validate_generated_inventory(root: &Path, qualification: &Qualification) -> Result<(), String> {
    for relative in &qualification.generated_files {
        let path = root.join(relative);
        if !path.is_file() {
            return Err(format!(
                "Aeneas generated artifact is absent: {}",
                path.display()
            ));
        }
        if path.extension().and_then(|value| value.to_str()) == Some("lean")
            && !relative.ends_with("_Template.lean")
        {
            let source = fs::read_to_string(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?;
            for forbidden in ["axiom ", "sorry", "admit"] {
                if source
                    .lines()
                    .any(|line| line.trim_start().starts_with(forbidden))
                {
                    return Err(format!(
                        "compiled qualification artifact contains forbidden `{forbidden}`: {relative}"
                    ));
                }
            }
        }
    }
    for inventory in &qualification.template_axioms {
        if inventory.compiled {
            return Err(format!(
                "Aeneas external template must not be compiled: {}",
                inventory.artifact
            ));
        }
        let source = fs::read_to_string(root.join(&inventory.artifact))
            .map_err(|error| format!("could not read {}: {error}", inventory.artifact))?;
        let count = source
            .lines()
            .filter(|line| line.trim_start().starts_with("axiom "))
            .count();
        if count != inventory.count {
            return Err(format!(
                "Aeneas template axiom inventory drifted for {}: expected {}, found {count}",
                inventory.artifact, inventory.count
            ));
        }
    }
    Ok(())
}

fn validate_translation_reports(root: &Path, qualification: &Qualification) -> Result<(), String> {
    let expected_aeneas = &qualification.tools.aeneas_commit[..7];
    for expected in &qualification.translations {
        let path = root.join(&expected.translation_json);
        let report: TranslationReport = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?,
        )
        .map_err(|error| {
            format!(
                "invalid Aeneas translation report {}: {error}",
                path.display()
            )
        })?;
        if report.crate_name != expected.crate_name
            || report.aeneas_version != expected_aeneas
            || report.charon_version != qualification.tools.charon
        {
            return Err(format!(
                "Aeneas translation identity drifted for {}",
                expected.crate_name
            ));
        }
        let local = report
            .functions
            .iter()
            .filter(|function| function.is_local)
            .count();
        let external = report.functions.len() - local;
        let opaque_local = report
            .functions
            .iter()
            .filter(|function| function.is_local && function.is_opaque)
            .count();
        if local != expected.local_functions
            || external != expected.external_functions
            || opaque_local != expected.opaque_local_functions
        {
            return Err(format!(
                "Aeneas function inventory drifted for {}: local={local}, external={external}, opaque-local={opaque_local}",
                expected.crate_name
            ));
        }
        let symbols: BTreeSet<_> = report
            .functions
            .iter()
            .map(|function| function.rust_name.as_str())
            .collect();
        for symbol in &expected.required_symbols {
            if !symbols.contains(symbol.as_str()) {
                return Err(format!(
                    "Aeneas translation for {} omits required production symbol {symbol}",
                    expected.crate_name
                ));
            }
        }
        let external_symbols: BTreeSet<_> = report
            .functions
            .iter()
            .filter(|function| !function.is_local)
            .map(|function| function.rust_name.as_str())
            .collect();
        let allowed: BTreeSet<_> = expected
            .allowed_external_symbols
            .iter()
            .map(String::as_str)
            .collect();
        if external_symbols != allowed {
            return Err(format!(
                "unreviewed Aeneas external functions for {}: expected={allowed:?}, actual={external_symbols:?}",
                expected.crate_name
            ));
        }
    }
    Ok(())
}

fn validate_workflow_gates(root: &Path) -> Result<(), String> {
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .map_err(|error| format!("could not read hosted CI workflow: {error}"))?;
    let release = fs::read_to_string(root.join(".github/workflows/release.yml"))
        .map_err(|error| format!("could not read release workflow: {error}"))?;
    for (label, source, needles) in [
        (
            "hosted CI",
            ci.as_str(),
            &[
                "leanprover/lean-action@",
                "kani-verifier --version 0.67.0",
                "cargo xtask ci authoritative",
                "cargo xtask ci formal-translation",
                "cargo xtask ci compliance",
                "target/formal/",
            ][..],
        ),
        (
            "release CI",
            release.as_str(),
            &[
                "leanprover/lean-action@",
                "kani-verifier --version 0.67.0",
                "cargo xtask release-check",
                "cargo xtask formal qualify aeneas",
            ][..],
        ),
    ] {
        for needle in needles {
            if !source.contains(needle) {
                return Err(format!("{label} omits required formal gate `{needle}`"));
            }
        }
    }
    Ok(())
}

fn build_qualification_cases(root: &Path, qualification: &Qualification) -> Result<(), String> {
    let formal = root.join("formal");
    for module in &qualification.case_modules {
        run_checked(
            "lake",
            &[String::from("build"), module.clone()],
            &formal,
            &[],
        )?;
    }
    Ok(())
}

fn run_rust_qualification_cases(root: &Path) -> Result<(), String> {
    run_checked(
        "cargo",
        &[
            "test".to_owned(),
            "-p".to_owned(),
            "auths-model".to_owned(),
            "-p".to_owned(),
            "auths-authority".to_owned(),
            "-p".to_owned(),
            "auths-author".to_owned(),
        ],
        root,
        &[],
    )
}

fn required_tool(variable: &str, fallback: &str) -> Result<PathBuf, String> {
    if let Some(value) = env::var_os(variable) {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "{variable} does not identify a file: {}",
            path.display()
        ));
    }
    let output = Command::new(fallback).arg("--help").output().map_err(|_| {
        format!(
            "pinned {fallback} is unavailable; set {variable} to the exact binary from formal/translation-toolchain.lock"
        )
    })?;
    if !output.status.success() {
        return Err(format!("could not execute {fallback} from PATH"));
    }
    Ok(PathBuf::from(fallback))
}

fn validate_translation_tool_versions(
    charon: &Path,
    aeneas: &Path,
    qualification: &Qualification,
) -> Result<(), String> {
    let charon_version = run_output(charon, &["version"], Path::new("."), &[])?;
    if charon_version.trim() != qualification.tools.charon {
        return Err(format!(
            "Charon drift: expected {}, found {}",
            qualification.tools.charon,
            charon_version.trim()
        ));
    }
    let aeneas_version = run_output(aeneas, &["-version"], Path::new("."), &[])?;
    let expected = format!("aeneas {}", &qualification.tools.aeneas_commit[..7]);
    if aeneas_version.trim() != expected {
        return Err(format!(
            "Aeneas drift: expected {expected}, found {}",
            aeneas_version.trim()
        ));
    }
    Ok(())
}

fn ensure_clean_extraction_environment(qualification: &Qualification) -> Result<(), String> {
    for variable in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CARGO_BUILD_TARGET",
    ] {
        if env::var_os(variable).is_some() {
            return Err(format!(
                "Aeneas qualification refuses ambient semantic build variable {variable}"
            ));
        }
    }
    if !qualification.semantic_cfg.is_empty() || !qualification.extraction_cfg.is_empty() {
        return Err("qualification requires empty shipping and extraction semantic cfg".to_owned());
    }
    Ok(())
}

fn recreate_directory(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_dir_all(path)
            .map_err(|error| format!("could not clear {}: {error}", path.display()))?;
    }
    fs::create_dir_all(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))
}

fn reproduce(
    root: &Path,
    charon: &Path,
    aeneas: &Path,
    stable_llbc: &Path,
    output: &Path,
) -> Result<(), String> {
    recreate_directory(output)?;
    recreate_directory(stable_llbc)?;
    let llbc = output.join("llbc");
    fs::create_dir_all(&llbc)
        .map_err(|error| format!("could not create {}: {error}", llbc.display()))?;

    let model_starts = [
        "auths_model::inclusive_window_contains",
        "auths_model::validity_window_contains",
        "auths_model::permission_set_contains",
        "auths_model::permission_set_is_subset",
        "auths_model::audience_set_contains",
        "auths_model::audience_set_is_subset",
        "auths_model::body_digest_set_contains",
        "auths_model::body_digest_set_is_subset",
        "auths_model::action_constraint_allows",
        "auths_model::action_constraint_attenuates",
        "auths_model::budget_ceiling_attenuates",
        "auths_model::optional_budget_attenuates",
        "auths_model::optional_budget_covers",
        "auths_model::status_policy_attenuates",
        "auths_model::assurance_policy_id_equal",
        "auths_model::principal_id_equal",
        "auths_model::grant_id_equal",
        "auths_model::optional_grant_id_equal",
        "auths_model::profile_slice_contains",
        "auths_model::profile_ref_equal",
    ]
    .join(",");
    run_checked(
        charon,
        &charon_arguments(
            &model_starts,
            &stable_llbc.join("auths_model.llbc"),
            "core/crates/auths-model/Cargo.toml",
            &[],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_algebra_kernel::generated::attenuation_checks_accept",
            &stable_llbc.join("auths_algebra_kernel.llbc"),
            "core/crates/auths-algebra-kernel/Cargo.toml",
            &[],
        ),
        root,
        &[],
    )?;
    let authority_options = [
        "--opaque",
        "auths_model",
        "--include",
        "auths_model::GrantAuthorityView",
        "--include",
        "auths_model::ActionAuthorityView",
        "--include",
        "auths_model::ScopeAuthorityView",
        "--include",
        "auths_model::DenialReason",
    ];
    run_checked(
        charon,
        &charon_arguments(
            "auths_authority::evaluate_grant_view,auths_authority::evaluate_action_coverage_view,auths_authority::evaluate_author_scope_view",
            &stable_llbc.join("auths_authority.llbc"),
            "core/crates/auths-authority/Cargo.toml",
            &authority_options,
        ),
        root,
        &[],
    )?;

    for crate_name in ["auths_model", "auths_algebra_kernel", "auths_authority"] {
        let snapshot = llbc.join(format!("{crate_name}.llbc"));
        fs::copy(stable_llbc.join(format!("{crate_name}.llbc")), &snapshot).map_err(|error| {
            format!("could not snapshot deterministic {crate_name} LLBC: {error}")
        })?;
        let arguments = ["pretty-print".to_owned(), snapshot.display().to_string()];
        let pretty = command_output(charon, &arguments, root, &[])?;
        if !pretty.status.success() {
            return Err(format_command_failure(&arguments, root, &pretty));
        }
        fs::write(
            llbc.join(format!("{crate_name}.llbc.pretty")),
            pretty.stdout,
        )
        .map_err(|error| format!("could not write canonical {crate_name} LLBC: {error}"))?;
    }

    for (crate_name, subdir) in [
        ("auths_model", "model"),
        ("auths_algebra_kernel", "algebra"),
        ("auths_authority", "authority"),
    ] {
        let destination = output.join(format!("{subdir}-run"));
        fs::create_dir_all(&destination).map_err(|error| {
            format!(
                "could not create Aeneas destination {}: {error}",
                destination.display()
            )
        })?;
        run_checked(
            aeneas,
            &[
                "-backend".to_owned(),
                "lean".to_owned(),
                "-split-files".to_owned(),
                "-emit-json".to_owned(),
                "-warnings-as-errors".to_owned(),
                "-subdir".to_owned(),
                format!("qualification/aeneas/generated/{subdir}"),
                "-dest".to_owned(),
                destination.display().to_string(),
                llbc.join(format!("{crate_name}.llbc"))
                    .display()
                    .to_string(),
            ],
            root,
            &[],
        )?;
    }
    for crate_name in ["auths_model", "auths_algebra_kernel", "auths_authority"] {
        fs::remove_file(llbc.join(format!("{crate_name}.llbc")))
            .map_err(|error| format!("could not remove raw nondeterministic LLBC: {error}"))?;
    }
    Ok(())
}

fn charon_arguments(
    start_from: &str,
    destination: &Path,
    manifest: &str,
    extra: &[&str],
) -> Vec<String> {
    let mut arguments = vec![
        "cargo".to_owned(),
        "--preset".to_owned(),
        "aeneas".to_owned(),
        "--start-from".to_owned(),
        start_from.to_owned(),
        "--error-on-warnings".to_owned(),
        "--dest-file".to_owned(),
        destination.display().to_string(),
        "--format".to_owned(),
        "json".to_owned(),
    ];
    for argument in extra {
        arguments.push((*argument).to_owned());
    }
    arguments.extend([
        "--".to_owned(),
        "--manifest-path".to_owned(),
        manifest.to_owned(),
    ]);
    arguments
}

fn synchronize_aeneas_output(root: &Path, reproduced: &Path, update: bool) -> Result<(), String> {
    let mappings = [
        (
            "model-run/qualification/aeneas/generated/model/Types.lean",
            "formal/qualification/aeneas/generated/model/Types.lean",
        ),
        (
            "model-run/qualification/aeneas/generated/model/Funs.lean",
            "formal/qualification/aeneas/generated/model/Funs.lean",
        ),
        (
            "model-run/qualification/aeneas/generated/model/FunsExternal_Template.lean",
            "formal/qualification/aeneas/generated/model/FunsExternal_Template.lean",
        ),
        (
            "model-run/translation.json",
            "formal/qualification/aeneas/generated/model/translation.json",
        ),
        (
            "algebra-run/qualification/aeneas/generated/algebra/Types.lean",
            "formal/qualification/aeneas/generated/algebra/Types.lean",
        ),
        (
            "algebra-run/qualification/aeneas/generated/algebra/Funs.lean",
            "formal/qualification/aeneas/generated/algebra/Funs.lean",
        ),
        (
            "algebra-run/translation.json",
            "formal/qualification/aeneas/generated/algebra/translation.json",
        ),
        (
            "authority-run/qualification/aeneas/generated/authority/Types.lean",
            "formal/qualification/aeneas/generated/authority/Types.lean",
        ),
        (
            "authority-run/qualification/aeneas/generated/authority/TypesExternal_Template.lean",
            "formal/qualification/aeneas/generated/authority/TypesExternal_Template.lean",
        ),
        (
            "authority-run/qualification/aeneas/generated/authority/Funs.lean",
            "formal/qualification/aeneas/generated/authority/Funs.lean",
        ),
        (
            "authority-run/qualification/aeneas/generated/authority/FunsExternal_Template.lean",
            "formal/qualification/aeneas/generated/authority/FunsExternal_Template.lean",
        ),
        (
            "authority-run/translation.json",
            "formal/qualification/aeneas/generated/authority/translation.json",
        ),
    ];
    for (source, destination) in mappings {
        let bytes = fs::read(reproduced.join(source)).map_err(|error| {
            format!("could not read reproduced Aeneas output {source}: {error}")
        })?;
        let destination = root.join(destination);
        if update {
            fs::write(&destination, bytes).map_err(|error| {
                format!(
                    "could not update generated Aeneas output {}: {error}",
                    destination.display()
                )
            })?;
        } else {
            let actual = fs::read(&destination).map_err(|error| {
                format!(
                    "could not read committed Aeneas output {}: {error}",
                    destination.display()
                )
            })?;
            if actual != bytes {
                return Err(format!(
                    "generated Aeneas output drifted: {}; reproduce with `cargo xtask formal qualify aeneas --update`",
                    destination.display()
                ));
            }
        }
    }
    Ok(())
}

fn collect_files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    fn walk(
        base: &Path,
        directory: &Path,
        output: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<(), String> {
        let mut entries: Vec<_> = fs::read_dir(directory)
            .map_err(|error| format!("could not read {}: {error}", directory.display()))?
            .collect::<Result<_, _>>()
            .map_err(|error| format!("could not enumerate {}: {error}", directory.display()))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, output)?;
            } else if path.is_file() {
                let relative = path
                    .strip_prefix(base)
                    .map_err(|error| format!("could not relativize {}: {error}", path.display()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                output.insert(
                    relative,
                    fs::read(&path)
                        .map_err(|error| format!("could not read {}: {error}", path.display()))?,
                );
            }
        }
        Ok(())
    }

    let mut files = BTreeMap::new();
    walk(root, root, &mut files)?;
    Ok(files)
}

fn write_evidence(
    root: &Path,
    qualification: &Qualification,
    closure_digest: &str,
    reproduced: bool,
) -> Result<(), String> {
    let path = root.join("target/formal/aeneas-qualification.json");
    write_pretty_json(
        &path,
        &json!({
            "schema": "auths-proof-aeneas-qualification-evidence/v1",
            "decision": qualification.decision,
            "source_closure_sha256": closure_digest,
            "production_features": qualification.production_features,
            "semantic_cfg": qualification.semantic_cfg,
            "extraction_cfg": qualification.extraction_cfg,
            "compiled_external_axioms": 0,
            "reviewed_external_models": qualification.external_models.len(),
            "case_modules": qualification.case_modules,
            "clean_reproduction": if reproduced { "byte-identical" } else { "not-run-committed-artifacts-validated" },
            "adr": qualification.adr,
        }),
    )
}

fn write_pretty_json(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not encode {}: {error}", path.display()))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| format!("could not write {}: {error}", path.display()))
}

fn run_checked<S: AsRef<std::ffi::OsStr>>(
    program: S,
    arguments: &[String],
    directory: &Path,
    environment: &[(&str, &str)],
) -> Result<(), String> {
    let output = command_output(program, arguments, directory, environment)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format_command_failure(arguments, directory, &output))
    }
}

fn run_output<S: AsRef<std::ffi::OsStr>>(
    program: S,
    arguments: &[&str],
    directory: &Path,
    environment: &[(&str, &str)],
) -> Result<String, String> {
    let owned: Vec<_> = arguments.iter().map(|value| (*value).to_owned()).collect();
    let output = command_output(program, &owned, directory, environment)?;
    if !output.status.success() {
        return Err(format_command_failure(&owned, directory, &output));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("tool emitted non-UTF-8 output: {error}"))
}

fn command_output<S: AsRef<std::ffi::OsStr>>(
    program: S,
    arguments: &[String],
    directory: &Path,
    environment: &[(&str, &str)],
) -> Result<Output, String> {
    let program_text = program.as_ref().to_string_lossy().into_owned();
    let mut command = Command::new(&program);
    command
        .args(arguments)
        .current_dir(directory)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTDOCFLAGS")
        .env_remove("CARGO_BUILD_TARGET");
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().map_err(|error| {
        format!(
            "could not run `{program_text} {}` in {}: {error}",
            arguments.join(" "),
            directory.display()
        )
    })
}

fn format_command_failure(arguments: &[String], directory: &Path, output: &Output) -> String {
    format!(
        "command failed in {}: {}\nstdout:\n{}\nstderr:\n{}",
        directory.display(),
        arguments.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
