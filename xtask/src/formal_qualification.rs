#![allow(clippy::too_many_lines)]

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const QUALIFICATION_PATH: &str = "formal/qualification/aeneas/qualification.toml";
const QUALIFICATION_SCHEMA: &str = "auths-proof-aeneas-qualification/v1";
const QUALIFICATION_BOUNDARY_CONTRACT_SHA256: &str =
    "dd329a08f632fafdcd536ff4bba53ef67d8a9574240baeca54365097a47a9ee0";

const AENEAS_OUTPUT_MAPPINGS: &[(&str, &str)] = &[
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
    (
        "bounded_policy-run/qualification/aeneas/generated/bounded_policy/Types.lean",
        "formal/qualification/aeneas/generated/bounded_policy/Types.lean",
    ),
    (
        "bounded_policy-run/qualification/aeneas/generated/bounded_policy/Funs.lean",
        "formal/qualification/aeneas/generated/bounded_policy/Funs.lean",
    ),
    (
        "bounded_policy-run/translation.json",
        "formal/qualification/aeneas/generated/bounded_policy/translation.json",
    ),
    (
        "lifecycle-run/qualification/aeneas/generated/lifecycle/Types.lean",
        "formal/qualification/aeneas/generated/lifecycle/Types.lean",
    ),
    (
        "lifecycle-run/qualification/aeneas/generated/lifecycle/Funs.lean",
        "formal/qualification/aeneas/generated/lifecycle/Funs.lean",
    ),
    (
        "lifecycle-run/translation.json",
        "formal/qualification/aeneas/generated/lifecycle/translation.json",
    ),
];

const REVIEWED_BRIDGE_ARTIFACTS: &[&str] = &[
    "formal/qualification/aeneas/generated/model/FunsExternal.lean",
    "formal/qualification/aeneas/generated/authority/TypesExternal.lean",
    "formal/qualification/aeneas/generated/authority/FunsExternal.lean",
];

/// Exact artifact set whose bytes a successful clean reproduction certifies.
/// Keep this ordered list aligned with the checked-in qualification manifest;
/// synchronization and reviewed bridge destinations are checked against it.
const GENERATED_ARTIFACTS: &[&str] = &[
    "formal/qualification/aeneas/generated/model/Types.lean",
    "formal/qualification/aeneas/generated/model/Funs.lean",
    "formal/qualification/aeneas/generated/model/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/model/FunsExternal.lean",
    "formal/qualification/aeneas/generated/model/translation.json",
    "formal/qualification/aeneas/generated/algebra/Types.lean",
    "formal/qualification/aeneas/generated/algebra/Funs.lean",
    "formal/qualification/aeneas/generated/algebra/translation.json",
    "formal/qualification/aeneas/generated/authority/Types.lean",
    "formal/qualification/aeneas/generated/authority/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/authority/TypesExternal.lean",
    "formal/qualification/aeneas/generated/authority/Funs.lean",
    "formal/qualification/aeneas/generated/authority/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/authority/FunsExternal.lean",
    "formal/qualification/aeneas/generated/authority/translation.json",
    "formal/qualification/aeneas/generated/bounded_policy/Types.lean",
    "formal/qualification/aeneas/generated/bounded_policy/Funs.lean",
    "formal/qualification/aeneas/generated/bounded_policy/translation.json",
    "formal/qualification/aeneas/generated/lifecycle/Types.lean",
    "formal/qualification/aeneas/generated/lifecycle/Funs.lean",
    "formal/qualification/aeneas/generated/lifecycle/translation.json",
];

const EXPECTED_CASE_MODULES: &[&str] = &[
    "qualification.aeneas.cases.Model",
    "qualification.aeneas.cases.Algebra",
    "qualification.aeneas.cases.Authority",
    "qualification.aeneas.cases.BoundedPolicy",
    "qualification.aeneas.cases.Lifecycle",
];

const REQUIRED_AUTHORED_SOURCE_INPUTS: &[&str] = &[
    ".cargo/config.toml",
    "Cargo.toml",
    "Cargo.lock",
    "formal/algebra-contract-v1.toml",
    "formal/qualification/aeneas/qualification.toml",
    "formal/translation-toolchain.lock",
    "formal/qualification/aeneas/cases/Model.lean",
    "formal/qualification/aeneas/cases/Algebra.lean",
    "formal/qualification/aeneas/cases/Authority.lean",
    "formal/qualification/aeneas/cases/BoundedPolicy.lean",
    "formal/qualification/aeneas/cases/Lifecycle.lean",
];

const EXPECTED_TRANSLATIONS: &[(&str, &str)] = &[
    (
        "auths_model",
        "formal/qualification/aeneas/generated/model/translation.json",
    ),
    (
        "auths_algebra_kernel",
        "formal/qualification/aeneas/generated/algebra/translation.json",
    ),
    (
        "auths_lifecycle",
        "formal/qualification/aeneas/generated/lifecycle/translation.json",
    ),
    (
        "auths_authority",
        "formal/qualification/aeneas/generated/authority/translation.json",
    ),
    (
        "auths_bounded_policy",
        "formal/qualification/aeneas/generated/bounded_policy/translation.json",
    ),
];

const EXPECTED_TEMPLATE_AXIOMS: &[&str] = &[
    "formal/qualification/aeneas/generated/model/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/authority/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/authority/FunsExternal_Template.lean",
];

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
    ensure_clean_extraction_environment(root, &qualification)?;
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

/// Qualifies the Aeneas translation, translation-first.
///
/// `build_and_audit` compiles Lean and runs the compiled assurance audit. It is
/// invoked AFTER regenerated outputs and reviewed bridges are synchronized,
/// never before reproduction: qualification regenerates the Lean a build would
/// compile, so building first deadlocks the moment a translation references a
/// symbol its upstream crate has not exported yet.
///
/// A failing build still fails qualification. Intentionally regenerated files
/// are left in the tree for the proofs to be repaired, but no evidence is
/// written and no success is printed.
pub(crate) fn qualify(
    root: &Path,
    attenuation_dimensions: &[String],
    update: bool,
    build_and_audit: &dyn Fn() -> Result<(), String>,
) -> Result<(), String> {
    let qualification = load_qualification(root)?;
    validate_manifest(root, &qualification)?;
    if !update {
        synchronize_source_closure(root, &qualification, false)?;
    }
    ensure_clean_extraction_environment(root, &qualification)?;
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
    canonicalize_aeneas_versions(&first, &qualification.tools.aeneas_commit)?;
    canonicalize_aeneas_versions(&second, &qualification.tools.aeneas_commit)?;

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

    // Everything below reads the generated Lean just synchronized above, so the
    // compiled gate runs here and not a step earlier.
    build_and_audit()?;

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
    if qualification.adr != "docs/adr/0011-rich-authority-rust-lean-link.md"
        || qualification.source_closure != "formal/qualification/aeneas/source-closure.json"
    {
        return Err("Aeneas qualification ADR or source-closure path drifted".to_owned());
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
    if qualification.case_modules.len() != 5
        || qualification.translations.len() != 5
        || qualification.external_models.len() != 4
        || qualification.warning_inventory.len() != 4
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
    for required in REQUIRED_AUTHORED_SOURCE_INPUTS {
        if !qualification
            .source_files
            .iter()
            .any(|path| path == required)
        {
            return Err(format!(
                "Aeneas authored source inventory omits required qualification input {required}"
            ));
        }
    }
    validate_generated_artifact_inventory(&qualification.generated_files)?;
    validate_exact_inventory(
        "case modules",
        &qualification.case_modules,
        EXPECTED_CASE_MODULES,
    )?;
    let actual_translations = qualification
        .translations
        .iter()
        .map(|translation| {
            (
                translation.crate_name.as_str(),
                translation.translation_json.as_str(),
            )
        })
        .collect::<Vec<_>>();
    if actual_translations != EXPECTED_TRANSLATIONS {
        return Err("Aeneas translation crate/report inventory drifted".to_owned());
    }
    let actual_templates = qualification
        .template_axioms
        .iter()
        .map(|inventory| inventory.artifact.as_str())
        .collect::<Vec<_>>();
    if actual_templates != EXPECTED_TEMPLATE_AXIOMS {
        return Err("Aeneas template axiom inventory drifted".to_owned());
    }
    let boundary_digest = qualification_boundary_contract_sha256(qualification);
    if boundary_digest != QUALIFICATION_BOUNDARY_CONTRACT_SHA256 {
        return Err(format!(
            "Aeneas reviewed translation/external boundary contract drifted: expected {QUALIFICATION_BOUNDARY_CONTRACT_SHA256}, found {boundary_digest}"
        ));
    }

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

fn qualification_boundary_contract_sha256(qualification: &Qualification) -> String {
    let external_models = qualification
        .external_models
        .iter()
        .map(|model| {
            json!({
                "id": model.id,
                "kind": model.kind,
                "artifact": model.artifact,
                "rust_symbols": model.rust_symbols,
                "authority_semantics": model.authority_semantics,
                "reviewed": model.reviewed,
                "axiom": model.axiom,
                "scope": model.scope,
            })
        })
        .collect::<Vec<_>>();
    let translations = qualification
        .translations
        .iter()
        .map(|translation| {
            json!({
                "crate_name": translation.crate_name,
                "translation_json": translation.translation_json,
                "local_functions": translation.local_functions,
                "external_functions": translation.external_functions,
                "opaque_local_functions": translation.opaque_local_functions,
                "required_symbols": translation.required_symbols,
                "allowed_external_symbols": translation.allowed_external_symbols,
            })
        })
        .collect::<Vec<_>>();
    let warnings = qualification
        .warning_inventory
        .iter()
        .map(|warning| {
            json!({
                "id": warning.id,
                "artifact": warning.artifact,
                "upstream_lines": warning.upstream_lines,
                "classification": warning.classification,
            })
        })
        .collect::<Vec<_>>();
    let templates = qualification
        .template_axioms
        .iter()
        .map(|template| {
            json!({
                "artifact": template.artifact,
                "count": template.count,
                "compiled": template.compiled,
            })
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&json!({
        "external_models": external_models,
        "translations": translations,
        "warning_inventory": warnings,
        "template_axioms": templates,
    }))
    .expect("in-memory qualification contract serializes");
    hex::encode(Sha256::digest(bytes))
}

fn validate_warning_inventory(root: &Path, qualification: &Qualification) -> Result<(), String> {
    let package = root.join("formal/.lake/packages/aeneas");
    let actual_commit = run_output("git", &["rev-parse", "HEAD"], &package, &[])?;
    if actual_commit.trim() != qualification.tools.aeneas_commit {
        return Err(format!(
            "pinned Aeneas package commit drifted: expected {}, found {}",
            qualification.tools.aeneas_commit,
            actual_commit.trim()
        ));
    }
    let status = run_output("git", &["status", "--porcelain=v1"], &package, &[])?;
    if !status.trim().is_empty() {
        return Err(format!(
            "pinned Aeneas package has local modifications; qualification refuses a dirty dependency:\n{}",
            status.trim_end()
        ));
    }

    let mut present = BTreeMap::new();
    collect_lean_sorries(root, &package.join("backends/lean"), &mut present)?;
    let mut inventoried = BTreeMap::new();
    for warning in &qualification.warning_inventory {
        if inventoried
            .insert(warning.artifact.clone(), warning.upstream_lines.clone())
            .is_some()
        {
            return Err(format!(
                "Aeneas warning inventory repeats artifact {}",
                warning.artifact
            ));
        }
    }
    if present != inventoried {
        return Err(format!(
            "pinned Aeneas package `sorry` inventory drifted: inventoried={inventoried:?}, present={present:?}"
        ));
    }
    Ok(())
}

/// Finds code-level `sorry`/`admit` identifiers while ignoring comments and
/// literal contents. Syntax quotations remain code and are inventoried because
/// a tactic capable of manufacturing `sorry` is part of the package surface.
fn lean_sorry_lines(source: &str) -> Vec<usize> {
    let bytes = source.as_bytes();
    let mut lines = BTreeSet::new();
    let mut index = 0;
    let mut line = 1;
    let mut block_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        if block_depth > 0 {
            if byte == b'\n' {
                line += 1;
            }
            if byte == b'/' && next == Some(b'-') {
                block_depth += 1;
                index += 2;
                continue;
            }
            if byte == b'-' && next == Some(b'/') {
                block_depth -= 1;
                index += 2;
                continue;
            }
            index += 1;
            continue;
        }
        if in_string {
            if byte == b'\n' {
                line += 1;
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'-' && next == Some(b'-') {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if byte == b'/' && next == Some(b'-') {
            block_depth = 1;
            index += 2;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'\'' {
            // Lean also uses `'(` for syntax quotation and apostrophes in
            // identifiers. Only skip a lexically complete character literal;
            // treating every apostrophe as one can hide arbitrary later code.
            index = lean_char_literal_end(source, index).unwrap_or(index + 1);
            continue;
        }
        if byte == b'\n' {
            line += 1;
            index += 1;
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b'\'')
            {
                index += 1;
            }
            let token = &source[start..index];
            if token == "sorry" || token == "admit" {
                lines.insert(line);
            }
            continue;
        }
        index += 1;
    }
    lines.into_iter().collect()
}

fn lean_char_literal_end(source: &str, quote: usize) -> Option<usize> {
    let tail = source.get(quote + 1..)?;
    let mut chars = tail.char_indices();
    let (_, first) = chars.next()?;
    if first == '\n' || first == '\r' || first == '\'' {
        return None;
    }
    if first != '\\' {
        let closing = quote + 1 + first.len_utf8();
        return (source.as_bytes().get(closing) == Some(&b'\'')).then_some(closing + 1);
    }

    let escaped = tail.as_bytes().get(1).copied()?;
    let closing = match escaped {
        b'x' => quote + 5,
        b'u' if tail.as_bytes().get(2) == Some(&b'{') => {
            let brace = tail.find('}')?;
            quote + 1 + brace + 1
        }
        _ => quote + 3,
    };
    (source.as_bytes().get(closing) == Some(&b'\'')).then_some(closing + 1)
}

fn collect_lean_sorries(
    workspace_root: &Path,
    directory: &Path,
    output: &mut BTreeMap<String, Vec<usize>>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("could not read {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("could not enumerate {}: {error}", directory.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_lean_sorries(workspace_root, &path, output)?;
        } else if path.extension().and_then(|value| value.to_str()) == Some("lean") {
            let source = fs::read_to_string(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?;
            let lines = lean_sorry_lines(&source);
            if !lines.is_empty() {
                let relative = path
                    .strip_prefix(workspace_root)
                    .map_err(|error| format!("Aeneas source escaped workspace: {error}"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                output.insert(relative, lines);
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

/// Renders the authority external bridge: transparent adapters plus imports.
///
/// The authority translation emits its OWN copies of the algebra carriers,
/// `auths_authority.auths_algebra_kernel.RootLinkage` and
/// `...generated.AttenuationChecks`, distinct from the `_root_` types the
/// translated `auths_algebra_kernel` owns. Lean rejects passing one where the
/// other is expected.
///
/// This file reboxes, field by field, and delegates. It restates NO Boolean
/// semantics: `root_preserved` and `attenuation_checks_accept` remain owned by
/// the mechanically translated algebra crate, and the adapters below only move
/// fields and call them. No axiom, cast, assumed equality, or reimplementation.
///
/// The eleven attenuation assignments are generated from `dimensions`, i.e.
/// from `formal/algebra-contract-v1.toml`, so adding a twelfth dimension
/// regenerates this file rather than silently dropping the field.
///
/// Emitted as explicit lines: Lean structure literals are layout-sensitive and
/// Rust string continuations strip leading whitespace.
fn render_authority_functions_external(dimensions: &[String]) -> String {
    const LINKAGE_FIELDS: [&str; 4] = [
        "parent_root",
        "parent_subject",
        "parent_delegated",
        "grant_issuer",
    ];
    let mut lines: Vec<String> = vec![
        "-- REVIEWED TRANSPARENT ADAPTERS FOR AENEAS-GENERATED PRODUCTION AUTHORITY CODE.".into(),
        "--".into(),
        "-- The authority translation emits authority-local copies of the algebra".into(),
        "-- carriers. These adapters rebox them field by field into the carriers the".into(),
        "-- translated `auths_algebra_kernel` owns and delegate to its functions.".into(),
        "--".into(),
        "-- NO axiom, cast, assumed equality, or restated semantics. Every Boolean".into(),
        "-- decision below is computed by the mechanically translated owning crate.".into(),
        format!(
            "-- Attenuation dimensions bound by formal/algebra-contract-v1.toml: {}.",
            dimensions.len()
        ),
        "import Aeneas".into(),
        "import qualification.aeneas.generated.authority.Types".into(),
        "import qualification.aeneas.generated.model.Funs".into(),
        "import qualification.aeneas.generated.algebra.Funs".into(),
        String::new(),
        "open Aeneas Aeneas.Std Result ControlFlow Error".into(),
        String::new(),
        "set_option linter.dupNamespace false".into(),
        "set_option linter.hashCommand false".into(),
        "set_option linter.unusedVariables false".into(),
        "set_option maxHeartbeats 1000000".into(),
        "set_option maxRecDepth 2048".into(),
        String::new(),
        "namespace auths_authority".into(),
        String::new(),
        "/-- Reboxes the authority-local root linkage into the owning carrier. -/".into(),
        "def auths_algebra_kernel.toRootLinkage {Identity : Type}".into(),
        "    (value : auths_algebra_kernel.RootLinkage Identity) :".into(),
        "    _root_.auths_algebra_kernel.RootLinkage Identity :=".into(),
    ];
    for (index, field) in LINKAGE_FIELDS.iter().enumerate() {
        let open = if index == 0 { "  { " } else { "    " };
        let close = if index + 1 == LINKAGE_FIELDS.len() {
            " }"
        } else {
            ","
        };
        lines.push(format!("{open}{field} := value.{field}{close}"));
    }
    lines.extend([
        String::new(),
        "/-- Delegates root preservation to the translated algebra kernel. -/".into(),
        "@[rust_fun \"auths_algebra_kernel::root_preserved\"]".into(),
        "def auths_algebra_kernel.root_preserved {Identity : Type}".into(),
        "    (inst : core.cmp.PartialEq Identity Identity)".into(),
        "    (linkage : auths_algebra_kernel.RootLinkage Identity) : Result Bool :=".into(),
        "  _root_.auths_algebra_kernel.root_preserved inst".into(),
        "    (auths_algebra_kernel.toRootLinkage linkage)".into(),
        String::new(),
        "/-- Reboxes the authority-local attenuation checks into the owning carrier. -/".into(),
        "def auths_algebra_kernel.generated.toAttenuationChecks".into(),
        "    (value : auths_algebra_kernel.generated.AttenuationChecks) :".into(),
        "    _root_.auths_algebra_kernel.generated.AttenuationChecks :=".into(),
    ]);
    for (index, dimension) in dimensions.iter().enumerate() {
        let open = if index == 0 { "  { " } else { "    " };
        let close = if index + 1 == dimensions.len() {
            " }"
        } else {
            ","
        };
        lines.push(format!("{open}{dimension} := value.{dimension}{close}"));
    }
    lines.extend([
        String::new(),
        "/-- Delegates the attenuation conjunction to the translated algebra kernel. -/".into(),
        "@[rust_fun \"auths_algebra_kernel::generated::attenuation_checks_accept\"]".into(),
        "def auths_algebra_kernel.generated.attenuation_checks_accept".into(),
        "    (checks : auths_algebra_kernel.generated.AttenuationChecks) : Result Bool :=".into(),
        "  _root_.auths_algebra_kernel.generated.attenuation_checks_accept".into(),
        "    (auths_algebra_kernel.generated.toAttenuationChecks checks)".into(),
        String::new(),
        "-- EXACT BRIDGE PROOFS. Each reboxed field is definitionally its source".into(),
        "-- field, and each adapter is definitionally the owning-crate function".into(),
        "-- applied to the conversion. A rebox that dropped or crossed a field".into(),
        "-- would not close by rfl.".into(),
        String::new(),
    ]);
    for field in LINKAGE_FIELDS {
        lines.extend([
            format!("theorem auths_algebra_kernel.toRootLinkage_{field} {{Identity : Type}}"),
            "    (value : auths_algebra_kernel.RootLinkage Identity) :".into(),
            format!(
                "    (auths_algebra_kernel.toRootLinkage value).{field} = value.{field} := rfl"
            ),
            String::new(),
        ]);
    }
    for dimension in dimensions {
        lines.extend([
            format!("theorem auths_algebra_kernel.generated.toAttenuationChecks_{dimension}"),
            "    (value : auths_algebra_kernel.generated.AttenuationChecks) :".into(),
            format!(
                "    (auths_algebra_kernel.generated.toAttenuationChecks value).{dimension} = value.{dimension} := rfl"
            ),
            String::new(),
        ]);
    }
    lines.extend([
        "theorem auths_algebra_kernel.root_preserved_delegates {Identity : Type}".into(),
        "    (inst : core.cmp.PartialEq Identity Identity)".into(),
        "    (linkage : auths_algebra_kernel.RootLinkage Identity) :".into(),
        "    auths_algebra_kernel.root_preserved inst linkage =".into(),
        "      _root_.auths_algebra_kernel.root_preserved inst".into(),
        "        (auths_algebra_kernel.toRootLinkage linkage) := rfl".into(),
        String::new(),
        "theorem auths_algebra_kernel.generated.attenuation_checks_accept_delegates".into(),
        "    (checks : auths_algebra_kernel.generated.AttenuationChecks) :".into(),
        "    auths_algebra_kernel.generated.attenuation_checks_accept checks =".into(),
        "      _root_.auths_algebra_kernel.generated.attenuation_checks_accept".into(),
        "        (auths_algebra_kernel.generated.toAttenuationChecks checks) := rfl".into(),
        String::new(),
        "end auths_authority".into(),
    ]);
    let mut output = lines.join("\n");
    output.push('\n');
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
    let expected_aeneas = qualification.tools.aeneas_commit.as_str();
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
            || !aeneas_version_matches(&report.aeneas_version, expected_aeneas)
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

/// Whether a reported Aeneas version names the pinned commit.
///
/// `expected_commit` is the FULL commit from the qualification manifest. The
/// check used to compare against exactly its first seven characters, so an
/// Aeneas built from precisely the pinned commit was rejected whenever git
/// abbreviated to eight -- which is what a local build of 3a8586fa does. That
/// gate tested the abbreviation's formatting rather than the commit's identity.
///
/// Any abbreviation is accepted provided it is a genuine prefix of the pinned
/// commit and at least seven characters, which is git's own lower bound for an
/// unambiguous short hash. A shorter or non-prefix string still fails, so the
/// gate keeps refusing a genuinely different Aeneas.
fn aeneas_version_matches(actual: &str, expected_commit: &str) -> bool {
    let candidate = actual.rsplit('-').next().unwrap_or(actual);
    candidate.len() >= 7
        && candidate.len() <= expected_commit.len()
        && expected_commit.starts_with(candidate)
}

fn validate_workflow_gates(root: &Path) -> Result<(), String> {
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .map_err(|error| format!("could not read hosted CI workflow: {error}"))?;
    validate_ci_workflow_gates(&ci)?;

    let release = fs::read_to_string(root.join(".github/workflows/release.yml"))
        .map_err(|error| format!("could not read release workflow: {error}"))?;
    let builder = fs::read_to_string(root.join(".github/workflows/release-builder.yml"))
        .map_err(|error| format!("could not read reusable release builder: {error}"))?;
    validate_release_workflow_gates(&release, &builder)
}

fn validate_ci_workflow_gates(ci: &str) -> Result<(), String> {
    validate_gate_source(
        "hosted CI",
        ci,
        &[
            "uses: ./.github/actions/setup-lean",
            "kani-verifier --version 0.67.0",
            "cargo xtask ci preflight",
            "cargo xtask ci authoritative",
            "cargo xtask ci formal-translation",
            "cargo xtask ci compliance",
            "target/formal/",
        ],
    )?;
    if ci
        .matches("cargo xtask formal qualify aeneas --update")
        .count()
        != 1
        || ci
            .matches("cargo xtask ci formal-post-qualification")
            .count()
            != 1
    {
        return Err(
            "hosted PR CI must reproduce/update exactly once and then run exactly one non-reproducing post-qualification gate".to_owned(),
        );
    }
    let formal_job = ci
        .split_once("\n  formal-translation-run:")
        .and_then(|(_, tail)| tail.split_once("\n  compliance-run:"))
        .map(|(job, _)| job)
        .ok_or("hosted CI omits the formal-translation-run job boundary")?;
    if !formal_job.contains("compiler-cache: \"false\"") {
        return Err(
            "hosted formal translation must disable the compiler cache and its semantic Rust environment overrides"
                .to_owned(),
        );
    }
    for job_name in [
        "authoritative-run",
        "formal-translation-run",
        "compliance-run",
        "dependencies-run",
        "secrets-run",
        "opentofu-live-run",
        "postgresql-live-run",
        "records-api-live-run",
    ] {
        let job = workflow_job_source(ci, job_name)?;
        if !job.contains("needs: [ci-plan, formal-update-gate, repository-preflight]")
            || !job.contains("needs.repository-preflight.result == 'success'")
        {
            return Err(format!(
                "hosted CI job `{job_name}` can start before the repository preflight succeeds"
            ));
        }
    }
    let compliance_job = workflow_job_source(ci, "compliance-run")?;
    if !compliance_job.contains("if: always() && hashFiles('target/compliance/**') != ''") {
        return Err(
            "hosted compliance evidence upload must skip a missing evidence directory without masking the primary failure"
                .to_owned(),
        );
    }
    Ok(())
}

fn workflow_job_source<'a>(workflow: &'a str, job_name: &str) -> Result<&'a str, String> {
    let marker = format!("\n  {job_name}:");
    let tail = workflow
        .split_once(&marker)
        .map(|(_, tail)| tail)
        .ok_or_else(|| format!("hosted CI omits the `{job_name}` job boundary"))?;
    let next_job = tail.match_indices("\n  ").find_map(|(index, _)| {
        tail[index + 3..]
            .chars()
            .next()
            .filter(|character| !character.is_whitespace())
            .map(|_| index)
    });
    Ok(next_job.map_or(tail, |index| &tail[..index]))
}

fn validate_release_workflow_gates(orchestration: &str, builder: &str) -> Result<(), String> {
    validate_gate_source(
        "release orchestration",
        orchestration,
        &["uses: ./.github/workflows/release-builder.yml"],
    )?;
    validate_gate_source(
        "reusable release builder",
        builder,
        &[
            "leanprover/lean-action@",
            "kani-verifier --version 0.67.0",
            "cargo xtask release-check",
            "cargo xtask formal qualify aeneas",
        ],
    )
}

fn validate_gate_source(label: &str, source: &str, needles: &[&str]) -> Result<(), String> {
    for needle in needles {
        if !source.contains(needle) {
            return Err(format!("{label} omits required formal gate `{needle}`"));
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
    let expected_commit = qualification.tools.aeneas_commit.as_str();
    let expected = format!("aeneas {expected_commit}");
    let actual = aeneas_version.trim();
    let actual_version = actual.strip_prefix("aeneas ").unwrap_or(actual);
    if !aeneas_version_matches(actual_version, expected_commit) {
        return Err(format!(
            "Aeneas drift: expected {expected}, found {}",
            aeneas_version.trim()
        ));
    }
    Ok(())
}

fn ensure_clean_extraction_environment(
    root: &Path,
    qualification: &Qualification,
) -> Result<(), String> {
    for (variable, _) in env::vars_os() {
        let variable = variable.to_string_lossy();
        if is_semantic_build_variable(&variable) {
            return Err(format!(
                "Aeneas qualification refuses ambient semantic build variable {variable}"
            ));
        }
    }
    validate_ambient_cargo_configuration(root)?;
    if !qualification.semantic_cfg.is_empty() || !qualification.extraction_cfg.is_empty() {
        return Err("qualification requires empty shipping and extraction semantic cfg".to_owned());
    }
    Ok(())
}

fn is_semantic_build_variable(variable: &str) -> bool {
    if variable == "CARGO_TARGET_DIR" {
        return false;
    }
    matches!(
        variable,
        "RUSTFLAGS"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "RUSTDOCFLAGS"
            | "RUSTC"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "RUSTC_BOOTSTRAP"
            | "CARGO_BUILD_TARGET"
    ) || variable.starts_with("CARGO_PROFILE_")
        || variable.starts_with("CARGO_TARGET_")
        || variable.starts_with("CARGO_BUILD_")
}

fn validate_ambient_cargo_configuration(root: &Path) -> Result<(), String> {
    let rustc = run_output("rustc", &["-vV"], Path::new("."), &[])?;
    let host = rustc
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or("rustc -vV omitted host triple")?;
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .ok_or("cannot resolve Cargo home for ambient configuration validation")?;
    let mut candidates = BTreeSet::new();
    for ancestor in root.ancestors() {
        for name in ["config.toml", "config"] {
            candidates.insert(ancestor.join(".cargo").join(name));
        }
    }
    for name in ["config.toml", "config"] {
        candidates.insert(cargo_home.join(name));
    }
    for path in candidates {
        if !path.exists() {
            continue;
        }
        let source = fs::read_to_string(&path).map_err(|error| {
            format!(
                "could not read ambient Cargo config {}: {error}",
                path.display()
            )
        })?;
        validate_ambient_cargo_config_source(&source, host).map_err(|error| {
            format!(
                "ambient Cargo config {} is semantic: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn validate_ambient_cargo_config_source(source: &str, host: &str) -> Result<(), String> {
    let config: toml::Value =
        toml::from_str(source).map_err(|error| format!("invalid Cargo config: {error}"))?;
    let table = config
        .as_table()
        .ok_or("Cargo config root is not a table")?;
    for (key, value) in table {
        match key.as_str() {
            // Aliases affect command spelling, not Cargo's build semantics.
            "alias" => {}
            // A concrete non-host target cannot affect this qualification,
            // which deliberately compiles for workspace-host. `cfg(...)`
            // selectors are rejected because they may match the host.
            "target" => {
                let targets = value
                    .as_table()
                    .ok_or("Cargo config [target] is not a table")?;
                if targets
                    .keys()
                    .any(|target| target == host || target.starts_with("cfg("))
                {
                    return Err("host-applicable [target] configuration is present".to_owned());
                }
            }
            _ => return Err(format!("unsupported ambient Cargo config section [{key}]")),
        }
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
        "auths_model::budget_ceiling_covers_action",
        "auths_model::status_policy_attenuates",
        "auths_model::critical_extensions_equal",
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
            "auths_algebra_kernel::generated::attenuation_checks_accept,auths_algebra_kernel::root_preserved,auths_algebra_kernel::RootLinkage",
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
    run_checked(
        charon,
        &charon_arguments(
            "auths_bounded_policy::kernel::configuration_match_code,auths_bounded_policy::kernel::checked_add_u64,auths_bounded_policy::kernel::checked_sub_u64,auths_bounded_policy::kernel::checked_mul_u64,auths_bounded_policy::kernel::checked_div_u64",
            &stable_llbc.join("auths_bounded_policy.llbc"),
            "product/policy/auths-bounded-policy/Cargo.toml",
            &[],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_lifecycle::kernel::transition_code,auths_lifecycle::kernel::additive_capacity_available,auths_lifecycle::kernel::exclusive_capacity_available,auths_lifecycle::kernel::replay_code",
            &stable_llbc.join("auths_lifecycle.llbc"),
            "product/runtime/auths-lifecycle/Cargo.toml",
            &[],
        ),
        root,
        &[],
    )?;

    for crate_name in [
        "auths_model",
        "auths_algebra_kernel",
        "auths_authority",
        "auths_bounded_policy",
        "auths_lifecycle",
    ] {
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
        ("auths_bounded_policy", "bounded_policy"),
        ("auths_lifecycle", "lifecycle"),
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
    for crate_name in [
        "auths_model",
        "auths_algebra_kernel",
        "auths_authority",
        "auths_bounded_policy",
        "auths_lifecycle",
    ] {
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
    for &(source, destination) in AENEAS_OUTPUT_MAPPINGS {
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

fn canonicalize_aeneas_versions(reproduced: &Path, expected_commit: &str) -> Result<(), String> {
    let expected_short = expected_commit;
    for component in [
        "model",
        "algebra",
        "authority",
        "bounded_policy",
        "lifecycle",
    ] {
        let path = reproduced
            .join(format!("{component}-run"))
            .join("translation.json");
        let mut report: Value = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?,
        )
        .map_err(|error| {
            format!(
                "invalid Aeneas translation report {}: {error}",
                path.display()
            )
        })?;
        let actual = report["aeneas_version"].as_str().ok_or_else(|| {
            format!(
                "Aeneas translation report omits aeneas_version: {}",
                path.display()
            )
        })?;
        if !aeneas_version_matches(actual, expected_short) {
            return Err(format!(
                "Aeneas translation identity drifted for {component}: expected {expected_short}, found {actual}"
            ));
        }
        report["aeneas_version"] = Value::String(expected_short.to_owned());
        write_pretty_json(&path, &report)?;
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
    let generated_artifacts_digest = generated_artifact_digest(root)?;
    let evidence = json!({
        "schema": "auths-proof-aeneas-qualification-evidence/v1",
        "decision": qualification.decision,
        "source_closure_sha256": closure_digest,
        "generated_artifacts_sha256": generated_artifacts_digest,
        "production_features": qualification.production_features,
        "semantic_cfg": qualification.semantic_cfg,
        "extraction_cfg": qualification.extraction_cfg,
        "compiled_external_axioms": 0,
        "reviewed_external_models": qualification.external_models.len(),
        "case_modules": qualification.case_modules,
        "clean_reproduction": if reproduced { "byte-identical" } else { "not-run-committed-artifacts-validated" },
        "adr": qualification.adr,
    });
    write_evidence_monotonic(&path, &evidence, reproduced)
}

fn validate_generated_artifact_inventory(paths: &[String]) -> Result<(), String> {
    let expected = GENERATED_ARTIFACTS
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<Vec<_>>();
    if paths != expected {
        return Err(format!(
            "Aeneas generated artifact inventory drifted; expected the canonical {}-artifact synchronization set",
            expected.len()
        ));
    }

    let synchronized = AENEAS_OUTPUT_MAPPINGS
        .iter()
        .map(|(_, destination)| *destination)
        .chain(REVIEWED_BRIDGE_ARTIFACTS.iter().copied())
        .collect::<BTreeSet<_>>();
    let canonical = GENERATED_ARTIFACTS.iter().copied().collect::<BTreeSet<_>>();
    if synchronized != canonical {
        return Err(
            "internal Aeneas synchronization destinations do not equal the canonical generated artifact inventory"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_exact_inventory(
    label: &str,
    actual: &[String],
    expected: &[&str],
) -> Result<(), String> {
    if actual.iter().map(String::as_str).collect::<Vec<_>>() != expected {
        return Err(format!("Aeneas {label} inventory drifted"));
    }
    Ok(())
}

fn generated_artifact_digest(root: &Path) -> Result<String, String> {
    let mut aggregate = Sha256::new();
    for relative in GENERATED_ARTIFACTS {
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("could not stat generated artifact {relative}: {error}"))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "generated artifact is not a regular non-symlink file: {relative}"
            ));
        }
        let bytes = fs::read(&path)
            .map_err(|error| format!("could not read generated artifact {relative}: {error}"))?;
        aggregate.update(relative.as_bytes());
        aggregate.update([0]);
        aggregate.update(&bytes);
        aggregate.update([0xff]);
    }
    Ok(hex::encode(aggregate.finalize()))
}

/// A cheaper committed-artifact validation must never erase stronger evidence
/// from an immediately preceding byte-identical reproduction. Preservation is
/// allowed only when every other field (especially source digest and config)
/// is identical; stale strong evidence is downgraded rather than carried over.
fn write_evidence_monotonic(
    path: &Path,
    candidate: &Value,
    reproduced: bool,
) -> Result<(), String> {
    if !reproduced && path.is_file() {
        let existing: Value = serde_json::from_slice(
            &fs::read(path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?,
        )
        .map_err(|error| format!("invalid existing evidence {}: {error}", path.display()))?;
        let mut normalized = existing.clone();
        if existing["clean_reproduction"] == "byte-identical" {
            normalized["clean_reproduction"] = candidate["clean_reproduction"].clone();
            if normalized == *candidate {
                return Ok(());
            }
        }
    }
    write_pretty_json(path, candidate)
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
    for (variable, _) in env::vars_os() {
        if is_semantic_build_variable(&variable.to_string_lossy()) {
            command.env_remove(variable);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const CI_GATES: &str = "uses: ./.github/actions/setup-lean\nkani-verifier --version 0.67.0\ncargo xtask ci preflight\ncargo xtask ci authoritative\ncargo xtask ci formal-translation\ntarget/formal/\n  authoritative-run:\nneeds: [ci-plan, formal-update-gate, repository-preflight]\nneeds.repository-preflight.result == 'success'\n  formal-translation-run:\nneeds: [ci-plan, formal-update-gate, repository-preflight]\nneeds.repository-preflight.result == 'success'\ncompiler-cache: \"false\"\ncargo xtask formal qualify aeneas --update\ncargo xtask ci formal-post-qualification\n  compliance-run:\nneeds: [ci-plan, formal-update-gate, repository-preflight]\nneeds.repository-preflight.result == 'success'\ncargo xtask ci compliance\nif: always() && hashFiles('target/compliance/**') != ''\n  dependencies-run:\nneeds: [ci-plan, formal-update-gate, repository-preflight]\nneeds.repository-preflight.result == 'success'\n  secrets-run:\nneeds: [ci-plan, formal-update-gate, repository-preflight]\nneeds.repository-preflight.result == 'success'\n  opentofu-live-run:\nneeds: [ci-plan, formal-update-gate, repository-preflight]\nneeds.repository-preflight.result == 'success'\n  postgresql-live-run:\nneeds: [ci-plan, formal-update-gate, repository-preflight]\nneeds.repository-preflight.result == 'success'\n  records-api-live-run:\nneeds: [ci-plan, formal-update-gate, repository-preflight]\nneeds.repository-preflight.result == 'success'\n";
    const BUILDER_GATES: &str = "leanprover/lean-action@\nkani-verifier --version 0.67.0\ncargo xtask release-check\ncargo xtask formal qualify aeneas\n";

    #[test]
    fn hosted_ci_uses_the_pinned_lean_setup() {
        validate_ci_workflow_gates(CI_GATES).expect("hosted CI gates must satisfy formal policy");
    }

    #[test]
    fn hosted_ci_cannot_omit_pinned_lean_setup() {
        let error = validate_ci_workflow_gates(
            &CI_GATES.replace("uses: ./.github/actions/setup-lean\n", ""),
        )
        .expect_err("missing pinned Lean setup must fail");
        assert!(error.contains("hosted CI omits required formal gate"));
    }

    #[test]
    fn every_expensive_ci_job_waits_for_repository_preflight() {
        let bypass = CI_GATES.replacen(
            "needs: [ci-plan, formal-update-gate, repository-preflight]",
            "needs: [ci-plan, formal-update-gate]",
            1,
        );
        let error = validate_ci_workflow_gates(&bypass)
            .expect_err("an implementation job must not bypass the shared preflight");
        assert!(error.contains("can start before the repository preflight succeeds"));
    }

    #[test]
    fn compliance_upload_does_not_mask_the_primary_failure() {
        let masking = CI_GATES.replace(
            "if: always() && hashFiles('target/compliance/**') != ''",
            "if: always()",
        );
        let error = validate_ci_workflow_gates(&masking)
            .expect_err("missing compliance evidence must not create a second failure");
        assert!(error.contains("without masking the primary failure"));
    }

    #[test]
    fn reusable_release_builder_owns_formal_gates() {
        validate_release_workflow_gates(
            "uses: ./.github/workflows/release-builder.yml\n",
            BUILDER_GATES,
        )
        .expect("reusable builder gates must satisfy release policy");
    }

    #[test]
    fn orchestration_must_call_the_reviewed_builder() {
        let error = validate_release_workflow_gates("workflow_dispatch:\n", BUILDER_GATES)
            .expect_err("missing reusable builder call must fail");
        assert!(error.contains("release orchestration omits required formal gate"));
    }

    #[test]
    fn reusable_builder_cannot_omit_formal_gate() {
        let error = validate_release_workflow_gates(
            "uses: ./.github/workflows/release-builder.yml\n",
            "cargo xtask release-check\n",
        )
        .expect_err("incomplete reusable builder must fail");
        assert!(error.contains("reusable release builder omits required formal gate"));
    }

    #[test]
    fn sorry_scanner_ignores_literals_and_comments_but_not_code_or_quotations() {
        let source = r#"
def x' : True := by sorry
-- sorry
/- admit -/
def text := "sorry"
def quoted ← `(tactic| sorry)
def oldQuoted := '(term| by sorry)
def character := 's'
"#;
        assert_eq!(lean_sorry_lines(source), vec![2, 6, 7]);
    }

    #[test]
    fn sorry_scanner_handles_nested_comments() {
        let source = "/- outer\n/- sorry -/\n-/\nexample : True := by admit\n";
        assert_eq!(lean_sorry_lines(source), vec![4]);
    }

    #[test]
    fn qualification_evidence_is_fail_monotonic_but_never_preserves_stale_digest() {
        let path = env::temp_dir().join(format!(
            "auths-qualification-evidence-{}.json",
            std::process::id()
        ));
        let strong = json!({
            "source_closure_sha256": "current",
            "generated_artifacts_sha256": "generated-current",
            "clean_reproduction": "byte-identical",
        });
        let weak = json!({
            "source_closure_sha256": "current",
            "generated_artifacts_sha256": "generated-current",
            "clean_reproduction": "not-run-committed-artifacts-validated",
        });
        write_evidence_monotonic(&path, &strong, true).expect("strong evidence");
        write_evidence_monotonic(&path, &weak, false).expect("later validation");
        let retained: Value = serde_json::from_slice(&fs::read(&path).expect("retained evidence"))
            .expect("valid retained evidence");
        assert_eq!(retained["clean_reproduction"], "byte-identical");

        let stale = json!({
            "source_closure_sha256": "current",
            "generated_artifacts_sha256": "generated-changed",
            "clean_reproduction": "not-run-committed-artifacts-validated",
        });
        write_evidence_monotonic(&path, &stale, false).expect("stale downgrade");
        let downgraded: Value =
            serde_json::from_slice(&fs::read(&path).expect("downgraded evidence"))
                .expect("valid downgraded evidence");
        assert_eq!(
            downgraded["clean_reproduction"],
            "not-run-committed-artifacts-validated"
        );
        assert_eq!(downgraded["source_closure_sha256"], "current");
        assert_eq!(
            downgraded["generated_artifacts_sha256"],
            "generated-changed"
        );
        fs::remove_file(path).expect("remove owned evidence fixture");
    }

    #[test]
    fn generated_artifact_inventory_rejects_omission_and_substitution() {
        let exact = GENERATED_ARTIFACTS
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<Vec<_>>();
        validate_generated_artifact_inventory(&exact).expect("canonical inventory");

        let mut omitted = exact.clone();
        omitted.pop();
        assert!(validate_generated_artifact_inventory(&omitted).is_err());

        let mut substituted = exact;
        substituted[0] = "formal/qualification/aeneas/generated/forged.lean".to_owned();
        assert!(validate_generated_artifact_inventory(&substituted).is_err());
    }

    #[test]
    fn semantic_rust_environment_and_host_cargo_config_fail_closed() {
        for variable in [
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTC_BOOTSTRAP",
            "CARGO_PROFILE_DEV_OPT_LEVEL",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS",
        ] {
            assert!(is_semantic_build_variable(variable));
        }
        assert!(!is_semantic_build_variable("CARGO_TARGET_DIR"));

        validate_ambient_cargo_config_source(
            "[alias]\nxtask = 'run -p xtask --'\n[target.aarch64-apple-ios]\nlinker = 'clang'\n",
            "aarch64-apple-darwin",
        )
        .expect("alias and foreign target are non-semantic for host extraction");
        assert!(
            validate_ambient_cargo_config_source(
                "[target.aarch64-apple-darwin]\nrustflags = ['--cfg', 'forged']\n",
                "aarch64-apple-darwin",
            )
            .is_err()
        );
        assert!(
            validate_ambient_cargo_config_source(
                "[target.'cfg(unix)']\nrustflags = ['--cfg', 'forged']\n",
                "aarch64-apple-darwin",
            )
            .is_err()
        );
        assert!(
            validate_ambient_cargo_config_source(
                "[build]\nrustflags = ['--cfg', 'forged']\n",
                "aarch64-apple-darwin",
            )
            .is_err()
        );
    }

    #[test]
    fn reviewed_translation_boundary_contract_is_exact() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has repository parent");
        let qualification = load_qualification(repository).expect("qualification manifest");
        assert_eq!(
            qualification_boundary_contract_sha256(&qualification),
            QUALIFICATION_BOUNDARY_CONTRACT_SHA256
        );
    }
}
