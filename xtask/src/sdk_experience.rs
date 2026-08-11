use crate::*;

const MATRIX_PATH: &str = "bindings/customer-journey-matrix-v1.json";
const TYPESCRIPT_API_PATH: &str = "bindings/typescript/api/public-api.txt";
const TYPESCRIPT_PACKAGE_PATH: &str = "bindings/typescript/package.json";
const TYPESCRIPT_CAPABILITY_PATH: &str = "bindings/typescript/sdk-capability.json";
const TYPESCRIPT_PERFORMANCE_PATH: &str = "bindings/typescript/performance-baseline.json";
const PYTHON_API_PATH: &str = "bindings/python/api/public-api.txt";
const PYTHON_ABI_PATH: &str = "bindings/python/native-abi-v2.json";
const PYTHON_CAPABILITY_PATH: &str = "bindings/python/sdk-capability.json";
const PYTHON_PERFORMANCE_PATH: &str = "bindings/python/performance-baseline.json";
const SEMANTIC_FREEZE_PATH: &str = "release/semantic-freeze.json";

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct JourneyMatrix {
    schema: String,
    semantic_owner: String,
    generated_corpus: String,
    experience: ExperienceContract,
    journeys: Vec<Journey>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExperienceContract {
    schema: String,
    enforcement: String,
    baseline: ExperienceBaseline,
    target_budgets: Value,
    moderated_recipe_three_cohort: Value,
    maintained_recipes: Vec<MaintainedRecipe>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExperienceBaseline {
    typescript_entry_points: usize,
    typescript_public_symbols: usize,
    python_modules: usize,
    python_public_symbols: usize,
    maintained_typescript_recipes: usize,
    maintained_python_recipes: usize,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct MaintainedRecipe {
    id: String,
    language: String,
    path: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Journey {
    id: String,
    rust: String,
    typescript: String,
    python: String,
    experience: JourneyExperience,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct JourneyExperience {
    target_journey: String,
    imports: Vec<String>,
    security_nouns: Vec<String>,
    domain_concepts: Vec<String>,
    setup_decisions: Vec<String>,
    api_mechanics: Vec<String>,
    required_application_components: Vec<String>,
    executable_statements: usize,
    application_orchestrated_security_transitions: usize,
    terminal_outcomes: Vec<String>,
    consumer_requires_rust: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicSurface {
    entry_points: usize,
    public_symbols: usize,
    symbols_by_entry_point: BTreeMap<String, usize>,
    ownership_by_entry_point: BTreeMap<String, String>,
}

pub(crate) fn sdk_experience(update: bool) -> Result<(), String> {
    let matrix_path = root().join(MATRIX_PATH);
    let mut matrix: JourneyMatrix = read_json(&matrix_path)?;
    validate_matrix(&matrix)?;

    let typescript = typescript_surface()?;
    let python = python_surface()?;
    let current = ExperienceBaseline {
        typescript_entry_points: typescript.entry_points,
        typescript_public_symbols: typescript.public_symbols,
        python_modules: python.entry_points,
        python_public_symbols: python.public_symbols,
        maintained_typescript_recipes: matrix
            .experience
            .maintained_recipes
            .iter()
            .filter(|recipe| recipe.language == "typescript")
            .count(),
        maintained_python_recipes: matrix
            .experience
            .maintained_recipes
            .iter()
            .filter(|recipe| recipe.language == "python")
            .count(),
    };

    if update {
        matrix.experience.baseline = current;
        let encoded = serde_json::to_string_pretty(&matrix)
            .map_err(|error| format!("could not encode {MATRIX_PATH}: {error}"))?;
        fs::write(&matrix_path, format!("{encoded}\n"))
            .map_err(|error| format!("could not update {MATRIX_PATH}: {error}"))?;
        println!("updated the existing SDK experience baseline in {MATRIX_PATH}");
        return Ok(());
    }

    if current != matrix.experience.baseline {
        return Err(format!(
            "SDK experience baseline drifted; review the public surfaces and run `cargo xtask sdk-experience --update`\nexpected: {:?}\nactual: {current:?}",
            matrix.experience.baseline
        ));
    }

    let journey_projection = project_journeys(&matrix.journeys)?;
    let typescript_capability: Value = read_json(&root().join(TYPESCRIPT_CAPABILITY_PATH))?;
    let python_capability: Value = read_json(&root().join(PYTHON_CAPABILITY_PATH))?;
    let typescript_performance: Value = read_json(&root().join(TYPESCRIPT_PERFORMANCE_PATH))?;
    let python_performance: Value = read_json(&root().join(PYTHON_PERFORMANCE_PATH))?;
    let typescript_package: Value = read_json(&root().join(TYPESCRIPT_PACKAGE_PATH))?;
    let python_abi: Value = read_json(&root().join(PYTHON_ABI_PATH))?;
    let semantic_freeze: Value = read_json(&root().join(SEMANTIC_FREEZE_PATH))?;

    let report = json!({
        "schema": "auths.sdk-experience-summary/1",
        "contract": matrix.experience.schema,
        "enforcement": matrix.experience.enforcement,
        "authoritativeInputs": [
            MATRIX_PATH,
            TYPESCRIPT_API_PATH,
            TYPESCRIPT_PACKAGE_PATH,
            TYPESCRIPT_CAPABILITY_PATH,
            TYPESCRIPT_PERFORMANCE_PATH,
            PYTHON_API_PATH,
            PYTHON_ABI_PATH,
            PYTHON_CAPABILITY_PATH,
            PYTHON_PERFORMANCE_PATH,
            SEMANTIC_FREEZE_PATH,
        ],
        "publicApi": {
            "typescript": typescript,
            "python": python,
        },
        "installedArtifacts": {
            "typescriptExportCount": typescript_package["exports"].as_object().map_or(0, serde_json::Map::len),
            "typescriptDistBytes": typescript_performance["measurements"]["distBytes"],
            "typescriptWasmBytes": typescript_performance["measurements"]["wasmBytes"],
            "pythonWheelBytes": python_performance["measurements"]["wheelBytes"],
            "pythonAbiSchema": python_abi["schema"],
        },
        "capability": {
            "typescript": capability_projection(&typescript_capability),
            "python": capability_projection(&python_capability),
        },
        "performance": {
            "typescript": typescript_performance,
            "python": python_performance,
        },
        "journeys": journey_projection,
        "recipes": matrix.experience.maintained_recipes,
        "moderatedRecipeThreeCohort": matrix.experience.moderated_recipe_three_cohort,
        "budgets": matrix.experience.target_budgets,
        "semanticFreezeSchema": semantic_freeze["schema"],
    });
    let encoded = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("could not encode SDK experience summary: {error}"))?;
    println!("{encoded}");
    write_github_summary(&report)?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("could not parse {}: {error}", path.display()))
}

fn typescript_surface() -> Result<PublicSurface, String> {
    let source = fs::read_to_string(root().join(TYPESCRIPT_API_PATH))
        .map_err(|error| format!("could not read {TYPESCRIPT_API_PATH}: {error}"))?;
    let mut symbols = BTreeMap::new();
    for line in source
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
    {
        let entry_point = line
            .split('\t')
            .next()
            .ok_or_else(|| format!("invalid TypeScript public API line: {line}"))?;
        *symbols.entry(entry_point.to_owned()).or_insert(0) += 1;
    }
    let ownership_by_entry_point = symbols
        .keys()
        .map(|entry| (entry.clone(), classify_typescript_entry(entry).to_owned()))
        .collect();
    Ok(PublicSurface {
        entry_points: symbols.len(),
        public_symbols: symbols.values().sum(),
        symbols_by_entry_point: symbols,
        ownership_by_entry_point,
    })
}

fn python_surface() -> Result<PublicSurface, String> {
    let source = fs::read_to_string(root().join(PYTHON_API_PATH))
        .map_err(|error| format!("could not read {PYTHON_API_PATH}: {error}"))?;
    let mut symbols = BTreeMap::new();
    let mut module: Option<String> = None;
    for line in source.lines() {
        if let Some(value) = line
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            module = Some(value.to_owned());
            symbols.entry(value.to_owned()).or_insert(0);
        } else if !line.is_empty() {
            let current = module
                .as_ref()
                .ok_or_else(|| format!("Python public API symbol has no module: {line}"))?;
            *symbols.entry(current.clone()).or_insert(0) += 1;
        }
    }
    let ownership_by_entry_point = symbols
        .keys()
        .map(|entry| (entry.clone(), classify_python_module(entry).to_owned()))
        .collect();
    Ok(PublicSurface {
        entry_points: symbols.len(),
        public_symbols: symbols.values().sum(),
        symbols_by_entry_point: symbols,
        ownership_by_entry_point,
    })
}

pub(crate) fn classify_typescript_entry(entry: &str) -> &'static str {
    match entry {
        "." => "product",
        "./identity" | "./verify" | "./inspection" | "./diagnostics" | "./observability" => {
            "component"
        }
        "./mcp" | "./profiles" => "profile",
        "./testkit" => "testkit",
        "./profile-kit" => "framework",
        "./approvals" | "./authority" | "./custody" | "./lifecycle" | "./runtime" | "./trust" => {
            "internal-leak"
        }
        _ => "internal-leak",
    }
}

pub(crate) fn classify_python_module(module: &str) -> &'static str {
    match module {
        "auths" => "product",
        "auths.identity"
        | "auths.verify"
        | "auths.inspection"
        | "auths.diagnostics"
        | "auths.observability"
        | "auths.errors" => "component",
        value if value.starts_with("auths.profiles.") => "profile",
        "auths.testkit" => "testkit",
        "auths.profile_kit" => "framework",
        "auths.integrations" => "integration",
        _ => "internal-leak",
    }
}

fn validate_matrix(matrix: &JourneyMatrix) -> Result<(), String> {
    if matrix.schema != "auths.customer-journey-matrix/1"
        || matrix.experience.schema != "auths.sdk-experience-metadata/1"
        || matrix.semantic_owner != "Rust"
    {
        return Err("customer journey matrix has an unsupported experience contract".to_owned());
    }
    if matrix.journeys.len() < 8 {
        return Err("customer journey matrix must cover at least eight journeys".to_owned());
    }
    let mut ids = BTreeSet::new();
    for journey in &matrix.journeys {
        if !ids.insert(&journey.id) {
            return Err(format!("duplicate customer journey {}", journey.id));
        }
    }
    Ok(())
}

fn project_journeys(journeys: &[Journey]) -> Result<Vec<Value>, String> {
    journeys
        .iter()
        .map(|journey| {
            let evidence = [&journey.rust, &journey.typescript, &journey.python];
            let missing: Vec<_> = evidence
                .iter()
                .filter(|path| !root().join(path).exists())
                .copied()
                .collect();
            Ok(json!({
                "id": journey.id,
                "targetJourney": journey.experience.target_journey,
                "imports": journey.experience.imports,
                "concepts": {
                    "security": journey.experience.security_nouns,
                    "domain": journey.experience.domain_concepts,
                    "setup": journey.experience.setup_decisions,
                    "mechanics": journey.experience.api_mechanics,
                },
                "requiredApplicationComponents": journey.experience.required_application_components,
                "executableStatements": journey.experience.executable_statements,
                "applicationOrchestratedSecurityTransitions": journey.experience.application_orchestrated_security_transitions,
                "terminalOutcomes": journey.experience.terminal_outcomes,
                "availability": { "typescript": true, "python": true },
                "consumerRequiresRust": journey.experience.consumer_requires_rust,
                "executable": missing.is_empty(),
                "missingEvidence": missing,
                "evidence": { "rust": journey.rust, "typescript": journey.typescript, "python": journey.python },
            }))
        })
        .collect()
}

fn capability_projection(capability: &Value) -> Value {
    json!({
        "schema": capability["schema"],
        "package": capability["package"],
        "language": capability["language"],
        "implementationTier": capability["implementationTier"],
        "evidenceStatus": capability["evidenceStatus"],
        "publicationStatus": capability["publicationStatus"],
    })
}

fn write_github_summary(report: &Value) -> Result<(), String> {
    let Some(path) = env::var_os("GITHUB_STEP_SUMMARY") else {
        return Ok(());
    };
    let typescript = &report["publicApi"]["typescript"];
    let python = &report["publicApi"]["python"];
    let journeys = report["journeys"]
        .as_array()
        .ok_or("SDK experience report has no journeys")?;
    let executable = journeys
        .iter()
        .filter(|journey| journey["executable"] == true)
        .count();
    let summary = format!(
        "## SDK experience\n\n| Surface | Entry points/modules | Symbols |\n| --- | ---: | ---: |\n| TypeScript | {} | {} |\n| Python | {} | {} |\n\nExecutable parity journeys: {executable}/{}\n",
        typescript["entryPoints"],
        typescript["publicSymbols"],
        python["entryPoints"],
        python["publicSymbols"],
        journeys.len(),
    );
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("could not open GitHub step summary: {error}"))?;
    file.write_all(summary.as_bytes())
        .map_err(|error| format!("could not write GitHub step summary: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_classification_is_explicit() {
        assert_eq!(classify_typescript_entry("."), "product");
        assert_eq!(classify_typescript_entry("./mcp"), "profile");
        assert_eq!(classify_typescript_entry("./authority"), "internal-leak");
        assert_eq!(classify_python_module("auths.integrations"), "integration");
        assert_eq!(classify_python_module("auths.authority"), "internal-leak");
    }
}
