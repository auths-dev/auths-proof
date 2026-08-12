use crate::*;

const GLOSSARY_PATH: &str = "docs/product/sdk-glossary.json";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VocabularyContract {
    schema: String,
    enforcement: String,
    security_nouns: BTreeMap<String, String>,
    operations: BTreeMap<String, String>,
    owner_concepts: BTreeMap<String, String>,
    equivalent_names: Vec<EquivalentName>,
    same_meaning_candidates: Vec<Vec<String>>,
    beginner_documents: Vec<String>,
    forbidden_beginner_terms: Vec<String>,
    misuse_rules: Vec<MisuseRule>,
}

#[derive(Debug, Deserialize, Serialize)]
struct EquivalentName {
    concept: String,
    typescript: String,
    python: String,
}

#[derive(Debug, Deserialize)]
struct MisuseRule {
    pattern: String,
    reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportProjection {
    language: &'static str,
    entry_point: String,
    symbol: String,
    owner: String,
    concept: String,
}

pub(crate) fn sdk_vocabulary() -> Result<(), String> {
    let contract: VocabularyContract = serde_json::from_slice(
        &fs::read(root().join(GLOSSARY_PATH))
            .map_err(|error| format!("could not read {GLOSSARY_PATH}: {error}"))?,
    )
    .map_err(|error| format!("could not parse {GLOSSARY_PATH}: {error}"))?;
    validate_contract(&contract)?;
    lint_beginner_documents(&contract)?;

    let mut exports = project_typescript_exports(&contract)?;
    exports.extend(project_python_exports(&contract)?);
    let mut meanings: BTreeMap<&str, BTreeSet<(&str, &str)>> = BTreeMap::new();
    for item in &exports {
        meanings
            .entry(&item.symbol)
            .or_default()
            .insert((&item.owner, &item.concept));
    }
    let collisions: Vec<_> = meanings
        .into_iter()
        .filter(|(_, values)| values.len() > 1)
        .map(|(symbol, values)| {
            json!({
                "symbol": symbol,
                "meanings": values.into_iter().map(|(owner, concept)| json!({
                    "owner": owner,
                    "concept": concept,
                })).collect::<Vec<_>>()
            })
        })
        .collect();
    let typescript_names: BTreeSet<_> = exports
        .iter()
        .filter(|item| item.language == "typescript")
        .map(|item| item.symbol.as_str())
        .collect();
    let python_names: BTreeSet<_> = exports
        .iter()
        .filter(|item| item.language == "python")
        .map(|item| item.symbol.as_str())
        .collect();
    let equivalence = contract
        .equivalent_names
        .iter()
        .map(|name| {
            json!({
                "concept": name.concept,
                "typescript": name.typescript,
                "typescriptPresent": typescript_names.contains(name.typescript.as_str()),
                "python": name.python,
                "pythonPresent": python_names.contains(name.python.as_str()),
            })
        })
        .collect::<Vec<_>>();
    if contract.enforcement == "final"
        && equivalence
            .iter()
            .any(|item| item["typescriptPresent"] != true || item["pythonPresent"] != true)
    {
        return Err("final SDK vocabulary operations are not present in both SDKs".to_owned());
    }
    let report = json!({
        "schema": "auths.sdk-vocabulary-report/1",
        "contract": contract.schema,
        "enforcement": contract.enforcement,
        "securityNouns": contract.security_nouns.keys().collect::<Vec<_>>(),
        "operations": contract.operations.keys().collect::<Vec<_>>(),
        "exports": exports,
        "sameNameDifferentMeaning": collisions,
        "sameMeaningCandidates": contract.same_meaning_candidates,
        "crossLanguageOperations": equivalence,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("could not encode SDK vocabulary report: {error}"))?
    );
    Ok(())
}

fn validate_contract(contract: &VocabularyContract) -> Result<(), String> {
    if contract.schema != "auths.sdk-vocabulary/1"
        || !matches!(contract.enforcement.as_str(), "prototype" | "final")
    {
        return Err("unsupported SDK vocabulary contract".to_owned());
    }
    let expected = ["Action", "Approval", "Authority", "Identity", "Receipt"];
    if contract
        .security_nouns
        .keys()
        .map(String::as_str)
        .ne(expected)
    {
        return Err("SDK vocabulary must define exactly the five security nouns".to_owned());
    }
    for owner in [
        "product",
        "component",
        "profile",
        "integration",
        "framework",
        "testkit",
        "internal-leak",
    ] {
        if !contract.owner_concepts.contains_key(owner) {
            return Err(format!("SDK vocabulary omitted owner {owner}"));
        }
    }
    Ok(())
}

fn lint_beginner_documents(contract: &VocabularyContract) -> Result<(), String> {
    for relative in &contract.beginner_documents {
        let source = fs::read_to_string(root().join(relative))
            .map_err(|error| format!("could not read beginner document {relative}: {error}"))?;
        let beginner = source
            .split("<!-- auths-beginner-end -->")
            .next()
            .unwrap_or(&source)
            .to_lowercase();
        for term in &contract.forbidden_beginner_terms {
            if beginner.contains(&term.to_lowercase()) {
                return Err(format!(
                    "beginner document {relative} uses unexplained internal term {term:?}"
                ));
            }
        }
        for rule in &contract.misuse_rules {
            if beginner.contains(&rule.pattern.to_lowercase()) {
                return Err(format!(
                    "beginner document {relative} violates vocabulary rule: {}",
                    rule.reason
                ));
            }
        }
    }
    Ok(())
}

fn project_typescript_exports(
    contract: &VocabularyContract,
) -> Result<Vec<ExportProjection>, String> {
    let source = fs::read_to_string(root().join("bindings/typescript/api/public-api.txt"))
        .map_err(|error| format!("could not read TypeScript public API: {error}"))?;
    source
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 3 {
                return Err(format!("invalid TypeScript public API line: {line}"));
            }
            let owner = classify_typescript_entry(fields[0]);
            Ok(ExportProjection {
                language: "typescript",
                entry_point: fields[0].to_owned(),
                symbol: fields[1].to_owned(),
                owner: owner.to_owned(),
                concept: owner_concept(contract, owner)?.to_owned(),
            })
        })
        .collect()
}

fn project_python_exports(contract: &VocabularyContract) -> Result<Vec<ExportProjection>, String> {
    let source = fs::read_to_string(root().join("bindings/python/api/public-api.txt"))
        .map_err(|error| format!("could not read Python public API: {error}"))?;
    let mut module: Option<&str> = None;
    let mut exports = Vec::new();
    for line in source.lines() {
        if let Some(value) = line
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            module = Some(value);
        } else if !line.is_empty() {
            let entry_point = module.ok_or("Python public API symbol has no module")?;
            let owner = classify_python_module(entry_point);
            exports.push(ExportProjection {
                language: "python",
                entry_point: entry_point.to_owned(),
                symbol: line.to_owned(),
                owner: owner.to_owned(),
                concept: owner_concept(contract, owner)?.to_owned(),
            });
        }
    }
    Ok(exports)
}

fn owner_concept<'a>(contract: &'a VocabularyContract, owner: &str) -> Result<&'a str, String> {
    contract
        .owner_concepts
        .get(owner)
        .map(String::as_str)
        .ok_or_else(|| format!("SDK vocabulary has no concept for owner {owner}"))
}
