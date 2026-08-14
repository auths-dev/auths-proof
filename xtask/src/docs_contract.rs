use crate::*;

const SNAPSHOT_PATH: &str = "release/auths-docs-contract-v1.json";
const DIGEST_DOMAIN: &[u8] = b"AUTHS-DOCS-CONTRACT\0\x01";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationsFile {
    schema: String,
    operation: Vec<Operation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    id: String,
    verb: Verb,
    summary: String,
    status: Status,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Verb {
    Create,
    Delegate,
    Execute,
    Resume,
    Verify,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Status {
    Experimental,
    Stable,
    Qualified,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PagesFile {
    schema: String,
    page: Vec<Page>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Page {
    id: String,
    path: String,
    kind: PageKind,
    title: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    operations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scenarios: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PageKind {
    Landing,
    Guide,
    SdkReference,
    RuntimeApiReference,
    Architecture,
    Operations,
    Integration,
    Assurance,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenariosFile {
    schema: String,
    scenario: Vec<Scenario>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    id: String,
    summary: String,
    languages: Vec<Language>,
}

#[derive(Debug, Clone, Copy, Deserialize, Ord, PartialOrd, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Language {
    Rust,
    Typescript,
    Python,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionsFile {
    schema: String,
    language: Language,
    projection: Vec<ProjectionInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionInput {
    operation: String,
    package: String,
    entrypoint: String,
    symbol: Option<String>,
    support: Support,
    reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Support {
    Supported,
    NotSupported,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Projection {
    operation: String,
    language: Language,
    package: String,
    entrypoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    support: Support,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContractPayload {
    schema: &'static str,
    version: u8,
    source_commit: Option<String>,
    semantic_freeze_sha256: String,
    operations: Vec<Operation>,
    pages: Vec<Page>,
    scenarios: Vec<Scenario>,
    projections: Vec<Projection>,
    runtime_facts: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Contract<'a> {
    #[serde(flatten)]
    payload: &'a ContractPayload,
    digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicTopology {
    layers: Vec<TopologyLayer>,
}

#[derive(Debug, Deserialize)]
struct TopologyLayer {
    typescript: Vec<String>,
    python: Vec<String>,
}

pub(crate) fn docs_contract(arguments: Vec<String>) -> Result<(), String> {
    let mut update = false;
    let mut artifact_dir = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--update" => update = true,
            "--artifact-dir" => {
                let value = arguments.next().ok_or("--artifact-dir requires a path")?;
                artifact_dir = Some(PathBuf::from(value));
            }
            _ => return Err(format!("unknown docs-contract argument {argument}")),
        }
    }
    if let Some(path) = artifact_dir {
        if !path.is_dir() {
            return Err(format!(
                "docs artifact directory does not exist: {}",
                path.display()
            ));
        }
    }

    let bytes = build_contract()?;
    let snapshot = root().join(SNAPSHOT_PATH);
    if update {
        fs::write(&snapshot, bytes)
            .map_err(|error| format!("could not write {}: {error}", snapshot.display()))?;
        println!("updated {SNAPSHOT_PATH}");
        return Ok(());
    }
    let current =
        fs::read(&snapshot).map_err(|error| format!("could not read {SNAPSHOT_PATH}: {error}"))?;
    if current != bytes {
        return Err(
            "documentation contract drifted; run `cargo xtask docs-contract --update`".to_owned(),
        );
    }
    println!("documentation surface contract passed");
    Ok(())
}

fn build_contract() -> Result<Vec<u8>, String> {
    let mut operations: OperationsFile = read_toml("release/docs/operations.toml")?;
    let mut pages: PagesFile = read_toml("release/docs/pages.toml")?;
    let mut scenarios: ScenariosFile = read_toml("release/docs/scenarios.toml")?;
    require_schema(&operations.schema, "auths.docs.operations/1")?;
    require_schema(&pages.schema, "auths.docs.pages/1")?;
    require_schema(&scenarios.schema, "auths.docs.scenarios/1")?;

    operations
        .operation
        .sort_by(|left, right| left.id.cmp(&right.id));
    pages.page.sort_by(|left, right| left.id.cmp(&right.id));
    scenarios
        .scenario
        .sort_by(|left, right| left.id.cmp(&right.id));
    validate_unique(
        "operation",
        operations.operation.iter().map(|item| &item.id),
    )?;
    validate_unique("page", pages.page.iter().map(|item| &item.id))?;
    validate_unique("scenario", scenarios.scenario.iter().map(|item| &item.id))?;

    let operation_ids: BTreeSet<String> = operations
        .operation
        .iter()
        .map(|item| item.id.clone())
        .collect();
    let scenario_ids: BTreeSet<String> = scenarios
        .scenario
        .iter()
        .map(|item| item.id.clone())
        .collect();
    for id in operation_ids.iter().chain(scenario_ids.iter()) {
        validate_identity(id)?;
    }
    for page in &mut pages.page {
        validate_identity(&page.id)?;
        if !page.path.starts_with('/') || page.path.contains("//") {
            return Err(format!("page {} has an invalid path", page.id));
        }
        page.operations.sort();
        page.scenarios.sort();
        for operation in &page.operations {
            if !operation_ids.contains(operation.as_str()) {
                return Err(format!(
                    "page {} names unknown operation {operation}",
                    page.id
                ));
            }
        }
        for scenario in &page.scenarios {
            if !scenario_ids.contains(scenario.as_str()) {
                return Err(format!(
                    "page {} names unknown scenario {scenario}",
                    page.id
                ));
            }
        }
    }
    for scenario in &mut scenarios.scenario {
        scenario.languages.sort();
        scenario.languages.dedup();
        if scenario.languages.is_empty() {
            return Err(format!(
                "scenario {} has no maintained language",
                scenario.id
            ));
        }
    }

    let topology: PublicTopology = read_json("bindings/public-topology-v1.json")?;
    let topology_typescript: BTreeSet<_> = topology
        .layers
        .iter()
        .flat_map(|layer| layer.typescript.iter().cloned())
        .collect();
    let topology_python: BTreeSet<_> = topology
        .layers
        .iter()
        .flat_map(|layer| layer.python.iter().cloned())
        .collect();
    let typescript_api = typescript_api()?;
    let python_api = python_api()?;
    let semantic_freeze = fs::read_to_string(root().join("release/semantic-freeze.json"))
        .map_err(|error| format!("could not read semantic freeze: {error}"))?;

    let mut projections = Vec::new();
    for path in [
        "release/docs/projections-rust.toml",
        "release/docs/projections-typescript.toml",
        "release/docs/projections-python.toml",
    ] {
        let file: ProjectionsFile = read_toml(path)?;
        require_schema(&file.schema, "auths.docs.projections/1")?;
        for input in file.projection {
            if !operation_ids.contains(input.operation.as_str()) {
                return Err(format!(
                    "projection names unknown operation {}",
                    input.operation
                ));
            }
            validate_projection(
                file.language,
                &input,
                &topology_typescript,
                &topology_python,
                &typescript_api,
                &python_api,
                &semantic_freeze,
            )?;
            projections.push(Projection {
                operation: input.operation,
                language: file.language,
                package: input.package,
                entrypoint: input.entrypoint,
                symbol: input.symbol,
                support: input.support,
                reason: input.reason,
            });
        }
    }
    projections.sort_by(|left, right| {
        (
            &left.operation,
            left.language,
            &left.package,
            &left.entrypoint,
        )
            .cmp(&(
                &right.operation,
                right.language,
                &right.package,
                &right.entrypoint,
            ))
    });
    let mut projection_keys = BTreeSet::new();
    for projection in &projections {
        let key = (
            projection.operation.as_str(),
            projection.language,
            projection.package.as_str(),
            projection.entrypoint.as_str(),
        );
        if !projection_keys.insert(key) {
            return Err(format!("duplicate projection for {}", projection.operation));
        }
    }
    for operation in &operation_ids {
        for language in [Language::Rust, Language::Typescript, Language::Python] {
            if !projections.iter().any(|projection| {
                projection.operation == *operation && projection.language == language
            }) {
                return Err(format!(
                    "operation {operation} has no {language:?} projection"
                ));
            }
        }
    }

    let semantic_freeze_bytes = fs::read(root().join("release/semantic-freeze.json"))
        .map_err(|error| format!("could not read semantic freeze: {error}"))?;
    let payload = ContractPayload {
        schema: "auths.docs.contract/1",
        version: 1,
        source_commit: None,
        semantic_freeze_sha256: format!("{:x}", Sha256::digest(&semantic_freeze_bytes)),
        operations: operations.operation,
        pages: pages.page,
        scenarios: scenarios.scenario,
        projections,
        runtime_facts: runtime_facts(&operation_ids, &scenario_ids)?,
    };
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|error| format!("could not encode documentation contract: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(payload_bytes);
    let contract = Contract {
        payload: &payload,
        digest: format!("{:x}", hasher.finalize()),
    };
    let mut bytes = serde_json::to_vec_pretty(&contract)
        .map_err(|error| format!("could not encode documentation contract: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn runtime_facts(
    operation_ids: &BTreeSet<String>,
    scenario_ids: &BTreeSet<String>,
) -> Result<Value, String> {
    let facts: Value = read_json("release/docs/runtime-facts-v1.json")?;
    if facts["schema"] != "auths.runtime-docs-facts/1" {
        return Err("unsupported runtime documentation facts".to_owned());
    }
    let endpoints = facts["endpoints"]
        .as_array()
        .ok_or("runtime documentation facts have no endpoints")?;
    let mut identities = BTreeSet::new();
    let mut routes = BTreeSet::new();
    for endpoint in endpoints {
        let id = endpoint["id"]
            .as_str()
            .ok_or("runtime endpoint has no identity")?;
        validate_identity(id)?;
        if !identities.insert(id) {
            return Err(format!("duplicate runtime endpoint identity {id}"));
        }
        let method = endpoint["method"]
            .as_str()
            .ok_or("runtime endpoint has no method")?;
        let path = endpoint["path"]
            .as_str()
            .ok_or("runtime endpoint has no path")?;
        if !routes.insert((method, path)) {
            return Err(format!("duplicate runtime endpoint route {method} {path}"));
        }
        if let Some(operation) = endpoint["operation"].as_str() {
            if !operation_ids.contains(operation) {
                return Err(format!(
                    "runtime endpoint {id} has unknown operation {operation}"
                ));
            }
        }
        if let Some(scenario) = endpoint["scenario"].as_str() {
            if !scenario_ids.contains(scenario) {
                return Err(format!(
                    "runtime endpoint {id} has unknown scenario {scenario}"
                ));
            }
        }
        if matches!(
            endpoint["class"].as_str(),
            Some("profile-execution" | "workflow-recovery")
        ) && endpoint["scenario"].is_null()
        {
            return Err(format!("effectful runtime endpoint {id} has no scenario"));
        }
    }
    Ok(facts)
}

fn validate_projection(
    language: Language,
    projection: &ProjectionInput,
    topology_typescript: &BTreeSet<String>,
    topology_python: &BTreeSet<String>,
    typescript_api: &BTreeMap<String, BTreeSet<String>>,
    python_api: &BTreeMap<String, BTreeSet<String>>,
    semantic_freeze: &str,
) -> Result<(), String> {
    match (&projection.support, &projection.symbol, &projection.reason) {
        (Support::Supported, Some(_), None) | (Support::NotSupported, None, Some(_)) => {}
        _ => {
            return Err(format!(
                "projection {} has an invalid support shape",
                projection.operation
            ));
        }
    }
    let Some(symbol) = projection.symbol.as_deref() else {
        return Ok(());
    };
    let public_name = symbol.split(['.', ':']).next().unwrap_or(symbol);
    match language {
        Language::Rust => {
            if !semantic_freeze.contains(&format!("\"{}\"", projection.package)) {
                return Err(format!(
                    "unknown public Rust package {}",
                    projection.package
                ));
            }
        }
        Language::Typescript => {
            let topology_name = if projection.entrypoint == "." {
                projection.package.clone()
            } else {
                format!(
                    "{}{}",
                    projection.package,
                    projection.entrypoint.trim_start_matches('.')
                )
            };
            if !topology_typescript.contains(&topology_name) {
                return Err(format!("unknown TypeScript entrypoint {topology_name}"));
            }
            if !typescript_api
                .get(&projection.entrypoint)
                .is_some_and(|symbols| symbols.contains(public_name))
            {
                return Err(format!(
                    "TypeScript symbol {public_name} is not public at {}",
                    projection.entrypoint
                ));
            }
        }
        Language::Python => {
            if !topology_python.contains(&projection.entrypoint) {
                return Err(format!(
                    "unknown Python entrypoint {}",
                    projection.entrypoint
                ));
            }
            if !python_api
                .get(&projection.entrypoint)
                .is_some_and(|symbols| symbols.contains(public_name))
            {
                return Err(format!(
                    "Python symbol {public_name} is not public at {}",
                    projection.entrypoint
                ));
            }
        }
    }
    Ok(())
}

fn validate_identity(id: &str) -> Result<(), String> {
    let valid = id.len() <= 128
        && id.rsplit_once('/').is_some_and(|(name, version)| {
            !name.is_empty()
                && version.parse::<u16>().is_ok_and(|value| value > 0)
                && name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'-')
                })
        });
    if valid {
        Ok(())
    } else {
        Err(format!("invalid documentation identity {id}"))
    }
}

fn validate_unique<'a>(kind: &str, values: impl Iterator<Item = &'a String>) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(format!("duplicate {kind} identity {value}"));
        }
    }
    Ok(())
}

fn require_schema(actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("unsupported documentation schema {actual}"))
    }
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    let source = fs::read_to_string(root().join(path))
        .map_err(|error| format!("could not read {path}: {error}"))?;
    toml::from_str(&source).map_err(|error| format!("could not parse {path}: {error}"))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    serde_json::from_slice(
        &fs::read(root().join(path)).map_err(|error| format!("could not read {path}: {error}"))?,
    )
    .map_err(|error| format!("could not parse {path}: {error}"))
}

fn typescript_api() -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let source = fs::read_to_string(root().join("bindings/typescript/api/public-api.txt"))
        .map_err(|error| format!("could not read TypeScript public API: {error}"))?;
    let mut api: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in source
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 3 {
            return Err(format!("invalid TypeScript public API line: {line}"));
        }
        api.entry(fields[0].to_owned())
            .or_default()
            .insert(fields[1].to_owned());
    }
    Ok(api)
}

fn python_api() -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let source = fs::read_to_string(root().join("bindings/python/api/public-api.txt"))
        .map_err(|error| format!("could not read Python public API: {error}"))?;
    let mut module = None;
    let mut api: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in source.lines() {
        if let Some(value) = line
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            module = Some(value.to_owned());
        } else if !line.is_empty() {
            let module = module
                .as_ref()
                .ok_or("Python public API symbol has no module")?;
            api.entry(module.clone())
                .or_default()
                .insert(line.to_owned());
        }
    }
    Ok(api)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documentation_identities_are_bounded_and_versioned() {
        assert!(validate_identity("auths.operation.verify/1").is_ok());
        assert!(validate_identity("Auths.operation.verify/1").is_err());
        assert!(validate_identity("auths.operation.verify/0").is_err());
    }

    #[test]
    fn contract_generation_is_deterministic() {
        assert_eq!(build_contract().unwrap(), build_contract().unwrap());
    }
}
