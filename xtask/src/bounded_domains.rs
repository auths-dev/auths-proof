use crate::*;

const REQUIRED_DOMAIN_IDS: [&str; 7] = [
    "github",
    "kubernetes",
    "opentofu",
    "postgresql",
    "radicle",
    "records-api",
    "stripe",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundedDomainInventory {
    schema: u32,
    inventory: InventoryMetadata,
    boundary: BoundaryRules,
    domains: Vec<DomainRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryMetadata {
    id: String,
    plan: String,
    audit: String,
    semantic_report: String,
    closed_contract_spec: String,
    required_domains: Vec<String>,
    required_scenarios: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryRules {
    core_must_remain_provider_neutral: bool,
    shared_product_must_not_import_provider_sdks: bool,
    domain_actions_remain_domain_owned: bool,
    domain_evidence_remains_domain_owned: bool,
    verified_commands_remain_domain_owned: bool,
    provider_gateways_remain_domain_owned: bool,
    credential_scopes_remain_domain_owned: bool,
    reconciliation_meaning_remains_domain_owned: bool,
    receipt_payloads_remain_domain_owned: bool,
    demos_remain_compatibility_consumers: bool,
    one_production_path_after_migration: bool,
    reference_evaluators_remain_test_oracles: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainRecord {
    id: String,
    migration_order: u8,
    package: String,
    package_path: String,
    consumer_package: String,
    consumer_path: String,
    spec: String,
    status: String,
    profiles: Vec<String>,
    evaluator_entrypoint: String,
    action_type: String,
    policy_type: String,
    evidence_type: String,
    configuration_type: String,
    decision_type: String,
    reservation_type: String,
    verified_command: String,
    provider_gateway: String,
    credential_scope: String,
    reconciliation: String,
    receipt_types: Vec<String>,
    fixture_dir: String,
    scenarios: Vec<String>,
    not_applicable: BTreeMap<String, String>,
    scenario_evidence: BTreeMap<String, Vec<String>>,
}

pub(crate) fn bounded_domains() -> Result<(), String> {
    let path = root().join("bounded-domains.toml");
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let inventory: BoundedDomainInventory = toml::from_str(&source)
        .map_err(|error| format!("invalid bounded-domains.toml: {error}"))?;
    validate_bounded_domain_inventory(&inventory)?;
    write_bounded_domain_inventory_report(&inventory)?;
    println!(
        "bounded-domain boundary passed ({} domains, {} required scenarios)",
        inventory.domains.len(),
        inventory.inventory.required_scenarios.len()
    );
    Ok(())
}

fn validate_bounded_domain_inventory(inventory: &BoundedDomainInventory) -> Result<(), String> {
    if inventory.schema != 1 {
        return Err("bounded-domains.toml must declare schema = 1".into());
    }
    for (label, value) in [
        ("inventory id", inventory.inventory.id.as_str()),
        ("plan", inventory.inventory.plan.as_str()),
        ("audit", inventory.inventory.audit.as_str()),
        (
            "semantic report",
            inventory.inventory.semantic_report.as_str(),
        ),
        (
            "closed contract specification",
            inventory.inventory.closed_contract_spec.as_str(),
        ),
    ] {
        require_nonempty(label, value)?;
    }
    for required in [
        &inventory.inventory.plan,
        &inventory.inventory.audit,
        &inventory.inventory.semantic_report,
        &inventory.inventory.closed_contract_spec,
    ] {
        require_repository_file(required)?;
    }
    validate_closed_contract_artifacts(inventory)?;
    validate_bounded_policy_registry(inventory)?;
    let declared_domains = unique_strings(
        "bounded inventory required domains",
        &inventory.inventory.required_domains,
    )?;
    let expected_domains: BTreeSet<_> = REQUIRED_DOMAIN_IDS.map(str::to_owned).into();
    if declared_domains != expected_domains {
        return Err(format!(
            "bounded inventory domain set drifted; expected={expected_domains:?}, actual={declared_domains:?}"
        ));
    }
    let required_scenarios = unique_strings(
        "bounded inventory required scenarios",
        &inventory.inventory.required_scenarios,
    )?;
    if required_scenarios.len() != 11 {
        return Err(format!(
            "bounded inventory must define 11 lifecycle scenarios, found {}",
            required_scenarios.len()
        ));
    }
    validate_boundary_rules(&inventory.boundary)?;

    if inventory.domains.len() != REQUIRED_DOMAIN_IDS.len() {
        return Err(format!(
            "bounded inventory must contain seven domains, found {}",
            inventory.domains.len()
        ));
    }
    let compliance_source = fs::read_to_string(root().join("compliance.toml"))
        .map_err(|error| format!("could not read compliance.toml: {error}"))?;
    let compliance: toml::Value = toml::from_str(&compliance_source)
        .map_err(|error| format!("invalid compliance.toml: {error}"))?;
    let packages = compliance
        .get("packages")
        .and_then(toml::Value::as_table)
        .ok_or("compliance.toml has no packages table")?;

    let mut domain_ids = BTreeSet::new();
    let mut migration_orders = BTreeSet::new();
    let mut profiles = BTreeSet::new();
    let mut specs = BTreeSet::new();
    let mut fixture_directories = BTreeSet::new();
    let mut verified_commands = BTreeSet::new();

    for domain in &inventory.domains {
        if !domain_ids.insert(domain.id.clone()) {
            return Err(format!("duplicate bounded domain {}", domain.id));
        }
        if !migration_orders.insert(domain.migration_order)
            || !(1..=u8::try_from(REQUIRED_DOMAIN_IDS.len()).unwrap_or(u8::MAX))
                .contains(&domain.migration_order)
        {
            return Err(format!(
                "bounded domain {} has invalid or duplicate migration order {}",
                domain.id, domain.migration_order
            ));
        }
        for (label, value) in [
            ("package", domain.package.as_str()),
            ("package path", domain.package_path.as_str()),
            ("consumer package", domain.consumer_package.as_str()),
            ("consumer path", domain.consumer_path.as_str()),
            ("specification", domain.spec.as_str()),
            (
                "evaluator entry point",
                domain.evaluator_entrypoint.as_str(),
            ),
            ("action type", domain.action_type.as_str()),
            ("policy type", domain.policy_type.as_str()),
            ("evidence type", domain.evidence_type.as_str()),
            ("configuration type", domain.configuration_type.as_str()),
            ("decision type", domain.decision_type.as_str()),
            ("reservation type", domain.reservation_type.as_str()),
            ("verified command", domain.verified_command.as_str()),
            ("provider gateway", domain.provider_gateway.as_str()),
            ("credential scope", domain.credential_scope.as_str()),
            ("reconciliation", domain.reconciliation.as_str()),
            ("fixture directory", domain.fixture_dir.as_str()),
        ] {
            require_nonempty(&format!("bounded domain {} {label}", domain.id), value)?;
        }
        if domain.status != "implemented" {
            return Err(format!(
                "primary bounded domain {} must be implemented, found {}",
                domain.id, domain.status
            ));
        }
        let domain_profiles = unique_strings(
            &format!("bounded domain {} profiles", domain.id),
            &domain.profiles,
        )?;
        if domain_profiles.is_empty() {
            return Err(format!(
                "bounded domain {} must declare at least one profile",
                domain.id
            ));
        }
        for profile in &domain.profiles {
            if !profiles.insert(profile.as_str()) {
                return Err(format!(
                    "bounded domain {} has duplicate profile {profile}",
                    domain.id
                ));
            }
        }
        for (label, inserted) in [
            ("specification", specs.insert(domain.spec.as_str())),
            (
                "fixture directory",
                fixture_directories.insert(domain.fixture_dir.as_str()),
            ),
            (
                "verified command",
                verified_commands.insert(domain.verified_command.as_str()),
            ),
        ] {
            if !inserted {
                return Err(format!(
                    "bounded domain {} has duplicate {label}",
                    domain.id
                ));
            }
        }
        require_repository_directory(&domain.package_path)?;
        require_repository_directory(&domain.consumer_path)?;
        require_repository_directory(&domain.fixture_dir)?;
        validate_specification_status(domain)?;
        validate_scenarios(domain, &required_scenarios)?;
        validate_fixture_manifest(domain)?;
        validate_compliance_registration(domain, packages)?;
        unique_strings(
            &format!("bounded domain {} receipt types", domain.id),
            &domain.receipt_types,
        )?;
    }

    if domain_ids != expected_domains {
        return Err(format!(
            "bounded domain records drifted; expected={expected_domains:?}, actual={domain_ids:?}"
        ));
    }
    Ok(())
}

fn validate_bounded_policy_registry(inventory: &BoundedDomainInventory) -> Result<(), String> {
    let path = root().join("product/fixtures/v1/bounded-policy/registry.toml");
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let registry: toml::Value = toml::from_str(&source)
        .map_err(|error| format!("invalid bounded-policy registry: {error}"))?;
    if registry.get("schema").and_then(toml::Value::as_str)
        != Some("auths.product.closed-evaluator-registry/1")
        || registry.get("contract").and_then(toml::Value::as_str)
            != Some("auths.product.bounded-policy-contract/1")
        || registry
            .get("migration_status")
            .and_then(toml::Value::as_str)
            != Some("reference-only")
    {
        return Err("bounded-policy registry identity or migration status drifted".into());
    }
    let domains = registry
        .get("domains")
        .and_then(toml::Value::as_array)
        .ok_or("bounded-policy registry has no domains")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or("bounded-policy registry domain is not a string")
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_domains: BTreeSet<_> = REQUIRED_DOMAIN_IDS.map(str::to_owned).into();
    if domains != expected_domains {
        return Err(format!(
            "bounded-policy registry domains drifted: expected={expected_domains:?}, actual={domains:?}"
        ));
    }
    let surfaces = registry
        .get("semantic_surfaces")
        .and_then(toml::Value::as_array)
        .ok_or("bounded-policy registry has no semantic surfaces")?;
    let mut identities = BTreeSet::new();
    for surface in surfaces {
        let table = surface
            .as_table()
            .ok_or("bounded-policy semantic surface is not a table")?;
        let identity = table
            .get("id")
            .and_then(toml::Value::as_str)
            .ok_or("bounded-policy semantic surface has no id")?;
        for field in ["rust_symbol", "lean_artifact"] {
            if table
                .get(field)
                .and_then(toml::Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(format!(
                    "bounded-policy semantic surface {identity} has no {field}"
                ));
            }
        }
        if !identities.insert(identity.to_owned()) {
            return Err(format!(
                "bounded-policy registry repeats semantic identity {identity}"
            ));
        }
    }
    let expected: BTreeSet<_> = [
        "auths.product.policy-commitment/1",
        "auths.product.evaluation-commitments/1",
        "auths.product.configuration-match/1",
        "auths.product.eligibility/1",
        "auths.product.checked-arithmetic/1",
        "auths.product.bounded-decision-envelope/1",
        "auths.product.bounded-policy-compatibility/1",
    ]
    .map(str::to_owned)
    .into();
    if identities != expected {
        return Err(format!(
            "bounded-policy semantic registry drifted: expected={expected:?}, actual={identities:?}"
        ));
    }

    let evaluators = registry
        .get("evaluators")
        .and_then(toml::Value::as_array)
        .ok_or("bounded-policy registry has no concrete evaluators")?;
    let expected_profiles: BTreeSet<_> = inventory
        .domains
        .iter()
        .flat_map(|domain| domain.profiles.iter().cloned())
        .collect();
    if evaluators.len() != expected_profiles.len() {
        return Err(format!(
            "bounded-policy registry must contain one evaluator per profile; expected={}, actual={}",
            expected_profiles.len(),
            evaluators.len()
        ));
    }

    let domains_by_id: BTreeMap<_, _> = inventory
        .domains
        .iter()
        .map(|domain| (domain.id.as_str(), domain))
        .collect();
    let mut registered_profiles = BTreeSet::new();
    let mut semantic_ids = BTreeSet::new();
    let mut previous_profile: Option<&str> = None;
    for evaluator in evaluators {
        let table = evaluator
            .as_table()
            .ok_or("bounded-policy evaluator registration is not a table")?;
        let domain_id = registry_string(table, "domain_id")?;
        let profile_id = registry_string(table, "profile_id")?;
        let domain = domains_by_id
            .get(domain_id)
            .ok_or_else(|| format!("bounded-policy evaluator names unknown domain {domain_id}"))?;
        if !domain.profiles.iter().any(|profile| profile == profile_id) {
            return Err(format!(
                "bounded-policy evaluator {profile_id} is not declared by domain {domain_id}"
            ));
        }
        if previous_profile.is_some_and(|previous| previous >= profile_id) {
            return Err(format!(
                "bounded-policy evaluator profiles are not strictly ordered at {profile_id}"
            ));
        }
        previous_profile = Some(profile_id);
        if !registered_profiles.insert(profile_id.to_owned()) {
            return Err(format!(
                "bounded-policy evaluator profile {profile_id} is duplicated"
            ));
        }

        let semantic_id = registry_string(table, "evaluator_semantic_id")?;
        if !semantic_ids.insert(semantic_id.to_owned()) {
            return Err(format!(
                "bounded-policy evaluator semantic identity {semantic_id} is duplicated"
            ));
        }
        if registry_string(table, "owning_package")? != domain.package
            || registry_string(table, "layer")? != "product"
            || registry_string(table, "migration_status")? != "reference-only"
        {
            return Err(format!(
                "bounded-policy evaluator {profile_id} ownership, layer, or migration status drifted"
            ));
        }

        let expected_fixture = format!("{}/manifest.json", domain.fixture_dir);
        if registry_string(table, "fixture_manifest")? != expected_fixture {
            return Err(format!(
                "bounded-policy evaluator {profile_id} fixture manifest does not match {}",
                domain.fixture_dir
            ));
        }
        let rust_symbol = registry_string(table, "rust_symbol")?;
        let reference_evaluator = registry_string(table, "reference_evaluator")?;
        if rust_symbol != reference_evaluator
            || !domain
                .evaluator_entrypoint
                .split('|')
                .any(|entrypoint| entrypoint == rust_symbol)
        {
            return Err(format!(
                "bounded-policy evaluator {profile_id} does not name its exact reference entry point"
            ));
        }

        for field in [
            "policy_type_id",
            "implementation_id",
            "canonicalization_id",
            "lean_artifact",
            "action_schema",
            "policy_schema",
            "evidence_schema",
            "state_schema",
            "result_schema",
            "intent_schema",
            "obligation_schema",
            "receipt_schema",
            "stable_code_source",
            "stable_stage_source",
            "hard_limit_source",
            "mutation_corpus",
            "fuzz_target",
            "kani_harnesses",
            "property_tests",
        ] {
            registry_string(table, field).map_err(|error| {
                format!("bounded-policy evaluator {profile_id} registration error: {error}")
            })?;
        }
        for field in [
            "stable_code_source",
            "stable_stage_source",
            "hard_limit_source",
            "fixture_manifest",
            "fuzz_target",
            "property_tests",
        ] {
            require_repository_file(registry_string(table, field)?)?;
        }
        require_repository_directory(registry_string(table, "mutation_corpus")?)?;

        for field in [
            "evidence_schema",
            "state_schema",
            "intent_schema",
            "obligation_schema",
        ] {
            if registry_string(table, field)? == "none-pre-migration" && domain_id != "records-api"
            {
                return Err(format!(
                    "only the pre-migration records profiles may explicitly lack {field}"
                ));
            }
        }
    }
    if registered_profiles != expected_profiles {
        return Err(format!(
            "bounded-policy evaluator profile coverage drifted: expected={expected_profiles:?}, actual={registered_profiles:?}"
        ));
    }
    Ok(())
}

fn registry_string<'a>(
    table: &'a toml::map::Map<String, toml::Value>,
    field: &str,
) -> Result<&'a str, String> {
    table
        .get(field)
        .and_then(toml::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing non-empty {field}"))
}

fn validate_closed_contract_artifacts(inventory: &BoundedDomainInventory) -> Result<(), String> {
    let report =
        fs::read_to_string(root().join(&inventory.inventory.semantic_report)).map_err(|error| {
            format!(
                "could not read semantic report {}: {error}",
                inventory.inventory.semantic_report
            )
        })?;
    let contract = fs::read_to_string(root().join(&inventory.inventory.closed_contract_spec))
        .map_err(|error| {
            format!(
                "could not read closed contract specification {}: {error}",
                inventory.inventory.closed_contract_spec
            )
        })?;

    for domain in REQUIRED_DOMAIN_IDS {
        let report_name = if domain == "records-api" {
            "Records API"
        } else {
            domain
        };
        if !report
            .to_ascii_lowercase()
            .contains(&report_name.to_ascii_lowercase())
        {
            return Err(format!(
                "seven-domain semantic report does not name required domain {domain}"
            ));
        }
    }
    for identity in [
        "auths.product.bounded-policy-contract/1",
        "auths.product.policy-commitment/1",
        "auths.product.evaluation-commitments/1",
        "auths.product.configuration-match/1",
        "auths.product.eligibility/1",
        "auths.product.checked-arithmetic/1",
        "auths.product.bounded-decision-envelope/1",
        "auths.product.bounded-policy-compatibility/1",
    ] {
        if !contract.contains(identity) {
            return Err(format!(
                "closed bounded-policy contract does not reserve {identity}"
            ));
        }
    }
    for case in [
        "0001-policy-and-evaluator-commitments.md",
        "0002-evaluation-context-and-configuration-match.md",
        "0003-eligibility-reservations-and-obligations.md",
        "0004-checked-arithmetic-limits-and-tightening.md",
        "0005-receipt-envelope.md",
        "0006-evidence-provider-and-lifecycle-exclusions.md",
    ] {
        require_repository_file(&format!("docs/research/domains/abstraction-cases/{case}"))?;
        if !report.contains(case) {
            return Err(format!(
                "semantic report does not reference abstraction case {case}"
            ));
        }
    }
    Ok(())
}

fn validate_boundary_rules(boundary: &BoundaryRules) -> Result<(), String> {
    let rules = [
        (
            "core_must_remain_provider_neutral",
            boundary.core_must_remain_provider_neutral,
        ),
        (
            "shared_product_must_not_import_provider_sdks",
            boundary.shared_product_must_not_import_provider_sdks,
        ),
        (
            "domain_actions_remain_domain_owned",
            boundary.domain_actions_remain_domain_owned,
        ),
        (
            "domain_evidence_remains_domain_owned",
            boundary.domain_evidence_remains_domain_owned,
        ),
        (
            "verified_commands_remain_domain_owned",
            boundary.verified_commands_remain_domain_owned,
        ),
        (
            "provider_gateways_remain_domain_owned",
            boundary.provider_gateways_remain_domain_owned,
        ),
        (
            "credential_scopes_remain_domain_owned",
            boundary.credential_scopes_remain_domain_owned,
        ),
        (
            "reconciliation_meaning_remains_domain_owned",
            boundary.reconciliation_meaning_remains_domain_owned,
        ),
        (
            "receipt_payloads_remain_domain_owned",
            boundary.receipt_payloads_remain_domain_owned,
        ),
        (
            "demos_remain_compatibility_consumers",
            boundary.demos_remain_compatibility_consumers,
        ),
        (
            "one_production_path_after_migration",
            boundary.one_production_path_after_migration,
        ),
        (
            "reference_evaluators_remain_test_oracles",
            boundary.reference_evaluators_remain_test_oracles,
        ),
    ];
    let disabled: Vec<_> = rules
        .iter()
        .filter_map(|(name, enabled)| (!enabled).then_some(*name))
        .collect();
    if disabled.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "bounded-domain boundary rules may not be disabled: {disabled:?}"
        ))
    }
}

fn validate_specification_status(domain: &DomainRecord) -> Result<(), String> {
    let path = root().join(&domain.spec);
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let header = source.lines().take(10).collect::<Vec<_>>().join("\n");
    if !header.contains("Status: Implemented") && !header.contains("**Status:** Implemented") {
        return Err(format!(
            "bounded domain {} specification {} is not marked Implemented",
            domain.id, domain.spec
        ));
    }
    for profile in &domain.profiles {
        if !source.contains(profile) {
            return Err(format!(
                "bounded domain {} specification {} does not declare profile {}",
                domain.id, domain.spec, profile
            ));
        }
    }
    Ok(())
}

fn validate_scenarios(domain: &DomainRecord, required: &BTreeSet<String>) -> Result<(), String> {
    let scenarios = unique_strings(
        &format!("bounded domain {} scenarios", domain.id),
        &domain.scenarios,
    )?;
    let not_applicable: BTreeSet<_> = domain.not_applicable.keys().cloned().collect();
    if scenarios.intersection(&not_applicable).next().is_some() {
        return Err(format!(
            "bounded domain {} marks a scenario both implemented and not applicable",
            domain.id
        ));
    }
    if scenarios
        .union(&not_applicable)
        .cloned()
        .collect::<BTreeSet<_>>()
        != *required
    {
        return Err(format!(
            "bounded domain {} scenario coverage drifted; implemented={scenarios:?}, not_applicable={not_applicable:?}, required={required:?}",
            domain.id
        ));
    }
    for (scenario, rationale) in &domain.not_applicable {
        require_nonempty(
            &format!(
                "bounded domain {} not-applicable rationale for {scenario}",
                domain.id
            ),
            rationale,
        )?;
    }
    if domain
        .scenario_evidence
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != scenarios
    {
        return Err(format!(
            "bounded domain {} executable scenario evidence does not match implemented scenarios",
            domain.id
        ));
    }
    for (scenario, anchors) in &domain.scenario_evidence {
        let unique = unique_strings(
            &format!("bounded domain {} evidence for {scenario}", domain.id),
            anchors,
        )?;
        if unique.is_empty() {
            return Err(format!(
                "bounded domain {} scenario {scenario} has no executable evidence",
                domain.id
            ));
        }
        for anchor in anchors {
            validate_compliance_evidence(&domain.package, anchor)?;
        }
    }
    Ok(())
}

fn validate_fixture_manifest(domain: &DomainRecord) -> Result<(), String> {
    let directory = root().join(&domain.fixture_dir);
    let manifest_path = directory.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path).map_err(|error| {
        format!(
            "could not read bounded domain {} fixture manifest {}: {error}",
            domain.id,
            manifest_path.display()
        )
    })?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        format!(
            "invalid bounded domain {} fixture manifest: {error}",
            domain.id
        )
    })?;
    if manifest["schema"] != "auths.bounded-domain-oracle-manifest/1"
        || manifest["domain"] != domain.id
        || manifest["profiles"]
            != Value::Array(domain.profiles.iter().cloned().map(Value::String).collect())
    {
        return Err(format!(
            "bounded domain {} fixture manifest identity drifted",
            domain.id
        ));
    }
    let hashes = manifest["sha256"]
        .as_object()
        .ok_or_else(|| format!("bounded domain {} manifest has no sha256 map", domain.id))?;
    let sizes = manifest["bytes"]
        .as_object()
        .ok_or_else(|| format!("bounded domain {} manifest has no bytes map", domain.id))?;
    let scenario_records = manifest["scenarios"]
        .as_object()
        .ok_or_else(|| format!("bounded domain {} manifest has no scenarios map", domain.id))?;
    let manifest_scenarios: BTreeSet<_> = scenario_records.keys().cloned().collect();
    let expected_scenarios: BTreeSet<_> = domain.scenarios.iter().cloned().collect();
    if manifest_scenarios != expected_scenarios {
        return Err(format!(
            "bounded domain {} manifest scenario set drifted",
            domain.id
        ));
    }
    let mut actual_files = BTreeSet::new();
    for entry in fs::read_dir(&directory)
        .map_err(|error| format!("could not list {}: {error}", directory.display()))?
    {
        let entry =
            entry.map_err(|error| format!("could not inspect {}: {error}", directory.display()))?;
        let path = entry.path();
        if path == manifest_path {
            continue;
        }
        if !path.is_file() {
            return Err(format!(
                "bounded domain {} fixture corpus must be flat: {}",
                domain.id,
                path.display()
            ));
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| format!("fixture path {} has no UTF-8 name", path.display()))?
            .to_owned();
        actual_files.insert(name.clone());
        let expected = hashes
            .get(&name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("bounded domain {} manifest omits fixture {name}", domain.id))?;
        let actual = sha256_file(&path)?;
        if actual != expected {
            return Err(format!(
                "bounded domain {} fixture {name} drifted; expected {expected}, found {actual}",
                domain.id
            ));
        }
        let expected_size = sizes.get(&name).and_then(Value::as_u64).ok_or_else(|| {
            format!(
                "bounded domain {} manifest omits byte size for fixture {name}",
                domain.id
            )
        })?;
        let actual_size = fs::metadata(&path)
            .map_err(|error| format!("could not stat {}: {error}", path.display()))?
            .len();
        if actual_size != expected_size {
            return Err(format!(
                "bounded domain {} fixture {name} size drifted; expected {expected_size}, found {actual_size}",
                domain.id
            ));
        }
    }
    let declared_files: BTreeSet<_> = hashes.keys().cloned().collect();
    let declared_sizes: BTreeSet<_> = sizes.keys().cloned().collect();
    if declared_sizes != declared_files {
        return Err(format!(
            "bounded domain {} fixture size inventory drifted",
            domain.id
        ));
    }
    if actual_files != declared_files {
        return Err(format!(
            "bounded domain {} fixture file inventory drifted; declared={declared_files:?}, actual={actual_files:?}",
            domain.id
        ));
    }
    if actual_files.is_empty() {
        return Err(format!(
            "bounded domain {} fixture corpus is empty",
            domain.id
        ));
    }
    Ok(())
}

fn validate_compliance_registration(
    domain: &DomainRecord,
    packages: &toml::map::Map<String, toml::Value>,
) -> Result<(), String> {
    for (label, package_name, package_path) in [
        (
            "product",
            domain.package.as_str(),
            domain.package_path.as_str(),
        ),
        (
            "consumer",
            domain.consumer_package.as_str(),
            domain.consumer_path.as_str(),
        ),
    ] {
        let package = packages
            .get(package_name)
            .and_then(toml::Value::as_table)
            .ok_or_else(|| {
                format!(
                    "bounded domain {} {label} package {package_name} is absent from compliance.toml",
                    domain.id
                )
            })?;
        if package.get("path").and_then(toml::Value::as_str) != Some(package_path) {
            return Err(format!(
                "bounded domain {} {label} compliance path drifted",
                domain.id
            ));
        }
        let registered_profiles = package
            .get("profiles")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| {
                format!(
                    "bounded domain {} {label} compliance record has no profiles",
                    domain.id
                )
            })?;
        for profile in &domain.profiles {
            if !registered_profiles
                .iter()
                .any(|value| value.as_str() == Some(profile))
            {
                return Err(format!(
                    "bounded domain {} {label} compliance record omits profile {}",
                    domain.id, profile
                ));
            }
        }
        let fixture_suites = package
            .get("fixture_suites")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| {
                format!(
                    "bounded domain {} {label} compliance record has no fixture suites",
                    domain.id
                )
            })?;
        if !fixture_suites
            .iter()
            .any(|value| value.as_str() == Some(&domain.fixture_dir))
        {
            return Err(format!(
                "bounded domain {} {label} compliance record omits fixture suite {}",
                domain.id, domain.fixture_dir
            ));
        }
    }
    Ok(())
}

fn write_bounded_domain_inventory_report(inventory: &BoundedDomainInventory) -> Result<(), String> {
    let domains = inventory
        .domains
        .iter()
        .map(|domain| {
            json!({
                "id": domain.id,
                "migration_order": domain.migration_order,
                "package": domain.package,
                "consumer_package": domain.consumer_package,
                "profiles": domain.profiles,
                "fixture_dir": domain.fixture_dir,
                "scenarios": domain.scenarios,
                "not_applicable": domain.not_applicable,
                "verified_command": domain.verified_command,
                "provider_gateway": domain.provider_gateway,
                "credential_scope": domain.credential_scope,
                "reconciliation": domain.reconciliation,
                "receipt_types": domain.receipt_types,
            })
        })
        .collect::<Vec<_>>();
    write_pretty_json(
        &root().join("target/compliance/bounded-domains.json"),
        &json!({
            "schema": "auths.bounded-domain-inventory-report/1",
            "inventory": inventory.inventory.id,
            "domains": domains,
        }),
    )
}

fn unique_strings(label: &str, values: &[String]) -> Result<BTreeSet<String>, String> {
    let mut unique = BTreeSet::new();
    for value in values {
        require_nonempty(label, value)?;
        if !unique.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value {value}"));
        }
    }
    Ok(unique)
}

fn require_nonempty(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_repository_file(relative: &str) -> Result<(), String> {
    let path = checked_repository_path(relative)?;
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("required repository file is absent: {relative}"))
    }
}

fn require_repository_directory(relative: &str) -> Result<(), String> {
    let path = checked_repository_path(relative)?;
    if path.is_dir() {
        Ok(())
    } else {
        Err(format!(
            "required repository directory is absent: {relative}"
        ))
    }
}

fn checked_repository_path(relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "repository path must be relative and contained: {relative}"
        ));
    }
    Ok(root().join(path))
}
