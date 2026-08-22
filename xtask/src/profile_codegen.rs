use crate::prelude::*;
use crate::root;
use auths_profile_kit::{ProfileApi, ProfilePackage, ProfileRoster, QualificationScenarioManifest};

const GENERATOR: &str = "auths-profile-generator/1";

pub(crate) fn profile_command(arguments: Vec<String>) -> Result<(), String> {
    if arguments.first().map(String::as_str) == Some("qualification") {
        return crate::profile_qualification_command(&arguments[1..]);
    }
    match parse_arguments(&arguments)? {
        ProfileCommand::New(arguments) => scaffold(&arguments),
        ProfileCommand::Generate { domain, check } => generate(&domain, check),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProfileCommand {
    New(NewProfileArguments),
    Generate { domain: String, check: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NewProfileArguments {
    domain: String,
    effect: String,
    version: u16,
    mode: NewProfileMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NewProfileMode {
    ExistingDomain,
    Connected {
        provider: String,
        connection_version: u16,
    },
    Connectionless,
}

fn parse_arguments(arguments: &[String]) -> Result<ProfileCommand, String> {
    let Some(action) = arguments.first().map(String::as_str) else {
        return Err(profile_usage());
    };
    if matches!(action, "generate" | "check") {
        if arguments.len() != 3 || arguments[1] != "--domain" {
            return Err(profile_usage());
        }
        validate_lower_token(&arguments[2], "profile domain")?;
        return Ok(ProfileCommand::Generate {
            domain: arguments[2].clone(),
            check: action == "check",
        });
    }
    if action != "new" {
        return Err(format!(
            "unknown profile action {action}; expected new, generate, or check"
        ));
    }
    parse_new_arguments(&arguments[1..]).map(ProfileCommand::New)
}

fn parse_new_arguments(arguments: &[String]) -> Result<NewProfileArguments, String> {
    let mut domain = None;
    let mut effect = None;
    let mut version = None;
    let mut existing_domain = false;
    let mut provider = None;
    let mut connection_version = None;
    let mut connectionless = false;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        match flag {
            "--existing-domain" => {
                if existing_domain {
                    return Err("duplicate --existing-domain".into());
                }
                existing_domain = true;
                index += 1;
            }
            "--connectionless" => {
                if connectionless {
                    return Err("duplicate --connectionless".into());
                }
                connectionless = true;
                index += 1;
            }
            "--domain" | "--effect" | "--version" | "--provider" | "--connection-version" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| format!("{flag} requires a value"))?
                    .clone();
                let target = match flag {
                    "--domain" => &mut domain,
                    "--effect" => &mut effect,
                    "--version" => &mut version,
                    "--provider" => &mut provider,
                    "--connection-version" => &mut connection_version,
                    _ => unreachable!(),
                };
                if target.replace(value).is_some() {
                    return Err(format!("duplicate {flag}"));
                }
                index += 2;
            }
            _ => {
                return Err(format!(
                    "unknown profile new argument {flag}; {}",
                    profile_usage()
                ));
            }
        }
    }
    let domain = domain.ok_or_else(profile_usage)?;
    let effect = effect.ok_or_else(profile_usage)?;
    validate_lower_token(&domain, "profile domain")?;
    validate_lower_token(&effect, "profile effect")?;
    let version = parse_version(version.as_deref(), "profile version")?;
    let mode = if existing_domain {
        if provider.is_some() || connection_version.is_some() || connectionless {
            return Err(
                "--existing-domain forbids --provider, --connection-version, and --connectionless"
                    .into(),
            );
        }
        NewProfileMode::ExistingDomain
    } else if connectionless {
        if provider.is_some() || connection_version.is_some() {
            return Err(
                "--connectionless cannot be combined with provider connection flags".into(),
            );
        }
        NewProfileMode::Connectionless
    } else {
        let provider = provider.ok_or_else(|| {
            "new domains require --provider with --connection-version, or --connectionless"
                .to_owned()
        })?;
        validate_lower_token(&provider, "provider")?;
        NewProfileMode::Connected {
            provider,
            connection_version: parse_version(connection_version.as_deref(), "connection version")?,
        }
    };
    Ok(NewProfileArguments {
        domain,
        effect,
        version,
        mode,
    })
}

fn parse_version(value: Option<&str>, label: &str) -> Result<u16, String> {
    let value = value.ok_or_else(profile_usage)?;
    let parsed = value
        .parse::<u16>()
        .map_err(|_| format!("{label} must be in 1..=65535"))?;
    if parsed == 0 {
        return Err(format!("{label} must be in 1..=65535"));
    }
    Ok(parsed)
}

fn validate_lower_token(value: &str, label: &str) -> Result<(), String> {
    if !lower_token(value) {
        return Err(format!("{label} must match [a-z][a-z0-9-]{{0,63}}"));
    }
    Ok(())
}

fn profile_usage() -> String {
    "usage: cargo xtask profile <generate|check> --domain <domain> | cargo xtask profile new --domain <domain> --effect <effect> --version <1..65535> [--existing-domain | --provider <provider> --connection-version <1..65535> | --connectionless]".into()
}

fn scaffold(arguments: &NewProfileArguments) -> Result<(), String> {
    scaffold_at(&root(), arguments)
}

fn scaffold_at(repository: &Path, arguments: &NewProfileArguments) -> Result<(), String> {
    let domain = arguments.domain.as_str();
    let package_root = repository.join(format!("product/integrations/auths-{domain}"));
    if package_root.exists() {
        return if arguments.mode == NewProfileMode::ExistingDomain {
            scaffold_existing_profile(repository, arguments, &package_root)
        } else {
            Err(format!(
                "profile domain already exists: {domain}; use --existing-domain to add an effect"
            ))
        };
    }
    if arguments.mode == NewProfileMode::ExistingDomain {
        return Err(format!("profile domain does not exist: {domain}"));
    }
    let api_dir = package_root.join("api");
    let errors_dir = package_root.join("errors");
    let qualification_dir = package_root.join("qualification");
    let effect_dir = package_root.join("src").join(&arguments.effect);
    let fixture_dir = package_root
        .join("fixtures")
        .join(&arguments.effect)
        .join(format!("v{}", arguments.version));
    let tests_dir = package_root.join("tests");
    for directory in [
        &api_dir,
        &errors_dir,
        &qualification_dir,
        &effect_dir,
        &fixture_dir,
        &tests_dir,
    ] {
        fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    }
    if matches!(arguments.mode, NewProfileMode::Connected { .. }) {
        fs::create_dir_all(package_root.join("src/connection"))
            .map_err(|error| error.to_string())?;
        fs::create_dir_all(package_root.join("fixtures/connection/v1"))
            .map_err(|error| error.to_string())?;
    }
    let class_name = pascal(domain);
    let effect_class = pascal(&arguments.effect);
    let input_type = format!("{effect_class}Input");
    let success_type = format!("{effect_class}Result");
    let api = json!({
        "schema": "auths.profile-api/1",
        "types": {
            input_type.clone(): {
                "kind": "record",
                "fields": [{
                    "name": "value",
                    "value": {"kind":"string","minimumBytes":1,"maximumBytes":128,"alphabet":"utf8"},
                    "sensitive": false
                }]
            },
            success_type.clone(): {
                "kind": "record",
                "fields": [{
                    "name": "id",
                    "value": {"kind":"string","minimumBytes":1,"maximumBytes":128,"alphabet":"registered-token"},
                    "sensitive": false
                }]
            }
        }
    });
    fs::write(api_dir.join("profile-api.json"), pretty_json(&api)?)
        .map_err(|error| error.to_string())?;
    let connection = match &arguments.mode {
        NewProfileMode::Connected {
            provider,
            connection_version,
        } => json!({
            "providerKind":provider,
            "contract":format!("auths.{provider}.connection/{connection_version}"),
            "descriptorSchema":format!("auths.{provider}.connection-descriptor/{connection_version}"),
            "sources":{
                "specification":format!("docs/specs/TODO-{provider}-connection.md"),
                "descriptor":format!("product/integrations/auths-{domain}/src/connection/descriptor.rs"),
                "onboarding":format!("product/integrations/auths-{domain}/src/connection/onboarding.rs"),
                "credentials":format!("product/integrations/auths-{domain}/src/connection/credentials.rs"),
                "adminRoutes":format!("product/integrations/auths-{domain}/src/connection/admin_routes.rs")
            },
            "evidence":{
                "fixtures":format!("product/integrations/auths-{domain}/fixtures/connection/v{connection_version}"),
                "conformance":format!("product/integrations/auths-{domain}/tests/connection_conformance.rs")
            }
        }),
        NewProfileMode::Connectionless => Value::Null,
        NewProfileMode::ExistingDomain => unreachable!(),
    };
    let profile_id = format!("auths.{domain}.{}", arguments.effect);
    let version = arguments.version;
    let effect = arguments.effect.as_str();
    let credential_scope = match &arguments.mode {
        NewProfileMode::Connected { provider, .. } => {
            Value::String(format!("{provider}.{effect}.execute/{version}"))
        }
        NewProfileMode::Connectionless => Value::Null,
        NewProfileMode::ExistingDomain => unreachable!(),
    };
    let manifest = json!({
        "schema":"auths.profile-package/1",
        "domain":{
            "id":domain,
            "clientClass":class_name,
            "rustPackage":format!("auths-{domain}"),
            "typescriptPackage":format!("@auths-dev/profile-{domain}"),
            "pythonDistribution":format!("auths-profile-{domain}"),
            "pythonModule":format!("auths_profiles.{}", domain.replace('-', "_")),
            "connection":connection
        },
        "api":"api/profile-api.json",
        "qualification":{
            "family":[format!("auths.{domain}.{effect}/{version}")],
            "adapter":domain,
            "targets":["linux-x86_64"],
            "protectedEnvironment":format!("qualification-{domain}"),
            "commonScenarios":"auths.profile-qualification-common/1",
            "domainScenarios":"qualification/scenarios-v1.json",
            "requirements":"qualification/requirements-v1.json",
            "providerMatrix":"qualification/provider-matrix-v1.json",
            "operationPlans":"qualification/operation-plans-v1.json",
            "failpointCoverage":"qualification/failpoint-coverage-v1.json",
            "providerTruthSchema":"qualification/provider-truth-v1.schema.json",
            "profileStateSnapshot":"profiles/{domain}-qualification-v1/state.json"
        },
        "profiles":[{
            "id":profile_id,
            "version":version,
            "semanticSubject":format!("auths.{domain}.{effect}/{version}"),
            "effectId":format!("{domain}.{effect}.execute"),
            "client":{
                "group":effect,
                "method":"execute",
                "inputType":input_type,
                "successType":success_type,
                "partialType":null,
                "progressType":null
            },
            "contracts":{
                "canonicalAction":format!("auths.{domain}.{effect}-action/{version}"),
                "evaluator":format!("auths.{domain}.{effect}-evaluator/{version}"),
                "lifecycle":format!("auths.{domain}.{effect}-lifecycle/{version}"),
                "provider":format!("auths.{domain}.{effect}-provider/{version}"),
                "receipt":format!("auths.{domain}.{effect}-receipt/{version}"),
                "credentialScope":credential_scope,
                "errorOwner":format!("{domain}-{effect}"),
                "errorOwnerVersion":version
            },
            "limits":{
                "requestBytes":262144,
                "responseBytes":262144,
                "receiptCount":4,
                "receiptBytes":65536,
                "executionMilliseconds":30000,
                "admissionsPerMinute":600,
                "activePerPrincipal":64,
                "unresolvedPerPrincipal":16,
                "durableBytesPerPrincipal":67108864,
                "tombstonesPerPrincipal":100000,
                "terminalRetentionSeconds":2592000,
                "idempotencyRetentionSeconds":2592000
            },
            "sources":{
                "specification":format!("docs/specs/TODO-{domain}-{effect}.md"),
                "action":format!("product/integrations/auths-{domain}/src/{effect}/action.rs"),
                "evaluator":format!("product/integrations/auths-{domain}/src/{effect}/evaluator.rs"),
                "command":format!("product/integrations/auths-{domain}/src/{effect}/command.rs"),
                "lifecycle":format!("product/integrations/auths-{domain}/src/{effect}/lifecycle.rs"),
                "gateway":format!("product/integrations/auths-{domain}/src/{effect}/gateway.rs"),
                "reconciliation":format!("product/integrations/auths-{domain}/src/{effect}/reconciliation.rs"),
                "receipt":format!("product/integrations/auths-{domain}/src/{effect}/receipt.rs"),
                "errors":format!("product/integrations/auths-{domain}/errors/{effect}-v{version}.json"),
                "errorMapping":format!("product/integrations/auths-{domain}/src/{effect}/errors.rs")
            },
            "evidence":{
                "fixtures":format!("product/integrations/auths-{domain}/fixtures/{effect}/v{version}"),
                "mutationCorpus":format!("product/integrations/auths-{domain}/tests/mutations.rs"),
                "providerRequests":format!("product/integrations/auths-{domain}/tests/provider_requests.rs"),
                "demo":format!("demos/{domain}-{effect}"),
                "liveContract":format!("demos/{domain}-{effect}/tests/live-contract.rs")
            }
        }]
    });
    fs::write(
        package_root.join("profile-package.json"),
        pretty_json(&manifest)?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        qualification_dir.join("scenarios-v1.json"),
        pretty_json(&json!({
            "schema":"auths.profile-qualification-scenarios/1",
            "domain":domain,
            "scenarios":[format!("{domain}-{effect}-live")]
        }))?,
    )
    .map_err(|error| error.to_string())?;
    write_qualification_scaffold_inputs(repository, arguments, &qualification_dir)?;
    write_qualification_entrypoint(repository, arguments)?;
    write_new_profile_scaffold(arguments, &package_root)?;
    write_profile_reference_scaffold(repository, arguments)?;
    register_new_domain(repository, arguments)?;
    generate_at(repository, domain, false, false)?;
    println!(
        "scaffolded {profile_id}/{version}; complete every explicit TODO, register the package, then run cargo xtask profile generate --domain {domain}"
    );
    Ok(())
}

fn write_qualification_scaffold_inputs(
    repository: &Path,
    arguments: &NewProfileArguments,
    qualification_dir: &Path,
) -> Result<(), String> {
    let common = QualificationScenarioManifest::from_json(
        &fs::read(repository.join("product/conformance/v2/profile-qualification-common.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let domain_scenario = format!("{}-{}-live", arguments.domain, arguments.effect);
    let mut scenarios = common.scenarios().to_vec();
    scenarios.push(domain_scenario.clone());
    scenarios.sort();
    scenarios.dedup();
    let profile = format!(
        "auths.{}.{}/{}",
        arguments.domain, arguments.effect, arguments.version
    );
    let provider = match &arguments.mode {
        NewProfileMode::Connected { provider, .. } => provider.as_str(),
        NewProfileMode::Connectionless => arguments.domain.as_str(),
        NewProfileMode::ExistingDomain => {
            return Err("qualification scaffold inputs are only created for a new domain".into());
        }
    };
    let requirements = qualification_requirements_value(arguments, &domain_scenario, &profile);
    let failpoint_coverage = crate::profile_qualification::qualification_failpoint_coverage_value(
        &arguments.domain,
        &["implemented", "schema"],
    );
    for (name, value) in [
        ("requirements-v1.json", requirements),
        (
            "provider-matrix-v1.json",
            json!({
                "schema":"auths.profile-qualification-provider-matrix/1",
                "domain":arguments.domain,
                "runs":[{
                    "contract":{"implemented":false,"schema":format!("auths.{}.qualification-provider-contract/1",arguments.domain)},
                    "id":format!("{}-protected-live",arguments.domain),
                    "provider":provider,
                    "providerArtifactSha256":"0000000000000000000000000000000000000000000000000000000000000000",
                    "providerVersion":"unimplemented",
                    "scenarioIds":scenarios.clone(),
                    "target":"linux-x86_64"
                }]
            }),
        ),
        (
            "operation-plans-v1.json",
            json!({
                "schema":"auths.profile-qualification-operation-plans/1",
                "domain":arguments.domain,
                "plans":[{
                    "scenarioIds":scenarios,
                    "operations":[{
                        "role":"effect",
                        "profile":profile,
                        "lifecycleOwner":true,
                        "providerMutationOwner":true
                    }]
                }]
            }),
        ),
        ("failpoint-coverage-v1.json", failpoint_coverage),
    ] {
        fs::write(qualification_dir.join(name), canonical_json(&value)?)
            .map_err(|error| error.to_string())?;
    }
    fs::write(
        qualification_dir.join("provider-truth-v1.schema.json"),
        pretty_json(&json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "$id":format!("https://auths.dev/spec/v1/{}-qualification-provider-truth.schema.json",arguments.domain),
            "type":"object",
            "additionalProperties":false,
            "required":["schema","implemented"],
            "properties":{
                "schema":{"const":format!("auths.{}.qualification-provider-truth/1",arguments.domain)},
                "implemented":{"const":false}
            }
        }))?,
    )
    .map_err(|error| error.to_string())
}

fn qualification_requirements_value(
    arguments: &NewProfileArguments,
    domain_scenario: &str,
    profile: &str,
) -> Value {
    json!({
        "schema":"auths.profile-qualification-requirements/1",
        "domain":arguments.domain,
        "requirements":[{
            "requirementId":format!("{}-{}-prerequisite",arguments.domain,arguments.effect),
            "profileReferences":[profile],
            "authoritativeSpecPath":format!("docs/specs/TODO-{}-{}.md",arguments.domain,arguments.effect),
            "authoritativeSpecSection":"1.1 Prerequisite implementation closure",
            "productionSourceOwners":[format!("product/integrations/auths-{}/src/{}/mod.rs",arguments.domain,arguments.effect)],
            "unitTests":[format!("product/integrations/auths-{}/tests/reference_semantics.rs",arguments.domain)],
            "mutationTests":[format!("product/integrations/auths-{}/tests/mutations.rs",arguments.domain)],
            "liveScenarioIds":[domain_scenario],
            "crashPointIds":[
                "crash-after-command",
                "crash-after-decision",
                "crash-after-entry-marker",
                "crash-after-execution-receipt",
                "crash-after-lease",
                "crash-after-observation",
                "crash-after-provider-result",
                "crash-after-request-write",
                "crash-after-reread",
                "crash-after-reservation",
                "crash-after-terminal",
                "crash-before-decision"
            ],
            "receiptClaimIds":[format!("{}.{}.claims",arguments.domain,arguments.effect)],
            "providerTruthReportFields":["implemented","schema"],
            "credentialRole":"none"
        }]
    })
}

fn write_qualification_entrypoint(
    repository: &Path,
    arguments: &NewProfileArguments,
) -> Result<(), String> {
    let workflow_dir = repository.join(".github/workflows");
    fs::create_dir_all(&workflow_dir).map_err(|error| error.to_string())?;
    let domain = arguments.domain.as_str();
    let title = pascal(domain);
    let workflow = format!(
        "name: Qualify {title} profiles\n\non:\n  workflow_dispatch:\n    inputs:\n      candidate_revision:\n        description: Exact 40-character candidate Git revision\n        required: true\n        type: string\n      release_build_run_id:\n        description: Immutable successful official release workflow run ID\n        required: true\n        type: string\n      release_build_artifact_id:\n        description: Immutable canonical release-build artifact ID\n        required: true\n        type: string\n      release_build_artifact_digest:\n        description: SHA-256 of the uploaded canonical release-build archive\n        required: true\n        type: string\n\npermissions:\n  actions: read\n  attestations: read\n  contents: read\n\njobs:\n  qualify:\n    uses: ./.github/workflows/profile-qualification.yml\n    with:\n      candidate_revision: ${{{{ inputs.candidate_revision }}}}\n      release_build_run_id: ${{{{ inputs.release_build_run_id }}}}\n      release_build_artifact_id: ${{{{ inputs.release_build_artifact_id }}}}\n      release_build_artifact_digest: ${{{{ inputs.release_build_artifact_digest }}}}\n      domain: {domain}\n      target: linux-x86_64\n      protected_environment: qualification-{domain}\n"
    );
    fs::write(
        workflow_dir.join(format!("profile-qualification-{domain}.yml")),
        workflow,
    )
    .map_err(|error| error.to_string())
}

fn scaffold_existing_profile(
    repository: &Path,
    arguments: &NewProfileArguments,
    package_root: &Path,
) -> Result<(), String> {
    let manifest_path = package_root.join("profile-package.json");
    let api_path = package_root.join("api/profile-api.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let mut api: Value =
        serde_json::from_slice(&fs::read(&api_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let effect_class = pascal(&arguments.effect);
    let input_type = format!("{effect_class}Input");
    let success_type = format!("{effect_class}Result");
    let types = api
        .get_mut("types")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "existing profile API types are malformed".to_owned())?;
    if types.contains_key(&input_type) || types.contains_key(&success_type) {
        return Err("profile effect collides with an existing generated type".into());
    }
    for path in [
        package_root.join("src").join(&arguments.effect),
        package_root
            .join("errors")
            .join(format!("{}-v{}.json", arguments.effect, arguments.version)),
        package_root
            .join("fixtures")
            .join(&arguments.effect)
            .join(format!("v{}", arguments.version)),
    ] {
        if path.exists() {
            return Err(format!(
                "profile effect source, error, or fixture path already exists: {}",
                path.display()
            ));
        }
    }
    types.insert(
        input_type.clone(),
        json!({"kind":"record","fields":[{"name":"value","value":{"kind":"string","minimumBytes":1,"maximumBytes":128,"alphabet":"utf8"},"sensitive":false}]}),
    );
    types.insert(
        success_type.clone(),
        json!({"kind":"record","fields":[{"name":"id","value":{"kind":"string","minimumBytes":1,"maximumBytes":128,"alphabet":"registered-token"},"sensitive":false}]}),
    );
    let domain = arguments.domain.as_str();
    let effect = arguments.effect.as_str();
    let version = arguments.version;
    let profile_id = format!("auths.{domain}.{effect}");
    let credential_scope = manifest
        .pointer("/domain/connection/providerKind")
        .and_then(Value::as_str)
        .map(|provider| Value::String(format!("{provider}.{effect}.execute/{version}")))
        .unwrap_or(Value::Null);
    let profiles = manifest
        .get_mut("profiles")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "existing profile manifest is malformed".to_owned())?;
    if profiles.iter().any(|profile| {
        profile.get("id").and_then(Value::as_str) == Some(&profile_id)
            && profile.get("version").and_then(Value::as_u64) == Some(u64::from(version))
    }) {
        return Err(format!(
            "profile semantic subject already exists: {profile_id}/{version}"
        ));
    }
    profiles.push(json!({
        "id":profile_id,
        "version":version,
        "semanticSubject":format!("auths.{domain}.{effect}/{version}"),
        "effectId":format!("{domain}.{effect}.execute"),
        "client":{"group":effect,"method":"execute","inputType":input_type,"successType":success_type,"partialType":null,"progressType":null},
        "contracts":{
            "canonicalAction":format!("auths.{domain}.{effect}-action/{version}"),
            "evaluator":format!("auths.{domain}.{effect}-evaluator/{version}"),
            "lifecycle":format!("auths.{domain}.{effect}-lifecycle/{version}"),
            "provider":format!("auths.{domain}.{effect}-provider/{version}"),
            "receipt":format!("auths.{domain}.{effect}-receipt/{version}"),
            "credentialScope":credential_scope,
            "errorOwner":format!("{domain}-{effect}"),
            "errorOwnerVersion":version
        },
        "limits":{"requestBytes":262144,"responseBytes":262144,"receiptCount":4,"receiptBytes":65536,"executionMilliseconds":30000,"admissionsPerMinute":600,"activePerPrincipal":64,"unresolvedPerPrincipal":16,"durableBytesPerPrincipal":67108864u64,"tombstonesPerPrincipal":100000,"terminalRetentionSeconds":2592000,"idempotencyRetentionSeconds":2592000},
        "sources":{
            "specification":format!("docs/specs/TODO-{domain}-{effect}.md"),
            "action":format!("product/integrations/auths-{domain}/src/{effect}/action.rs"),
            "evaluator":format!("product/integrations/auths-{domain}/src/{effect}/evaluator.rs"),
            "command":format!("product/integrations/auths-{domain}/src/{effect}/command.rs"),
            "lifecycle":format!("product/integrations/auths-{domain}/src/{effect}/lifecycle.rs"),
            "gateway":format!("product/integrations/auths-{domain}/src/{effect}/gateway.rs"),
            "reconciliation":format!("product/integrations/auths-{domain}/src/{effect}/reconciliation.rs"),
            "receipt":format!("product/integrations/auths-{domain}/src/{effect}/receipt.rs"),
            "errors":format!("product/integrations/auths-{domain}/errors/{effect}-v{version}.json"),
            "errorMapping":format!("product/integrations/auths-{domain}/src/{effect}/errors.rs")
        },
        "evidence":{
            "fixtures":format!("product/integrations/auths-{domain}/fixtures/{effect}/v{version}"),
            "mutationCorpus":format!("product/integrations/auths-{domain}/tests/{effect}_mutations.rs"),
            "providerRequests":format!("product/integrations/auths-{domain}/tests/{effect}_provider_requests.rs"),
            "demo":format!("demos/{domain}-{effect}"),
            "liveContract":format!("demos/{domain}-{effect}/tests/live-contract.rs")
        }
    }));
    profiles.sort_by(|left, right| {
        (
            left.get("id").and_then(Value::as_str).unwrap_or_default(),
            left.get("version")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        )
            .cmp(&(
                right.get("id").and_then(Value::as_str).unwrap_or_default(),
                right
                    .get("version")
                    .and_then(Value::as_u64)
                    .unwrap_or_default(),
            ))
    });
    let qualification_family = profiles
        .iter()
        .map(|profile| {
            profile
                .get("semanticSubject")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| "profile semanticSubject is missing".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let qualification = manifest
        .get_mut("qualification")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "existing profile qualification declaration is malformed".to_owned())?;
    qualification.insert("family".to_owned(), json!(qualification_family));
    let lib_path = package_root.join("src/lib.rs");
    let mut lib = fs::read_to_string(&lib_path).map_err(|error| error.to_string())?;
    let module_line = format!("pub mod {};", rust_field(effect));
    if lib.lines().any(|line| line.trim() == module_line) {
        return Err(format!(
            "profile effect source module already exists: {effect}"
        ));
    }
    if !lib.ends_with('\n') {
        lib.push('\n');
    }
    writeln!(lib, "{module_line}").map_err(|error| error.to_string())?;
    write_profile_effect_scaffold(arguments, package_root)?;
    append_existing_domain_local_agent_scaffold(arguments, package_root)?;
    fs::write(lib_path, lib).map_err(|error| error.to_string())?;
    fs::write(api_path, pretty_json(&api)?).map_err(|error| error.to_string())?;
    fs::write(manifest_path, pretty_json(&manifest)?).map_err(|error| error.to_string())?;
    register_existing_profile_in_roster(repository, domain, &format!("{profile_id}/{version}"))?;
    write_profile_reference_scaffold(repository, arguments)?;
    generate_at(repository, domain, false, true)?;
    println!(
        "scaffolded {profile_id}/{version}; complete every explicit TODO, then regenerate {domain}"
    );
    Ok(())
}

fn append_existing_domain_local_agent_scaffold(
    arguments: &NewProfileArguments,
    package_root: &Path,
) -> Result<(), String> {
    let prefix = format!("{}_execute", rust_field(&arguments.effect));
    let path = package_root.join("src/local_agent.rs");
    let mut source = fs::read_to_string(&path).map_err(|error| error.to_string())?;
    if source.contains(&format!("pub fn {prefix}_prepare(")) {
        return Err(format!(
            "profile local-agent entry points already exist: {prefix}"
        ));
    }
    if !source.ends_with('\n') {
        source.push('\n');
    }
    writeln!(
        source,
        "\n/// TODO(auths-profile): implement bounded preparation and exact authority mapping.\npub fn {prefix}_prepare(_input: auths_profile_runtime::PrepareProfileInput<'_>) -> Result<auths_profile_runtime::ProfilePreparation, auths_profile_runtime::ProfileRuntimeError> {{ Err(auths_profile_runtime::ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): build bounded canonical decision claims from immutable preparation facts.\npub fn {prefix}_build_decision_receipt_claims(_facts: auths_profile_runtime::ProfileDecisionReceiptFacts<'_>) -> Result<Vec<u8>, auths_profile_runtime::ProfileRuntimeError> {{ Err(auths_profile_runtime::ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): build bounded canonical execution claims from the immutable mint-time basis.\npub fn {prefix}_build_execution_receipt_claims(_facts: auths_profile_runtime::ProfileExecutionReceiptFacts<'_>) -> Result<Vec<u8>, auths_profile_runtime::ProfileRuntimeError> {{ Err(auths_profile_runtime::ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): independently inspect signed claims against immutable and current terminal truth.\npub fn {prefix}_inspect_receipt_claims(_inspection: auths_profile_runtime::ProfileReceiptInspection<'_>) -> Result<(), auths_profile_runtime::ProfileRuntimeError> {{ Err(auths_profile_runtime::ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): seal the credential-free command and any domain reservation.\npub async fn {prefix}_seal_provider_call(_input: auths_profile_runtime::SealProfileCallInput<'_>) -> Result<auths_profile_runtime::SealedProfileCall, auths_profile_runtime::ProfileRuntimeError> {{ Err(auths_profile_runtime::ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): perform the protected critical reread after command durability.\npub fn {prefix}_recheck_pre_entry(_input: auths_profile_runtime::PreEntryRecheckInput<'_>) -> Result<auths_profile_runtime::ProfilePreEntryRecheck, auths_profile_runtime::ProfileRuntimeError> {{ Err(auths_profile_runtime::ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): release profile-owned state only with durable proof of no provider entry.\npub fn {prefix}_release_pre_entry(_input: auths_profile_runtime::ReleaseProfileCallInput<'_>) -> Result<(), auths_profile_runtime::ProfileRuntimeError> {{ Err(auths_profile_runtime::ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): implement the one closed provider command.\npub async fn {prefix}_call_provider(_input: auths_profile_runtime::CallProviderInput<'_>) -> Result<Vec<u8>, auths_profile_runtime::ProfileRuntimeError> {{ Err(auths_profile_runtime::ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): classify only a durable provider result.\npub fn {prefix}_observe_provider_result(_input: auths_profile_runtime::ObserveProviderResultInput<'_>) -> Result<auths_profile_runtime::ProfileObservation, auths_profile_runtime::ProfileRuntimeError> {{ Err(auths_profile_runtime::ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): observe the original attempt without blind retry.\npub async fn {prefix}_reconcile(_input: auths_profile_runtime::ReconcileProfileInput<'_>) -> Result<auths_profile_runtime::ProfileObservation, auths_profile_runtime::ProfileRuntimeError> {{ Err(auths_profile_runtime::ProfileRuntimeError::Invalid) }}"
    )
    .map_err(|error| error.to_string())?;
    fs::write(path, source).map_err(|error| error.to_string())
}

fn register_existing_profile_in_roster(
    repository: &Path,
    domain: &str,
    semantic_subject: &str,
) -> Result<(), String> {
    let roster_path = repository.join("product/runtime/auths-node/profile-packages.json");
    let mut roster: Value =
        serde_json::from_slice(&fs::read(&roster_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let package = roster
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .and_then(|packages| {
            packages
                .iter_mut()
                .find(|entry| entry.get("domain").and_then(Value::as_str) == Some(domain))
        })
        .ok_or_else(|| format!("profile roster domain is missing: {domain}"))?;
    let profiles = package
        .get_mut("profiles")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| format!("profile roster profiles are malformed: {domain}"))?;
    if profiles
        .iter()
        .any(|profile| profile.get("profile").and_then(Value::as_str) == Some(semantic_subject))
    {
        return Err(format!(
            "profile roster semantic subject already exists: {semantic_subject}"
        ));
    }
    profiles.push(json!({
        "profile": semantic_subject,
        "state": "unqualified",
        "testkitAvailable": false,
        "targets": [],
        "qualificationIds": [],
    }));
    profiles.sort_by(|left, right| {
        left.get("profile")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(
                right
                    .get("profile")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
    });
    let roster_bytes = pretty_json(&roster)?;
    ProfileRoster::from_json(roster_bytes.as_bytes()).map_err(|error| error.to_string())?;
    fs::write(roster_path, roster_bytes).map_err(|error| error.to_string())
}

fn write_new_profile_scaffold(
    arguments: &NewProfileArguments,
    package_root: &Path,
) -> Result<(), String> {
    let domain = arguments.domain.as_str();
    fs::write(
        package_root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"auths-{domain}\"\nversion.workspace = true\nedition.workspace = true\nlicense.workspace = true\nrust-version.workspace = true\npublish = false\n\n[features]\nqualification = [\"dep:auths-profile-kit\"]\n\n[dependencies]\nasync-trait.workspace = true\nauths-connections.workspace = true\nauths-errors.workspace = true\nauths-profile-kit = {{ workspace = true, optional = true }}\nauths-profile-runtime.workspace = true\nminicbor.workspace = true\nserde.workspace = true\nserde_json.workspace = true\nserde_json_canonicalizer.workspace = true\nsha2.workspace = true\nthiserror.workspace = true\n\n[lints]\nworkspace = true\n"
        ),
    )
    .map_err(|error| error.to_string())?;
    let mut modules = String::from(
        "//! Profile-owned semantics. Generated files contain no policy.\n\n#![forbid(unsafe_code)]\n\npub mod generated;\npub mod local_agent;\n#[cfg(feature = \"qualification\")]\npub mod qualification;\n",
    );
    if matches!(arguments.mode, NewProfileMode::Connected { .. }) {
        modules.push_str("pub mod connection;\n");
    }
    writeln!(modules, "pub mod {};", rust_field(&arguments.effect))
        .map_err(|error| error.to_string())?;
    fs::create_dir_all(package_root.join("src/generated")).map_err(|error| error.to_string())?;
    fs::write(package_root.join("src/lib.rs"), modules).map_err(|error| error.to_string())?;
    let prefix = format!("{}_execute", rust_field(&arguments.effect));
    fs::write(
        package_root.join("src/local_agent.rs"),
        format!(
            "//! Fail-closed static entry points. Replace each TODO before qualification.\n\n#![forbid(unsafe_code)]\n\nuse auths_profile_runtime::{{CallProviderInput, ObserveProviderResultInput, PrepareProfileInput, ProfileDecisionReceiptFacts, ProfileExecutionReceiptFacts, ProfileObservation, ProfilePreparation, ProfileReceiptInspection, ProfileRuntimeError, ReconcileProfileInput, ReleaseProfileCallInput, SealProfileCallInput, SealedProfileCall}};\n\n/// TODO(auths-profile): implement bounded preparation and exact authority mapping.\npub fn {prefix}_prepare(_input: PrepareProfileInput<'_>) -> Result<ProfilePreparation, ProfileRuntimeError> {{ Err(ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): build bounded canonical decision claims from immutable preparation facts.\npub fn {prefix}_build_decision_receipt_claims(_facts: ProfileDecisionReceiptFacts<'_>) -> Result<Vec<u8>, ProfileRuntimeError> {{ Err(ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): build bounded canonical execution claims from the immutable mint-time basis.\npub fn {prefix}_build_execution_receipt_claims(_facts: ProfileExecutionReceiptFacts<'_>) -> Result<Vec<u8>, ProfileRuntimeError> {{ Err(ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): independently inspect signed claims against immutable and current terminal truth.\npub fn {prefix}_inspect_receipt_claims(_inspection: ProfileReceiptInspection<'_>) -> Result<(), ProfileRuntimeError> {{ Err(ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): implement fresh re-verification and credential-free sealing.\npub async fn {prefix}_seal_provider_call(_input: SealProfileCallInput<'_>) -> Result<SealedProfileCall, ProfileRuntimeError> {{ Err(ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): release profile-owned state only with durable proof of no provider entry.\npub fn {prefix}_release_pre_entry(_input: ReleaseProfileCallInput<'_>) -> Result<(), ProfileRuntimeError> {{ Err(ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): implement the one closed provider command.\npub async fn {prefix}_call_provider(_input: CallProviderInput<'_>) -> Result<Vec<u8>, ProfileRuntimeError> {{ Err(ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): classify only a durable provider result.\npub fn {prefix}_observe_provider_result(_input: ObserveProviderResultInput<'_>) -> Result<ProfileObservation, ProfileRuntimeError> {{ Err(ProfileRuntimeError::Invalid) }}\n\n/// TODO(auths-profile): observe the original attempt without blind retry.\npub async fn {prefix}_reconcile(_input: ReconcileProfileInput<'_>) -> Result<ProfileObservation, ProfileRuntimeError> {{ Err(ProfileRuntimeError::Invalid) }}\n"
        ),
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        package_root.join("src/qualification.rs"),
        qualification_adapter_scaffold(arguments)?,
    )
    .map_err(|error| error.to_string())?;
    if let NewProfileMode::Connected {
        provider,
        connection_version,
    } = &arguments.mode
    {
        let connection = package_root.join("src/connection");
        let scope = format!(
            "{provider}.{}.execute/{}",
            arguments.effect, arguments.version
        );
        let contract = format!("auths.{provider}.connection/{connection_version}");
        let descriptor_schema =
            format!("auths.{provider}.connection-descriptor/{connection_version}");
        fs::write(
            connection.join("mod.rs"),
            format!(
                "//! Draft fail-closed {provider} connection boundary.\n\npub mod admin_routes;\nmod credentials;\nmod descriptor;\nmod onboarding;\n\npub use credentials::DraftConnectionAdapter;\npub use descriptor::DraftConnectionDescriptor;\npub use onboarding::validate_onboarding;\n\n#[must_use]\npub fn adapter() -> DraftConnectionAdapter {{ DraftConnectionAdapter::new() }}\n"
            ),
        )
        .map_err(|error| error.to_string())?;
        fs::write(
            connection.join("admin_routes.rs"),
            format!(
                "//! Draft privileged routes; onboarding remains fail-closed.\n\npub const START: &str = \"/v1/admin/providers/{provider}/connections/start\";\npub const COMPLETE: &str = \"/v1/admin/providers/{provider}/connections/complete\";\n"
            ),
        )
        .map_err(|error| error.to_string())?;
        fs::write(
            connection.join("descriptor.rs"),
            format!(
                "//! Draft immutable descriptor. Replace the account identity fields before qualification.\n\nuse auths_connections::{{ConnectionAdapterError, ValidatedConnectionDescriptor}};\nuse serde::{{Deserialize, Serialize}};\nuse sha2::{{Digest as _, Sha256}};\n\n#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]\n#[serde(rename_all = \"camelCase\", deny_unknown_fields)]\npub struct DraftConnectionDescriptor {{ schema: String, account_identity: String, allowed_scopes: Vec<String> }}\n\nimpl DraftConnectionDescriptor {{\n    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ConnectionAdapterError> {{\n        if bytes.is_empty() || bytes.len() > 65_536 {{ return Err(ConnectionAdapterError::InvalidDescriptor); }}\n        let value: Self = serde_json::from_slice(bytes).map_err(|_| ConnectionAdapterError::InvalidDescriptor)?;\n        if value.schema != {descriptor_schema:?} || !(1..=512).contains(&value.account_identity.len()) || !value.account_identity.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) || value.allowed_scopes.as_slice() != [{scope:?}] || serde_json_canonicalizer::to_vec(&value).map_err(|_| ConnectionAdapterError::InvalidDescriptor)?.as_slice() != bytes {{ return Err(ConnectionAdapterError::InvalidDescriptor); }}\n        Ok(value)\n    }}\n    pub fn account_commitment(&self) -> [u8; 32] {{ let mut digest = Sha256::new(); digest.update(b\"auths.draft-provider-account/1\\0\"); digest.update(self.account_identity.as_bytes()); digest.finalize().into() }}\n    pub fn validated(&self) -> Result<ValidatedConnectionDescriptor, ConnectionAdapterError> {{ ValidatedConnectionDescriptor::from_adapter(serde_json_canonicalizer::to_vec(self).map_err(|_| ConnectionAdapterError::InvalidDescriptor)?, self.account_commitment()) }}\n}}\n"
            ),
        )
        .map_err(|error| error.to_string())?;
        fs::write(
            connection.join("credentials.rs"),
            format!(
                "//! Draft adapter. Credential leasing intentionally fails until provider semantics are implemented.\n\nuse super::DraftConnectionDescriptor;\nuse async_trait::async_trait;\nuse auths_connections::{{ConnectionAdapterError, ConnectionBinding, ConnectionCredentialStore, CredentialScope, ProviderConnectionAdapter, ProviderCredentialLease, ValidatedConnectionDescriptor}};\nuse std::time::Instant;\n\npub struct DraftConnectionAdapter;\nimpl DraftConnectionAdapter {{ #[must_use] pub const fn new() -> Self {{ Self }} }}\nimpl Default for DraftConnectionAdapter {{ fn default() -> Self {{ Self::new() }} }}\n\n#[async_trait]\nimpl ProviderConnectionAdapter for DraftConnectionAdapter {{\n    fn provider_kind(&self) -> &'static str {{ {provider:?} }}\n    fn contract_id(&self) -> &'static str {{ {contract:?} }}\n    fn descriptor_schema(&self) -> &'static str {{ {descriptor_schema:?} }}\n    fn validate_descriptor(&self, bytes: &[u8]) -> Result<ValidatedConnectionDescriptor, ConnectionAdapterError> {{ DraftConnectionDescriptor::from_canonical_bytes(bytes)?.validated() }}\n    fn permits_scope(&self, descriptor: &ValidatedConnectionDescriptor, scope: &CredentialScope) -> Result<(), ConnectionAdapterError> {{ let parsed = DraftConnectionDescriptor::from_canonical_bytes(descriptor.bytes())?; if parsed.account_commitment() != *descriptor.account_commitment() || scope.as_str() != {scope:?} {{ return Err(ConnectionAdapterError::ScopeDenied); }} Ok(()) }}\n    async fn lease_credential<S: ConnectionCredentialStore + Sync>(&self, _binding: &ConnectionBinding, _scope: &CredentialScope, _store: &S, _deadline: Instant) -> Result<ProviderCredentialLease, ConnectionAdapterError> {{ Err(ConnectionAdapterError::PreparationFailed) }}\n}}\n"
            ),
        )
        .map_err(|error| error.to_string())?;
        fs::write(
            connection.join("onboarding.rs"),
            "//! Draft onboarding deliberately refuses every secret until account discovery is implemented.\n\nuse auths_connections::{ConnectionAdapterError, SecretBytes};\n\npub fn validate_onboarding(_descriptor: &[u8], mut secret: Vec<u8>) -> Result<SecretBytes, ConnectionAdapterError> { secret.fill(0); Err(ConnectionAdapterError::PreparationFailed) }\n",
        )
        .map_err(|error| error.to_string())?;
        fs::write(
            package_root.join("tests/connection_conformance.rs"),
            "//! TODO(auths-profile): run the complete provider connection conformance suite.\n",
        )
        .map_err(|error| error.to_string())?;
    }
    write_profile_effect_scaffold(arguments, package_root)
}

fn qualification_adapter_scaffold(arguments: &NewProfileArguments) -> Result<String, String> {
    let domain = arguments.domain.as_str();
    let adapter = format!("{}QualificationAdapter", pascal(domain));
    let profile = format!("auths.{domain}.{}/{}", arguments.effect, arguments.version);
    let scenario = format!("{domain}-{}-live", arguments.effect);
    let provider = match &arguments.mode {
        NewProfileMode::Connected { provider, .. } => provider.as_str(),
        NewProfileMode::Connectionless => domain,
        NewProfileMode::ExistingDomain => domain,
    };
    let requirements = qualification_requirements_value(arguments, &scenario, &profile);
    let requirements_sha256 = hex::encode(Sha256::digest(canonical_json(&requirements)?));
    Ok(format!(
        "//! Qualification-only adapter scaffold. Every method remains fail-closed until live closure.\n\n\
use auths_profile_kit::{{QualificationAdapterMetadata, QualificationCleanupEvidence, QualificationCollectedOperation, QualificationCollectionAdapter, QualificationCommonOperationInstanceEvidence, QualificationCommonReceiptClaims, QualificationEffect, QualificationHarnessError, QualificationOperationRole, QualificationPhaseClient, QualificationProtectedObserver, QualificationProviderTruth, QualificationRunContext, QualificationRunReference, QualificationSetupHandoffV1, QualificationTarget, QualificationVector}};\n\n\
pub struct {adapter};\n\n\
pub fn qualification_requirement_ids() -> &'static [&'static str] {{ &[{requirement_id:?}] }}\n\n\
pub const fn qualification_requirements_sha256() -> &'static str {{ {requirements_sha256:?} }}\n\n\
pub fn qualification_domain_scenario_ids() -> &'static [&'static str] {{ &[{scenario:?}] }}\n\n\
pub fn qualification_receipt_claim_ids() -> &'static [&'static str] {{ &[{receipt_claim:?}] }}\n\n\
pub fn qualification_provider_truth_fields() -> &'static [&'static str] {{ &[\"implemented\", \"schema\"] }}\n\n\
pub fn qualification_forbidden_evidence_fields() -> &'static [&'static str] {{ &[] }}\n\n\
pub fn qualification_redaction_prefixes() -> &'static [&'static str] {{ &[] }}\n\n\
pub fn qualification_provider_matrix_rows() -> &'static [(&'static str, &'static str, &'static str, &'static str, &'static str)] {{ &[({provider_run:?}, {provider:?}, \"unimplemented\", \"0000000000000000000000000000000000000000000000000000000000000000\", \"linux-x86_64\")] }}\n\n\
pub fn qualification_operation_plan() -> &'static [(QualificationOperationRole, &'static str, bool, bool)] {{ &[(QualificationOperationRole::Effect, {profile:?}, true, true)] }}\n\n\
impl QualificationCollectionAdapter for {adapter} {{\n\
    type Environment = ();\n\
    fn metadata(&self) -> QualificationAdapterMetadata {{ metadata() }}\n\
    fn open(&self, _context: &QualificationRunContext, _handoff: &QualificationSetupHandoffV1) -> Result<(), QualificationHarnessError> {{ Err(unavailable()) }}\n\
    fn invoke_phase(&self, _environment: &mut (), _client: &QualificationPhaseClient, _connection_alias: &str, _vector: &QualificationVector, _phase_index: u8, _role: QualificationOperationRole, _profile: &str) -> Result<QualificationCollectedOperation, QualificationHarnessError> {{ Err(unavailable()) }}\n\
}}\n\n\
impl QualificationProtectedObserver for {adapter} {{\n\
    type Environment = ();\n\
    fn metadata(&self) -> QualificationAdapterMetadata {{ metadata() }}\n\
    fn open(&self, _context: &QualificationRunContext, _reference: Option<&QualificationRunReference>) -> Result<(), QualificationHarnessError> {{ Err(unavailable()) }}\n\
    fn provider_truth(&self, _environment: &(), _phase: &QualificationCollectedOperation, _instance: &QualificationCommonOperationInstanceEvidence) -> Result<QualificationProviderTruth, QualificationHarnessError> {{ Err(unavailable()) }}\n\
    fn validate_receipt_payload(&self, _environment: &(), _phase: &QualificationCollectedOperation, _instance: &QualificationCommonOperationInstanceEvidence, _truth: &QualificationProviderTruth, _claims: &[QualificationCommonReceiptClaims]) -> Result<(), QualificationHarnessError> {{ Err(unavailable()) }}\n\
    fn cleanup(&self, _context: &QualificationRunContext, _reference: Option<&QualificationRunReference>) -> Result<QualificationCleanupEvidence, QualificationHarnessError> {{ Err(unavailable()) }}\n\
}}\n\n\
pub fn validate_provider_truth_facts(_bytes: &[u8], _effect: QualificationEffect) -> Result<(), QualificationHarnessError> {{ Err(unavailable()) }}\n\n\
pub fn validate_provider_matrix_contract(bytes: &[u8], provider_version: &str, provider_artifact_sha256: &str) -> Result<(), QualificationHarnessError> {{\n\
    let expected = serde_json::json!({{\"implemented\":false,\"schema\":{matrix_schema:?}}});\n\
    if provider_version != \"unimplemented\" || provider_artifact_sha256 != \"0000000000000000000000000000000000000000000000000000000000000000\" || serde_json_canonicalizer::to_vec(&expected).map_err(|_| QualificationHarnessError::ProviderTruth)? != bytes {{ return Err(unavailable()); }}\n\
    Ok(())\n\
}}\n\n\
fn metadata() -> QualificationAdapterMetadata {{ QualificationAdapterMetadata {{ domain: {domain:?}, family: &[{profile:?}], targets: &[QualificationTarget::LinuxX86_64], protected_environment: {environment:?}, scenarios: &[{scenario:?}] }} }}\n\n\
fn unavailable() -> QualificationHarnessError {{ QualificationHarnessError::PrerequisiteUnavailable(\"generated provider qualification adapter is incomplete\") }}\n",
        environment = format!("qualification-{domain}"),
        matrix_schema = format!("auths.{domain}.qualification-provider-contract/1"),
        receipt_claim = format!("{domain}.{}.claims", arguments.effect),
        requirement_id = format!("{domain}-{}-prerequisite", arguments.effect),
        provider_run = format!("{domain}-protected-live"),
    ))
}

fn write_profile_effect_scaffold(
    arguments: &NewProfileArguments,
    package_root: &Path,
) -> Result<(), String> {
    let effect = arguments.effect.as_str();
    let version = arguments.version;
    let effect_dir = package_root.join("src").join(effect);
    let fixture_dir = package_root
        .join("fixtures")
        .join(effect)
        .join(format!("v{version}"));
    fs::create_dir_all(&effect_dir).map_err(|error| error.to_string())?;
    fs::create_dir_all(&fixture_dir).map_err(|error| error.to_string())?;
    fs::create_dir_all(package_root.join("tests")).map_err(|error| error.to_string())?;
    let modules = [
        "action",
        "evaluator",
        "command",
        "lifecycle",
        "gateway",
        "reconciliation",
        "receipt",
        "errors",
        "routes",
    ];
    fs::write(
        effect_dir.join("mod.rs"),
        modules
            .iter()
            .map(|name| format!("mod {name};"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
    .map_err(|error| error.to_string())?;
    for name in modules {
        fs::write(
            effect_dir.join(format!("{name}.rs")),
            format!(
                "//! TODO(auths-profile): implement the exact {effect}/{version} {name} contract.\n"
            ),
        )
        .map_err(|error| error.to_string())?;
    }
    let owner = format!("{}-{effect}", arguments.domain);
    let fragment = json!({
        "schema":"auths.error-registry-fragment/1",
        "owner":owner,
        "ownerVersion":version,
        "definitions":[
            {"code":format!("{}.{}-denied",arguments.domain,effect),"operation":"execute","stage":"profile-evaluation","effect":"not-applied","retry":"satisfy-condition","action":"inspect-input","summary":format!("The exact {effect} request was denied.")},
            {"code":format!("{}.{}-outcome-unknown",arguments.domain,effect),"operation":"execute","stage":"provider-observation","effect":"possible","retry":"recover-only","action":"recover","summary":format!("The {effect} provider outcome requires recovery.")}
        ]
    });
    fs::create_dir_all(package_root.join("errors")).map_err(|error| error.to_string())?;
    fs::write(
        package_root
            .join("errors")
            .join(format!("{effect}-v{version}.json")),
        pretty_json(&fragment)?,
    )
    .map_err(|error| error.to_string())?;
    for (name, contents) in [
        ("valid.json", "{\"todo\":\"canonical positive fixture\"}\n"),
        ("malformed.json", "{\"todo\":\"malformed fixture\"}\n"),
        ("maximum.json", "{\"todo\":\"inclusive maximum fixture\"}\n"),
        (
            "maximum-plus-one.json",
            "{\"todo\":\"boundary plus one fixture\"}\n",
        ),
    ] {
        fs::write(fixture_dir.join(name), contents).map_err(|error| error.to_string())?;
    }
    let test_prefix = if arguments.mode == NewProfileMode::ExistingDomain {
        format!("{effect}_")
    } else {
        String::new()
    };
    for name in [
        "reference_semantics",
        "mutations",
        "lifecycle",
        "provider_requests",
        "receipts",
    ] {
        let path = package_root
            .join("tests")
            .join(format!("{test_prefix}{name}.rs"));
        if path.exists() {
            return Err(format!(
                "refusing to overwrite scaffold evidence: {}",
                path.display()
            ));
        }
        fs::write(
            path,
            format!("//! TODO(auths-profile): implement {effect}/{version} {name} evidence.\n"),
        )
        .map_err(|error| error.to_string())?;
    }
    let readme = package_root.join("README.md");
    if !readme.exists() {
        fs::write(
            readme,
            format!(
                "# {} {}\n\nStatus: specified, not qualified. Complete every generated TODO and the AP-SPEC-040 qualification gate before publishing.\n",
                arguments.domain, effect
            ),
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn write_profile_reference_scaffold(
    repository: &Path,
    arguments: &NewProfileArguments,
) -> Result<(), String> {
    let domain = arguments.domain.as_str();
    let effect = arguments.effect.as_str();
    let specification = repository.join(format!("docs/specs/TODO-{domain}-{effect}.md"));
    if !specification.exists() {
        if let Some(parent) = specification.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        fs::write(
            &specification,
            format!(
                "# {domain} {effect} profile\n\nStatus: specified, not qualified.\n\n### 1.1 Prerequisite implementation closure\n\nTODO(auths-profile): replace this file with the complete bounded semantic contract required by AP-SPEC-040.\n"
            ),
        )
        .map_err(|error| error.to_string())?;
    }
    if let NewProfileMode::Connected { provider, .. } = &arguments.mode {
        let connection = repository.join(format!("docs/specs/TODO-{provider}-connection.md"));
        if !connection.exists() {
            fs::write(
                connection,
                format!(
                    "# {provider} connection\n\nStatus: specified, not qualified.\n\nTODO(auths-profile): define immutable account identity, onboarding, least-privilege scopes, rotation, revocation, and reconciliation credential behavior.\n"
                ),
            )
            .map_err(|error| error.to_string())?;
        }
    }
    let demo = repository.join(format!("demos/{domain}-{effect}"));
    fs::create_dir_all(demo.join("tests")).map_err(|error| error.to_string())?;
    let live_contract = demo.join("tests/live-contract.rs");
    if !live_contract.exists() {
        fs::write(
            live_contract,
            "//! TODO(auths-profile): prove one real provider effect, replay, denial, recovery, and receipt verification.\n",
        )
        .map_err(|error| error.to_string())?;
    }
    let inventory = repository.join(format!("docs/architecture/profiles/{domain}.md"));
    if let Some(parent) = inventory.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    if !inventory.exists() {
        fs::write(
            inventory,
            format!(
                "# {domain} profile package\n\nQualification: specified (not qualified).\n\nThis package is statically rostered. It MUST remain fail-closed until every AP-SPEC-040 promotion gate passes.\n"
            ),
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn register_new_domain(repository: &Path, arguments: &NewProfileArguments) -> Result<(), String> {
    let domain = arguments.domain.as_str();
    let rust_package = format!("auths-{domain}");
    let manifest_path = format!("product/integrations/auths-{domain}/profile-package.json");
    let roster_path = repository.join("product/runtime/auths-node/profile-packages.json");
    let mut roster: Value =
        serde_json::from_slice(&fs::read(&roster_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let packages = roster
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "profile roster packages are malformed".to_owned())?;
    if packages.len() >= 64
        || packages.iter().any(|entry| {
            entry.get("domain").and_then(Value::as_str) == Some(domain)
                || entry.get("rustPackage").and_then(Value::as_str) == Some(&rust_package)
                || entry.get("manifestPath").and_then(Value::as_str) == Some(&manifest_path)
        })
    {
        return Err("profile roster domain, package, or manifest path collides".into());
    }
    packages.push(json!({
        "domain": domain,
        "rustPackage": rust_package,
        "manifestPath": manifest_path,
        "profiles": [{
            "profile": format!("auths.{domain}.{}/{}", arguments.effect, arguments.version),
            "state": "unqualified",
            "testkitAvailable": false,
            "targets": [],
            "qualificationIds": [],
        }],
    }));
    packages.sort_by(|left, right| {
        left.get("domain")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(
                right
                    .get("domain")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
    });
    let roster_bytes = pretty_json(&roster)?;
    ProfileRoster::from_json(roster_bytes.as_bytes()).map_err(|error| error.to_string())?;
    fs::write(roster_path, roster_bytes).map_err(|error| error.to_string())?;

    let workspace_path = repository.join("Cargo.toml");
    let workspace = fs::read_to_string(&workspace_path).map_err(|error| error.to_string())?;
    let workspace =
        insert_workspace_member(&workspace, &format!("product/integrations/auths-{domain}"))?;
    let workspace = insert_toml_entry(
        &workspace,
        "[workspace.dependencies]",
        &rust_package,
        &format!(
            "{rust_package} = {{ version = \"1.0.0-rc.1\", path = \"product/integrations/auths-{domain}\" }}"
        ),
    )?;
    fs::write(workspace_path, workspace).map_err(|error| error.to_string())?;

    let node_manifest = repository.join("product/runtime/auths-node/Cargo.toml");
    let node = fs::read_to_string(&node_manifest).map_err(|error| error.to_string())?;
    let node = insert_toml_entry(
        &node,
        "[dependencies]",
        &rust_package,
        &format!("{rust_package}.workspace = true"),
    )?;
    fs::write(node_manifest, node).map_err(|error| error.to_string())?;

    let xtask_manifest = repository.join("xtask/Cargo.toml");
    let xtask = fs::read_to_string(&xtask_manifest).map_err(|error| error.to_string())?;
    let xtask = insert_toml_entry(
        &xtask,
        "[dependencies]",
        &rust_package,
        &format!("{rust_package} = {{ workspace = true, features = [\"qualification\"] }}"),
    )?;
    fs::write(xtask_manifest, xtask).map_err(|error| error.to_string())?;

    let architecture_path = repository.join("architecture.toml");
    let architecture = fs::read_to_string(&architecture_path).map_err(|error| error.to_string())?;
    let architecture = insert_toml_entry(
        &architecture,
        "[packages]",
        &rust_package,
        &format!("{rust_package} = \"product\""),
    )?;
    fs::write(architecture_path, architecture).map_err(|error| error.to_string())?;
    Ok(())
}

fn insert_workspace_member(contents: &str, member: &str) -> Result<String, String> {
    let needle = format!("    \"{member}\",");
    if contents.lines().any(|line| line == needle) {
        return Err(format!("workspace member already exists: {member}"));
    }
    let start = contents
        .find("members = [")
        .ok_or_else(|| "workspace members table is missing".to_owned())?;
    let relative_end = contents[start..]
        .find("\n]")
        .ok_or_else(|| "workspace members table is unterminated".to_owned())?;
    let end = start + relative_end;
    let mut output = String::with_capacity(contents.len() + needle.len() + 1);
    output.push_str(&contents[..end]);
    output.push('\n');
    output.push_str(&needle);
    output.push_str(&contents[end..]);
    Ok(output)
}

fn insert_toml_entry(
    contents: &str,
    section: &str,
    key: &str,
    entry: &str,
) -> Result<String, String> {
    let start = contents
        .find(section)
        .ok_or_else(|| format!("TOML section is missing: {section}"))?;
    let body_start = start + section.len();
    let end = contents[body_start..]
        .find("\n[")
        .map_or(contents.len(), |offset| body_start + offset);
    let key_prefix = format!("{key} =");
    if contents[body_start..end]
        .lines()
        .any(|line| line.trim_start().starts_with(&key_prefix))
    {
        return Err(format!("TOML entry already exists: {key}"));
    }
    let insertion = if contents[..end].ends_with('\n') {
        format!("{entry}\n")
    } else {
        format!("\n{entry}\n")
    };
    let mut output = String::with_capacity(contents.len() + insertion.len());
    output.push_str(&contents[..end]);
    output.push_str(&insertion);
    output.push_str(&contents[end..]);
    Ok(output)
}

pub(crate) fn generate(domain: &str, check: bool) -> Result<(), String> {
    let repository = root();
    generate_at(&repository, domain, check, true)
}

fn generate_at(
    repository: &Path,
    domain: &str,
    check: bool,
    validate_declarations: bool,
) -> Result<(), String> {
    if validate_declarations {
        crate::validate_qualification_state_for_generation(repository, domain)?;
    }
    let roster_path = repository.join("product/runtime/auths-node/profile-packages.json");
    let roster_bytes = fs::read(&roster_path).map_err(|error| error.to_string())?;
    let roster = ProfileRoster::from_json(&roster_bytes).map_err(|error| error.to_string())?;
    let entry = roster
        .packages()
        .iter()
        .find(|entry| entry.domain() == domain)
        .ok_or_else(|| format!("domain {domain} is not in the static profile roster"))?;
    let manifest_path = repository.join(entry.manifest_path());
    let package_root = manifest_path
        .parent()
        .ok_or_else(|| "manifest has no parent".to_owned())?;
    let manifest_bytes = fs::read(&manifest_path).map_err(|error| error.to_string())?;
    let manifest_json: Value =
        serde_json::from_slice(&manifest_bytes).map_err(|error| error.to_string())?;
    let api_relative = manifest_json
        .get("api")
        .and_then(Value::as_str)
        .ok_or_else(|| "manifest api path is absent".to_owned())?;
    let api_path = package_root.join(api_relative);
    let api_bytes = fs::read(&api_path).map_err(|error| error.to_string())?;
    let api = ProfileApi::from_json(&api_bytes).map_err(|error| error.to_string())?;
    let package =
        ProfilePackage::from_json(&manifest_bytes, &api).map_err(|error| error.to_string())?;
    let qualification_metadata = entry
        .profiles()
        .iter()
        .map(|profile| (profile.profile_ref().to_owned(), Vec::new()))
        .collect::<BTreeMap<_, _>>();
    let api_json: Value = serde_json::from_slice(&api_bytes).map_err(|error| error.to_string())?;

    let common_scenarios = QualificationScenarioManifest::from_json(
        &fs::read(repository.join("product/conformance/v2/profile-qualification-common.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let domain_scenarios = QualificationScenarioManifest::from_json(
        &fs::read(package_root.join(package.qualification().domain_scenarios()))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if common_scenarios.domain() != "common"
        || domain_scenarios.domain() != package.domain().id()
        || domain_scenarios
            .scenarios()
            .iter()
            .any(|scenario| common_scenarios.scenarios().contains(scenario))
    {
        return Err(format!(
            "qualification scenario rosters are invalid for {}",
            package.domain().id()
        ));
    }

    validate_source_paths(repository, &manifest_json)?;
    let error_digests = load_error_projection_digests(repository, &manifest_json)?;
    let source_digest = source_digest(&manifest_bytes, &api_bytes);
    let mut outputs = render_outputs(
        domain,
        entry.manifest_path(),
        &source_digest,
        &manifest_json,
        &api_json,
        &package,
        &api,
        &error_digests,
        &qualification_metadata,
    )?;
    outputs.insert(
        "product/runtime/auths-node/src/generated/profile_routes.rs".into(),
        render_root_profile_roster(repository, &roster)?,
    );
    outputs.insert(
        "product/runtime/auths-node/src/generated/profile_launch_projection.json".into(),
        crate::expected_profile_launch_projection(repository, &roster)?,
    );
    outputs.insert(
        "xtask/src/profile_qualification_adapters.rs".into(),
        rustfmt_generated(render_qualification_adapter_roster(&roster)?)?,
    );
    outputs.insert(
        "product/qualification/auths-qualification-evidence-source/src/generated/qualification_routes.rs".into(),
        rustfmt_generated(render_qualification_source_routes(repository, &roster)?)?,
    );
    let mut stale = Vec::new();
    for (path, contents) in outputs {
        let path = repository.join(path);
        if check {
            if fs::read_to_string(&path).ok().as_deref() != Some(contents.as_str()) {
                stale.push(path);
            }
        } else {
            write_generated(&path, &contents)?;
        }
    }
    if !stale.is_empty() {
        return Err(format!(
            "generated profile output is stale:\n{}",
            stale
                .iter()
                .map(|path| format!("  {}", path.display()))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    println!(
        "{} generated profile package {domain} ({source_digest})",
        if check { "checked" } else { "wrote" }
    );
    Ok(())
}

fn render_root_profile_roster(repository: &Path, roster: &ProfileRoster) -> Result<String, String> {
    let mut registrations = Vec::new();
    let mut providers = Vec::new();
    for entry in roster.packages() {
        let manifest_path = repository.join(entry.manifest_path());
        let manifest_bytes = fs::read(&manifest_path).map_err(|error| error.to_string())?;
        let manifest_json: Value =
            serde_json::from_slice(&manifest_bytes).map_err(|error| error.to_string())?;
        let api_relative = manifest_json
            .get("api")
            .and_then(Value::as_str)
            .ok_or_else(|| "manifest api path is absent".to_owned())?;
        let api_bytes = fs::read(
            manifest_path
                .parent()
                .ok_or_else(|| "manifest has no parent".to_owned())?
                .join(api_relative),
        )
        .map_err(|error| error.to_string())?;
        let api = ProfileApi::from_json(&api_bytes).map_err(|error| error.to_string())?;
        let package =
            ProfilePackage::from_json(&manifest_bytes, &api).map_err(|error| error.to_string())?;
        if let Some(connection) = package.domain().connection() {
            providers.push((
                package.domain().id().to_owned(),
                entry.rust_package().replace('-', "_"),
                connection.provider_kind().to_owned(),
                connection.contract().to_owned(),
                connection.descriptor_schema().to_owned(),
            ));
        }
        let raw_profiles = manifest_json
            .get("profiles")
            .and_then(Value::as_array)
            .ok_or_else(|| "manifest profiles missing after validation".to_owned())?;
        for (profile, raw) in package.profiles().iter().zip(raw_profiles) {
            let semantic_subject = format!("{}/{}", profile.id(), profile.version());
            let roster_profile = entry.profile(&semantic_subject).ok_or_else(|| {
                format!(
                    "profile roster is missing manifest profile {semantic_subject} for {}",
                    entry.domain()
                )
            })?;
            let constant = screaming(&format!(
                "{}_{}",
                profile.client().group(),
                profile.client().method()
            ));
            let crate_name = entry.rust_package().replace('-', "_");
            let connection = package.domain().connection().map_or_else(
                || "None".to_owned(),
                |connection| {
                    format!(
                        "Some(ProfileConnectionAdvertisement::new({:?}, {:?}, {:?}).map_err(|_| LocalAgentFailure::InvalidConfiguration)?)",
                        connection.provider_kind(),
                        connection.contract(),
                        connection.descriptor_schema(),
                    )
                },
            );
            let limits = raw
                .get("limits")
                .and_then(Value::as_object)
                .ok_or_else(|| "profile limits missing after validation".to_owned())?;
            let number = |name: &str| -> Result<u64, String> {
                limits
                    .get(name)
                    .and_then(Value::as_u64)
                    .ok_or_else(|| format!("profile limit {name} missing after validation"))
            };
            let function_stem = format!(
                "{}_{}",
                snake(profile.client().group()),
                snake(profile.client().method())
            );
            let variant = format!(
                "{}{}{}",
                pascal(package.domain().id()),
                pascal(profile.client().group()),
                pascal(profile.client().method())
            );
            let credential_scope = raw
                .pointer("/contracts/credentialScope")
                .and_then(Value::as_str)
                .ok_or_else(|| "profile credential scope missing after validation".to_owned())?
                .to_owned();
            let configuration_format = raw
                .pointer("/contracts/configurationFormat")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let preparation_evidence = raw
                .pointer("/contracts/preparationEvidence")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let _ = roster_profile;
            registrations.push((
                profile.id().to_owned(),
                profile.version(),
                crate_name,
                constant,
                connection,
                number("requestBytes")?,
                number("admissionsPerMinute")?,
                number("activePerPrincipal")?,
                number("unresolvedPerPrincipal")?,
                number("durableBytesPerPrincipal")?,
                number("tombstonesPerPrincipal")?,
                number("terminalRetentionSeconds")?,
                number("idempotencyRetentionSeconds")?,
                number("receiptCount")?,
                number("receiptBytes")?,
                number("responseBytes")?,
                variant,
                function_stem,
                credential_scope,
                configuration_format,
                preparation_evidence,
            ));
        }
        if entry.profiles().len() != package.profiles().len() {
            return Err(format!(
                "profile roster and manifest profile sets differ for {}",
                entry.domain()
            ));
        }
    }
    registrations
        .sort_by(|left, right| (left.0.as_str(), left.1).cmp(&(right.0.as_str(), right.1)));
    providers.sort_by(|left, right| left.2.cmp(&right.2));
    let header = format!(
        "generated by {GENERATOR}; source=profile package manifests and normalized launch projection"
    );
    let mut output = format!(
        "// {header}\n//! Generated static local-agent profile and provider registrations.\n\n#![allow(clippy::let_and_return, clippy::manual_range_contains, clippy::match_same_arms, clippy::match_single_binding, clippy::missing_errors_doc, clippy::must_use_candidate, clippy::needless_borrow, clippy::never_loop, clippy::too_many_lines, clippy::unnecessary_wraps, clippy::unreadable_literal, clippy::unused_self, clippy::vec_init_then_push)]\n\nuse crate::local_agent::{{LocalAgentFailure, LocalOperationContext, RegisteredLocalProfile}};\nuse crate::profile_configuration::ProfileConfigurationSnapshot;\nuse crate::profile_launch::{{launch_profile, validate_exact_profiles, LaunchFlavor}};\n#[cfg(all(target_os = \"linux\", feature = \"qualification-failpoints\"))]\nuse auths_connections::QualificationProviderCallResponse;\nuse auths_connections::{{ConnectionAdapterError, ConnectionBinding, CredentialScope, PersistentCredentialStore, ProviderConnectionAdapter as _, ProviderCredentialLease, SecretBytes}};\nuse auths_lifecycle::OperationProfileV1;\nuse auths_production_client::{{ProfileAdvertisement, ProfileConnectionAdvertisement, SessionProfileKey}};\nuse auths_profile_runtime::{{CallProviderInput, ObserveProviderResultInput, PreEntryRecheckInput, PreparationEvidenceAcquisition, PreparationEvidenceAcquisitionInput, PreparationEvidenceAuthorizationInput, PrepareProfileInput, ProfileConnectionRequirement, ProfileDecisionReceiptFacts, ProfileExecutionReceiptFacts, ProfileObservation, ProfileOperationContext, ProfilePreEntryRecheck, ProfilePreparation, ProfileReceiptInspection, ProfileRuntimeError, ReconcileProfileInput, ReleaseProfileCallInput, SealProfileCallInput, SealedProfileCall}};\nuse auths_stores::{{JournalRecordV1, OperationJournalLimitsV1}};\nuse std::time::{{Instant}};\n\n"
    );
    output.push_str(
        "/// Closed provider set emitted from the build-time package roster.\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub(crate) enum RegisteredProvider {\n",
    );
    for (domain, ..) in &providers {
        writeln!(output, "    {},", pascal(domain)).map_err(|error| error.to_string())?;
    }
    output.push_str("}\n\nimpl RegisteredProvider {\n");
    output.push_str(
        "    pub(crate) fn parse(value: &str) -> Option<Self> {\n        match value {\n",
    );
    for (domain, _, provider, ..) in &providers {
        writeln!(
            output,
            "            {provider:?} => Some(Self::{}),",
            pascal(domain)
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("            _ => None,\n        }\n    }\n\n");
    for method in ["kind", "contract", "descriptor_schema"] {
        writeln!(
            output,
            "    pub(crate) const fn {method}(self) -> &'static str {{\n        match self {{"
        )
        .map_err(|error| error.to_string())?;
        for provider in &providers {
            let value = match method {
                "kind" => &provider.2,
                "contract" => &provider.3,
                "descriptor_schema" => &provider.4,
                _ => unreachable!("fixed generated provider method"),
            };
            writeln!(
                output,
                "            Self::{} => {value:?},",
                pascal(&provider.0)
            )
            .map_err(|error| error.to_string())?;
        }
        output.push_str("        }\n    }\n\n");
    }
    output.push_str("    pub(crate) fn validate_descriptor(self, bytes: &[u8]) -> Result<[u8; 32], ConnectionAdapterError> {\n        match self {\n");
    for (domain, crate_name, ..) in &providers {
        writeln!(output, "            Self::{} => {crate_name}::connection::adapter().validate_descriptor(bytes).map(|value| *value.account_commitment()),", pascal(domain))
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) fn validate_onboarding(self, descriptor: &[u8], bytes: Vec<u8>) -> Result<SecretBytes, ConnectionAdapterError> {\n        match self {\n");
    for (domain, crate_name, ..) in &providers {
        writeln!(
            output,
            "            Self::{} => {crate_name}::connection::validate_onboarding(descriptor, bytes),",
            pascal(domain)
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) async fn lease_credential(self, descriptor: &[u8], binding: &ConnectionBinding, scope: &CredentialScope, store: &PersistentCredentialStore, deadline: Instant) -> Result<ProviderCredentialLease, ConnectionAdapterError> {\n        match self {\n");
    for (domain, crate_name, ..) in &providers {
        writeln!(output, "            Self::{} => {{ let adapter = {crate_name}::connection::adapter(); let validated = adapter.validate_descriptor(descriptor)?; adapter.permits_scope(&validated, scope)?; adapter.lease_credential(binding, scope, store, deadline).await }},", pascal(domain))
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n}\n\n");
    output.push_str("/// Validates every deployment-owned profile configuration through the statically linked domain owner.\npub(crate) fn validate_profile_configurations(snapshot: &ProfileConfigurationSnapshot, flavor: LaunchFlavor) -> Result<(), LocalAgentFailure> {\n");
    output.push_str("    validate_launch_projection()?;\n");
    output.push_str(
        "    for (profile_ref, binding) in snapshot.iter() {\n        match profile_ref {\n",
    );
    for registration in &registrations {
        if registration.19.is_some() {
            writeln!(output, "            {:?} => {{ if !RegisteredProfile::{}.is_available_for(flavor) || RegisteredProfile::{}.configuration_format() != Some(binding.format()) {{ return Err(LocalAgentFailure::InvalidConfiguration); }} {}::local_agent::validate_profile_configuration(binding).map_err(|_| LocalAgentFailure::InvalidConfiguration)?; }},", format!("{}/{}", registration.0, registration.1), registration.16, registration.16, registration.2)
                .map_err(|error| error.to_string())?;
        }
    }
    output.push_str(
        "            _ => return Err(LocalAgentFailure::InvalidConfiguration),\n        }\n    }\n",
    );
    for registration in &registrations {
        if let Some(format) = &registration.19 {
            writeln!(
                output,
                "    let {} = if RegisteredProfile::{}.is_available_for(flavor) {{ Some(snapshot.get({:?}).ok_or(LocalAgentFailure::InvalidConfiguration)?) }} else {{ None }};",
                snake(&registration.16),
                registration.16,
                format!("{}/{}", registration.0, registration.1)
            )
            .map_err(|error| error.to_string())?;
            writeln!(output, "    if {}.as_ref().is_some_and(|binding| binding.format() != {:?}) {{ return Err(LocalAgentFailure::InvalidConfiguration); }}", snake(&registration.16), format)
                .map_err(|error| error.to_string())?;
        }
    }
    let mut by_crate = BTreeMap::<&str, Vec<&str>>::new();
    for registration in &registrations {
        if registration.19.is_some() {
            by_crate
                .entry(registration.2.as_str())
                .or_default()
                .push(registration.16.as_str());
        }
    }
    for variants in by_crate.values() {
        if let Some(first) = variants.first() {
            for other in variants.iter().skip(1) {
                writeln!(output, "    if let (Some(left), Some(right)) = ({}, {}) && !left.same_source(&right) {{ return Err(LocalAgentFailure::InvalidConfiguration); }}", snake(first), snake(other))
                    .map_err(|error| error.to_string())?;
            }
        }
    }
    output.push_str("    Ok(())\n}\n\n");
    output.push_str("/// Merges every exact provider onboarding route without handwritten node branches.\npub(crate) fn built_in_connection_admin_routes() -> axum::Router<crate::connection_admin::ConnectionAdminState> {\n    let router = axum::Router::new();\n");
    for (domain, crate_name, ..) in &providers {
        writeln!(output, "    let router = router.merge(crate::connection_admin::provider_admin_routes(RegisteredProvider::{}, {crate_name}::connection::admin_routes::START, {crate_name}::connection::admin_routes::COMPLETE));", pascal(domain))
            .map_err(|error| error.to_string())?;
    }
    output.push_str("    router\n}\n\n");
    output.push_str(
        "/// Closed profile set emitted from the build-time package roster.\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub(crate) enum RegisteredProfile {\n",
    );
    for registration in &registrations {
        writeln!(output, "    {},", registration.16).map_err(|error| error.to_string())?;
    }
    output.push_str("}\n\nfn validate_launch_projection() -> Result<(), LocalAgentFailure> {\n    validate_exact_profiles(&[\n");
    for registration in &registrations {
        writeln!(
            output,
            "        {:?},",
            format!("{}/{}", registration.0, registration.1)
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("    ])\n}\n\nimpl RegisteredProfile {\n");
    output.push_str("    pub(crate) const ALL: &'static [Self] = &[\n");
    for registration in &registrations {
        writeln!(output, "        Self::{},", registration.16)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("    ];\n\n");
    output.push_str("    pub(crate) fn parse(id: &str, version: u16, flavor: LaunchFlavor) -> Option<Self> {\n        let selected = match (id, version) {\n");
    for registration in &registrations {
        writeln!(
            output,
            "            ({:?}, {}) => Some(Self::{}),",
            registration.0, registration.1, registration.16
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("            _ => None,\n        };\n        selected.filter(|profile| profile.is_available_for(flavor))\n    }\n\n");
    output.push_str(
        "    pub(crate) fn semantic_subject(self) -> &'static str {\n        match self {\n",
    );
    for registration in &registrations {
        writeln!(
            output,
            "            Self::{} => {:?},",
            registration.16,
            format!("{}/{}", registration.0, registration.1),
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n    pub(crate) fn is_available_for(self, flavor: LaunchFlavor) -> bool {\n        launch_profile(self.semantic_subject()).is_ok_and(|profile| profile.available_for(flavor))\n    }\n\n");
    output.push_str("    pub(crate) fn profile(self) -> Result<OperationProfileV1, LocalAgentFailure> {\n        match self {\n");
    for registration in &registrations {
        writeln!(output, "            Self::{} => OperationProfileV1::new({:?}, {}, {}::generated::profile_routes::{}_RUNTIME_DIGEST).map_err(|_| LocalAgentFailure::InvalidConfiguration),", registration.16, registration.0, registration.1, registration.2, registration.3)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) fn build_decision_receipt_claims(self, facts: ProfileDecisionReceiptFacts<'_>) -> Result<Vec<u8>, ProfileRuntimeError> {\n        match self {\n");
    for registration in &registrations {
        writeln!(
            output,
            "            Self::{} => {}::local_agent::{}_build_decision_receipt_claims(facts),",
            registration.16, registration.2, registration.17
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) fn build_execution_receipt_claims(self, facts: ProfileExecutionReceiptFacts<'_>) -> Result<Vec<u8>, ProfileRuntimeError> {\n        match self {\n");
    for registration in &registrations {
        writeln!(
            output,
            "            Self::{} => {}::local_agent::{}_build_execution_receipt_claims(facts),",
            registration.16, registration.2, registration.17
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) fn inspect_receipt_claims(self, inspection: ProfileReceiptInspection<'_>) -> Result<(), ProfileRuntimeError> {\n        match self {\n");
    for registration in &registrations {
        writeln!(
            output,
            "            Self::{} => {}::local_agent::{}_inspect_receipt_claims(inspection),",
            registration.16, registration.2, registration.17
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) const fn connection_requirement(self) -> Option<ProfileConnectionRequirement> {\n        match self {\n");
    for registration in &registrations {
        let requirement = providers.iter().find(|provider| {
            provider.0
                == registration
                    .2
                    .trim_start_matches("auths_")
                    .replace('_', "-")
        });
        let requirement = requirement.map_or_else(
            || "None".to_owned(),
            |provider| format!("Some(ProfileConnectionRequirement {{ provider_kind: {:?}, contract: {:?}, descriptor_schema: {:?}, credential_scope: {:?} }})", provider.2, provider.3, provider.4, registration.18),
        );
        writeln!(
            output,
            "            Self::{} => {requirement},",
            registration.16
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) fn revalidate_configuration(self, context: &LocalOperationContext) -> Result<(), LocalAgentFailure> {\n        match self.configuration_format() {\n            None => { if context.profile_configuration.is_some() { return Err(LocalAgentFailure::InvalidConfiguration); } Ok(()) },\n            Some(format) => {\n                let binding = context.profile_configuration.as_deref().ok_or(LocalAgentFailure::InvalidConfiguration)?;\n                if binding.format() != format { return Err(LocalAgentFailure::InvalidConfiguration); }\n                crate::profile_configuration::revalidate_binding(binding).map_err(|_| LocalAgentFailure::InvalidConfiguration)?;\n                match self {\n");
    for registration in &registrations {
        if registration.19.is_some() {
            writeln!(output, "                    Self::{} => {}::local_agent::validate_profile_configuration(binding).map_err(|_| LocalAgentFailure::InvalidConfiguration),", registration.16, registration.2)
                .map_err(|error| error.to_string())?;
        } else {
            writeln!(
                output,
                "                    Self::{} => Err(LocalAgentFailure::InvalidConfiguration),",
                registration.16
            )
            .map_err(|error| error.to_string())?;
        }
    }
    output.push_str("                }\n            }\n        }\n    }\n\n");
    output.push_str("    pub(crate) const fn configuration_format(self) -> Option<&'static str> {\n        match self {\n");
    for registration in &registrations {
        let value = registration
            .19
            .as_deref()
            .map_or_else(|| "None".to_owned(), |value| format!("Some({value:?})"));
        writeln!(output, "            Self::{} => {value},", registration.16)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    fn operation_context<'a>(self, context: &'a LocalOperationContext, profile: &'a OperationProfileV1) -> ProfileOperationContext<'a> {\n        ProfileOperationContext::new(context.workload_id.as_ref(), context.principal.as_ref(), profile, context.authority.proof_bytes(), context.authority.trusted_context_bytes(), context.authority.artifact_commitment(), context.profile_configuration.as_deref(), &context.profile_state_root)\n    }\n\n");
    output.push_str("    pub(crate) const fn preparation_evidence_kind(self) -> Option<&'static str> {\n        match self {\n");
    for registration in &registrations {
        let value = registration
            .20
            .as_deref()
            .map_or_else(|| "None".to_owned(), |value| format!("Some({value:?})"));
        writeln!(output, "            Self::{} => {value},", registration.16)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) fn authorize_preparation_evidence(self, context: &LocalOperationContext, workflow_id: &str, profile_input: &[u8], connection: Option<&ConnectionBinding>, now_unix_seconds: u64) -> Result<[u8; 32], ProfileRuntimeError> {\n        if self.preparation_evidence_kind() != Some(\"protected-lease\") { return Err(ProfileRuntimeError::Invalid); }\n        let profile = self.profile().map_err(|_| ProfileRuntimeError::Invalid)?;\n        let context = self.operation_context(context, &profile);\n        match self {\n");
    for registration in registrations
        .iter()
        .filter(|registration| registration.20.is_some())
    {
        writeln!(output, "            Self::{} => {}::local_agent::{}_authorize_preparation_evidence(PreparationEvidenceAuthorizationInput {{ context, workflow_id, profile_input, connection, now_unix_seconds }}),", registration.16, registration.2, registration.17)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("            _ => Err(ProfileRuntimeError::Invalid),\n        }\n    }\n\n");
    output.push_str("    pub(crate) fn acquire_preparation_evidence(self, context: &LocalOperationContext, workflow_id: &str, profile_input: &[u8], connection: Option<&ConnectionBinding>, authority_action_commitment: [u8; 32], now_unix_seconds: u64) -> Result<PreparationEvidenceAcquisition, ProfileRuntimeError> {\n        if self.preparation_evidence_kind() != Some(\"protected-lease\") { return Err(ProfileRuntimeError::Invalid); }\n        let profile = self.profile().map_err(|_| ProfileRuntimeError::Invalid)?;\n        let context = self.operation_context(context, &profile);\n        match self {\n");
    for registration in registrations
        .iter()
        .filter(|registration| registration.20.is_some())
    {
        writeln!(output, "            Self::{} => {}::local_agent::{}_acquire_preparation_evidence(PreparationEvidenceAcquisitionInput {{ context, workflow_id, profile_input, connection, authority_action_commitment, now_unix_seconds }}),", registration.16, registration.2, registration.17)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("            _ => Err(ProfileRuntimeError::Invalid),\n        }\n    }\n\n");
    output.push_str("    pub(crate) fn prepare(self, context: &LocalOperationContext, workflow_id: &str, profile_input: &[u8], connection: Option<&ConnectionBinding>, preparation_evidence: Option<&[u8]>, now_unix_seconds: u64) -> Result<ProfilePreparation, ProfileRuntimeError> {\n        let profile = self.profile().map_err(|_| ProfileRuntimeError::Invalid)?;\n        let context = self.operation_context(context, &profile);\n        match self {\n");
    for registration in &registrations {
        writeln!(output, "            Self::{} => {}::local_agent::{}_prepare(PrepareProfileInput {{ context, workflow_id, profile_input, connection, preparation_evidence, now_unix_seconds }}),", registration.16, registration.2, registration.17)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) async fn seal_provider_call(self, context: &LocalOperationContext, record: &JournalRecordV1, now_unix_seconds: u64) -> Result<SealedProfileCall, ProfileRuntimeError> {\n        let profile = self.profile().map_err(|_| ProfileRuntimeError::Invalid)?;\n        let context = self.operation_context(context, &profile);\n        match self {\n");
    for registration in &registrations {
        writeln!(output, "            Self::{} => {}::local_agent::{}_seal_provider_call(SealProfileCallInput {{ context, record, now_unix_seconds }}).await,", registration.16, registration.2, registration.17)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) fn recheck_pre_entry(self, context: &LocalOperationContext, record: &JournalRecordV1, now_unix_seconds: u64) -> Result<ProfilePreEntryRecheck, ProfileRuntimeError> {\n        let profile = self.profile().map_err(|_| ProfileRuntimeError::Invalid)?;\n        let context = self.operation_context(context, &profile);\n        match self {\n");
    for registration in &registrations {
        writeln!(output, "            Self::{} => {}::local_agent::{}_recheck_pre_entry(PreEntryRecheckInput {{ context, record, now_unix_seconds }}),", registration.16, registration.2, registration.17)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) fn release_pre_entry(self, context: &LocalOperationContext, record: &JournalRecordV1) -> Result<(), ProfileRuntimeError> {\n        let profile = self.profile().map_err(|_| ProfileRuntimeError::Invalid)?;\n        let context = self.operation_context(context, &profile);\n        match self {\n");
    for registration in &registrations {
        writeln!(output, "            Self::{} => {}::local_agent::{}_release_pre_entry(ReleaseProfileCallInput {{ context, record }}),", registration.16, registration.2, registration.17)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) async fn call_provider(self, context: &LocalOperationContext, call: &SealedProfileCall, credential: Option<&ProviderCredentialLease>, now_unix_seconds: u64) -> Result<Vec<u8>, ProfileRuntimeError> {\n        let profile = self.profile().map_err(|_| ProfileRuntimeError::Invalid)?;\n        let context = self.operation_context(context, &profile);\n        match self {\n");
    for registration in &registrations {
        writeln!(output, "            Self::{} => {}::local_agent::{}_call_provider(CallProviderInput {{ context, call, credential, now_unix_seconds }}).await,", registration.16, registration.2, registration.17)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str(r#"    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    pub(crate) fn finalize_qualification_provider_result(
        self,
        context: &LocalOperationContext,
        call: &SealedProfileCall,
        credential: Option<&ProviderCredentialLease>,
        now_unix_seconds: u64,
        result: Result<Vec<u8>, ProfileRuntimeError>,
    ) -> Result<Vec<u8>, ProfileRuntimeError> {
        let profile = self.profile().map_err(|_| ProfileRuntimeError::Invalid)?;
        let context = self.operation_context(context, &profile);
        match self {
            Self::StripeRefundsCreate => auths_stripe::local_agent::refunds_create_finalize_transport_result(
                CallProviderInput { context, call, credential, now_unix_seconds },
                result,
            ),
            Self::OpentofuPlansCreate => auths_opentofu::qualification::import_provider_transport_result(
                "auths.opentofu.plan-preflight/1",
                context.profile_state_root(),
                result?,
            ),
            _ => result,
        }
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    pub(crate) fn finalize_qualification_reconcile_result(
        self,
        context: &LocalOperationContext,
        record: &JournalRecordV1,
        now_unix_seconds: u64,
        result: QualificationProviderCallResponse,
    ) -> Result<ProfileObservation, ProfileRuntimeError> {
        let profile = self.profile().map_err(|_| ProfileRuntimeError::Invalid)?;
        let context = self.operation_context(context, &profile);
        let result = match result {
            QualificationProviderCallResponse::Success(value) => Some(value),
            QualificationProviderCallResponse::NotApplied => None,
            QualificationProviderCallResponse::Possible(issue) => {
                return Err(ProfileRuntimeError::Possible(issue));
            }
            QualificationProviderCallResponse::Invalid
            | QualificationProviderCallResponse::PostEntryTimeout
            | QualificationProviderCallResponse::PreEntry(_)
            | QualificationProviderCallResponse::PreEntryPending
            | QualificationProviderCallResponse::PossibleWithProfileState { .. } => {
                return Err(ProfileRuntimeError::Invalid);
            }
        };
        match self {
            Self::StripeRefundsCreate => {
                let bytes = result.as_deref().ok_or(ProfileRuntimeError::Invalid)?;
                auths_stripe::local_agent::refunds_create_finalize_reconcile_transport(
                    ReconcileProfileInput { context, record, credential: None, now_unix_seconds },
                    bytes,
                )
            }
            Self::PostgresqlUpdatePreflightsCreate => {
                let bytes = result.as_deref().ok_or(ProfileRuntimeError::Invalid)?;
                auths_postgresql::local_agent::update_preflights_create_observe_provider_result(
                    ObserveProviderResultInput { context, record, provider_result: bytes, now_unix_seconds },
                )
            }
            Self::PostgresqlUpdatesExecute => {
                auths_postgresql::local_agent::updates_execute_finalize_reconcile_transport(
                    ReconcileProfileInput { context, record, credential: None, now_unix_seconds },
                    result.as_deref(),
                )
            }
            Self::OpentofuPlansCreate => {
                let bytes = auths_opentofu::qualification::import_provider_transport_result(
                    "auths.opentofu.plan-preflight/1",
                    context.profile_state_root(),
                    result.ok_or(ProfileRuntimeError::Invalid)?,
                )?;
                auths_opentofu::local_agent::plans_create_observe_provider_result(
                    ObserveProviderResultInput { context, record, provider_result: &bytes, now_unix_seconds },
                )
            }
            Self::OpentofuSavedPlansApply => {
                auths_opentofu::local_agent::saved_plans_apply_finalize_reconcile_transport(
                    ReconcileProfileInput { context, record, credential: None, now_unix_seconds },
                    result.as_deref(),
                )
            }
        }
    }

"#);
    output.push_str("    pub(crate) fn observe_provider_result(self, context: &LocalOperationContext, record: &JournalRecordV1, provider_result: &[u8], now_unix_seconds: u64) -> Result<ProfileObservation, ProfileRuntimeError> {\n        let profile = self.profile().map_err(|_| ProfileRuntimeError::Invalid)?;\n        let context = self.operation_context(context, &profile);\n        match self {\n");
    for registration in &registrations {
        writeln!(output, "            Self::{} => {}::local_agent::{}_observe_provider_result(ObserveProviderResultInput {{ context, record, provider_result, now_unix_seconds }}),", registration.16, registration.2, registration.17)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    output.push_str("    pub(crate) async fn reconcile(self, context: &LocalOperationContext, record: &JournalRecordV1, credential: Option<&ProviderCredentialLease>, now_unix_seconds: u64) -> Result<ProfileObservation, ProfileRuntimeError> {\n        let profile = self.profile().map_err(|_| ProfileRuntimeError::Invalid)?;\n        let context = self.operation_context(context, &profile);\n        match self {\n");
    for registration in &registrations {
        writeln!(output, "            Self::{} => {}::local_agent::{}_reconcile(ReconcileProfileInput {{ context, record, credential, now_unix_seconds }}).await,", registration.16, registration.2, registration.17)
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n}\n\n");
    output.push_str("/// Returns production-qualified profiles for the exact build target.\npub fn built_in_local_profiles() -> Result<Vec<RegisteredLocalProfile>, LocalAgentFailure> {\n    built_in_local_profiles_for(LaunchFlavor::Production)\n}\n\n#[cfg(feature = \"qualification-failpoints\")]\n/// Returns the exact immutable profile roster exercised by live qualification.\npub fn built_in_qualification_local_profiles() -> Result<Vec<RegisteredLocalProfile>, LocalAgentFailure> {\n    built_in_local_profiles_for(LaunchFlavor::Qualification)\n}\n\n#[cfg(any(test, feature = \"testkit-agent\"))]\n/// Returns only the explicitly testkit-available profile set.\npub fn built_in_testkit_local_profiles() -> Result<Vec<RegisteredLocalProfile>, LocalAgentFailure> {\n    built_in_local_profiles_for(LaunchFlavor::Testkit)\n}\n\n");
    writeln!(
        output,
        "fn built_in_local_profiles_for(flavor: LaunchFlavor) -> Result<Vec<RegisteredLocalProfile>, LocalAgentFailure> {{\n    validate_launch_projection()?;\n    let mut values = Vec::with_capacity({});",
        registrations.len()
    )
    .map_err(|error| error.to_string())?;
    for registration in &registrations {
        let (id, version, crate_name, constant, connection, request_bytes, ..) = registration;
        let preparation_evidence = registration
            .20
            .as_ref()
            .map_or_else(|| "None".to_owned(), |kind| format!("Some({kind:?})"));
        writeln!(
            output,
            "    if RegisteredProfile::{}.is_available_for(flavor) {{ let qualification = launch_profile({:?})?.qualification_for(flavor)?; values.push(RegisteredLocalProfile::new(ProfileAdvertisement::new(SessionProfileKey::new({id:?}, {version}).map_err(|_| LocalAgentFailure::InvalidConfiguration)?, {crate_name}::generated::profile_routes::{constant}_RUNTIME_DIGEST, \"auths.profile-operation/1\", {crate_name}::generated::profile_routes::{constant}_ERROR_DIGEST, {connection}, qualification).map_err(|_| LocalAgentFailure::InvalidConfiguration)?, {request_bytes}usize, {preparation_evidence})?); }}",
            registration.16,
            format!("{id}/{version}"),
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str(
        "    values.sort_by(|left, right| left.advertisement().profile().cmp(right.advertisement().profile()));\n    Ok(values)\n}\n\n",
    );
    writeln!(
        output,
        "/// Returns manifest-derived limits for the common durable journal.\npub fn built_in_operation_limits() -> Result<Vec<(OperationProfileV1, OperationJournalLimitsV1)>, LocalAgentFailure> {{\n    let mut values = Vec::with_capacity({});",
        registrations.len()
    )
    .map_err(|error| error.to_string())?;
    for registration in &registrations {
        let (
            id,
            version,
            crate_name,
            constant,
            _,
            _,
            admissions,
            active,
            unresolved,
            durable,
            tombstones,
            terminal_retention,
            idempotency_retention,
            receipt_count,
            receipt_bytes,
            response_bytes,
            _,
            _,
            _,
            _,
            _,
        ) = registration;
        writeln!(
            output,
            "    values.push((OperationProfileV1::new({id:?}, {version}, {crate_name}::generated::profile_routes::{constant}_RUNTIME_DIGEST).map_err(|_| LocalAgentFailure::InvalidConfiguration)?, OperationJournalLimitsV1::new({admissions}u32, {active}u16, {unresolved}u16, {durable}u64, {tombstones}u32, {terminal_retention}u64, {idempotency_retention}u64, {receipt_count}u8, {receipt_bytes}u64, {response_bytes}u64).map_err(|_| LocalAgentFailure::InvalidConfiguration)?));"
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("    values.sort_by(|left, right| left.0.cmp(&right.0));\n    Ok(values)\n}\n");
    rustfmt_generated(output)
}

fn render_qualification_adapter_roster(roster: &ProfileRoster) -> Result<String, String> {
    let mut output = String::from(
        "// generated by auths-profile-generator/1 from the closed profile roster.\n\
//! Static qualification-time provider adapter registration.\n\n\
use crate::profile_qualification::{CleanupAdapterContext, ObserveAdapterContext, RunAdapterContext, cleanup_domain_adapter, observe_domain_adapter, run_domain_adapter};\n\
use auths_profile_kit::{QualificationEffect, QualificationOperationRole, QualificationProtectedSetup, QualificationProtectedSetupInput, QualificationSetupHandoffV1};\n\n",
    );
    for (function, domain_function, error) in [
        (
            "qualification_domain_scenario_ids",
            "qualification_domain_scenario_ids",
            "qualification domain has no generated scenario roster",
        ),
        (
            "qualification_requirement_ids",
            "qualification_requirement_ids",
            "qualification domain has no generated requirement roster",
        ),
        (
            "qualification_receipt_claim_ids",
            "qualification_receipt_claim_ids",
            "qualification domain has no generated receipt-claim roster",
        ),
        (
            "qualification_provider_truth_fields",
            "qualification_provider_truth_fields",
            "qualification domain has no generated provider-truth field roster",
        ),
        (
            "qualification_forbidden_evidence_fields",
            "qualification_forbidden_evidence_fields",
            "qualification domain has no generated forbidden-evidence field roster",
        ),
        (
            "qualification_redaction_prefixes",
            "qualification_redaction_prefixes",
            "qualification domain has no generated redaction-prefix roster",
        ),
    ] {
        writeln!(
            output,
            "pub(crate) fn {function}(domain: &str) -> Result<&'static [&'static str], String> {{\n    match domain {{"
        )
        .map_err(|error| error.to_string())?;
        for entry in roster.packages() {
            let crate_name = entry.rust_package().replace('-', "_");
            writeln!(
                output,
                "        {:?} => Ok({crate_name}::qualification::{domain_function}()),",
                entry.domain()
            )
            .map_err(|error| error.to_string())?;
        }
        writeln!(output, "        _ => Err({error:?}.into()),\n    }}\n}}\n")
            .map_err(|error| error.to_string())?;
    }
    output.push_str("pub(crate) fn qualification_requirements_sha256(domain: &str) -> Result<&'static str, String> {\n    match domain {\n");
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        writeln!(
            output,
            "        {:?} => Ok({crate_name}::qualification::qualification_requirements_sha256()),",
            entry.domain()
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        _ => Err(\"qualification domain has no generated requirement inventory digest\".into()),\n    }\n}\n\n");
    output.push_str("pub(crate) fn qualification_provider_matrix_rows(domain: &str) -> Result<&'static [(&'static str, &'static str, &'static str, &'static str, &'static str)], String> {\n    match domain {\n");
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        writeln!(
            output,
            "        {:?} => Ok({crate_name}::qualification::qualification_provider_matrix_rows()),",
            entry.domain()
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        _ => Err(\"qualification domain has no generated provider-matrix row roster\".into()),\n    }\n}\n\n");
    output.push_str("pub(crate) fn qualification_operation_plan(domain: &str) -> Result<&'static [(QualificationOperationRole, &'static str, bool, bool)], String> {\n    match domain {\n");
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        writeln!(
            output,
            "        {:?} => Ok({crate_name}::qualification::qualification_operation_plan()),",
            entry.domain()
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        _ => Err(\"qualification domain has no generated operation-plan roster\".into()),\n    }\n}\n\n");
    output.push_str(
        "pub(crate) fn run_protected_setup(input: QualificationProtectedSetupInput<'_>, setup_credential: &[u8]) -> Result<QualificationSetupHandoffV1, String> {\n    let result = match input.run_context.protected_environment.as_str() {\n",
    );
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        let adapter = format!("{}QualificationAdapter", pascal(entry.domain()));
        writeln!(
            output,
            "        {:?} => {crate_name}::qualification::{adapter}.setup(input, setup_credential),",
            format!("qualification-{}", entry.domain())
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        _ => return Err(\"qualification domain is absent from the generated static setup roster\".into()),\n    };\n    result.map_err(|error| error.to_string())\n}\n\n");
    output.push_str(
        "pub(crate) fn run_collection_adapter(context: RunAdapterContext<'_>) -> Result<(), String> {\n\
    match context.domain {\n",
    );
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        let adapter = format!("{}QualificationAdapter", pascal(entry.domain()));
        writeln!(
            output,
            "        {:?} => run_domain_adapter({crate_name}::qualification::{adapter}, context),",
            entry.domain()
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str(
        "        _ => Err(\"qualification domain is absent from the generated static adapter roster\".into()),\n\
    }\n\
}\n\n\
pub(crate) fn validate_provider_truth_facts(domain: &str, bytes: &[u8], effect: QualificationEffect) -> Result<(), String> {\n\
    let result = match domain {\n",
    );
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        writeln!(
            output,
            "        {:?} => {crate_name}::qualification::validate_provider_truth_facts(bytes, effect),",
            entry.domain()
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str(
        "        _ => return Err(\"qualification domain has no generated provider-truth validator\".into()),\n\
    };\n\
    result.map_err(|error| error.to_string())\n\
}\n\n\
pub(crate) fn validate_provider_matrix_contract(domain: &str, bytes: &[u8], provider_version: &str, provider_artifact_sha256: &str) -> Result<(), String> {\n\
    let result = match domain {\n",
    );
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        writeln!(
            output,
            "        {:?} => {crate_name}::qualification::validate_provider_matrix_contract(bytes, provider_version, provider_artifact_sha256),",
            entry.domain()
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str(
        "        _ => return Err(\"qualification domain has no generated provider-matrix validator\".into()),\n\
    };\n\
    result.map_err(|error| error.to_string())\n\
}\n\n\
pub(crate) fn run_protected_observer(context: ObserveAdapterContext<'_>) -> Result<(), String> {\n\
    match context.domain {\n",
    );
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        let adapter = format!("{}QualificationAdapter", pascal(entry.domain()));
        writeln!(
            output,
            "        {:?} => observe_domain_adapter({crate_name}::qualification::{adapter}, context),",
            entry.domain()
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str(
        "        _ => Err(\"qualification domain is absent from the generated static observer roster\".into()),\n\
    }\n\
}\n\n\
pub(crate) fn run_protected_cleanup(context: CleanupAdapterContext<'_>) -> Result<(), String> {\n\
    match context.domain {\n",
    );
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        let adapter = format!("{}QualificationAdapter", pascal(entry.domain()));
        writeln!(
            output,
            "        {:?} => cleanup_domain_adapter({crate_name}::qualification::{adapter}, context),",
            entry.domain()
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str(
        "        _ => Err(\"qualification domain is absent from the generated static cleanup roster\".into()),\n\
    }\n\
}\n",
    );
    Ok(output)
}

fn render_qualification_source_routes(
    repository: &Path,
    roster: &ProfileRoster,
) -> Result<String, String> {
    let mut output = String::from(
        "// generated by auths-profile-generator/1 from the closed profile roster.\n\
//! Protected qualification provider routing.\n\n\
use auths_connections::{ProviderCredentialLease, QualificationProviderCallKind};\n\
use auths_profile_kit::{QualificationEffect, QualificationHarnessError, QualificationProfileStateFactV1};\n\
use auths_profile_runtime::{ProfileReceiptInspection, ProfileRuntimeError};\n\
use auths_stores::JournalRecordV1;\n\
use std::path::Path;\n\n\
#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
pub(crate) enum QualificationRoute {\n",
    );
    for entry in roster.packages() {
        writeln!(output, "    {},", pascal(entry.domain())).map_err(|error| error.to_string())?;
    }
    output.push_str("}\n\nimpl QualificationRoute {\n    pub(crate) fn for_profile(profile: &str) -> Result<Self, String> {\n        match profile {\n");
    for entry in roster.packages() {
        let profiles = entry
            .profiles()
            .iter()
            .map(|profile| format!("{:?}", profile.profile_ref()))
            .collect::<Vec<_>>()
            .join(" | ");
        writeln!(
            output,
            "            {profiles} => Ok(Self::{}),",
            pascal(entry.domain())
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("            _ => Err(\"profile is absent from the generated qualification route roster\".into()),\n        }\n    }\n\n");
    output.push_str("    #[allow(clippy::too_many_arguments)]\n    pub(crate) async fn dispatch_provider_transport(\n        self,\n        profile: &str,\n        kind: QualificationProviderCallKind,\n        command: &[u8],\n        profile_state: &[u8],\n        credential: &ProviderCredentialLease,\n        configuration: Option<&[u8]>,\n        transport_root: &Path,\n        operation_id: &str,\n        now_unix_seconds: u64,\n        deadline: std::time::Instant,\n    ) -> Result<Option<Vec<u8>>, ProfileRuntimeError> {\n        match self {\n");
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        writeln!(
            output,
            "            Self::{} => {crate_name}::qualification::dispatch_provider_transport(profile, kind, command, profile_state, credential, configuration, transport_root, operation_id, now_unix_seconds, deadline).await,",
            pascal(entry.domain())
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n    pub(crate) async fn observe_provider_truth(\n        self,\n        record: &JournalRecordV1,\n        credential: &[u8],\n        observer_root: &Path,\n        now_unix_seconds: u64,\n    ) -> Result<(QualificationEffect, Vec<u8>), ProfileRuntimeError> {\n        match self {\n");
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        let call = match entry.domain() {
            "stripe" => format!(
                "{crate_name}::qualification::observe_provider_truth(record, credential.to_vec()).await"
            ),
            "opentofu" => format!(
                "{crate_name}::qualification::observe_provider_truth(record, credential, observer_root, now_unix_seconds).await"
            ),
            _ => format!(
                "{crate_name}::qualification::observe_provider_truth(record, credential, now_unix_seconds).await"
            ),
        };
        writeln!(
            output,
            "            Self::{} => {call},",
            pascal(entry.domain())
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n    pub(crate) fn inspect_receipt_claims(\n        self,\n        profile: &str,\n        inspection: ProfileReceiptInspection<'_>,\n    ) -> Result<(), ProfileRuntimeError> {\n        match self {\n");
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        writeln!(
            output,
            "            Self::{} => {crate_name}::qualification::inspect_receipt_claims(profile, inspection),",
            pascal(entry.domain())
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n    pub(crate) fn validate_provider_truth(\n        self,\n        bytes: &[u8],\n        effect: QualificationEffect,\n    ) -> Result<(), QualificationHarnessError> {\n        match self {\n");
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        writeln!(
            output,
            "            Self::{} => {crate_name}::qualification::validate_provider_truth_facts(bytes, effect),",
            pascal(entry.domain())
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n    pub(crate) fn profile_state_snapshot_path(self) -> &'static str {\n        match self {\n");
    for entry in roster.packages() {
        let manifest_bytes =
            fs::read(repository.join(entry.manifest_path())).map_err(|error| error.to_string())?;
        let manifest: Value =
            serde_json::from_slice(&manifest_bytes).map_err(|error| error.to_string())?;
        let snapshot_path = manifest
            .get("qualification")
            .and_then(|value| value.get("profileStateSnapshot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "qualification profile-state snapshot is missing for {}",
                    entry.domain()
                )
            })?;
        writeln!(
            output,
            "            Self::{} => {:?},",
            pascal(entry.domain()),
            snapshot_path
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n    pub(crate) fn inspect_profile_state(\n        self,\n        profile: &str,\n        records: &[JournalRecordV1],\n        store_bytes: &[u8],\n    ) -> Result<Vec<QualificationProfileStateFactV1>, QualificationHarnessError> {\n        match self {\n");
    for entry in roster.packages() {
        let crate_name = entry.rust_package().replace('-', "_");
        writeln!(
            output,
            "            Self::{} => {crate_name}::qualification::inspect_profile_state(profile, records, store_bytes),",
            pascal(entry.domain())
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n}\n");
    Ok(output)
}

fn rustfmt_generated(contents: String) -> Result<String, String> {
    let mut file = tempfile::NamedTempFile::new().map_err(|error| error.to_string())?;
    file.write_all(contents.as_bytes())
        .map_err(|error| error.to_string())?;
    let status = Command::new("rustfmt")
        .arg("--edition")
        .arg("2024")
        .arg(file.path())
        .status()
        .map_err(|error| format!("failed to run rustfmt for generated Rust: {error}"))?;
    if !status.success() {
        return Err("rustfmt rejected generated profile route source".into());
    }
    fs::read_to_string(file.path()).map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
fn render_outputs(
    domain: &str,
    manifest_path: &str,
    digest: &str,
    manifest: &Value,
    api: &Value,
    package: &ProfilePackage,
    parsed_api: &ProfileApi,
    error_digests: &BTreeMap<(String, u16), [u8; 32]>,
    qualification_metadata: &BTreeMap<String, Vec<(String, String, String)>>,
) -> Result<BTreeMap<String, String>, String> {
    let mut outputs = BTreeMap::new();
    let types = api
        .get("types")
        .and_then(Value::as_object)
        .ok_or_else(|| "profile API types missing after validation".to_owned())?;
    let header = format!("generated by {GENERATOR}; source={manifest_path}; sha256={digest}");
    let success_types = package
        .profiles()
        .iter()
        .map(|profile| profile.client().success_type().to_owned())
        .collect::<BTreeSet<_>>();
    let package_root = format!("product/integrations/auths-{domain}/src/generated");
    outputs.insert(
        format!("{package_root}/mod.rs"),
        format!(
            "// {header}\n//! Generated profile caller API and route constants.\n\npub mod profile_api;\npub mod profile_routes;\n"
        ),
    );
    outputs.insert(
        format!("{package_root}/profile_api.rs"),
        render_rust_api(&header, api)?,
    );
    outputs.insert(
        format!("{package_root}/profile_routes.rs"),
        render_rust_routes(&header, package, parsed_api, error_digests)?,
    );

    let ts_root = format!("bindings/generated/{domain}/typescript");
    outputs.insert(
        format!("{ts_root}/src/generated.ts"),
        render_typescript_types(&header, types, &success_types)?,
    );
    outputs.insert(
        format!("{ts_root}/src/index.ts"),
        render_typescript_client(
            &header,
            domain,
            manifest,
            api,
            package,
            parsed_api,
            error_digests,
            qualification_metadata,
        )?,
    );
    outputs.insert(
        format!("{ts_root}/package.json"),
        pretty_json(&json!({
            "name": format!("@auths-dev/profile-{domain}"),
            "version": "1.0.0-rc.1",
            "type": "module",
            "engines": {"node": ">=20.6.0"},
            "exports": {".": {"types":"./dist/index.d.ts","import":"./dist/index.js"}},
            "peerDependencies": {"@auths-dev/sdk":"^1.0.0-rc.1"},
            "devDependencies": {"typescript":"5.9.3"},
            "scripts": {"build":"tsc -p tsconfig.json"},
            "files":["dist","README.md"]
        }))?,
    );
    outputs.insert(
        format!("{ts_root}/README.md"),
        render_typescript_quickstart(&header, domain, manifest, api, package)?,
    );
    outputs.insert(
        format!("{ts_root}/tsconfig.json"),
        pretty_json(&json!({
            "compilerOptions": {
                "declaration":true,"exactOptionalPropertyTypes":true,"lib":["DOM","ES2022","ESNext.Disposable"],
                "module":"NodeNext","moduleResolution":"NodeNext","outDir":"dist","rootDir":"src","strict":true,
                "target":"ES2022","types":[]
            },
            "include":["src/**/*.ts"]
        }))?,
    );

    let python_root = format!("bindings/generated/{domain}/python");
    let module_domain = domain.replace('-', "_");
    outputs.insert(
        format!("{python_root}/src/auths_profiles/{module_domain}/generated.py"),
        render_python_types(&header, types, &success_types)?,
    );
    outputs.insert(
        format!("{python_root}/src/auths_profiles/{module_domain}/__init__.py"),
        render_python_client(
            &header,
            domain,
            manifest,
            api,
            package,
            parsed_api,
            error_digests,
            qualification_metadata,
        )?,
    );
    outputs.insert(
        format!("{python_root}/src/auths_profiles/{module_domain}/py.typed"),
        format!("# {header}\n"),
    );
    outputs.insert(
        format!("{python_root}/pyproject.toml"),
        format!(
            "# {header}\n[build-system]\nrequires = [\"setuptools>=75\"]\nbuild-backend = \"setuptools.build_meta\"\n\n[project]\nname = \"auths-profile-{domain}\"\nversion = \"1.0.0rc1\"\nrequires-python = \">=3.9\"\nreadme = \"README.md\"\ndependencies = [\"auths>=1.0.0rc1,<2\"]\n\n[tool.setuptools.packages.find]\nwhere = [\"src\"]\ninclude = [\"auths_profiles.{module_domain}\"]\n\n[tool.setuptools.package-data]\n\"auths_profiles.{module_domain}\" = [\"py.typed\"]\n"
        ),
    );
    outputs.insert(
        format!("{python_root}/README.md"),
        render_python_quickstart(&header, domain, manifest, api, package)?,
    );
    outputs.insert(
        format!("bindings/generated/{domain}/fixtures/manifest-digests.json"),
        render_digest_fixture(manifest_path, digest, package, parsed_api, error_digests)?,
    );
    Ok(outputs)
}

fn primary_profile(manifest: &Value) -> Result<&Value, String> {
    manifest
        .get("profiles")
        .and_then(Value::as_array)
        .and_then(|profiles| {
            profiles.iter().max_by_key(|profile| {
                profile
                    .pointer("/limits/requestBytes")
                    .and_then(Value::as_u64)
                    .unwrap_or_default()
            })
        })
        .ok_or_else(|| "generated quickstart requires one profile".to_owned())
}

fn render_typescript_quickstart(
    header: &str,
    domain: &str,
    manifest: &Value,
    api: &Value,
    package: &ProfilePackage,
) -> Result<String, String> {
    let profile = primary_profile(manifest)?;
    let client = profile
        .get("client")
        .ok_or_else(|| "profile client missing".to_owned())?;
    let input = string(client, "inputType")?;
    let node = api
        .pointer(&format!("/types/{input}"))
        .ok_or_else(|| format!("input type {input} missing"))?;
    let value = ts_example(node, api, 0)?;
    let group = camel(string(client, "group")?);
    let method = string(client, "method")?;
    let class_name = package.domain().client_class();
    let constructor = if manifest
        .pointer("/domain/connection")
        .is_some_and(|value| !value.is_null())
    {
        format!("new {class_name}(session, {{ connection: \"default\" }})")
    } else {
        format!("new {class_name}(session)")
    };
    Ok(format!(
        "<!-- {header} -->\n# `@auths-dev/profile-{domain}` application contract\n\nInstalling this generated package does not activate its effect route. The exact local-agent build must advertise a qualified matching profile; otherwise the session fails closed before provider access.\n\nThe application uses ambient local-agent identity; it receives no Auths token or provider credential.\n\n```ts\nimport {{ connect }} from \"@auths-dev/sdk\";\nimport {{ {class_name} }} from \"@auths-dev/profile-{domain}\";\n\nawait using session = await connect();\nconst client = {constructor};\nconst result = await client.{group}.{method}({value});\nconsole.log(result.auths.operationId);\n```\n\nAfter qualification, the operator provisions the optional `default` connection alias separately. Possible effects return a typed recovery error; do not repeat the original call.\n"
    ))
}

fn render_python_quickstart(
    header: &str,
    domain: &str,
    manifest: &Value,
    api: &Value,
    package: &ProfilePackage,
) -> Result<String, String> {
    let profile = primary_profile(manifest)?;
    let client = profile
        .get("client")
        .ok_or_else(|| "profile client missing".to_owned())?;
    let input = string(client, "inputType")?;
    let node = api
        .pointer(&format!("/types/{input}"))
        .ok_or_else(|| format!("input type {input} missing"))?;
    let mut imports = BTreeSet::new();
    collect_reference_names(node, api, &mut imports, 0)?;
    imports.insert(package.domain().client_class().to_owned());
    let imports = imports.into_iter().collect::<Vec<_>>().join(", ");
    let fields = array(node, "fields")?
        .iter()
        .map(|field| {
            Ok(format!(
                "        {}={},",
                snake(string(field, "name")?),
                py_example(
                    field
                        .get("value")
                        .ok_or_else(|| "field value missing".to_owned())?,
                    api,
                    0,
                )?
            ))
        })
        .collect::<Result<Vec<_>, String>>()?
        .join("\n");
    let group = snake(string(client, "group")?);
    let method = snake(string(client, "method")?);
    let class_name = package.domain().client_class();
    let constructor = if manifest
        .pointer("/domain/connection")
        .is_some_and(|value| !value.is_null())
    {
        format!("{class_name}(session, connection=\"default\")")
    } else {
        format!("{class_name}(session)")
    };
    Ok(format!(
        "<!-- {header} -->\n# `auths-profile-{domain}` application contract\n\nInstalling this generated package does not activate its effect route. The exact local-agent build must advertise a qualified matching profile; otherwise the session fails closed before provider access.\n\nThe application uses ambient local-agent identity; it receives no Auths token or provider credential.\n\n```python\nimport auths\nfrom auths_profiles.{module} import {imports}\n\nasync with auths.connect() as session:\n    client = {constructor}\n    result = await client.{group}.{method}(\n{fields}\n    )\n    print(result.auths.operation_id)\n```\n\nAfter qualification, the operator provisions the optional `default` connection alias separately. Possible effects raise a typed recovery error; do not repeat the original call.\n",
        module = domain.replace('-', "_")
    ))
}

fn ts_example(node: &Value, api: &Value, depth: usize) -> Result<String, String> {
    if depth > 16 {
        return Err("generated quickstart type depth exceeds 16".into());
    }
    match string(node, "kind")? {
        "boolean" => Ok("false".into()),
        "uint" | "int" => {
            let minimum = string(node, "minimum")?;
            let maximum = string(node, "maximum")?
                .parse::<i128>()
                .map_err(|error| error.to_string())?;
            Ok(if maximum > 9_007_199_254_740_991 {
                format!("{minimum}n")
            } else {
                minimum.into()
            })
        }
        "string" => example_string(node),
        "bytes" => Ok(format!(
            "new Uint8Array({})",
            node.get("minimumBytes")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        )),
        "enum" => Ok(format!(
            "{:?}",
            array(node, "values")?
                .first()
                .and_then(Value::as_str)
                .ok_or_else(|| "empty enum".to_owned())?
        )),
        "ref" => ts_example(reference(api, string(node, "name")?)?, api, depth + 1),
        "list" => {
            let minimum = node
                .get("minimumItems")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let value = ts_example(
                node.get("value")
                    .ok_or_else(|| "list value missing".to_owned())?,
                api,
                depth + 1,
            )?;
            Ok(format!("[{}]", vec![value; minimum as usize].join(", ")))
        }
        "record" => Ok(format!(
            "{{ {} }}",
            array(node, "fields")?
                .iter()
                .map(|field| Ok(format!(
                    "{}: {}",
                    string(field, "name")?,
                    ts_example(
                        field
                            .get("value")
                            .ok_or_else(|| "field value missing".to_owned())?,
                        api,
                        depth + 1
                    )?
                )))
                .collect::<Result<Vec<_>, String>>()?
                .join(", ")
        )),
        "union" => {
            let variant = array(node, "variants")?
                .first()
                .ok_or_else(|| "empty union".to_owned())?;
            let mut fields = vec![format!(
                "{}: {:?}",
                string(node, "discriminator")?,
                string(variant, "tag")?
            )];
            for field in array(variant, "fields")? {
                fields.push(format!(
                    "{}: {}",
                    string(field, "name")?,
                    ts_example(
                        field
                            .get("value")
                            .ok_or_else(|| "field value missing".to_owned())?,
                        api,
                        depth + 1,
                    )?
                ));
            }
            Ok(format!("{{ {} }}", fields.join(", ")))
        }
        kind => Err(format!("unsupported quickstart TypeScript kind {kind}")),
    }
}

fn py_example(node: &Value, api: &Value, depth: usize) -> Result<String, String> {
    if depth > 16 {
        return Err("generated quickstart type depth exceeds 16".into());
    }
    match string(node, "kind")? {
        "boolean" => Ok("False".into()),
        "uint" | "int" => Ok(string(node, "minimum")?.into()),
        "string" => example_string(node),
        "bytes" => Ok(format!(
            "bytes({})",
            node.get("minimumBytes")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        )),
        "enum" => Ok(format!(
            "{:?}",
            array(node, "values")?
                .first()
                .and_then(Value::as_str)
                .ok_or_else(|| "empty enum".to_owned())?
        )),
        "ref" => {
            let name = string(node, "name")?;
            let referenced = reference(api, name)?;
            if string(referenced, "kind")? == "record" {
                Ok(format!(
                    "{name}({})",
                    array(referenced, "fields")?
                        .iter()
                        .map(|field| Ok(format!(
                            "{}={}",
                            snake(string(field, "name")?),
                            py_example(
                                field
                                    .get("value")
                                    .ok_or_else(|| "field value missing".to_owned())?,
                                api,
                                depth + 1
                            )?
                        )))
                        .collect::<Result<Vec<_>, String>>()?
                        .join(", ")
                ))
            } else {
                py_example(referenced, api, depth + 1)
            }
        }
        "list" => {
            let minimum = node
                .get("minimumItems")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let value = py_example(
                node.get("value")
                    .ok_or_else(|| "list value missing".to_owned())?,
                api,
                depth + 1,
            )?;
            let values = vec![value; minimum as usize];
            Ok(match values.as_slice() {
                [] => "()".into(),
                [only] => format!("({only},)"),
                _ => format!("({})", values.join(", ")),
            })
        }
        kind => Err(format!("unsupported quickstart Python kind {kind}")),
    }
}

fn reference<'a>(api: &'a Value, name: &str) -> Result<&'a Value, String> {
    api.pointer(&format!("/types/{name}"))
        .ok_or_else(|| format!("referenced type {name} missing"))
}

fn collect_reference_names(
    node: &Value,
    api: &Value,
    output: &mut BTreeSet<String>,
    depth: usize,
) -> Result<(), String> {
    if depth > 16 {
        return Err("generated quickstart type depth exceeds 16".into());
    }
    match string(node, "kind")? {
        "ref" => {
            let name = string(node, "name")?;
            if output.insert(name.to_owned()) {
                collect_reference_names(reference(api, name)?, api, output, depth + 1)?;
            }
        }
        "list" => collect_reference_names(
            node.get("value")
                .ok_or_else(|| "list value missing".to_owned())?,
            api,
            output,
            depth + 1,
        )?,
        "record" => {
            for field in array(node, "fields")? {
                collect_reference_names(
                    field
                        .get("value")
                        .ok_or_else(|| "field value missing".to_owned())?,
                    api,
                    output,
                    depth + 1,
                )?;
            }
        }
        "union" => {
            for variant in array(node, "variants")? {
                for field in array(variant, "fields")? {
                    collect_reference_names(
                        field
                            .get("value")
                            .ok_or_else(|| "field value missing".to_owned())?,
                        api,
                        output,
                        depth + 1,
                    )?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn example_string(node: &Value) -> Result<String, String> {
    let minimum = node
        .get("minimumBytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| "string minimumBytes missing".to_owned())? as usize;
    let alphabet = string(node, "alphabet")?;
    let fill = if alphabet == "lower-hex" { '0' } else { 'x' };
    Ok(format!("{:?}", fill.to_string().repeat(minimum)))
}

fn render_rust_api(header: &str, api: &Value) -> Result<String, String> {
    let api_json = serde_json::to_string(api).map_err(|error| error.to_string())?;
    let source_types = api
        .get("types")
        .and_then(Value::as_object)
        .ok_or_else(|| "profile API types missing after validation".to_owned())?;
    let types = collect_rust_types(source_types)?;
    let mut output = format!(
        "// {header}\n//! Generated restricted caller DTOs and deterministic-CBOR codecs.\n\n#![allow(\n    clippy::deref_addrof,\n    clippy::let_and_return,\n    clippy::manual_range_contains,\n    clippy::missing_errors_doc,\n    clippy::must_use_candidate,\n    clippy::needless_borrow,\n    clippy::trivially_copy_pass_by_ref,\n    clippy::unreadable_literal,\n    clippy::useless_conversion,\n)]\n\n#[allow(unused_imports)]\nuse minicbor::{{Decoder, Encoder, data::Type}};\nuse std::collections::BTreeMap;\n\n/// Exact validated `auths.profile-api/1` JSON.\npub const PROFILE_API_JSON: &str = r#\"{api_json}\"#;\n\n"
    );
    output.push_str(
        "/// Closed generated profile-API codec failure.\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub enum ProfileApiCodecError { Malformed, NonCanonical, Limit }\n\nimpl core::fmt::Display for ProfileApiCodecError {\n    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {\n        formatter.write_str(match self { Self::Malformed => \"malformed generated profile value\", Self::NonCanonical => \"non-canonical generated profile value\", Self::Limit => \"generated profile value exceeds its bound\" })\n    }\n}\n\nimpl std::error::Error for ProfileApiCodecError {}\n\n",
    );
    for (name, node) in &types {
        render_rust_named_type(&mut output, name, node)?;
    }
    output.push_str(RUST_CODEC_HELPERS);
    rustfmt_generated(output)
}

const RUST_CODEC_HELPERS: &str = r#"
fn codec<T>(_: T) -> ProfileApiCodecError { ProfileApiCodecError::Malformed }

fn exact_map(decoder: &mut Decoder<'_>, expected: usize) -> Result<(), ProfileApiCodecError> {
    let count = decoder.map().map_err(codec)?.ok_or(ProfileApiCodecError::Malformed)?;
    if usize::try_from(count).ok() != Some(expected) { return Err(ProfileApiCodecError::Malformed); }
    Ok(())
}

#[allow(dead_code)]
fn exact_array(decoder: &mut Decoder<'_>, minimum: usize, maximum: usize) -> Result<usize, ProfileApiCodecError> {
    let count = decoder.array().map_err(codec)?.ok_or(ProfileApiCodecError::Malformed)?;
    let count = usize::try_from(count).map_err(|_| ProfileApiCodecError::Limit)?;
    if count < minimum || count > maximum { return Err(ProfileApiCodecError::Limit); }
    Ok(count)
}

fn expect_key(decoder: &mut Decoder<'_>, expected: &str) -> Result<(), ProfileApiCodecError> {
    if decoder.str().map_err(codec)? != expected { return Err(ProfileApiCodecError::Malformed); }
    Ok(())
}

fn finish(decoder: &Decoder<'_>, bytes: &[u8]) -> Result<(), ProfileApiCodecError> {
    if decoder.position() != bytes.len() { return Err(ProfileApiCodecError::Malformed); }
    Ok(())
}

fn valid_string(value: &str, minimum: usize, maximum: usize, alphabet: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < minimum || bytes.len() > maximum { return false; }
    match alphabet {
        "utf8" => !value.chars().any(|character| matches!(character as u32, 0..=31 | 127..=159)),
        "ascii-graphic" => bytes.iter().all(|byte| matches!(byte, 0x21..=0x7e)),
        "registered-token" => bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')),
        "lower-token" => bytes.first().is_some_and(u8::is_ascii_lowercase)
            && bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'),
        "lower-hex" => !bytes.is_empty() && bytes.iter().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "base64url" => !bytes.is_empty() && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        _ => false,
    }
}

#[allow(dead_code)]
fn decode_union_fields(decoder: &mut Decoder<'_>, maximum: usize) -> Result<BTreeMap<String, Vec<u8>>, ProfileApiCodecError> {
    let count = decoder.map().map_err(codec)?.ok_or(ProfileApiCodecError::Malformed)?;
    let count = usize::try_from(count).map_err(|_| ProfileApiCodecError::Limit)?;
    if count == 0 || count > maximum { return Err(ProfileApiCodecError::Limit); }
    let mut fields = BTreeMap::new();
    for _ in 0..count {
        let key = decoder.str().map_err(codec)?.to_owned();
        let start = decoder.position();
        decoder.skip().map_err(codec)?;
        let end = decoder.position();
        if fields.insert(key, decoder.input()[start..end].to_vec()).is_some() {
            return Err(ProfileApiCodecError::Malformed);
        }
    }
    Ok(fields)
}

#[allow(dead_code)]
fn decode_isolated<T>(bytes: &[u8], decode: impl FnOnce(&mut Decoder<'_>) -> Result<T, ProfileApiCodecError>) -> Result<T, ProfileApiCodecError> {
    let mut decoder = Decoder::new(bytes);
    let value = decode(&mut decoder)?;
    finish(&decoder, bytes)?;
    Ok(value)
}
"#;

fn collect_rust_types(
    source: &serde_json::Map<String, Value>,
) -> Result<BTreeMap<String, Value>, String> {
    let mut output = source
        .iter()
        .map(|(name, node)| (name.clone(), node.clone()))
        .collect::<BTreeMap<_, _>>();
    let declared = output.keys().cloned().collect::<BTreeSet<_>>();
    for (name, node) in source {
        collect_inline_rust_types(name, node, &declared, &mut output, true)?;
    }
    Ok(output)
}

fn collect_inline_rust_types(
    name: &str,
    node: &Value,
    declared: &BTreeSet<String>,
    output: &mut BTreeMap<String, Value>,
    root: bool,
) -> Result<(), String> {
    let kind = string(node, "kind")?;
    if !root
        && matches!(kind, "enum" | "record" | "union")
        && (declared.contains(name) || output.insert(name.to_owned(), node.clone()).is_some())
    {
        return Err(format!("generated Rust type name collides: {name}"));
    }
    match kind {
        "option" => collect_inline_rust_types(
            &format!("{name}Value"),
            node.get("value")
                .ok_or_else(|| "option value missing".to_owned())?,
            declared,
            output,
            false,
        ),
        "list" => collect_inline_rust_types(
            &format!("{name}Item"),
            node.get("value")
                .ok_or_else(|| "list value missing".to_owned())?,
            declared,
            output,
            false,
        ),
        "record" => {
            for field in array(node, "fields")? {
                let field_name = string(field, "name")?;
                collect_inline_rust_types(
                    &format!("{name}{}", pascal(field_name)),
                    field
                        .get("value")
                        .ok_or_else(|| "record field value missing".to_owned())?,
                    declared,
                    output,
                    false,
                )?;
            }
            Ok(())
        }
        "union" => {
            for variant in array(node, "variants")? {
                let variant_name = pascal(string(variant, "tag")?);
                for field in array(variant, "fields")? {
                    let field_name = string(field, "name")?;
                    collect_inline_rust_types(
                        &format!("{name}{variant_name}{}", pascal(field_name)),
                        field
                            .get("value")
                            .ok_or_else(|| "union field value missing".to_owned())?,
                        declared,
                        output,
                        false,
                    )?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn render_rust_named_type(output: &mut String, name: &str, node: &Value) -> Result<(), String> {
    match string(node, "kind")? {
        "record" => render_rust_record(output, name, node),
        "enum" => render_rust_enum(output, name, node),
        "union" => render_rust_union(output, name, node),
        _ => render_rust_newtype(output, name, node),
    }
}

fn render_rust_record(output: &mut String, name: &str, node: &Value) -> Result<(), String> {
    let fields = array(node, "fields")?;
    writeln!(
        output,
        "#[derive(Clone, Debug, Eq, PartialEq)]\npub struct {name} {{"
    )
    .map_err(|error| error.to_string())?;
    for field in fields {
        let canonical = string(field, "name")?;
        let field_type = rust_type(
            field
                .get("value")
                .ok_or_else(|| "record field value missing".to_owned())?,
            &format!("{name}{}", pascal(canonical)),
        )?;
        writeln!(output, "    pub {}: {field_type},", rust_field(canonical))
            .map_err(|error| error.to_string())?;
    }
    output.push_str("}\n\n");
    render_rust_codec_open(output, name)?;
    let mut ordered = fields.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|field| cbor_text_order(string(field, "name").unwrap_or_default()));
    writeln!(
        output,
        "        encoder.map({}).map_err(codec)?;",
        fields.len()
    )
    .map_err(|error| error.to_string())?;
    for field in &ordered {
        let canonical = string(field, "name")?;
        writeln!(
            output,
            "        encoder.str({canonical:?}).map_err(codec)?;"
        )
        .map_err(|error| error.to_string())?;
        render_rust_encode(
            output,
            field
                .get("value")
                .ok_or_else(|| "record field value missing".to_owned())?,
            &format!("&self.{}", rust_field(canonical)),
            &format!("{name}{}", pascal(canonical)),
            2,
        )?;
    }
    output.push_str("        Ok(())\n    }\n\n    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ProfileApiCodecError> {\n");
    writeln!(output, "        exact_map(decoder, {})?;", fields.len())
        .map_err(|error| error.to_string())?;
    for field in &ordered {
        let canonical = string(field, "name")?;
        writeln!(output, "        expect_key(decoder, {canonical:?})?;")
            .map_err(|error| error.to_string())?;
        let expression = rust_decode_expression(
            field
                .get("value")
                .ok_or_else(|| "record field value missing".to_owned())?,
            "decoder",
            &format!("{name}{}", pascal(canonical)),
        )?;
        writeln!(
            output,
            "        let {} = {expression};",
            rust_field(canonical)
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        Ok(Self {\n");
    for field in fields {
        writeln!(
            output,
            "            {},",
            rust_field(string(field, "name")?)
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("        })\n    }\n}\n\n");
    Ok(())
}

fn render_rust_enum(output: &mut String, name: &str, node: &Value) -> Result<(), String> {
    let values = array(node, "values")?;
    writeln!(
        output,
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub enum {name} {{"
    )
    .map_err(|error| error.to_string())?;
    for value in values {
        writeln!(
            output,
            "    {},",
            pascal(value.as_str().unwrap_or_default())
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("}\n\n");
    writeln!(
        output,
        "impl {name} {{\n    pub const fn as_str(self) -> &'static str {{\n        match self {{"
    )
    .map_err(|error| error.to_string())?;
    for value in values {
        let value = value.as_str().unwrap_or_default();
        writeln!(output, "            Self::{} => {value:?},", pascal(value))
            .map_err(|error| error.to_string())?;
    }
    output.push_str("        }\n    }\n\n");
    render_rust_public_codec_methods(output, name)?;
    output.push_str("    fn encode_into(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), ProfileApiCodecError> {\n        encoder.str(self.as_str()).map_err(codec)?;\n        Ok(())\n    }\n\n    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ProfileApiCodecError> {\n        match decoder.str().map_err(codec)? {\n");
    for value in values {
        let value = value.as_str().unwrap_or_default();
        writeln!(
            output,
            "            {value:?} => Ok(Self::{}),",
            pascal(value)
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str(
        "            _ => Err(ProfileApiCodecError::Malformed),\n        }\n    }\n}\n\n",
    );
    Ok(())
}

fn render_rust_union(output: &mut String, name: &str, node: &Value) -> Result<(), String> {
    let variants = array(node, "variants")?;
    writeln!(
        output,
        "#[derive(Clone, Debug, Eq, PartialEq)]\npub enum {name} {{"
    )
    .map_err(|error| error.to_string())?;
    for variant in variants {
        let variant_name = pascal(string(variant, "tag")?);
        writeln!(output, "    {variant_name} {{").map_err(|error| error.to_string())?;
        for field in array(variant, "fields")? {
            let canonical = string(field, "name")?;
            let field_type = rust_type(
                field
                    .get("value")
                    .ok_or_else(|| "union field value missing".to_owned())?,
                &format!("{name}{variant_name}{}", pascal(canonical)),
            )?;
            writeln!(output, "        {}: {field_type},", rust_field(canonical))
                .map_err(|error| error.to_string())?;
        }
        output.push_str("    },\n");
    }
    output.push_str("}\n\n");
    render_rust_codec_open(output, name)?;
    output.push_str("        match self {\n");
    for variant in variants {
        let tag = string(variant, "tag")?;
        let variant_name = pascal(tag);
        let fields = array(variant, "fields")?;
        write!(output, "            Self::{variant_name} {{ ")
            .map_err(|error| error.to_string())?;
        for field in fields {
            write!(output, "{}, ", rust_field(string(field, "name")?))
                .map_err(|error| error.to_string())?;
        }
        output.push_str("} => {\n");
        writeln!(
            output,
            "                encoder.map({}).map_err(codec)?;",
            fields.len() + 1
        )
        .map_err(|error| error.to_string())?;
        let mut pairs = fields
            .iter()
            .map(|field| (string(field, "name").unwrap_or_default(), Some(field)))
            .collect::<Vec<_>>();
        pairs.push(("kind", None));
        pairs.sort_by_key(|(key, _)| cbor_text_order(key));
        for (key, field) in pairs {
            writeln!(
                output,
                "                encoder.str({key:?}).map_err(codec)?;"
            )
            .map_err(|error| error.to_string())?;
            if let Some(field) = field {
                render_rust_encode(
                    output,
                    field
                        .get("value")
                        .ok_or_else(|| "union field value missing".to_owned())?,
                    rust_field(key).as_str(),
                    &format!("{name}{variant_name}{}", pascal(key)),
                    4,
                )?;
            } else {
                writeln!(
                    output,
                    "                encoder.str({tag:?}).map_err(codec)?;"
                )
                .map_err(|error| error.to_string())?;
            }
        }
        output.push_str("                Ok(())\n            }\n");
    }
    output.push_str("        }\n    }\n\n    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ProfileApiCodecError> {\n");
    let maximum = variants
        .iter()
        .map(|variant| array(variant, "fields").map(|fields| fields.len() + 1))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .unwrap_or(1);
    writeln!(
        output,
        "        let mut fields = decode_union_fields(decoder, {maximum})?;"
    )
    .map_err(|error| error.to_string())?;
    output.push_str("        let kind = fields.remove(\"kind\").ok_or(ProfileApiCodecError::Malformed)?;\n        let kind = decode_isolated(&kind, |decoder| decoder.str().map(str::to_owned).map_err(codec))?;\n        match kind.as_str() {\n");
    for variant in variants {
        let tag = string(variant, "tag")?;
        let variant_name = pascal(tag);
        let fields = array(variant, "fields")?;
        writeln!(
            output,
            "            {tag:?} if fields.len() == {} => {{",
            fields.len()
        )
        .map_err(|error| error.to_string())?;
        for field in fields {
            let canonical = string(field, "name")?;
            let expression = rust_decode_expression(
                field
                    .get("value")
                    .ok_or_else(|| "union field value missing".to_owned())?,
                "decoder",
                &format!("{name}{variant_name}{}", pascal(canonical)),
            )?;
            writeln!(output, "                let raw = fields.remove({canonical:?}).ok_or(ProfileApiCodecError::Malformed)?;\n                let {} = decode_isolated(&raw, |decoder| Ok({expression}))?;", rust_field(canonical))
                .map_err(|error| error.to_string())?;
        }
        write!(output, "                Ok(Self::{variant_name} {{ ")
            .map_err(|error| error.to_string())?;
        for field in fields {
            write!(output, "{}, ", rust_field(string(field, "name")?))
                .map_err(|error| error.to_string())?;
        }
        output.push_str("})\n            }\n");
    }
    output.push_str(
        "            _ => Err(ProfileApiCodecError::Malformed),\n        }\n    }\n}\n\n",
    );
    Ok(())
}

fn render_rust_newtype(output: &mut String, name: &str, node: &Value) -> Result<(), String> {
    let inner = rust_type(node, name)?;
    writeln!(
        output,
        "#[derive(Clone, Debug, Eq, PartialEq)]\npub struct {name}(pub {inner});\n"
    )
    .map_err(|error| error.to_string())?;
    render_rust_codec_open(output, name)?;
    render_rust_encode(output, node, "&self.0", name, 2)?;
    output.push_str("        Ok(())\n    }\n\n    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ProfileApiCodecError> {\n");
    let expression = rust_decode_expression(node, "decoder", name)?;
    writeln!(output, "        Ok(Self({expression}))\n    }}\n")
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn render_rust_codec_open(output: &mut String, name: &str) -> Result<(), String> {
    writeln!(output, "impl {name} {{").map_err(|error| error.to_string())?;
    render_rust_public_codec_methods(output, name)?;
    output.push_str("    fn encode_into(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), ProfileApiCodecError> {\n");
    Ok(())
}

fn render_rust_public_codec_methods(output: &mut String, _name: &str) -> Result<(), String> {
    output.push_str(
        "    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProfileApiCodecError> {\n        let mut encoder = Encoder::new(Vec::new());\n        self.encode_into(&mut encoder)?;\n        Ok(encoder.into_writer())\n    }\n\n    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ProfileApiCodecError> {\n        let mut decoder = Decoder::new(bytes);\n        let value = Self::decode_from(&mut decoder)?;\n        finish(&decoder, bytes)?;\n        if value.to_canonical_cbor()?.as_slice() != bytes { return Err(ProfileApiCodecError::NonCanonical); }\n        Ok(value)\n    }\n\n",
    );
    Ok(())
}

fn rust_type(node: &Value, hint: &str) -> Result<String, String> {
    match string(node, "kind")? {
        "boolean" => Ok("bool".into()),
        "uint" => Ok(format!(
            "u{}",
            node.get("bits")
                .and_then(Value::as_u64)
                .ok_or_else(|| "uint bits missing".to_owned())?
        )),
        "int" => Ok(format!(
            "i{}",
            node.get("bits")
                .and_then(Value::as_u64)
                .ok_or_else(|| "int bits missing".to_owned())?
        )),
        "string" => Ok("String".into()),
        "bytes" => Ok("Vec<u8>".into()),
        "enum" | "record" | "union" => Ok(hint.into()),
        "ref" => Ok(string(node, "name")?.into()),
        "option" => Ok(format!(
            "Option<{}>",
            rust_type(
                node.get("value")
                    .ok_or_else(|| "option value missing".to_owned())?,
                &format!("{hint}Value")
            )?
        )),
        "list" => Ok(format!(
            "Vec<{}>",
            rust_type(
                node.get("value")
                    .ok_or_else(|| "list value missing".to_owned())?,
                &format!("{hint}Item")
            )?
        )),
        kind => Err(format!("unsupported generated Rust kind {kind}")),
    }
}

fn render_rust_encode(
    output: &mut String,
    node: &Value,
    access: &str,
    hint: &str,
    indent: usize,
) -> Result<(), String> {
    let pad = "    ".repeat(indent);
    let line = match string(node, "kind")? {
        "boolean" => format!("encoder.bool(*{access}).map_err(codec)?;"),
        "uint" => {
            let bits = node
                .get("bits")
                .and_then(Value::as_u64)
                .ok_or_else(|| "uint bits missing".to_owned())?;
            let minimum = string(node, "minimum")?;
            let maximum = string(node, "maximum")?;
            format!(
                "if !({minimum}u{bits}..={maximum}u{bits}).contains({access}) {{ return Err(ProfileApiCodecError::Limit); }} encoder.u64(u64::from(*{access})).map_err(codec)?;"
            )
        }
        "int" => {
            let bits = node
                .get("bits")
                .and_then(Value::as_u64)
                .ok_or_else(|| "int bits missing".to_owned())?;
            let minimum = string(node, "minimum")?;
            let maximum = string(node, "maximum")?;
            format!(
                "if !({minimum}i{bits}..={maximum}i{bits}).contains({access}) {{ return Err(ProfileApiCodecError::Limit); }} encoder.i64(i64::from(*{access})).map_err(codec)?;"
            )
        }
        "string" => {
            let minimum = node
                .get("minimumBytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| "string minimum missing".to_owned())?;
            let maximum = node
                .get("maximumBytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| "string maximum missing".to_owned())?;
            let alphabet = string(node, "alphabet")?;
            format!(
                "if !valid_string({access}, {minimum}usize, {maximum}usize, {alphabet:?}) {{ return Err(ProfileApiCodecError::Limit); }} encoder.str({access}).map_err(codec)?;"
            )
        }
        "bytes" => {
            let minimum = node
                .get("minimumBytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| "bytes minimum missing".to_owned())?;
            let maximum = node
                .get("maximumBytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| "bytes maximum missing".to_owned())?;
            format!(
                "if !({minimum}usize..={maximum}usize).contains(&({access}).len()) {{ return Err(ProfileApiCodecError::Limit); }} encoder.bytes({access}).map_err(codec)?;"
            )
        }
        "enum" | "record" | "union" | "ref" => {
            format!("({access}).encode_into(encoder)?;")
        }
        "option" => {
            writeln!(output, "{pad}match {access} {{").map_err(|error| error.to_string())?;
            writeln!(output, "{pad}    Some(value) => {{").map_err(|error| error.to_string())?;
            render_rust_encode(
                output,
                node.get("value")
                    .ok_or_else(|| "option value missing".to_owned())?,
                "value",
                &format!("{hint}Value"),
                indent + 2,
            )?;
            writeln!(
                output,
                "{pad}    }}\n{pad}    None => {{ encoder.null().map_err(codec)?; }}\n{pad}}}"
            )
            .map_err(|error| error.to_string())?;
            return Ok(());
        }
        "list" => {
            let minimum = node
                .get("minimumItems")
                .and_then(Value::as_u64)
                .ok_or_else(|| "list minimum missing".to_owned())?;
            let maximum = node
                .get("maximumItems")
                .and_then(Value::as_u64)
                .ok_or_else(|| "list maximum missing".to_owned())?;
            writeln!(output, "{pad}if !({minimum}usize..={maximum}usize).contains(&({access}).len()) {{ return Err(ProfileApiCodecError::Limit); }}").map_err(|error| error.to_string())?;
            writeln!(output, "{pad}encoder.array(({access}).len() as u64).map_err(codec)?;\n{pad}for value in {access} {{").map_err(|error| error.to_string())?;
            render_rust_encode(
                output,
                node.get("value")
                    .ok_or_else(|| "list value missing".to_owned())?,
                "value",
                &format!("{hint}Item"),
                indent + 1,
            )?;
            writeln!(output, "{pad}}}").map_err(|error| error.to_string())?;
            return Ok(());
        }
        kind => return Err(format!("unsupported generated Rust encode kind {kind}")),
    };
    writeln!(output, "{pad}{line}").map_err(|error| error.to_string())
}

fn rust_decode_expression(node: &Value, decoder: &str, hint: &str) -> Result<String, String> {
    match string(node, "kind")? {
        "boolean" => Ok(format!("{decoder}.bool().map_err(codec)?")),
        "uint" => {
            let bits = node
                .get("bits")
                .and_then(Value::as_u64)
                .ok_or_else(|| "uint bits missing".to_owned())?;
            let minimum = string(node, "minimum")?;
            let maximum = string(node, "maximum")?;
            let minimum_value = minimum.parse::<u64>().map_err(|error| error.to_string())?;
            let maximum_value = maximum.parse::<u64>().map_err(|error| error.to_string())?;
            let type_maximum = if bits == 64 {
                u64::MAX
            } else {
                (1_u64 << bits) - 1
            };
            let mut conditions = Vec::new();
            if minimum_value > 0 {
                conditions.push(format!("value < {minimum}u{bits}"));
            }
            if maximum_value < type_maximum {
                conditions.push(format!("value > {maximum}u{bits}"));
            }
            let check = if conditions.is_empty() {
                String::new()
            } else {
                format!(
                    " if {} {{ return Err(ProfileApiCodecError::Limit); }}",
                    conditions.join(" || ")
                )
            };
            Ok(format!(
                "{{ let value = {decoder}.u{bits}().map_err(codec)?;{check} value }}"
            ))
        }
        "int" => {
            let bits = node
                .get("bits")
                .and_then(Value::as_u64)
                .ok_or_else(|| "int bits missing".to_owned())?;
            let minimum = string(node, "minimum")?;
            let maximum = string(node, "maximum")?;
            let minimum_value = minimum.parse::<i64>().map_err(|error| error.to_string())?;
            let maximum_value = maximum.parse::<i64>().map_err(|error| error.to_string())?;
            let (type_minimum, type_maximum) = if bits == 64 {
                (i64::MIN, i64::MAX)
            } else {
                (-(1_i64 << (bits - 1)), (1_i64 << (bits - 1)) - 1)
            };
            let mut conditions = Vec::new();
            if minimum_value > type_minimum {
                conditions.push(format!("value < {minimum}i{bits}"));
            }
            if maximum_value < type_maximum {
                conditions.push(format!("value > {maximum}i{bits}"));
            }
            let check = if conditions.is_empty() {
                String::new()
            } else {
                format!(
                    " if {} {{ return Err(ProfileApiCodecError::Limit); }}",
                    conditions.join(" || ")
                )
            };
            Ok(format!(
                "{{ let value = {decoder}.i{bits}().map_err(codec)?;{check} value }}"
            ))
        }
        "string" => {
            let minimum = node
                .get("minimumBytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| "string minimum missing".to_owned())?;
            let maximum = node
                .get("maximumBytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| "string maximum missing".to_owned())?;
            let alphabet = string(node, "alphabet")?;
            Ok(format!(
                "{{ let value = {decoder}.str().map_err(codec)?.to_owned(); if !valid_string(&value, {minimum}usize, {maximum}usize, {alphabet:?}) {{ return Err(ProfileApiCodecError::Limit); }} value }}"
            ))
        }
        "bytes" => {
            let minimum = node
                .get("minimumBytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| "bytes minimum missing".to_owned())?;
            let maximum = node
                .get("maximumBytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| "bytes maximum missing".to_owned())?;
            Ok(format!(
                "{{ let value = {decoder}.bytes().map_err(codec)?.to_vec(); if !({minimum}usize..={maximum}usize).contains(&value.len()) {{ return Err(ProfileApiCodecError::Limit); }} value }}"
            ))
        }
        "enum" | "record" | "union" => Ok(format!("{hint}::decode_from({decoder})?")),
        "ref" => Ok(format!(
            "{}::decode_from({decoder})?",
            string(node, "name")?
        )),
        "option" => {
            let inner = rust_decode_expression(
                node.get("value")
                    .ok_or_else(|| "option value missing".to_owned())?,
                decoder,
                &format!("{hint}Value"),
            )?;
            Ok(format!(
                "if {decoder}.datatype().map_err(codec)? == Type::Null {{ {decoder}.null().map_err(codec)?; None }} else {{ Some({inner}) }}"
            ))
        }
        "list" => {
            let minimum = node
                .get("minimumItems")
                .and_then(Value::as_u64)
                .ok_or_else(|| "list minimum missing".to_owned())?;
            let maximum = node
                .get("maximumItems")
                .and_then(Value::as_u64)
                .ok_or_else(|| "list maximum missing".to_owned())?;
            let inner = rust_decode_expression(
                node.get("value")
                    .ok_or_else(|| "list value missing".to_owned())?,
                decoder,
                &format!("{hint}Item"),
            )?;
            Ok(format!(
                "{{ let count = exact_array({decoder}, {minimum}usize, {maximum}usize)?; let mut values = Vec::with_capacity(count); for _ in 0..count {{ values.push({inner}); }} values }}"
            ))
        }
        kind => Err(format!("unsupported generated Rust decode kind {kind}")),
    }
}

fn cbor_text_order(value: &str) -> (usize, Vec<u8>) {
    let mut encoded = Vec::with_capacity(value.len() + 2);
    match value.len() {
        length @ 0..=23 => encoded.push(0x60 | length as u8),
        length @ 24..=255 => encoded.extend([0x78, length as u8]),
        _ => encoded.extend([0x79, (value.len() >> 8) as u8, value.len() as u8]),
    }
    encoded.extend(value.as_bytes());
    (encoded.len(), encoded)
}

fn rust_field(value: &str) -> String {
    let field = snake(value);
    if matches!(
        field.as_str(),
        "as" | "break"
            | "const"
            | "continue"
            | "crate"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "self"
            | "Self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "async"
            | "await"
            | "dyn"
    ) {
        format!("r#{field}")
    } else {
        field
    }
}

fn render_rust_routes(
    header: &str,
    package: &ProfilePackage,
    api: &ProfileApi,
    error_digests: &BTreeMap<(String, u16), [u8; 32]>,
) -> Result<String, String> {
    let mut output =
        format!("// {header}\n//! Generated static profile route and digest constants.\n\n");
    for profile in package.profiles() {
        let constant = screaming(&format!(
            "{}_{}",
            profile.client().group(),
            profile.client().method()
        ));
        let route = auths_production_client::ProfileRoute::new(profile.id(), profile.version())
            .map_err(|error| error.to_string())?;
        let error_digest = error_digest(error_digests, profile.id(), profile.version())?;
        let digest = package
            .runtime_contract_digest(profile.id(), profile.version(), api, error_digest)
            .map_err(|error| error.to_string())?;
        writeln!(output, "/// Static operation collection route.")
            .map_err(|error| error.to_string())?;
        writeln!(
            output,
            "pub const {constant}_ROUTE: &str = {:?};",
            route.collection()
        )
        .map_err(|error| error.to_string())?;
        writeln!(
            output,
            "/// Exact runtime contract digest including the profile error projection."
        )
        .map_err(|error| error.to_string())?;
        writeln!(
            output,
            "pub const {constant}_RUNTIME_DIGEST: [u8; 32] = {:?};\n",
            digest
        )
        .map_err(|error| error.to_string())?;
        writeln!(
            output,
            "/// Exact profile error-projection digest.\npub const {constant}_ERROR_DIGEST: [u8; 32] = {:?};\n",
            error_digest
        )
        .map_err(|error| error.to_string())?;
    }
    rustfmt_generated(output)
}

fn render_typescript_types(
    header: &str,
    types: &serde_json::Map<String, Value>,
    success_types: &BTreeSet<String>,
) -> Result<String, String> {
    let mut output =
        format!("// {header}\nimport type {{ OperationMetadata }} from \"@auths-dev/sdk\";\n\n");
    for (name, node) in types {
        if node.get("kind").and_then(Value::as_str) == Some("record") {
            writeln!(output, "export interface {name} {{").map_err(|error| error.to_string())?;
            for field in array(node, "fields")? {
                let field_name = string(field, "name")?;
                let value = field
                    .get("value")
                    .ok_or_else(|| "field value missing".to_owned())?;
                writeln!(output, "  readonly {field_name}: {};", ts_type(value)?)
                    .map_err(|error| error.to_string())?;
            }
            if success_types.contains(name) {
                output.push_str("  readonly auths: OperationMetadata;\n");
            }
            output.push_str("}\n\n");
        } else {
            writeln!(output, "export type {name} = {};\n", ts_type(node)?)
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(output)
}

fn render_typescript_client(
    header: &str,
    _domain: &str,
    manifest: &Value,
    api: &Value,
    package: &ProfilePackage,
    parsed_api: &ProfileApi,
    error_digests: &BTreeMap<(String, u16), [u8; 32]>,
    _qualification_metadata: &BTreeMap<String, Vec<(String, String, String)>>,
) -> Result<String, String> {
    let class_name = package.domain().client_class();
    let api_json = serde_json::to_string(api).map_err(|error| error.to_string())?;
    let profiles = manifest
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| "profiles missing".to_owned())?;
    let connected = manifest
        .pointer("/domain/connection")
        .is_some_and(|value| !value.is_null());
    let mut output = format!(
        "// {header}\nimport type {{ Client, OperationOptions, RecoveryHandle, RecoveryOptions }} from \"@auths-dev/sdk\";\nimport {{ bindProfile, type ProfileOutcome }} from \"@auths-dev/sdk/profile-runtime\";\nexport * from \"./generated.js\";\nimport type * as Types from \"./generated.js\";\n\nconst PROFILE_API = {api_json} as const;\n\n"
    );
    output.push_str(
        "export const PROFILE_CLIENT_RUNTIME = \"auths.profile-client-runtime/1\" as const;\n\n",
    );
    for profile in profiles {
        let client = profile
            .get("client")
            .ok_or_else(|| "profile client missing".to_owned())?;
        let group = string(client, "group")?;
        let group_class = pascal(group);
        let method = string(client, "method")?;
        let input = string(client, "inputType")?;
        let success = string(client, "successType")?;
        let id = string(profile, "id")?;
        let version = profile
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| "version missing".to_owned())?;
        let request_limit = profile
            .pointer("/limits/requestBytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| "request limit missing".to_owned())?;
        let response_limit = profile
            .pointer("/limits/responseBytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| "response limit missing".to_owned())?;
        let execution_limit = profile
            .pointer("/limits/executionMilliseconds")
            .and_then(Value::as_u64)
            .ok_or_else(|| "execution limit missing".to_owned())?;
        let receipt_count = profile
            .pointer("/limits/receiptCount")
            .and_then(Value::as_u64)
            .ok_or_else(|| "receipt count missing".to_owned())?;
        let receipt_bytes = profile
            .pointer("/limits/receiptBytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| "receipt byte limit missing".to_owned())?;
        let preparation_evidence = profile
            .pointer("/contracts/preparationEvidence")
            .and_then(Value::as_str);
        let preparation_evidence =
            serde_json::to_string(&preparation_evidence).map_err(|error| error.to_string())?;
        let route = profile_route(id, version)?;
        let error_digest = error_digest(error_digests, id, version as u16)?;
        let runtime_digest = package
            .runtime_contract_digest(id, version as u16, parsed_api, error_digest)
            .map_err(|error| error.to_string())?;
        writeln!(
            output,
            "export type {group_class}Outcome = ProfileOutcome<Types.{success}, never, never>;\n"
        )
        .map_err(|error| error.to_string())?;
        writeln!(output, "export class {group_class} {{").map_err(|error| error.to_string())?;
        output.push_str("  readonly #profile;\n  constructor(session: Client, connection: string | undefined) {\n");
        writeln!(output, "    this.#profile = bindProfile(session, Object.freeze({{ profileClientRuntime: PROFILE_CLIENT_RUNTIME, profileId: {id:?}, version: {version}, collectionRoute: {route:?}, runtimeContractDigest: {:?}, errorProjectionDigest: {:?}, preparationEvidence: {preparation_evidence}, requestBytes: {request_limit}, responseBytes: {response_limit}, executionMilliseconds: {execution_limit}, receiptCount: {receipt_count}, receiptBytes: {receipt_bytes}, profileApi: PROFILE_API, inputType: {input:?}, successType: {success:?} }}), connection);\n  }}", hex::encode(runtime_digest), hex::encode(error_digest))
            .map_err(|error| error.to_string())?;
        writeln!(output, "  async {method}(input: Types.{input}, options?: OperationOptions): Promise<Types.{success}> {{ return this.#profile.invoke(input, options) as Promise<Types.{success}>; }}")
            .map_err(|error| error.to_string())?;
        writeln!(output, "  async {method}Outcome(input: Types.{input}, options?: OperationOptions): Promise<{group_class}Outcome> {{ return this.#profile.invokeOutcome(input, options) as Promise<{group_class}Outcome>; }}")
            .map_err(|error| error.to_string())?;
        writeln!(output, "  async recover(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<Types.{success}> {{ return this.#profile.recover(recovery, options) as Promise<Types.{success}>; }}")
            .map_err(|error| error.to_string())?;
        writeln!(output, "  async recoverOutcome(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<{group_class}Outcome> {{ return this.#profile.recoverOutcome(recovery, options) as Promise<{group_class}Outcome>; }}\n}}\n")
            .map_err(|error| error.to_string())?;
    }
    writeln!(output, "export class {class_name} {{").map_err(|error| error.to_string())?;
    for profile in profiles {
        let client = profile
            .get("client")
            .ok_or_else(|| "profile client missing".to_owned())?;
        writeln!(
            output,
            "  readonly {}: {};",
            camel(string(client, "group")?),
            pascal(string(client, "group")?)
        )
        .map_err(|error| error.to_string())?;
    }
    if connected {
        writeln!(
            output,
            "  constructor(session: Client, options: Readonly<{{ connection?: string }}> = {{}}) {{"
        )
        .map_err(|error| error.to_string())?;
    } else {
        writeln!(output, "  constructor(session: Client) {{").map_err(|error| error.to_string())?;
    }
    for profile in profiles {
        let client = profile
            .get("client")
            .ok_or_else(|| "profile client missing".to_owned())?;
        let group = string(client, "group")?;
        writeln!(
            output,
            "    this.{} = new {}(session, {});",
            camel(group),
            pascal(group),
            if connected {
                "options.connection"
            } else {
                "undefined"
            }
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("    Object.freeze(this);\n  }\n}\n");
    Ok(output)
}

fn render_python_types(
    header: &str,
    types: &serde_json::Map<String, Value>,
    success_types: &BTreeSet<String>,
) -> Result<String, String> {
    let mut output = format!(
        "# {header}\nfrom dataclasses import dataclass\nfrom typing import Literal, Tuple, Union\nfrom auths import OperationMetadata\n\n"
    );
    writeln!(
        output,
        "__all__ = [{}]\n",
        types
            .keys()
            .map(|name| format!("{name:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
    .map_err(|error| error.to_string())?;
    for (name, node) in types {
        if node.get("kind").and_then(Value::as_str) == Some("record") {
            writeln!(output, "@dataclass(frozen=True, init=False)\nclass {name}:")
                .map_err(|error| error.to_string())?;
            let mut parameters = Vec::new();
            let mut assignments = Vec::new();
            for field in array(node, "fields")? {
                let field_name = snake(string(field, "name")?);
                let field_type = py_type(
                    field
                        .get("value")
                        .ok_or_else(|| "field value missing".to_owned())?,
                )?;
                writeln!(output, "    {}: {}", field_name, field_type,)
                    .map_err(|error| error.to_string())?;
                parameters.push(format!("{field_name}: {field_type}"));
                assignments.push(format!(
                    "        object.__setattr__(self, {field_name:?}, {field_name})"
                ));
            }
            if success_types.contains(name) {
                output.push_str("    auths: OperationMetadata\n");
                parameters.push("auths: OperationMetadata".to_owned());
                assignments.push("        object.__setattr__(self, \"auths\", auths)".to_owned());
            }
            writeln!(
                output,
                "    def __init__(self, *, {}) -> None:",
                parameters.join(", ")
            )
            .map_err(|error| error.to_string())?;
            for assignment in assignments {
                writeln!(output, "{assignment}").map_err(|error| error.to_string())?;
            }
            output.push('\n');
        } else {
            writeln!(output, "{name} = {}\n", py_type(node)?).map_err(|error| error.to_string())?;
        }
    }
    let typing = ["Literal", "Tuple", "Union"]
        .into_iter()
        .filter(|name| output.contains(&format!("{name}[")))
        .collect::<Vec<_>>();
    output = output.replacen(
        "from typing import Literal, Tuple, Union\n",
        &if typing.is_empty() {
            String::new()
        } else {
            format!("from typing import {}\n", typing.join(", "))
        },
        1,
    );
    if output.contains("ProfileFile") {
        output = output.replacen(
            "from auths import OperationMetadata\n",
            "from auths import OperationMetadata\nfrom auths.profile_runtime import ProfileFile\n",
            1,
        );
    }
    Ok(output)
}

fn render_python_client(
    header: &str,
    _domain: &str,
    manifest: &Value,
    api: &Value,
    package: &ProfilePackage,
    parsed_api: &ProfileApi,
    error_digests: &BTreeMap<(String, u16), [u8; 32]>,
    _qualification_metadata: &BTreeMap<String, Vec<(String, String, String)>>,
) -> Result<String, String> {
    let class_name = package.domain().client_class();
    let api_json = serde_json::to_string(api).map_err(|error| error.to_string())?;
    let profiles = manifest
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| "profiles missing".to_owned())?;
    let connected = manifest
        .pointer("/domain/connection")
        .is_some_and(|value| !value.is_null());
    let mut output = format!(
        "# {header}\nimport json as _json\nfrom typing import NoReturn, Optional, Tuple, Union\nfrom auths import Client, OperationOptions, RecoveryHandle, RecoveryOptions\nfrom auths.profile_runtime import BoundProfile, ProfileOutcome, bind_profile\nfrom .generated import *\n\n_PROFILE_API = _json.loads({api_json:?})\n\n"
    );
    output.push_str("PROFILE_CLIENT_RUNTIME = \"auths.profile-client-runtime/1\"\n\n");
    for profile in profiles {
        let client = profile
            .get("client")
            .ok_or_else(|| "profile client missing".to_owned())?;
        let group = string(client, "group")?;
        let group_class = pascal(group);
        let method = snake(string(client, "method")?);
        let input = string(client, "inputType")?;
        let id = string(profile, "id")?;
        let version = profile
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| "version missing".to_owned())?;
        let request_limit = profile
            .pointer("/limits/requestBytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| "request limit missing".to_owned())?;
        let response_limit = profile
            .pointer("/limits/responseBytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| "response limit missing".to_owned())?;
        let execution_limit = profile
            .pointer("/limits/executionMilliseconds")
            .and_then(Value::as_u64)
            .ok_or_else(|| "execution limit missing".to_owned())?;
        let receipt_count = profile
            .pointer("/limits/receiptCount")
            .and_then(Value::as_u64)
            .ok_or_else(|| "receipt count missing".to_owned())?;
        let receipt_bytes = profile
            .pointer("/limits/receiptBytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| "receipt byte limit missing".to_owned())?;
        let preparation_evidence = profile
            .pointer("/contracts/preparationEvidence")
            .and_then(Value::as_str);
        let preparation_evidence =
            preparation_evidence.map_or_else(|| "None".to_owned(), |value| format!("{value:?}"));
        let success = string(client, "successType")?;
        let partial = client
            .get("partialType")
            .and_then(Value::as_str)
            .unwrap_or("NoReturn");
        let progress = client
            .get("progressType")
            .and_then(Value::as_str)
            .unwrap_or("NoReturn");
        let route = profile_route(id, version)?;
        let error_digest = error_digest(error_digests, id, version as u16)?;
        let runtime_digest = package
            .runtime_contract_digest(id, version as u16, parsed_api, error_digest)
            .map_err(|error| error.to_string())?;
        let input_node = api
            .pointer(&format!("/types/{input}"))
            .ok_or_else(|| format!("input type {input} missing"))?;
        let fields = array(input_node, "fields")?;
        let parameters = fields
            .iter()
            .map(|field| {
                Ok(format!(
                    "{}: {}",
                    snake(string(field, "name")?),
                    py_type(
                        field
                            .get("value")
                            .ok_or_else(|| "field value missing".to_owned())?
                    )?
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let constructor = fields
            .iter()
            .map(|field| {
                let name = snake(string(field, "name")?);
                Ok(format!("{name}={name}"))
            })
            .collect::<Result<Vec<_>, String>>()?
            .join(", ");
        writeln!(
            output,
            "{group_class}Outcome = ProfileOutcome[{success}, {partial}, {progress}]\n"
        )
        .map_err(|error| error.to_string())?;
        writeln!(output, "class {group_class}:").map_err(|error| error.to_string())?;
        let partial_arguments = if partial == "NoReturn" {
            String::new()
        } else {
            format!(", partial_type={partial:?}, partial_class={partial}")
        };
        let progress_arguments = if progress == "NoReturn" {
            String::new()
        } else {
            format!(", progress_type={progress:?}, progress_class={progress}")
        };
        writeln!(output, "    def __init__(self, session: Client, connection: Optional[str]) -> None:\n        self._profile: BoundProfile[{success}, {partial}, {progress}] = bind_profile(session, profile_client_runtime=PROFILE_CLIENT_RUNTIME, profile_id={id:?}, version={version}, collection_route={route:?}, runtime_contract_digest={:?}, error_projection_digest={:?}, preparation_evidence={preparation_evidence}, request_bytes={request_limit}, response_bytes={response_limit}, execution_milliseconds={execution_limit}, receipt_count={receipt_count}, receipt_bytes={receipt_bytes}, profile_api=_PROFILE_API, input_type={input:?}, success_type={success:?}, input_class={input}, success_class={success}, connection=connection{partial_arguments}{progress_arguments})", hex::encode(runtime_digest), hex::encode(error_digest))
            .map_err(|error| error.to_string())?;
        writeln!(output, "    async def {method}(self, *, {}, options: Optional[OperationOptions] = None) -> {success}:\n        return await self._profile.invoke({input}({constructor}), options=options)", parameters.join(", "))
            .map_err(|error| error.to_string())?;
        writeln!(output, "    async def {method}_outcome(self, *, {}, options: Optional[OperationOptions] = None) -> {group_class}Outcome:\n        return await self._profile.invoke_outcome({input}({constructor}), options=options)", parameters.join(", "))
            .map_err(|error| error.to_string())?;
        writeln!(output, "    async def recover(self, recovery: RecoveryHandle, /, *, options: Optional[RecoveryOptions] = None) -> {success}:\n        return await self._profile.recover(recovery, options=options)\n")
            .map_err(|error| error.to_string())?;
        writeln!(output, "    async def recover_outcome(self, recovery: RecoveryHandle, /, *, options: Optional[RecoveryOptions] = None) -> {group_class}Outcome:\n        return await self._profile.recover_outcome(recovery, options=options)\n")
            .map_err(|error| error.to_string())?;
    }
    writeln!(output, "class {class_name}:").map_err(|error| error.to_string())?;
    if connected {
        writeln!(output, "    def __init__(self, session: Client, /, *, connection: Optional[str] = None) -> None:")
            .map_err(|error| error.to_string())?;
    } else {
        writeln!(
            output,
            "    def __init__(self, session: Client, /) -> None:\n        connection = None"
        )
        .map_err(|error| error.to_string())?;
    }
    for profile in profiles {
        let client = profile
            .get("client")
            .ok_or_else(|| "profile client missing".to_owned())?;
        let group = string(client, "group")?;
        writeln!(
            output,
            "        self.{} = {}(session, connection)",
            snake(group),
            pascal(group)
        )
        .map_err(|error| error.to_string())?;
    }
    output = output.replacen(
        "from typing import NoReturn, Optional, Tuple, Union\n",
        "",
        1,
    );
    let typing = ["NoReturn", "Optional", "Tuple", "Union"]
        .into_iter()
        .filter(|name| output.contains(name))
        .collect::<Vec<_>>();
    if !typing.is_empty() {
        output = output.replacen(
            "import json as _json\n",
            &format!(
                "import json as _json\nfrom typing import {}\n",
                typing.join(", ")
            ),
            1,
        );
    }
    if output.contains("ProfileFile") {
        output = output.replacen(
            "from auths.profile_runtime import BoundProfile, ProfileOutcome, bind_profile\n",
            "from auths.profile_runtime import BoundProfile, ProfileFile, ProfileOutcome, bind_profile\n",
            1,
        );
    }
    Ok(output)
}

fn render_digest_fixture(
    manifest_path: &str,
    source_digest: &str,
    package: &ProfilePackage,
    api: &ProfileApi,
    error_digests: &BTreeMap<(String, u16), [u8; 32]>,
) -> Result<String, String> {
    let mut profiles = Vec::new();
    for profile in package.profiles() {
        let error_digest = error_digest(error_digests, profile.id(), profile.version())?;
        profiles.push(json!({
            "id":profile.id(),
            "version":profile.version(),
            "errorProjectionSha256":hex::encode(error_digest),
            "runtimeContractSha256":hex::encode(package.runtime_contract_digest(profile.id(), profile.version(), api, error_digest).map_err(|error| error.to_string())?)
        }));
    }
    pretty_json(&json!({
        "schema":"auths.generated-profile-fixture/1",
        "generator":GENERATOR,
        "manifest":manifest_path,
        "sourceSha256":source_digest,
        "profiles":profiles
    }))
}

fn load_error_projection_digests(
    repository: &Path,
    manifest: &Value,
) -> Result<BTreeMap<(String, u16), [u8; 32]>, String> {
    let mut output = BTreeMap::new();
    for profile in manifest
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| "profiles missing".to_owned())?
    {
        let id = string(profile, "id")?.to_owned();
        let version = profile
            .get("version")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| "invalid profile version".to_owned())?;
        let path = profile
            .pointer("/sources/errors")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("profile {id} has no error fragment"))?;
        let bytes = fs::read(repository.join(path)).map_err(|error| error.to_string())?;
        let fragment: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if fragment.get("schema").and_then(Value::as_str) != Some("auths.error-registry-fragment/1")
        {
            return Err(format!("profile {id} has an invalid error fragment schema"));
        }
        let canonical =
            serde_json_canonicalizer::to_vec(&fragment).map_err(|error| error.to_string())?;
        output.insert((id, version), Sha256::digest(canonical).into());
    }
    Ok(output)
}

fn error_digest(
    values: &BTreeMap<(String, u16), [u8; 32]>,
    profile_id: &str,
    version: u16,
) -> Result<[u8; 32], String> {
    values
        .get(&(profile_id.to_owned(), version))
        .copied()
        .ok_or_else(|| format!("missing error projection digest for {profile_id}/{version}"))
}

fn ts_type(node: &Value) -> Result<String, String> {
    let kind = string(node, "kind")?;
    match kind {
        "boolean" => Ok("boolean".into()),
        "uint" | "int" => {
            let maximum = string(node, "maximum")?
                .parse::<i128>()
                .map_err(|error| error.to_string())?;
            let minimum = string(node, "minimum")?
                .parse::<i128>()
                .map_err(|error| error.to_string())?;
            Ok(
                if maximum > 9_007_199_254_740_991 || minimum < -9_007_199_254_740_991 {
                    "bigint"
                } else {
                    "number"
                }
                .into(),
            )
        }
        "string" => Ok("string".into()),
        "bytes" => Ok(
            if node.get("sourceConvenience").and_then(Value::as_str) == Some("file") {
                "Uint8Array | Readonly<{ file: string }>"
            } else {
                "Uint8Array"
            }
            .into(),
        ),
        "enum" => Ok(array(node, "values")?
            .iter()
            .map(|value| format!("{:?}", value.as_str().unwrap_or_default()))
            .collect::<Vec<_>>()
            .join(" | ")),
        "ref" => Ok(string(node, "name")?.into()),
        "list" => Ok(format!(
            "readonly {}[]",
            ts_type(
                node.get("value")
                    .ok_or_else(|| "list value missing".to_owned())?
            )?
        )),
        "record" => {
            let fields = array(node, "fields")?
                .iter()
                .map(|field| {
                    Ok(format!(
                        "readonly {}: {}",
                        string(field, "name")?,
                        ts_type(
                            field
                                .get("value")
                                .ok_or_else(|| "field value missing".to_owned())?
                        )?
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(format!("Readonly<{{ {} }}>", fields.join("; ")))
        }
        "union" => {
            let discriminator = string(node, "discriminator")?;
            let variants = array(node, "variants")?
                .iter()
                .map(|variant| {
                    let tag = string(variant, "tag")?;
                    let fields = array(variant, "fields")?
                        .iter()
                        .map(|field| {
                            Ok(format!(
                                "readonly {}: {}",
                                string(field, "name")?,
                                ts_type(
                                    field
                                        .get("value")
                                        .ok_or_else(|| "field value missing".to_owned())?
                                )?
                            ))
                        })
                        .collect::<Result<Vec<_>, String>>()?;
                    Ok(format!(
                        "Readonly<{{ readonly {discriminator}: {tag:?}; {} }}>",
                        fields.join("; ")
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(variants.join(" | "))
        }
        _ => Err(format!("unsupported generated TypeScript kind {kind}")),
    }
}

fn py_type(node: &Value) -> Result<String, String> {
    let kind = string(node, "kind")?;
    match kind {
        "boolean" => Ok("bool".into()),
        "uint" | "int" => Ok("int".into()),
        "string" => Ok("str".into()),
        "bytes" => Ok(
            if node.get("sourceConvenience").and_then(Value::as_str) == Some("file") {
                "Union[bytes, ProfileFile]"
            } else {
                "bytes"
            }
            .into(),
        ),
        "enum" => Ok(format!(
            "Literal[{}]",
            array(node, "values")?
                .iter()
                .map(|value| format!("{:?}", value.as_str().unwrap_or_default()))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        "ref" => Ok(string(node, "name")?.into()),
        "list" => Ok(format!(
            "Tuple[{}, ...]",
            py_type(
                node.get("value")
                    .ok_or_else(|| "list value missing".to_owned())?
            )?
        )),
        "record" => Ok("object".into()),
        "union" => Ok(format!(
            "Union[{}]",
            array(node, "variants")?
                .iter()
                .map(|_| "object")
                .collect::<Vec<_>>()
                .join(", ")
        )),
        _ => Err(format!("unsupported generated Python kind {kind}")),
    }
}

fn validate_source_paths(repository: &Path, manifest: &Value) -> Result<(), String> {
    for profile in manifest
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| "profiles missing".to_owned())?
    {
        for group in ["sources", "evidence"] {
            let paths = profile
                .get(group)
                .and_then(Value::as_object)
                .ok_or_else(|| format!("profile {group} missing"))?;
            for path in paths.values().filter_map(Value::as_str) {
                if !repository.join(path).exists() {
                    return Err(format!(
                        "manifest source/evidence path does not exist: {path}"
                    ));
                }
            }
        }
    }
    if let Some(connection) = manifest
        .pointer("/domain/connection")
        .filter(|value| !value.is_null())
    {
        for group in ["sources", "evidence"] {
            for path in connection
                .get(group)
                .and_then(Value::as_object)
                .ok_or_else(|| format!("connection {group} missing"))?
                .values()
                .filter_map(Value::as_str)
            {
                if !repository.join(path).exists() {
                    return Err(format!(
                        "connection source/evidence path does not exist: {path}"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn write_generated(path: &Path, contents: &str) -> Result<(), String> {
    if let Ok(existing) = fs::read_to_string(path) {
        let first = existing.lines().next().unwrap_or_default();
        if !first.contains(GENERATOR)
            && path.extension().and_then(|value| value.to_str()) != Some("json")
        {
            return Err(format!(
                "refusing to overwrite unrecognized file: {}",
                path.display()
            ));
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(path, contents).map_err(|error| error.to_string())
}

fn source_digest(manifest: &[u8], api: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(manifest);
    digest.update([0]);
    digest.update(api);
    hex::encode(digest.finalize())
}
fn pretty_json(value: &Value) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map(|value| format!("{value}\n"))
        .map_err(|error| error.to_string())
}
fn canonical_json(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json_canonicalizer::to_vec(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string {key}"))
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("missing array {key}"))
}
fn lower_token(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
fn pascal(value: &str) -> String {
    value
        .split('-')
        .filter(|item| !item.is_empty())
        .map(|item| {
            let mut chars = item.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_ascii_uppercase().to_string() + chars.as_str()
            })
        })
        .collect()
}
fn camel(value: &str) -> String {
    let pascal = pascal(value);
    let mut chars = pascal.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_ascii_lowercase().to_string() + chars.as_str()
    })
}
fn snake(value: &str) -> String {
    let mut out = String::new();
    for (index, ch) in value.chars().enumerate() {
        if ch == '-' {
            out.push('_');
        } else if ch.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}
fn screaming(value: &str) -> String {
    snake(value).to_ascii_uppercase()
}
fn profile_route(id: &str, version: u64) -> Result<String, String> {
    let parts = id.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err("invalid profile route identity".into());
    }
    Ok(format!(
        "/v1/profiles/{}/{}/{version}/operations",
        parts[1], parts[2]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn new_profile_cli_requires_one_exact_domain_mode() {
        let parsed = parse_arguments(&arguments(&[
            "new",
            "--domain",
            "mailbox",
            "--effect",
            "send",
            "--version",
            "1",
            "--provider",
            "gmail",
            "--connection-version",
            "2",
        ]))
        .unwrap();
        assert_eq!(
            parsed,
            ProfileCommand::New(NewProfileArguments {
                domain: "mailbox".into(),
                effect: "send".into(),
                version: 1,
                mode: NewProfileMode::Connected {
                    provider: "gmail".into(),
                    connection_version: 2,
                },
            })
        );

        for invalid in [
            arguments(&[
                "new",
                "--domain",
                "mailbox",
                "--effect",
                "send",
                "--version",
                "1",
            ]),
            arguments(&[
                "new",
                "--domain",
                "mailbox",
                "--effect",
                "send",
                "--version",
                "0",
                "--connectionless",
            ]),
            arguments(&[
                "new",
                "--domain",
                "mailbox",
                "--effect",
                "send",
                "--version",
                "1",
                "--existing-domain",
                "--connectionless",
            ]),
            arguments(&[
                "new",
                "--domain",
                "mailbox",
                "--domain",
                "other",
                "--effect",
                "send",
                "--version",
                "1",
                "--connectionless",
            ]),
        ] {
            assert!(parse_arguments(&invalid).is_err());
        }
    }

    #[test]
    fn generate_and_check_keep_the_narrow_domain_only_grammar() {
        assert_eq!(
            parse_arguments(&arguments(&["generate", "--domain", "stripe"])).unwrap(),
            ProfileCommand::Generate {
                domain: "stripe".into(),
                check: false,
            }
        );
        assert!(
            parse_arguments(&arguments(&[
                "check", "--domain", "stripe", "--effect", "refund"
            ]))
            .is_err()
        );
    }

    #[test]
    fn generated_route_source_is_invariant_across_launch_state() {
        let repository = root();
        let roster_bytes =
            fs::read(repository.join("product/runtime/auths-node/profile-packages.json")).unwrap();
        let roster = ProfileRoster::from_json(&roster_bytes).unwrap();
        let before = render_root_profile_roster(&repository, &roster).unwrap();

        let mut value: Value = serde_json::from_slice(&roster_bytes).unwrap();
        let stripe = value["packages"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|package| package["domain"] == "stripe")
            .unwrap();
        let profile = &mut stripe["profiles"][0];
        profile["state"] = json!("qualified");
        profile["targets"] = json!(["linux-x86_64"]);
        profile["qualificationIds"] = json!([format!("qlf_{}", "A".repeat(43))]);
        let changed = serde_json_canonicalizer::to_vec(&value).unwrap();
        let roster = ProfileRoster::from_json(&changed).unwrap();
        let after = render_root_profile_roster(&repository, &roster).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn new_connected_domain_is_registered_generated_and_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let repository = directory.path();
        for path in [
            ".github/workflows",
            "bindings/typescript/src",
            "product/runtime/auths-node",
            "product/integrations/auths-stripe/api",
            "product/conformance/v2",
            "product/sdk/auths-profile-kit/src",
            "xtask/src",
        ] {
            fs::create_dir_all(repository.join(path)).unwrap();
        }
        fs::write(
            repository.join("Cargo.toml"),
            "[workspace]\nmembers = [\n    \"product/integrations/auths-stripe\",\n]\n\n[workspace.dependencies]\nauths-stripe = { version = \"1.0.0-rc.1\", path = \"product/integrations/auths-stripe\" }\n",
        )
        .unwrap();
        fs::write(
            repository.join("architecture.toml"),
            "schema = 1\n\n[packages]\nauths-stripe = \"product\"\n",
        )
        .unwrap();
        fs::write(
            repository.join("product/runtime/auths-node/Cargo.toml"),
            "[package]\nname = \"auths-node\"\n\n[dependencies]\nauths-stripe.workspace = true\n",
        )
        .unwrap();
        fs::write(
            repository.join("xtask/Cargo.toml"),
            "[package]\nname = \"xtask\"\n\n[dependencies]\nauths-stripe.workspace = true\n",
        )
        .unwrap();
        let common_workflow = "name: immutable common qualification workflow\n";
        let common_supervisor = "// immutable common crash supervisor\n";
        let common_sdk = "// immutable common SDK surface\n";
        fs::write(
            repository.join(".github/workflows/profile-qualification.yml"),
            common_workflow,
        )
        .unwrap();
        fs::write(
            repository.join("xtask/src/profile_qualification.rs"),
            common_supervisor,
        )
        .unwrap();
        fs::write(
            repository.join("bindings/typescript/src/session.ts"),
            common_sdk,
        )
        .unwrap();
        fs::write(
            repository.join("product/runtime/auths-node/profile-packages.json"),
            b"{\"schema\":\"auths.profile-roster/2\",\"packages\":[{\"domain\":\"stripe\",\"rustPackage\":\"auths-stripe\",\"manifestPath\":\"product/integrations/auths-stripe/profile-package.json\",\"profiles\":[{\"profile\":\"auths.stripe.refund/1\",\"state\":\"unqualified\",\"testkitAvailable\":true,\"targets\":[],\"qualificationIds\":[]}]}]}\n",
        )
        .unwrap();
        fs::write(
            repository.join("product/integrations/auths-stripe/profile-package.json"),
            include_bytes!("../../product/integrations/auths-stripe/profile-package.json"),
        )
        .unwrap();
        fs::write(
            repository.join("product/integrations/auths-stripe/api/profile-api.json"),
            include_bytes!("../../product/integrations/auths-stripe/api/profile-api.json"),
        )
        .unwrap();
        fs::write(
            repository.join("product/conformance/v2/profile-qualification-common.json"),
            include_bytes!("../../product/conformance/v2/profile-qualification-common.json"),
        )
        .unwrap();

        let request = NewProfileArguments {
            domain: "mailbox".into(),
            effect: "send".into(),
            version: 1,
            mode: NewProfileMode::Connected {
                provider: "gmail".into(),
                connection_version: 1,
            },
        };
        scaffold_at(repository, &request).unwrap();

        assert!(
            repository
                .join("product/integrations/auths-mailbox/src/generated/profile_api.rs")
                .is_file()
        );
        assert!(
            repository
                .join("bindings/generated/mailbox/typescript/src/index.ts")
                .is_file()
        );
        assert!(
            repository
                .join("bindings/generated/mailbox/python/src/auths_profiles/mailbox/py.typed")
                .is_file()
        );
        assert!(
            repository
                .join("product/integrations/auths-mailbox/src/qualification.rs")
                .is_file()
        );
        let adapter_roster =
            fs::read_to_string(repository.join("xtask/src/profile_qualification_adapters.rs"))
                .unwrap();
        assert!(adapter_roster.contains("MailboxQualificationAdapter"));
        assert_eq!(
            fs::read_to_string(repository.join(".github/workflows/profile-qualification.yml"))
                .unwrap(),
            common_workflow
        );
        assert_eq!(
            fs::read_to_string(repository.join("xtask/src/profile_qualification.rs")).unwrap(),
            common_supervisor
        );
        assert_eq!(
            fs::read_to_string(repository.join("bindings/typescript/src/session.ts")).unwrap(),
            common_sdk
        );
        let typescript_quickstart =
            fs::read_to_string(repository.join("bindings/generated/mailbox/typescript/README.md"))
                .unwrap();
        let python_quickstart =
            fs::read_to_string(repository.join("bindings/generated/mailbox/python/README.md"))
                .unwrap();
        assert!(typescript_quickstart.contains("await client.send.execute"));
        assert!(python_quickstart.contains("await client.send.execute"));
        assert!(!typescript_quickstart.contains("AUTHS_TOKEN"));
        assert!(!python_quickstart.contains("AUTHS_TOKEN"));
        let package = fs::read_to_string(
            repository.join("bindings/generated/mailbox/typescript/package.json"),
        )
        .unwrap();
        assert!(package.contains("\"typescript\": \"5.9.3\""));
        let roster =
            fs::read_to_string(repository.join("product/runtime/auths-node/profile-packages.json"))
                .unwrap();
        assert!(roster.find("mailbox").unwrap() < roster.find("stripe").unwrap());
        assert!(
            fs::read_to_string(repository.join("Cargo.toml"))
                .unwrap()
                .contains("product/integrations/auths-mailbox")
        );
        assert!(
            fs::read_to_string(repository.join("product/runtime/auths-node/Cargo.toml"))
                .unwrap()
                .contains("auths-mailbox.workspace = true")
        );
        assert!(
            fs::read_to_string(repository.join("docs/architecture/profiles/mailbox.md"))
                .unwrap()
                .contains("not qualified")
        );
        assert!(scaffold_at(repository, &request).is_err());
    }
}
