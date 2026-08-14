use crate::*;
use auths_config::{ProductionCandidate, ProductionCandidateInput};

const INPUT: &str = "release/open-production-candidate.toml";
const MANIFEST: &str = "release/open-production-candidate.json";
const SCHEMA: &str = "product/spec/v1/open-production-candidate.schema.json";
const EXACT_EFFECT_QUALIFICATION: &str = "product/qualification/v1/exact-effect-verticals.json";

pub(crate) fn production_contract(update: bool) -> Result<(), String> {
    let input = fs::read_to_string(root().join(INPUT))
        .map_err(|error| format!("could not read {INPUT}: {error}"))?;
    let candidate = ProductionCandidateInput::parse_toml(&input)
        .and_then(ProductionCandidateInput::compile)
        .map_err(|error| format!("production candidate {}: {error}", error.field()))?;
    let manifest = candidate
        .canonical_manifest()
        .map_err(|error| format!("could not encode production candidate: {error}"))?;
    let manifest_value: Value = serde_json::from_slice(&manifest)
        .map_err(|error| format!("generated production candidate is invalid JSON: {error}"))?;
    validate_references(&manifest_value)?;
    validate_exact_effect_qualification(&manifest_value)?;
    validate_release_subject_binding()?;

    let mut schema = serde_json::to_vec_pretty(&ProductionCandidate::canonical_schema())
        .map_err(|error| format!("could not encode production candidate schema: {error}"))?;
    schema.push(b'\n');
    check_or_update(MANIFEST, &manifest, update)?;
    check_or_update(SCHEMA, &schema, update)?;

    if update {
        println!("open production contract generated");
    } else {
        println!(
            "open production contract passed ({} profiles, {} evidence requirements)",
            manifest_value["profiles"].as_array().map_or(0, Vec::len),
            manifest_value["evidence"].as_array().map_or(0, Vec::len)
        );
    }
    Ok(())
}

fn validate_exact_effect_qualification(manifest: &Value) -> Result<(), String> {
    let qualification: Value = serde_json::from_slice(
        &fs::read(root().join(EXACT_EFFECT_QUALIFICATION))
            .map_err(|error| format!("could not read {EXACT_EFFECT_QUALIFICATION}: {error}"))?,
    )
    .map_err(|error| format!("invalid {EXACT_EFFECT_QUALIFICATION}: {error}"))?;
    if qualification["schema"] != "auths.exact-effect-qualification/1"
        || qualification["externalDesignPartnerPilot"] != "required-before-production-claim"
        || qualification["commonAdversarialScenarios"]
            .as_array()
            .is_none_or(|scenarios| scenarios.len() < 20)
    {
        return Err("exact-effect qualification identity or common matrix drifted".into());
    }
    let qualified = qualification["profiles"]
        .as_array()
        .ok_or("qualified profiles are not an array")?;
    let profiles = manifest["profiles"]
        .as_array()
        .ok_or("production profiles are not an array")?;
    if qualified.len() != profiles.len() {
        return Err("every production profile must have exact-effect qualification".into());
    }
    for profile in profiles {
        let id = &profile["id"];
        let evidence = qualified
            .iter()
            .find(|candidate| candidate["id"] == *id)
            .ok_or_else(|| format!("production profile lacks qualification: {id}"))?;
        if evidence["providerContracts"] != profile["providerContracts"] {
            return Err(format!(
                "provider contracts differ from qualification for {id}"
            ));
        }
        for field in ["requestFixtures", "liveContracts", "recoveryEvidence"] {
            let paths = evidence[field]
                .as_array()
                .ok_or_else(|| format!("{id} {field} is not an array"))?;
            if paths.is_empty() {
                return Err(format!("{id} has no {field}"));
            }
            for path in paths {
                require_repository_path(path, field)?;
            }
        }
        require_repository_path(&evidence["runbook"], "vertical runbook")?;
    }
    Ok(())
}

fn validate_references(manifest: &Value) -> Result<(), String> {
    if manifest["schema"] != "auths.open-production-candidate/1"
        || manifest["release"]["version"] != env!("CARGO_PKG_VERSION")
        || manifest["topology"]["runtimeInstances"] != 3
        || manifest["lifecycleStore"]["tls"] != "required"
    {
        return Err("open production contract identity or fixed topology drifted".to_owned());
    }
    for profile in manifest["profiles"]
        .as_array()
        .ok_or("production profiles are not an array")?
    {
        require_repository_path(&profile["package"], "profile package")?;
        require_repository_path(&profile["fixtureSuite"], "profile fixture suite")?;
    }
    for sdk in manifest["sdks"]
        .as_array()
        .ok_or("production SDKs are not an array")?
    {
        require_repository_path(&sdk["abi"], "SDK ABI")?;
        require_repository_path(&sdk["publicApiSnapshot"], "SDK public API snapshot")?;
    }
    Ok(())
}

fn require_repository_path(value: &Value, label: &str) -> Result<(), String> {
    let path = value
        .as_str()
        .ok_or_else(|| format!("{label} path is not a string"))?;
    if path.starts_with('/') || path.contains("..") || !root().join(path).exists() {
        return Err(format!(
            "{label} does not resolve inside the repository: {path}"
        ));
    }
    Ok(())
}

fn validate_release_subject_binding() -> Result<(), String> {
    let catalogue: toml::Value = toml::from_str(
        &fs::read_to_string(root().join("release/release-subjects.toml"))
            .map_err(|error| format!("could not read release subject catalogue: {error}"))?,
    )
    .map_err(|error| format!("could not parse release subject catalogue: {error}"))?;
    if catalogue
        .get("production_candidate_manifest")
        .and_then(toml::Value::as_str)
        != Some(MANIFEST)
        || catalogue
            .get("production_candidate_schema")
            .and_then(toml::Value::as_str)
            != Some(SCHEMA)
    {
        return Err("release subjects do not bind the open production contract".to_owned());
    }
    Ok(())
}

fn check_or_update(relative: &str, expected: &[u8], update: bool) -> Result<(), String> {
    let path = root().join(relative);
    if update {
        fs::create_dir_all(
            path.parent()
                .ok_or_else(|| format!("{relative} has no parent"))?,
        )
        .map_err(|error| format!("could not create parent for {relative}: {error}"))?;
        fs::write(&path, expected)
            .map_err(|error| format!("could not update {relative}: {error}"))?;
        return Ok(());
    }
    let actual = fs::read(&path).map_err(|error| {
        format!(
            "could not read {relative}: {error}; run `cargo xtask production-contract --update`"
        )
    })?;
    if actual != expected {
        return Err(format!(
            "open production contract drifted: {relative}; run `cargo xtask production-contract --update`"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_production_contract_is_current() {
        production_contract(false).expect("production contract must be current");
    }
}
