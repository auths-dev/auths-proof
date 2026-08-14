use crate::*;

const REPORT_PATH: &str = "release/docs/public-docs-report.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    maintained_languages: Vec<String>,
    tier: Vec<Tier>,
    owner: Vec<Owner>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tier {
    name: String,
    #[serde(default)]
    operations: Vec<String>,
    surface: Option<String>,
    required_sections: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    surface: String,
    path: String,
}

pub(crate) fn public_docs(update: bool) -> Result<(), String> {
    let source = fs::read_to_string(root().join("docs/public-api-documentation-policy.toml"))
        .map_err(|error| format!("could not read public documentation policy: {error}"))?;
    let policy: Policy = toml::from_str(&source)
        .map_err(|error| format!("could not parse public documentation policy: {error}"))?;
    if policy.schema != "auths.public-docs-policy/1"
        || policy.maintained_languages != ["rust", "typescript", "python"]
    {
        return Err("unsupported public documentation policy".to_owned());
    }
    let p0 = policy
        .tier
        .iter()
        .find(|tier| tier.name == "P0")
        .ok_or("public documentation policy has no P0 tier")?;
    if p0.operations.len() != 5
        || p0.required_sections != ["summary", "outcomes", "security", "scenario"]
    {
        return Err(
            "P0 documentation policy must cover five verbs and four contract sections".to_owned(),
        );
    }
    if policy.tier.iter().any(|tier| {
        tier.required_sections.is_empty()
            || (tier.name != "P0" && tier.surface.as_deref().unwrap_or_default().is_empty())
    }) {
        return Err("public documentation tier is incomplete".to_owned());
    }
    let owners: BTreeSet<_> = policy
        .owner
        .iter()
        .map(|owner| owner.surface.as_str())
        .collect();
    if owners != BTreeSet::from(["python", "rust", "typescript"])
        || policy.owner.iter().any(|owner| owner.path.is_empty())
    {
        return Err("public documentation policy has incomplete ownership".to_owned());
    }

    command_in(
        "node",
        &["tools/public-docs.mjs"],
        &root().join("bindings/typescript"),
        None,
    )?;
    command_in(
        "python3",
        &["tools/check_public_docs.py"],
        &root().join("bindings/python"),
        None,
    )?;

    let report = json!({
        "schema": "auths.public-docs-report/1",
        "policy": policy.schema,
        "tiers": policy.tier.iter().map(|tier| json!({
            "name": tier.name,
            "operationCount": tier.operations.len(),
            "requiredSections": tier.required_sections,
        })).collect::<Vec<_>>(),
        "languages": policy.maintained_languages,
        "p0": { "required": 5, "documented": 5, "missing": [] },
    });
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("could not encode public documentation report: {error}"))?;
    bytes.push(b'\n');
    let path = root().join(REPORT_PATH);
    if update {
        fs::write(&path, bytes)
            .map_err(|error| format!("could not write {REPORT_PATH}: {error}"))?;
        println!("updated {REPORT_PATH}");
        return Ok(());
    }
    if fs::read(&path).map_err(|error| format!("could not read {REPORT_PATH}: {error}"))? != bytes {
        return Err(
            "public documentation report drifted; run `cargo xtask public-docs --update`"
                .to_owned(),
        );
    }
    println!("public documentation policy passed");
    Ok(())
}
