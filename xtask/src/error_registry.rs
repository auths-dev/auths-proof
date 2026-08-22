use crate::*;
use auths_errors::{
    CauseCategory, EffectState, EnteredBoundaries, ErrorEnvelope, ErrorEnvelopeInput,
};

/// A code no registry may ever contain, used to read the fail-closed branch of
/// `auths_errors::classify` without hardcoding its answer.
const UNRECOGNIZED_PROBE: &str = "auths.unrecognized-code-probe";

const OUTPUTS: [&str; 7] = [
    "product/errors/v1/registry.json",
    "product/fixtures/v1/errors/manifest.json",
    "bindings/typescript/src/generated/error-registry.ts",
    "bindings/python/python/auths/_error_registry.py",
    "docs/reference/error-codes.md",
    "bindings/typescript/src/generated/error-registry-digest.ts",
    "bindings/typescript/src/generated/error-registry-runtime.ts",
];

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistryDocument<'a> {
    schema: &'static str,
    definitions: Vec<&'a auths_errors::ErrorDefinition>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FixtureManifest {
    schema: &'static str,
    fixtures: Vec<ErrorEnvelope>,
}

pub(crate) fn error_registry(update: bool) -> Result<(), String> {
    auths_errors::validate_registry()
        .map_err(|error| format!("invalid Rust error registry: {error:?}"))?;
    let definitions: Vec<_> = auths_errors::registry().collect();
    let registration_schema = root().join("product/errors/v1/profile-registration.schema.json");
    let schema: Value =
        serde_json::from_slice(&fs::read(&registration_schema).map_err(|error| {
            format!("could not read {}: {error}", registration_schema.display())
        })?)
        .map_err(|error| format!("invalid {}: {error}", registration_schema.display()))?;
    if schema["properties"]["schema"]["const"] != "auths.profile-error-registration/1" {
        return Err("profile error registration schema has the wrong identity".to_owned());
    }
    let registry = RegistryDocument {
        schema: auths_errors::REGISTRY_SCHEMA,
        definitions,
    };
    let fixtures = FixtureManifest {
        schema: "auths.error-fixtures/1",
        fixtures: auths_errors::registry()
            .map(fixture_for)
            .collect::<Result<_, _>>()?,
    };
    let registry_json = pretty_json(&registry)?;
    // JavaScript's previous runtime implementation recursively sorted the
    // registry before hashing it. Project the same canonical compact JSON at
    // build time so loading the root SDK does not eagerly retain and re-hash
    // the complete registry.
    let canonical_registry: Value = serde_json::from_slice(&registry_json)
        .map_err(|error| format!("could not canonicalize error registry: {error}"))?;
    let canonical_registry = serde_json::to_vec(&sort_json(canonical_registry))
        .map_err(|error| format!("could not encode canonical error registry: {error}"))?;
    let registry_sha256 = hex::encode(Sha256::digest(&canonical_registry));
    // The fail-closed answer for a code this build's registry does not contain
    // is `auths_errors::classify`'s, not a binding's. Projecting it here is what
    // stops TypeScript and Python from each inventing their own fourth state.
    let unrecognized_json = pretty_json(&auths_errors::classify(UNRECOGNIZED_PROBE))?;
    // Which registry code a verdict or runtime outcome carries is also Rust's
    // answer, not a binding's.
    let outcome_json = pretty_json(&auths_errors::outcome_codes())?;
    let outputs = [
        registry_json.clone(),
        pretty_json(&fixtures)?,
        render_typescript(
            &registry_json,
            &registry_sha256,
            &unrecognized_json,
            &outcome_json,
        ),
        render_python(&registry_json, &unrecognized_json, &outcome_json),
        render_docs(&registry),
        render_typescript_digest(&registry_sha256),
        render_typescript_runtime(&registry_json, &unrecognized_json)?,
    ];
    for (path, bytes) in OUTPUTS.iter().zip(outputs) {
        let path = root().join(path);
        if update {
            fs::create_dir_all(path.parent().ok_or("generated output has no parent")?)
                .map_err(|error| format!("could not create {}: {error}", path.display()))?;
            fs::write(&path, bytes)
                .map_err(|error| format!("could not update {}: {error}", path.display()))?;
        } else {
            let committed = fs::read(&path).map_err(|error| {
                format!(
                    "could not read {}: {error}; run `cargo xtask error-registry --update`",
                    path.display()
                )
            })?;
            if committed != bytes {
                return Err(format!(
                    "error registry projection drifted: {}; run `cargo xtask error-registry --update`",
                    path.display()
                ));
            }
        }
    }
    if update {
        println!("error registry projections updated");
    } else {
        println!(
            "error registry passed ({} stable codes)",
            registry.definitions.len()
        );
    }
    Ok(())
}

fn fixture_for(definition: &auths_errors::ErrorDefinition) -> Result<ErrorEnvelope, String> {
    let outcome = definition
        .outcomes
        .first()
        .ok_or_else(|| format!("{} has no fixture outcome", definition.code))?;
    ErrorEnvelope::parse(ErrorEnvelopeInput {
        code: definition.code.into(),
        operation: definition.operation.into(),
        stage: definition.stages[0].into(),
        summary: definition.title.into(),
        correlation_id: format!("fixture:{}", definition.fixture_id),
        retry: outcome.retry,
        effect: outcome.effect,
        entered: EnteredBoundaries {
            state: definition.stages.contains(&"reservation"),
            provider: outcome.effect == EffectState::Possible,
            ..EnteredBoundaries::default()
        },
        recommended_action: definition.recommended_action,
        execution_reference: definition
            .allows_execution_reference
            .then(|| format!("execution:{}", definition.fixture_id)),
        decision_reference: None,
        receipt_reference: None,
        causes: vec![CauseCategory::Unknown],
    })
    .map_err(|error| format!("invalid fixture {}: {error:?}", definition.fixture_id))
}

fn pretty_json(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not encode error registry: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        Value::Object(values) => {
            let mut values: Vec<_> = values.into_iter().collect();
            values.sort_by(|(left, _), (right, _)| left.cmp(right));
            Value::Object(
                values
                    .into_iter()
                    .map(|(key, value)| (key, sort_json(value)))
                    .collect(),
            )
        }
        scalar => scalar,
    }
}

fn render_typescript(
    registry: &[u8],
    registry_sha256: &str,
    unrecognized: &[u8],
    outcomes: &[u8],
) -> Vec<u8> {
    let json = String::from_utf8_lossy(registry);
    let unrecognized = String::from_utf8_lossy(unrecognized);
    let outcomes = String::from_utf8_lossy(outcomes);
    format!(
        "export const ERROR_REGISTRY = {} as const;\n\n/** SHA-256 of canonical compact JSON for this generated registry. */\nexport const ERROR_REGISTRY_SHA256 = {registry_sha256:?} as const;\n\n/**\n * `auths_errors::classify` applied to a code this build's registry does not\n * contain. A binding projects this; it never recomputes it and never invents a\n * fourth effect state.\n */\nexport const UNRECOGNIZED_CODE = {} as const;\n\n/**\n * `auths_errors::outcome_codes` -- the registry code an authorization verdict\n * carries. A verdict names itself with a kernel diagnostic, not a registry\n * code; this is the Rust-owned translation.\n */\nexport const OUTCOME_CODES = {} as const;\n",
        json.trim_end(),
        unrecognized.trim_end(),
        outcomes.trim_end()
    )
    .into_bytes()
}

fn render_typescript_digest(registry_sha256: &str) -> Vec<u8> {
    format!(
        "/** Generated SHA-256 of canonical compact JSON for the error registry. */\n\
         export const ERROR_REGISTRY_SHA256 = {registry_sha256:?} as const;\n"
    )
    .into_bytes()
}

fn render_typescript_runtime(registry: &[u8], unrecognized: &[u8]) -> Result<Vec<u8>, String> {
    let registry: Value = serde_json::from_slice(registry)
        .map_err(|error| format!("could not project TypeScript error runtime: {error}"))?;
    let definitions = registry["definitions"]
        .as_array()
        .ok_or("error registry definitions are not an array")?;
    let definitions: Vec<_> = definitions
        .iter()
        .map(|definition| {
            Ok(json!({
                "code": required_projection(definition, "code")?,
                "family": required_projection(definition, "family")?,
                "operation": required_projection(definition, "operation")?,
                "stages": required_projection(definition, "stages")?,
                "outcomes": required_projection(definition, "outcomes")?,
                "recommendedAction": required_projection(definition, "recommendedAction")?,
                "allowsExecutionReference": required_projection(definition, "allowsExecutionReference")?,
                "allowsDecisionReference": required_projection(definition, "allowsDecisionReference")?,
                "allowsReceiptReference": required_projection(definition, "allowsReceiptReference")?,
            }))
        })
        .collect::<Result<_, String>>()?;
    let definitions = String::from_utf8_lossy(&pretty_json(&definitions)?)
        .trim()
        .to_owned();
    let unrecognized = String::from_utf8_lossy(unrecognized);
    Ok(format!(
        "/** Minimal generated validation projection used by the root SDK. */\n\
         export const ERROR_RUNTIME_DEFINITIONS = {definitions} as const;\n\n\
         /** Rust-owned fail-closed classification for an unknown code. */\n\
         export const UNRECOGNIZED_CODE = {} as const;\n",
        unrecognized.trim_end(),
    )
    .into_bytes())
}

fn required_projection(value: &Value, field: &str) -> Result<Value, String> {
    value
        .get(field)
        .cloned()
        .ok_or_else(|| format!("error registry definition omitted {field}"))
}

fn render_python(registry: &[u8], unrecognized: &[u8], outcomes: &[u8]) -> Vec<u8> {
    let json = String::from_utf8_lossy(registry);
    let unrecognized = String::from_utf8_lossy(unrecognized);
    let outcomes = String::from_utf8_lossy(outcomes);
    format!(
        "from __future__ import annotations\n\nimport json\nfrom typing import Any, Final\n\nERROR_REGISTRY: Final[dict[str, Any]] = json.loads(r'''{json}''')\n\n# `auths_errors::classify` applied to a code this build's registry does not\n# contain. A binding projects this; it never recomputes it.\nUNRECOGNIZED_CODE: Final[dict[str, Any]] = json.loads(r'''{unrecognized}''')\n\n# `auths_errors::outcome_codes` -- the registry code an authorization verdict\n# carries.\nOUTCOME_CODES: Final[dict[str, Any]] = json.loads(r'''{outcomes}''')\n"
    )
    .into_bytes()
}

fn render_docs(registry: &RegistryDocument<'_>) -> Vec<u8> {
    let mut output = String::from(
        "# Auths error and recovery registry\n\nEvery row is generated from the Rust-owned registry. `possible` effects are never retry-safe.\n\n| Code | Operation | Effect / retry | Recommended action | Meaning |\n| --- | --- | --- | --- | --- |\n",
    );
    for definition in &registry.definitions {
        let outcomes = definition
            .outcomes
            .iter()
            .map(|outcome| format!("{:?} / {:?}", outcome.effect, outcome.retry).to_lowercase())
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!(
            "| `{}` | `{}` | {} | `{:?}` | {} |\n",
            definition.code,
            definition.operation,
            outcomes,
            definition.recommended_action,
            definition.explanation
        ));
    }
    output.into_bytes()
}
