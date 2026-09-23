//! Byte-exact rendering of the three derived files and the report.

use crate::mapper::worst_case_json;
use crate::model::{
    ArgSchema, CredentialKind, Mapping, Media, OPERATION_ID_MAX_BYTES, Segment, Template,
};
use crate::request::{Literal, Request};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

/// Facts about the source document that the provenance record commits to.
pub(crate) struct Source<'d> {
    pub(crate) sha256: String,
    pub(crate) bytes: usize,
    pub(crate) openapi: String,
    pub(crate) display_name: &'d str,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) pointer: String,
}

/// The rendered files.
pub(crate) struct Rendered {
    pub(crate) profile_toml: String,
    pub(crate) recipe_json: String,
    pub(crate) derivation_json: String,
    pub(crate) lines: Vec<String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// All profile fields in output order: binding fields, then derived ones.
fn profile_fields(request: &Request, mapping: &Mapping) -> Vec<(String, ArgSchema)> {
    let mut fields = vec![
        (
            "operator_namespace".to_owned(),
            ArgSchema::Enum(vec![request.operator_namespace.clone()]),
        ),
        (
            "operation_id".to_owned(),
            ArgSchema::String {
                min: 1,
                max: OPERATION_ID_MAX_BYTES,
            },
        ),
        (
            "recipe_digest".to_owned(),
            ArgSchema::String { min: 64, max: 64 },
        ),
    ];
    fields.extend(
        mapping
            .arguments
            .iter()
            .map(|argument| (argument.name.clone(), argument.schema.clone())),
    );
    fields
}

fn field_toml(name: &str, schema: &ArgSchema) -> String {
    let body = match schema {
        ArgSchema::String { min, max } => {
            format!("type = \"string\"\nmin_bytes = {min}\nmax_bytes = {max}\n")
        }
        ArgSchema::Enum(variants) => {
            let listed: Vec<String> = variants
                .iter()
                .map(|variant| format!("\"{variant}\""))
                .collect();
            format!("type = \"enum\"\nvariants = [{}]\n", listed.join(", "))
        }
        ArgSchema::Integer { min, max } => {
            format!("type = \"integer\"\nminimum = {min}\nmaximum = {max}\n")
        }
        ArgSchema::Boolean => "type = \"boolean\"\n".to_owned(),
    };
    format!("\n[arguments.fields.{name}]\n{body}")
}

fn profile_toml(request: &Request, mapping: &Mapping, fields: &[(String, ArgSchema)]) -> String {
    let header = format!(
        "# Derived by auths-profile derive; derivation.json records the source and overrides.\n[profile]\nname = \"{}\"\nversion = {}\nservice = \"{}\"\ntool = \"{}\"\n\n[arguments]\ntype = \"object\"\n",
        request.name, request.version, request.service, mapping.tool
    );
    fields.iter().fold(header, |out, (name, schema)| {
        out + &field_toml(name, schema)
    })
}

/// The generator's normalized schema digest: SHA-256 over RFC 8785 JSON.
fn schema_digest(fields: &[(String, ArgSchema)]) -> String {
    let mut map = Map::new();
    for (name, schema) in fields {
        let node = match schema {
            ArgSchema::String { min, max } => {
                json!({"kind": "string", "minimum": min, "maximum": max})
            }
            ArgSchema::Enum(variants) => json!({"type": "enum", "variants": variants}),
            ArgSchema::Integer { min, max } => {
                json!({"kind": "integer", "minimum": min, "maximum": max})
            }
            ArgSchema::Boolean => json!({"kind": "boolean"}),
        };
        map.insert(name.clone(), node);
    }
    let schema = json!({"kind": "object", "fields": Value::Object(map)});
    // INVARIANT: the value holds only strings, safe integers, and objects,
    // which RFC 8785 always serializes.
    let bytes = serde_json_canonicalizer::to_vec(&schema).unwrap_or_default();
    sha256_hex(&bytes)
}

fn literal(value: &Literal) -> Value {
    match value {
        Literal::String(text) => json!({"kind": "string", "value": text}),
        Literal::Integer(number) => json!({"kind": "integer", "value": number}),
        Literal::Boolean(flag) => json!({"kind": "boolean", "value": flag}),
    }
}

fn json_template(template: &Template) -> Value {
    match template {
        Template::Field { name, .. } => json!({"kind": "field", "name": name}),
        Template::Literal(value) => literal(value),
        Template::Object(fields) => {
            let mut map = Map::new();
            for (key, child) in fields {
                map.insert(key.clone(), json_template(child));
            }
            json!({"kind": "object", "fields": Value::Object(map)})
        }
    }
}

fn form_template(template: &Template) -> Value {
    match template {
        Template::Field {
            name,
            string_like: true,
        } => json!({"kind": "field", "name": name}),
        Template::Literal(Literal::String(text)) => json!({"kind": "string", "value": text}),
        other => json!({"kind": "json", "value": json_template(other)}),
    }
}

fn recipe_json(request: &Request, mapping: &Mapping, digest: &str, method: &str) -> String {
    let credential = match &mapping.credential.kind {
        CredentialKind::Bearer => json!({"kind": "bearer"}),
        CredentialKind::HeaderApiKey(header) => json!({"kind": "header-api-key", "header": header}),
    };
    let path: Vec<Value> = mapping
        .path
        .iter()
        .map(|segment| match segment {
            Segment::Fixed(value) => json!({"kind": "fixed", "value": value}),
            Segment::Field(name) => json!({"kind": "field", "name": name}),
        })
        .collect();
    let body = match mapping.media {
        Media::Json => {
            json!({"kind": "json", "value": json_template(&Template::Object(mapping.body.clone()))})
        }
        Media::Form => {
            let mut map = Map::new();
            for (key, template) in &mapping.body {
                map.insert(key.clone(), form_template(template));
            }
            json!({"kind": "form", "fields": Value::Object(map)})
        }
    };
    let recipe = json!({
        "schema": "auths.gateway-recipe-source/1",
        "profile_schema_digest": digest,
        "service": request.service,
        "tool": format!("{}_v{}", mapping.tool, request.version),
        "operator_namespace": request.operator_namespace,
        "credential": credential,
        "origin": mapping.server.origin,
        "write": {"method": method, "path": path, "body": body},
    });
    pretty(&recipe)
}

fn pretty(value: &Value) -> String {
    // INVARIANT: a `Value` built here always serializes.
    let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
    text.push('\n');
    text
}

fn derivation_json(
    request: &Request,
    mapping: &Mapping,
    source: &Source<'_>,
    profile: &str,
    recipe: &str,
) -> String {
    let credential = &mapping.credential;
    let credential_value = match &credential.kind {
        CredentialKind::Bearer => json!({"kind": "bearer"}),
        CredentialKind::HeaderApiKey(header) => json!({"kind": "header-api-key", "header": header}),
    };
    let omitted: Vec<Value> = mapping
        .omitted
        .iter()
        .map(|entry| json!({"pointer": entry.pointer, "path": entry.path, "reason": entry.reason}))
        .collect();
    let unenforced: Vec<Value> = mapping
        .unenforced
        .iter()
        .map(|entry| json!({"pointer": entry.pointer, "path": entry.path, "keyword": entry.keyword, "note": entry.note}))
        .collect();
    let arguments: Vec<Value> = mapping
        .arguments
        .iter()
        .map(|argument| json!({"name": argument.name, "pointer": argument.pointer}))
        .collect();
    let record = json!({
        "schema": "auths.openapi-derivation/1",
        "document": {"sha256": source.sha256, "bytes": source.bytes, "openapi": source.openapi},
        "operation": {
            "operation_id": request.operation,
            "method": source.method,
            "path": source.path,
            "pointer": source.pointer,
        },
        "server": {
            "listed": mapping.server.listed,
            "origin": mapping.server.origin,
            "base_path": mapping.server.base_path,
        },
        "security": {
            "scheme": credential.scheme_name,
            "type": credential.scheme_type,
            "source": if credential.from_override { "--security-scheme" } else { "document" },
            "acquisition": if credential.application_owned_acquisition { "application-owned" } else { "static-credential" },
            "credential": credential_value,
        },
        "profile": {
            "name": request.name,
            "service": request.service,
            "tool": mapping.tool,
            "version": request.version,
            "operator_namespace": request.operator_namespace,
        },
        "arguments": arguments,
        "overrides": request.recorded,
        "omitted": omitted,
        "unenforced": unenforced,
        "generator_format": 2,
        "outputs": {
            "profile.toml": sha256_hex(profile.as_bytes()),
            "recipe.json": sha256_hex(recipe.as_bytes()),
        },
    });
    pretty(&record)
}

fn report(request: &Request, mapping: &Mapping, source: &Source<'_>) -> Vec<String> {
    let credential = &mapping.credential;
    let security = match (&credential.kind, &credential.scheme_name) {
        (CredentialKind::Bearer, Some(name)) if credential.application_owned_acquisition => {
            format!(
                "bearer ({} {name:?}); acquisition is application-owned",
                credential.scheme_type
            )
        }
        (CredentialKind::Bearer, Some(name)) => {
            format!("bearer ({} {name:?})", credential.scheme_type)
        }
        (CredentialKind::HeaderApiKey(header), Some(name)) => {
            format!(
                "api key in header {header} ({} {name:?})",
                credential.scheme_type
            )
        }
        (CredentialKind::Bearer, None) => {
            "bearer (--security-scheme; the document declares none)".to_owned()
        }
        (CredentialKind::HeaderApiKey(header), None) => {
            format!("api key in header {header} (--security-scheme; the document declares none)")
        }
    };
    let rendered_path: String = mapping
        .path
        .iter()
        .map(|segment| match segment {
            Segment::Fixed(value) => format!("/{value}"),
            Segment::Field(name) => format!("/<{name}>"),
        })
        .collect();
    let list = |items: Vec<String>| {
        if items.is_empty() {
            "none".to_owned()
        } else {
            items.join(" ")
        }
    };
    let omitted = list(
        mapping
            .omitted
            .iter()
            .map(|entry| format!("{} ({})", entry.path, entry.reason))
            .collect(),
    );
    let overrides = list(request.recorded.clone());
    let mut lines = vec![
        format!(
            "  document:   sha256:{}  ({}, {} bytes, OpenAPI {})",
            source.sha256, source.display_name, source.bytes, source.openapi
        ),
        format!(
            "  operation:  {} {}  ({})",
            source.method, source.path, request.operation
        ),
        format!("  security:   {security}"),
        format!(
            "  arguments:  {} fields ({} derived + 3 gateway binding), worst-case {} bytes canonical JSON",
            mapping.arguments.len() + 3,
            mapping.arguments.len(),
            worst_case_json(&mapping.arguments, &request.operator_namespace)
        ),
        format!(
            "  recipe:     {} {}{rendered_path}  body: {}",
            source.method,
            mapping.server.origin,
            mapping.media.as_str()
        ),
        format!("  omitted:    {omitted}"),
        format!("  overrides:  {overrides}"),
    ];
    for entry in &mapping.unenforced {
        lines.push(format!(
            "  unenforced: {} {} ({})",
            entry.path, entry.keyword, entry.pointer
        ));
    }
    lines.extend([
        "  wrote:      profile.toml recipe.json derivation.json".to_owned(),
        "  next:       auths-profile generate profile.toml && auths gateway recipe check --recipe recipe.json --profile-lock profile.lock.json".to_owned(),
        "  claim:      derived shape only; provider effect unqualified".to_owned(),
    ]);
    lines
}

/// Renders the three files and the report.
pub(crate) fn render(request: &Request, mapping: &Mapping, source: &Source<'_>) -> Rendered {
    let fields = profile_fields(request, mapping);
    let profile_toml = profile_toml(request, mapping, &fields);
    let recipe_json = recipe_json(request, mapping, &schema_digest(&fields), &source.method);
    let derivation_json = derivation_json(request, mapping, source, &profile_toml, &recipe_json);
    Rendered {
        lines: report(request, mapping, source),
        profile_toml,
        recipe_json,
        derivation_json,
    }
}
