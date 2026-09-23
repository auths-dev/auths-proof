//! Generation-time derivation of one exact operation contract and its
//! declared gateway request recipe from a local `OpenAPI` document.
//!
//! Derivation is a pure function of the document bytes, the requested
//! `operationId`, and explicit flags. It performs no network or file access
//! and reads no credential; the packaged CLIs read the document and write the
//! three outputs. The document is untrusted and bounded: every construct the
//! restricted profile schema or the gateway recipe compiler cannot express is
//! rejected with a stable code, a JSON pointer, and the flag that would
//! resolve it, if one exists. Nothing derived here is authority: the outputs
//! are reviewed source that the existing profile generator and recipe
//! compiler consume unchanged.

mod diagnostic;
mod document;
mod json;
mod mapper;
mod model;
mod render;
mod request;
mod schema;

pub use diagnostic::{DeriveCode, Diagnostic};

use document::{MAX_REF_RESOLUTIONS, dialect, measure, select};
use mapper::Mapper;
use serde_json::json;
use sha2::{Digest as _, Sha256};

/// Largest document accepted, in bytes.
pub const MAX_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;

/// Schema of the provenance record written as `derivation.json`.
pub const DERIVATION_SCHEMA: &str = "auths.openapi-derivation/1";

/// Schema of the in-process result both language bindings decode.
pub const RESULT_SCHEMA: &str = "auths.openapi-derive-result/1";

/// Schema of the in-process result of reading a provenance record.
pub const RECORD_RESULT_SCHEMA: &str = "auths.openapi-derivation-record-result/1";

/// Largest `derivation.json` read back.
pub const MAX_DERIVATION_BYTES: usize = 262_144;

/// Output file names, in the order they are written.
pub const OUTPUT_FILES: [&str; 3] = ["profile.toml", "recipe.json", "derivation.json"];

/// A successful derivation: exact file bytes and the report lines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Derived {
    profile_toml: String,
    recipe_json: String,
    derivation_json: String,
    version: u16,
    lines: Vec<String>,
}

impl Derived {
    /// Returns the restricted `profile.toml` source.
    #[must_use]
    pub fn profile_toml(&self) -> &str {
        &self.profile_toml
    }

    /// Returns the gateway recipe source (`auths.gateway-recipe-source/1`).
    #[must_use]
    pub fn recipe_json(&self) -> &str {
        &self.recipe_json
    }

    /// Returns the provenance record.
    #[must_use]
    pub fn derivation_json(&self) -> &str {
        &self.derivation_json
    }

    /// Returns the profile version written into `profile.toml`.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the human report both CLIs print after writing.
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }
}

/// A rejected derivation: every diagnostic found, in document order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rejected {
    diagnostics: Vec<Diagnostic>,
}

impl Rejected {
    /// Returns the diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Returns the report both CLIs print; nothing is written on rejection.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec!["REJECTED  contract".to_owned()];
        lines.extend(self.diagnostics.iter().flat_map(Diagnostic::lines));
        lines.push("nothing written".to_owned());
        lines
    }
}

fn reject(diagnostic: Diagnostic) -> Rejected {
    Rejected {
        diagnostics: vec![diagnostic],
    }
}

fn identity_errors(request: &request::Request) -> Vec<Diagnostic> {
    let identity = |value: &str| {
        value.len() <= 64
            && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
    };
    let namespace = request.operator_namespace.as_str();
    let mut errors = Vec::new();
    for (flag, value) in [("--service", &request.service), ("--name", &request.name)] {
        if !identity(value) {
            errors.push(Diagnostic::new(
                DeriveCode::InvalidRequest,
                "",
                format!("{flag} {value:?} must be a 1-64 byte lowercase identifier"),
            ));
        }
    }
    if !(namespace.len() <= 64
        && namespace
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        errors.push(Diagnostic::new(
            DeriveCode::InvalidRequest,
            "",
            format!("--operator-namespace {namespace:?} must be a 1-64 byte [A-Za-z0-9._-] token starting with a letter or digit"),
        ));
    }
    errors
}

fn display_name(name: &str) -> &str {
    if !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        name
    } else {
        "document"
    }
}

fn parse_document(document: &[u8]) -> Result<json::Json, Rejected> {
    if document.is_empty() || document.len() > MAX_DOCUMENT_BYTES {
        return Err(reject(Diagnostic::new(
            DeriveCode::DocumentInvalid,
            "#",
            "the document must be 1 byte to 32 MiB",
        )));
    }
    let first = document.iter().find(|byte| !byte.is_ascii_whitespace());
    if first != Some(&b'{') {
        return Err(reject(Diagnostic::new(
            DeriveCode::DocumentFormat,
            "#",
            "the document is not a JSON object; YAML is not read, so convert it to JSON with a safe loader first",
        )));
    }
    json::parse(document)
        .map_err(|reason| reject(Diagnostic::new(DeriveCode::DocumentInvalid, "#", reason)))
}

/// Derives one operation.
///
/// `arguments` are the derive flags after the CLI removed its own
/// `--openapi` and output-directory flags: `--operation`, `--service`,
/// `--name`, `--operator-namespace`, optional `--version`, and the override
/// flags. `document_name` is shown in the report only and never affects the
/// written bytes.
///
/// # Errors
/// Returns every rejection found. Document-level failures (size, format,
/// version, operation selection, reference bounds) stop at the first one;
/// mapping failures are collected so one run reports the whole wall.
pub fn derive(
    document: &[u8],
    document_name: &str,
    arguments: &[String],
) -> Result<Derived, Rejected> {
    let (request, overrides) =
        request::parse(arguments).map_err(|diagnostics| Rejected { diagnostics })?;
    let errors = identity_errors(&request);
    if !errors.is_empty() {
        return Err(Rejected {
            diagnostics: errors,
        });
    }
    let tree = parse_document(document)?;
    let (dialect, openapi) = dialect(&tree).map_err(reject)?;
    let selected = select(&tree, &request.operation).map_err(reject)?;
    let method = selected.method.to_ascii_uppercase();
    if !matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        return Err(reject(Diagnostic::new(
            DeriveCode::UnsupportedMethod,
            selected.pointer.clone(),
            format!(
                "{method} is not a single write; only POST, PUT, PATCH, and DELETE are derived"
            ),
        )));
    }
    let operation = measure(&tree, selected.operation, &selected.pointer).map_err(reject)?;
    if let Some(shared) = selected.item.get("parameters") {
        let parameters = measure(
            &tree,
            shared,
            &format!("{}/parameters", selected.item_pointer),
        )
        .map_err(reject)?;
        if operation.resolutions + parameters.resolutions > MAX_REF_RESOLUTIONS {
            return Err(reject(Diagnostic::new(
                DeriveCode::RefLimit,
                selected.pointer.clone(),
                "the operation needs more than 256 reference resolutions",
            )));
        }
    }
    let source = render::Source {
        sha256: hex::encode(Sha256::digest(document)),
        bytes: document.len(),
        openapi,
        display_name: display_name(document_name),
        method,
        path: selected.path.to_owned(),
        pointer: selected.pointer.clone(),
    };
    let mapper = Mapper {
        document: &tree,
        dialect,
        overrides,
        diagnostics: Vec::new(),
        omitted: Vec::new(),
        unenforced: Vec::new(),
        arguments: Vec::new(),
    };
    let mapping = mapper
        .map(&request, &selected)
        .map_err(|diagnostics| Rejected { diagnostics })?;
    let rendered = render::render(&request, &mapping, &source).map_err(reject)?;
    Ok(Derived {
        profile_toml: rendered.profile_toml,
        recipe_json: rendered.recipe_json,
        derivation_json: rendered.derivation_json,
        version: request.version,
        lines: rendered.lines,
    })
}

/// Runs [`derive()`] and encodes the outcome as the JSON both bindings decode.
/// This never fails: every problem is an in-band `ok: false` result.
#[must_use]
pub fn derive_to_json(document: &[u8], document_name: &str, arguments: &[String]) -> String {
    let value = match derive(document, document_name, arguments) {
        Ok(derived) => json!({
            "schema": RESULT_SCHEMA,
            "ok": true,
            "version": derived.version,
            "files": {
                "profile.toml": derived.profile_toml,
                "recipe.json": derived.recipe_json,
                "derivation.json": derived.derivation_json,
            },
            "lines": derived.lines,
        }),
        Err(rejected) => json!({
            "schema": RESULT_SCHEMA,
            "ok": false,
            "stage": "contract",
            "diagnostics": rejected.diagnostics.iter().map(|diagnostic| json!({
                "code": diagnostic.code().as_str(),
                "pointer": diagnostic.pointer(),
                "message": diagnostic.message(),
                "overrides": diagnostic.overrides(),
            })).collect::<Vec<_>>(),
            "lines": rejected.lines(),
        }),
    };
    value.to_string()
}

/// The facts `profile check`, `profile diff`, and `derive` read back from a
/// written `derivation.json`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivationRecord {
    version: u16,
    profile_sha256: String,
    recipe_sha256: String,
}

impl DerivationRecord {
    /// Returns the profile version the files were derived under.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the recorded lowercase SHA-256 of `profile.toml`.
    #[must_use]
    pub fn profile_sha256(&self) -> &str {
        &self.profile_sha256
    }

    /// Returns the recorded lowercase SHA-256 of `recipe.json`.
    #[must_use]
    pub fn recipe_sha256(&self) -> &str {
        &self.recipe_sha256
    }
}

/// Reads a `derivation.json` strictly: bounded UTF-8 JSON without duplicate
/// keys, the provenance schema, an integer `profile.version` from 1 to 9999
/// (`1.0` is rejected), and two 64-character lowercase hex digests. Both
/// CLIs call this, so they accept and reject exactly the same records.
///
/// # Errors
/// Returns a human reason when any of those rules fails.
pub fn read_derivation_record(bytes: &[u8]) -> Result<DerivationRecord, String> {
    let invalid = || "derivation.json is invalid".to_owned();
    if bytes.is_empty() || bytes.len() > MAX_DERIVATION_BYTES {
        return Err("derivation.json must be 1 byte to 256 KiB".to_owned());
    }
    let tree = json::parse(bytes).map_err(|_| invalid())?;
    if tree.get("schema").and_then(json::Json::as_str) != Some(DERIVATION_SCHEMA) {
        return Err(invalid());
    }
    let version = match tree
        .get("profile")
        .and_then(|profile| profile.get("version"))
    {
        Some(json::Json::Number(number)) => number
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| (1..=9999).contains(value))
            .ok_or_else(invalid)?,
        _ => return Err(invalid()),
    };
    let digest = |name: &str| {
        tree.get("outputs")
            .and_then(|outputs| outputs.get(name))
            .and_then(json::Json::as_str)
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .map(str::to_owned)
            .ok_or_else(invalid)
    };
    Ok(DerivationRecord {
        version,
        profile_sha256: digest("profile.toml")?,
        recipe_sha256: digest("recipe.json")?,
    })
}

/// Runs [`read_derivation_record`] and encodes the outcome as the JSON both
/// bindings decode. This never fails: an invalid record is `ok: false`.
#[must_use]
pub fn read_derivation_record_to_json(bytes: &[u8]) -> String {
    let value = match read_derivation_record(bytes) {
        Ok(record) => json!({
            "schema": RECORD_RESULT_SCHEMA,
            "ok": true,
            "version": record.version,
            "outputs": {
                "profile.toml": record.profile_sha256,
                "recipe.json": record.recipe_sha256,
            },
        }),
        Err(message) => json!({
            "schema": RECORD_RESULT_SCHEMA,
            "ok": false,
            "message": message,
        }),
    };
    value.to_string()
}
