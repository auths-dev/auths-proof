//! Document-level selection: version, one operation, and local references.

use crate::diagnostic::{DeriveCode, Diagnostic};
use crate::json::{Json, escape_token, string_len};

/// Maximum `$ref` resolutions for one derivation.
pub(crate) const MAX_REF_RESOLUTIONS: usize = 256;
/// Maximum compact bytes of the operation after inlining every reference.
pub(crate) const MAX_SLICE_BYTES: usize = 256 * 1024;

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// The `OpenAPI` minor line of the document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Dialect {
    V30,
    V31,
}

/// The selected operation and its location.
pub(crate) struct Selected<'a> {
    pub(crate) path: &'a str,
    pub(crate) method: &'a str,
    pub(crate) item: &'a Json,
    pub(crate) item_pointer: String,
    pub(crate) operation: &'a Json,
    pub(crate) pointer: String,
}

/// Measured slice of the selected operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SliceMeasure {
    pub(crate) resolutions: usize,
    pub(crate) bytes: usize,
}

/// Reads the `openapi` version string.
///
/// # Errors
/// Rejects Swagger 2.0 and every version outside 3.0.x and 3.1.x.
pub(crate) fn dialect(document: &Json) -> Result<(Dialect, String), Diagnostic> {
    let unsupported = |message: &str| {
        Diagnostic::new(
            DeriveCode::UnsupportedVersion,
            "#/openapi",
            message.to_owned(),
        )
    };
    if document.as_object().is_none() {
        return Err(Diagnostic::new(
            DeriveCode::DocumentInvalid,
            "#",
            "the document root is not an object",
        ));
    }
    if document.get("swagger").is_some() {
        return Err(unsupported("Swagger 2.0 documents are not read"));
    }
    let version = document
        .get("openapi")
        .and_then(Json::as_str)
        .ok_or_else(|| unsupported("the document has no openapi version string"))?;
    let mut parts = version.split('.');
    let valid_patch = |part: Option<&str>| {
        part.is_some_and(|patch| {
            !patch.is_empty() && patch.len() <= 4 && patch.bytes().all(|byte| byte.is_ascii_digit())
        })
    };
    let dialect = match (parts.next(), parts.next()) {
        (Some("3"), Some("0")) => Dialect::V30,
        (Some("3"), Some("1")) => Dialect::V31,
        _ => return Err(unsupported("only OpenAPI 3.0.x and 3.1.x are read")),
    };
    if !valid_patch(parts.next()) || parts.next().is_some() {
        return Err(unsupported("only OpenAPI 3.0.x and 3.1.x are read"));
    }
    Ok((dialect, version.to_owned()))
}

/// Finds exactly one operation with `operation_id` under `paths`.
///
/// # Errors
/// Rejects a missing, duplicated, or reference-hidden operation.
pub(crate) fn select<'a>(
    document: &'a Json,
    operation_id: &str,
) -> Result<Selected<'a>, Diagnostic> {
    let paths = document
        .get("paths")
        .and_then(Json::as_object)
        .ok_or_else(|| {
            Diagnostic::new(
                DeriveCode::OperationNotFound,
                "#/paths",
                "the document has no paths object",
            )
        })?;
    let mut found: Vec<Selected<'a>> = Vec::new();
    for (path, item) in paths {
        let item_pointer = format!("#/paths/{}", escape_token(path));
        if item.get("$ref").is_some() {
            return Err(Diagnostic::new(
                DeriveCode::UnsupportedConstruct,
                format!("{item_pointer}/$ref"),
                "a referenced path item hides its operations; inline it",
            ));
        }
        for method in METHODS {
            let Some(operation) = item.get(method) else {
                continue;
            };
            if operation.get("operationId").and_then(Json::as_str) == Some(operation_id) {
                found.push(Selected {
                    path,
                    method,
                    item,
                    pointer: format!("{item_pointer}/{method}"),
                    item_pointer: item_pointer.clone(),
                    operation,
                });
            }
        }
    }
    match found.len() {
        0 => Err(Diagnostic::new(
            DeriveCode::OperationNotFound,
            "#/paths",
            format!("no operation has operationId {operation_id:?}"),
        )),
        1 => Ok(found.remove(0)),
        _ => Err(Diagnostic::new(
            DeriveCode::DuplicateOperation,
            found[1].pointer.clone(),
            format!("operationId {operation_id:?} is not unique"),
        )),
    }
}

/// Resolves a local reference string to its target and canonical pointer.
fn lookup<'a>(
    document: &'a Json,
    reference: &str,
    at: &str,
) -> Result<(&'a Json, String), Diagnostic> {
    let Some(rest) = reference.strip_prefix('#') else {
        return Err(Diagnostic::new(
            DeriveCode::RemoteRef,
            at,
            format!(
                "reference {reference:?} leaves the document; only local #/ references are read"
            ),
        ));
    };
    if !(rest.is_empty() || rest.starts_with('/')) || rest.contains('%') {
        return Err(Diagnostic::new(
            DeriveCode::UnsupportedConstruct,
            at,
            format!("reference {reference:?} is not a plain local JSON pointer"),
        ));
    }
    let mut current = document;
    for raw in rest.split('/').skip(1) {
        if raw.contains('~') && !valid_escapes(raw) {
            return Err(Diagnostic::new(
                DeriveCode::UnsupportedConstruct,
                at,
                format!("reference {reference:?} has an invalid escape"),
            ));
        }
        let token = raw.replace("~1", "/").replace("~0", "~");
        current = match current {
            Json::Object(_) => current.get(&token),
            Json::Array(items) => token
                .parse::<usize>()
                .ok()
                .filter(|index| index.to_string() == token)
                .and_then(|index| items.get(index)),
            _ => None,
        }
        .ok_or_else(|| {
            Diagnostic::new(
                DeriveCode::UnsupportedConstruct,
                at,
                format!("reference {reference:?} does not resolve"),
            )
        })?;
    }
    Ok((current, reference.to_owned()))
}

fn valid_escapes(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes
        .iter()
        .enumerate()
        .all(|(index, byte)| *byte != b'~' || matches!(bytes.get(index + 1), Some(b'0' | b'1')))
}

/// Follows a `$ref` chain from `node`; returns the final node and pointer.
///
/// # Errors
/// Rejects remote, malformed, dangling, or cyclic references and reference
/// objects with constraining siblings.
pub(crate) fn resolve<'a>(
    document: &'a Json,
    node: &'a Json,
    pointer: String,
) -> Result<(&'a Json, String), Diagnostic> {
    let mut current = node;
    let mut at = pointer;
    let mut chain: Vec<String> = Vec::new();
    while let Some(reference) = current.get("$ref") {
        let reference = reference.as_str().ok_or_else(|| {
            Diagnostic::new(
                DeriveCode::UnsupportedConstruct,
                format!("{at}/$ref"),
                "$ref is not a string",
            )
        })?;
        check_ref_siblings(current, &at)?;
        if chain.iter().any(|seen| seen == reference) || chain.len() >= MAX_REF_RESOLUTIONS {
            return Err(Diagnostic::new(
                DeriveCode::RefCycle,
                format!("{at}/$ref"),
                format!("reference {reference:?} returns to itself"),
            ));
        }
        chain.push(reference.to_owned());
        let (target, target_pointer) = lookup(document, reference, &format!("{at}/$ref"))?;
        current = target;
        at = target_pointer;
    }
    Ok((current, at))
}

fn check_ref_siblings(node: &Json, at: &str) -> Result<(), Diagnostic> {
    let extra = node.as_object().into_iter().flatten().find(|(key, _)| {
        !matches!(key.as_str(), "$ref" | "description" | "summary") && !key.starts_with("x-")
    });
    match extra {
        Some((key, _)) => Err(Diagnostic::new(
            DeriveCode::UnsupportedConstruct,
            format!("{at}/{}", escape_token(key)),
            format!("keyword {key:?} beside $ref is not read"),
        )),
        None => Ok(()),
    }
}

/// Measures the operation with every reference inlined, stopping as soon as
/// a bound is exceeded so the work stays proportional to the bounds.
///
/// # Errors
/// Rejects remote or cyclic references, more than the resolution budget, and
/// a slice larger than the byte budget.
pub(crate) fn measure(
    document: &Json,
    node: &Json,
    pointer: &str,
) -> Result<SliceMeasure, Diagnostic> {
    let mut state = Measure {
        document,
        resolutions: 0,
        bytes: 0,
        stack: Vec::new(),
        start: pointer.to_owned(),
    };
    state.visit(node, pointer)?;
    Ok(SliceMeasure {
        resolutions: state.resolutions,
        bytes: state.bytes,
    })
}

struct Measure<'a> {
    document: &'a Json,
    resolutions: usize,
    bytes: usize,
    stack: Vec<String>,
    start: String,
}

impl<'a> Measure<'a> {
    fn add(&mut self, bytes: usize) -> Result<(), Diagnostic> {
        self.bytes += bytes;
        if self.bytes > MAX_SLICE_BYTES {
            return Err(Diagnostic::new(
                DeriveCode::SliceLimit,
                self.start.clone(),
                "the operation with every reference inlined exceeds 256 KiB",
            ));
        }
        Ok(())
    }

    fn visit(&mut self, node: &'a Json, at: &str) -> Result<(), Diagnostic> {
        if let Some(reference) = node.get("$ref").and_then(Json::as_str) {
            self.resolutions += 1;
            if self.resolutions > MAX_REF_RESOLUTIONS {
                return Err(Diagnostic::new(
                    DeriveCode::RefLimit,
                    format!("{at}/$ref"),
                    "the operation needs more than 256 reference resolutions",
                ));
            }
            if self.stack.iter().any(|seen| seen == reference) {
                return Err(Diagnostic::new(
                    DeriveCode::RefCycle,
                    format!("{at}/$ref"),
                    format!("reference {reference:?} is reached from itself"),
                ));
            }
            let (target, pointer) = lookup(self.document, reference, &format!("{at}/$ref"))?;
            self.stack.push(reference.to_owned());
            self.visit(target, &pointer)?;
            self.stack.pop();
            return Ok(());
        }
        match node {
            Json::Array(items) => {
                self.add(2 + items.len().saturating_sub(1))?;
                for (index, item) in items.iter().enumerate() {
                    self.visit(item, &format!("{at}/{index}"))?;
                }
            }
            Json::Object(entries) => {
                self.add(2 + entries.len().saturating_sub(1))?;
                for (key, value) in entries {
                    self.add(string_len(key) + 1)?;
                    self.visit(value, &format!("{at}/{}", escape_token(key)))?;
                }
            }
            scalar => self.add(scalar.compact_len())?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;
    use std::path::Path;

    #[test]
    fn slice_measurement_reproduces_the_published_vendor_measurements() {
        let Ok(directory) = std::env::var("AUTHS_OPENAPI_CORPUS_DIR") else {
            return;
        };
        let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../bindings/fixtures/openapi-corpus/cases.json");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap();
        for case in manifest["cases"].as_array().unwrap() {
            let vendor = case["vendor"].as_str().unwrap().to_ascii_lowercase();
            let bytes =
                std::fs::read(Path::new(&directory).join(format!("{vendor}.json"))).unwrap();
            let document = parse(&bytes).unwrap();
            let selected = select(
                &document,
                case["operation"]["operationId"].as_str().unwrap(),
            )
            .unwrap();
            let measured = measure(&document, selected.operation, &selected.pointer).unwrap();
            assert_eq!(
                measured.resolutions as u64,
                case["measured"]["refResolutionsInlined"].as_u64().unwrap(),
                "{vendor} resolutions"
            );
            assert_eq!(
                measured.bytes as u64,
                case["measured"]["inlinedOperationBytes"].as_u64().unwrap(),
                "{vendor} bytes"
            );
        }
    }

    #[test]
    fn references_are_local_escaped_and_acyclic() {
        let document = parse(br##"{"a":{"b/c":{"$ref":"#/a/d~1e"},"d/e":{"type":"string"},"x":{"$ref":"#/a/y"},"y":{"$ref":"#/a/x"}}}"##).unwrap();
        let node = document.get("a").unwrap().get("b/c").unwrap();
        let (target, pointer) = resolve(&document, node, "#/a/b~1c".to_owned()).unwrap();
        assert_eq!(target.get("type").and_then(Json::as_str), Some("string"));
        assert_eq!(pointer, "#/a/d~1e");
        let cycle = document.get("a").unwrap().get("x").unwrap();
        assert!(resolve(&document, cycle, "#/a/x".to_owned()).is_err());
        let remote = parse(br#"{"$ref":"other.json#/a"}"#).unwrap();
        assert_eq!(
            resolve(&remote, &remote, "#".to_owned())
                .unwrap_err()
                .code(),
            DeriveCode::RemoteRef
        );
        let escaped = parse(br##"{"$ref":"#/a%20b"}"##).unwrap();
        assert!(resolve(&escaped, &escaped, "#".to_owned()).is_err());
    }
}
