//! WebAssembly export of the generation-time `OpenAPI` operation derivation
//! tool used by the packaged profile CLI.
//!
//! This module is separate from the runtime verifier module so that browser
//! and server verifiers never download the authoring-only mapper.

#![forbid(unsafe_code)]

use wasm_bindgen::prelude::wasm_bindgen;

/// Derives one `OpenAPI` operation into profile, recipe, and provenance bytes
/// for the packaged profile CLI. Pure: it reads only its arguments, and a
/// rejected document is an `ok: false` JSON result, never an exception.
#[must_use]
#[wasm_bindgen(js_name = deriveOpenapiOperationV1)]
// wasm-bindgen passes a JavaScript string array only as an owned vector.
#[allow(clippy::needless_pass_by_value)]
pub fn derive_openapi_operation_v1(
    document: &[u8],
    document_name: &str,
    arguments: Vec<String>,
) -> String {
    auths_openapi_derive::derive_to_json(document, document_name, &arguments)
}

/// Reads a written `derivation.json` strictly for the packaged profile CLI;
/// an invalid record is an `ok: false` JSON result, never an exception.
#[must_use]
#[wasm_bindgen(js_name = readDerivationRecordV1)]
pub fn read_derivation_record_v1(record: &[u8]) -> String {
    auths_openapi_derive::read_derivation_record_to_json(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn parse(result: &str) -> Value {
        serde_json::from_str(result).expect("the boundary always returns JSON")
    }

    #[test]
    fn hostile_input_is_an_in_band_rejection_not_a_panic() {
        for document in [&b""[..], b"\xff", b"{", b"[]", b"null"] {
            let result = parse(&derive_openapi_operation_v1(
                document,
                "hostile.json",
                vec!["--operation".to_owned(), "x".to_owned()],
            ));
            assert_eq!(result["schema"], "auths.openapi-derive-result/1");
            assert_eq!(result["ok"], false);
        }
        for record in [&b""[..], b"\xff", b"{}", b"{\"schema\":1}"] {
            let result = parse(&read_derivation_record_v1(record));
            assert_eq!(result["schema"], "auths.openapi-derivation-record-result/1");
            assert_eq!(result["ok"], false);
        }
    }

    #[test]
    fn the_boundary_returns_the_native_mapper_bytes_unchanged() {
        let document =
            include_bytes!("../../../fixtures/openapi-derivation/documents/minimal.json");
        let arguments: Vec<String> = [
            "--operation",
            "createNote",
            "--service",
            "notes",
            "--name",
            "create-note",
            "--operator-namespace",
            "notes-demo",
            "--omit",
            "dry_run",
            "--require",
            "pinned",
            "--require",
            "priority",
            "--pick",
            "priority=integer",
            "--omit",
            "meta.weight",
            "--literal",
            "body=\"Created through the Auths gateway\"",
            "--max-bytes",
            "title=100",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let exported = derive_openapi_operation_v1(document, "minimal.json", arguments.clone());
        assert_eq!(
            exported,
            auths_openapi_derive::derive_to_json(document, "minimal.json", &arguments)
        );
        let derived = parse(&exported);
        assert_eq!(derived["ok"], true);
        let record = derived["files"]["derivation.json"]
            .as_str()
            .expect("a derived operation carries its provenance record");
        let read = parse(&read_derivation_record_v1(record.as_bytes()));
        assert_eq!(read["ok"], true);
        assert_eq!(read["version"], derived["version"]);
    }
}
