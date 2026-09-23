//! Work and input bounds that a fixture file cannot show cheaply.

use std::time::{Duration, Instant};

fn arguments(operation: &str) -> Vec<String> {
    [
        "--operation",
        operation,
        "--service",
        "hostile",
        "--name",
        "hostile",
        "--operator-namespace",
        "hostile",
    ]
    .iter()
    .map(|value| (*value).to_owned())
    .collect()
}

/// A request body that references `key` under components, whose target is an
/// array of `items` small elements.
fn document(path: &str, key: &str, items: usize) -> Vec<u8> {
    let array = vec!["0"; items].join(",");
    format!(
        r##"{{"openapi":"3.1.0","servers":[{{"url":"https://api.hostile.example"}}],"security":[{{"B":[]}}],"components":{{"securitySchemes":{{"B":{{"type":"http","scheme":"bearer"}}}},"schemas":{{"{key}":{{"type":"object","x-items":[{array}]}}}}}},"paths":{{"{path}":{{"post":{{"operationId":"op","requestBody":{{"required":true,"content":{{"application/json":{{"schema":{{"$ref":"#/components/schemas/{key}"}}}}}}}}}}}}}}}}"##
    )
    .into_bytes()
}

fn assert_quick(started: Instant) {
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "derivation took {:?}",
        started.elapsed()
    );
}

#[test]
fn a_megabyte_reference_is_refused_without_per_node_copies() {
    let bytes = document("/x", &"k".repeat(1 << 20), 120_000);
    let started = Instant::now();
    let rejected = auths_openapi_derive::derive(&bytes, "doc.json", &arguments("op")).unwrap_err();
    assert_quick(started);
    assert_eq!(
        rejected.diagnostics()[0].code(),
        auths_openapi_derive::DeriveCode::UnsupportedConstruct
    );
    assert!(rejected.diagnostics()[0].pointer().len() <= 2051);
}

#[test]
fn measuring_many_nodes_under_a_long_reference_stays_linear() {
    let bytes = document("/x", &"k".repeat(1000), 120_000);
    let started = Instant::now();
    let result = auths_openapi_derive::derive(&bytes, "doc.json", &arguments("op"));
    assert_quick(started);
    // The slice fits (about 240 KB) and is fully measured; mapping then
    // rejects the object for declaring no additionalProperties.
    let rejected = result.unwrap_err();
    assert_eq!(
        rejected.diagnostics()[0].code(),
        auths_openapi_derive::DeriveCode::OpenObject
    );
}

#[test]
fn a_long_path_template_is_refused() {
    let path = format!("/{}", "p".repeat(2000));
    let bytes = document(&path, "Body", 1);
    let rejected = auths_openapi_derive::derive(&bytes, "doc.json", &arguments("op")).unwrap_err();
    assert_eq!(rejected.diagnostics()[0].pointer(), "#/paths");
}

#[test]
fn derivation_records_are_read_strictly() {
    let digest = "a".repeat(64);
    let record = |version: &str| {
        format!(
            r#"{{"schema":"auths.openapi-derivation/1","profile":{{"version":{version}}},"outputs":{{"profile.toml":"{digest}","recipe.json":"{digest}"}}}}"#
        )
        .into_bytes()
    };
    let read = auths_openapi_derive::read_derivation_record(&record("2")).unwrap();
    assert_eq!(read.version(), 2);
    assert_eq!(read.profile_sha256(), digest);
    for bad in ["1.0", "0", "10000", "\"1\"", "-1"] {
        assert!(
            auths_openapi_derive::read_derivation_record(&record(bad)).is_err(),
            "{bad}"
        );
    }
    let mut invalid_utf8 = record("1");
    invalid_utf8.insert(1, 0xff);
    assert!(auths_openapi_derive::read_derivation_record(&invalid_utf8).is_err());
    let mut duplicate = record("1");
    duplicate.splice(1..1, br#""schema":"x","#.iter().copied());
    assert!(auths_openapi_derive::read_derivation_record(&duplicate).is_err());
    let encoded: serde_json::Value = serde_json::from_str(
        &auths_openapi_derive::read_derivation_record_to_json(&record("1.0")),
    )
    .unwrap();
    assert_eq!(encoded["ok"], false);
}
