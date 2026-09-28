//! Pending vectors: fixtures for the next gateway revision, which current
//! code does not satisfy yet (AP-SPEC-063, epic 1).
//!
//! Each submodule generates one fixture under `bindings/fixtures/gateway/`
//! from fixed inputs and requires the committed file to be byte-identical;
//! `AUTHS_UPDATE_FIXTURES=1` rewrites it, as for `approval-quorum.json`.
//! Each submodule whose epic has not landed also runs its vectors against
//! today's code and asserts the specific way that code falls short: the
//! evaluator registry lacks the revised evaluator, the outcome verifier
//! refuses the revised outcome, and the codes of unimplemented epics exist
//! nowhere in the crate.
//!
//! These assertions are expected to fail when the implementing work lands.
//! That failure is the signal: the change that makes a vector pass replaces
//! its pending assertion with the conformance test that drives it. The recipe
//! corpus has made that change: its test compiles every base to its
//! documented class and digest and fails every hostile case with its code.
//! So have the attempt scenarios: `scenario_tests` drives every case of
//! `attempt-scenarios-v3.json` whose checks exist, and the account-scope
//! binding cases wait for the grant policy that carries a scope. So have the
//! key-identity vectors: `keys` checks every key identity and overlap they
//! pin, and separation by key.

pub(crate) mod attempts;
mod bounds;
mod codes;
mod keys;
mod outcomes;
mod recipes;

use serde_json::Value;
use std::path::{Path, PathBuf};

/// Fixed gateway evaluation time shared by the vectors, as in the
/// approval-quorum fixture.
const NOW: u64 = 1_790_000_000;

fn fixture_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bindings/fixtures/gateway")
}

/// Renders a generated document exactly as it is committed.
fn render(document: &Value) -> String {
    let mut text = serde_json::to_string_pretty(document).expect("fixture JSON");
    text.push('\n');
    text
}

/// Requires the committed fixture `name` to equal `document`, or rewrites it
/// when `AUTHS_UPDATE_FIXTURES` is set.
fn require_current(name: &str, document: &Value) {
    let path = fixture_directory().join(name);
    let generated = render(document);
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &generated).expect("write fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == generated,
        "{name} is stale; rerun with AUTHS_UPDATE_FIXTURES=1"
    );
}

/// Reads a committed fixture.
fn load(name: &str) -> Value {
    let bytes = std::fs::read(fixture_directory().join(name)).expect("committed fixture");
    serde_json::from_slice(&bytes).expect("fixture JSON")
}

/// Applies one recipe mutation: `set` replaces the value at `pointer` or adds
/// it to the existing parent object, `append` pushes onto the array at
/// `pointer`, and `remove` deletes the object member or array element.
fn apply_mutation(document: &mut Value, mutation: &Value) {
    let op = mutation["op"].as_str().expect("op");
    let pointer = mutation["pointer"].as_str().expect("pointer");
    let value = mutation.get("value").cloned().unwrap_or(Value::Null);
    match op {
        "set" => {
            if let Some(existing) = document.pointer_mut(pointer) {
                *existing = value;
            } else {
                let (parent, key) = pointer.rsplit_once('/').expect("child pointer");
                document
                    .pointer_mut(parent)
                    .and_then(Value::as_object_mut)
                    .expect("existing parent object")
                    .insert(key.to_owned(), value);
            }
        }
        "append" => document
            .pointer_mut(pointer)
            .and_then(Value::as_array_mut)
            .expect("existing array")
            .push(value),
        "remove" => {
            let (parent, key) = pointer.rsplit_once('/').expect("child pointer");
            match document.pointer_mut(parent).expect("existing parent") {
                Value::Object(object) => {
                    object.remove(key).expect("existing member");
                }
                Value::Array(array) => {
                    array.remove(key.parse().expect("array index"));
                }
                _ => panic!("remove needs an object or array parent"),
            }
        }
        _ => panic!("unknown mutation {op}"),
    }
}

/// Every Rust source file of this crate outside this module, with its text.
fn crate_sources() -> Vec<(PathBuf, String)> {
    fn walk(directory: &Path, found: &mut Vec<(PathBuf, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(directory)
            .expect("source directory")
            .map(|entry| entry.expect("directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                if path.file_name().and_then(|name| name.to_str()) != Some("pending_vectors") {
                    walk(&path, found);
                }
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                let text = std::fs::read_to_string(&path).expect("source text");
                found.push((path, text));
            }
        }
    }
    let mut found = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut found,
    );
    found
}

/// Reports whether `code` appears as a string literal, or as the first word
/// of a formatted log line, anywhere in the crate outside this module.
fn crate_defines_code(sources: &[(PathBuf, String)], code: &str) -> bool {
    let quoted = format!("\"{code}\"");
    let logged = format!("\"{code} ");
    sources
        .iter()
        .any(|(_, text)| text.contains(&quoted) || text.contains(&logged))
}

#[test]
fn mutations_follow_their_documented_semantics() {
    let mut document = serde_json::json!({"a": {"b": [1, 2]}, "c": 3});
    for mutation in [
        serde_json::json!({"op": "set", "pointer": "/c", "value": 4}),
        serde_json::json!({"op": "set", "pointer": "/a/d", "value": 5}),
        serde_json::json!({"op": "append", "pointer": "/a/b", "value": 6}),
        serde_json::json!({"op": "remove", "pointer": "/a/b/0"}),
        serde_json::json!({"op": "remove", "pointer": "/a/d"}),
    ] {
        apply_mutation(&mut document, &mutation);
    }
    assert_eq!(document, serde_json::json!({"a": {"b": [2, 6]}, "c": 4}));
}
