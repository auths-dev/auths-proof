use super::*;
use serde_json::json;

pub(crate) fn definition() -> Value {
    json!({"schema":SCHEMA,"resource_pointer":"/id","parent_pointer":"/parent_id","parent_kind":"scalar",
        "maximum_items":64,"complete":[{"kind":"absent","pointer":"/offset"}]})
}
fn token() -> String {
    format!("{}{}", super::super::ECHO_PREFIX, "0".repeat(64))
}
fn item() -> Value {
    json!({"id":"child-fixture","parent_id":"parent-fixture","marker":token()})
}
fn document() -> Value {
    json!({"records":[item()]})
}

fn case(
    name: &str,
    definition: Value,
    items: &str,
    marker: &str,
    document: Vec<u8>,
    expected: Option<&str>,
) -> Value {
    let selection: Selection = serde_json::from_value(definition.clone()).unwrap();
    let selected = super::super::parse_provider_response(&document)
        .and_then(|value| selection.select(&value, items, marker, &token(), "parent-fixture"));
    assert_eq!(
        selected.as_ref().map(Candidate::handle),
        expected,
        "case {name}"
    );
    json!({"name":name,"selection":definition,"items_pointer":items,"marker_pointer":marker,"token":token(),"parent":"parent-fixture",
        "response_hex":hex::encode(document),"selected_handle":expected})
}
fn json_case(name: &str, definition: Value, document: Value, expected: Option<&str>) -> Value {
    case(
        name,
        definition,
        "/records",
        "/marker",
        serde_json::to_vec(&document).unwrap(),
        expected,
    )
}
fn cases() -> Vec<Value> {
    let mut cases = vec![
        json_case(
            "complete-unique-records",
            definition(),
            document(),
            Some("child-fixture"),
        ),
        json_case("zero", definition(), json!({"records":[]}), None),
        json_case(
            "duplicate-even-identical-id",
            definition(),
            json!({"records":[item(),item()]}),
            None,
        ),
    ];
    let mut value = document();
    value["offset"] = json!("more");
    cases.push(json_case("pagination", definition(), value, None));
    let mut selection = definition();
    selection["complete"] = json!([{"kind":"absent","pointer":"/page/token"}]);
    cases.push(json_case(
        "missing-completeness-parent",
        selection.clone(),
        document(),
        None,
    ));
    let mut value = document();
    value["page"] = Value::Null;
    cases.push(json_case(
        "null-completeness-parent",
        selection.clone(),
        value,
        None,
    ));
    let mut value = document();
    value["page"] = json!({});
    cases.push(json_case(
        "present-completeness-parent",
        selection,
        value,
        Some("child-fixture"),
    ));
    for (name, field, value) in [
        ("wrong-parent", "parent_id", json!("other-parent")),
        ("missing-marker", "marker", Value::Null),
        ("integer-marker", "marker", json!(3)),
        ("wrong-marker", "marker", json!("other")),
        ("integer-id", "id", json!(4)),
        ("empty-id", "id", json!("")),
        ("control-id", "id", json!("child\u{0001}")),
        ("oversized-id", "id", json!("a".repeat(257))),
        ("wrong-parent-type", "parent_id", json!(["parent-fixture"])),
    ] {
        let mut document = document();
        document["records"][0][field] = value;
        cases.push(json_case(name, definition(), document, None));
    }
    let mut value = document();
    value["records"][0]["id"] = json!("é".repeat(128));
    cases.push(json_case(
        "utf8-256-byte-id",
        definition(),
        value,
        Some(&"é".repeat(128)),
    ));
    let mut value = document();
    value["records"][0]["id"] = json!("é".repeat(129));
    cases.push(json_case("utf8-258-byte-id", definition(), value, None));
    for (name, change) in [
        ("unknown-escape", "/bad~3"),
        ("dangling-escape", "/bad~"),
        ("empty-pointer", ""),
        ("too-deep", "/a/a/a/a/a/a/a/a/a"),
    ] {
        let mut selection = definition();
        selection["resource_pointer"] = json!(change);
        cases.push(json_case(name, selection, document(), None));
    }
    for (name, maximum) in [("zero-item-bound", 0), ("too-large-item-bound", 65)] {
        let mut selection = definition();
        selection["maximum_items"] = json!(maximum);
        cases.push(json_case(name, selection, document(), None));
    }
    let mut selection = definition();
    selection["resource_pointer"] = json!("/marker");
    cases.push(json_case(
        "aliased-resource-marker",
        selection,
        document(),
        None,
    ));
    let mut selection = definition();
    selection["complete"] = json!([{"kind":"absent","pointer":"/records/next"}]);
    cases.push(json_case(
        "completeness-in-items",
        selection,
        document(),
        None,
    ));
    let mut selection = definition();
    selection["complete"] = json!([{"kind":"absent","pointer":"/offset"},{"kind":"boolean","pointer":"/offset","equals":false}]);
    cases.push(json_case(
        "duplicate-completeness-pointer",
        selection,
        document(),
        None,
    ));
    let mut selection = definition();
    selection["maximum_items"] = json!(1);
    cases.push(json_case(
        "maximum-items-overflow",
        selection,
        json!({"records":[item(),{"marker":"different"}]}),
        None,
    ));
    let mut values = vec![json!({"marker":"different"}); 63];
    values.push(item());
    cases.push(json_case(
        "full-array-64",
        definition(),
        json!({"records":values}),
        Some("child-fixture"),
    ));
    let one = serde_json::to_string(&item()).unwrap();
    for (name, body) in [
        (
            "duplicate-json-key-last-wins",
            format!("{{\"records\":[],\"records\":[{one}]}}"),
        ),
        (
            "duplicate-json-key-first-wins",
            format!("{{\"records\":[{one}],\"records\":[]}}"),
        ),
    ] {
        cases.push(case(
            name,
            definition(),
            "/records",
            "/marker",
            body.into_bytes(),
            None,
        ));
    }
    cases.push(case(
        "invalid-utf8",
        definition(),
        "/records",
        "/marker",
        vec![0xff],
        None,
    ));
    cases.push(case(
        "trailing-json",
        definition(),
        "/records",
        "/marker",
        b"{} {}".to_vec(),
        None,
    ));
    let mut oversized = serde_json::to_vec(&document()).unwrap();
    oversized.resize(65_537, b' ');
    cases.push(case(
        "oversized-response",
        definition(),
        "/records",
        "/marker",
        oversized,
        None,
    ));
    let mut selection = definition();
    selection["complete"] = json!([{"kind":"boolean","pointer":"/has_more","equals":false}]);
    cases.push(case(
        "complete-data-envelope",
        selection.clone(),
        "/data",
        "/marker",
        serde_json::to_vec(&json!({"data":[item()],"has_more":false})).unwrap(),
        Some("child-fixture"),
    ));
    cases.push(case(
        "nonboolean-complete",
        selection,
        "/data",
        "/marker",
        serde_json::to_vec(&json!({"data":[item()],"has_more":0})).unwrap(),
        None,
    ));
    let mut selection = definition();
    selection["parent_kind"] = json!("sole-string-array");
    selection["parent_pointer"] = json!("/parents");
    selection["complete"] = json!([{"kind":"absent","pointer":"/nextPageToken"},{"kind":"boolean","pointer":"/incompleteSearch","equals":false}]);
    let mut file = item();
    file.as_object_mut().unwrap().remove("parent_id");
    file["parents"] = json!(["parent-fixture"]);
    let document = json!({"files":[file],"incompleteSearch":false});
    cases.push(case(
        "complete-files-envelope",
        selection.clone(),
        "/files",
        "/marker",
        serde_json::to_vec(&document).unwrap(),
        Some("child-fixture"),
    ));
    let mut incomplete = document.clone();
    incomplete["incompleteSearch"] = json!(true);
    cases.push(case(
        "incomplete-files",
        selection.clone(),
        "/files",
        "/marker",
        serde_json::to_vec(&incomplete).unwrap(),
        None,
    ));
    let mut multiple = document;
    multiple["files"][0]["parents"] = json!(["parent-fixture", "other-parent"]);
    cases.push(case(
        "multiple-parents",
        selection,
        "/files",
        "/marker",
        serde_json::to_vec(&multiple).unwrap(),
        None,
    ));
    cases
}

#[test]
fn native_created_resource_selection_fixture_is_current() {
    let cases = cases();
    let document = json!({"schema":"auths.created-resource-selection-vectors/1","cases":cases,
        "scope":"bounded duplicate-free provider JSON projection only; synthetic identifiers and marker; no provider truth, authority, journal, credential, child permit or retry claim"});
    let bytes = serde_json::to_vec_pretty(&document).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/creation-selection.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

proptest::proptest! {
    #[test]
    fn arbitrary_bounded_provider_bytes_cannot_panic(bytes in proptest::collection::vec(proptest::num::u8::ANY,0..2048)) {
        let selection:Selection=serde_json::from_value(definition()).unwrap();
        if let Some(document)=super::super::parse_provider_response(&bytes) {let _=selection.select(&document,"/records","/marker",&token(),"parent-fixture");}
    }
    #[test]
    fn two_matches_never_select_an_identity(id in "[a-z0-9]{1,32}") {
        let mut value=item();value["id"]=json!(id);
        let selection:Selection=serde_json::from_value(definition()).unwrap();
        proptest::prop_assert!(selection.select(&json!({"records":[value.clone(),value]}),"/records","/marker",&token(),"parent-fixture").is_none(), "duplicate candidates cannot establish uniqueness");
    }
}
