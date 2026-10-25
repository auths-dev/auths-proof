use super::*;
use crate::recipe::{source::BodySource, strict_json};
use proptest::prelude::*;
use serde::Serialize;
use serde_json::json;

// Frozen test-only derive: the production decoder has one iterative path.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum DerivedOracle {
    String { value: String },
    Integer { value: i64 },
    Boolean { value: bool },
    Field { name: String },
    Object { fields: BTreeMap<String, DerivedOracle> },
    Array { items: Vec<DerivedOracle> },
    Echo,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum BufferedOracle {
    Json { value: DerivedOracle },
}

fn compare(original: &Value) {
    let bytes = serde_json::to_vec(original).expect("original JSON");
    let actual = strict_json::from_slice::<ValueExpr>(&bytes);
    let expected = strict_json::from_slice::<DerivedOracle>(&bytes);
    match (actual, expected) {
        (Ok(actual), Ok(expected)) => assert_eq!(serde_json::to_value(actual).expect("actual source"),
            serde_json::to_value(expected).expect("derived source"), "{original}"),
        (Err(_), Err(_)) => {}
        _ => panic!("iterative/derive direct verdict differs for {original}"),
    }
    let buffered = serde_json::to_vec(&json!({"kind":"json","value":original})).expect("buffered original");
    let actual = strict_json::from_slice::<BodySource>(&buffered);
    let expected = strict_json::from_slice::<BufferedOracle>(&buffered);
    match (actual, expected) {
        (Ok(actual), Ok(expected)) => assert_eq!(serde_json::to_value(actual).expect("actual source"),
            serde_json::to_value(expected).expect("derived source"), "buffered {original}"),
        (Err(_), Err(_)) => {}
        _ => panic!("iterative/derive buffered verdict differs for {original}"),
    }
}

fn expression() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        ".{0,64}".prop_map(|value| json!({"kind":"string","value":value})),
        any::<i64>().prop_map(|value| json!({"kind":"integer","value":value})),
        any::<bool>().prop_map(|value| json!({"kind":"boolean","value":value})),
        ".{0,32}".prop_map(|name| json!({"kind":"field","name":name})),
        Just(json!({"kind":"echo","ignored":{"nested":[true,null,1]}})),
    ];
    leaf.prop_recursive(4, 96, 8, |inner| prop_oneof![
        proptest::collection::vec(inner.clone(), 0..6).prop_map(|items| json!({"kind":"array","items":items})),
        proptest::collection::btree_map("[a-zA-Z0-9é]{0,12}", inner, 0..6)
            .prop_map(|fields| json!({"kind":"object","fields":fields})),
    ])
}

#[test]
fn iterative_source_decoder_matches_derive_for_forms_tags_fields_and_word_domains() {
    for value in [
        json!(["string", "é😀\u{0000}"]), json!(["integer", i64::MIN]),
        json!(["integer", i64::MAX]), json!(["boolean", false]), json!(["field", "record_id"]),
        json!(["object", {"z":["integer",1], "a":{"kind":"echo","ignored":[]}}]),
        json!(["array", [["boolean",true], {"kind":1,"value":7}]]),
        json!(["echo"]), json!({"kind":"echo","ignored":{"nested":[1,null,true]}}),
        json!({"kind":"integer","value":u64::MAX}), json!({"kind":"integer","value":-0.0}),
        json!({"kind":"boolean","value":1}), json!({"kind":"string","value":null}),
        json!({"kind":"field","name":null}), json!({"kind":"array","items":{}}),
        json!({"kind":"object","fields":[]}), json!({"kind":"integer","value":1,"unknown":0}),
        json!(["echo",1]), json!(["integer"]), json!(["integer",1,2]), json!({}), json!(null),
    ] {
        compare(&value);
    }
    for index in 0_u64..=8 {
        compare(&json!({"kind":index,"value":7}));
        compare(&json!([index,7]));
    }
}

#[test]
fn iterative_source_decoder_retains_every_nested_object_and_array_child() {
    let mut original = json!({"kind":"integer","value":i64::MIN});
    for level in 0..40 {
        original = if level % 2 == 0 {
            json!({"kind":"array","items":[{"kind":"boolean","value":true},original]})
        } else {
            json!({"kind":"object","fields":{"z":original,"a":{"kind":"string","value":"é😀"}}})
        };
    }
    compare(&original);
    for bytes in [
        br#"{"kind":"array","items":[{"kind":"integer","value":1,"value":2}]}"#.as_slice(),
        br#"{"kind":"object","fields":{"a":{"kind":"echo"},"\u0061":{"kind":"echo"}}}"#.as_slice(),
        br#"{"kind":"echo","kind":"echo"}"#.as_slice(),
    ] {
        assert!(strict_json::from_slice::<ValueExpr>(bytes).is_err());
        assert!(strict_json::from_slice::<DerivedOracle>(bytes).is_err());
    }
}

proptest! {
    #[test]
    fn iterative_source_decode_has_derive_parity_on_unique_recursive_originals(original in expression()) {
        compare(&original);
    }

    #[test]
    fn iterative_source_decode_has_derive_parity_for_nested_buffered_identifier_indices(
        value in any::<i64>(), index in 0_u64..=10, positional in any::<bool>(),
    ) {
        let child = if positional { json!([index,value]) } else { json!({"kind":index,"value":value}) };
        compare(&json!({"kind":"array","items":[child]}));
    }
}
