use super::*;
use crate::{FileGatewayAttemptStore, GatewayAttemptError, GatewayAttemptStage};
use serde_json::json;
use std::sync::Arc;
use url::form_urlencoded;

// Native evidence for the independent full typed-source serialization model.
// These exercise serde/JCS only: successful decoding does not admit a recipe.
fn serde_contract_round_trip<T: serde::de::DeserializeOwned + serde::Serialize>(value: Value) {
    let bytes = serde_json::to_vec(&value).expect("test input");
    let decoded: T = strict_json::from_slice(&bytes).expect("typed test input");
    assert_eq!(serde_json::to_value(decoded).expect("typed serialization"), value);
}

fn serde_contract_normalizes<T: serde::de::DeserializeOwned + serde::Serialize>(input: Value, expected: Value) {
    let bytes = serde_json::to_vec(&input).expect("test input");
    let decoded: T = strict_json::from_slice(&bytes).expect("typed test input");
    assert_eq!(serde_json::to_value(decoded).expect("typed serialization"), expected);
}

fn serde_contract_refuses_unknown<T: serde::de::DeserializeOwned>(mut value: Value) {
    let original = serde_json::to_vec(&value).expect("test input");
    assert!(strict_json::from_slice::<T>(&original).is_ok(), "valid counterpart: {}", std::any::type_name::<T>());
    value.as_object_mut().expect("object test input").insert("auths_unknown_member".into(), json!(true));
    let bytes = serde_json::to_vec(&value).expect("test input");
    assert!(strict_json::from_slice::<T>(&bytes).is_err(), "{}", std::any::type_name::<T>());
}

fn serde_contract_source(value: &Value) -> RecipeSource {
    strict_json::from_slice(&serde_json::to_vec(value).expect("test input")).expect("typed source")
}

// Test-only serializer that preserves the supplied property event order and
// can deliberately emit duplicates. Actual Auths source serializers must earn
// uniqueness; silently overwriting entries in a Value map cannot test that risk.
struct CanonicalMapEntries<'a>(&'a [(String, Value)]);

impl serde::Serialize for CanonicalMapEntries<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

// Test-only collect_str producer exercises native fragment boundaries. Auths
// source derives do not accept this or another runtime Serialize callback.
struct CanonicalChunkedString<'a>(&'a [String]);

impl std::fmt::Display for CanonicalChunkedString<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for chunk in self.0 {
            formatter.write_str(chunk)?;
        }
        Ok(())
    }
}

impl serde::Serialize for CanonicalChunkedString<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[test]
fn canonical_string_fragment_boundaries_keep_exact_escaping_and_one_quote_pair() {
    let chunks = ["", "plain", "é😀", "\"\0", "\\", "/\n", "\u{2028}\u{2029}", "tail", ""]
        .map(str::to_owned);
    let joined = chunks.concat();
    let expected = serde_json_canonicalizer::to_vec(&joined).expect("whole string");
    let actual = serde_json_canonicalizer::to_vec(&CanonicalChunkedString(&chunks)).expect("chunked string");
    assert_eq!(actual, expected);
    assert_eq!(strict_json::from_slice::<String>(&actual).expect("original string"), joined);
    let mut output = b"prefix:".to_vec();
    serde_json_canonicalizer::to_writer(&CanonicalChunkedString(&chunks), &mut output).expect("append chunked string");
    assert_eq!(&output[..7], b"prefix:");
    assert_eq!(&output[7..], expected.as_slice());
    for scalar in 0_u32..=255 {
        let character = char::from_u32(scalar).expect("Latin-1 scalar");
        let text = character.to_string();
        let canonical = serde_json_canonicalizer::to_vec(&text).expect("canonical scalar string");
        let parsed: String = strict_json::from_slice(&canonical).expect("exact scalar");
        assert_eq!(parsed, text);
        if scalar >= 128 {
            let mut buffer = [0_u8; 4];
            assert_eq!(&canonical[1..canonical.len() - 1], character.encode_utf8(&mut buffer).as_bytes(),
                "non-ASCII UTF-8 bytes do not trigger the escape table");
        }
    }
}

#[test]
fn canonical_object_set_retains_first_property_for_a_duplicate_sorting_key() {
    let entries = [("b".to_owned(), json!(1)), ("a".to_owned(), json!(false)),
        ("a".to_owned(), json!("later-payload"))];
    let serialized = serde_json::to_vec(&CanonicalMapEntries(&entries)).expect("raw property events");
    assert!(strict_json::from_slice::<Value>(&serialized).is_err(), "raw duplicate must fail preflight");
    let canonical = serde_json_canonicalizer::to_vec(&CanonicalMapEntries(&entries)).expect("canonicalizer set behavior");
    assert_eq!(canonical, br#"{"a":false,"b":1}"#,
        "the ordinary canonicalizer does not itself reject duplicate Serialize events");
    let reversed = entries.into_iter().rev().collect::<Vec<_>>();
    assert_eq!(serde_json_canonicalizer::to_vec(&CanonicalMapEntries(&reversed)).expect("reversed events"),
        br#"{"a":"later-payload","b":1}"#,
        "permutation invariance requires original unique names");
}

#[test]
fn canonical_object_buffers_keep_complete_nested_children_and_exact_framing() {
    let entries = [("child".to_owned(), json!({"z":null,"a":{"y":false,"x":true}})),
        ("array".to_owned(), json!([{"b":2,"a":1},[],[true,false,null]])),
        (String::new(), json!("")), ("\n".to_owned(), json!("control")),
        ("\u{e000}".to_owned(), json!("literal")), ("\u{10000}".to_owned(), json!([]))];
    let expected = [r#"{"":"","\n":"control","array":[{"a":1,"b":2},[],[true,false,null]],"child":{"a":{"x":true,"y":false},"z":null},""#,
        "\u{10000}", "\":[],\"", "\u{e000}", "\":\"literal\"}"].concat();
    let canonical = serde_json_canonicalizer::to_vec(&CanonicalMapEntries(&entries)).expect("nested canonical object");
    assert_eq!(canonical, expected.as_bytes());
    let decoded: Value = strict_json::from_slice(&canonical).expect("complete unique nested result");
    for (key, value) in &entries {
        assert_eq!(decoded.get(key), Some(value), "complete original payload for {key:?}");
    }
    assert_eq!(serde_json_canonicalizer::to_vec(&CanonicalMapEntries(&[])).expect("empty object"), b"{}");
}

#[test]
fn native_key_string_reader_validates_utf8_escapes_and_complete_documents() {
    let valid: &[(&[u8], &str)] = &[
        (&[0xc2, 0x80], "\u{80}"), (&[0xe0, 0xa0, 0x80], "\u{800}"),
        (&[0xed, 0x9f, 0xbf], "\u{d7ff}"), (&[0xee, 0x80, 0x80], "\u{e000}"),
        (&[0xef, 0xbf, 0xbf], "\u{ffff}"), (&[0xf0, 0x90, 0x80, 0x80], "\u{10000}"),
        (&[0xf4, 0x8f, 0xbf, 0xbf], "\u{10ffff}"),
    ];
    for (bytes, expected) in valid {
        let input = [b"\"".as_slice(), *bytes, b"\"".as_slice()].concat();
        assert_eq!(serde_json::from_slice::<String>(&input).expect("valid scalar"), *expected);
        assert_eq!(serde_json::from_slice::<Value>(&input).expect("native key value").as_str(), Some(*expected));
    }
    let invalid: &[&[u8]] = &[
        &[0x80], &[0xff], &[0xc0, 0x80], &[0xc1, 0xbf], &[0xc2],
        &[0xe0, 0x80, 0x80], &[0xed, 0xa0, 0x80], &[0xe2, 0x82],
        &[0xf0, 0x80, 0x80, 0x80], &[0xf4, 0x90, 0x80, 0x80],
        &[0xf5, 0x80, 0x80, 0x80], &[0xf0, 0x9f, 0x98], &[0], &[31],
    ];
    for bytes in invalid {
        let input = [b"\"".as_slice(), *bytes, b"\"".as_slice()].concat();
        assert!(serde_json::from_slice::<String>(&input).is_err(), "invalid scalar {bytes:x?}");
        assert!(serde_json::from_slice::<Value>(&input).is_err(), "actual key-value parse {bytes:x?}");
    }
    for input in [br#""\ud800""#.as_slice(), br#""\udfff""#.as_slice(), br#""\ud800\ud800""#.as_slice(),
        br#""\u000""#.as_slice(), br#""\x00""#.as_slice(), br#""\u{41}""#.as_slice(),
        br#""ok" true"#.as_slice(), b"\"ok\"\x0b".as_slice()] {
        assert!(serde_json::from_slice::<String>(input).is_err());
    }
    for input in [b"null".as_slice(), b"true".as_slice(), b"1".as_slice(), b"[]".as_slice(), b"{}".as_slice()] {
        assert!(serde_json::from_slice::<Value>(input).expect("valid non-string JSON").as_str().is_none());
        assert!(serde_json::from_slice::<String>(input).is_err(), "property key must be a string");
    }
}

#[test]
fn malformed_map_event_refusal_keeps_the_original_outer_writer_prefix() {
    struct ValueBeforeKey;
    impl serde::Serialize for ValueBeforeKey {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_value(&false)?;
            map.end()
        }
    }
    let mut output = b"existing-prefix".to_vec();
    let error = serde_json_canonicalizer::to_writer(&ValueBeforeKey, &mut output).expect_err("missing property key");
    assert_eq!(error.io_error_kind(), Some(std::io::ErrorKind::InvalidData));
    assert!(error.to_string().contains("end_object_key"), "pinned formatter missing-key error");
    assert_eq!(output, b"existing-prefix", "buffered incomplete property never reaches the outer sink");
}

#[test]
fn quoted_object_names_round_trip_while_writer_appends_to_an_existing_sink() {
    let name = "\0\"\\é\u{10000}".to_owned();
    let child = json!({"nested":[{"kind":false,"value":null},[true,false]]});
    let entries = [(name.clone(), child.clone()), (format!("{name}\0"), json!({}))];
    let standalone = serde_json_canonicalizer::to_vec(&CanonicalMapEntries(&entries)).expect("standalone object");
    let mut output = b"existing-prefix:".to_vec();
    let prefix_length = output.len();
    serde_json_canonicalizer::to_writer(&CanonicalMapEntries(&entries), &mut output).expect("append object");
    assert_eq!(&output[..prefix_length], b"existing-prefix:");
    assert_eq!(&output[prefix_length..], standalone.as_slice());
    let decoded: Value = strict_json::from_slice(&output[prefix_length..]).expect("complete appended object");
    assert_eq!(decoded.get(&name), Some(&child));
    assert_eq!(decoded.as_object().expect("object").len(), 2);
    assert_eq!(serde_json::from_slice::<String>(&serde_json_canonicalizer::to_vec(&name).expect("quoted name"))
        .expect("reparsed original name"), name);
}

#[test]
fn typed_source_none_and_explicit_null_have_the_same_canonical_preimage() {
    let (bytes, _) = fixture("airtable");
    let mut absent: Value = serde_json::from_slice(bytes).expect("source fixture");
    let optional_keys = ["provider_headers", "account_scope", "bounds", "relative_ceiling",
        "observation", "echo", "pre_entry", "preconditions"];
    for key in optional_keys { absent.as_object_mut().expect("object").remove(key); }
    absent["write"].as_object_mut().expect("write").remove("idempotency");
    let mut explicit_null = absent.clone();
    for key in optional_keys { explicit_null[key] = Value::Null; }
    explicit_null["credential"]["guard"] = Value::Null;
    explicit_null["write"]["idempotency"] = Value::Null;
    let absent = serde_contract_source(&absent);
    let explicit_null = serde_contract_source(&explicit_null);
    assert_eq!(serde_json::to_value(&absent).expect("source"), serde_json::to_value(&explicit_null).expect("source"));
    assert_eq!(serde_json_canonicalizer::to_vec(&absent).expect("canonical source"),
        serde_json_canonicalizer::to_vec(&explicit_null).expect("canonical source"));
}

#[test]
fn typed_source_present_empty_collections_are_not_absent_options() {
    let (bytes, _) = fixture("airtable");
    let original: Value = serde_json::from_slice(bytes).expect("source fixture");
    for (key, empty) in [("provider_headers", json!({})), ("bounds", json!({})), ("preconditions", json!({}))] {
        let mut absent = original.clone();
        absent.as_object_mut().expect("object").remove(key);
        let mut present = absent.clone();
        present[key] = empty.clone();
        let present = serde_contract_source(&present);
        assert_eq!(serde_json::to_value(&present).expect("source").get(key), Some(&empty));
        assert_ne!(serde_json_canonicalizer::to_vec(&present).expect("canonical source"),
            serde_json_canonicalizer::to_vec(&serde_contract_source(&absent)).expect("canonical source"), "{key}");
    }
    let mut source = original;
    source["credential"]["guard"] = json!({"prefixes": [], "denied_reads": []});
    source["relative_ceiling"] = json!({"argument": "amount", "basis_points": 125,
        "path": [], "json_pointer": "/amount", "bind": [], "maximum_response_bytes": 1024});
    let encoded = serde_json::to_value(serde_contract_source(&source)).expect("source");
    assert_eq!(encoded["credential"]["guard"]["denied_reads"], json!([]));
    assert_eq!(encoded["relative_ceiling"]["bind"], json!([]));
}

#[test]
fn only_default_empty_verified_arguments_are_omitted() {
    let missing: source::PreconditionSource = strict_json::from_slice(b"{}").expect("default");
    let empty: source::PreconditionSource = strict_json::from_slice(br#"{"verified":[]}"#).expect("empty");
    assert_eq!(serde_json::to_value(missing).expect("source"), json!({}));
    assert_eq!(serde_json::to_value(empty).expect("source"), json!({}));
    serde_contract_round_trip::<source::PreconditionSource>(json!({"read_back_subject": "", "verified": ["expected"]}));
    assert!(strict_json::from_slice::<source::PreconditionSource>(br#"{"verified":null}"#).is_err());
}

#[test]
fn all_typed_body_variants_preserve_tags_children_and_scalar_values() {
    for value in [json!({"kind":"string", "value":"a\u{0}é"}),
        json!({"kind":"integer", "value":i64::MIN}), json!({"kind":"integer", "value":i64::MAX}),
        json!({"kind":"boolean", "value":false}), json!({"kind":"field", "name":"amount"}),
        json!({"kind":"object", "fields":{"z":{"kind":"echo"},"a":{"kind":"boolean","value":true}}}),
        json!({"kind":"array", "items":[{"kind":"integer","value":1},{"kind":"echo"}]}),
        json!({"kind":"echo"})] {
        serde_contract_round_trip::<source::ValueExpr>(value);
    }
    for value in [json!({"kind":"string", "value":""}), json!({"kind":"field", "name":"amount"}),
        json!({"kind":"json", "value":{"kind":"array", "items":[]}}), json!({"kind":"echo"})] {
        serde_contract_round_trip::<source::FormExpr>(value);
    }
    serde_contract_round_trip::<source::BodySource>(json!({"kind":"form", "fields":{}}));
    serde_contract_round_trip::<source::BodySource>(json!({"kind":"json", "value":{"kind":"echo"}}));
    for value in [json!({"kind":"fixed", "value":""}), json!({"kind":"field", "name":"id"}),
        json!({"kind":"response-field", "pointer":"/id", "max_bytes":u64::MAX}), json!({"kind":"echo"})] {
        serde_contract_round_trip::<source::PathSegment>(value);
    }
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        serde_contract_round_trip::<WriteMethod>(json!(method));
    }
}

#[test]
fn actual_serde_preserves_probe_numbers_before_canonical_formatting() {
    let (bytes, _) = fixture("airtable");
    let base: Value = serde_json::from_slice(bytes).expect("source fixture");
    for literal in [json!(u64::MAX), json!(i64::MIN), json!(-0.0), json!(1.5),
        json!(false), Value::Null, json!("a\u{0}é"), json!([1, false]), json!({"z":1,"a":2})] {
        let mut value = base.clone();
        value["credential"]["guard"] = json!({"prefixes":[], "probe":{
            "path":[], "json_pointer":"", "equals":literal.clone(), "maximum_response_bytes":1}});
        let encoded = serde_json::to_value(serde_contract_source(&value)).expect("source");
        let actual = &encoded["credential"]["guard"]["probe"]["equals"];
        assert_eq!(actual, &literal);
        if literal.is_f64() {
            assert_eq!(actual.as_f64().map(f64::to_bits), literal.as_f64().map(f64::to_bits));
        }
    }
}

#[test]
fn complete_typed_source_keeps_every_present_field_before_admission() {
    let (bytes, _) = fixture("airtable");
    let mut value: Value = serde_json::from_slice(bytes).expect("source fixture");
    value["provider_headers"] = json!({"X-Example":"value"});
    value["account_scope"] = json!({"header":"X-Account","field":"account"});
    value["bounds"] = json!({"sum":{"argument":"amount","partition":"account"}});
    value["relative_ceiling"] = json!({"argument":"amount","basis_points":125,
        "path":[{"kind":"fixed","value":"balance"}],"json_pointer":"/available",
        "subtract_pointer":"/reserved","bind":[{"pointer":"/id","field":"account"}],"maximum_response_bytes":1024});
    value["credential"] = json!({"kind":"header-api-key","header":"X-Example-Key","guard":{
        "prefixes":["example_"],"probe":{"path":[],"json_pointer":"/active","equals":true,"maximum_response_bytes":1024},
        "account":{"path":[],"json_pointer":"/account","maximum_response_bytes":2048},
        "denied_reads":[{"method":"GET","path":[{"kind":"fixed","value":"forbidden"}],"refused_status":[401,403]}]}});
    value["write"]["body"] = json!({"kind":"form","fields":{
        "plain":{"kind":"string","value":"example"},"argument":{"kind":"field","name":"amount"},
        "nested":{"kind":"json","value":{"kind":"array","items":[{"kind":"boolean","value":false}]}}}});
    value["write"]["idempotency"] = json!({"kind":"operation-id-field","location":{
        "json_pointer":"/operation","form_field":"operation","pointer":"/operation"},"retention_seconds":60});
    value["echo"] = json!({"write":{"kind":"form-field","name":"echo"},"observe":"/echo"});
    value["pre_entry"] = json!({"path":[],"pointers":["/id","/version"],"maximum_response_bytes":4096});
    value["preconditions"] = json!({"read_back_subject":"id","verified":["expected","version"]});
    // This deliberately exercises the full typed language, including mutually
    // conflicting declarations. It grants no compiler/recipe admission.
    serde_contract_round_trip::<RecipeSource>(value);
    serde_contract_round_trip::<source::IdempotencySource>(json!({"kind":"derived-header","retention_seconds":60}));
    serde_contract_round_trip::<source::EchoPlacement>(json!({"kind":"json-pointer","pointer":"/echo"}));
}

#[test]
fn actual_canonicalizer_uses_utf16_key_order_instead_of_utf8_order() {
    let value = json!({"\u{e000}":1,"\u{10000}":2});
    assert!("\u{e000}".as_bytes() < "\u{10000}".as_bytes());
    assert_eq!(serde_json_canonicalizer::to_vec(&value).expect("canonical JSON"),
        "{\"\u{10000}\":2,\"\u{e000}\":1}".as_bytes());
}

#[test]
fn native_body_map_keeps_scalar_key_order_and_all_payloads_across_utf8_widths() {
    let keys = ["", "\u{0}", "\u{1}", "a", "a\u{0}", "ab", "e\u{301}", "é",
        "\u{7f}", "\u{80}", "\u{7ff}", "\u{800}", "\u{d7ff}", "\u{e000}",
        "\u{ffff}", "\u{10000}", "\u{10ffff}"];
    let mut members = Map::new();
    for (index, key) in keys.iter().enumerate().rev() {
        members.insert((*key).to_owned(), json!({"kind":"integer","value":index}));
    }
    let bytes = serde_json::to_vec(&json!({"kind":"object","fields":members})).expect("source AST");
    let parsed: source::ValueExpr = strict_json::from_slice(&bytes).expect("typed source AST");
    let source::ValueExpr::Object { fields } = parsed else { panic!("object source AST") };
    let mut expected = keys.map(str::to_owned).to_vec();
    // Independent scalar iteration is the order used by the Lean String
    // model; the native BTreeMap uses Rust String's UTF-8 comparison.
    expected.sort_by(|left, right| left.chars().cmp(right.chars()));
    assert_eq!(fields.keys().cloned().collect::<Vec<_>>(), expected);
    assert_eq!(fields.len(), keys.len(), "no empty/NUL/Unicode name is collapsed");
    for (index, key) in keys.iter().enumerate() {
        assert!(matches!(fields.get(*key), Some(source::ValueExpr::Integer { value })
            if *value == i64::try_from(index).expect("small corpus index")), "{key:?}");
    }
}

#[test]
fn canonical_integer_rounding_aliases_remain_outside_source_admission() {
    let (raw_source, lock) = fixture("airtable");
    let original: Value = serde_json::from_slice(raw_source).expect("source fixture");
    let mut first = original.clone();
    let mut second = original;
    first["write"]["body"] = json!({"kind":"json","value":{"kind":"integer","value":9007199254740992_i64}});
    second["write"]["body"] = json!({"kind":"json","value":{"kind":"integer","value":9007199254740993_i64}});
    let first_typed = serde_contract_source(&first);
    let second_typed = serde_contract_source(&second);
    assert_ne!(serde_json::to_value(&first_typed).expect("source"), serde_json::to_value(&second_typed).expect("source"));
    assert_eq!(serde_json_canonicalizer::to_vec(&first_typed).expect("canonical source"),
        serde_json_canonicalizer::to_vec(&second_typed).expect("canonical source"),
        "JCS converts both integers to the same binary64 value before formatting");
    for source in [first, second] {
        assert_eq!(CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source"), lock).err(),
            Some(GatewayRecipeError::UnsafeTemplate));
    }
    assert_eq!(serde_json_canonicalizer::to_vec(&9007199254740993_u64).expect("canonical integer"), b"9007199254740992");
}

#[test]
fn probe_numeric_admission_keeps_safe_endpoints_and_refuses_jcs_aliases_and_float_kinds() {
    let (source, lock) = fixture("airtable");
    let mut base: Value = serde_json::from_slice(source).expect("source fixture");
    base["credential"]["guard"] = json!({"prefixes":["fixture_"],"probe":{
        "path":[{"kind":"fixed","value":"credential-check"}],"json_pointer":"/active",
        "equals":0,"maximum_response_bytes":65536}});
    for literal in [json!(-9_007_199_254_740_991_i64), json!(0), json!(9_007_199_254_740_991_u64)] {
        let mut value = base.clone();
        value["credential"]["guard"]["probe"]["equals"] = literal;
        CompiledRecipe::compile(&serde_json::to_vec(&value).expect("source"), lock).expect("safe probe number");
    }
    let mut aliases = Vec::new();
    for literal in [json!(9_007_199_254_740_992_u64), json!(9_007_199_254_740_993_u64)] {
        let mut value = base.clone();
        value["credential"]["guard"]["probe"]["equals"] = literal;
        aliases.push(serde_json_canonicalizer::to_vec(&serde_contract_source(&value)).expect("canonical typed source"));
        assert_eq!(CompiledRecipe::compile(&serde_json::to_vec(&value).expect("source"), lock).err(),
            Some(GatewayRecipeError::InvalidCredentialGuard));
    }
    assert_eq!(aliases[0], aliases[1], "unsafe probe integers can alias before admission");
    for literal in [json!(1.0), json!(-0.0), json!(1.5), json!(u64::MAX), json!(i64::MIN)] {
        let mut value = base.clone();
        value["credential"]["guard"]["probe"]["equals"] = literal;
        assert_eq!(CompiledRecipe::compile(&serde_json::to_vec(&value).expect("source"), lock).err(),
            Some(GatewayRecipeError::InvalidCredentialGuard));
    }
}

#[test]
fn closed_schema_numeric_admission_refuses_unsafe_or_float_bounds_and_extra_annotations() {
    for source in [json!({"kind":"integer","minimum":-9_007_199_254_740_991_i64,"maximum":9_007_199_254_740_991_u64}),
        json!({"kind":"integer","minimum":0,"maximum":0}),
        json!({"kind":"string","minimum":0,"maximum":4096})] {
        assert!(parse_field_schema(&source).is_ok(), "safe closed schema {source}");
    }
    for source in [json!({"kind":"integer","minimum":0,"maximum":9_007_199_254_740_992_u64}),
        json!({"kind":"integer","minimum":0,"maximum":9_007_199_254_740_993_u64}),
        json!({"kind":"integer","minimum":-9_007_199_254_740_992_i64,"maximum":0}),
        json!({"kind":"integer","minimum":0.0,"maximum":1}),
        json!({"kind":"integer","minimum":0,"maximum":1.0}),
        json!({"kind":"string","minimum":0,"maximum":4097}),
        json!({"kind":"string","minimum":0.0,"maximum":1}),
        json!({"kind":"boolean","annotation":9_007_199_254_740_993_u64})] {
        assert!(parse_field_schema(&source).is_err(), "no unsafe/erased schema annotation {source}");
    }
}

// Inspect every original numeric leaf before canonicalization. Comparing only
// the reparsed JCS result could miss the very integer aliases being excluded.
fn assert_full_json_safe_integer_numbers(value: &Value) {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Number(number) => {
                let safe = number
                    .as_i64()
                    .map(|integer| integer.unsigned_abs() <= 9_007_199_254_740_991)
                    .or_else(|| number.as_u64().map(|integer| integer <= 9_007_199_254_740_991))
                    .unwrap_or(false);
                assert!(safe, "original number must be a safe integer: {number}");
            }
            Value::Array(values) => pending.extend(values.iter()),
            Value::Object(members) => pending.extend(members.values()),
            Value::Null | Value::Bool(_) | Value::String(_) => {}
        }
    }
}

fn assert_admitted_source_numeric_serialization(recipe: &CompiledRecipe) {
    let original = serde_json::to_value(&recipe.source).expect("complete admitted typed source");
    assert_full_json_safe_integer_numbers(&original);
    let canonical = serde_json_canonicalizer::to_vec(&recipe.source).expect("complete canonical source");
    let reparsed: Value = strict_json::from_slice(&canonical).expect("complete unique canonical source");
    assert_eq!(reparsed, original, "all original numeric leaves survive canonicalization");
}

#[test]
fn successful_public_compile_keeps_all_source_and_schema_numbers_exact() {
    for name in ["airtable", "todoist", "github"] {
        assert_admitted_source_numeric_serialization(&compiled(name));
        let (_, raw_lock) = fixture(name);
        let lock: ProfileLockFile = strict_json::from_slice(raw_lock).expect("complete lock fixture");
        assert_full_json_safe_integer_numbers(&lock.command_schema);
    }
    let corpus = corpus();
    for (name, base) in corpus["bases"].as_object().expect("valid corpus bases") {
        let recipe = serde_json::to_vec(&base["recipe"]).expect("complete corpus source");
        let lock = serde_json::to_vec(&base["lock"]).expect("complete corpus lock");
        let admitted = CompiledRecipe::compile(&recipe, &lock).expect(name);
        assert_admitted_source_numeric_serialization(&admitted);
        assert_full_json_safe_integer_numbers(&base["lock"]["command_schema"]);
    }
}

#[test]
fn safe_integer_formatter_bytes_match_exact_plain_decimal_across_decimal_and_binary_boundaries() {
    fn compare_unsigned(value: u64) {
        let expected = value.to_string().into_bytes();
        let actual = serde_json_canonicalizer::to_vec(&value).expect("canonical unsigned integer");
        assert_eq!(actual, expected, "safe unsigned integer {value}");
        assert_eq!(strict_json::from_slice::<u64>(&actual).expect("same integer"), value);
        assert!(actual.len() <= 16);
        assert!(actual.iter().all(u8::is_ascii_digit));
    }
    fn compare_signed(value: i64) {
        let expected = value.to_string().into_bytes();
        let actual = serde_json_canonicalizer::to_vec(&value).expect("canonical signed integer");
        assert_eq!(actual, expected, "safe signed integer {value}");
        assert_eq!(strict_json::from_slice::<i64>(&actual).expect("same integer"), value);
        assert!(actual.len() <= 17);
        assert!(!actual.contains(&b'.') && !actual.contains(&b'e') && !actual.contains(&b'E'));
    }
    for value in [0_u64, 1, 9, 10, 99, 100, 999_999, 1_000_000, 9_007_199_254_740_990, 9_007_199_254_740_991] {
        compare_unsigned(value);
        let signed = i64::try_from(value).expect("safe integer fits i64");
        compare_signed(signed);
        compare_signed(-signed);
    }
    for power in 0..=52 {
        let center = 1_u64 << power;
        for value in [center.saturating_sub(1), center, center + 1] {
            compare_unsigned(value);
            let signed = i64::try_from(value).expect("safe integer fits i64");
            compare_signed(signed);
            compare_signed(-signed);
        }
    }
    for power in 0..=15 {
        let center = 10_u64.pow(power);
        for value in [center.saturating_sub(1), center, center + 1] {
            compare_unsigned(value);
            let signed = i64::try_from(value).expect("safe integer fits i64");
            compare_signed(signed);
            compare_signed(-signed);
        }
    }
    assert_eq!(serde_json_canonicalizer::to_vec(&0_i64).expect("zero"), b"0");
    assert_eq!(serde_json_canonicalizer::to_vec(&-9_007_199_254_740_991_i64).expect("negative endpoint"), b"-9007199254740991");
    assert_eq!(serde_json_canonicalizer::to_vec(&9_007_199_254_740_991_u64).expect("positive endpoint"), b"9007199254740991");
}

// Test-only complete reference for already-unique JSON trees in the earned
// safe-integer domain. No expected child bytes come from the canonicalizer.
// Raw duplicate detection remains covered at the strict public byte boundary.
fn reference_admitted_tree_bytes(value: &Value) -> Vec<u8> {
    fn quoted(text: &str, output: &mut Vec<u8>) {
        output.push(b'"');
        for character in text.chars() {
            match character {
                '"' => output.extend_from_slice(b"\\\""),
                '\\' => output.extend_from_slice(b"\\\\"),
                '\u{8}' => output.extend_from_slice(b"\\b"),
                '\t' => output.extend_from_slice(b"\\t"),
                '\n' => output.extend_from_slice(b"\\n"),
                '\u{c}' => output.extend_from_slice(b"\\f"),
                '\r' => output.extend_from_slice(b"\\r"),
                control if control < '\u{20}' => {
                    let control = u8::try_from(u32::from(control)).expect("control byte");
                    let digits = b"0123456789abcdef";
                    output.extend_from_slice(b"\\u00");
                    output.push(digits[usize::from(control / 16)]);
                    output.push(digits[usize::from(control % 16)]);
                }
                original => {
                    let mut buffer = [0_u8; 4];
                    output.extend_from_slice(original.encode_utf8(&mut buffer).as_bytes());
                }
            }
        }
        output.push(b'"');
    }
    fn emit(value: &Value, output: &mut Vec<u8>) {
        match value {
            Value::Null => output.extend_from_slice(b"null"),
            Value::Bool(true) => output.extend_from_slice(b"true"),
            Value::Bool(false) => output.extend_from_slice(b"false"),
            Value::Number(number) => {
                if let Some(integer) = number.as_i64() {
                    assert!(integer.unsigned_abs() <= 9_007_199_254_740_991);
                    output.extend_from_slice(integer.to_string().as_bytes());
                } else {
                    let integer = number.as_u64().expect("reference excludes float kinds");
                    assert!(integer <= 9_007_199_254_740_991);
                    output.extend_from_slice(integer.to_string().as_bytes());
                }
            }
            Value::String(text) => quoted(text, output),
            Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    emit(value, output);
                }
                output.push(b']');
            }
            Value::Object(members) => {
                let mut original = members.iter().collect::<Vec<_>>();
                original.sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
                output.push(b'{');
                for (index, (name, value)) in original.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    quoted(name, output);
                    output.push(b':');
                    emit(value, output);
                }
                output.push(b'}');
            }
        }
    }
    let mut output = Vec::new();
    emit(value, &mut output);
    output
}

fn admitted_tree_values() -> impl proptest::strategy::Strategy<Value = Value> {
    use proptest::prelude::*;
    let text = proptest::collection::vec(any::<char>(), 0..24)
        .prop_map(|characters| characters.into_iter().collect::<String>());
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-9_007_199_254_740_991_i64..=9_007_199_254_740_991).prop_map(|integer| json!(integer)),
        (0_u64..=9_007_199_254_740_991).prop_map(|integer| json!(integer)),
        text.clone().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 64, 8, move |child| {
        prop_oneof![
            proptest::collection::vec(child.clone(), 0..8).prop_map(Value::Array),
            proptest::collection::vec((text.clone(), child), 0..8)
                .prop_map(|members| Value::Object(members.into_iter().collect())),
        ]
    })
}

// Logical output envelope from every original node/key/value byte. This is
// deliberately separate from allocator capacity, recursion and parser work.
fn reference_admitted_tree_size_bound(value: &Value) -> usize {
    match value {
        Value::Null => 4,
        Value::Bool(_) => 5,
        Value::Number(_) => 17,
        Value::String(text) => 6 * text.len() + 2,
        Value::Array(values) => 2 + values.iter().map(|value| reference_admitted_tree_size_bound(value) + 1).sum::<usize>(),
        Value::Object(members) => 2 + members.iter().map(|(name, value)| {
            6 * name.len() + reference_admitted_tree_size_bound(value) + 4
        }).sum::<usize>(),
    }
}

#[test]
fn complete_tree_size_envelope_covers_control_expansion_and_all_nested_children() {
    let controls = "\0".repeat(4096);
    let scalar = Value::String(controls.clone());
    let bytes = serde_json_canonicalizer::to_vec(&scalar).expect("complete control string");
    assert_eq!(bytes.len(), 6 * controls.len() + 2);
    assert_eq!(bytes.len(), reference_admitted_tree_size_bound(&scalar));
    let mut members = serde_json::Map::new();
    members.insert(controls.clone(), json!([controls.clone(),
        {"nested":[-9_007_199_254_740_991_i64,9_007_199_254_740_991_u64,false,null,{},[]]}]));
    members.insert("é😀\"\\\n".into(), json!(["é😀", "\0", true]));
    let original = Value::Object(members);
    let bytes = serde_json_canonicalizer::to_vec(&original).expect("all nested children");
    assert_eq!(bytes, reference_admitted_tree_bytes(&original));
    assert!(bytes.len() <= reference_admitted_tree_size_bound(&original));
    let prefix = vec![0_u8; 1024];
    let mut output = prefix.clone();
    serde_json_canonicalizer::to_writer(&original, &mut output).expect("append bounded tree");
    assert!(output.len() <= prefix.len() + reference_admitted_tree_size_bound(&original));
    assert_eq!(&output[..prefix.len()], prefix.as_slice());
    assert_eq!(&output[prefix.len()..], bytes.as_slice());
}

#[test]
fn raw_json_number_syntax_is_distinct_from_native_numeric_kind_and_finite_range() {
    for text in ["0", "-0", "123", "-123", "0.0", "-0.0", "1.0", "1e0", "1E+02", "-1.25e-02",
        "18446744073709551615", "-9223372036854775808", "9007199254740993"] {
        let parsed: Value = strict_json::from_slice(text.as_bytes()).expect("complete valid number syntax and native range");
        assert!(parsed.is_number(), "{text}");
    }
    for text in ["", "-", "+1", "01", "-01", ".1", "-.1", "1.", "1e", "1E+", "1e-", "1ee0",
        "--1", "0x10", "NaN", "Infinity", "1 2", "1x", "１", "\u{a0}1"] {
        assert!(strict_json::from_slice::<Value>(text.as_bytes()).is_err(), "complete number document refuses {text:?}");
    }
    let integer: Value = strict_json::from_slice(b"0").expect("integer zero");
    assert_eq!(integer.as_i64(), Some(0));
    for text in ["-0", "-0.0", "-0e0"] {
        let parsed: Value = strict_json::from_slice(text.as_bytes()).expect("negative zero syntax");
        assert!(parsed.as_number().expect("number").is_f64());
        assert_eq!(parsed.as_f64().expect("floating negative zero").to_bits(), (-0.0_f64).to_bits());
    }
    for text in ["1.0", "1e0", "1E+00"] {
        let parsed: Value = strict_json::from_slice(text.as_bytes()).expect("float syntax");
        assert!(parsed.as_number().expect("number").is_f64());
        assert_eq!(serde_json_canonicalizer::to_vec(&parsed).expect("canonical normalization"), b"1");
    }
    // These have valid JSON-number lexical forms, but a full native Value
    // parse refuses overflow. Lexical success must not promise native success.
    for text in ["1e309", "-1E+309", "9.99e99999"] {
        assert!(strict_json::from_slice::<Value>(text.as_bytes()).is_err());
    }
}

#[derive(Debug, PartialEq)]
enum ObservedNumericDispatch {
    Unsigned(u64),
    Signed(i64),
    Floating(u64),
}

// Test-only visitor observes ParserNumber::visit directly. Value::as_i64 and
// is_i64 also report convertible positive u64 values and cannot identify which
// numeric visitor method actually ran. No production callback is introduced.
impl<'de> serde::Deserialize<'de> for ObservedNumericDispatch {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct NumericVisitor;
        impl<'de> serde::de::Visitor<'de> for NumericVisitor {
            type Value = ObservedNumericDispatch;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a native JSON numeric dispatch")
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(ObservedNumericDispatch::Unsigned(value))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(ObservedNumericDispatch::Signed(value))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
                Ok(ObservedNumericDispatch::Floating(value.to_bits()))
            }
        }
        deserializer.deserialize_any(NumericVisitor)
    }
}

#[test]
fn raw_number_word_limits_and_negative_zero_choose_the_actual_native_visitor_kind() {
    for value in [0_u64, 1, 9_007_199_254_740_993, 9_223_372_036_854_775_807,
        9_223_372_036_854_775_808, u64::MAX] {
        let text = value.to_string();
        assert_eq!(serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("native u64 dispatch"),
            ObservedNumericDispatch::Unsigned(value));
    }
    for value in [-1_i64, -9_007_199_254_740_993, i64::MIN] {
        let text = value.to_string();
        assert_eq!(serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("native i64 dispatch"),
            ObservedNumericDispatch::Signed(value));
    }
    for text in ["-0", "-0.0", "-0e0"] {
        assert_eq!(serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("native negative-zero dispatch"),
            ObservedNumericDispatch::Floating((-0.0_f64).to_bits()));
    }
    for text in ["18446744073709551616", "-9223372036854775809", "1.0", "1e0", "1E+02"] {
        assert!(matches!(serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("native floating dispatch"),
            ObservedNumericDispatch::Floating(_)), "{text}");
    }
    assert!(serde_json::from_slice::<ObservedNumericDispatch>(b"1e309").is_err(),
        "a floating conversion path does not promise a finite numeric result");
}

#[allow(clippy::cast_precision_loss, reason = "test observes serde's explicit original u64-to-f64 fallback cast")]
fn original_unsigned_negative_float_bits(original: u64) -> u64 {
    (-(original as f64)).to_bits()
}

#[test]
fn original_signed_word_cast_wrapping_and_floating_fallback_preserve_the_correct_magnitude() {
    let word = 1_i128 << 64;
    let half = 1_i128 << 63;
    for original in [0_u64, 1, 9_223_372_036_854_775_807, 9_223_372_036_854_775_808,
        9_223_372_036_854_775_809, u64::MAX] {
        // Same bit interpretation as the source cast, through an independent
        // endian-explicit byte API, compared against wider exact arithmetic.
        let cast = i64::from_le_bytes(original.to_le_bytes());
        let exact_cast = if i128::from(original) < half { i128::from(original) } else { i128::from(original) - word };
        assert_eq!(i128::from(cast), exact_cast);
        let exact_negative = -exact_cast;
        let exact_wrapped = if half <= exact_negative { exact_negative - word } else { exact_negative };
        let wrapped = cast.wrapping_neg();
        assert_eq!(i128::from(wrapped), exact_wrapped);
        assert_eq!(wrapped < 0, original > 0 && original <= 9_223_372_036_854_775_808);
        let text = format!("-{original}");
        let parsed = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("original negative word dispatch");
        if wrapped < 0 {
            assert_eq!(i128::from(wrapped), -i128::from(original));
            assert_eq!(parsed, ObservedNumericDispatch::Signed(wrapped));
        } else {
            let expected = original_unsigned_negative_float_bits(original);
            assert_eq!(parsed, ObservedNumericDispatch::Floating(expected));
            assert!(f64::from_bits(expected).is_finite());
            assert_ne!(expected & (1_u64 << 63), 0, "negative-zero/underflow fallback keeps the negative sign");
        }
    }
}

fn source_unsigned_digit_overflows(value: u64, digit: u64) -> bool {
    value >= u64::MAX / 10 && (value > u64::MAX / 10 || digit > u64::MAX % 10)
}

#[test]
fn original_unsigned_digit_overflow_threshold_matches_checked_updates_and_native_dispatch() {
    for value in [0_u64, 1, u64::MAX / 10 - 1, u64::MAX / 10, u64::MAX / 10 + 1, u64::MAX] {
        for digit in 0_u64..=9 {
            let overflow = source_unsigned_digit_overflows(value, digit);
            let checked = value.checked_mul(10).and_then(|prefix| prefix.checked_add(digit));
            assert_eq!(overflow, checked.is_none());
            if value > 0 {
                let text = format!("{value}{digit}");
                let parsed = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("finite original integer token");
                match checked {
                    Some(word) => assert_eq!(parsed, ObservedNumericDispatch::Unsigned(word)),
                    None => assert!(matches!(parsed, ObservedNumericDispatch::Floating(_))),
                }
            }
        }
    }
    assert!(!source_unsigned_digit_overflows(1_844_674_407_370_955_161, 5));
    assert!(source_unsigned_digit_overflows(1_844_674_407_370_955_161, 6));
}

#[test]
fn initial_integer_and_continuation_refusals_keep_the_native_error_categories_and_peek_position() {
    for text in ["", "-", "0.", "1e", "1e+"] {
        let error = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect_err("incomplete numeric document");
        assert!(error.is_eof(), "{text:?}: {error}");
    }
    for text in ["00", "01", "-01", "-a", "+1", "1e+x"] {
        let error = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect_err("invalid numeric syntax");
        assert!(error.is_syntax(), "{text:?}: {error}");
    }
    for negative in [false, true] {
        for digit in 0..=9 {
            let sign = if negative { "-" } else { "" };
            let text = format!("{sign}0{digit}e99999");
            let error = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect_err("leading-zero peek refuses first");
            assert!(error.is_syntax());
            assert_eq!(error.line(), 1);
            assert_eq!(error.column(), if negative { 3 } else { 2 }, "error points to the unread second digit");
        }
    }
    for text in ["0", "-0", "0.1", "-0.1", "0e0", "-0E+02", "18446744073709551616"] {
        serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("correct word/floating continuation");
    }
}

#[test]
fn decimal_stages_require_digits_and_preserve_first_digit_overflow_and_negative_zero() {
    let eof = serde_json::from_slice::<ObservedNumericDispatch>(b"0.").expect_err("fraction needs a digit");
    assert!(eof.is_eof());
    for text in ["0.e1", "1.x", "-0.E+2"] {
        let error = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect_err("no fractional digit");
        assert!(error.is_syntax());
    }
    for text in ["18446744073709551615.1", "-18446744073709551615.9", "18446744073709551615.123e-2"] {
        assert!(matches!(serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("overflowing first fraction digit is present"),
            ObservedNumericDispatch::Floating(_)));
    }
    for (text, expected) in [("0.000", 0.0_f64.to_bits()), ("-0.000e-5", (-0.0_f64).to_bits())] {
        assert_eq!(serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("fraction zero kind/sign"),
            ObservedNumericDispatch::Floating(expected));
    }
    for negative in [false, true] {
        let sign = if negative { "-" } else { "" };
        let text = format!("{sign}0.{}1", "0".repeat(4096));
        let expected = if negative { (-0.0_f64).to_bits() } else { 0.0_f64.to_bits() };
        assert_eq!(serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("bounded long fractional underflow"),
            ObservedNumericDispatch::Floating(expected));
    }
}

// Pinned serde exponent arithmetic. Independent checked operations below are
// the oracle; native dispatch/error columns exercise the public parser path.
fn source_exponent_digit_overflows(value: i32, digit: u8) -> bool {
    assert!(value >= 0 && digit <= 9);
    value >= i32::MAX / 10 && (value > i32::MAX / 10 || i32::from(digit) > i32::MAX % 10)
}

#[test]
fn exponent_stages_keep_first_digit_errors_consumed_overflow_trigger_and_signed_zero() {
    for (value, digit) in [(0_i32, 9_u8), (214_748_364, 7), (214_748_364, 8), (214_748_365, 0), (i32::MAX, 9)] {
        let checked = value.checked_mul(10).and_then(|product| product.checked_add(i32::from(digit)));
        assert_eq!(source_exponent_digit_overflows(value, digit), checked.is_none());
    }
    for (text, column) in [("1e", 2), ("1e+", 3), ("1e-", 3), ("-1e-", 4)] {
        let error = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect_err("mandatory exponent digit");
        assert!(error.is_eof(), "{text:?}: {error}");
        assert_eq!((error.line(), error.column()), (1, column));
    }
    for (text, column) in [("1e]", 3), ("1e+]", 4), ("-1e-]", 5), ("1e+x2", 4)] {
        let error = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect_err("invalid first exponent digit consumed");
        assert!(error.is_syntax(), "{text:?}: {error}");
        assert_eq!((error.line(), error.column()), (1, column));
    }
    for (text, column) in [("1e21474836480", 12), ("-1e21474836480", 13),
        ("1e+21474836480000", 13), ("1e00021474836480", 15), ("0.1e21474836480", 14)] {
        let error = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect_err("positive nonzero exponent overflow");
        assert!(error.is_syntax(), "{text:?}: {error}");
        assert!(error.to_string().starts_with("number out of range"), "{text:?}: {error}");
        assert_eq!((error.line(), error.column()), (1, column), "trigger is already consumed; remaining digits are not");
    }
    for text in ["0e21474836480", "0e+214748364800000", "1e-214748364800000", "0.0e21474836480",
        "0e2147483647", "1e-2147483647", "0.01e-2147483647"] {
        for negative in [false, true] {
            let sign = if negative { "-" } else { "" };
            let whole = format!("{sign}{text}");
            let expected = if negative { (-0.0_f64).to_bits() } else { 0.0_f64.to_bits() };
            assert_eq!(serde_json::from_slice::<ObservedNumericDispatch>(whole.as_bytes()).expect("zero branch retains numeric sign"),
                ObservedNumericDispatch::Floating(expected));
            let with_end = format!("{whole}]");
            let mut deserializer = serde_json::Deserializer::from_slice(with_end.as_bytes());
            let parsed = <ObservedNumericDispatch as serde::Deserialize>::deserialize(&mut deserializer).expect("prefix stops at delimiter");
            assert_eq!(parsed, ObservedNumericDispatch::Floating(expected));
            let trailing = deserializer.end().expect_err("delimiter remains outside numeric prefix");
            assert!(trailing.is_syntax());
            assert_eq!((trailing.line(), trailing.column()), (1, whole.len() + 1));
        }
    }
}

#[test]
fn long_number_scratch_paths_preserve_decimal_position_and_exact_power_of_two() {
    for (suffix, eof, column) in [(".", true, 21), (".e0", false, 22), (".]", false, 22)] {
        let text = format!("18446744073709551616{suffix}");
        let error = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect_err("long fraction requires a digit");
        assert_eq!(error.is_eof(), eof);
        assert_eq!((error.line(), error.column()), (1, column));
    }
    // 2^64 is exactly representable. These whole-source cases exercise native
    // scratch preparation without assuming a result for arbitrary decimals.
    for zeroes in [0_usize, 1, 19, 20, 64, 1024, 4096] {
        for negative in [false, true] {
            let sign = if negative { "-" } else { "" };
            let bits = 0x43f0_0000_0000_0000_u64 | (u64::from(negative) << 63);
            for text in [
                format!("{sign}18446744073709551616{}e-{zeroes}", "0".repeat(zeroes)),
                format!("{sign}0.{}18446744073709551616e+{}", "0".repeat(zeroes), zeroes + 20),
                format!("{sign}0.{}184467440737095516160000e+{}", "0".repeat(zeroes), zeroes + 20),
            ] {
                assert_eq!(serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("exact long integer/fraction scaling"),
                    ObservedNumericDispatch::Floating(bits));
            }
        }
    }
}

#[test]
fn long_exponent_checks_original_nonzero_digits_even_when_the_unscaled_fraction_underflows() {
    for zeroes in [350_usize, 400, 1024] {
        for negative in [false, true] {
            let sign = if negative { "-" } else { "" };
            let original = format!("{sign}0.{}18446744073709551616", "0".repeat(zeroes));
            let zero_bits = if negative { (-0.0_f64).to_bits() } else { 0.0_f64.to_bits() };
            assert_eq!(serde_json::from_slice::<ObservedNumericDispatch>(original.as_bytes()).expect("tiny finite long fraction"),
                ObservedNumericDispatch::Floating(zero_bits));
            let positive_exponent = format!("{original}e+21474836480000]");
            let error = serde_json::from_slice::<ObservedNumericDispatch>(positive_exponent.as_bytes()).expect_err("original digits are nonzero");
            assert!(error.is_syntax());
            assert!(error.to_string().starts_with("number out of range"));
            assert_eq!((error.line(), error.column()), (1, original.len() + 12), "consumed overflow trigger, later digits unread");
            let negative_exponent = format!("{original}E-21474836480000]");
            let mut deserializer = serde_json::Deserializer::from_slice(negative_exponent.as_bytes());
            let parsed = <ObservedNumericDispatch as serde::Deserialize>::deserialize(&mut deserializer).expect("huge negative exponent");
            assert_eq!(parsed, ObservedNumericDispatch::Floating(zero_bits));
            let trailing = deserializer.end().expect_err("entire exponent suffix consumed before delimiter");
            assert_eq!((trailing.line(), trailing.column()), (1, negative_exponent.len()));
        }
    }
}

#[test]
fn full_original_json_preflight_visits_ignored_unit_content_and_all_nested_children() {
    let original = br#" {"array":[null,true,false,-0,1.25E+02,{"a":"\u0061","unicode":"\ud83d\ude00"}],"object":{}} "#;
    let parsed: Value = strict_json::from_slice(original).expect("complete original nested document");
    assert_eq!(parsed["array"][5]["a"], json!("a"));
    assert_eq!(parsed["array"][5]["unicode"], json!("😀"));
    for document in [
        r#"{"array":[null,{"a":1,"\u0061":2}]}"#,
        r#"{"kind":"echo","ignored":{"a":1,"\u0061":2}}"#,
        r#"{"nested":[{"":"first","":"last"}]}"#,
        r#"{"a":1,}"#,
        r#"[null,true,]"#,
        r#"{"a" 1}"#,
        r#"[null true]"#,
        r#"{"a":1} []"#,
        r#"{"a":"\ud800"}"#,
    ] {
        assert!(strict_json::from_slice::<Value>(document.as_bytes()).is_err(), "{document}");
    }
    let (raw_source, lock) = fixture("airtable");
    let mut source: Value = serde_json::from_slice(raw_source).expect("source fixture");
    source["write"]["body"] = json!({"kind":"json","value":{"kind":"echo","ignored":{"auths_dup_marker":null}}});
    let bytes = serde_json::to_string(&source).expect("complete source");
    let repeated = bytes.replacen("\"auths_dup_marker\":null", "\"a\":1,\"\\u0061\":2", 1);
    assert_ne!(repeated, bytes, "duplicate introduced inside ignored unit content");
    serde_json::from_slice::<RecipeSource>(repeated.as_bytes()).expect("typed unit visitor ignores its content");
    assert!(strict_json::from_slice::<RecipeSource>(repeated.as_bytes()).is_err());
    assert_eq!(CompiledRecipe::compile(repeated.as_bytes(), lock).err(), Some(GatewayRecipeError::InvalidSource));
}

#[test]
fn recipe_preflight_refuses_out_of_range_numbers_inside_ignored_nested_unit_content() {
    let (raw_source, lock) = fixture("airtable");
    let mut source: Value = serde_json::from_slice(raw_source).expect("source fixture");
    source["write"]["body"] = json!({"kind":"json","value":{"kind":"echo","ignored":{"auths_numeric_marker":null}}});
    let original = serde_json::to_string(&source).expect("complete original source");
    strict_json::from_slice::<RecipeSource>(original.as_bytes()).expect("typed counterpart with finite unit content");
    for number in ["1e309".to_owned(), "1e21474836480".to_owned(),
        format!("0.{}18446744073709551616e+21474836480", "0".repeat(400))] {
        let nested = format!("\"deep\":[{{\"nested\":{number}}}]");
        let poisoned = original.replacen("\"auths_numeric_marker\":null", &nested, 1);
        assert_ne!(poisoned, original, "numeric failure is inside original source bytes");
        assert!(strict_json::from_slice::<RecipeSource>(poisoned.as_bytes()).is_err());
        assert_eq!(CompiledRecipe::compile(poisoned.as_bytes(), lock).err(), Some(GatewayRecipeError::InvalidSource));
    }
}

#[test]
fn full_nested_tree_canonicalization_matches_independent_original_child_reference() {
    fn compare_recipe(recipe: &CompiledRecipe) {
        let original = serde_json::to_value(&recipe.source).expect("complete original typed source");
        let expected = reference_admitted_tree_bytes(&original);
        assert!(expected.len() <= reference_admitted_tree_size_bound(&original));
        assert_eq!(serde_json_canonicalizer::to_vec(&recipe.source).expect("typed source JCS"), expected);
        // Independent declared domain and complete reference bytes, rather
        // than reusing the production preimage helper or JCS child outputs.
        let mut commitment = Sha256::new();
        commitment.update(b"auths.gateway-compiled-recipe/2\0");
        commitment.update(&expected);
        let expected_digest: [u8; 32] = commitment.finalize().into();
        assert_eq!(recipe.digest(), &expected_digest);
    }
    let nested = json!({
        "outer":[{},[],null,true,false,{"inside":[-9_007_199_254_740_991_i64,9_007_199_254_740_991_u64,
            {"\u{10000}":"😀\n\0","\u{e000}":"\"\\","":""}]}],
        "control_keys":{"\n":[],"\"":{},"\\":[0],"a":false},
        "unicode":{"\u{d7ff}":1,"\u{e000}":2,"\u{ffff}":3,"\u{10000}":4,"\u{10ffff}":5}
    });
    let expected = reference_admitted_tree_bytes(&nested);
    let actual = serde_json_canonicalizer::to_vec(&nested).expect("full nested canonical value");
    assert_eq!(actual, expected);
    assert_eq!(strict_json::from_slice::<Value>(&actual).expect("complete original value"), nested);
    for name in ["airtable", "todoist", "github"] {
        let recipe = compiled(name);
        compare_recipe(&recipe);
        let (_, lock) = fixture(name);
        let lock: ProfileLockFile = strict_json::from_slice(lock).expect("original lock");
        assert_eq!(serde_json_canonicalizer::to_vec(&lock.command_schema).expect("full schema JCS"),
            reference_admitted_tree_bytes(&lock.command_schema));
    }
    let corpus = corpus();
    for (name, base) in corpus["bases"].as_object().expect("valid corpus bases") {
        let recipe = serde_json::to_vec(&base["recipe"]).expect("complete original corpus source");
        let lock = serde_json::to_vec(&base["lock"]).expect("complete original corpus lock");
        compare_recipe(&CompiledRecipe::compile(&recipe, &lock).expect(name));
        let schema = &base["lock"]["command_schema"];
        assert_eq!(serde_json_canonicalizer::to_vec(schema).expect("complete corpus schema"), reference_admitted_tree_bytes(schema));
    }
}

proptest::proptest! {
    #[test]
    fn nested_original_numeric_range_failure_is_never_hidden_by_typed_unit_content(
        negative in proptest::arbitrary::any::<bool>(),
        zeroes in 350_usize..1025,
        exponent_suffix in proptest::collection::vec(0_u8..=9, 0..64),
        depth in 0_usize..12,
    ) {
        let (raw_source, lock) = fixture("airtable");
        let mut source: Value = serde_json::from_slice(raw_source).expect("source fixture");
        source["write"]["body"] = json!({"kind":"json","value":{"kind":"echo","ignored":{"auths_numeric_marker":null}}});
        let original = serde_json::to_string(&source).expect("complete original source");
        let sign = if negative { "-" } else { "" };
        let suffix = exponent_suffix.into_iter().map(|digit| char::from(b'0' + digit)).collect::<String>();
        let number = format!("{sign}0.{}18446744073709551616E+2147483648{suffix}", "0".repeat(zeroes));
        let nested = format!("\"nested\":{}{number}{}", "[".repeat(depth), "]".repeat(depth));
        let poisoned = original.replacen("\"auths_numeric_marker\":null", &nested, 1);
        proptest::prop_assert_ne!(&poisoned, &original);
        proptest::prop_assert!(strict_json::from_slice::<RecipeSource>(poisoned.as_bytes()).is_err());
        proptest::prop_assert_eq!(CompiledRecipe::compile(poisoned.as_bytes(), lock).err(), Some(GatewayRecipeError::InvalidSource));
    }

    #[test]
    fn underflowed_long_fraction_cannot_replace_original_nonzero_scratch_in_exponent_overflow(
        negative in proptest::arbitrary::any::<bool>(),
        zeroes in 350_usize..1025,
        digits in proptest::collection::vec(0_u8..=9, 0..64),
        exponent_suffix in proptest::collection::vec(0_u8..=9, 0..64),
    ) {
        let sign = if negative { "-" } else { "" };
        let digits = digits.into_iter().map(|digit| char::from(b'0' + digit)).collect::<String>();
        let exponent_suffix = exponent_suffix.into_iter().map(|digit| char::from(b'0' + digit)).collect::<String>();
        let original = format!("{sign}0.{}18446744073709551616{digits}", "0".repeat(zeroes));
        let zero_bits = if negative { (-0.0_f64).to_bits() } else { 0.0_f64.to_bits() };
        proptest::prop_assert_eq!(serde_json::from_slice::<ObservedNumericDispatch>(original.as_bytes()).expect("tiny long fraction"),
            ObservedNumericDispatch::Floating(zero_bits));
        let positive_exponent = format!("{original}E+2147483648{exponent_suffix}]");
        let error = serde_json::from_slice::<ObservedNumericDispatch>(positive_exponent.as_bytes()).expect_err("all original scratch digits matter");
        proptest::prop_assert!(error.is_syntax());
        proptest::prop_assert!(error.to_string().starts_with("number out of range"));
        proptest::prop_assert_eq!((error.line(), error.column()), (1, original.len() + 12));
        let negative_exponent = format!("{original}e-2147483648{exponent_suffix}]");
        let mut deserializer = serde_json::Deserializer::from_slice(negative_exponent.as_bytes());
        let parsed = <ObservedNumericDispatch as serde::Deserialize>::deserialize(&mut deserializer).expect("negative overflow zero branch");
        proptest::prop_assert_eq!(parsed, ObservedNumericDispatch::Floating(zero_bits));
        let trailing = deserializer.end().expect_err("all exponent digits consumed, delimiter retained");
        proptest::prop_assert_eq!((trailing.line(), trailing.column()), (1, negative_exponent.len()));
    }

    #[test]
    fn long_integer_and_fraction_scratch_keep_exact_original_decimal_scaling(
        negative in proptest::arbitrary::any::<bool>(),
        fractional in proptest::arbitrary::any::<bool>(),
        leading_zeroes in 0_usize..513,
        trailing_zeroes in 0_usize..129,
    ) {
        let sign = if negative { "-" } else { "" };
        let trailing = "0".repeat(trailing_zeroes);
        let text = if fractional {
            format!("{sign}0.{}18446744073709551616{trailing}E+{}", "0".repeat(leading_zeroes), leading_zeroes + 20)
        } else {
            format!("{sign}18446744073709551616{trailing}E-{trailing_zeroes}")
        };
        let bits = 0x43f0_0000_0000_0000_u64 | (u64::from(negative) << 63);
        let with_end = format!("{text}]");
        let mut deserializer = serde_json::Deserializer::from_slice(with_end.as_bytes());
        let parsed = <ObservedNumericDispatch as serde::Deserialize>::deserialize(&mut deserializer).expect("exact long-number scaling");
        proptest::prop_assert_eq!(parsed, ObservedNumericDispatch::Floating(bits));
        let trailing = deserializer.end().expect_err("numeric suffix ends before original delimiter");
        proptest::prop_assert!(trailing.is_syntax());
        proptest::prop_assert_eq!((trailing.line(), trailing.column()), (1, text.len() + 1));
    }

    #[test]
    fn exponent_checked_update_and_overflow_suffix_agree_with_original_native_input(
        value in 0_i32..=i32::MAX,
        digit in 0_u8..=9,
        negative in proptest::arbitrary::any::<bool>(),
        zero in proptest::arbitrary::any::<bool>(),
        positive_exponent in proptest::arbitrary::any::<bool>(),
        leading_zero_count in 0_usize..33,
        suffix in proptest::collection::vec(0_u8..=9, 0..64),
    ) {
        let checked = value.checked_mul(10).and_then(|product| product.checked_add(i32::from(digit)));
        proptest::prop_assert_eq!(source_exponent_digit_overflows(value, digit), checked.is_none());
        let sign = if negative { "-" } else { "" };
        let mantissa = if zero { "0" } else { "1" };
        let exponent_sign = if positive_exponent { "+" } else { "-" };
        let leading = "0".repeat(leading_zero_count);
        let suffix = suffix.into_iter().map(|value| char::from(b'0' + value)).collect::<String>();
        let original = format!("{sign}{mantissa}e{exponent_sign}{leading}2147483648{suffix}");
        let with_end = format!("{original}]");
        let mut deserializer = serde_json::Deserializer::from_slice(with_end.as_bytes());
        let parsed = <ObservedNumericDispatch as serde::Deserialize>::deserialize(&mut deserializer);
        if !zero && positive_exponent {
            let error = parsed.expect_err("range refusal occurs immediately after consumed trigger");
            proptest::prop_assert!(error.is_syntax());
            proptest::prop_assert!(error.to_string().starts_with("number out of range"));
            let consumed = sign.len() + mantissa.len() + 1 + exponent_sign.len() + leading_zero_count + 10;
            proptest::prop_assert_eq!((error.line(), error.column()), (1, consumed));
        } else {
            let bits = if negative { (-0.0_f64).to_bits() } else { 0.0_f64.to_bits() };
            proptest::prop_assert_eq!(parsed.expect("signed zero from huge exponent"), ObservedNumericDispatch::Floating(bits));
            let trailing = deserializer.end().expect_err("entire digit suffix consumed, delimiter unread");
            proptest::prop_assert!(trailing.is_syntax());
            proptest::prop_assert_eq!((trailing.line(), trailing.column()), (1, original.len() + 1));
        }
    }

    #[test]
    fn complete_fraction_forms_keep_floating_dispatch_and_sign_across_word_overflow(
        negative in proptest::arbitrary::any::<bool>(),
        integer in proptest::arbitrary::any::<u64>(),
        digits in proptest::collection::vec(0_u8..=9, 1..64),
        exponent in -30_i32..=30,
    ) {
        let sign = if negative { "-" } else { "" };
        let fraction = digits.into_iter().map(|digit| char::from(b'0' + digit)).collect::<String>();
        let text = format!("{sign}{integer}.{fraction}e{exponent}");
        let parsed = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("complete finite fraction/exponent form");
        match parsed {
            ObservedNumericDispatch::Floating(bits) => {
                proptest::prop_assert!(f64::from_bits(bits).is_finite());
                proptest::prop_assert_eq!(bits >> 63, u64::from(negative));
            }
            _ => proptest::prop_assert!(false, "fraction syntax must dispatch to f64"),
        }
    }

    #[test]
    fn leading_zero_refusal_reports_the_unread_digit_before_a_later_float_suffix(
        negative in proptest::arbitrary::any::<bool>(),
        digit in 0_u8..=9,
        exponent in proptest::arbitrary::any::<u32>(),
    ) {
        let sign = if negative { "-" } else { "" };
        let text = format!("{sign}0{digit}e+{exponent}");
        let error = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect_err("leading-zero refusal");
        proptest::prop_assert!(error.is_syntax());
        proptest::prop_assert_eq!(error.line(), 1);
        proptest::prop_assert_eq!(error.column(), if negative { 3 } else { 2 });
    }

    #[test]
    fn every_unsigned_digit_step_matches_checked_arithmetic_and_native_number_kind(
        value in proptest::arbitrary::any::<u64>(),
        digit in 0_u64..=9,
    ) {
        let checked = value.checked_mul(10).and_then(|prefix| prefix.checked_add(digit));
        proptest::prop_assert_eq!(source_unsigned_digit_overflows(value, digit), checked.is_none());
        if value > 0 {
            let text = format!("{value}{digit}");
            let parsed = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("finite original integer syntax");
            match checked {
                Some(word) => proptest::prop_assert_eq!(parsed, ObservedNumericDispatch::Unsigned(word)),
                None => proptest::prop_assert!(matches!(parsed, ObservedNumericDispatch::Floating(_))),
            }
        }
    }

    #[test]
    fn every_original_negative_u64_word_uses_the_correct_signed_or_float_cast_payload(
        original in proptest::arbitrary::any::<u64>(),
    ) {
        let text = format!("-{original}");
        let parsed = serde_json::from_slice::<ObservedNumericDispatch>(text.as_bytes()).expect("complete original unsigned magnitude");
        if original > 0 && original <= 9_223_372_036_854_775_808 {
            let signed = i64::try_from(-i128::from(original)).expect("original negative magnitude fits i64");
            proptest::prop_assert_eq!(parsed, ObservedNumericDispatch::Signed(signed));
        } else {
            proptest::prop_assert_eq!(parsed, ObservedNumericDispatch::Floating(original_unsigned_negative_float_bits(original)));
        }
    }

    #[test]
    fn original_integer_words_and_fraction_forms_choose_the_native_numeric_dispatch(
        positive in proptest::arbitrary::any::<u64>(),
        negative_magnitude in 1_u64..=9_223_372_036_854_775_808,
    ) {
        let positive_text = positive.to_string();
        proptest::prop_assert_eq!(serde_json::from_slice::<ObservedNumericDispatch>(positive_text.as_bytes()).expect("u64 dispatch"),
            ObservedNumericDispatch::Unsigned(positive));
        let negative_text = format!("-{negative_magnitude}");
        let negative = i64::try_from(-i128::from(negative_magnitude)).expect("negative word fits i64");
        proptest::prop_assert_eq!(serde_json::from_slice::<ObservedNumericDispatch>(negative_text.as_bytes()).expect("i64 dispatch"),
            ObservedNumericDispatch::Signed(negative));
        let fraction_text = format!("{positive_text}.0");
        proptest::prop_assert!(matches!(serde_json::from_slice::<ObservedNumericDispatch>(fraction_text.as_bytes()).expect("fraction dispatch"),
            ObservedNumericDispatch::Floating(_)));
    }

    #[test]
    fn strict_original_json_refuses_escaped_duplicate_names_before_map_collapse(
        number in proptest::arbitrary::any::<u32>(),
        depth in 0_usize..8,
    ) {
        let name = format!("item_{number}");
        let quoted = serde_json::to_string(&name).expect("quoted original name");
        let escaped = name.bytes().map(|byte| format!("\\u{byte:04x}")).collect::<String>();
        let object = format!("{{{quoted}:1,\"{escaped}\":2}}");
        let document = format!("{}{object}{}", "[".repeat(depth), "]".repeat(depth));
        let collapsed: Value = serde_json::from_slice(document.as_bytes()).expect("ordinary map parser collapses duplicates");
        let mut inner = &collapsed;
        for _ in 0..depth {
            inner = &inner[0];
        }
        proptest::prop_assert_eq!(inner.as_object().expect("collapsed object").len(), 1);
        proptest::prop_assert_eq!(&inner[&name], &json!(2));
        proptest::prop_assert!(strict_json::from_slice::<Value>(document.as_bytes()).is_err());
    }

    #[test]
    fn complete_finite_json_fraction_and_exponent_forms_parse_and_refuse_trailing_junk(
        negative in proptest::arbitrary::any::<bool>(),
        integer in 0_u64..=999_999_999_999,
        fraction in 0_u32..=999_999,
        exponent in -20_i32..=20,
        upper in proptest::arbitrary::any::<bool>(),
    ) {
        let minus = if negative { "-" } else { "" };
        let marker = if upper { "E" } else { "e" };
        let sign = if exponent < 0 { "-" } else { "+" };
        let text = format!("{minus}{integer}.{fraction:06}{marker}{sign}{:02}", exponent.unsigned_abs());
        let parsed: Value = strict_json::from_slice(text.as_bytes()).expect("finite complete numeric grammar");
        proptest::prop_assert!(parsed.is_number());
        proptest::prop_assert!(parsed.as_number().expect("number").is_f64());
        proptest::prop_assert!(parsed.as_f64().expect("finite number").is_finite());
        let surrounded = format!(" \t{text}\r\n");
        proptest::prop_assert_eq!(strict_json::from_slice::<Value>(surrounded.as_bytes()).expect("four JSON whitespace bytes"), parsed);
        proptest::prop_assert!(strict_json::from_slice::<Value>(format!("+{text}").as_bytes()).is_err());
        proptest::prop_assert!(strict_json::from_slice::<Value>(format!("{text}x").as_bytes()).is_err());
    }

    #[test]
    fn complete_admitted_trees_match_independent_bytes_and_keep_original_sink_prefix(
        value in admitted_tree_values(),
        prefix in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..128),
    ) {
        let expected = reference_admitted_tree_bytes(&value);
        let actual = serde_json_canonicalizer::to_vec(&value).expect("complete admitted tree");
        proptest::prop_assert_eq!(&actual, &expected);
        proptest::prop_assert!(actual.len() <= reference_admitted_tree_size_bound(&value));
        proptest::prop_assert_eq!(strict_json::from_slice::<Value>(&actual).expect("all original children"), value.clone());
        let mut output = prefix.clone();
        serde_json_canonicalizer::to_writer(&value, &mut output).expect("append complete nested tree");
        let mut full_expected = prefix;
        full_expected.extend_from_slice(&expected);
        proptest::prop_assert_eq!(output, full_expected);
    }

    #[test]
    fn safe_integer_formatter_uses_exact_original_decimal_and_appends_to_original_sink(
        signed in -9_007_199_254_740_991_i64..=9_007_199_254_740_991,
        unsigned in 0_u64..=9_007_199_254_740_991,
        prefix in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..128),
    ) {
        let signed_expected = signed.to_string().into_bytes();
        let unsigned_expected = unsigned.to_string().into_bytes();
        let signed_actual = serde_json_canonicalizer::to_vec(&signed).expect("safe signed integer");
        let unsigned_actual = serde_json_canonicalizer::to_vec(&unsigned).expect("safe unsigned integer");
        proptest::prop_assert_eq!(&signed_actual, &signed_expected);
        proptest::prop_assert_eq!(&unsigned_actual, &unsigned_expected);
        proptest::prop_assert_eq!(strict_json::from_slice::<i64>(&signed_actual).expect("same signed value"), signed);
        proptest::prop_assert_eq!(strict_json::from_slice::<u64>(&unsigned_actual).expect("same unsigned value"), unsigned);
        proptest::prop_assert!(signed_actual.len() <= 17);
        proptest::prop_assert!(unsigned_actual.len() <= 16);
        let mut output = prefix.clone();
        serde_json_canonicalizer::to_writer(&signed, &mut output).expect("append signed integer");
        serde_json_canonicalizer::to_writer(&unsigned, &mut output).expect("append unsigned integer");
        let mut expected = prefix;
        expected.extend_from_slice(&signed_expected);
        expected.extend_from_slice(&unsigned_expected);
        proptest::prop_assert_eq!(output, expected);
    }

    #[test]
    fn admitted_nested_body_and_probe_integers_survive_complete_source_serialization(
        positive in 0_u64..=9_007_199_254_740_991,
        negative in -9_007_199_254_740_991_i64..=0,
        probe in -9_007_199_254_740_991_i64..=9_007_199_254_740_991,
    ) {
        let (raw_source, lock) = fixture("airtable");
        let mut source: Value = serde_json::from_slice(raw_source).expect("source fixture");
        source["write"]["body"]["value"]["fields"]["numeric_evidence"] = json!({
            "kind":"array", "items":[
                {"kind":"integer","value":positive},
                {"kind":"object","fields":{"negative":{"kind":"integer","value":negative}}}
            ]
        });
        source["credential"]["guard"] = json!({"prefixes":["fixture_"],"probe":{
            "path":[{"kind":"fixed","value":"credential-check"}],"json_pointer":"/active",
            "equals":probe,"maximum_response_bytes":65536}});
        let bytes = serde_json::to_vec(&source).expect("complete source");
        let admitted = CompiledRecipe::compile(&bytes, lock).expect("admitted safe numeric source");
        assert_admitted_source_numeric_serialization(&admitted);
        let original = serde_json::to_value(&admitted.source).expect("full typed source");
        proptest::prop_assert_eq!(&original["write"]["body"]["value"]["fields"]["numeric_evidence"],
            &source["write"]["body"]["value"]["fields"]["numeric_evidence"]);
        proptest::prop_assert_eq!(&original["credential"]["guard"]["probe"]["equals"], &json!(probe));
    }
}

#[test]
fn canonical_float_zero_normalization_does_not_describe_raw_bit_identity() {
    assert_ne!(0.0_f64.to_bits(), (-0.0_f64).to_bits());
    assert_eq!(serde_json_canonicalizer::to_vec(&0.0_f64).expect("canonical zero"), b"0");
    assert_eq!(serde_json_canonicalizer::to_vec(&-0.0_f64).expect("canonical negative zero"), b"0");
}

#[test]
fn canonical_property_sorting_uses_decoded_names_before_json_escapes() {
    let value = json!({"a":4,"\\":3,"\"":2,"\n":1});
    assert_eq!(serde_json_canonicalizer::to_vec(&value).expect("canonical object"),
        br#"{"\n":1,"\"":2,"\\":3,"a":4}"#);
}

#[test]
fn canonical_utf16_keys_keep_surrogate_boundaries_prefixes_and_payloads() {
    let keys = ["", "\0", "a", "a\0", "\u{d7ff}", "\u{e000}", "\u{ffff}",
        "\u{10000}", "\u{103ff}", "\u{10400}", "\u{10ffff}"];
    let expected_units: &[&[u16]] = &[&[], &[0], &[97], &[97, 0], &[0xd7ff],
        &[0xe000], &[0xffff], &[0xd800, 0xdc00], &[0xd800, 0xdfff],
        &[0xd801, 0xdc00], &[0xdbff, 0xdfff]];
    let mut object = serde_json::Map::new();
    for (index, (key, expected)) in keys.iter().zip(expected_units).enumerate().rev() {
        assert_eq!(key.encode_utf16().collect::<Vec<_>>(), *expected);
        object.insert((*key).to_owned(), json!(index));
    }
    let canonical = serde_json_canonicalizer::to_vec(&Value::Object(object)).expect("canonical object");
    let decoded: Value = strict_json::from_slice(&canonical).expect("unique canonical properties");
    let decoded = decoded.as_object().expect("object");
    let mut ordered = keys.to_vec();
    ordered.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
    assert_eq!(decoded.keys().map(String::as_str).collect::<Vec<_>>(), ordered);
    assert_eq!(decoded.len(), keys.len());
    for (index, key) in keys.iter().enumerate() {
        assert_eq!(decoded.get(*key), Some(&json!(index)), "original payload for {key:?}");
    }
    assert!("\u{e000}" < "\u{10000}", "native UTF-8 body-key order");
    assert!("\u{10000}".encode_utf16().cmp("\u{e000}".encode_utf16()).is_lt(),
        "canonical UTF-16 property order differs");
}

#[test]
fn canonical_strings_keep_unicode_and_use_exact_control_escapes() {
    let input = "\0\u{1}\u{7}\u{8}\t\n\u{b}\u{c}\r\u{e}\u{1f}\"\\/é\u{2028}\u{2029}😀";
    let expected = [r#""\u0000\u0001\u0007\b\t\n\u000b\f\r\u000e\u001f\"\\/é"#,
        "\u{2028}\u{2029}😀\""].concat();
    let canonical = serde_json_canonicalizer::to_vec(&input).expect("canonical text");
    assert_eq!(canonical, expected.as_bytes());
    assert_eq!(strict_json::from_slice::<String>(&canonical).expect("decoded text"), input);
    assert!(canonical.len() <= 6 * input.len() + 2);
}

#[test]
fn strict_json_refuses_isolated_surrogates_before_canonical_key_construction() {
    for input in [br#""\ud800""#.as_slice(), br#""\udfff""#.as_slice(),
        br#""\ud800x""#.as_slice(), br#""\ud800\u0041""#.as_slice(),
        br#"{"\ud800":1}"#.as_slice()] {
        assert!(strict_json::from_slice::<Value>(input).is_err());
    }
    let paired: Value = strict_json::from_slice(br#"{"\ud800\udc00":1}"#).expect("paired scalar");
    assert_eq!(paired.get("\u{10000}"), Some(&json!(1)));
    let duplicated = r#"{"\ud800\udc00":1,"𐀀":2}"#;
    assert!(strict_json::from_slice::<Value>(duplicated.as_bytes()).is_err(),
        "escape aliases name the same property before JCS set insertion");
}

#[test]
fn typed_source_structs_and_struct_variants_refuse_unknown_members() {
    let (bytes, lock) = fixture("airtable");
    serde_contract_refuses_unknown::<RecipeSource>(serde_json::from_slice(bytes).expect("source fixture"));
    serde_contract_refuses_unknown::<ProfileLockFile>(serde_json::from_slice(lock).expect("lock fixture"));
    serde_contract_refuses_unknown::<source::GuardSource>(json!({"prefixes":[]}));
    serde_contract_refuses_unknown::<source::ProbeSource>(json!({"path":[],"json_pointer":"","equals":null,"maximum_response_bytes":1}));
    serde_contract_refuses_unknown::<source::AccountReadSource>(json!({"path":[],"json_pointer":"","maximum_response_bytes":1}));
    serde_contract_refuses_unknown::<source::DeniedReadSource>(json!({"method":"GET","path":[],"refused_status":[403]}));
    serde_contract_refuses_unknown::<source::AccountScopeSource>(json!({"header":"X-Account","field":"account"}));
    serde_contract_refuses_unknown::<source::BoundsSource>(json!({}));
    serde_contract_refuses_unknown::<source::SumBoundSource>(json!({"argument":"amount"}));
    serde_contract_refuses_unknown::<source::RelativeCeilingSource>(json!({"argument":"amount","basis_points":1,"path":[],"json_pointer":"","maximum_response_bytes":1}));
    serde_contract_refuses_unknown::<source::BindSource>(json!({"pointer":"/id","field":"id"}));
    serde_contract_refuses_unknown::<source::WriteSource>(json!({"method":"POST","path":[],"body":{"kind":"form","fields":{}}}));
    serde_contract_refuses_unknown::<source::IdempotencyLocation>(json!({}));
    serde_contract_refuses_unknown::<source::ObservationSource>(json!({"path":[],"json_pointer":"","expected_field":"id","maximum_response_bytes":1}));
    serde_contract_refuses_unknown::<source::EchoSource>(json!({"write":{"kind":"form-field","name":"echo"},"observe":"/echo"}));
    serde_contract_refuses_unknown::<source::PreEntrySource>(json!({"path":[],"pointers":[],"maximum_response_bytes":1}));
    serde_contract_refuses_unknown::<source::PreconditionSource>(json!({}));
    serde_contract_refuses_unknown::<source::CredentialSource>(json!({"kind":"bearer"}));
    serde_contract_refuses_unknown::<source::IdempotencySource>(json!({"kind":"derived-header","retention_seconds":1}));
    serde_contract_refuses_unknown::<source::PathSegment>(json!({"kind":"fixed","value":"id"}));
    serde_contract_refuses_unknown::<source::BodySource>(json!({"kind":"form","fields":{}}));
    serde_contract_refuses_unknown::<source::FormExpr>(json!({"kind":"string","value":""}));
    serde_contract_refuses_unknown::<source::ValueExpr>(json!({"kind":"boolean","value":false}));
    serde_contract_refuses_unknown::<source::EchoPlacement>(json!({"kind":"json-pointer","pointer":"/echo"}));
}

#[test]
fn typed_source_serialization_keeps_user_names_separate_from_fixed_serde_fields() {
    let (source, _) = fixture("airtable");
    let original: Value = serde_json::from_slice(source).expect("source fixture");
    let names = ["kind", "value", "fields", "items", "schema", "credential", "write", "",
        "\0", "\n", "\"", "\\", "\u{e000}", "\u{10000}"];
    for form in [false, true] {
        let mut source = original.clone();
        let mut fields = serde_json::Map::new();
        let mut headers = serde_json::Map::new();
        let mut literal = serde_json::Map::new();
        for (index, name) in names.iter().enumerate() {
            let payload = format!("payload-{index}");
            fields.insert((*name).to_owned(), json!({"kind":"string","value":payload}));
            headers.insert((*name).to_owned(), json!(payload));
            literal.insert((*name).to_owned(), json!([index, false, null]));
        }
        source["provider_headers"] = Value::Object(headers.clone());
        source["credential"]["guard"] = json!({"prefixes":[], "probe":{
            "path":[],"json_pointer":"","equals":literal.clone(),"maximum_response_bytes":1}});
        source["write"]["body"] = if form {
            json!({"kind":"form","fields":fields.clone()})
        } else {
            json!({"kind":"json","value":{"kind":"object","fields":fields.clone()}})
        };
        // Representation evidence only: these header/body names deliberately
        // include values that later source admission must refuse.
        let typed = serde_contract_source(&source);
        let serialized = serde_json::to_vec(&typed).expect("typed source serialization");
        let canonical = serde_json_canonicalizer::to_vec(&typed).expect("canonical source");
        for bytes in [serialized, canonical] {
            let decoded: Value = strict_json::from_slice(&bytes).expect("all serialized names are unique");
            let body_fields = if form { &decoded["write"]["body"]["fields"] }
                else { &decoded["write"]["body"]["value"]["fields"] };
            assert_eq!(body_fields.as_object().expect("fields").len(), names.len());
            assert_eq!(body_fields, &Value::Object(fields.clone()));
            assert_eq!(decoded["provider_headers"], Value::Object(headers.clone()));
            assert_eq!(decoded["credential"]["guard"]["probe"]["equals"], Value::Object(literal.clone()));
        }
    }
}

#[test]
fn profile_schema_canonicalization_preserves_nested_names_and_refuses_raw_duplicates() {
    let (_, lock) = fixture("airtable");
    let mut value: Value = serde_json::from_slice(lock).expect("lock fixture");
    let schema = json!({"kind": {"kind":false,"value":null,"fields":[{"schema":1,"version":2}]},
        "command_schema":{"schema_digest":"literal","generator_format":3}, "\u{10000}":4,"\u{e000}":5});
    value["command_schema"] = schema.clone();
    let typed: ProfileLockFile = strict_json::from_slice(&serde_json::to_vec(&value).expect("lock input")).expect("typed lock");
    let canonical = serde_json_canonicalizer::to_vec(&typed.command_schema).expect("canonical schema only");
    assert_eq!(strict_json::from_slice::<Value>(&canonical).expect("unique complete schema"), schema);
    value["command_schema"] = json!({"unique_schema_marker":null});
    let raw = serde_json::to_string(&value).expect("lock input").replace(
        "\"unique_schema_marker\":null", "\"same\":false,\"same\":true");
    assert!(strict_json::from_slice::<ProfileLockFile>(raw.as_bytes()).is_err(),
        "strict traversal must see repeated occurrences before generic JSON map construction");
}

#[test]
fn serde_struct_sequences_normalize_to_the_same_typed_source_and_lock() {
    let (source_bytes, lock_bytes) = fixture("airtable");
    let source: Value = serde_json::from_slice(source_bytes).expect("source fixture");
    let lock: Value = serde_json::from_slice(lock_bytes).expect("lock fixture");
    let positional_source = Value::Array(["schema", "profile_schema_digest", "service", "tool", "operator_namespace",
        "credential", "origin", "provider_headers", "account_scope", "bounds", "relative_ceiling", "write",
        "observation", "echo", "pre_entry", "preconditions"].into_iter()
        .map(|key| source.get(key).cloned().unwrap_or(Value::Null)).collect());
    let positional_lock = Value::Array(["schema", "profile", "version", "service", "tool", "schema_digest",
        "command_schema", "generator_format"].into_iter()
        .map(|key| lock.get(key).expect("required lock field").clone()).collect());
    serde_contract_normalizes::<RecipeSource>(positional_source.clone(),
        serde_json::to_value(serde_contract_source(&source)).expect("typed source"));
    let original = CompiledRecipe::compile(source_bytes, lock_bytes).expect("original fixture");
    let positional = CompiledRecipe::compile(&serde_json::to_vec(&positional_source).expect("source"),
        &serde_json::to_vec(&positional_lock).expect("lock")).expect("positional fixture");
    assert_eq!(positional.digest(), original.digest());
    assert_eq!(positional.namespace().as_str(), original.namespace().as_str());
}

#[test]
fn serde_positional_defaults_do_not_replace_present_null() {
    for input in [json!([]), json!([null]), json!([null, []])] {
        serde_contract_normalizes::<source::PreconditionSource>(input, json!({}));
    }
    serde_contract_normalizes::<source::PreconditionSource>(json!(["id", ["expected"]]),
        json!({"read_back_subject":"id","verified":["expected"]}));
    for input in [json!([null, null]), json!([null, [], 1])] {
        assert!(strict_json::from_slice::<source::PreconditionSource>(&serde_json::to_vec(&input).expect("input")).is_err());
    }
    assert!(strict_json::from_slice::<source::EchoSource>(br#"[{"kind":"form-field","name":"echo"}]"#).is_err());
    serde_contract_normalizes::<source::EchoSource>(json!([{"kind":"form-field","name":"echo"}, "/echo"]),
        json!({"write":{"kind":"form-field","name":"echo"},"observe":"/echo"}));
}

#[test]
fn serde_internal_sequences_use_declared_field_order_and_defaults() {
    serde_contract_normalizes::<source::CredentialSource>(json!(["bearer"]), json!({"kind":"bearer"}));
    serde_contract_normalizes::<source::CredentialSource>(json!(["header-api-key", "X-Example-Key"]),
        json!({"kind":"header-api-key","header":"X-Example-Key"}));
    serde_contract_normalizes::<source::ValueExpr>(json!(["integer", i64::MIN]), json!({"kind":"integer","value":i64::MIN}));
    serde_contract_normalizes::<source::ValueExpr>(json!(["array", []]), json!({"kind":"array","items":[]}));
    serde_contract_normalizes::<source::BodySource>(json!(["json", ["echo"]]), json!({"kind":"json","value":{"kind":"echo"}}));
    serde_contract_normalizes::<source::BodySource>(json!(["form", {}]), json!({"kind":"form","fields":{}}));
    assert!(strict_json::from_slice::<source::ValueExpr>(br#"["integer"]"#).is_err());
    assert!(strict_json::from_slice::<source::CredentialSource>(br#"["bearer",null,1]"#).is_err());
}

#[test]
fn serde_unit_echo_ignores_map_content_but_strict_preflight_still_visits_it() {
    let input = json!({"kind":"echo","ignored":{"nested":[true,1,null]}});
    serde_contract_normalizes::<source::ValueExpr>(input.clone(), json!({"kind":"echo"}));
    serde_contract_normalizes::<source::FormExpr>(input.clone(), json!({"kind":"echo"}));
    serde_contract_normalizes::<source::PathSegment>(input, json!({"kind":"echo"}));
    serde_contract_normalizes::<source::ValueExpr>(json!(["echo"]), json!({"kind":"echo"}));
    assert!(strict_json::from_slice::<source::ValueExpr>(br#"["echo",1]"#).is_err());
    let duplicate = br#"{"kind":"echo","ignored":{"x":1,"x":2}}"#;
    // Ordinary serde ignores this content. Auths' actual first pass still
    // refuses its duplicate member before the typed visitor can ignore it.
    assert!(serde_json::from_slice::<source::ValueExpr>(duplicate).is_ok());
    assert!(strict_json::from_slice::<source::ValueExpr>(duplicate).is_err());
}

#[test]
fn ignored_echo_content_does_not_bypass_public_source_admission() {
    let (source, lock) = fixture("airtable");
    let base: Value = serde_json::from_slice(source).expect("source fixture");
    let echo = json!({"kind":"echo","ignored":{"dup_marker":0}});
    for location in ["path", "json", "form"] {
        let mut source = base.clone();
        match location {
            "path" => source["write"]["path"] = json!([echo.clone()]),
            "json" => source["write"]["body"] = json!({"kind":"json","value":echo.clone()}),
            "form" => source["write"]["body"] = json!({"kind":"form","fields":{"echo":echo.clone()}}),
            _ => unreachable!("closed test cases"),
        }
        let raw = serde_json::to_string(&source).expect("source");
        assert_eq!(CompiledRecipe::compile(raw.as_bytes(), lock).err(), Some(GatewayRecipeError::EchoConflict), "{location}");
        let duplicate = raw.replacen("\"dup_marker\":0", "\"dup_marker\":0,\"dup_marker\":1", 1);
        assert_ne!(duplicate, raw, "the duplicate mutation must occur");
        assert_eq!(CompiledRecipe::compile(duplicate.as_bytes(), lock).err(), Some(GatewayRecipeError::InvalidSource), "{location}");
    }
}

#[test]
fn serde_buffering_changes_numeric_variant_identifier_acceptance() {
    let numeric = json!({"kind":1,"value":7});
    assert!(strict_json::from_slice::<source::ValueExpr>(&serde_json::to_vec(&numeric).expect("input")).is_err());
    serde_contract_normalizes::<source::BodySource>(json!({"kind":"json","value":numeric}),
        json!({"kind":"json","value":{"kind":"integer","value":7}}));
    let invalid = json!({"kind":"json","value":{"kind":7,"value":7}});
    assert!(strict_json::from_slice::<source::BodySource>(&serde_json::to_vec(&invalid).expect("input")).is_err());
}

#[test]
fn serde_write_method_accepts_unit_variant_objects_and_strings() {
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(tag = "kind", rename_all = "kebab-case")]
    enum BufferedMethod {
        Wrapper { method: WriteMethod },
    }
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let mut object = Map::new();
        object.insert(method.to_owned(), Value::Null);
        serde_contract_normalizes::<WriteMethod>(Value::Object(object), json!(method));
    }
    for invalid in [json!({"POST":true}), json!({"POST":null,"PUT":null}), json!(0)] {
        assert!(strict_json::from_slice::<WriteMethod>(&serde_json::to_vec(&invalid).expect("input")).is_err());
    }
    assert!(strict_json::from_slice::<WriteMethod>(br#"{"POST":{}}"#).is_err());
    serde_contract_normalizes::<BufferedMethod>(json!({"kind":"wrapper","method":{"POST":{}}}),
        json!({"kind":"wrapper","method":"POST"}));
}

#[test]
fn typed_lock_integer_widths_refuse_overflow_and_floating_numbers() {
    let (source, lock) = fixture("airtable");
    let original: Value = serde_json::from_slice(lock).expect("lock fixture");
    for (key, values) in [("version", [json!(65536), json!(1.0), json!(-1)]),
        ("generator_format", [json!(256), json!(1.0), json!(-1)])] {
        for value in values {
            let mut invalid = original.clone();
            invalid[key] = value;
            let bytes = serde_json::to_vec(&invalid).expect("input");
            assert!(strict_json::from_slice::<ProfileLockFile>(&bytes).is_err());
            assert_eq!(CompiledRecipe::compile(source, &bytes).err(), Some(GatewayRecipeError::InvalidProfileLock));
        }
    }
}

#[test]
fn public_byte_entry_retains_inclusive_input_limits_and_canonical_meaning() {
    let (source, lock) = fixture("airtable");
    assert!(source.len() < recipe_binding::MAX_SOURCE_BYTES);
    assert!(lock.len() < recipe_binding::MAX_LOCK_BYTES);
    let original = CompiledRecipe::compile(source, lock).expect("original fixture");
    let mut padded_source = source.to_vec();
    let mut padded_lock = lock.to_vec();
    padded_source.resize(recipe_binding::MAX_SOURCE_BYTES, b' ');
    padded_lock.resize(recipe_binding::MAX_LOCK_BYTES, b' ');
    let bounded = CompiledRecipe::compile(&padded_source, &padded_lock).expect("inclusive byte limits");
    assert_eq!(bounded.digest(), original.digest(), "original typed source, independent of trailing whitespace");
    assert_eq!(bounded.namespace().as_str(), original.namespace().as_str());
    padded_source.push(b' ');
    assert_eq!(CompiledRecipe::compile(&padded_source, lock).err(), Some(GatewayRecipeError::InvalidSource));
    padded_lock.push(b' ');
    assert_eq!(CompiledRecipe::compile(source, &padded_lock).err(), Some(GatewayRecipeError::InvalidSource));
    assert_eq!(CompiledRecipe::compile(&[], lock).err(), Some(GatewayRecipeError::InvalidSource));
    assert_eq!(CompiledRecipe::compile(source, &[]).err(), Some(GatewayRecipeError::InvalidSource));
}

#[test]
fn public_byte_entry_preserves_parse_before_admission_refusal_order() {
    let (source, lock) = fixture("airtable");
    assert_eq!(CompiledRecipe::compile(b"{", b"{").err(), Some(GatewayRecipeError::InvalidSource));
    assert_eq!(CompiledRecipe::compile(source, b"{").err(), Some(GatewayRecipeError::InvalidProfileLock));
    let mut obsolete: Value = serde_json::from_slice(source).expect("source fixture");
    obsolete["schema"] = json!("auths.gateway-recipe-source/1");
    let obsolete = serde_json::to_vec(&obsolete).expect("obsolete typed source");
    assert_eq!(CompiledRecipe::compile(&obsolete, b"{").err(), Some(GatewayRecipeError::InvalidProfileLock));
    assert_eq!(CompiledRecipe::compile(&obsolete, lock).err(), Some(GatewayRecipeError::InvalidSource));
}

#[test]
fn explicit_credential_header_scan_retains_the_original_http_name_policy() {
    fn reference(header: &str) -> bool {
        let lower = header.to_ascii_lowercase();
        !header.is_empty() && header.len() <= 64
            && header.bytes().enumerate().all(|(position, byte)| {
                byte.is_ascii_alphanumeric() || (position > 0 && byte == b'-')
            })
            && !["authorization", "host", "cookie", "set-cookie", "content-type", "content-length",
                "accept", "connection", "transfer-encoding", "idempotency-key"].contains(&lower.as_str())
            && !PROVIDER_HEADERS.iter().any(|entry| entry.name.eq_ignore_ascii_case(header))
    }
    let compare = |header: &str| {
        let requirement = CredentialRequirement::HeaderApiKey { header: header.to_owned() };
        assert_eq!(requirement.validate().is_ok(), reference(header), "{header:?}");
    };
    for length in [0, 1, 2, 63, 64, 65] {
        compare(&"a".repeat(length));
        for position in 0..length {
            for byte in 0_u8..=127 {
                let mut candidate = vec![b'a'; length];
                candidate[position] = byte;
                compare(std::str::from_utf8(&candidate).expect("ASCII test candidate"));
            }
        }
    }
    for header in ["Authorization", "HOST", "cookie", "set-cookie", "content-type", "content-length",
        "accept", "connection", "transfer-encoding", "idempotency-key", "Stripe-Version", "stripe-version",
        "STRIPE-ACCOUNT", "X-GitHub-Api-Version", "X-Test-Key", "é", "X-é-Key", "-X-Test"] {
        compare(header);
        compare(&header.to_ascii_uppercase());
    }
}

fn fixture(name: &str) -> (&'static [u8], &'static [u8]) {
    match name {
        "airtable" => (
            include_bytes!("../../../../../bindings/fixtures/gateway/airtable/recipe.json"),
            include_bytes!("../../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
        ),
        "todoist" => (
            include_bytes!("../../../../../bindings/fixtures/gateway/todoist/recipe.json"),
            include_bytes!("../../../../../bindings/fixtures/gateway/todoist/profile.lock.json"),
        ),
        "github" => (
            include_bytes!("../../../../../bindings/fixtures/gateway/github/recipe.json"),
            include_bytes!("../../../../../bindings/fixtures/gateway/github/profile.lock.json"),
        ),
        _ => panic!("unknown test-only fixture"),
    }
}

fn compiled(name: &str) -> CompiledRecipe {
    let (recipe, lock) = fixture(name);
    CompiledRecipe::compile(recipe, lock).expect("canonical fixture compiles")
}

#[test]
fn canonicalization_failures_are_consumed_at_the_original_rule_boundaries() {
    let (raw_source, raw_lock) = fixture("airtable");
    let source: RecipeSource = strict_json::from_slice(raw_source).expect("source");
    let lock: ProfileLockFile = strict_json::from_slice(raw_lock).expect("lock");
    let canonical = CanonicalRecipeInputs::from_decoded(&source, &lock);
    let failed = CanonicalRecipeInputs { schema: Err(()), source: Err(()) };
    let mut unsupported = source.clone();
    unsupported.schema = "auths.gateway-recipe-source/1".into();
    assert_eq!(validate::validate_source(&unsupported, &lock, &failed).err(), Some(GatewayRecipeError::InvalidSource));
    assert_eq!(validate::validate_source(&source, &lock, &failed).err(), Some(GatewayRecipeError::InvalidProfileLock));

    let source_failure = CanonicalRecipeInputs { schema: canonical.schema, source: Err(()) };
    let checked = validate::validate_source(&source, &lock, &source_failure).expect("source rules still run first");
    assert_eq!(checked.digest(), Err(GatewayRecipeError::InvalidSource));
    let mut unsafe_origin = source.clone();
    unsafe_origin.origin = "http://api.example.com".into();
    assert_eq!(validate::validate_source(&unsafe_origin, &lock, &source_failure).err(), Some(GatewayRecipeError::UnsafeOrigin));
}

#[test]
fn retained_original_canonical_source_has_the_same_domain_separated_digest() {
    for name in ["airtable", "todoist", "github"] {
        let (raw_source, raw_lock) = fixture(name);
        let source: RecipeSource = strict_json::from_slice(raw_source).expect("source");
        let lock: ProfileLockFile = strict_json::from_slice(raw_lock).expect("lock");
        let canonical = CanonicalRecipeInputs::from_decoded(&source, &lock);
        let checked = validate::validate_source(&source, &lock, &canonical).expect("admission");
        // The prior implementation serialized this exact source at digest
        // time. This is a test-only oracle for the staging change.
        let bytes = serde_json_canonicalizer::to_vec(&source).expect("canonical source");
        let input = recipe_binding::recipe_digest_input(&bytes);
        let mut hash = Sha256::new();
        hash.update(input.domain);
        hash.update(input.canonical_source);
        let expected: [u8; 32] = hash.finalize().into();
        assert_eq!(checked.digest(), Ok(expected));
        assert_eq!(compiled(name).digest(), &expected);
    }
}

#[test]
fn decoded_compile_caller_refuses_before_digest_or_lowering_when_prior_rules_fail() {
    let (raw_source, raw_lock) = fixture("airtable");
    let source: RecipeSource = strict_json::from_slice(raw_source).expect("source");
    let lock: ProfileLockFile = strict_json::from_slice(raw_lock).expect("lock");
    let canonical = CanonicalRecipeInputs::from_decoded(&source, &lock);
    let failed = CanonicalRecipeInputs { schema: Err(()), source: Err(()) };
    let mut unsupported = source.clone();
    unsupported.schema = "auths.gateway-recipe-source/1".into();
    assert_eq!(compile_decoded(unsupported, &lock, &failed).err(), Some(GatewayRecipeError::InvalidSource));
    assert_eq!(compile_decoded(source.clone(), &lock, &failed).err(), Some(GatewayRecipeError::InvalidProfileLock));
    let failed_source = CanonicalRecipeInputs { schema: canonical.schema, source: Err(()) };
    let mut unsafe_origin = source.clone();
    unsafe_origin.origin = "http://api.example.com".into();
    assert_eq!(compile_decoded(unsafe_origin, &lock, &failed_source).err(), Some(GatewayRecipeError::UnsafeOrigin));
    assert_eq!(compile_decoded(source, &lock, &failed_source).err(), Some(GatewayRecipeError::InvalidSource));
}

fn arguments(recipe: &CompiledRecipe, values: &Value) -> Map<String, Value> {
    let mut object = values.as_object().expect("object fixture").clone();
    object.insert(
        "operator_namespace".into(),
        Value::String(recipe.namespace().as_str().to_owned()),
    );
    object.insert("recipe_digest".into(), Value::String(recipe.digest_hex()));
    object
}

#[test]
fn three_independent_recipes_compile_without_provider_code() {
    for name in ["airtable", "todoist", "github"] {
        let recipe = compiled(name);
        assert!(recipe.review().origin().starts_with("https://"));
        assert_eq!(recipe.digest_hex().len(), 64);
        assert_eq!(recipe.review().maximum_body_bytes(), MAX_BODY_BYTES);
    }
}

#[test]
fn native_source_profile_admission_keeps_dependency_order_and_stable_errors() {
    let (raw_source, raw_lock) = fixture("airtable");
    let original_source: Value = serde_json::from_slice(raw_source).expect("source");
    let original_lock: Value = serde_json::from_slice(raw_lock).expect("lock");
    let refusal = |source: &Value, lock: &Value| {
        CompiledRecipe::compile(
            &serde_json::to_vec(source).expect("source JSON"),
            &serde_json::to_vec(lock).expect("lock JSON"),
        ).err().expect("invalid recipe refuses")
    };

    let mut source = original_source.clone();
    let mut lock = original_lock.clone();
    source["schema"] = json!("auths.gateway-recipe-source/1");
    lock["schema"] = json!("auths.self-hosted-profile-lock/2");
    assert_eq!(refusal(&source, &lock), GatewayRecipeError::InvalidSource);
    // Both input documents must parse before decoded source rules run.
    assert_eq!(CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("source"), b"{",
    ).err(), Some(GatewayRecipeError::InvalidProfileLock));

    source = original_source.clone();
    lock = original_lock.clone();
    source["service"] = json!("different-service");
    lock["version"] = json!(0);
    assert_eq!(refusal(&source, &lock), GatewayRecipeError::InvalidProfileLock);

    lock = original_lock.clone();
    lock["command_schema"]["fields"]["replacement"] = json!({"kind": "unsupported"});
    let digest = hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&lock["command_schema"]).expect("schema"),
    ));
    lock["schema_digest"] = json!(digest);
    source["profile_schema_digest"] = lock["schema_digest"].clone();
    assert_eq!(refusal(&source, &lock), GatewayRecipeError::ProfileMismatch);
    source["service"] = original_source["service"].clone();
    assert_eq!(refusal(&source, &lock), GatewayRecipeError::InvalidProfileLock);

    source = original_source.clone();
    source["operator_namespace"] = json!("");
    source["origin"] = json!("http://api.airtable.com");
    assert_eq!(refusal(&source, &original_lock), GatewayRecipeError::InvalidNamespace);
    source["operator_namespace"] = original_source["operator_namespace"].clone();
    source["write"]["body"] = json!({"kind": "json", "value": {"kind": "echo"}});
    assert_eq!(refusal(&source, &original_lock), GatewayRecipeError::UnsafeOrigin);
}

#[test]
fn admitted_source_owns_one_field_snapshot_for_lowering_and_original_source_digest() {
    let (raw_source, raw_lock) = fixture("airtable");
    let source: source::RecipeSource = serde_json::from_slice(raw_source).expect("source");
    let mut lock: ProfileLockFile = serde_json::from_slice(raw_lock).expect("lock");
    let original_lock: Value = serde_json::from_slice(raw_lock).expect("lock JSON");
    let expected_names: Vec<Vec<u8>> = original_lock["command_schema"]["fields"]
        .as_object().expect("fields").keys().map(|name| name.as_bytes().to_vec()).collect();
    let canonical = CanonicalRecipeInputs::from_decoded(&source, &lock);
    let checked = validate::validate_source(&source, &lock, &canonical).expect("admission");

    // The admitted handle owns parsed fields and retains an immutable source
    // borrow. Replacing the caller's lock cannot replace its admitted inputs.
    lock.command_schema = json!({"kind": "object", "fields": {"injected": {"kind": "boolean"}}});
    lock.service = "different-service".into();
    lock.schema_digest = "0".repeat(64);
    assert_eq!(validate_lock(&lock), Err(GatewayRecipeError::InvalidProfileLock));
    assert!(std::ptr::eq(checked.source(), &source));
    assert_eq!(checked.parsed_host(), "api.airtable.com");
    assert_eq!(checked.field_specs().iter().map(|field| field.name.clone()).collect::<Vec<_>>(), expected_names);
    let plans = lower::plans(&checked).expect("original admitted plans");
    assert_eq!(plans.field_schemas.iter().map(|field| field.name.clone()).collect::<Vec<_>>(), expected_names);

    let original_json: Value = serde_json::from_slice(raw_source).expect("original JSON");
    let mut original_preimage = b"auths.gateway-compiled-recipe/2\0".to_vec();
    original_preimage.extend(serde_json_canonicalizer::to_vec(&original_json).expect("canonical original JSON"));
    let expected_digest: [u8; 32] = Sha256::digest(&original_preimage).into();
    assert_eq!(checked.digest().expect("original source digest"), expected_digest);
    assert_eq!(checked.into_namespace().as_str(), "airtable-demo");
}

#[test]
fn canonical_member_choices_keep_echo_positions_and_original_values_against_serde() {
    let (raw_source, lock) = fixture("airtable");
    for pointer in ["/A0", "/aa", "/zz", "/a/A0", "/a/b0", "/a/zz"] {
        let mut source: Value = serde_json::from_slice(raw_source).expect("source");
        source["write"]["body"] = json!({"kind": "json", "value": {"kind": "object", "fields": {
            "z": {"kind": "string", "value": "tail/é"},
            "replacement": {"kind": "field", "name": "replacement"},
            "a": {"kind": "object", "fields": {
                "z": {"kind": "boolean", "value": true},
                "b": {"kind": "string", "value": "first\\\"\n"},
                "n": {"kind": "integer", "value": -17}
            }},
            "A": {"kind": "string", "value": "head"}
        }}});
        source["echo"]["write"] = json!({"kind": "json-pointer", "pointer": pointer});
        let recipe = CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source"), lock).expect("echo mapping");
        let arguments = arguments(&recipe, &json!({
            "operation_id": "echo-order-1", "record_id": "recTEST0000000001", "replacement": "Approved"
        }));
        oracle_request(&recipe, &arguments, [19; 32]);
        let request = recipe.closed_request_from_arguments(&arguments, [19; 32]).expect("request");
        let body: Value = serde_json::from_slice(request.body()).expect("body");
        assert_eq!(body.pointer(pointer).and_then(Value::as_str), request.echo_token());
        assert_eq!(body["replacement"], "Approved");
        assert_eq!(body["a"]["b"], "first\\\"\n");
        assert_eq!(body["a"]["n"], -17);
    }
    for echo_name in ["A0", "metadata[auths_echo]", "zz"] {
        let mut source: Value = serde_json::from_slice(raw_source).expect("source");
        source["write"]["body"] = json!({"kind": "form", "fields": {
            "z": {"kind": "field", "name": "replacement"},
            "a": {"kind": "string", "value": "a&b=é +%"}
        }});
        source["echo"]["write"] = json!({"kind": "form-field", "name": echo_name});
        let recipe = CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source"), lock).expect("form echo mapping");
        let arguments = arguments(&recipe, &json!({
            "operation_id": "echo-order-2", "record_id": "recTEST0000000001", "replacement": "Approved"
        }));
        oracle_request(&recipe, &arguments, [23; 32]);
        let request = recipe.closed_request_from_arguments(&arguments, [23; 32]).expect("request");
        let pairs: BTreeMap<_, _> = form_urlencoded::parse(request.body()).into_owned().collect();
        assert_eq!(pairs[echo_name], request.echo_token().expect("echo"));
        assert_eq!(pairs["z"], "Approved");
        assert_eq!(pairs["a"], "a&b=é +%");
    }
}

/// A reviewed JSON mapping that actually emits each scalar kind. This fixture
/// exercises conversion through source/lock compilation and native request
/// construction rather than passing preconverted values into the leaf.
fn scalar_projection_source_and_lock() -> (Value, Value) {
    let (source, lock) = fixture("airtable");
    let mut source: Value = serde_json::from_slice(source).expect("source");
    let mut lock: Value = serde_json::from_slice(lock).expect("lock");
    let schemas = json!({
        "a_text": {"kind": "string", "minimum": 0, "maximum": 64},
        "a_text_suffix": {"kind": "string", "minimum": 0, "maximum": 64},
        "number": {"kind": "integer", "minimum": -9007199254740991_i64, "maximum": 9007199254740991_i64},
        "flag": {"kind": "boolean"}
    });
    let fields = lock["command_schema"]["fields"].as_object_mut().expect("fields");
    fields.extend(schemas.as_object().expect("schemas").clone());
    source["write"]["body"]["value"]["fields"]["scalar_probe"] = json!({
        "kind": "object", "fields": {
            "text": {"kind": "field", "name": "a_text"},
            "similar": {"kind": "field", "name": "a_text_suffix"},
            "number": {"kind": "field", "name": "number"},
            "flag": {"kind": "field", "name": "flag"}
        }
    });
    let digest = hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&lock["command_schema"]).expect("schema"),
    ));
    lock["schema_digest"] = Value::String(digest.clone());
    source["profile_schema_digest"] = Value::String(digest);
    (source, lock)
}

fn scalar_projection_recipe() -> CompiledRecipe {
    let (source, lock) = scalar_projection_source_and_lock();
    CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("source"),
        &serde_json::to_vec(&lock).expect("lock"),
    ).expect("scalar mapping compiles")
}

#[test]
fn named_form_compilation_preserves_nested_json_echo_and_similar_fields_against_serde() {
    let (mut source, lock) = scalar_projection_source_and_lock();
    source["write"]["body"] = json!({
        "kind": "form", "fields": {
            "amount": {"kind": "field", "name": "number"},
            "literal": {"kind": "string", "value": "a&b=é +%"},
            "nested": {"kind": "json", "value": {"kind": "object", "fields": {
                "a": {"kind": "field", "name": "a_text"},
                "a.b": {"kind": "field", "name": "a_text_suffix"},
                "flag": {"kind": "field", "name": "flag"},
                "number": {"kind": "field", "name": "number"}
            }}},
            "replacement": {"kind": "field", "name": "replacement"}
        }
    });
    source["echo"]["write"] = json!({"kind": "form-field", "name": "metadata[auths_echo]"});
    let recipe = CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("source"),
        &serde_json::to_vec(&lock).expect("lock"),
    ).expect("form with nested JSON compiles");
    for number in [-9007199254740991_i64, -1, 0, 1, 9007199254740991] {
        for flag in [false, true] {
            for text in ["", "é\"\\\n/+&=%", "second is a distinct named field"] {
                let supplied = arguments(&recipe, &json!({
                    "operation_id": "form-names-1", "record_id": "recTEST0000000001",
                    "replacement": "Approved", "a_text": text,
                    "a_text_suffix": "not the first field", "number": number, "flag": flag
                }));
                oracle_request(&recipe, &supplied, [5; 32]);
                let request = recipe.closed_request_from_arguments(&supplied, [5; 32]).expect("request");
                let pairs: BTreeMap<_, _> = form_urlencoded::parse(request.body()).into_owned().collect();
                let nested: Value = serde_json::from_str(&pairs["nested"]).expect("decoded JSON");
                assert_eq!(nested, json!({"a": text, "a.b": "not the first field", "flag": flag, "number": number}));
                assert_eq!(pairs["literal"], "a&b=é +%");
                assert_eq!(pairs["amount"], number.to_string());
                assert_eq!(pairs["metadata[auths_echo]"], request.echo_token().expect("gateway echo"));
            }
        }
    }
}

#[test]
fn direct_boolean_form_field_refuses_while_integer_and_nested_boolean_remain_useful() {
    let (mut source, lock) = scalar_projection_source_and_lock();
    let original = source["write"]["body"]["value"].clone();
    source["write"]["body"] = json!({
        "kind": "form", "fields": {
            "direct": {"kind": "field", "name": "flag"},
            "nested": {"kind": "json", "value": original}
        }
    });
    source["echo"]["write"] = json!({"kind": "form-field", "name": "metadata[auths_echo]"});
    assert!(matches!(CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("source"),
        &serde_json::to_vec(&lock).expect("lock"),
    ), Err(GatewayRecipeError::UnsafeTemplate)));

    source["write"]["body"]["fields"]["direct"] = json!({"kind": "field", "name": "number"});
    let recipe = CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("source"),
        &serde_json::to_vec(&lock).expect("lock"),
    ).expect("integer direct form field and nested JSON Boolean compile");
    let supplied = arguments(&recipe, &json!({
        "operation_id": "form-kind-1", "record_id": "recTEST0000000001", "replacement": "Approved",
        "a_text": "text", "a_text_suffix": "other", "number": -17, "flag": true
    }));
    let request = recipe.closed_request_from_arguments(&supplied, [8; 32]).expect("typed form request");
    let pairs: BTreeMap<_, _> = form_urlencoded::parse(request.body()).into_owned().collect();
    assert_eq!(pairs["direct"], "-17");
    let nested: Value = serde_json::from_str(&pairs["nested"]).expect("nested JSON");
    assert_eq!(nested["scalar_probe"]["flag"], Value::Bool(true));
}

#[test]
fn schema_conversion_and_named_binding_preserve_complete_scalars_on_wire() {
    let recipe = scalar_projection_recipe();
    for number in [-9007199254740991_i64, -1, 0, 1, 9007199254740991] {
        for flag in [false, true] {
            for text in [String::new(), "é\"\\\n".to_owned(), "é".repeat(32)] {
                let arguments = arguments(&recipe, &json!({
                    "operation_id": "projection-1", "record_id": "recTEST0000000001",
                    "replacement": "Approved", "a_text": text,
                    "a_text_suffix": "other field", "number": number, "flag": flag
                }));
                // Independent profile-lock field order and preceding decimal
                // formatting, rather than another call to the shipping mapper.
                let expected = vec![
                    ArgumentValue::Text(text.as_bytes().to_vec()),
                    ArgumentValue::Text(b"other field".to_vec()),
                    ArgumentValue::Boolean(flag),
                    ArgumentValue::Integer(number.to_string().into_bytes()),
                    ArgumentValue::Text(b"projection-1".to_vec()),
                    ArgumentValue::Text(recipe.namespace().as_str().as_bytes().to_vec()),
                    ArgumentValue::Text(recipe.digest_hex().into_bytes()),
                    ArgumentValue::Text(b"recTEST0000000001".to_vec()),
                    ArgumentValue::Text(b"Approved".to_vec()),
                ];
                let admitted = recipe.request_arguments(&arguments).expect("binding");
                assert_eq!(admitted.values, expected);
                assert_eq!(admitted.operation_id, b"projection-1");
                let request = recipe.closed_request_from_arguments(&arguments, [7; 32]).expect("request");
                let body: Value = serde_json::from_slice(request.body()).expect("wire JSON");
                assert_eq!(body["scalar_probe"], json!({
                    "text": text, "similar": "other field", "number": number, "flag": flag
                }));
                oracle_request(&recipe, &arguments, [7; 32]);
            }
        }
    }
}

#[test]
fn write_observation_template_and_partial_read_use_one_compiled_field_layout() {
    let recipe = scalar_projection_recipe();
    let record = "recTEST0000000001/é";
    let supplied = arguments(&recipe, &json!({
        "operation_id": "layout-1", "record_id": record, "replacement": "Approved",
        "a_text": "first", "a_text_suffix": "second", "number": -1, "flag": false
    }));
    let request = recipe.closed_request_from_arguments(&supplied, [6; 32]).expect("request");
    let template = request.observation_template().expect("template");
    let restored = template.request(None).expect("resolved template");
    let partial = recipe.read_back_target(json!({"record_id": record}).as_object().expect("object")).expect("partial read");
    let expected = "https://api.airtable.com/v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001%2F%C3%A9";
    assert_eq!(request.url(), expected);
    assert_eq!(request.observation().expect("observation").url(), expected);
    assert_eq!(restored.url(), expected);
    assert_eq!(partial.url(), expected);
    assert_eq!(restored.expected(), &json!("Approved"));
    assert_eq!(
        field_projection::field_names(&recipe.plans.field_schemas).expect("layout"),
        ["a_text", "a_text_suffix", "flag", "number", "operation_id", "operator_namespace", "recipe_digest", "record_id", "replacement"]
            .map(|name| name.as_bytes().to_vec()).to_vec()
    );
}

#[test]
fn compiler_keeps_similar_source_names_distinct_and_renders_literal_integers_exactly() {
    let (source, lock) = fixture("airtable");
    let mut source: Value = serde_json::from_slice(source).expect("source");
    let mut lock: Value = serde_json::from_slice(lock).expect("lock");
    lock["command_schema"]["fields"]["record_id_suffix"] =
        json!({"kind": "string", "minimum": 17, "maximum": 43});
    source["observation"]["path"][3] = json!({"kind": "field", "name": "record_id_suffix"});
    let digest = hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&lock["command_schema"]).expect("schema"),
    ));
    lock["schema_digest"] = Value::String(digest.clone());
    source["profile_schema_digest"] = Value::String(digest);
    for literal in [-9007199254740991_i64, -1, 0, 9007199254740991] {
        source["write"]["body"]["value"]["fields"]["integer_literal"] =
            json!({"kind": "integer", "value": literal});
        let recipe = CompiledRecipe::compile(
            &serde_json::to_vec(&source).expect("source"),
            &serde_json::to_vec(&lock).expect("lock"),
        ).expect("declared paths and literals compile");
        let supplied = arguments(&recipe, &json!({
            "operation_id": "named-path-1", "record_id": "recTEST0000000001",
            "record_id_suffix": "recTEST0000000002", "replacement": "Approved"
        }));
        let request = recipe.closed_request_from_arguments(&supplied, [4; 32]).expect("request");
        assert!(request.url().ends_with("/recTEST0000000001"));
        let observation = request.observation().expect("observation");
        assert!(observation.url().ends_with("/recTEST0000000002"));
        let template = request.observation_template().expect("template").request(None).expect("resolved");
        assert_eq!(template.url(), observation.url());
        let body: Value = serde_json::from_slice(request.body()).expect("body JSON");
        assert_eq!(body["integer_literal"], json!(literal));
        oracle_request(&recipe, &supplied, [4; 32]);
    }
}

#[test]
fn compiler_origin_is_exact_bounded_and_preserves_dns_policy_classes() {
    assert_eq!(validate_origin("https://api.example.com"), Ok("api.example.com".to_owned()));
    for origin in [
        "HTTPS://api.example.com", " https://api.example.com", "https:////api.example.com",
        "https://api.example.com/", "https://user@api.example.com", "https://api.example.com:443",
        "https://api.example.com?x=1", "https://api.example.com#x", "https://API.example.com",
        "https://localhost", "https://localhost.", "https://x.localhost.",
        "https://service.local.", "https://service.internal.",
    ] {
        assert_eq!(validate_origin(origin), Err(GatewayRecipeError::UnsafeOrigin), "{origin}");
    }
    let excessive_slashes = format!("https:{}api.example.com", "/".repeat(300));
    assert_eq!(validate_origin(&excessive_slashes), Err(GatewayRecipeError::UnsafeOrigin));
}

#[test]
fn byte_domain_policy_retains_the_original_string_policy() {
    fn reference(domain: &str) -> bool {
        let policy = domain.strip_suffix('.').unwrap_or(domain);
        domain.len() <= 253
            && policy != "localhost"
            && !policy.ends_with(".localhost")
            && policy.split('.').next_back() != Some("local")
            && !policy.ends_with(".internal")
            && policy.contains('.')
    }
    for domain in [
        "", "localhost", "localhost.", "x.localhost", "x.localhost.",
        "local", "local.", "x.local", "x.local.", "x.internal", "x.internal.",
        "example.com", "example.com.", "example.com..", "localhost..",
        "LOCALHOST.example", "x.local.example", "x.internal.example", "é.example",
        ".local", ".internal", ".", "..",
    ] {
        assert_eq!(origin_domain_allowed(domain), reference(domain), "{domain}");
    }
    for length in [250, 251, 252] {
        let domain = format!("{}.a", "x".repeat(length));
        assert_eq!(origin_domain_allowed(&domain), reference(&domain), "{} bytes", domain.len());
        let dotted = format!("{domain}.");
        assert_eq!(origin_domain_allowed(&dotted), reference(&dotted), "{} bytes", dotted.len());
    }
}

#[test]
fn named_binding_retains_schema_refusals_before_request_construction() {
    let recipe = scalar_projection_recipe();
    let valid = arguments(&recipe, &json!({
        "operation_id": "projection-1", "record_id": "recTEST0000000001",
        "replacement": "Approved", "a_text": "first", "a_text_suffix": "second",
        "number": 1, "flag": true
    }));
    for (field, invalid) in [
        ("number", json!(9007199254740992_u64)),
        ("number", json!(-9007199254740992_i64)),
        ("number", json!(1.0)),
        ("flag", json!(1)),
        ("a_text", json!("a\0b")),
        ("a_text", json!("é".repeat(33))),
        ("replacement", json!("Other")),
    ] {
        let mut hostile = valid.clone();
        hostile.insert(field.to_owned(), invalid);
        assert_eq!(recipe.closed_request_from_arguments(&hostile, [7; 32]).unwrap_err(), GatewayRecipeError::ActionMismatch);
    }
    let mut renamed = valid.clone();
    let value = renamed.remove("a_text").expect("field");
    renamed.insert("A_text".into(), value);
    assert_eq!(recipe.request_arguments(&renamed), Err(GatewayRecipeError::ActionMismatch));
}

/// Frozen pre-cutover scalar interpretation. It deliberately keeps the
/// standard string formatter and iterator/range checks as an independent
/// oracle for the new arithmetic/scanning kernel used in shipping code.
fn frozen_scalar_projection(schema: &Value, value: &Value) -> Option<ArgumentValue> {
    if schema["type"].as_str() == Some("enum") {
        let text = value.as_str()?;
        return schema["variants"].as_array()?.iter().any(|variant| variant.as_str() == Some(text))
            .then(|| ArgumentValue::Text(text.as_bytes().to_vec()));
    }
    match schema["kind"].as_str()? {
        "string" => {
            let text = value.as_str()?;
            let minimum = usize::try_from(schema["minimum"].as_u64()?).ok()?;
            let maximum = usize::try_from(schema["maximum"].as_u64()?).ok()?;
            ((minimum..=maximum).contains(&text.len()) && text.as_bytes().iter().all(|byte| *byte != 0))
                .then(|| ArgumentValue::Text(text.as_bytes().to_vec()))
        }
        "integer" => {
            let number = value.as_i64()?;
            let minimum = schema["minimum"].as_i64()?;
            let maximum = schema["maximum"].as_i64()?;
            (minimum..=maximum).contains(&number)
                .then(|| ArgumentValue::Integer(number.to_string().into_bytes()))
        }
        "boolean" => value.as_bool().map(ArgumentValue::Boolean),
        _ => None,
    }
}

#[test]
fn every_scalar_kind_retains_frozen_validation_and_projection() {
    let schemas = [
        json!({"kind": "string", "minimum": 0, "maximum": 0}),
        json!({"kind": "string", "minimum": 1, "maximum": 1}),
        json!({"kind": "string", "minimum": 2, "maximum": 64}),
        json!({"kind": "string", "minimum": 0, "maximum": 4096}),
        json!({"type": "enum", "variants": ["first", "second:_-.9"]}),
        json!({"kind": "integer", "minimum": -9007199254740991_i64, "maximum": 9007199254740991_i64}),
        json!({"kind": "integer", "minimum": -1, "maximum": 1}),
        json!({"kind": "boolean"}),
    ];
    let values = [
        Value::Null, json!([]), json!({}), json!(false), json!(true), json!(""),
        json!("x"), json!("é"), json!("a\0b"), json!("first"), json!("second:_-.9"),
        json!("First"), json!("é".repeat(32)), json!("x".repeat(4096)), json!("x".repeat(4097)),
        json!(i64::MIN), json!(-9007199254740992_i64), json!(-9007199254740991_i64),
        json!(-1), json!(0), json!(1), json!(9007199254740991_i64),
        json!(9007199254740992_i64), json!(i64::MAX), json!(u64::MAX), json!(1.0), json!(-0.0),
    ];
    for schema in schemas {
        let parsed = parse_field_schema(&schema).expect("admitted schema");
        for value in &values {
            let expected = frozen_scalar_projection(&schema, value);
            assert_eq!(parsed.validate_value(value), expected.is_some(), "{schema}: {value}");
            assert_eq!(parsed.argument_value(value), expected, "{schema}: {value}");
        }
    }
}

#[test]
fn scalar_schema_limits_preserve_exact_profile_lock_refusals() {
    for schema in [
        json!({"kind": "string", "minimum": 2, "maximum": 1}),
        json!({"kind": "string", "minimum": 0, "maximum": 4097}),
        json!({"kind": "integer", "minimum": 2, "maximum": 1}),
        json!({"kind": "integer", "minimum": -9007199254740992_i64, "maximum": 1}),
        json!({"kind": "integer", "minimum": 0, "maximum": 9007199254740992_i64}),
        json!({"type": "enum", "variants": []}),
        json!({"type": "enum", "variants": ["same", "same"]}),
        json!({"type": "enum", "variants": ["é"]}),
        json!({"type": "enum", "variants": ["a\0b"]}),
        json!({"type": "enum", "variants": ["x".repeat(65)]}),
        json!({"kind": "boolean", "extra": true}),
        json!({"kind": "string", "minimum": 1.0, "maximum": 4}),
        json!({"kind": "string", "minimum": -0.0, "maximum": 4}),
        json!({"kind": "integer", "minimum": 0, "maximum": 1.0}),
        json!({"kind": "integer", "minimum": 0, "maximum": u64::MAX}),
        json!({"kind": "boolean", "type": "enum", "variants": ["a"]}),
    ] {
        assert!(matches!(parse_field_schema(&schema), Err(GatewayRecipeError::InvalidProfileLock)));
    }
}

#[test]
fn profile_parser_retains_raw_integer_kinds_and_kernel_produced_field_pairs() {
    for name in ["airtable", "todoist", "github"] {
        let (source, lock) = fixture(name);
        let lock_value: Value = serde_json::from_slice(lock).expect("lock");
        let fields = parse_root_fields(&lock_value["command_schema"]).expect("root");
        let rule_fields = profile::rule_fields(&fields).expect("ASCII fields");
        let original_names: Vec<_> = lock_value["command_schema"]["fields"].as_object().expect("fields")
            .keys().map(|name| name.as_bytes().to_vec()).collect();
        assert_eq!(fields.iter().map(|field| field.name.clone()).collect::<Vec<_>>(), original_names);
        for field in &fields {
            let native_name = std::str::from_utf8(&field.name).expect("ASCII token");
            assert_eq!(rule_fields.get(native_name), Some(&field.schema));
        }
        let compiled = CompiledRecipe::compile(source, lock).expect("recipe");
        assert_eq!(compiled.plans.field_schemas, fields);
        assert!(auths_gateway_kernel::profile_schema::binding_fields_match(
            &fields, compiled.namespace().as_str().as_bytes(),
        ));
    }
    for numeric in [json!(0.0), json!(-0.0), json!(1.0), json!("0"), json!(true), Value::Null] {
        let schema = json!({"kind": "string", "minimum": numeric, "maximum": 4});
        assert_eq!(parse_field_schema(&schema), Err(GatewayRecipeError::InvalidProfileLock));
    }
    let schema: Value = serde_json::from_str("{\"kind\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991}").expect("integer source");
    assert_eq!(parse_field_schema(&schema), Ok(FieldSchema::Integer { minimum: 0, maximum: 9_007_199_254_740_991 }));
}

#[test]
fn native_rule_map_refuses_duplicate_pairs_and_invalid_utf8_without_overwrite() {
    use auths_gateway_kernel::field_projection::FieldSpec;
    let first = FieldSpec { name: b"same".to_vec(), schema: FieldSchema::Boolean };
    let second = FieldSpec { name: b"same".to_vec(), schema: FieldSchema::String { minimum: 1, maximum: 4 } };
    assert_eq!(profile::rule_fields(&[first.clone(), second]).err(), Some(GatewayRecipeError::InvalidProfileLock));
    let invalid = FieldSpec { name: vec![0xff], schema: FieldSchema::Boolean };
    assert_eq!(profile::rule_fields(&[invalid]).err(), Some(GatewayRecipeError::InvalidProfileLock));
    let similar = FieldSpec { name: b"same_suffix".to_vec(), schema: FieldSchema::Integer { minimum: -1, maximum: 1 } };
    let fields = profile::rule_fields(&[similar, first]).expect("distinct original names");
    assert_eq!(fields.len(), 2);
    assert_eq!(fields.get("same"), Some(&FieldSchema::Boolean));
    assert_eq!(fields.get("same_suffix"), Some(&FieldSchema::Integer { minimum: -1, maximum: 1 }));
}

#[test]
fn native_echo_tokenization_keeps_exact_names_through_request_lowering() {
    let (raw, lock) = fixture("airtable");
    for name in ["A0", "a.b", "b_0-c", "z" ] {
        let mut source: Value = serde_json::from_slice(raw).expect("source");
        let pointer = format!("/fields/{name}");
        source["echo"]["write"] = json!({"kind": "json-pointer", "pointer": pointer.clone()});
        let recipe = CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source JSON"), lock).expect("original-name echo");
        let values = arguments(&recipe, &json!({"operation_id": "pointer-1", "record_id": "recTEST0000000001", "replacement": "Approved"}));
        oracle_request(&recipe, &values, [31; 32]);
        let request = recipe.closed_request_from_arguments(&values, [31; 32]).expect("request");
        let rendered: Value = serde_json::from_slice(request.body()).expect("rendered JSON");
        assert_eq!(rendered.pointer(&pointer).and_then(Value::as_str), request.echo_token());
    }
    for pointer in ["", "fields/echo", "/", "/fields/", "/fields//echo", "/fields/a~0b", "/fields/a%2Fb", "/fields/é"] {
        let mut source: Value = serde_json::from_slice(raw).expect("source");
        source["echo"]["write"] = json!({"kind": "json-pointer", "pointer": pointer});
        assert_eq!(CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source JSON"), lock).err(),
            Some(GatewayRecipeError::EchoConflict));
    }
}

#[test]
fn json_scalar_carrier_is_selected_by_actual_kind_without_coercion() {
    let text = json!("\0é e\u{301}\"\\");
    assert_eq!(scalar_input(&text), scalars::ScalarInput::Text("\0é e\u{301}\"\\".as_bytes()));
    for integer in [i64::MIN, -9007199254740991, -1, 0, 1, 9007199254740991, i64::MAX] {
        let value = json!(integer);
        assert_eq!(scalar_input(&value), scalars::ScalarInput::Integer(integer));
    }
    for value in [
        Value::Null, json!([]), json!({}), json!(1.0), json!(-0.0),
        json!(9223372036854775808_u64), json!(u64::MAX),
    ] {
        assert_eq!(scalar_input(&value), scalars::ScalarInput::Unsupported);
    }
    for flag in [false, true] {
        let value = json!(flag);
        assert_eq!(scalar_input(&value), scalars::ScalarInput::Boolean(flag));
    }
    let string_number = json!("1");
    assert_eq!(scalar_input(&string_number), scalars::ScalarInput::Text(b"1"));
    assert_eq!(
        scalars::project_scalar(&FieldSchema::Integer { minimum: 0, maximum: 2 }, scalar_input(&string_number)),
        None
    );
}

#[test]
fn hostile_recipe_corpus_fails_with_exact_codes() {
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../../../bindings/fixtures/gateway/hostile-recipes.json"
    ))
    .expect("valid corpus");
    assert_eq!(
        corpus.get("schema").and_then(Value::as_str),
        Some("auths.gateway-hostile-recipes/1")
    );
    for case in corpus["cases"].as_array().expect("cases") {
        let base = case["base"].as_str().expect("base");
        let pointer = case["pointer"].as_str().expect("pointer");
        let expected = case["code"].as_str().expect("code");
        let (source, lock) = fixture(base);
        let mut mutated: Value = serde_json::from_slice(source).expect("recipe JSON");
        let value = case["value"].clone();
        if pointer.ends_with("/items/1") {
            mutated
                .pointer_mut("/write/body/fields/commands/value/items")
                .and_then(Value::as_array_mut)
                .expect("array")
                .push(value);
        } else if let Some(existing) = mutated.pointer_mut(pointer) {
            *existing = value;
        } else {
            let (parent, key) = pointer.rsplit_once('/').expect("child pointer");
            mutated
                .pointer_mut(parent)
                .and_then(Value::as_object_mut)
                .expect("existing parent object")
                .insert(key.to_owned(), value);
        }
        let bytes = serde_json::to_vec(&mutated).expect("fixture JSON");
        let result = CompiledRecipe::compile(&bytes, lock).expect_err("hostile recipe");
        assert_eq!(result.code(), expected, "{}", case["id"]);
    }
}

/// Compiles the Airtable fixture with `extra` profile fields and an
/// optional precondition block, recomputing the lock digest.
fn with_preconditions(
    extra: &Value,
    preconditions: Option<Value>,
    without_observation: bool,
) -> Result<CompiledRecipe, GatewayRecipeError> {
    let (source, lock) = fixture("airtable");
    let mut lock: Value = serde_json::from_slice(lock).expect("lock");
    for (key, value) in extra.as_object().expect("extra") {
        lock["command_schema"]["fields"][key] = value.clone();
    }
    let digest = hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&lock["command_schema"]).expect("schema"),
    ));
    lock["schema_digest"] = Value::String(digest.clone());
    let mut source: Value = serde_json::from_slice(source).expect("source");
    source["profile_schema_digest"] = Value::String(digest);
    if let Some(preconditions) = preconditions {
        source["preconditions"] = preconditions;
    }
    if without_observation {
        let object = source.as_object_mut().expect("object");
        object.remove("observation");
        object.remove("echo");
    }
    CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("source"),
        &serde_json::to_vec(&lock).expect("lock"),
    )
}

fn precondition_fields() -> Value {
    json!({
        "expected": {"type": "enum", "variants": ["Approved", "Pending"]},
        "record_uri": {"kind": "string", "minimum": 1, "maximum": 256},
        "count": {"kind": "integer", "minimum": 0, "maximum": 10},
        "signed": {"kind": "integer", "minimum": -1, "maximum": 10},
        "flag": {"kind": "boolean"},
        "long": {"kind": "string", "minimum": 1, "maximum": 257}
    })
}

#[test]
fn preconditions_are_closed_reviewed_and_digest_bound() {
    let extra = precondition_fields();
    let all = json!({
        "read_back_subject": "record_uri",
        "verified": ["expected", "count", "signed", "flag", "long"]
    });
    assert_eq!(
        with_preconditions(&extra, Some(all), false).err(),
        Some(GatewayRecipeError::PreconditionConflict),
        "signed integers, booleans, and over-bound strings have no fact form"
    );
    let unused = json!({"expected": extra["expected"], "record_uri": extra["record_uri"]});
    let good = json!({"read_back_subject": "record_uri", "verified": ["expected"]});
    let recipe = with_preconditions(&unused, Some(good.clone()), false).expect("compiles");
    assert_ne!(recipe.digest(), compiled("airtable").digest());
    let review = recipe.review();
    let preconditions = review.preconditions().expect("reviewed");
    assert_eq!(preconditions.read_back_subject(), Some("record_uri"));
    assert_eq!(preconditions.verified(), ["expected"]);
    assert!(
        preconditions
            .disclosure()
            .contains("never sent to the provider")
    );
    assert!(compiled("airtable").review().preconditions().is_none());
    assert_eq!(
        with_preconditions(&unused, None, false).err(),
        Some(GatewayRecipeError::UnsafeTemplate),
        "an argument no request uses still needs an explicit declaration"
    );
    assert_eq!(
        with_preconditions(&unused, Some(good), true).err(),
        Some(GatewayRecipeError::PreconditionWithoutObservation)
    );
    for (hostile, code) in [
        (json!({}), GatewayRecipeError::InvalidSource),
        (
            json!({"verified": ["expected"], "extra": 1}),
            GatewayRecipeError::InvalidSource,
        ),
        (
            json!({"read_back_subject": "record_uri", "verified": ["replacement", "expected"]}),
            GatewayRecipeError::PreconditionConflict,
        ),
        (
            json!({"read_back_subject": "record_uri", "verified": ["expected", "operation_id"]}),
            GatewayRecipeError::PreconditionConflict,
        ),
        (
            json!({"read_back_subject": "record_uri", "verified": ["expected", "expected"]}),
            GatewayRecipeError::PreconditionConflict,
        ),
        (
            json!({"read_back_subject": "expected", "verified": ["record_uri"]}),
            GatewayRecipeError::PreconditionConflict,
        ),
        (
            json!({"read_back_subject": "record_uri", "verified": ["expected", "record_uri"]}),
            GatewayRecipeError::PreconditionConflict,
        ),
    ] {
        assert_eq!(
            with_preconditions(&unused, Some(hostile.clone()), false).err(),
            Some(code),
            "{hostile}"
        );
    }
    let many: Value = (0..9)
        .map(|index| {
            (
                format!("v{index}"),
                json!({"type": "enum", "variants": ["a"]}),
            )
        })
        .collect::<Map<_, _>>()
        .into();
    let names: Vec<String> = (0..9).map(|index| format!("v{index}")).collect();
    assert_eq!(
        with_preconditions(&many, Some(json!({"verified": names})), false).err(),
        Some(GatewayRecipeError::PreconditionConflict)
    );
}

#[test]
fn read_back_subject_must_name_exactly_the_observed_record() {
    let extra = json!({
        "expected": {"type": "enum", "variants": ["Approved", "Pending"]},
        "record_uri": {"kind": "string", "minimum": 1, "maximum": 256}
    });
    let recipe = with_preconditions(
        &extra,
        Some(json!({"read_back_subject": "record_uri", "verified": ["expected"]})),
        false,
    )
    .expect("recipe");
    let subject = "https://api.airtable.com/v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001#/fields/DemoStatus";
    let request = |uri: &str| {
        recipe.closed_request_from_arguments(
            &arguments(
                &recipe,
                &json!({"operation_id": "run-1", "record_id": "recTEST0000000001",
                    "replacement": "Approved", "expected": "Pending", "record_uri": uri}),
            ),
            [1; 32],
        )
    };
    let closed = request(subject).expect("matching subject");
    assert_eq!(
        closed.observation().expect("observation").subject(),
        subject
    );
    assert!(!String::from_utf8_lossy(closed.body()).contains("Pending"));
    for hostile in [
        subject.replace("0001#", "0002#"),
        subject.replace("DemoStatus", "Other"),
        subject.trim_end_matches("#/fields/DemoStatus").to_owned(),
    ] {
        assert_eq!(
            request(&hostile).err(),
            Some(GatewayRecipeError::PreconditionSubjectMismatch)
        );
    }
}

#[test]
fn read_back_target_takes_exactly_the_observation_path_fields() {
    let recipe = compiled("airtable");
    let target = |value: Value| recipe.read_back_target(value.as_object().expect("object"));
    let closed = target(json!({"record_id": "recTEST0000000001"})).expect("target");
    assert_eq!(
        closed.url(),
        "https://api.airtable.com/v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001"
    );
    assert_eq!(closed.expected(), &Value::Null);
    assert_eq!(
        closed.observed_values(br#"{"fields":{"DemoStatus":"Pending","auths_echo":null}}"#),
        Some((json!("Pending"), None))
    );
    assert_eq!(closed.observed_values(br#"{"fields":{}}"#), None);
    for hostile in [
        json!({}),
        json!({"record_id": "short"}),
        json!({"record_id": "recTEST0000000001", "replacement": "Approved"}),
        json!({"url": "https://attacker.example"}),
    ] {
        assert_eq!(
            target(hostile).err(),
            Some(GatewayRecipeError::ActionMismatch)
        );
    }
    assert!(
        compiled("github").read_back_target(&Map::new()).is_err(),
        "a recipe without an observation has no read-back"
    );
}

#[test]
fn airtable_closed_request_uses_only_bound_values() {
    let recipe = compiled("airtable");
    let arguments = arguments(
        &recipe,
        &json!({
            "operation_id": "run-123",
            "record_id": "recTEST0000000001",
            "replacement": "Approved"
        }),
    );
    let request = recipe
        .closed_request_from_arguments(&arguments, [5; 32])
        .expect("closed request");
    assert_eq!(request.method(), WriteMethod::Patch);
    assert_eq!(
        request.url(),
        "https://api.airtable.com/v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001"
    );
    let token = echo_token(
        recipe.namespace(),
        &LogicalOperationId::parse("run-123").expect("operation"),
        &[5; 32],
    );
    assert_eq!(request.echo_token(), Some(token.as_str()));
    assert_eq!(
        request.body(),
        format!(r#"{{"fields":{{"DemoStatus":"Approved","auths_echo":"{token}"}}}}"#).as_bytes()
    );
    let observation = request.observation().expect("read-back declared");
    assert_eq!(observation.json_pointer(), "/fields/DemoStatus");
    assert_eq!(observation.expected(), "Approved");
    assert_eq!(observation.echo_pointer(), Some("/fields/auths_echo"));
}

#[test]
fn echo_token_is_domain_separated_and_bound_to_every_input() {
    let namespace = OperatorNamespace::parse("airtable-demo").expect("namespace");
    let operation = LogicalOperationId::parse("run-1").expect("operation");
    let token = echo_token(&namespace, &operation, &[1; 32]);
    let mut preimage = b"auths.gateway-echo/1\0airtable-demo\0run-1\0".to_vec();
    preimage.extend_from_slice(&[1; 32]);
    assert_eq!(
        token,
        format!("auths-e1-{}", hex::encode(Sha256::digest(&preimage)))
    );
    assert_eq!(token.len(), 73);
    assert_ne!(token, echo_token(&namespace, &operation, &[2; 32]));
    assert_ne!(
        token,
        echo_token(
            &namespace,
            &LogicalOperationId::parse("run-2").expect("operation"),
            &[1; 32]
        )
    );
    assert_ne!(
        token,
        echo_token(
            &OperatorNamespace::parse("other").expect("namespace"),
            &operation,
            &[1; 32]
        )
    );
}

#[test]
fn derived_token_cutover_matches_frozen_incremental_hashing_at_input_bounds() {
    for namespace_bytes in ["a".to_owned(), "n".repeat(64)] {
        for operation_bytes in ["b".to_owned(), "o".repeat(128)] {
            let namespace = OperatorNamespace::parse(&namespace_bytes).expect("namespace");
            let operation = LogicalOperationId::parse(&operation_bytes).expect("operation");
            for byte in [0, 1, 127, 255] {
                let commitment = [byte; 32];
                let mut old = Sha256::new();
                old.update(b"auths.gateway-echo/1\0");
                old.update(namespace_bytes.as_bytes());
                old.update([0]);
                old.update(operation_bytes.as_bytes());
                old.update([0]);
                old.update(commitment);
                let expected = format!("auths-e1-{}", hex::encode(old.finalize()));
                let actual = echo_token(&namespace, &operation, &commitment);
                assert_eq!(actual, expected);
                assert_eq!(actual.len(), 73);
                assert!(actual.is_ascii());
            }
            let mut old = Sha256::new();
            old.update(b"auths.gateway-idempotency-key/1\0");
            old.update(namespace_bytes.as_bytes());
            old.update([0]);
            old.update(operation_bytes.as_bytes());
            let expected = format!("auths-i1-{}", hex::encode(old.finalize()));
            let actual = idempotency_key(&namespace, &operation);
            assert_eq!(actual, expected);
            assert_eq!(actual.len(), 73);
            assert!(actual.is_ascii());
        }
    }
}

#[test]
fn idempotency_key_is_domain_separated_and_bound_to_namespace_and_operation() {
    let namespace = |value| OperatorNamespace::parse(value).expect("namespace");
    let operation = |value| LogicalOperationId::parse(value).expect("operation");
    let key = idempotency_key(&namespace("stripe-refunds"), &operation("refund-1"));
    assert_eq!(
        key,
        format!(
            "auths-i1-{}",
            hex::encode(Sha256::digest(
                b"auths.gateway-idempotency-key/1\0stripe-refunds\0refund-1"
            ))
        )
    );
    assert_eq!(key.len(), 73);
    assert_eq!(
        key,
        idempotency_key(&namespace("stripe-refunds"), &operation("refund-1")),
        "deterministic"
    );
    assert_ne!(
        key,
        idempotency_key(&namespace("stripe-refunds"), &operation("refund-2"))
    );
    assert_ne!(
        key,
        idempotency_key(&namespace("other"), &operation("refund-1"))
    );
    assert_ne!(
        idempotency_key(&namespace("ab"), &operation("c")),
        idempotency_key(&namespace("a"), &operation("bc")),
        "the separator keeps the two fields apart"
    );
    let replay = crate::GatewayAttemptKey::for_operation(
        &namespace("stripe-refunds"),
        &operation("refund-1"),
    );
    assert_ne!(key[9..], hex::encode(replay.as_bytes()), "own hash domain");
}

/// Compiles fixture `name` with `write.idempotency_key` set to `value`.
fn with_idempotency(name: &str, value: Value) -> Result<CompiledRecipe, GatewayRecipeError> {
    let (source, lock) = fixture(name);
    let mut source: Value = serde_json::from_slice(source).expect("source");
    source["write"]["idempotency"] = value;
    CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source"), lock)
}

fn derived_header() -> Value {
    json!({"kind": "derived-header", "retention_seconds": 86_400})
}

#[test]
fn idempotency_is_opt_in_reviewed_and_digest_bound() {
    for name in ["airtable", "todoist", "github"] {
        let (source, _) = fixture(name);
        let plain = compiled(name);
        let mut preimage = b"auths.gateway-compiled-recipe/2\0".to_vec();
        preimage.extend(
            serde_json_canonicalizer::to_vec(
                &serde_json::from_slice::<Value>(source).expect("source"),
            )
            .expect("canonical source"),
        );
        assert_eq!(
            plain.digest_hex(),
            hex::encode(Sha256::digest(&preimage)),
            "{name}: an undeclared mechanism adds nothing to the canonical source"
        );
        assert!(!plain.review().sends_idempotency_key());
        let declared = with_idempotency(name, derived_header()).expect("declared");
        assert_ne!(
            declared.digest(),
            plain.digest(),
            "{name}: needs a new approval"
        );
        assert!(declared.review().sends_idempotency_key());
        let longer = with_idempotency(
            name,
            json!({"kind": "derived-header", "retention_seconds": 86_401}),
        )
        .expect("declared");
        assert_ne!(
            longer.digest(),
            declared.digest(),
            "{name}: retention is bound"
        );
    }
}

#[test]
fn closed_request_carries_the_derived_key_only_when_declared() {
    let values = |operation: &str, replacement: &str| {
        json!({"operation_id": operation, "record_id": "recTEST0000000001",
            "replacement": replacement})
    };
    let plain = compiled("airtable");
    let undeclared = plain
        .closed_request_from_arguments(&arguments(&plain, &values("run-7", "Approved")), [1; 32])
        .expect("request");
    assert_eq!(undeclared.idempotency_key(), None);
    assert!(undeclared.headers().is_empty());
    let recipe = with_idempotency("airtable", derived_header()).expect("declared");
    let request = |operation: &str, replacement: &str, commitment: [u8; 32]| {
        recipe
            .closed_request_from_arguments(
                &arguments(&recipe, &values(operation, replacement)),
                commitment,
            )
            .expect("request")
    };
    let first = request("run-7", "Approved", [1; 32]);
    let key = idempotency_key(
        recipe.namespace(),
        &LogicalOperationId::parse("run-7").expect("operation"),
    );
    assert_eq!(first.idempotency_key(), Some(key.as_str()));
    assert_eq!(
        first
            .headers()
            .iter()
            .map(|header| (header.name(), header.value()))
            .collect::<Vec<_>>(),
        [("Idempotency-Key", key.as_str())]
    );
    assert!(
        first
            .observation()
            .expect("observation")
            .headers()
            .is_empty(),
        "no read sends the key"
    );
    assert!(!String::from_utf8_lossy(first.body()).contains(&key));
    assert!(!first.url().contains(&key));
    let reentered = request("run-7", "Pending", [2; 32]);
    assert_ne!(reentered.echo_token(), first.echo_token());
    assert_eq!(
        reentered.idempotency_key(),
        first.idempotency_key(),
        "a fresh challenge or changed action for the same logical operation sends the same key"
    );
    assert_ne!(
        request("run-8", "Approved", [1; 32]).idempotency_key(),
        first.idempotency_key()
    );
    let declared_field = with_idempotency(
        "todoist",
        json!({"kind": "operation-id-field",
            "location": {"form_field": "commands", "pointer": "/0/uuid"},
            "retention_seconds": 3600}),
    )
    .expect("operation-id field");
    assert!(!declared_field.review().sends_idempotency_key());
}

#[test]
fn echo_changes_the_digest_and_is_shown_in_review() {
    let recipe = compiled("airtable");
    let review = recipe.review();
    let echo = review.echo().expect("airtable declares echo");
    assert_eq!(echo.write(), "/fields/auths_echo");
    assert_eq!(echo.observe(), "/fields/auths_echo");
    assert!(echo.disclosure().contains("anyone who can read the record"));
    assert!(echo.disclosure().contains("secrets"));
    let (source, lock) = fixture("airtable");
    let mut without: Value = serde_json::from_slice(source).expect("source");
    without.as_object_mut().expect("object").remove("echo");
    let plain = CompiledRecipe::compile(&serde_json::to_vec(&without).expect("source"), lock)
        .expect("recipe without echo");
    assert_ne!(plain.digest(), recipe.digest());
    assert!(plain.review().echo().is_none());
    for name in ["todoist", "github"] {
        assert!(compiled(name).review().echo().is_none());
    }
}

#[test]
fn read_back_links_only_an_exact_token_with_the_verified_value() {
    let recipe = compiled("airtable");
    let args = arguments(
        &recipe,
        &json!({"operation_id": "run-9", "record_id": "recTEST0000000001", "replacement": "Approved"}),
    );
    let request = recipe
        .closed_request_from_arguments(&args, [3; 32])
        .expect("request");
    let token = request.echo_token().expect("token");
    let observation = request.observation().expect("observation");
    let read = |fields: Value| {
        observation.read_back(
            Some(token),
            &serde_json::to_vec(&json!({"fields": fields})).expect("bytes"),
        )
    };
    assert_eq!(
        read(json!({"DemoStatus": "Approved", "auths_echo": token})),
        Some(ReadBack::EchoMatched)
    );
    assert_eq!(
        read(json!({"DemoStatus": "Pending", "auths_echo": token})),
        Some(ReadBack::Value { matched: false })
    );
    assert_eq!(
        read(json!({"DemoStatus": "Approved", "auths_echo": "auths-e1-other"})),
        Some(ReadBack::EchoMismatch)
    );
    assert_eq!(
        read(json!({"DemoStatus": "Approved", "auths_echo": 7})),
        Some(ReadBack::EchoMismatch)
    );
    assert_eq!(
        read(json!({"DemoStatus": "Approved"})),
        Some(ReadBack::Value { matched: true })
    );
    assert_eq!(
        read(json!({"DemoStatus": "Approved", "auths_echo": null})),
        Some(ReadBack::Value { matched: true })
    );
    assert_eq!(read(json!({"auths_echo": token})), None);
    assert_eq!(observation.read_back(Some(token), b"not json"), None);
}

#[test]
fn todoist_sync_body_is_compiler_serialized_one_command() {
    let recipe = compiled("todoist");
    let arguments = arguments(
        &recipe,
        &json!({
            "operation_id": "f38bff5f-430e-4fe1-814b-6e43690a641f",
            "content": "Auths gateway test",
            "description": "Auths demo run f38bff5f-430e-4fe1-814b-6e43690a641f",
            "temp_id": "f5034de3-4de1-42e0-bb54-70a340226f0e"
        }),
    );
    let request = recipe
        .closed_request_from_arguments(&arguments, [0; 32])
        .expect("closed request");
    assert_eq!(request.method(), WriteMethod::Post);
    assert_eq!(request.echo_token(), None);
    assert_eq!(request.url(), "https://api.todoist.com/api/v1/sync");
    let form: BTreeMap<String, String> = form_urlencoded::parse(request.body())
        .into_owned()
        .collect();
    assert_eq!(form.len(), 1);
    let commands: Value = serde_json::from_str(&form["commands"]).expect("JSON form field");
    assert_eq!(commands.as_array().expect("array").len(), 1);
    assert_eq!(commands[0]["type"], "item_add");
}

#[test]
fn form_body_renders_an_integer_field_as_decimal_text() {
    let schema = json!({"kind": "object", "fields": {
        "operation_id": {"kind": "string", "minimum": 1, "maximum": 128},
        "operator_namespace": {"type": "enum", "variants": ["refunds"]},
        "recipe_digest": {"kind": "string", "minimum": 64, "maximum": 64},
        "payment_intent": {"kind": "string", "minimum": 3, "maximum": 255},
        "amount": {"kind": "integer", "minimum": 1, "maximum": 99_999_999}
    }});
    let digest = hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&schema).expect("canonical schema"),
    ));
    let lock = json!({
        "command_schema": schema, "generator_format": 2, "profile": "refund",
        "schema": "auths.self-hosted-profile-lock/1", "schema_digest": digest,
        "service": "refunds", "tool": "create_refund_v1", "version": 1
    });
    let source = json!({
        "schema": "auths.gateway-recipe-source/2", "profile_schema_digest": digest,
        "service": "refunds", "tool": "create_refund_v1", "operator_namespace": "refunds",
        "credential": {"kind": "bearer"}, "origin": "https://api.stripe.com",
        "write": {"method": "POST",
            "path": [{"kind": "fixed", "value": "v1"}, {"kind": "fixed", "value": "refunds"}],
            "body": {"kind": "form", "fields": {
                "payment_intent": {"kind": "field", "name": "payment_intent"},
                "amount": {"kind": "field", "name": "amount"}}}}
    });
    let recipe = CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("source"),
        &serde_json::to_vec(&lock).expect("lock"),
    )
    .expect("form recipe compiles");
    let arguments = arguments(
        &recipe,
        &json!({"operation_id": "refund-1", "payment_intent": "pi_1", "amount": 1500}),
    );
    let request = recipe
        .closed_request_from_arguments(&arguments, [0; 32])
        .expect("closed request");
    assert_eq!(request.url(), "https://api.stripe.com/v1/refunds");
    assert_eq!(request.content_type(), "application/x-www-form-urlencoded");
    assert_eq!(request.body(), b"amount=1500&payment_intent=pi_1");
}

#[test]
fn github_recipe_change_invalidates_old_authorized_arguments() {
    let original = compiled("github");
    let arguments = arguments(
        &original,
        &json!({"operation_id": "issue-1", "title": "Example", "body": "Example body"}),
    );
    let (source, lock) = fixture("github");
    let mut mutated: Value = serde_json::from_slice(source).expect("source");
    mutated["write"]["path"][2]["value"] = Value::String("other-repo".into());
    let changed = CompiledRecipe::compile(&serde_json::to_vec(&mutated).expect("source"), lock)
        .expect("deliberate changed recipe");
    assert_ne!(original.digest(), changed.digest());
    assert_eq!(
        changed
            .closed_request_from_arguments(&arguments, [0; 32])
            .err(),
        Some(GatewayRecipeError::ActionMismatch)
    );
}

#[test]
fn logical_id_and_namespace_are_canonical_and_bounded() {
    assert!(LogicalOperationId::parse("run-1.2").is_ok());
    assert!(OperatorNamespace::parse("operator_A").is_ok());
    for hostile in ["", "-leading", "with/slash", "with space", "x\n"] {
        assert!(LogicalOperationId::parse(hostile).is_err());
        assert!(OperatorNamespace::parse(hostile).is_err());
    }
    assert!(LogicalOperationId::parse(&"x".repeat(129)).is_err());
    assert!(OperatorNamespace::parse(&"x".repeat(65)).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_claim_is_one_use_across_races_and_restart() {
    let recipe = compiled("github");
    let args = arguments(
        &recipe,
        &json!({"operation_id": "issue-42", "title": "Exact", "body": "One issue"}),
    );
    let request = Arc::new(
        recipe
            .closed_request_from_arguments(&args, [7; 32])
            .expect("request"),
    );
    let temp = tempfile::tempdir().expect("temp directory");
    let root = std::fs::canonicalize(temp.path())
        .expect("canonical temp")
        .join("attempts");
    let store = crate::GatewayAttempts::new(Arc::new(
        FileGatewayAttemptStore::open(&root).expect("private store"),
    ));
    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let store = store.clone();
            let request = Arc::clone(&request);
            tokio::spawn(
                async move { store.claim(&request, 1_790_000_000).await.map(drop) },
            )
        })
        .collect();
    let mut outcomes = Vec::new();
    for task in tasks {
        outcomes.push(task.await.expect("task"));
    }
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(GatewayAttemptError::Replay)))
            .count(),
        15
    );
    drop(store);
    let restarted = crate::GatewayAttempts::new(Arc::new(
        FileGatewayAttemptStore::open(&root).expect("restart"),
    ));
    let snapshot = restarted
        .read(request.namespace(), request.operation_id())
        .await
        .expect("read")
        .expect("retained claim");
    assert_eq!(snapshot.stage(), GatewayAttemptStage::Unknown);
    assert!(matches!(
        restarted
            .claim(&request, 1_790_000_000)
            .await,
        Err(GatewayAttemptError::Replay)
    ));
}

#[tokio::test]
async fn response_and_observation_are_distinct_durable_stages() {
    let recipe = compiled("airtable");
    let args = arguments(
        &recipe,
        &json!({"operation_id": "record-1", "record_id": "recTEST0000000001", "replacement": "Approved"}),
    );
    let request = recipe
        .closed_request_from_arguments(&args, [9; 32])
        .expect("request");
    let temp = tempfile::tempdir().expect("temp directory");
    let root = std::fs::canonicalize(temp.path())
        .expect("canonical temp")
        .join("attempts");
    let store = crate::GatewayAttempts::new(Arc::new(
        FileGatewayAttemptStore::open(&root).expect("store"),
    ));
    let claim = store
        .claim(&request, 1_790_000_000)
        .await
        .expect("claim");
    let response = claim
        .record_response(200, [3; 32], None)
        .await
        .expect("response");
    assert_eq!(
        response.snapshot().expect("snapshot").stage(),
        GatewayAttemptStage::ResponseRecorded
    );
    let observed = response
        .record_observation(true)
        .await
        .expect("observation");
    assert_eq!(observed.stage(), GatewayAttemptStage::Observed);
    assert_eq!(observed.observation_match(), Some(true));
    assert_eq!(
        store
            .read(request.namespace(), request.operation_id())
            .await
            .expect("read"),
        Some(observed)
    );
    assert!(matches!(
        store.claim(&request, 1_790_000_000).await,
        Err(GatewayAttemptError::Replay)
    ));
}

/// The `/2` corpus of the recipe revision: valid bases and hostile cases.
fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../bindings/fixtures/gateway/hostile-recipes-v2.json"
    ))
    .expect("corpus")
}

fn corpus_recipe(base: &str) -> CompiledRecipe {
    let corpus = corpus();
    let base = &corpus["bases"][base];
    CompiledRecipe::compile(
        &serde_json::to_vec(&base["recipe"]).expect("recipe"),
        &serde_json::to_vec(&base["lock"]).expect("lock"),
    )
    .expect("corpus base compiles")
}

const ACCOUNT: &str = "acct_TESTACCOUNT01";

fn stripe_arguments(recipe: &CompiledRecipe, account: Option<&str>) -> Map<String, Value> {
    let mut values = json!({"operation_id": "refund-1", "payment_intent": "pi_TEST0000000001",
        "amount": 500, "currency": "usd"});
    if let Some(account) = account {
        values["connect_account"] = json!(account);
    }
    arguments(recipe, &values)
}

fn header_pairs(headers: &[RequestHeader]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|header| (header.name(), header.value()))
        .collect()
}

#[test]
fn source_v1_is_refused_without_a_reader() {
    for name in ["airtable", "todoist", "github"] {
        let (source, lock) = fixture(name);
        let mut source: Value = serde_json::from_slice(source).expect("source");
        source["schema"] = json!("auths.gateway-recipe-source/1");
        assert_eq!(
            CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source"), lock).err(),
            Some(GatewayRecipeError::InvalidSource),
            "{name}"
        );
    }
}

#[test]
fn review_document_is_v2_and_discloses_every_declaration() {
    let stripe = corpus_recipe("stripe");
    let review = stripe.review_document();
    assert_eq!(review["schema"], RECIPE_REVIEW_SCHEMA);
    assert_eq!(review["digest"], stripe.digest_hex());
    assert_eq!(review["write_is_conditional"], false);
    assert_eq!(review["recovery"]["schema"], RECOVERY_CAPABILITY_SCHEMA);
    assert_eq!(review["recovery"]["class"], "linked-after-response");
    assert_eq!(review["recovery"]["write_is_conditional"], false);
    assert_eq!(
        review["provider_headers"]["Stripe-Version"]["response"],
        "required"
    );
    assert!(
        review["idempotency"]["disclosure"]
            .as_str()
            .expect("idempotency")
            .contains("cannot verify that the provider honors it")
    );
    assert!(
        review["credential_guard"]["disclosure"]
            .as_str()
            .expect("guard")
            .contains("a denied read shows only the refusals observed")
    );
    assert_eq!(
        review["credential_guard"]["denied_reads"][1]["path"],
        json!(["v1", "payouts"])
    );
    assert_eq!(review["account_scope"]["header"], "Stripe-Account");
    assert!(
        review["account_scope"]["disclosure"]
            .as_str()
            .expect("scope")
            .contains("a value the grant lists")
    );
    assert_eq!(
        review["relative_ceiling"]["rule"],
        "amount ≤ floor(basis × 5000 / 10000)"
    );
    assert_eq!(review["bounds"]["sum"]["partition"], "currency");
    assert_eq!(review["observation"]["locator"], "response-locator");
    assert_eq!(review["echo"]["kind"], "form-field");
    assert_eq!(review["pre_entry"], Value::Null);
    let pre_entry = corpus_recipe("airtable-pre-entry").review_document();
    assert!(
        pre_entry["pre_entry"]["disclosure"]
            .as_str()
            .expect("pre-entry")
            .contains("the write is not conditional")
    );
    let plain = compiled("github").review_document();
    for absent in [
        "provider_headers",
        "credential_guard",
        "idempotency",
        "observation",
        "pre_entry",
        "account_scope",
        "relative_ceiling",
        "bounds",
        "echo",
    ] {
        assert_eq!(plain[absent], Value::Null, "{absent}");
    }
    assert_eq!(plain["recovery"]["class"], "recorded");
}

#[test]
fn recovery_capability_follows_its_table() {
    let observations = [
        StateObservation::None,
        StateObservation::VerifiedLocator,
        StateObservation::ResponseLocator,
    ];
    let reentries = [
        LostClaimReentry::None,
        LostClaimReentry::Declared {
            kind: IdempotencyKind::DerivedHeader,
            retention_seconds: 86_400,
        },
        LostClaimReentry::Declared {
            kind: IdempotencyKind::OperationIdField,
            retention_seconds: 1,
        },
    ];
    for observation in observations {
        for echo in [false, true] {
            for idempotency in reentries {
                for pre_entry in [false, true] {
                    let capability = recovery_capability(RecoveryDeclarations {
                        observation,
                        echo,
                        idempotency,
                        pre_entry,
                    });
                    let link = if echo {
                        observation
                    } else {
                        StateObservation::None
                    };
                    let class = match (observation, echo) {
                        (StateObservation::VerifiedLocator, true) => RecoveryClass::Linked,
                        (StateObservation::ResponseLocator, true) => {
                            RecoveryClass::LinkedAfterResponse
                        }
                        (StateObservation::None, _) => RecoveryClass::Recorded,
                        (_, false) => RecoveryClass::Observed,
                    };
                    assert_eq!(capability.state_observation, observation);
                    assert_eq!(capability.provider_link, link);
                    assert_eq!(capability.class, class);
                    assert_eq!(
                        capability.unknown_resolution == UnknownResolution::GatewayReobservation,
                        class == RecoveryClass::Linked
                    );
                    assert_eq!(capability.lost_claim_reentry, idempotency);
                    assert_eq!(capability.pre_entry_reread, pre_entry);
                    assert!(!capability.write_is_conditional);
                }
            }
        }
    }
}

#[test]
fn form_echo_is_placed_in_sorted_field_order() {
    let recipe = corpus_recipe("stripe-platform");
    let request = recipe
        .closed_request_from_arguments(&stripe_arguments(&recipe, None), [4; 32])
        .expect("request");
    let token = request.echo_token().expect("echo token");
    assert_eq!(
        String::from_utf8(request.body().to_vec()).expect("form body"),
        format!("amount=500&metadata%5Bauths_echo%5D={token}&payment_intent=pi_TEST0000000001")
    );
    assert_eq!(request.content_type(), "application/x-www-form-urlencoded");
}

#[test]
fn account_scope_header_is_exact_on_the_write_and_action_reads_and_nowhere_else() {
    let recipe = corpus_recipe("stripe");
    let request = recipe
        .closed_request_from_arguments(&stripe_arguments(&recipe, Some(ACCOUNT)), [4; 32])
        .expect("request");
    let version = ("Stripe-Version", "2025-03-31.basil");
    let key = idempotency_key(
        recipe.namespace(),
        &LogicalOperationId::parse("refund-1").expect("operation"),
    );
    assert_eq!(
        header_pairs(request.headers()),
        [
            version,
            ("Stripe-Account", ACCOUNT),
            ("Idempotency-Key", key.as_str())
        ]
    );
    let ceiling = request
        .relative_ceiling_read()
        .expect("relative ceiling read");
    assert_eq!(
        ceiling.url(),
        "https://api.stripe.com/v1/payment_intents/pi_TEST0000000001"
    );
    assert_eq!(
        header_pairs(ceiling.headers()),
        [version, ("Stripe-Account", ACCOUNT)]
    );
    assert!(
        request.observation().is_none(),
        "a response locator is resolved only from the recorded response"
    );
    let reads = recipe.credential_reads().expect("credential reads");
    for read in reads
        .probe()
        .into_iter()
        .chain(reads.account())
        .chain(reads.denied())
    {
        assert_eq!(header_pairs(read.headers()), [version], "{}", read.url());
    }
    let platform = corpus_recipe("stripe-platform");
    let unscoped = platform
        .closed_request_from_arguments(&stripe_arguments(&platform, None), [4; 32])
        .expect("platform request");
    let no_scope = |headers: &[RequestHeader]| {
        headers
            .iter()
            .all(|header| !header.name().eq_ignore_ascii_case("stripe-account"))
    };
    assert!(no_scope(unscoped.headers()));
    assert!(no_scope(
        unscoped
            .relative_ceiling_read()
            .expect("relative ceiling read")
            .headers()
    ));
}

#[test]
fn account_scope_value_outside_its_grammar_is_refused() {
    let recipe = corpus_recipe("stripe");
    for hostile in [
        "acct_TEST\r\nX-Injected: 1",
        "acct_TEST ACCOUNT",
        "acct_TEST-ACCOUNT",
        "cust_TESTACCOUNT01",
    ] {
        let refused = recipe
            .closed_request_from_arguments(&stripe_arguments(&recipe, Some(hostile)), [4; 32])
            .err();
        assert_eq!(
            refused,
            Some(GatewayRecipeError::InvalidAccountScopeValue),
            "{hostile:?}"
        );
        assert_eq!(
            refused.map(GatewayRecipeError::code),
            Some("gateway.account-scope.invalid-value")
        );
    }
    // A value shorter than the profile field's minimum fails the profile
    // schema before the header grammar is reached.
    assert_eq!(
        recipe
            .closed_request_from_arguments(
                &stripe_arguments(&recipe, Some("acct_SHORT12")),
                [4; 32]
            )
            .err(),
        Some(GatewayRecipeError::ActionMismatch)
    );
}

#[test]
fn credential_reads_are_fixed_and_carry_no_action_value() {
    let recipe = corpus_recipe("stripe");
    let reads = recipe.credential_reads().expect("credential reads");
    let probe = reads.probe().expect("probe");
    assert_eq!(probe.method(), CredentialReadMethod::Get);
    assert_eq!(probe.url(), "https://api.stripe.com/v1/balance");
    assert_eq!(probe.maximum_response_bytes(), 16_384);
    assert_eq!(
        reads.account().expect("account").url(),
        "https://api.stripe.com/v1/account"
    );
    assert_eq!(
        reads
            .denied()
            .iter()
            .map(|read| (
                read.method().as_str(),
                read.url(),
                read.maximum_response_bytes()
            ))
            .collect::<Vec<_>>(),
        [
            ("GET", "https://api.stripe.com/v1/customers", 16_384),
            ("GET", "https://api.stripe.com/v1/payouts", 16_384)
        ]
    );
    let corpus = corpus();
    let mut source = corpus["bases"]["stripe"]["recipe"].clone();
    source["credential"]["guard"]["denied_reads"][0]["method"] = json!("HEAD");
    let head = CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("recipe"),
        &serde_json::to_vec(&corpus["bases"]["stripe"]["lock"]).expect("lock"),
    )
    .expect("HEAD denied read");
    assert_eq!(
        head.credential_reads().expect("reads").denied()[0].method(),
        CredentialReadMethod::Head
    );
    assert!(
        compiled("github")
            .credential_reads()
            .expect("reads")
            .denied()
            .is_empty()
    );
}

/// The serde renderer the construction leaf replaced, kept only as a test
/// oracle: it evaluates the template to a JSON value, inserts the echo, and
/// serializes under RFC 8785, or form-encodes the sorted pairs.
mod oracle {
    use super::super::source::{BodySource, EchoPlacement, FormExpr, PathSegment, ValueExpr};
    use serde_json::{Map, Value};
    use std::collections::BTreeMap;
    use url::form_urlencoded;

    fn eval(value: &ValueExpr, arguments: &Map<String, Value>) -> Value {
        match value {
            ValueExpr::String { value } => Value::String(value.clone()),
            ValueExpr::Integer { value } => Value::from(*value),
            ValueExpr::Boolean { value } => Value::Bool(*value),
            ValueExpr::Field { name } => arguments[name].clone(),
            ValueExpr::Object { fields } => Value::Object(
                fields
                    .iter()
                    .map(|(name, value)| (name.clone(), eval(value, arguments)))
                    .collect(),
            ),
            ValueExpr::Array { items } => {
                Value::Array(items.iter().map(|item| eval(item, arguments)).collect())
            }
            ValueExpr::Echo => Value::Null,
        }
    }

    pub(super) fn body(
        body: &BodySource,
        echo: Option<(&EchoPlacement, &str)>,
        arguments: &Map<String, Value>,
    ) -> Vec<u8> {
        match body {
            BodySource::Json { value } => {
                let mut value = eval(value, arguments);
                if let Some((EchoPlacement::JsonPointer { pointer }, token)) = echo {
                    let (parent, key) = pointer.rsplit_once('/').expect("pointer");
                    value
                        .pointer_mut(parent)
                        .and_then(Value::as_object_mut)
                        .expect("object")
                        .insert(key.to_owned(), Value::String(token.to_owned()));
                }
                serde_json_canonicalizer::to_vec(&value).expect("canonical")
            }
            BodySource::Form { fields } => {
                let mut pairs: BTreeMap<String, String> = fields
                    .iter()
                    .map(|(name, value)| {
                        let text = match value {
                            FormExpr::String { value } => value.clone(),
                            FormExpr::Field { name } => match &arguments[name] {
                                Value::String(text) => text.clone(),
                                other => other.to_string(),
                            },
                            FormExpr::Json { value } => String::from_utf8(
                                serde_json_canonicalizer::to_vec(&eval(value, arguments))
                                    .expect("canonical"),
                            )
                            .expect("utf-8"),
                            FormExpr::Echo => String::new(),
                        };
                        (name.clone(), text)
                    })
                    .collect();
                if let Some((EchoPlacement::FormField { name }, token)) = echo {
                    pairs.insert(name.clone(), token.to_owned());
                }
                let mut serializer = form_urlencoded::Serializer::new(String::new());
                for (name, value) in pairs {
                    serializer.append_pair(&name, &value);
                }
                serializer.finish().into_bytes()
            }
        }
    }

    pub(super) fn path(segments: &[PathSegment], arguments: &Map<String, Value>) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut path = String::new();
        for segment in segments {
            path.push('/');
            match segment {
                PathSegment::Fixed { value } => path.push_str(value),
                PathSegment::Field { name } => {
                    for byte in arguments[name].as_str().expect("text").bytes() {
                        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
                        {
                            path.push(char::from(byte));
                        } else {
                            path.push('%');
                            path.push(char::from(HEX[usize::from(byte >> 4)]));
                            path.push(char::from(HEX[usize::from(byte & 0x0f)]));
                        }
                    }
                }
                PathSegment::ResponseField { .. } | PathSegment::Echo => {}
            }
        }
        path
    }
}

fn oracle_request(recipe: &CompiledRecipe, arguments: &Map<String, Value>, commitment: [u8; 32]) {
    let request = recipe
        .closed_request_from_arguments(arguments, commitment)
        .expect("request");
    let echo = recipe
        .source
        .echo
        .as_ref()
        .map(|echo| (&echo.write, request.echo_token().expect("token")));
    assert_eq!(
        request.body(),
        oracle::body(&recipe.source.write.body, echo, arguments),
        "body"
    );
    assert_eq!(
        request.url(),
        format!(
            "{}{}",
            recipe.source.origin,
            oracle::path(&recipe.source.write.path, arguments)
        ),
        "url"
    );
}

/// Arbitrary text with quotes, backslashes, controls other than NUL,
/// separators, percent signs, and multi-byte characters.
fn hostile_text(
    minimum: usize,
    maximum: usize,
) -> impl proptest::strategy::Strategy<Value = String> {
    use proptest::prelude::*;
    let unit = prop_oneof![
        4 => proptest::char::range('a', 'z'),
        1 => proptest::char::range('\u{1}', '\u{1f}'),
        1 => Just('"'),
        1 => Just('\\'),
        1 => Just('/'),
        1 => Just(' '),
        1 => Just('%'),
        1 => Just('&'),
        1 => Just('\u{7f}'),
        1 => Just('é'),
        1 => Just('\u{2028}'),
        1 => Just('😀'),
    ];
    proptest::collection::vec(unit, 0..maximum)
        .prop_map(|chars| chars.into_iter().collect::<String>())
        .prop_filter("byte length", move |text| {
            (minimum..=maximum).contains(&text.len())
        })
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    #[test]
    fn canonical_chunked_string_writes_match_whole_original_unicode_strings(
        characters in proptest::collection::vec(
            proptest::collection::vec(proptest::arbitrary::any::<char>(), 0..16), 0..16),
        prefix in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..32),
    ) {
        let chunks = characters.into_iter().map(|chars| chars.into_iter().collect::<String>()).collect::<Vec<_>>();
        let joined = chunks.concat();
        let whole = serde_json_canonicalizer::to_vec(&joined).expect("whole original string");
        let chunked = serde_json_canonicalizer::to_vec(&CanonicalChunkedString(&chunks)).expect("native fragmented string");
        proptest::prop_assert_eq!(&chunked, &whole);
        proptest::prop_assert_eq!(strict_json::from_slice::<String>(&chunked).expect("complete original string"), joined);
        let mut output = prefix.clone();
        serde_json_canonicalizer::to_writer(&CanonicalChunkedString(&chunks), &mut output).expect("append fragmented string");
        proptest::prop_assert_eq!(&output[..prefix.len()], prefix.as_slice());
        proptest::prop_assert_eq!(&output[prefix.len()..], whole.as_slice());
    }

    #[test]
    fn complete_quoted_property_writes_preserve_arbitrary_outer_prefixes_and_original_payloads(
        characters in proptest::collection::vec(proptest::arbitrary::any::<char>(), 0..64),
        prefix in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..64),
    ) {
        let name: String = characters.into_iter().collect();
        let child = json!({"array":[null,false,{"z":[],"a":{"value":true}}]});
        let entries = [(name.clone(), child.clone()), (format!("{name}\0"), json!([true,false]))];
        let standalone = serde_json_canonicalizer::to_vec(&CanonicalMapEntries(&entries)).expect("canonical object");
        let mut output = prefix.clone();
        serde_json_canonicalizer::to_writer(&CanonicalMapEntries(&entries), &mut output).expect("first append");
        let first_end = output.len();
        let reversed = entries.iter().cloned().rev().collect::<Vec<_>>();
        serde_json_canonicalizer::to_writer(&CanonicalMapEntries(&reversed), &mut output).expect("second append");
        proptest::prop_assert_eq!(&output[..prefix.len()], prefix.as_slice());
        proptest::prop_assert_eq!(&output[prefix.len()..first_end], standalone.as_slice());
        proptest::prop_assert_eq!(&output[first_end..], standalone.as_slice());
        // Each appended document is parsed separately. The arbitrary original
        // prefix and concatenated documents are a byte-sink test, not one JSON document.
        for appended in [&output[prefix.len()..first_end], &output[first_end..]] {
            let decoded: Value = strict_json::from_slice(appended).expect("complete appended object");
            proptest::prop_assert_eq!(decoded.get(&name), Some(&child));
            proptest::prop_assert_eq!(decoded.as_object().expect("object").len(), entries.len());
        }
        let quoted = serde_json_canonicalizer::to_vec(&name).expect("quoted property name");
        proptest::prop_assert_eq!(serde_json::from_slice::<String>(&quoted).expect("original name"), name);
    }

    #[test]
    fn native_key_reparse_handles_all_utf16_escapes_and_requires_complete_eof(
        characters in proptest::collection::vec(proptest::arbitrary::any::<char>(), 0..96),
    ) {
        use std::fmt::Write as _;
        let original: String = characters.into_iter().collect();
        let mut escaped = String::from("\"");
        for (index, unit) in original.encode_utf16().enumerate() {
            if index % 2 == 0 {
                write!(&mut escaped, "\\u{unit:04x}").expect("string formatter");
            } else {
                write!(&mut escaped, "\\u{unit:04X}").expect("string formatter");
            }
        }
        escaped.push('"');
        let document = format!(" \t\r\n{escaped} \n\r\t");
        let decoded = serde_json::from_slice::<Value>(document.as_bytes()).expect("complete escaped key");
        proptest::prop_assert_eq!(decoded.as_str(), Some(original.as_str()));
        proptest::prop_assert_eq!(serde_json::from_slice::<String>(document.as_bytes()).expect("key string"), original.clone());
        proptest::prop_assert_eq!(serde_json_canonicalizer::to_vec(&decoded).expect("canonical decoded key"),
            serde_json_canonicalizer::to_vec(&original).expect("canonical original key"));
        for trailing in [b'x', 0x0b, 0x0c] {
            let mut malformed = document.as_bytes().to_vec();
            malformed.push(trailing);
            proptest::prop_assert!(serde_json::from_slice::<Value>(&malformed).is_err());
            proptest::prop_assert!(serde_json::from_slice::<String>(&malformed).is_err());
        }
    }

    #[test]
    fn canonical_object_bytes_are_compositional_and_invariant_under_unique_property_permutations(
        inputs in proptest::collection::vec(
            proptest::collection::vec(proptest::arbitrary::any::<char>(), 0..24), 0..16),
    ) {
        let mut unique = std::collections::BTreeMap::new();
        for (index, name) in inputs.into_iter().enumerate() {
            let name: String = name.into_iter().collect();
            unique.insert(name, json!({"nested":[index,false,null,{"z":[],"a":{}}]}));
        }
        let entries = unique.into_iter().collect::<Vec<_>>();
        let canonical = serde_json_canonicalizer::to_vec(&CanonicalMapEntries(&entries)).expect("canonical property events");
        let mut permuted = entries.clone();
        permuted.reverse();
        proptest::prop_assert_eq!(serde_json_canonicalizer::to_vec(&CanonicalMapEntries(&permuted)).expect("reversed events"), canonical.clone());
        if !permuted.is_empty() {
            permuted.rotate_left(1);
        }
        proptest::prop_assert_eq!(serde_json_canonicalizer::to_vec(&CanonicalMapEntries(&permuted)).expect("rotated events"), canonical.clone());
        let mut ordered = entries.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
        let mut reference = vec![b'{'];
        for (index, (name, value)) in ordered.into_iter().enumerate() {
            if index > 0 { reference.push(b','); }
            reference.extend_from_slice(&serde_json_canonicalizer::to_vec(name).expect("complete key bytes"));
            reference.push(b':');
            reference.extend_from_slice(&serde_json_canonicalizer::to_vec(value).expect("complete child bytes"));
        }
        reference.push(b'}');
        proptest::prop_assert_eq!(&canonical, &reference);
        let decoded: Value = strict_json::from_slice(&canonical).expect("unique complete output");
        proptest::prop_assert_eq!(decoded.as_object().expect("object").len(), entries.len());
        for (name, value) in entries {
            proptest::prop_assert_eq!(decoded.get(&name), Some(&value));
        }
    }

    #[test]
    fn complete_typed_source_serialization_retains_arbitrary_user_name_maps(
        inputs in proptest::collection::vec(
            proptest::collection::vec(proptest::arbitrary::any::<char>(), 0..24), 0..16),
    ) {
        let (source, _) = fixture("airtable");
        let mut source: Value = serde_json::from_slice(source).expect("source fixture");
        let mut fields = serde_json::Map::new();
        let mut literal = serde_json::Map::new();
        for (index, name) in inputs.into_iter().enumerate() {
            let name: String = name.into_iter().collect();
            fields.insert(name.clone(), json!({"kind":"boolean","value":index % 2 == 0}));
            literal.insert(name, json!([index, false, null]));
        }
        source["write"]["body"] = json!({"kind":"json","value":{"kind":"object","fields":fields.clone()}});
        source["credential"]["guard"] = json!({"prefixes":[], "probe":{
            "path":[],"json_pointer":"","equals":literal.clone(),"maximum_response_bytes":1}});
        let typed = serde_contract_source(&source);
        for bytes in [serde_json::to_vec(&typed).expect("serialized source"),
            serde_json_canonicalizer::to_vec(&typed).expect("canonical source")] {
            let decoded: Value = strict_json::from_slice(&bytes).expect("unique original names");
            proptest::prop_assert_eq!(&decoded["write"]["body"]["value"]["fields"], &Value::Object(fields.clone()));
            proptest::prop_assert_eq!(&decoded["credential"]["guard"]["probe"]["equals"], &Value::Object(literal.clone()));
        }
    }

    #[test]
    fn canonical_utf16_keys_match_scalar_reference_and_retain_all_properties(
        inputs in proptest::collection::vec(
            proptest::collection::vec(proptest::arbitrary::any::<char>(), 0..40), 0..24),
    ) {
        let mut object = serde_json::Map::new();
        for (index, characters) in inputs.into_iter().enumerate() {
            let name: String = characters.into_iter().collect();
            let reference = name.chars().flat_map(|character| {
                let scalar = u32::from(character);
                if scalar < 0x10000 {
                    vec![u16::try_from(scalar).expect("BMP scalar")]
                } else {
                    let offset = scalar - 0x10000;
                    vec![u16::try_from(0xd800 + offset / 1024).expect("high surrogate"),
                        u16::try_from(0xdc00 + offset % 1024).expect("low surrogate")]
                }
            }).collect::<Vec<_>>();
            proptest::prop_assert_eq!(name.encode_utf16().collect::<Vec<_>>(), reference.clone());
            proptest::prop_assert_eq!(String::from_utf16(&reference).expect("paired UTF-16"), name.clone());
            object.insert(name, json!(index));
        }
        let mut expected_order = object.keys().cloned().collect::<Vec<_>>();
        expected_order.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
        let canonical = serde_json_canonicalizer::to_vec(&Value::Object(object.clone())).expect("canonical object");
        let decoded: Value = strict_json::from_slice(&canonical).expect("unique canonical properties");
        let decoded = decoded.as_object().expect("object");
        proptest::prop_assert_eq!(decoded.keys().cloned().collect::<Vec<_>>(), expected_order);
        proptest::prop_assert_eq!(decoded.len(), object.len());
        for (key, value) in &object {
            proptest::prop_assert_eq!(decoded.get(key), Some(value));
        }
    }

    #[test]
    fn canonical_string_bytes_match_complete_scalar_escape_reference(
        characters in proptest::collection::vec(proptest::arbitrary::any::<char>(), 0..128),
    ) {
        let input: String = characters.into_iter().collect();
        let mut expected = vec![b'"'];
        for character in input.chars() {
            match character {
                '"' => expected.extend_from_slice(b"\\\""),
                '\\' => expected.extend_from_slice(b"\\\\"),
                '\u{8}' => expected.extend_from_slice(b"\\b"),
                '\t' => expected.extend_from_slice(b"\\t"),
                '\n' => expected.extend_from_slice(b"\\n"),
                '\u{c}' => expected.extend_from_slice(b"\\f"),
                '\r' => expected.extend_from_slice(b"\\r"),
                control if control < '\u{20}' => {
                    let control = u8::try_from(u32::from(control)).expect("control byte");
                    let digits = b"0123456789abcdef";
                    expected.extend_from_slice(b"\\u00");
                    expected.push(digits[usize::from(control / 16)]);
                    expected.push(digits[usize::from(control % 16)]);
                }
                original => {
                    let mut buffer = [0_u8; 4];
                    expected.extend_from_slice(original.encode_utf8(&mut buffer).as_bytes());
                }
            }
        }
        expected.push(b'"');
        let canonical = serde_json_canonicalizer::to_vec(&input).expect("canonical string");
        proptest::prop_assert_eq!(&canonical, &expected);
        proptest::prop_assert_eq!(strict_json::from_slice::<String>(&canonical).expect("original string"), input.clone());
        proptest::prop_assert!(canonical.len() <= 6 * input.len() + 2);
    }

    #[test]
    fn construction_leaf_matches_the_serde_oracle_on_json_bodies(
        title in hostile_text(1, 128),
        body in hostile_text(0, 256),
        record in hostile_text(17, 43),
    ) {
        let github = compiled("github");
        oracle_request(
            &github,
            &arguments(&github, &json!({"operation_id": "issue-1", "title": title, "body": body})),
            [2; 32],
        );
        let airtable = compiled("airtable");
        oracle_request(
            &airtable,
            &arguments(
                &airtable,
                &json!({"operation_id": "run-1", "record_id": record, "replacement": "Pending"}),
            ),
            [3; 32],
        );
    }

    #[test]
    fn construction_leaf_matches_the_serde_oracle_on_form_bodies(
        content in hostile_text(1, 256),
        description in hostile_text(1, 80),
        intent in hostile_text(3, 255),
        amount in 1_i64..=99_999_999,
    ) {
        let todoist = compiled("todoist");
        oracle_request(
            &todoist,
            &arguments(&todoist, &json!({
                "operation_id": "f38bff5f-430e-4fe1-814b-6e43690a641f",
                "content": content,
                "description": description,
                "temp_id": "f5034de3-4de1-42e0-bb54-70a340226f0e"
            })),
            [5; 32],
        );
        let stripe = corpus_recipe("stripe-plain");
        oracle_request(
            &stripe,
            &arguments(&stripe, &json!({"operation_id": "refund-1", "payment_intent": intent,
                "amount": amount})),
            [6; 32],
        );
        let platform = corpus_recipe("stripe-platform");
        oracle_request(
            &platform,
            &arguments(&platform, &json!({"operation_id": "refund-1", "payment_intent": intent,
                "amount": amount, "currency": "usd"})),
            [7; 32],
        );
    }

    #[test]
    fn a_path_value_never_adds_a_segment(record in hostile_text(17, 43)) {
        let airtable = compiled("airtable");
        let request = airtable.closed_request_from_arguments(
            &arguments(
                &airtable,
                &json!({"operation_id": "run-1", "record_id": record, "replacement": "Pending"}),
            ),
            [3; 32],
        );
        match request {
            Ok(request) => {
                let path = request
                    .url()
                    .strip_prefix("https://api.airtable.com")
                    .expect("origin");
                proptest::prop_assert_eq!(path.matches('/').count(), 4);
                proptest::prop_assert!(!path.contains('?') && !path.contains('#'));
            }
            Err(error) => proptest::prop_assert_eq!(error, GatewayRecipeError::UnsafePath),
        }
    }
}

#[test]
fn compiler_refuses_duplicate_members_in_source_and_profile_lock() {
    let (recipe, lock) = fixture("airtable");
    let source_text = std::str::from_utf8(recipe).unwrap();
    let source_value: Value = serde_json::from_slice(recipe).unwrap();
    let service = serde_json::to_string(&source_value["service"]).unwrap();
    let duplicate_source = source_text.replacen('{', &format!("{{\"service\":{service},"), 1);
    assert_eq!(
        CompiledRecipe::compile(duplicate_source.as_bytes(), lock).unwrap_err(),
        GatewayRecipeError::InvalidSource
    );
    let lock_text = std::str::from_utf8(lock).unwrap();
    let duplicate_lock = lock_text.replacen('{', "{\"service\":\"duplicate\",", 1);
    assert_eq!(
        CompiledRecipe::compile(recipe, duplicate_lock.as_bytes()).unwrap_err(),
        GatewayRecipeError::InvalidProfileLock
    );
}
