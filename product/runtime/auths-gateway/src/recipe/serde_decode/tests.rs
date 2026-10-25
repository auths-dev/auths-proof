use super::oracle;
use crate::recipe::{ProfileLockFile, WriteMethod, source, strict_json};
use proptest::prelude::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

fn compare<T: DeserializeOwned + Serialize, O: DeserializeOwned + Serialize>(value: &Value) {
    let input = serde_json::to_vec(value).expect("original JSON");
    let actual = strict_json::from_slice::<T>(&input);
    let expected = strict_json::from_slice::<O>(&input);
    match (actual, expected) {
        (Ok(actual), Ok(expected)) => assert_eq!(serde_json::to_vec(&actual).expect("actual normalization"),
            serde_json::to_vec(&expected).expect("derive normalization"), "{value}"),
        (Err(_), Err(_)) => {}
        _ => panic!("explicit/derive verdict differs for {}: {value}", std::any::type_name::<T>()),
    }
}

fn record<T: DeserializeOwned + Serialize, O: DeserializeOwned + Serialize>(names: &[&str], value: Value) {
    compare::<T, O>(&value);
    let fields = value.as_object().expect("record specimen");
    let positional = Value::Array(names.iter().map(|name| fields.get(*name).cloned().unwrap_or(Value::Null)).collect());
    compare::<T, O>(&positional);
    compare::<T, O>(&json!([]));
    compare::<T, O>(&json!([null]));
    let mut unknown = value.clone();
    unknown.as_object_mut().expect("record").insert("auths_unknown_field".to_owned(), json!(true));
    compare::<T, O>(&unknown);
    for name in names {
        let mut absent = value.clone();
        absent.as_object_mut().expect("record").remove(*name);
        compare::<T, O>(&absent);
        let mut null = value.clone();
        null[*name] = Value::Null;
        compare::<T, O>(&null);
    }
    let mut trailing = positional.as_array().expect("positional record").clone();
    trailing.push(Value::Null);
    compare::<T, O>(&Value::Array(trailing));
}

fn source_value() -> Value {
    json!({
        "schema":"auths.gateway-recipe-source/2", "profile_schema_digest":"test-only-digest",
        "service":"test-service", "tool":"test-tool", "operator_namespace":"test-namespace",
        "credential":{"kind":"bearer"}, "origin":"https://example.test",
        "write":{"method":"POST","path":[{"kind":"fixed","value":"records"}],
            "body":{"kind":"json","value":{"kind":"object","fields":{
                "number":{"kind":"integer","value":7}, "echo":{"kind":"echo","ignored":[]}
            }}}}
    })
}

#[test]
fn explicit_records_preserve_fields_missing_defaults_nulls_and_positional_order() {
    record::<source::RecipeSource, oracle::RecipeSource>(&["schema","profile_schema_digest","service","tool",
        "operator_namespace","credential","origin","provider_headers","account_scope","bounds","relative_ceiling",
        "write","observation","echo","pre_entry","preconditions"], source_value());
    record::<source::GuardSource, oracle::GuardSource>(&["prefixes","probe","account","denied_reads"], json!({"prefixes":["test-"]}));
    record::<source::ProbeSource, oracle::ProbeSource>(&["path","json_pointer","equals","maximum_response_bytes"],
        json!({"path":[{"kind":"fixed","value":"probe"}],"json_pointer":"/ok","equals":{"a":[null,true,-0.0]},"maximum_response_bytes":4096}));
    record::<source::AccountReadSource, oracle::AccountReadSource>(&["path","json_pointer","maximum_response_bytes"],
        json!({"path":[],"json_pointer":"/id","maximum_response_bytes":4096}));
    record::<source::DeniedReadSource, oracle::DeniedReadSource>(&["method","path","refused_status"],
        json!({"method":"GET","path":[],"refused_status":[401,403]}));
    record::<source::AccountScopeSource, oracle::AccountScopeSource>(&["header","field"], json!({"header":"X-Account","field":"account"}));
    record::<source::BoundsSource, oracle::BoundsSource>(&["sum"], json!({"sum":{"argument":"amount"}}));
    record::<source::SumBoundSource, oracle::SumBoundSource>(&["argument","partition"], json!({"argument":"amount"}));
    record::<source::RelativeCeilingSource, oracle::RelativeCeilingSource>(&["argument","basis_points","path","json_pointer",
        "subtract_pointer","bind","maximum_response_bytes"], json!({"argument":"amount","basis_points":1000,
            "path":[],"json_pointer":"/available","maximum_response_bytes":4096}));
    record::<source::BindSource, oracle::BindSource>(&["pointer","field"], json!({"pointer":"/id","field":"id"}));
    record::<source::WriteSource, oracle::WriteSource>(&["method","path","body","idempotency"], source_value()["write"].clone());
    record::<source::IdempotencyLocation, oracle::IdempotencyLocation>(&["json_pointer","form_field","pointer"], json!({"json_pointer":"/operation"}));
    record::<source::ObservationSource, oracle::ObservationSource>(&["path","json_pointer","expected_field","maximum_response_bytes"],
        json!({"path":[],"json_pointer":"/ok","expected_field":"expected","maximum_response_bytes":4096}));
    record::<source::EchoSource, oracle::EchoSource>(&["write","observe"], json!({"write":{"kind":"form-field","name":"echo"},"observe":"/echo"}));
    record::<source::PreEntrySource, oracle::PreEntrySource>(&["path","pointers","maximum_response_bytes"],
        json!({"path":[],"pointers":["/id"],"maximum_response_bytes":4096}));
    record::<source::PreconditionSource, oracle::PreconditionSource>(&["read_back_subject","verified"], json!({}));
}

#[test]
fn explicit_variant_tables_preserve_tags_payloads_unit_content_and_field_types() {
    for value in [json!({"kind":"bearer"}), json!(["bearer"]), json!(["bearer",null]),
        json!({"kind":"header-api-key","header":"X-Test-Key"}), json!(["header-api-key","X-Test-Key"]),
        json!({"kind":0}), json!({"kind":"bearer","unknown":true}), json!(["bearer",null,1])] {
        compare::<source::CredentialSource, oracle::CredentialSource>(&value);
    }
    for value in [json!({"kind":"derived-header","retention_seconds":u64::MAX}),
        json!(["operation-id-field",{"json_pointer":"/operation"},60]), json!({"kind":"derived-header","retention_seconds":-1}),
        json!(["derived-header",1.0]), json!(["derived-header"])] {
        compare::<source::IdempotencySource, oracle::IdempotencySource>(&value);
    }
    for value in [json!(["fixed","a"]), json!(["field","id"]), json!(["response-field","/id",32]),
        json!({"kind":"echo","ignored":{"nested":[true,1,null]}}), json!(["echo"]), json!(["echo",1]),
        json!({"kind":"response-field","pointer":"/id","max_bytes":-0.0})] {
        compare::<source::PathSegment, oracle::PathSegment>(&value);
    }
    for value in [json!(["json",["integer",i64::MIN]]), json!(["form",{}]),
        json!({"kind":"json","value":{"kind":1,"value":7}}), json!({"kind":0,"value":{"kind":"echo"}}),
        json!({"kind":"form","fields":{"a":{"kind":"json","value":{"kind":6,"ignored":null}}}})] {
        compare::<source::BodySource, oracle::BodySource>(&value);
    }
    for value in [json!(["string","a"]), json!(["field","id"]), json!(["json",["array",[]]]),
        json!({"kind":"echo","ignored":{"a":1}}), json!(["echo"]), json!(["echo",true])] {
        compare::<source::FormExpr, oracle::FormExpr>(&value);
    }
    for value in [json!(["json-pointer","/echo"]), json!(["form-field","echo"]),
        json!({"kind":"form-field","name":false}), json!({"kind":0,"pointer":"/echo"})] {
        compare::<source::EchoPlacement, oracle::EchoPlacement>(&value);
    }
    for value in [json!("POST"), json!("PUT"), json!("PATCH"), json!("DELETE"), json!("GET"),
        json!({"POST":null}), json!({"POST":{}}), json!({"POST":[]}), json!(0), json!(true)] {
        compare::<WriteMethod, oracle::WriteMethod>(&value);
    }
}

fn lock_value(lock: ProfileLockFile) -> Value {
    json!({"schema":lock.schema,"profile":lock.profile,"version":lock.version,"service":lock.service,
        "tool":lock.tool,"schema_digest":lock.schema_digest,"command_schema":lock.command_schema,"generator_format":lock.generator_format})
}

fn compare_lock(value: &Value) {
    let input = serde_json::to_vec(value).expect("original lock");
    match (strict_json::from_slice::<ProfileLockFile>(&input), strict_json::from_slice::<oracle::ProfileLockFile>(&input)) {
        (Ok(actual), Ok(expected)) => assert_eq!(lock_value(actual), serde_json::to_value(expected).expect("derive lock")),
        (Err(_), Err(_)) => {}
        _ => panic!("explicit/derive lock verdict differs for {value}"),
    }
}

#[test]
fn explicit_lock_fields_preserve_word_widths_positional_form_and_full_schema() {
    let original = json!({"schema":"lock","profile":"profile","version":1,"service":"test","tool":"tool",
        "schema_digest":"test-only-digest","command_schema":{"items":[true,null,-0.0,{"a":1}]},"generator_format":1});
    compare_lock(&original);
    let names = ["schema","profile","version","service","tool","schema_digest","command_schema","generator_format"];
    compare_lock(&Value::Array(names.iter().map(|name| original[*name].clone()).collect()));
    for name in names {
        let mut value = original.clone();
        value.as_object_mut().expect("lock").remove(name);
        compare_lock(&value);
    }
    for version in [json!(0),json!(u16::MAX),json!(u32::from(u16::MAX)+1),json!(-1),json!(1.0),json!(null)] {
        let mut value = original.clone(); value["version"] = version; compare_lock(&value);
    }
    for format in [json!(0),json!(u8::MAX),json!(u16::from(u8::MAX)+1),json!(-1),json!(1.0),json!(false)] {
        let mut value = original.clone(); value["generator_format"] = format; compare_lock(&value);
    }
}

proptest! {
    #[test]
    fn explicit_record_tables_have_derive_parity_on_untrusted_optional_and_required_values(
        text in ".{0,96}", number in any::<u64>(), boolean in any::<bool>(), choice in 0_u8..7,
    ) {
        let raw = match choice {
            0 => Value::String(text), 1 => Value::from(number), 2 => Value::Bool(boolean),
            3 => Value::Null, 4 => json!([]), 5 => json!({}), _ => json!(["echo"]),
        };
        compare::<source::PreconditionSource, oracle::PreconditionSource>(&json!({"verified":raw.clone()}));
        compare::<source::CredentialSource, oracle::CredentialSource>(&json!({"kind":"bearer","guard":raw.clone()}));
        compare::<source::SumBoundSource, oracle::SumBoundSource>(&json!({"argument":raw.clone(),"partition":null}));
        compare::<source::ProbeSource, oracle::ProbeSource>(&json!({"path":[],"json_pointer":"/x","equals":raw,"maximum_response_bytes":number}));
    }

    #[test]
    fn explicit_variant_tables_have_derive_parity_for_nested_buffered_ordinals(index in 0_u64..12, value in any::<i64>()) {
        compare::<source::BodySource, oracle::BodySource>(&json!({"kind":"json","value":{"kind":index,"value":value}}));
        compare::<source::GuardSource, oracle::GuardSource>(&json!({"prefixes":[],"probe":{
            "path":[{"kind":index,"value":"x","name":"x","pointer":"/x","max_bytes":8}],
            "json_pointer":"/x","equals":null,"maximum_response_bytes":32}}));
    }
}
