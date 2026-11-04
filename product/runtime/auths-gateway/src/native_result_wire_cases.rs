//! Data-only decoding parity for every public submission-result variant.
//! Real native transport and signed evidence are established by the parent.
use crate::GatewaySubmitResult;
use serde_json::{Value, json};

fn wire(output: &mut Vec<Value>, name: &str, response: &str, accepted: bool) {
    assert_eq!(
        serde_json::from_str::<GatewaySubmitResult>(response).is_ok(),
        accepted,
        "{name}"
    );
    output.push(json!({"case":name,"response":response,"accepted":accepted}));
}

fn value(output: &mut Vec<Value>, name: &str, response: &Value, accepted: bool) {
    wire(output, name, &response.to_string(), accepted);
}

fn status_cases(output: &mut Vec<Value>, base: &Value) {
    let outcome = base["outcome"].as_str().expect("variant");
    for (name, status, accepted) in [
        ("minimum", json!(100), true),
        ("maximum", json!(599), true),
        ("below", json!(99), false),
        ("above", json!(600), false),
        ("u16-maximum", json!(65535), false),
        ("negative", json!(-1), false),
        ("boolean", json!(true), false),
        ("string", json!("200"), false),
        ("null", Value::Null, outcome == "observed-by-provider"),
    ] {
        let mut changed = base.clone();
        changed["status"] = status;
        value(
            output,
            &format!("{outcome}-status-{name}"),
            &changed,
            accepted,
        );
    }
    for number in ["200.0", "2e2"] {
        wire(
            output,
            &format!("{outcome}-status-{number}"),
            &base
                .to_string()
                .replace("\"status\":200", &format!("\"status\":{number}")),
            false,
        );
    }
}

fn refusal_cases(output: &mut Vec<Value>, outcome: &str) {
    for (name, code, accepted) in [
        ("one-byte", json!("a"), true),
        ("ascii-limit", json!("a".repeat(128)), true),
        ("utf8-limit", json!("é".repeat(64)), true),
        ("astral-limit", json!("🟢".repeat(32)), true),
        ("ascii-over-limit", json!("a".repeat(129)), false),
        ("utf8-over-limit", json!("é".repeat(65)), false),
        ("astral-over-limit", json!("🟢".repeat(33)), false),
        ("empty", json!(""), false),
        ("null", Value::Null, false),
        ("number", json!(7), false),
        ("boolean", json!(false), false),
    ] {
        value(
            output,
            &format!("{outcome}-code-{name}"),
            &json!({"outcome":outcome,"code":code}),
            accepted,
        );
    }
    for escaped in [r"\ud800", r"\udc00", r"\ud800x"] {
        wire(
            output,
            &format!("{outcome}-unpaired-{escaped}"),
            &format!(r#"{{"outcome":"{outcome}","code":"{escaped}"}}"#),
            false,
        );
    }
}

fn shape_cases(output: &mut Vec<Value>, base: &Value) {
    let outcome = base["outcome"].as_str().expect("variant");
    value(output, &format!("{outcome}-valid"), base, true);
    for field in base.as_object().expect("object").keys() {
        let mut missing = base.clone();
        missing.as_object_mut().expect("object").remove(field);
        value(
            output,
            &format!("{outcome}-missing-{field}"),
            &missing,
            false,
        );
        let encoded_key = serde_json::to_string(field).expect("key");
        let encoded_value = serde_json::to_string(&base[field]).expect("value");
        wire(
            output,
            &format!("{outcome}-duplicate-{field}"),
            &base.to_string().replacen(
                &format!("{encoded_key}:"),
                &format!("{encoded_key}:{encoded_value},{encoded_key}:"),
                1,
            ),
            false,
        );
    }
    let mut extra = base.clone();
    extra["provider_success"] = json!(true);
    value(output, &format!("{outcome}-unknown-field"), &extra, false);
    wire(
        output,
        &format!("{outcome}-escaped-duplicate-outcome"),
        &base.to_string().replacen(
            "\"outcome\":",
            &format!("\"outc\\u006fme\":\"{outcome}\",\"outcome\":"),
            1,
        ),
        false,
    );
    wire(
        output,
        &format!("{outcome}-bom"),
        &format!("\u{feff}{base}"),
        false,
    );
}

pub(super) fn cases() -> Value {
    let bases = [
        json!({"outcome":"denied","code":"native.denied"}),
        json!({"outcome":"indeterminate","code":"native.unavailable"}),
        json!({"outcome":"not-entered","code":"native.refused"}),
        json!({"outcome":"reserved","revision":1}),
        json!({"outcome":"unknown"}),
        json!({"outcome":"response-recorded","status":200}),
        json!({"outcome":"observed","status":200,"matched":true}),
        json!({"outcome":"observed-by-provider","status":200,
            "evidence":{"schema":crate::PUBLIC_EVIDENCE_SCHEMA,"channel":"read-back",
                "evidence_commitment":"ab".repeat(32),"observed_at":1790000000}}),
    ];
    let mut output = Vec::new();
    for base in &bases {
        shape_cases(&mut output, base);
        if base.get("status").is_some() {
            status_cases(&mut output, base);
        }
    }
    for outcome in ["denied", "indeterminate", "not-entered"] {
        refusal_cases(&mut output, outcome);
    }
    for (name, revision, accepted) in [
        ("maximum", json!(9_007_199_254_740_991_u64), true),
        ("above-maximum", json!(9_007_199_254_740_992_u64), false),
        ("u64-maximum", json!(u64::MAX), false),
        ("zero", json!(0), false),
        ("negative", json!(-1), false),
        ("boolean", json!(true), false),
        ("string", json!("1"), false),
        ("null", Value::Null, false),
    ] {
        value(
            &mut output,
            &format!("reserved-revision-{name}"),
            &json!({"outcome":"reserved","revision":revision}),
            accepted,
        );
    }
    for number in ["1.0", "1e0"] {
        wire(
            &mut output,
            &format!("reserved-revision-{number}"),
            &format!("{{\"outcome\":\"reserved\",\"revision\":{number}}}"),
            false,
        );
    }
    for (name, matched, accepted) in [
        ("false", json!(false), true),
        ("number", json!(1), false),
        ("string", json!("true"), false),
        ("null", Value::Null, false),
    ] {
        value(
            &mut output,
            &format!("observed-matched-{name}"),
            &json!({"outcome":"observed","status":200,"matched":matched}),
            accepted,
        );
    }
    for (name, response) in [
        ("array", json!([])),
        ("null", Value::Null),
        ("string", json!("unknown")),
        ("obsolete-outcome", json!({"outcome":"success"})),
    ] {
        value(&mut output, name, &response, false);
    }
    json!(output)
}
