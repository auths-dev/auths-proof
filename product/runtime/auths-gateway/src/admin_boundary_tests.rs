//! Native operator frame boundary and generated interface catalog artifact.
use super::*;
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf};

fn request(command: &str) -> Value {
    let mut value = json!({"schema":ADMIN_REQUEST_SCHEMA,"command":command});
    match command {
        "disable"
        | "enable"
        | "revoke"
        | "rotate"
        | "rotate-prepare"
        | "status"
        | "execution-witness"
        | "qualification-reload" => {}
        "rotate-commit" => value["commitment"] = json!("00".repeat(32)),
        "audit-export" => value["operation_id"] = json!("original"),
        "recover" => value["source_operation"] = json!("original"),
        "recovery-record" => {
            value["source_operation"] = json!("original");
            value["acquisition_operation"] = json!("independent-read");
        }
        _ => panic!("new native command requires a boundary example"),
    }
    value
}

fn record(cases: &mut Vec<Value>, name: &str, bytes: Vec<u8>, accepted: bool) {
    let result = parse_admin_request(&bytes);
    assert_eq!(result.is_ok(), accepted, "{name}");
    if !accepted {
        assert_eq!(result, Err("gateway.admin.invalid-frame"));
    }
    cases.push(json!({"case":name,"input":String::from_utf8(bytes).expect("JSON fixture"),
        "accepted":accepted,"refusal":if accepted {None} else {Some("gateway.admin.invalid-frame")}}));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one finite native parser corpus constructs its boundary artifact"
)]
fn admin_request_boundary_fixture_is_current() {
    let commands: BTreeSet<_> = ADMIN_REQUEST_COMMANDS.iter().copied().collect();
    assert_eq!(commands.len(), ADMIN_REQUEST_COMMANDS.len());
    let mut cases = Vec::new();
    for command in ADMIN_REQUEST_COMMANDS {
        let value = request(command);
        record(
            &mut cases,
            &format!("{command}:valid"),
            serde_json::to_vec(&value).expect("JSON"),
            true,
        );
        for (key, field) in value.as_object().expect("request") {
            for replacement in [field.clone(), json!("altered-public-fixture")] {
                let mut bytes = serde_json::to_vec(&value).expect("JSON");
                bytes.pop();
                bytes.extend_from_slice(
                    format!(
                        ",{}:{replacement}}}",
                        serde_json::to_string(key).expect("key")
                    )
                    .as_bytes(),
                );
                record(
                    &mut cases,
                    &format!(
                        "{command}:duplicate-{key}-{}",
                        if &replacement == field {
                            "same"
                        } else {
                            "different"
                        }
                    ),
                    bytes,
                    false,
                );
            }
        }
        let mut unknown = value.clone();
        unknown["administrative_resolution"] = json!("not-entered-and-refunded");
        record(
            &mut cases,
            &format!("{command}:unknown-argument"),
            serde_json::to_vec(&unknown).expect("JSON"),
            false,
        );
        let mut wrong_type = value;
        wrong_type["command"] = json!({"name":command});
        record(
            &mut cases,
            &format!("{command}:non-string-command"),
            serde_json::to_vec(&wrong_type).expect("JSON"),
            false,
        );
    }
    for (name, bytes) in [
        ("escaped-duplicate-schema", format!(r#"{{"schema":"{ADMIN_REQUEST_SCHEMA}","\u0073chema":"{ADMIN_REQUEST_SCHEMA}","command":"status"}}"#).into_bytes()),
        ("duplicate-command-first-invalid", format!(r#"{{"schema":"{ADMIN_REQUEST_SCHEMA}","command":"unsupported","command":"status"}}"#).into_bytes()),
        ("argument-for-other-command", format!(r#"{{"schema":"{ADMIN_REQUEST_SCHEMA}","command":"disable","commitment":"public"}}"#).into_bytes()),
        ("nested-source", format!(r#"{{"schema":"{ADMIN_REQUEST_SCHEMA}","command":"recover","source_operation":{{"id":"original"}}}}"#).into_bytes()),
        ("obsolete-command", format!(r#"{{"schema":"{ADMIN_REQUEST_SCHEMA}","command":"reobserve","operation_id":"original"}}"#).into_bytes()),
        ("non-object", b"[]".to_vec()),
        ("trailing-data", format!(r#"{{"schema":"{ADMIN_REQUEST_SCHEMA}","command":"status"}} null"#).into_bytes()),
    ] {
        record(&mut cases, name, bytes, false);
    }
    let mut boundary = serde_json::to_vec(&request("status")).expect("JSON");
    boundary.resize(MAX_ADMIN_REQUEST_BYTES, b' ');
    record(&mut cases, "byte-limit", boundary.clone(), true);
    boundary.push(b' ');
    record(&mut cases, "byte-limit-plus-one", boundary, false);
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            use tokio::io::AsyncWriteExt as _;
            let (mut sender, mut receiver) = tokio::net::UnixStream::pair().expect("socket pair");
            sender
                .write_all(
                    &u32::try_from(MAX_ADMIN_REQUEST_BYTES + 1)
                        .expect("length")
                        .to_be_bytes(),
                )
                .await
                .expect("advertise length without a body");
            let clock = crate::app::SessionClock::start(crate::app::APP_SESSION_LIMITS);
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                clock.read_frame_limited(&mut receiver, MAX_ADMIN_REQUEST_BYTES),
            )
            .await
            .expect("must refuse length before waiting for body bytes");
            assert_eq!(result, Err("gateway.ipc.invalid-size"));
        });
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.admin-request-boundary/1",
        "scope":"native closed decoder and enum-generated interface catalog; decoding grants no operator, provider or recovery authority",
        "maximum_command_bytes":MAX_ADMIN_REQUEST_BYTES,"oversized_advertised_length_refused_before_body":true,"application_schemas":crate::app::APPLICATION_REQUEST_SCHEMAS,
        "operator_commands":ADMIN_REQUEST_COMMANDS,"cases":cases})).expect("artifact");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/admin-request-boundary.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("fixture");
    }
    assert_eq!(std::fs::read(path).expect("artifact"), artifact);
}
