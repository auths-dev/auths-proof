//! Application and admin frames: parsing never panics and accepts only the
//! closed schemas.

#![no_main]

use auths_gateway::admin::{ADMIN_REQUEST_SCHEMA, parse_admin_request};
use auths_gateway::app::{
    APP_CONTENT_HISTORY_SCHEMA, APP_CONTENT_SCHEMA, APP_DISCLOSURE_ACK_SCHEMA,
    APP_DISCLOSURE_SCHEMA, APP_OBSERVE_SCHEMA, APP_RECOVERY_SCHEMA, APP_REQUEST_SCHEMA,
};
use auths_gateway::fuzzing;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let schema = || {
        serde_json::from_slice::<Value>(data)
            .ok()
            .and_then(|value| {
                value
                    .get("schema")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
    };
    if let Some(kind) = fuzzing::app_frame_kind(data) {
        let expected = match kind {
            "submit" => APP_REQUEST_SCHEMA,
            "observe" => APP_OBSERVE_SCHEMA,
            "recover" => APP_RECOVERY_SCHEMA,
            "content" => APP_CONTENT_SCHEMA,
            "disclose" => APP_DISCLOSURE_SCHEMA,
            "content-history" => APP_CONTENT_HISTORY_SCHEMA,
            "disclosure-ack" => APP_DISCLOSURE_ACK_SCHEMA,
            _ => panic!("unknown closed application frame"),
        };
        assert_eq!(schema().as_deref(), Some(expected));
    }
    if parse_admin_request(data).is_ok() {
        assert_eq!(schema().as_deref(), Some(ADMIN_REQUEST_SCHEMA));
    }
});
