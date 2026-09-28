//! Application and admin frames: parsing never panics and accepts only the
//! closed schemas.

#![no_main]

use auths_gateway::admin::{ADMIN_REQUEST_SCHEMA, parse_admin_request};
use auths_gateway::app::{APP_OBSERVE_SCHEMA, APP_REQUEST_SCHEMA};
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
            _ => APP_OBSERVE_SCHEMA,
        };
        assert_eq!(schema().as_deref(), Some(expected));
    }
    if parse_admin_request(data).is_ok() {
        assert_eq!(schema().as_deref(), Some(ADMIN_REQUEST_SCHEMA));
    }
});
