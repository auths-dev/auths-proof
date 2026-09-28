//! The operator socket's request frame: one JSON object with exactly the
//! schema, the command, and that command's arguments. A secret, which only
//! `rotate` carries, travels in a second frame and never in this one.

use serde::Deserialize;

/// Schema of an admin request frame.
pub const ADMIN_REQUEST_SCHEMA: &str = "auths.gateway-admin-request/1";
/// Schema of an admin response frame.
pub const ADMIN_RESPONSE_SCHEMA: &str = "auths.gateway-admin-response/1";

/// One admin command and its arguments.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AdminRequestCommand {
    // Struct variants, so an argument the command does not take is
    // refused: an internally tagged unit variant ignores extra members.
    /// Stop new entries in every process sharing the store.
    Disable {},
    /// Re-enable a disabled connection.
    Enable {},
    /// Revoke the connection permanently.
    Revoke {},
    /// Rotate the credential; the secret follows in a second frame.
    Rotate {},
    /// Report connection state.
    Status {},
    /// Re-observe one logical operation, read-only.
    Reobserve {
        /// The logical operation ID.
        operation_id: String,
    },
}

/// Parses one `auths.gateway-admin-request/1` frame.
///
/// # Errors
/// Returns `gateway.admin.invalid-frame` for anything but a JSON object with
/// exactly the schema, a known command, and that command's arguments.
pub fn parse_admin_request(bytes: &[u8]) -> Result<AdminRequestCommand, &'static str> {
    let invalid = "gateway.admin.invalid-frame";
    let mut request: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(bytes).map_err(|_| invalid)?;
    if request.remove("schema") != Some(serde_json::Value::String(ADMIN_REQUEST_SCHEMA.into())) {
        return Err(invalid);
    }
    serde_json::from_value(serde_json::Value::Object(request)).map_err(|_| invalid)
}
