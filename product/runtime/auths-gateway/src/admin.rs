//! The operator socket's request frame: one JSON object with exactly the
//! schema, the command, and that command's arguments. Rotation secrets and
//! recovery proof/action/approval inputs travel in a second bounded frame.

use serde::Deserialize;

/// Schema of an admin request frame.
pub const ADMIN_REQUEST_SCHEMA: &str = "auths.gateway-admin-request/2";
/// Schema of an admin response frame.
pub const ADMIN_RESPONSE_SCHEMA: &str = "auths.gateway-admin-response/2";

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
    /// Store a successor credential without publishing it; the secret
    /// follows in a second frame. Answers with its reference commitment.
    RotatePrepare {},
    /// Publish the prepared successor the commitment names.
    RotateCommit {
        /// The reference commitment `rotate-prepare` answered with, as 64
        /// lowercase hexadecimal characters.
        commitment: String,
    },
    /// Report connection state.
    Status {},
    /// Read process-local custody and transport measurements; grants no authority.
    ExecutionWitness {},
    /// Read the qualification inputs the operator placed on this host again
    /// and report the resulting state.
    QualificationReload {},
    /// Acquire/refine one recovery read; a native submission follows in frame 2.
    Recover {
        /// Retained source mutation whose contract the read must bind.
        source_operation: String,
    },
    /// Record evidence from an existing acquisition without provider/custody I/O.
    RecoveryRecord {
        /// Retained source mutation.
        source_operation: String,
        /// Separately authorized read whose response is already retained.
        acquisition_operation: String,
    },
}

/// Parses one `auths.gateway-admin-request/2` frame.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(command: &str) -> Result<AdminRequestCommand, &'static str> {
        parse_admin_request(
            format!("{{\"schema\":\"{ADMIN_REQUEST_SCHEMA}\",{command}}}").as_bytes(),
        )
    }

    #[test]
    fn two_phase_rotation_frames_are_closed() {
        assert_eq!(
            parse("\"command\":\"rotate-prepare\""),
            Ok(AdminRequestCommand::RotatePrepare {})
        );
        assert_eq!(
            parse("\"command\":\"rotate-commit\",\"commitment\":\"ab\""),
            Ok(AdminRequestCommand::RotateCommit {
                commitment: "ab".to_owned()
            })
        );
        assert_eq!(
            parse("\"command\":\"qualification-reload\""),
            Ok(AdminRequestCommand::QualificationReload {})
        );
        assert_eq!(
            parse("\"command\":\"execution-witness\""),
            Ok(AdminRequestCommand::ExecutionWitness {})
        );
        for refused in [
            "\"command\":\"execution-witness\",\"reset\":true",
            "\"command\":\"qualification-reload\",\"state\":\"qualified\"",
            "\"command\":\"qualification-reload\",\"policy\":\"optional\"",
            "\"command\":\"qualification-import\"",
            "\"command\":\"rotate-commit\"",
            "\"command\":\"rotate-prepare\",\"commitment\":\"ab\"",
            "\"command\":\"rotate-prepare\",\"secret\":\"s\"",
            "\"command\":\"rotate-commit\",\"commitment\":\"ab\",\"generation\":2",
            "\"command\":\"rotate-rollback\"",
        ] {
            assert_eq!(
                parse(refused),
                Err("gateway.admin.invalid-frame"),
                "{refused}"
            );
        }
    }
}
