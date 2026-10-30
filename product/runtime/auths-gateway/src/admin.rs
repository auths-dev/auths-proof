//! The operator socket's request frame: one JSON object with exactly the
//! schema, the command, and that command's arguments. Rotation secrets and
//! recovery proof/action/approval inputs travel in a second bounded frame.

use serde::Deserialize;

#[cfg(all(test, unix))]
#[path = "admin_boundary_tests.rs"]
mod boundary_tests;

/// Schema of an admin request frame.
pub const ADMIN_REQUEST_SCHEMA: &str = "auths.gateway-admin-request/2";
/// Schema of an admin response frame.
pub const ADMIN_RESPONSE_SCHEMA: &str = "auths.gateway-admin-response/2";

/// Largest operator command object; secrets and native submissions use their
/// own second frames. Five bounded string fields need substantially less space.
pub const MAX_ADMIN_REQUEST_BYTES: usize = 4096;

macro_rules! admin_commands {
    ($( $(#[$variant_doc:meta])* $variant:ident($name:literal) {
        $( $(#[$field_doc:meta])* $field:ident: $field_type:ty ),* $(,)?
    } ),* $(,)?) => {
        /// One closed operator command and its arguments.
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
        #[serde(tag = "command", deny_unknown_fields)]
        pub enum AdminRequestCommand {
            $( $(#[$variant_doc])* #[serde(rename = $name)] $variant {
                $( $(#[$field_doc])* $field: $field_type ),*
            } ),*
        }
        /// Complete operator command catalog, generated with the native enum.
        pub const ADMIN_REQUEST_COMMANDS: &[&str] = &[$($name),*];
        const ARGUMENT_NAMES: &[&str] = &[$($(stringify!($field),)*)*];
    };
}

admin_commands! {
    // Struct variants, so an argument the command does not take is
    // refused: an internally tagged unit variant ignores extra members.
    /// Stop new entries in every process sharing the store.
    Disable("disable") {},
    /// Re-enable a disabled connection.
    Enable("enable") {},
    /// Revoke the connection permanently.
    Revoke("revoke") {},
    /// Rotate the credential; the secret follows in a second frame.
    Rotate("rotate") {},
    /// Store a successor credential without publishing it; the secret
    /// follows in a second frame. Answers with its reference commitment.
    RotatePrepare("rotate-prepare") {},
    /// Publish the prepared successor the commitment names.
    RotateCommit("rotate-commit") {
        /// The reference commitment `rotate-prepare` answered with, as 64
        /// lowercase hexadecimal characters.
        commitment: String,
    },
    /// Report connection state.
    Status("status") {},
    /// Read process-local custody and transport measurements; grants no authority.
    ExecutionWitness("execution-witness") {},
    /// Read the qualification inputs the operator placed on this host again
    /// and report the resulting state.
    QualificationReload("qualification-reload") {},
    /// Acquire/refine one recovery read; a native submission follows in frame 2.
    Recover("recover") {
        /// Retained source mutation whose contract the read must bind.
        source_operation: String,
    },
    /// Record evidence from an existing acquisition without provider/custody I/O.
    RecoveryRecord("recovery-record") {
        /// Retained source mutation.
        source_operation: String,
        /// Separately authorized read whose response is already retained.
        acquisition_operation: String,
    },
}

struct AdminFields(serde_json::Map<String, serde_json::Value>);

impl<'de> Deserialize<'de> for AdminFields {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = AdminFields;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("unique operator command string fields")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut fields = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if fields.contains_key(&key)
                        || (key != "schema"
                            && key != "command"
                            && !ARGUMENT_NAMES.contains(&key.as_str()))
                    {
                        return Err(serde::de::Error::custom("invalid operator command field"));
                    }
                    let value = map.next_value::<String>()?;
                    fields.insert(key, serde_json::Value::String(value));
                }
                Ok(AdminFields(fields))
            }
        }
        deserializer.deserialize_map(Fields)
    }
}

/// Parses one `auths.gateway-admin-request/2` frame.
///
/// # Errors
/// Returns `gateway.admin.invalid-frame` for anything but a JSON object with
/// exactly the schema, a known command, and that command's arguments. Duplicate
/// members, non-string values and objects over `MAX_ADMIN_REQUEST_BYTES` are refused.
pub fn parse_admin_request(bytes: &[u8]) -> Result<AdminRequestCommand, &'static str> {
    let invalid = "gateway.admin.invalid-frame";
    if bytes.len() > MAX_ADMIN_REQUEST_BYTES {
        return Err(invalid);
    }
    let AdminFields(mut request) = serde_json::from_slice(bytes).map_err(|_| invalid)?;
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
