//! Offline echo verification: whether a provider record an auditor fetched
//! with their own access holds the echo token of one authorized action.
//!
//! Nothing here reads a network, a socket, or gateway state. The action's
//! commitment is computed exactly as native verification computes it, over
//! canonical action bytes under `auths.canonical-action.v1`, and the token
//! with [`echo_token`]. The token is unkeyed: a match shows the record is
//! consistent with this action, not who wrote it.

use crate::{CompiledRecipe, LogicalOperationId, OperatorNamespace, echo_token};
use auths_model::VerifierLimits;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// Schema of an echo verification result.
pub const ECHO_VERIFICATION_SCHEMA: &str = "auths.gateway-echo-verification/1";
/// Largest provider record the verification reads, in bytes.
pub const MAX_ECHO_RECORD_BYTES: usize = 1024 * 1024;
/// Largest JSON pointer the verification accepts, in bytes.
pub const MAX_ECHO_POINTER_BYTES: usize = 256;
/// What a result states, and what it does not.
pub const ECHO_VERIFICATION_NOTE: &str =
    "a match shows the record is consistent with this action; it does not show who wrote it";

const MAX_ACTION_BYTES: usize = 64 * 1024;
const MAX_BUNDLE_BYTES: usize = crate::MAX_AUDIT_BUNDLE_BYTES;

/// What the record holds at the pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EchoResult {
    /// The pointer holds exactly this action's token.
    Match,
    /// The pointer holds another value.
    Mismatch,
    /// The pointer is absent or holds `null`.
    Absent,
}

impl EchoResult {
    /// Returns the stable code of the result.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Match => "gateway.echo-verify.match",
            Self::Mismatch => "gateway.echo-verify.mismatch",
            Self::Absent => "gateway.echo-verify.absent",
        }
    }
}

/// `auths.gateway-echo-verification/1`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EchoVerification {
    /// [`ECHO_VERIFICATION_SCHEMA`].
    pub schema: &'static str,
    /// The stable code of the result.
    pub code: &'static str,
    /// The echo token of the action.
    pub token: String,
    /// What the record holds at the pointer.
    pub result: EchoResult,
    /// Lowercase hex SHA-256 of the exact record bytes.
    pub record_sha256: String,
    /// The JSON pointer read.
    pub pointer: String,
    /// [`ECHO_VERIFICATION_NOTE`].
    pub note: &'static str,
}

/// Why no result could be computed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EchoVerifyError {
    /// The record is empty, oversized, or not JSON.
    #[error("the record is not a bounded JSON document")]
    RecordInvalid,
    /// The action is not canonical, the bundle does not carry the
    /// operation, or the namespace or operation ID is malformed.
    #[error("the action is not a canonical action of this operation")]
    ActionInvalid,
    /// The pointer is not a bounded JSON pointer.
    #[error("the pointer is not a bounded JSON pointer")]
    PointerInvalid,
}

impl EchoVerifyError {
    /// Returns the stable code of the refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RecordInvalid => "gateway.echo-verify.record-invalid",
            Self::ActionInvalid => "gateway.echo-verify.action-invalid",
            Self::PointerInvalid => "gateway.echo-verify.pointer-invalid",
        }
    }
}

/// The commitment native verification computes for canonical action bytes.
/// Refuses bytes that do not decode, or that decode but re-encode to other
/// bytes.
///
/// # Errors
/// Returns [`EchoVerifyError::ActionInvalid`] for empty, oversized, or
/// non-canonical bytes.
pub fn canonical_action_commitment(action: &[u8]) -> Result<[u8; 32], EchoVerifyError> {
    if action.is_empty() || action.len() > MAX_ACTION_BYTES {
        return Err(EchoVerifyError::ActionInvalid);
    }
    let decoded = auths_codec::decode_canonical_action(action, &VerifierLimits::default())
        .map_err(|_| EchoVerifyError::ActionInvalid)?;
    let encoded = auths_codec::encode_canonical_action(&decoded)
        .map_err(|_| EchoVerifyError::ActionInvalid)?;
    if encoded != action {
        return Err(EchoVerifyError::ActionInvalid);
    }
    auths_codec::domain_commitment("auths.canonical-action.v1", action)
        .map(|digest| *digest.as_bytes())
        .map_err(|_| EchoVerifyError::ActionInvalid)
}

/// Compares the record at `pointer` with the echo token of one action.
///
/// # Errors
/// Returns the refusal whose code names the invalid input; the pointer is
/// checked before the record is parsed, and both before the action.
pub fn echo_verify(
    record: &[u8],
    pointer: &str,
    namespace: &str,
    operation_id: &str,
    action: &[u8],
) -> Result<EchoVerification, EchoVerifyError> {
    if !valid_pointer(pointer) {
        return Err(EchoVerifyError::PointerInvalid);
    }
    if record.is_empty() || record.len() > MAX_ECHO_RECORD_BYTES {
        return Err(EchoVerifyError::RecordInvalid);
    }
    let document: Value =
        serde_json::from_slice(record).map_err(|_| EchoVerifyError::RecordInvalid)?;
    let namespace =
        OperatorNamespace::parse(namespace).map_err(|_| EchoVerifyError::ActionInvalid)?;
    let operation =
        LogicalOperationId::parse(operation_id).map_err(|_| EchoVerifyError::ActionInvalid)?;
    let commitment = canonical_action_commitment(action)?;
    let token = echo_token(&namespace, &operation, &commitment);
    let result = match document.pointer(pointer) {
        None | Some(Value::Null) => EchoResult::Absent,
        Some(Value::String(found)) if found == &token => EchoResult::Match,
        Some(_) => EchoResult::Mismatch,
    };
    Ok(EchoVerification {
        schema: ECHO_VERIFICATION_SCHEMA,
        code: result.code(),
        token,
        result,
        record_sha256: hex::encode(Sha256::digest(record)),
        pointer: pointer.to_owned(),
        note: ECHO_VERIFICATION_NOTE,
    })
}

#[derive(Deserialize)]
struct BundleView {
    recipe_b64: String,
    profile_lock_b64: String,
    entries: Vec<BundleEntryView>,
}

#[derive(Deserialize)]
struct BundleEntryView {
    operation_id: String,
    action_b64: String,
}

/// [`echo_verify`] for the operation an audit bundle carries: the namespace
/// comes from the bundle's recipe and the action from its entry.
///
/// # Errors
/// Returns [`EchoVerifyError::ActionInvalid`] when the bundle is malformed,
/// its recipe does not compile, or it carries no entry for `operation_id`,
/// and otherwise [`echo_verify`]'s refusals.
pub fn echo_verify_bundle(
    record: &[u8],
    pointer: &str,
    bundle: &[u8],
    operation_id: &str,
) -> Result<EchoVerification, EchoVerifyError> {
    if !valid_pointer(pointer) {
        return Err(EchoVerifyError::PointerInvalid);
    }
    if bundle.is_empty() || bundle.len() > MAX_BUNDLE_BYTES {
        return Err(EchoVerifyError::ActionInvalid);
    }
    let view: BundleView =
        serde_json::from_slice(bundle).map_err(|_| EchoVerifyError::ActionInvalid)?;
    let decode = |text: &str| {
        Base64UrlUnpadded::decode_vec(text).map_err(|_| EchoVerifyError::ActionInvalid)
    };
    let recipe =
        CompiledRecipe::compile(&decode(&view.recipe_b64)?, &decode(&view.profile_lock_b64)?)
            .map_err(|_| EchoVerifyError::ActionInvalid)?;
    let mut matching = view
        .entries
        .iter()
        .filter(|entry| entry.operation_id == operation_id);
    let (Some(entry), None) = (matching.next(), matching.next()) else {
        return Err(EchoVerifyError::ActionInvalid);
    };
    let action = decode(&entry.action_b64)?;
    echo_verify(
        record,
        pointer,
        recipe.namespace().as_str(),
        operation_id,
        &action,
    )
}

/// A JSON pointer of 1 to [`MAX_ECHO_POINTER_BYTES`] bytes that starts with
/// `/` and escapes `~` only as `~0` or `~1`.
fn valid_pointer(pointer: &str) -> bool {
    let bytes = pointer.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_ECHO_POINTER_BYTES || bytes[0] != b'/' {
        return false;
    }
    bytes
        .iter()
        .enumerate()
        .all(|(index, byte)| *byte != b'~' || matches!(bytes.get(index + 1), Some(b'0' | b'1')))
        && !pointer.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn action() -> Vec<u8> {
        let call = crate::harness::call(
            &json!({"operation_id": "refund-1", "record_id": "recTEST0000000001"})
                .as_object()
                .expect("object")
                .clone(),
        )
        .expect("call");
        let bytes = call.canonical_bytes().expect("canonical call");
        let canonical =
            <auths_profile_mcp::McpProfile as auths_profile_api::ActionProfile>::canonicalize(
                &auths_profile_mcp::McpProfile,
                &bytes,
            )
            .expect("canonical action");
        auths_codec::encode_canonical_action(&canonical).expect("encoded")
    }

    fn token() -> String {
        let commitment = canonical_action_commitment(&action()).expect("commitment");
        echo_token(
            &OperatorNamespace::parse("observer-demo").expect("namespace"),
            &LogicalOperationId::parse("refund-1").expect("operation"),
            &commitment,
        )
    }

    #[test]
    fn match_mismatch_and_absent_each_have_their_code() {
        let record = json!({"metadata": {"auths_echo": token()}, "other": "x"}).to_string();
        let verified = echo_verify(
            record.as_bytes(),
            "/metadata/auths_echo",
            "observer-demo",
            "refund-1",
            &action(),
        )
        .expect("verified");
        assert_eq!(verified.result, EchoResult::Match);
        assert_eq!(verified.code, "gateway.echo-verify.match");
        assert_eq!(verified.token, token());
        assert_eq!(verified.note, ECHO_VERIFICATION_NOTE);
        assert_eq!(
            verified.record_sha256,
            hex::encode(Sha256::digest(record.as_bytes()))
        );
        let other = echo_verify(
            record.as_bytes(),
            "/other",
            "observer-demo",
            "refund-1",
            &action(),
        )
        .expect("verified");
        assert_eq!(other.code, "gateway.echo-verify.mismatch");
        let absent = echo_verify(
            record.as_bytes(),
            "/metadata/missing",
            "observer-demo",
            "refund-1",
            &action(),
        )
        .expect("verified");
        assert_eq!(absent.code, "gateway.echo-verify.absent");
        let another_operation = echo_verify(
            record.as_bytes(),
            "/metadata/auths_echo",
            "observer-demo",
            "refund-2",
            &action(),
        )
        .expect("verified");
        assert_eq!(another_operation.result, EchoResult::Mismatch);
    }

    #[test]
    fn invalid_inputs_are_refused_with_their_codes() {
        let record = br#"{"a": 1}"#;
        let refuse = |record: &[u8], pointer: &str, action: &[u8]| {
            echo_verify(record, pointer, "observer-demo", "refund-1", action)
                .err()
                .map(EchoVerifyError::code)
        };
        assert_eq!(
            refuse(record, "a", &action()),
            Some("gateway.echo-verify.pointer-invalid")
        );
        assert_eq!(
            refuse(record, "/a~2", &action()),
            Some("gateway.echo-verify.pointer-invalid")
        );
        assert_eq!(
            refuse(b"not json", "/a", &action()),
            Some("gateway.echo-verify.record-invalid")
        );
        assert_eq!(
            refuse(&vec![b' '; MAX_ECHO_RECORD_BYTES + 1], "/a", &action()),
            Some("gateway.echo-verify.record-invalid")
        );
        let mut noncanonical = action();
        noncanonical.push(0);
        assert_eq!(
            refuse(record, "/a", &noncanonical),
            Some("gateway.echo-verify.action-invalid")
        );
        assert_eq!(
            refuse(record, "/a", b""),
            Some("gateway.echo-verify.action-invalid")
        );
    }
}
