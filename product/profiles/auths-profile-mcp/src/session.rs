use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{McpCommand, PROFILE_ID, PROFILE_VERSION};
use auths_model::SignedGrant;

pub const MCP_SESSION_SEMANTIC_SUBJECT: &str = "auths.mcp-session/1";
pub const MAX_APPLICATION_REQUEST_ID_BYTES: usize = 128;
pub const MAX_HANDLER_OUTPUT_BYTES: usize = 1024 * 1024;
pub const MAX_HANDLER_OUTPUT_DEPTH: usize = 32;
pub const MAX_HANDLER_COUNT: usize = 128;
pub const MAX_SAFE_ERROR_BYTES: usize = 256;
pub const MAX_HANDLER_DURATION_MS: u64 = 300_000;
pub const DEFAULT_HANDLER_DURATION_MS: u64 = 30_000;
pub const MCP_AUTHORITY_COMMITMENT_SUBJECT: &str = "auths.mcp-authority-chain/1";
const MAX_RECOVERY_RECORD_BYTES: usize = 2 * 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpProfileLimitsV1 {
    pub tool_count: usize,
    pub tool_name_bytes: usize,
    pub input_bytes: usize,
    pub input_depth: usize,
    pub output_bytes: usize,
    pub output_depth: usize,
    pub safe_error_bytes: usize,
    pub maximum_duration_ms: u64,
    pub default_duration_ms: u64,
}

#[must_use]
pub const fn mcp_profile_limits_v1() -> McpProfileLimitsV1 {
    McpProfileLimitsV1 {
        tool_count: MAX_HANDLER_COUNT,
        tool_name_bytes: crate::MAX_TOOL_NAME_BYTES,
        input_bytes: crate::MAX_CANONICAL_CALL_BYTES,
        input_depth: MAX_HANDLER_OUTPUT_DEPTH,
        output_bytes: MAX_HANDLER_OUTPUT_BYTES,
        output_depth: MAX_HANDLER_OUTPUT_DEPTH,
        safe_error_bytes: MAX_SAFE_ERROR_BYTES,
        maximum_duration_ms: MAX_HANDLER_DURATION_MS,
        default_duration_ms: DEFAULT_HANDLER_DURATION_MS,
    }
}

pub struct McpSessionKey([u8; 32]);

impl McpSessionKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpExecutionReference(String);

impl McpExecutionReference {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpReservationResult {
    Acquired,
    ExactReplay,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum McpCause {
    Cancelled,
    InvalidOutput,
    LimitExceeded,
    Timeout,
    Unavailable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpHandlerEffect {
    NotApplied,
    Applied,
    Possible,
}

#[derive(Clone, Debug, PartialEq)]
pub struct McpHandlerResult {
    effect: McpHandlerEffect,
    output: Option<Value>,
    cause: Option<McpCause>,
}

impl McpHandlerResult {
    /// Parses one closed, bounded handler observation.
    ///
    /// # Errors
    ///
    /// Returns [`McpSessionError::InvalidHandlerOutput`] for a mismatched,
    /// malformed, oversized, or excessively nested output.
    pub fn parse(
        effect: McpHandlerEffect,
        output: Option<&[u8]>,
        cause: Option<McpCause>,
    ) -> Result<Self, McpSessionError> {
        let parsed = match (effect, output) {
            (McpHandlerEffect::Applied, Some(bytes)) => {
                if bytes.is_empty() || bytes.len() > MAX_HANDLER_OUTPUT_BYTES {
                    return Err(McpSessionError::InvalidHandlerOutput);
                }
                let value: Value = serde_json::from_slice(bytes)
                    .map_err(|_| McpSessionError::InvalidHandlerOutput)?;
                if json_depth(&value) > MAX_HANDLER_OUTPUT_DEPTH {
                    return Err(McpSessionError::InvalidHandlerOutput);
                }
                Some(value)
            }
            (McpHandlerEffect::Applied, None)
            | (McpHandlerEffect::NotApplied | McpHandlerEffect::Possible, Some(_)) => {
                return Err(McpSessionError::InvalidHandlerOutput);
            }
            (McpHandlerEffect::NotApplied | McpHandlerEffect::Possible, None) => None,
        };
        Ok(Self {
            effect,
            output: parsed,
            cause,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum McpSessionStep {
    Reserve {
        execution_id: String,
    },
    MarkProviderEntry {
        execution_id: String,
    },
    Invoke {
        execution_id: String,
        service: String,
        tool: String,
        arguments_json: Vec<u8>,
    },
    PersistReceipt {
        execution_id: String,
        receipt_json: Vec<u8>,
    },
    Reconcile {
        execution_id: String,
        service: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum McpTerminal {
    Completed {
        execution_id: String,
        output_json: Vec<u8>,
        receipt_json: Vec<u8>,
    },
    NotApplied {
        execution_id: String,
    },
    ExactReplay {
        execution_id: String,
    },
    Conflict {
        execution_id: String,
    },
    Recoverable {
        execution_id: String,
        reference: McpExecutionReference,
        record_json: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpSessionError {
    InvalidRequestId,
    InvalidHandlerOutput,
    InvalidTransition,
    ResultPending,
    Terminal,
    InvalidRecoveryRecord,
    InvalidExecutionReference,
    ReceiptPersistenceFailed,
    InvalidAuthority,
}

impl core::fmt::Display for McpSessionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequestId => "invalid MCP application request identifier",
            Self::InvalidHandlerOutput => "invalid bounded MCP handler output",
            Self::InvalidTransition => "invalid MCP execution transition",
            Self::ResultPending => "MCP execution step result is pending",
            Self::Terminal => "MCP execution session is terminal",
            Self::InvalidRecoveryRecord => "invalid MCP recovery record",
            Self::InvalidExecutionReference => "invalid MCP execution reference",
            Self::ReceiptPersistenceFailed => "MCP receipt persistence failed",
            Self::InvalidAuthority => "invalid MCP authority chain",
        })
    }
}

/// Commits only the canonical signed grant chain, excluding per-attempt action
/// signatures and evidence.
///
/// # Errors
///
/// Returns [`McpSessionError::InvalidAuthority`] for an empty or unencodable
/// grant chain.
pub fn mcp_authority_commitment(grants: &[SignedGrant]) -> Result<[u8; 32], McpSessionError> {
    if grants.is_empty() {
        return Err(McpSessionError::InvalidAuthority);
    }
    let mut hasher = Sha256::new();
    hasher.update(MCP_AUTHORITY_COMMITMENT_SUBJECT.as_bytes());
    for grant in grants {
        let bytes = auths_codec::encode_signed_grant(grant)
            .map_err(|_| McpSessionError::InvalidAuthority)?;
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(hasher.finalize().into())
}

impl std::error::Error for McpSessionError {}

pub struct McpExecutionSession {
    execution_id: String,
    key: McpSessionKey,
    service: String,
    tool: String,
    arguments_json: Vec<u8>,
    action_commitment: [u8; 32],
    authority_commitment: [u8; 32],
    context_commitment: [u8; 32],
    state: SessionState,
}

enum SessionState {
    ReadyReserve,
    WaitingReservation,
    ReadyProviderEntry,
    WaitingProviderEntry,
    ReadyInvoke,
    WaitingHandler,
    ReadyReceipt { output: Value, receipt: Vec<u8> },
    WaitingReceipt { output: Value, receipt: Vec<u8> },
    ReadyReconcile,
    WaitingReconcile,
    Terminal(McpTerminal),
    Invalid,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryRecord {
    schema: String,
    semantic_subject: String,
    profile: String,
    profile_version: u16,
    execution_id: String,
    service: String,
    kind: RecoveryKind,
    action_commitment: String,
    authority_commitment: String,
    context_commitment: String,
    output: Option<Value>,
    receipt: Option<Value>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RecoveryKind {
    Possible,
    ReceiptPending,
}

impl McpExecutionSession {
    /// Consumes a verified command and binds one execution identity.
    ///
    /// # Errors
    ///
    /// Returns a typed session error for an invalid request identifier or
    /// command projection.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn begin(
        command: McpCommand,
        action_commitment: [u8; 32],
        authority_commitment: [u8; 32],
        context_commitment: [u8; 32],
        request_id: Option<&str>,
        key: McpSessionKey,
    ) -> Result<Self, McpSessionError> {
        let request_id = request_id.unwrap_or("");
        if request_id.len() > MAX_APPLICATION_REQUEST_ID_BYTES
            || !request_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
            })
        {
            return Err(McpSessionError::InvalidRequestId);
        }
        let arguments_json = serde_json_canonicalizer::to_vec(command.arguments())
            .map_err(|_| McpSessionError::InvalidHandlerOutput)?;
        let service = command.call().service().to_owned();
        let tool = command.name().to_owned();
        let execution_id = derive_execution_id(
            &command,
            action_commitment,
            authority_commitment,
            request_id,
        )?;
        Ok(Self {
            execution_id,
            key,
            service,
            tool,
            arguments_json,
            action_commitment,
            authority_commitment,
            context_commitment,
            state: SessionState::ReadyReserve,
        })
    }

    /// Authenticates and restores a profile-owned recovery record.
    ///
    /// # Errors
    ///
    /// Returns a typed session error when the reference, record, profile, or
    /// semantic subject does not match.
    pub fn resume(
        key: McpSessionKey,
        reference: &str,
        record_json: &[u8],
    ) -> Result<Self, McpSessionError> {
        if record_json.is_empty() || record_json.len() > MAX_RECOVERY_RECORD_BYTES {
            return Err(McpSessionError::InvalidRecoveryRecord);
        }
        verify_reference(&key, reference, record_json)?;
        let record: RecoveryRecord = serde_json::from_slice(record_json)
            .map_err(|_| McpSessionError::InvalidRecoveryRecord)?;
        let canonical = serde_json_canonicalizer::to_vec(&record)
            .map_err(|_| McpSessionError::InvalidRecoveryRecord)?;
        if canonical != record_json
            || record.schema != "auths.mcp-recovery/1"
            || record.semantic_subject != MCP_SESSION_SEMANTIC_SUBJECT
            || record.profile != PROFILE_ID
            || record.profile_version != PROFILE_VERSION
            || !reference.starts_with(&format!("mcp1.{}.", record.execution_id))
        {
            return Err(McpSessionError::InvalidRecoveryRecord);
        }
        let action_commitment = parse_digest(&record.action_commitment)?;
        let authority_commitment = parse_digest(&record.authority_commitment)?;
        let context_commitment = parse_digest(&record.context_commitment)?;
        let state = match record.kind {
            RecoveryKind::Possible => SessionState::ReadyReconcile,
            RecoveryKind::ReceiptPending => {
                let output = record
                    .output
                    .ok_or(McpSessionError::InvalidRecoveryRecord)?;
                let receipt = record
                    .receipt
                    .ok_or(McpSessionError::InvalidRecoveryRecord)?;
                SessionState::ReadyReceipt {
                    output,
                    receipt: serde_json_canonicalizer::to_vec(&receipt)
                        .map_err(|_| McpSessionError::InvalidRecoveryRecord)?,
                }
            }
        };
        Ok(Self {
            execution_id: record.execution_id,
            key,
            service: record.service,
            tool: String::new(),
            arguments_json: Vec::new(),
            action_commitment,
            authority_commitment,
            context_commitment,
            state,
        })
    }

    #[must_use]
    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    /// Releases exactly one bounded side-effect request.
    ///
    /// # Errors
    ///
    /// Returns [`McpSessionError::ResultPending`] until the previously released
    /// step receives a parsed result, or a terminal/transition error.
    pub fn next_step(&mut self) -> Result<McpSessionStep, McpSessionError> {
        let state = core::mem::replace(&mut self.state, SessionState::Invalid);
        let (next, step) = match state {
            SessionState::ReadyReserve => (
                SessionState::WaitingReservation,
                McpSessionStep::Reserve {
                    execution_id: self.execution_id.clone(),
                },
            ),
            SessionState::ReadyProviderEntry => (
                SessionState::WaitingProviderEntry,
                McpSessionStep::MarkProviderEntry {
                    execution_id: self.execution_id.clone(),
                },
            ),
            SessionState::ReadyInvoke => (
                SessionState::WaitingHandler,
                McpSessionStep::Invoke {
                    execution_id: self.execution_id.clone(),
                    service: self.service.clone(),
                    tool: self.tool.clone(),
                    arguments_json: self.arguments_json.clone(),
                },
            ),
            SessionState::ReadyReceipt { output, receipt } => {
                let step = McpSessionStep::PersistReceipt {
                    execution_id: self.execution_id.clone(),
                    receipt_json: receipt.clone(),
                };
                (SessionState::WaitingReceipt { output, receipt }, step)
            }
            SessionState::ReadyReconcile => (
                SessionState::WaitingReconcile,
                McpSessionStep::Reconcile {
                    execution_id: self.execution_id.clone(),
                    service: self.service.clone(),
                },
            ),
            waiting @ (SessionState::WaitingReservation
            | SessionState::WaitingProviderEntry
            | SessionState::WaitingHandler
            | SessionState::WaitingReceipt { .. }
            | SessionState::WaitingReconcile) => {
                self.state = waiting;
                return Err(McpSessionError::ResultPending);
            }
            SessionState::Terminal(terminal) => {
                self.state = SessionState::Terminal(terminal);
                return Err(McpSessionError::Terminal);
            }
            SessionState::Invalid => return Err(McpSessionError::InvalidTransition),
        };
        self.state = next;
        Ok(step)
    }

    /// Accepts the result of the released atomic reservation.
    ///
    /// # Errors
    ///
    /// Returns [`McpSessionError::InvalidTransition`] outside the matching step.
    pub fn accept_reservation(
        &mut self,
        result: McpReservationResult,
    ) -> Result<(), McpSessionError> {
        if !matches!(self.state, SessionState::WaitingReservation) {
            return Err(McpSessionError::InvalidTransition);
        }
        self.state = match result {
            McpReservationResult::Acquired => SessionState::ReadyProviderEntry,
            McpReservationResult::ExactReplay => SessionState::Terminal(McpTerminal::ExactReplay {
                execution_id: self.execution_id.clone(),
            }),
            McpReservationResult::Conflict => SessionState::Terminal(McpTerminal::Conflict {
                execution_id: self.execution_id.clone(),
            }),
        };
        Ok(())
    }

    /// Accepts durable evidence that provider entry was recorded.
    ///
    /// # Errors
    ///
    /// Returns [`McpSessionError::InvalidTransition`] outside the matching step.
    pub fn accept_provider_entry(&mut self) -> Result<(), McpSessionError> {
        if !matches!(self.state, SessionState::WaitingProviderEntry) {
            return Err(McpSessionError::InvalidTransition);
        }
        self.state = SessionState::ReadyInvoke;
        Ok(())
    }

    /// Terminates before provider entry when cancellation is observed.
    ///
    /// # Errors
    ///
    /// Returns [`McpSessionError::InvalidTransition`] after provider entry or
    /// outside the provider-entry step.
    pub fn cancel_before_provider(&mut self) -> Result<(), McpSessionError> {
        if !matches!(
            self.state,
            SessionState::ReadyProviderEntry | SessionState::WaitingProviderEntry
        ) {
            return Err(McpSessionError::InvalidTransition);
        }
        self.state = SessionState::Terminal(McpTerminal::NotApplied {
            execution_id: self.execution_id.clone(),
        });
        Ok(())
    }

    /// Accepts one bounded handler or reconciliation observation.
    ///
    /// # Errors
    ///
    /// Returns a typed session error when no matching handler step is pending.
    pub fn accept_handler(&mut self, result: McpHandlerResult) -> Result<(), McpSessionError> {
        if !matches!(
            self.state,
            SessionState::WaitingHandler | SessionState::WaitingReconcile
        ) {
            return Err(McpSessionError::InvalidTransition);
        }
        self.accept_effect(result)
    }

    /// Accepts durable receipt persistence evidence.
    ///
    /// # Errors
    ///
    /// Returns a typed session error for an invalid step or failed persistence.
    pub fn accept_receipt(&mut self, persisted: bool) -> Result<(), McpSessionError> {
        let state = core::mem::replace(&mut self.state, SessionState::Invalid);
        let SessionState::WaitingReceipt { output, receipt } = state else {
            self.state = state;
            return Err(McpSessionError::InvalidTransition);
        };
        if persisted {
            self.state = SessionState::Terminal(McpTerminal::Completed {
                execution_id: self.execution_id.clone(),
                output_json: serde_json_canonicalizer::to_vec(&output)
                    .map_err(|_| McpSessionError::InvalidHandlerOutput)?,
                receipt_json: receipt,
            });
            Ok(())
        } else {
            self.state =
                self.recoverable(RecoveryKind::ReceiptPending, Some(output), Some(receipt))?;
            Err(McpSessionError::ReceiptPersistenceFailed)
        }
    }

    #[must_use]
    pub fn terminal(&self) -> Option<&McpTerminal> {
        let SessionState::Terminal(value) = &self.state else {
            return None;
        };
        Some(value)
    }

    fn accept_effect(&mut self, result: McpHandlerResult) -> Result<(), McpSessionError> {
        self.state = match result.effect {
            McpHandlerEffect::NotApplied => SessionState::Terminal(McpTerminal::NotApplied {
                execution_id: self.execution_id.clone(),
            }),
            McpHandlerEffect::Applied => {
                let output = result.output.ok_or(McpSessionError::InvalidHandlerOutput)?;
                let receipt = self.receipt(&output, result.cause)?;
                SessionState::ReadyReceipt { output, receipt }
            }
            McpHandlerEffect::Possible => self.recoverable(RecoveryKind::Possible, None, None)?,
        };
        Ok(())
    }

    fn receipt(&self, output: &Value, cause: Option<McpCause>) -> Result<Vec<u8>, McpSessionError> {
        let output_bytes = serde_json_canonicalizer::to_vec(output)
            .map_err(|_| McpSessionError::InvalidHandlerOutput)?;
        let receipt = ReceiptProjection {
            schema: "auths.mcp-receipt/1",
            semantic_subject: MCP_SESSION_SEMANTIC_SUBJECT,
            profile: PROFILE_ID,
            profile_version: PROFILE_VERSION,
            execution_id: &self.execution_id,
            action_commitment: hex::encode(self.action_commitment),
            authority_commitment: hex::encode(self.authority_commitment),
            context_commitment: hex::encode(self.context_commitment),
            output_digest: hex::encode(Sha256::digest(output_bytes)),
            cause,
        };
        serde_json_canonicalizer::to_vec(&receipt)
            .map_err(|_| McpSessionError::InvalidHandlerOutput)
    }

    fn recoverable(
        &self,
        kind: RecoveryKind,
        output: Option<Value>,
        receipt: Option<Vec<u8>>,
    ) -> Result<SessionState, McpSessionError> {
        let receipt = receipt
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()
            .map_err(|_| McpSessionError::InvalidRecoveryRecord)?;
        let record = RecoveryRecord {
            schema: "auths.mcp-recovery/1".into(),
            semantic_subject: MCP_SESSION_SEMANTIC_SUBJECT.into(),
            profile: PROFILE_ID.into(),
            profile_version: PROFILE_VERSION,
            execution_id: self.execution_id.clone(),
            service: self.service.clone(),
            kind,
            action_commitment: hex::encode(self.action_commitment),
            authority_commitment: hex::encode(self.authority_commitment),
            context_commitment: hex::encode(self.context_commitment),
            output,
            receipt,
        };
        let record_json = serde_json_canonicalizer::to_vec(&record)
            .map_err(|_| McpSessionError::InvalidRecoveryRecord)?;
        let reference = create_reference(&self.key, &self.execution_id, &record_json)?;
        Ok(SessionState::Terminal(McpTerminal::Recoverable {
            execution_id: self.execution_id.clone(),
            reference,
            record_json,
        }))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptProjection<'a> {
    schema: &'static str,
    semantic_subject: &'static str,
    profile: &'static str,
    profile_version: u16,
    execution_id: &'a str,
    action_commitment: String,
    authority_commitment: String,
    context_commitment: String,
    output_digest: String,
    cause: Option<McpCause>,
}

fn derive_execution_id(
    command: &McpCommand,
    action: [u8; 32],
    authority: [u8; 32],
    request_id: &str,
) -> Result<String, McpSessionError> {
    let canonical = command
        .call()
        .canonical_bytes()
        .map_err(|_| McpSessionError::InvalidHandlerOutput)?;
    let mut hasher = Sha256::new();
    hasher.update(MCP_SESSION_SEMANTIC_SUBJECT.as_bytes());
    for bytes in [action.as_slice(), authority.as_slice(), &canonical] {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.update((request_id.len() as u64).to_be_bytes());
    hasher.update(request_id.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn create_reference(
    key: &McpSessionKey,
    execution_id: &str,
    record: &[u8],
) -> Result<McpExecutionReference, McpSessionError> {
    let mut mac = HmacSha256::new_from_slice(&key.0)
        .map_err(|_| McpSessionError::InvalidExecutionReference)?;
    mac.update(record);
    Ok(McpExecutionReference(format!(
        "mcp1.{execution_id}.{}",
        hex::encode(mac.finalize().into_bytes())
    )))
}

fn verify_reference(
    key: &McpSessionKey,
    reference: &str,
    record: &[u8],
) -> Result<(), McpSessionError> {
    let tag = reference
        .rsplit_once('.')
        .ok_or(McpSessionError::InvalidExecutionReference)?
        .1;
    let tag = hex::decode(tag).map_err(|_| McpSessionError::InvalidExecutionReference)?;
    let mut mac = HmacSha256::new_from_slice(&key.0)
        .map_err(|_| McpSessionError::InvalidExecutionReference)?;
    mac.update(record);
    mac.verify_slice(&tag)
        .map_err(|_| McpSessionError::InvalidExecutionReference)
}

fn parse_digest(value: &str) -> Result<[u8; 32], McpSessionError> {
    let decoded = hex::decode(value).map_err(|_| McpSessionError::InvalidRecoveryRecord)?;
    decoded
        .try_into()
        .map_err(|_| McpSessionError::InvalidRecoveryRecord)
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::McpToolCall;
    use serde_json::Map;

    fn command() -> McpCommand {
        let call = McpToolCall::new("reports", "publish", Map::new()).unwrap();
        McpCommand { call }
    }

    fn session() -> McpExecutionSession {
        McpExecutionSession::begin(
            command(),
            [1; 32],
            [2; 32],
            [3; 32],
            Some("request-1"),
            McpSessionKey::new([9; 32]),
        )
        .unwrap()
    }

    #[test]
    fn one_accepted_result_gates_every_side_effect() {
        let mut session = session();
        assert!(matches!(
            session.next_step().unwrap(),
            McpSessionStep::Reserve { .. }
        ));
        assert_eq!(session.next_step(), Err(McpSessionError::ResultPending));
        session
            .accept_reservation(McpReservationResult::Acquired)
            .unwrap();
        assert!(matches!(
            session.next_step().unwrap(),
            McpSessionStep::MarkProviderEntry { .. }
        ));
        session.accept_provider_entry().unwrap();
        assert!(matches!(
            session.next_step().unwrap(),
            McpSessionStep::Invoke { .. }
        ));
        session
            .accept_handler(
                McpHandlerResult::parse(McpHandlerEffect::Applied, Some(br#"{"ok":true}"#), None)
                    .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            session.next_step().unwrap(),
            McpSessionStep::PersistReceipt { .. }
        ));
        session.accept_receipt(true).unwrap();
        assert!(matches!(
            session.terminal(),
            Some(McpTerminal::Completed { .. })
        ));
    }

    #[test]
    fn execution_identity_uses_stable_authority_not_observation_context() {
        let first = McpExecutionSession::begin(
            command(),
            [1; 32],
            [2; 32],
            [3; 32],
            Some("request-1"),
            McpSessionKey::new([9; 32]),
        )
        .unwrap();
        let refreshed = McpExecutionSession::begin(
            command(),
            [1; 32],
            [2; 32],
            [4; 32],
            Some("request-1"),
            McpSessionKey::new([9; 32]),
        )
        .unwrap();
        let another_authority = McpExecutionSession::begin(
            command(),
            [1; 32],
            [5; 32],
            [3; 32],
            Some("request-1"),
            McpSessionKey::new([9; 32]),
        )
        .unwrap();
        assert_eq!(first.execution_id(), refreshed.execution_id());
        assert_ne!(first.execution_id(), another_authority.execution_id());
    }

    #[test]
    fn ambiguous_effect_resumes_only_with_authenticated_record() {
        let mut session = session();
        session.next_step().unwrap();
        session
            .accept_reservation(McpReservationResult::Acquired)
            .unwrap();
        session.next_step().unwrap();
        session.accept_provider_entry().unwrap();
        session.next_step().unwrap();
        session
            .accept_handler(
                McpHandlerResult::parse(McpHandlerEffect::Possible, None, Some(McpCause::Timeout))
                    .unwrap(),
            )
            .unwrap();
        let Some(McpTerminal::Recoverable {
            reference,
            record_json,
            ..
        }) = session.terminal()
        else {
            panic!("expected recoverable session");
        };
        let reference = reference.as_str().to_owned();
        let record = record_json.clone();
        let mut resumed =
            McpExecutionSession::resume(McpSessionKey::new([9; 32]), &reference, &record).unwrap();
        assert!(matches!(
            resumed.next_step().unwrap(),
            McpSessionStep::Reconcile { .. }
        ));
        assert_eq!(
            McpExecutionSession::resume(McpSessionKey::new([8; 32]), &reference, &record).err(),
            Some(McpSessionError::InvalidExecutionReference)
        );
    }

    #[test]
    fn oversized_or_deep_handler_output_fails_before_receipt() {
        let large = vec![b'x'; MAX_HANDLER_OUTPUT_BYTES + 1];
        assert_eq!(
            McpHandlerResult::parse(McpHandlerEffect::Applied, Some(&large), None),
            Err(McpSessionError::InvalidHandlerOutput)
        );
        let deep = format!(
            "{}0{}",
            "[".repeat(MAX_HANDLER_OUTPUT_DEPTH + 1),
            "]".repeat(MAX_HANDLER_OUTPUT_DEPTH + 1)
        );
        assert_eq!(
            McpHandlerResult::parse(McpHandlerEffect::Applied, Some(deep.as_bytes()), None),
            Err(McpSessionError::InvalidHandlerOutput)
        );
    }
}
