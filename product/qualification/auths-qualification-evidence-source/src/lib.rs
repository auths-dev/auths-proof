//! One-private-key protected signers for qualification evidence source events.
//!
//! Each implemented binary in this package fixes exactly one source role at
//! compile time, links no domain adapter, and accepts its one seed only after
//! deriving a typed event from its authenticated source. Roles whose dedicated
//! reader is not implemented fail closed and never expose a generic signer.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod generated {
    pub(crate) mod qualification_routes;
}

#[cfg(target_os = "linux")]
use generated::qualification_routes::QualificationRoute;

#[cfg(target_os = "linux")]
use auths_config::{AgentConfig, AgentPlatform};
#[cfg(target_os = "linux")]
use auths_errors::ErrorEnvelope;
#[cfg(target_os = "linux")]
use auths_lifecycle::{OperationEffectV1, OperationIdV1, OperationStateV1};
#[cfg(target_os = "linux")]
use auths_production_client::{
    ClientRequestId, LocalOperationCompletion, MAX_LOCAL_REQUEST_BYTES, MAX_LOCAL_RESPONSE_BYTES,
    ProfileRoute, decode_execute_operation_request, decode_local_agent_http_request,
    decode_local_agent_http_response, decode_local_operation_outcome,
    decode_preparation_evidence_outcome, decode_preparation_evidence_request,
    decode_prepare_operation_request, decode_recover_operation_request, decode_session_request,
    decode_session_response, local_agent_http_message_length, local_idempotency_commitment,
    local_preparation_input_commitment, local_principal_commitment, local_request_commitment,
    qualification_client_cancellation_result,
};
#[cfg(target_os = "linux")]
use auths_profile_kit::QualificationCredentialBrokerObservationV1;
#[cfg(test)]
use auths_profile_kit::QualificationOperationRole;
#[cfg(target_os = "linux")]
use auths_profile_kit::QualificationProviderProxyObservationV1;
#[cfg(target_os = "linux")]
use auths_profile_kit::{
    QualificationAdmissionFaultV1, QualificationClientBridgeBindingV1,
    QualificationCrashActionContextV1, QualificationCrashActionRecordV1,
    QualificationDurableDecisionAckV1, QualificationEvidenceEventPayload,
    QualificationEvidenceLedgerPlanV1, QualificationEvidencePhasePlanV1,
    QualificationEvidenceSourceTrustRegistry, QualificationFailpoint,
    QualificationJournalDecisionContext, QualificationJournalDecisionContextRecord,
    QualificationJournalState, QualificationReceiptExecutionOutcome,
    QualificationSupervisorPhaseRequestV1, qualification_event_marker_sha256,
    qualification_pre_admission_attempt_count,
};
#[cfg(any(target_os = "linux", test))]
use auths_profile_kit::{
    QualificationClientProxyObservationV1, QualificationCompletion, QualificationEvidenceEventKind,
    QualificationOutcomeKind, QualificationSourceEventContextV1,
};
#[cfg(any(target_os = "linux", test))]
use auths_profile_kit::{
    QualificationClientProxyRecordV1, QualificationCredentialBrokerRecordV1,
    QualificationEvidenceEvent, QualificationProfileStateRecordV1,
    QualificationProviderObserverRecordV1, QualificationProviderProxyRecordV1,
    QualificationReceiptVerifierRecordV1, QualificationSourceProcessBindingV1,
};
use auths_profile_kit::{
    QualificationDecisionSnapshotState, QualificationDecisionSnapshotV1, QualificationEffect,
    QualificationEvidenceSource, QualificationReceiptDecisionClass,
};
#[cfg(target_os = "linux")]
use auths_profile_kit::{QualificationProfileStateFactV1, QualificationProfileStateObservationV1};
#[cfg(target_os = "linux")]
use auths_profile_runtime::{
    ProfileReceiptInspection, ProfileReceiptInspectionCommitmentsV1,
    ProfileReceiptInspectionFactsV1, ProfileRuntimeError,
};
use auths_receipts::{
    DecisionClass, PortableReceipt, decode_portable_receipt, decode_receipt_trust_anchors,
    verified_portable_receipt_claims_digest, verify_portable_receipt_with_anchors,
};
#[cfg(target_os = "linux")]
use auths_receipts::{ExecutionOutcome, portable_receipt_id};
#[cfg(target_os = "linux")]
use auths_stores::{
    JournalCompletionV1, JournalExecutionOutcomeV1, PersistentConnectionStore,
    QualificationJournalBoundaryV1,
};
use auths_stores::{JournalDecisionClassV1, JournalRecordV1};
#[cfg(target_os = "linux")]
use auths_stores::{
    QualificationJournalBoundaryKindV1,
    read_persisted_operation_record_from_qualification_snapshot,
    read_persisted_operation_records_from_qualification_snapshot,
    read_persisted_qualification_boundaries_from_snapshot,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use minicbor::{Decoder, Encoder};
#[cfg(any(target_os = "linux", test))]
use rustix::fs::openat;
#[cfg(any(target_os = "linux", test))]
use rustix::fs::{Mode, OFlags, open};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
#[cfg(any(target_os = "linux", test))]
use std::collections::{BTreeMap, BTreeSet};
use std::{env, process::ExitCode};
#[cfg(target_os = "linux")]
use std::{
    fs,
    future::Future,
    io::{IoSliceMut, Seek as _, SeekFrom},
    mem::MaybeUninit,
    net::Shutdown,
    os::fd::OwnedFd,
    os::unix::{
        fs::{FileTypeExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::{Component, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(any(target_os = "linux", test))]
use std::{
    fs::File,
    io::{Read, Write as _},
    os::unix::fs::MetadataExt as _,
    path::Path,
};
#[cfg(all(test, not(target_os = "linux")))]
use std::{
    net::Shutdown,
    os::unix::net::UnixStream,
    thread,
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
const TYPED_SOURCE_ROW_COMPLETE: &[u8] = b"AUTHS-QUALIFICATION-SOURCE-ROW-COMPLETE/1";
#[cfg(target_os = "linux")]
const TYPED_SOURCE_ROW_COMPLETE_ACK: &[u8] = b"AUTHS-QUALIFICATION-SOURCE-ROW-COMPLETE-ACK/1";

#[cfg(any(target_os = "linux", test))]
use auths_connections::QualificationCredentialLeaseRequest;
#[cfg(target_os = "linux")]
use auths_connections::{
    ConnectionAlias, ConnectionCredentialStore as _, ConnectionId, ConnectionProfile,
    ConnectionRecord, ConnectionState, CredentialScope, PersistentCredentialStore,
    ProviderConnectionAdapter as _, ProviderCredentialLease, ProviderKind,
    QualificationProviderCallKind, QualificationProviderCallRequest,
    QualificationProviderCallResponse, RegistryLimits, SecretBytes, SemanticId,
};

/// Kernel-bound identity of one protected source-session peer.
#[cfg(target_os = "linux")]
pub struct QualificationSourceSessionPeer {
    uid: u32,
    gid: u32,
    pid: i32,
    start_time_ticks: u64,
    executable_sha256: String,
}

#[cfg(target_os = "linux")]
impl QualificationSourceSessionPeer {
    /// Observes the connected peer through `SO_PEERCRED` and immutable process
    /// facts before any caller-authored frame is accepted.
    pub fn observe(stream: &UnixStream) -> Result<Self, String> {
        let peer = rustix::net::sockopt::socket_peercred(stream).map_err(string_error)?;
        let pid = peer.pid.as_raw_pid();
        Ok(Self {
            uid: peer.uid.as_raw(),
            gid: peer.gid.as_raw(),
            pid,
            start_time_ticks: process_start_time_ticks(pid)?,
            executable_sha256: hash_peer_executable(pid)?,
        })
    }

    /// Returns the peer's effective UID.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the peer's effective primary GID.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// Returns the peer PID pinned by the connection.
    #[must_use]
    pub const fn pid(&self) -> i32 {
        self.pid
    }

    /// Returns the peer process start-time identity.
    #[must_use]
    pub const fn start_time_ticks(&self) -> u64 {
        self.start_time_ticks
    }

    /// Returns the digest of the executable observed through `/proc`.
    #[must_use]
    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    /// Rejects PID reuse or an executable change during a framed transaction.
    pub fn verify_unchanged(&self) -> Result<(), String> {
        verify_peer_unchanged(self.pid, self.start_time_ticks, &self.executable_sha256)
    }
}

/// Returns the digest of the exact executable mapped into the current
/// protected source process.
#[cfg(target_os = "linux")]
pub fn qualification_source_process_executable_sha256() -> Result<String, String> {
    hash_peer_executable(i32::try_from(std::process::id()).map_err(string_error)?)
}

#[cfg(target_os = "linux")]
const MAX_TRUST_BYTES: u64 = 262_144;
#[cfg(target_os = "linux")]
const MAX_SEED_BYTES: u64 = 128;
#[cfg(any(target_os = "linux", test))]
const MAX_CONTEXT_BYTES: u64 = 65_536;
#[cfg(any(target_os = "linux", test))]
const MAX_TYPED_SOURCE_SESSION_EVENTS: u16 = 1_024;
#[cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
const MAX_CLIENT_PROXY_IN_FLIGHT: usize = 64;
#[cfg(target_os = "linux")]
const MAX_CREDENTIAL_BROKER_IN_FLIGHT: usize = 16;
#[cfg(target_os = "linux")]
const CREDENTIAL_BROKER_ACQUIRE: u8 = 0;
#[cfg(target_os = "linux")]
const CREDENTIAL_BROKER_CLOSE_RETRY: u8 = 1;
#[cfg(target_os = "linux")]
const CREDENTIAL_BROKER_PROXY_REDEEM: u8 = 2;
#[cfg(target_os = "linux")]
const CLIENT_RESULT_HEADER_BYTES: usize = 22;
#[cfg(target_os = "linux")]
const MAX_RECEIPT_TRUST_BYTES: u64 = 262_144;
const RECOVERY_HANDLE_SEMANTIC_ID: &[u8] = b"auths.recovery-handle/1";
#[cfg(target_os = "linux")]
const SOURCE_CHECKPOINT_ENROLLMENT_VERSION: u8 = 1;
#[cfg(target_os = "linux")]
const SOURCE_CHECKPOINT_AFTER_REREAD: u8 = 1;
#[cfg(target_os = "linux")]
const SOURCE_CHECKPOINT_AFTER_LEASE: u8 = 2;
#[cfg(target_os = "linux")]
const SOURCE_CHECKPOINT_AFTER_REQUEST_WRITE: u8 = 3;
#[cfg(target_os = "linux")]
const SOURCE_CHECKPOINT_PROVIDER_AUTHORIZATION: u8 = 16;
#[cfg(target_os = "linux")]
const SOURCE_CHECKPOINT_ABORT: u8 = 0;
#[cfg(target_os = "linux")]
const SOURCE_CHECKPOINT_CLEAN: u8 = 1;

/// One authenticated, capability-free request sent by the protected crash
/// controller to the separately supervised JournalReader process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationJournalDecisionRequestV1 {
    pub schema: String,
    pub journal_owner_uid: u32,
    pub principal: String,
    pub operation: String,
    pub receipt_trust_base64url: String,
    pub recovery_key_id: String,
    pub recovery_public_key_base64url: String,
    pub event_context_base64url: String,
}

/// One bounded response returned over the authenticated one-shot channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationJournalDecisionResponseV1 {
    pub schema: String,
    pub decision_snapshot_base64url: String,
    pub event_base64url: String,
}

/// One Supervisor-authenticated decision row supplied to a full journal
/// boundary drain.  The JournalReader independently binds both byte strings
/// to the co-persisted Decision boundary before it signs any event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationJournalBoundaryDecisionV1 {
    pub operation_id: String,
    pub supervisor_context_base64url: String,
    pub decision_snapshot_base64url: String,
    pub durable_ack_base64url: String,
}

/// Controller-authenticated process identity that owned one durable boundary.
/// The roster is private to the bounded JournalReader session; it prevents a
/// post-crash full-prefix retry from relabelling pre-crash events with the
/// restarted candidate identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationJournalBoundaryProcessV1 {
    pub ordinal: u32,
    pub agent_generation: u32,
    pub agent_process_id: u32,
    pub agent_boot_sha256: String,
}

/// Capability-free request for one complete, idempotent journal-boundary
/// drain.  No cursor is accepted: the reader authenticates the complete
/// bounded roster and resumes every deterministic intent in store order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationJournalBoundaryDrainRequestV1 {
    pub schema: String,
    pub journal_owner_uid: u32,
    pub principal: String,
    pub decisions: Vec<QualificationJournalBoundaryDecisionV1>,
    pub processes: Vec<QualificationJournalBoundaryProcessV1>,
}

/// One exact event commitment returned for controller-side release checks.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationJournalBoundaryEventV1 {
    pub ordinal: u32,
    pub operation_id: String,
    pub event_sha256: String,
}

/// Bounded acknowledgement returned only after the complete retained journal
/// prefix is durably represented by authenticated source events.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationJournalBoundaryDrainResponseV1 {
    pub schema: String,
    pub events: Vec<QualificationJournalBoundaryEventV1>,
}

/// One exact Supervisor-signed action context and its derived source event.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCrashActionResponseV1 {
    pub schema: String,
    pub action_context_base64url: String,
    pub event_base64url: String,
}

impl QualificationJournalDecisionRequestV1 {
    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json_canonicalizer::to_vec(self).map_err(string_error)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 524_288 {
            return Err("journal-reader request exceeds its hard bound".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(string_error)?;
        value.validate()?;
        if serde_json_canonicalizer::to_vec(&value).map_err(string_error)? != bytes {
            return Err("journal-reader request is not exact canonical JSON".into());
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != "auths.qualification-journal-decision-request/1"
            || self.journal_owner_uid == u32::MAX
            || self.principal.is_empty()
            || self.principal.len() > 1_024
            || self.operation.is_empty()
            || self.operation.len() > 128
            || self.receipt_trust_base64url.is_empty()
            || self.receipt_trust_base64url.len() > 524_288
            || self.recovery_key_id.is_empty()
            || self.recovery_key_id.len() > 128
            || self.recovery_public_key_base64url.len() != 43
            || self.event_context_base64url.is_empty()
            || self.event_context_base64url.len() > 131_072
        {
            return Err("journal-reader request is malformed".into());
        }
        Ok(())
    }
}

impl QualificationJournalBoundaryDrainRequestV1 {
    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json_canonicalizer::to_vec(self).map_err(string_error)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 2_097_152 {
            return Err("journal boundary drain request exceeds its hard bound".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(string_error)?;
        value.validate()?;
        if serde_json_canonicalizer::to_vec(&value).map_err(string_error)? != bytes {
            return Err("journal boundary drain request is not exact canonical JSON".into());
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        let bounded = |value: &str| {
            Base64UrlUnpadded::decode_vec(value)
                .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= 131_072)
        };
        if self.schema != "auths.qualification-journal-boundary-drain-request/1"
            || self.journal_owner_uid == u32::MAX
            || self.principal.is_empty()
            || self.principal.len() > 1_024
            || self.decisions.len() > 8
            || self.processes.len() > 16_384
            || self.processes.iter().enumerate().any(|(index, process)| {
                process.ordinal == 0
                    || process.agent_generation == 0
                    || process.agent_process_id == 0
                    || process.agent_boot_sha256.len() != 64
                    || !process
                        .agent_boot_sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                    || index.checked_sub(1).is_some_and(|prior| {
                        self.processes[prior]
                            .ordinal
                            .checked_add(1)
                            .is_none_or(|expected| expected != process.ordinal)
                    })
            })
            || self.decisions.iter().enumerate().any(|(index, decision)| {
                decision.operation_id.is_empty()
                    || decision.operation_id.len() > 128
                    || self.decisions[..index]
                        .iter()
                        .any(|prior| prior.operation_id == decision.operation_id)
                    || !bounded(&decision.supervisor_context_base64url)
                    || !bounded(&decision.decision_snapshot_base64url)
                    || !bounded(&decision.durable_ack_base64url)
            })
        {
            return Err("journal boundary drain request is malformed".into());
        }
        Ok(())
    }
}

impl QualificationJournalBoundaryDrainResponseV1 {
    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json_canonicalizer::to_vec(self).map_err(string_error)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 2_097_152 {
            return Err("journal boundary drain response exceeds its hard bound".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(string_error)?;
        value.validate()?;
        if serde_json_canonicalizer::to_vec(&value).map_err(string_error)? != bytes {
            return Err("journal boundary drain response is not exact canonical JSON".into());
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != "auths.qualification-journal-boundary-drain-response/1"
            || self.events.len() > 16_384
            || self.events.iter().enumerate().any(|(index, event)| {
                event.ordinal == 0
                    || index.checked_sub(1).is_some_and(|prior| {
                        self.events[prior]
                            .ordinal
                            .checked_add(1)
                            .is_none_or(|expected| expected != event.ordinal)
                    })
                    || event.operation_id.is_empty()
                    || event.operation_id.len() > 128
                    || event.event_sha256.len() != 64
                    || !event
                        .event_sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
        {
            return Err("journal boundary drain response is malformed".into());
        }
        Ok(())
    }
}

impl QualificationCrashActionResponseV1 {
    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json_canonicalizer::to_vec(self).map_err(string_error)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 196_608 {
            return Err("crash action response exceeds its hard bound".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(string_error)?;
        value.validate()?;
        if serde_json_canonicalizer::to_vec(&value).map_err(string_error)? != bytes {
            return Err("crash action response is not exact canonical JSON".into());
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        let bounded = |value: &str| {
            Base64UrlUnpadded::decode_vec(value)
                .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= 65_536)
        };
        if self.schema != "auths.qualification-crash-action-response/1"
            || !bounded(&self.action_context_base64url)
            || !bounded(&self.event_base64url)
        {
            return Err("crash action response is malformed".into());
        }
        Ok(())
    }
}

impl QualificationJournalDecisionResponseV1 {
    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json_canonicalizer::to_vec(self).map_err(string_error)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 262_144 {
            return Err("journal-reader response exceeds its hard bound".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(string_error)?;
        value.validate()?;
        if serde_json_canonicalizer::to_vec(&value).map_err(string_error)? != bytes {
            return Err("journal-reader response is not exact canonical JSON".into());
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != "auths.qualification-journal-decision-response/1"
            || self.decision_snapshot_base64url.is_empty()
            || self.decision_snapshot_base64url.len() > 131_072
            || self.event_base64url.is_empty()
            || self.event_base64url.len() > 131_072
        {
            return Err("journal-reader response is malformed".into());
        }
        Ok(())
    }
}

/// Exact public receipt artifacts returned by the protected native verifier
/// after their source events are durably appended.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationReceiptVerifierResponseV1 {
    pub schema: String,
    pub operations: Vec<QualificationReceiptVerifierOperationV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationReceiptVerifierOperationV1 {
    pub operation_id: String,
    pub inspection_base64url: String,
    pub receipts: Vec<QualificationReceiptVerifierArtifactV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationReceiptVerifierArtifactV1 {
    pub sequence: u8,
    pub receipt_id: String,
    pub bytes_base64url: String,
}

/// Capability-free provider observations returned to the protected phase
/// controller after their typed source events have been durably appended.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationProviderObserverResponseV1 {
    pub schema: String,
    pub operations: Vec<QualificationProviderObserverOperationV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationProviderObserverOperationV1 {
    pub operation_id: String,
    pub effect: QualificationEffect,
    pub provider_truth_sha256: String,
    /// Base64url encoding of the canonical redacted domain facts whose digest
    /// is signed by the ProviderObserver event. Raw provider state and
    /// responses are never included.
    pub domain_facts_base64url: String,
}

impl QualificationProviderObserverResponseV1 {
    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json_canonicalizer::to_vec(self).map_err(string_error)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 16 * 1_024 * 1_024 {
            return Err("provider-observer response exceeds its hard bound".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(string_error)?;
        value.validate()?;
        if serde_json_canonicalizer::to_vec(&value).map_err(string_error)? != bytes {
            return Err("provider-observer response is not exact canonical JSON".into());
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != "auths.qualification-provider-observer-response/1"
            || self.operations.len() > 8
            || self
                .operations
                .windows(2)
                .any(|pair| pair[0].operation_id.as_bytes() >= pair[1].operation_id.as_bytes())
            || self.operations.iter().any(|operation| {
                auths_lifecycle::OperationIdV1::parse(&operation.operation_id).is_err()
                    || !matches!(
                        operation.effect,
                        QualificationEffect::Applied | QualificationEffect::NotApplied
                    )
                    || !lower_hex_sha256(&operation.provider_truth_sha256)
                    || operation.domain_facts_base64url.is_empty()
                    || operation.domain_facts_base64url.len() > 5_592_406
                    || operation.domain_facts_base64url.contains('=')
                    || Base64UrlUnpadded::decode_vec(&operation.domain_facts_base64url)
                        .ok()
                        .filter(|facts| !facts.is_empty() && facts.len() <= 4 * 1_024 * 1_024)
                        .is_none_or(|facts| {
                            hex::encode(Sha256::digest(facts)) != operation.provider_truth_sha256
                        })
            })
        {
            return Err("provider-observer response is malformed".into());
        }
        Ok(())
    }
}

fn lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

impl QualificationReceiptVerifierResponseV1 {
    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json_canonicalizer::to_vec(self).map_err(string_error)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 67_108_864 {
            return Err("receipt-verifier response exceeds its hard bound".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(string_error)?;
        value.validate()?;
        if serde_json_canonicalizer::to_vec(&value).map_err(string_error)? != bytes {
            return Err("receipt-verifier response is not exact canonical JSON".into());
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != "auths.qualification-receipt-verifier-response/1"
            || self.operations.len() > 8
            || self
                .operations
                .windows(2)
                .any(|pair| pair[0].operation_id.as_bytes() >= pair[1].operation_id.as_bytes())
            || self.operations.iter().any(|operation| {
                auths_lifecycle::OperationIdV1::parse(&operation.operation_id).is_err()
                    || !Base64UrlUnpadded::decode_vec(&operation.inspection_base64url)
                        .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= 4_194_304)
                    || operation.receipts.is_empty()
                    || operation.receipts.len() > 2
                    || operation
                        .receipts
                        .iter()
                        .enumerate()
                        .any(|(index, receipt)| {
                            usize::from(receipt.sequence) != index
                                || auths_receipts::validate_portable_receipt_id(&receipt.receipt_id)
                                    .is_err()
                                || !Base64UrlUnpadded::decode_vec(&receipt.bytes_base64url)
                                    .is_ok_and(|bytes| {
                                        !bytes.is_empty() && bytes.len() <= 8_388_608
                                    })
                        })
            })
        {
            return Err("receipt-verifier response is malformed".into());
        }
        Ok(())
    }
}

/// Derives the complete capability-free public decision snapshot from one
/// exact private revision-one journal record.
///
/// The full recovery handle and raw receipt are verified here but never
/// returned, serialized, or retained in public qualification evidence.
pub fn derive_qualification_decision_snapshot(
    record: &JournalRecordV1,
    principal: &str,
    receipt_trust_bytes: &[u8],
    recovery_key_id: &str,
    recovery_public_key_base64url: &str,
    now_unix_seconds: u64,
) -> Result<QualificationDecisionSnapshotV1, String> {
    record.validate_exact_decision_snapshot().map_err(|_| {
        "journal record is not the exact first durable decision snapshot".to_owned()
    })?;
    derive_historical_decision_snapshot(
        record,
        principal,
        receipt_trust_bytes,
        recovery_key_id,
        recovery_public_key_base64url,
        now_unix_seconds,
    )
}

fn derive_historical_decision_snapshot(
    record: &JournalRecordV1,
    principal: &str,
    receipt_trust_bytes: &[u8],
    recovery_key_id: &str,
    recovery_public_key_base64url: &str,
    now_unix_seconds: u64,
) -> Result<QualificationDecisionSnapshotV1, String> {
    let receipt_trust = decode_receipt_trust_anchors(receipt_trust_bytes).map_err(string_error)?;
    verify_recovery_handle(
        record.recovery_handle(),
        principal,
        record.operation_id(),
        record.binding().profile(),
        recovery_key_id,
        recovery_public_key_base64url,
        now_unix_seconds,
    )?;
    let [decision, ..] = record.receipts() else {
        return Err("durable decision has no retained decision receipt".into());
    };
    if !matches!(
        decode_portable_receipt(decision.bytes()).map_err(string_error)?,
        PortableReceipt::Decision { .. }
    ) {
        return Err("durable decision receipt is not a decision-only portable receipt".into());
    }
    let profile = auths_model::ProfileRef::new(
        auths_model::ProfileId::parse(record.binding().profile().id()).map_err(string_error)?,
        record.binding().profile().version(),
    )
    .map_err(string_error)?;
    let verified = verify_portable_receipt_with_anchors(
        decision.bytes(),
        &receipt_trust,
        Some(&profile),
        None,
    )
    .map_err(string_error)?;
    let expected_decision = match record.decision_class() {
        JournalDecisionClassV1::Authorized => DecisionClass::Authorized,
        JournalDecisionClassV1::Denied => DecisionClass::Denied,
        JournalDecisionClassV1::Indeterminate => DecisionClass::Indeterminate,
    };
    if verified.portable_id() != decision.receipt_id()
        || verified.decision_action() != record.receipt_action_commitment()
        || verified.decision_context() != record.receipt_context_commitment()
        || verified.decision() != expected_decision
    {
        return Err("durable decision receipt differs from the decoded journal record".into());
    }
    let binding = record.binding();
    Ok(QualificationDecisionSnapshotV1 {
        schema: "auths.qualification-decision-snapshot/1".to_owned(),
        operation_id: record.operation_id().as_str().to_owned(),
        profile: format!("{}/{}", binding.profile().id(), binding.profile().version()),
        connection_generation: binding
            .connection()
            .ok_or_else(|| "qualified durable decision has no connection binding".to_owned())?
            .generation()
            .to_string(),
        journal_revision: 1,
        state: match record.decision_class() {
            JournalDecisionClassV1::Authorized => QualificationDecisionSnapshotState::Ready,
            JournalDecisionClassV1::Denied => QualificationDecisionSnapshotState::Denied,
            JournalDecisionClassV1::Indeterminate => {
                QualificationDecisionSnapshotState::Unavailable
            }
        },
        decision_class: match record.decision_class() {
            JournalDecisionClassV1::Authorized => QualificationReceiptDecisionClass::Authorized,
            JournalDecisionClassV1::Denied => QualificationReceiptDecisionClass::Denied,
            JournalDecisionClassV1::Indeterminate => {
                QualificationReceiptDecisionClass::Indeterminate
            }
        },
        canonical_input_sha256: hex::encode(binding.canonical_input_commitment()),
        idempotency_sha256: binding.idempotency_commitment().map(hex::encode),
        canonical_action_sha256: hex::encode(binding.canonical_action_commitment()),
        receipt_action_sha256: hex::encode(record.receipt_action_commitment()),
        receipt_context_sha256: hex::encode(record.receipt_context_commitment()),
        authority_sha256: hex::encode(binding.authority_commitment()),
        configuration_sha256: hex::encode(binding.configuration_commitment()),
        runtime_contract_sha256: hex::encode(binding.profile().runtime_contract_digest()),
        preparation_sha256: hex::encode(binding.preparation_commitment()),
        decision_receipt_id: decision.receipt_id().to_owned(),
        decision_receipt_bytes_sha256: hex::encode(Sha256::digest(decision.bytes())),
        decoded_claims_sha256: hex::encode(
            verified_portable_receipt_claims_digest(
                &verified,
                Some(record.operation_id().as_str()),
            )
            .map_err(string_error)?,
        ),
        recovery_key_id: recovery_key_id.to_owned(),
        recovery_public_key_base64url: recovery_public_key_base64url.to_owned(),
        receipt_trust_anchor_sha256: hex::encode(Sha256::digest(receipt_trust_bytes)),
    })
}

#[cfg(target_os = "linux")]
struct VerifiedReceiptArtifact {
    receipt_id: String,
    bytes: Vec<u8>,
    decoded_claims_sha256: String,
}

#[cfg(target_os = "linux")]
struct VerifiedReceiptArtifacts {
    inspection_bytes: Vec<u8>,
    receipts: Vec<VerifiedReceiptArtifact>,
}

/// Independently verifies the exact durable receipt set and its profile-owned
/// claims using only a pinned journal record and public deployment anchors.
#[cfg(target_os = "linux")]
fn verify_receipt_artifacts(
    record: &JournalRecordV1,
    receipt_trust_bytes: &[u8],
) -> Result<VerifiedReceiptArtifacts, String> {
    let receipts = record.receipts();
    if receipts.is_empty() || receipts.len() > 2 {
        return Err("durable operation has no closed portable-receipt set".into());
    }
    let anchors = decode_receipt_trust_anchors(receipt_trust_bytes).map_err(string_error)?;
    let operation_id = record.operation_id().as_str();
    let profile = record.binding().profile();
    let profile_ref = auths_model::ProfileRef::new(
        auths_model::ProfileId::parse(profile.id()).map_err(string_error)?,
        profile.version(),
    )
    .map_err(string_error)?;
    let verified = receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| {
            let value = verify_portable_receipt_with_anchors(
                receipt.bytes(),
                &anchors,
                Some(&profile_ref),
                (index == 1).then_some(operation_id),
            )
            .map_err(string_error)?;
            if value.portable_id() != receipt.receipt_id() {
                return Err("portable receipt identity differs from durable journal truth".into());
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let decision = &verified[0];
    let expected_decision = match record.decision_class() {
        JournalDecisionClassV1::Authorized => DecisionClass::Authorized,
        JournalDecisionClassV1::Denied => DecisionClass::Denied,
        JournalDecisionClassV1::Indeterminate => DecisionClass::Indeterminate,
    };
    if decision.execution_outcome().is_some()
        || decision.decision_action() != record.receipt_action_commitment()
        || decision.decision_context() != record.receipt_context_commitment()
        || decision.decision() != expected_decision
    {
        return Err("portable decision receipt differs from durable journal truth".into());
    }
    let execution = verified.get(1);
    let expected_command = record.sealed_command().map(|command| {
        let digest: [u8; 32] = Sha256::digest(command).into();
        digest
    });
    let expected_outcome = record.execution_outcome().map(|outcome| match outcome {
        JournalExecutionOutcomeV1::Succeeded => ExecutionOutcome::Succeeded,
        JournalExecutionOutcomeV1::Failed => ExecutionOutcome::Failed,
        JournalExecutionOutcomeV1::Indeterminate => ExecutionOutcome::Indeterminate,
    });
    if execution.is_some() != record.execution_outcome().is_some()
        || execution.is_some_and(|value| {
            value.decision_profile_claims() != decision.decision_profile_claims()
                || value.execution_command().copied() != expected_command
                || value.execution_result() != record.execution_result_commitment()
                || value.execution_outcome() != expected_outcome
        })
    {
        return Err("portable execution receipt differs from durable journal truth".into());
    }
    let inspection = ProfileReceiptInspectionFactsV1::from_record(record);
    inspection
        .validate()
        .map_err(|error| format!("receipt inspection facts are invalid: {error:?}"))?;
    inspect_profile_receipt(
        &format!("{}/{}", profile.id(), profile.version()),
        ProfileReceiptInspection {
            facts: &inspection,
            decision_claims: decision.decision_profile_claims(),
            execution_claims: execution.and_then(|value| value.execution_profile_claims()),
        },
    )?;
    let public_inspection =
        ProfileReceiptInspectionCommitmentsV1::from_inspection(ProfileReceiptInspection {
            facts: &inspection,
            decision_claims: decision.decision_profile_claims(),
            execution_claims: execution.and_then(|value| value.execution_profile_claims()),
        })
        .map_err(|error| format!("public receipt inspection commitments are invalid: {error:?}"))?;
    let inspection_bytes =
        serde_json_canonicalizer::to_vec(&public_inspection).map_err(string_error)?;
    let receipts = receipts
        .iter()
        .zip(verified)
        .map(|(receipt, verified)| {
            Ok(VerifiedReceiptArtifact {
                receipt_id: receipt.receipt_id().to_owned(),
                bytes: receipt.bytes().to_vec(),
                decoded_claims_sha256: hex::encode(
                    verified_portable_receipt_claims_digest(&verified, Some(operation_id))
                        .map_err(string_error)?,
                ),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(VerifiedReceiptArtifacts {
        inspection_bytes,
        receipts,
    })
}

#[cfg(target_os = "linux")]
fn inspect_profile_receipt(
    profile: &str,
    inspection: ProfileReceiptInspection<'_>,
) -> Result<(), String> {
    let result =
        QualificationRoute::for_profile(profile)?.inspect_receipt_claims(profile, inspection);
    result.map_err(|error| format!("profile receipt inspection failed: {error:?}"))
}

/// Runs one exact source-role signer.
pub fn main_for_source(source: QualificationEvidenceSource) -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let result = if source == QualificationEvidenceSource::ClientProxy
        && arguments.first().map(String::as_str) == Some("serve-ordinary-row-session")
    {
        run_client_proxy_ordinary_row(&arguments)
    } else if source == QualificationEvidenceSource::ClientProxy
        && arguments.first().map(String::as_str) == Some("serve-reader-session")
    {
        run_client_proxy_reader(&arguments)
    } else {
        run_typed_source(source, &arguments)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification {source:?} source failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the role-fixed ReceiptVerifier signer or its distinct no-seed reader
/// mode. Protected source trust requires different OS identities even though
/// both modes use the same reviewed executable bytes.
pub fn main_for_receipt_verifier() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let result = if arguments.first().map(String::as_str) == Some("serve-ordinary-row-session") {
        run_receipt_verifier_ordinary_row(&arguments)
    } else if arguments.first().map(String::as_str) == Some("serve-reader-session") {
        run_receipt_verifier_reader(&arguments)
    } else {
        run_typed_source(QualificationEvidenceSource::ReceiptVerifier, &arguments)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification ReceiptVerifier source failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the role-fixed CredentialBroker signer or its distinct no-seed
/// credential-reader mode. The reader owns the protected credential store;
/// the qualification agent receives only one deadline-bound lease.
pub fn main_for_credential_broker() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let result = if arguments.first().map(String::as_str) == Some("initialize-stores") {
        initialize_credential_broker_stores(&arguments)
    } else if arguments.first().map(String::as_str) == Some("serve-ordinary-row-session") {
        run_credential_broker_ordinary_row(&arguments)
    } else if arguments.first().map(String::as_str) == Some("serve-reader-session") {
        run_credential_broker_reader(&arguments)
    } else {
        run_typed_source(QualificationEvidenceSource::CredentialBroker, &arguments)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification CredentialBroker source failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the role-fixed ProviderProxy signer or its distinct no-seed transport
/// owner. The reader accepts a complete canonical call before it emits the
/// durable request-written boundary, then owns the one provider execution and
/// retained response across an agent restart.
pub fn main_for_provider_proxy() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let result = if arguments.first().map(String::as_str) == Some("serve-ordinary-row-session") {
        run_provider_proxy_ordinary_row(&arguments)
    } else if arguments.first().map(String::as_str) == Some("serve-reader-session") {
        run_provider_proxy_reader(&arguments)
    } else {
        run_typed_source(QualificationEvidenceSource::ProviderProxy, &arguments)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification ProviderProxy source failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the role-fixed ProviderObserver signer or the distinct no-seed,
/// runtime-read-credential owner. The reader starts provider I/O only after
/// the controller has reaped the candidate and transferred a pinned journal
/// snapshot.
pub fn main_for_provider_observer() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let result = if arguments.first().map(String::as_str) == Some("serve-ordinary-row-session") {
        run_provider_observer_ordinary_row(&arguments)
    } else if arguments.first().map(String::as_str) == Some("serve-reader-session") {
        run_provider_observer_reader(&arguments)
    } else {
        run_typed_source(QualificationEvidenceSource::ProviderObserver, &arguments)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification ProviderObserver source failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialBrokerInitialization<'a> {
    schema: &'a str,
    descriptor_base64url: &'a str,
    credential_base64url: &'a str,
}

#[cfg(target_os = "linux")]
fn initialize_credential_broker_stores(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values_for(
        arguments,
        "initialize-stores",
        &[
            "--agent-config",
            "--connection-store",
            "--credential-store",
            "--ledger-plan",
            "--source-trust",
        ],
        typed_source_usage,
    )?;
    reject_secret_environment()?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&read_bounded(
        Path::new(value_for(&values, "--ledger-plan", typed_source_usage)?),
        MAX_TRUST_BYTES,
        true,
    )?)
    .map_err(string_error)?;
    let trust = QualificationEvidenceSourceTrustRegistry::from_json(&read_bounded(
        Path::new(value_for(&values, "--source-trust", typed_source_usage)?),
        MAX_TRUST_BYTES,
        false,
    )?)
    .map_err(string_error)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let reader_uid = rustix::process::geteuid().as_raw();
    let reader_artifact = qualification_source_process_executable_sha256()?;
    if trust
        .fixed_source_for_reader_process(
            reader_uid,
            &reader_artifact,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?
        != QualificationEvidenceSource::CredentialBroker
    {
        return Err("CredentialBroker initializer differs from protected source trust".into());
    }
    let connection_path = Path::new(value_for(
        &values,
        "--connection-store",
        typed_source_usage,
    )?);
    let credential_path = Path::new(value_for(
        &values,
        "--credential-store",
        typed_source_usage,
    )?);
    if connection_path == credential_path {
        return Err("CredentialBroker stores must be distinct".into());
    }
    validate_new_broker_store_path(connection_path, reader_uid)?;
    validate_new_broker_store_path(credential_path, reader_uid)?;
    let config_bytes = read_bounded(
        Path::new(value_for(&values, "--agent-config", typed_source_usage)?),
        4_194_304,
        false,
    )?;
    let config = AgentConfig::from_toml(
        std::str::from_utf8(&config_bytes).map_err(string_error)?,
        AgentPlatform::Linux,
    )
    .map_err(string_error)?;
    let workload = config
        .workloads()
        .iter()
        .filter(|workload| {
            hex::encode(Sha256::digest(workload.id().as_bytes()))
                == plan.phases[0].credential_requirement.workload_id_sha256
        })
        .collect::<Vec<_>>();
    if workload.len() != 1
        || plan.phases.iter().any(|phase| {
            phase.credential_requirement.workload_id_sha256
                != plan.phases[0].credential_requirement.workload_id_sha256
                || phase.credential_requirement.provider_kind
                    != plan.phases[0].credential_requirement.provider_kind
                || phase.credential_requirement.contract
                    != plan.phases[0].credential_requirement.contract
                || phase.credential_requirement.descriptor_schema
                    != plan.phases[0].credential_requirement.descriptor_schema
        })
    {
        return Err("CredentialBroker plan does not select one workload connection".into());
    }
    let workload = workload[0];
    let requirement = &plan.phases[0].credential_requirement;
    let aliases = workload
        .connections()
        .iter()
        .filter(|connection| connection.provider() == requirement.provider_kind)
        .collect::<Vec<_>>();
    if aliases.len() != 1 || !aliases[0].is_default() {
        return Err("CredentialBroker workload has no unique default connection".into());
    }
    let mut input = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(196_609)
        .read_to_end(&mut input)
        .map_err(string_error)?;
    if input.is_empty() || input.len() > 196_608 {
        return Err("CredentialBroker initialization exceeds its bound".into());
    }
    let initialization: CredentialBrokerInitialization<'_> =
        serde_json::from_slice(&input).map_err(string_error)?;
    if initialization.schema != "auths.qualification-credential-broker-initialization/1" {
        return Err("CredentialBroker initialization schema is invalid".into());
    }
    let descriptor = Zeroizing::new(
        Base64UrlUnpadded::decode_vec(initialization.descriptor_base64url).map_err(string_error)?,
    );
    let credential = Zeroizing::new(
        Base64UrlUnpadded::decode_vec(initialization.credential_base64url).map_err(string_error)?,
    );
    let (account_commitment, secret) = validate_credential_onboarding(
        &requirement.provider_kind,
        &descriptor,
        credential.to_vec(),
    )?;
    let limits = RegistryLimits {
        maximum_records: std::num::NonZeroUsize::new(10_000)
            .ok_or_else(|| "CredentialBroker connection bound is invalid".to_owned())?,
        maximum_encoded_bytes: std::num::NonZeroUsize::new(268_435_456)
            .ok_or_else(|| "CredentialBroker connection byte bound is invalid".to_owned())?,
    };
    let connections =
        PersistentConnectionStore::open(connection_path, limits).map_err(string_error)?;
    let credentials = PersistentCredentialStore::open(credential_path).map_err(string_error)?;
    let connection_id = ConnectionId::generate().map_err(string_error)?;
    let generation = std::num::NonZeroU64::new(1)
        .ok_or_else(|| "CredentialBroker generation is invalid".to_owned())?;
    let credential_commitment =
        poll_immediate(credentials.install(&connection_id, generation, secret))?
            .map_err(string_error)?;
    let mut profiles = plan
        .phases
        .iter()
        .map(|phase| {
            let (id, version) = phase
                .profile
                .rsplit_once('/')
                .ok_or_else(|| "CredentialBroker profile is malformed".to_owned())?;
            ConnectionProfile::new(
                SemanticId::parse(id).map_err(string_error)?,
                version.parse::<u16>().map_err(string_error)?,
            )
            .map_err(string_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    profiles.sort();
    profiles.dedup();
    let record = ConnectionRecord::new(
        ProviderKind::parse(&requirement.provider_kind).map_err(string_error)?,
        ConnectionAlias::parse(aliases[0].alias()).map_err(string_error)?,
        connection_id,
        SemanticId::parse(&requirement.contract).map_err(string_error)?,
        SemanticId::parse(&requirement.descriptor_schema).map_err(string_error)?,
        descriptor.to_vec(),
        account_commitment,
        *credential_commitment.as_bytes(),
        generation,
        ConnectionState::Active,
        vec![workload.id().to_owned()],
        profiles,
        now,
        now,
        None,
    )
    .map_err(string_error)?;
    connections
        .insert_with_defaults(record, &[workload.id().to_owned()])
        .map_err(string_error)?;
    for path in [connection_path, credential_path] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(string_error)?;
        validate_broker_store_path(path, reader_uid)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_new_broker_store_path(path: &Path, owner_uid: u32) -> Result<(), String> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.exists()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err("CredentialBroker new store path is invalid".into());
    }
    let parent = open_directory_componentwise(
        path.parent()
            .ok_or_else(|| "CredentialBroker store path has no parent".to_owned())?,
    )?;
    let metadata = parent.metadata().map_err(string_error)?;
    if metadata.uid() != owner_uid || metadata.mode() & 0o777 != 0o700 {
        return Err("CredentialBroker store parent ownership or mode is invalid".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_credential_onboarding(
    provider: &str,
    descriptor: &[u8],
    credential: Vec<u8>,
) -> Result<([u8; 32], SecretBytes), String> {
    let account = match provider {
        "opentofu" => auths_opentofu::connection::adapter()
            .validate_descriptor(descriptor)
            .map_err(string_error)?
            .account_commitment()
            .to_owned(),
        "postgresql" => auths_postgresql::connection::adapter()
            .validate_descriptor(descriptor)
            .map_err(string_error)?
            .account_commitment()
            .to_owned(),
        "stripe" => auths_stripe::connection::adapter()
            .validate_descriptor(descriptor)
            .map_err(string_error)?
            .account_commitment()
            .to_owned(),
        _ => return Err("CredentialBroker provider is not statically registered".into()),
    };
    let secret = match provider {
        "opentofu" => auths_opentofu::connection::validate_onboarding(descriptor, credential),
        "postgresql" => auths_postgresql::connection::validate_onboarding(descriptor, credential),
        "stripe" => auths_stripe::connection::validate_onboarding(descriptor, credential),
        _ => unreachable!("provider was checked above"),
    }
    .map_err(string_error)?;
    Ok((account, secret))
}

#[cfg(not(target_os = "linux"))]
fn initialize_credential_broker_stores(_arguments: &[String]) -> Result<(), String> {
    Err("CredentialBroker store initialization requires Linux process identity".into())
}

/// Runs the role-fixed ProfileStateReader signer or its distinct no-seed
/// reader mode. The reader receives only controller-pinned read-only snapshots
/// and projects domain-owned state through the existing static adapters.
pub fn main_for_profile_state_reader() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let result = if arguments.first().map(String::as_str) == Some("serve-ordinary-row-session") {
        run_profile_state_ordinary_row(&arguments)
    } else if arguments.first().map(String::as_str) == Some("serve-reader-session") {
        run_profile_state_reader(&arguments)
    } else {
        run_typed_source(QualificationEvidenceSource::ProfileStateReader, &arguments)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification ProfileStateReader source failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn ordinary_row_plan(
    values: &BTreeMap<&str, &str>,
) -> Result<QualificationEvidenceLedgerPlanV1, String> {
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&read_bounded(
        Path::new(value_for(values, "--ledger-plan", typed_source_usage)?),
        MAX_TRUST_BYTES,
        true,
    )?)
    .map_err(string_error)?;
    if plan.phases.is_empty() {
        return Err("row reader requires at least one immutable phase".into());
    }
    Ok(plan)
}

#[cfg(target_os = "linux")]
fn ordinary_row_phases(
    plan: &QualificationEvidenceLedgerPlanV1,
) -> impl Iterator<Item = &auths_profile_kit::QualificationEvidencePhasePlanV1> {
    plan.phases.iter()
}

#[cfg(target_os = "linux")]
fn ordinary_row_phase_root(
    runtime_root: &Path,
    phase: &auths_profile_kit::QualificationEvidencePhasePlanV1,
) -> Result<PathBuf, String> {
    if !runtime_root.is_absolute()
        || runtime_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("ordinary row runtime root is not normalized and absolute".into());
    }
    Ok(runtime_root
        .join(&phase.scenario_id)
        .join(format!("phase-{}", phase.phase_index)))
}

#[cfg(target_os = "linux")]
fn row_value(values: &BTreeMap<&str, &str>, flag: &str) -> Result<String, String> {
    value_for(values, flag, typed_source_usage).map(str::to_owned)
}

#[cfg(target_os = "linux")]
fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "ordinary row path is not UTF-8".to_owned())
}

#[cfg(target_os = "linux")]
fn run_client_proxy_ordinary_row(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values_for(
        arguments,
        "serve-ordinary-row-session",
        &[
            "--runtime-root",
            "--signer-socket",
            "--sequencer-socket",
            "--ledger-plan",
            "--source-trust",
        ],
        typed_source_usage,
    )?;
    let plan = ordinary_row_plan(&values)?;
    let runtime_root = Path::new(value_for(&values, "--runtime-root", typed_source_usage)?);
    for phase in ordinary_row_phases(&plan) {
        let root = ordinary_row_phase_root(runtime_root, phase)?;
        run_client_proxy_reader(&[
            "serve-reader-session".into(),
            "--client-socket".into(),
            path_text(&root.join("client-proxy/client.sock"))?,
            "--result-socket".into(),
            path_text(&root.join("client-proxy/result.sock"))?,
            "--control-socket".into(),
            path_text(&root.join("client-proxy/control.sock"))?,
            "--agent-socket".into(),
            path_text(&root.join("agent/agent.sock"))?,
            "--signer-socket".into(),
            row_value(&values, "--signer-socket")?,
            "--sequencer-socket".into(),
            row_value(&values, "--sequencer-socket")?,
            "--ledger-plan".into(),
            row_value(&values, "--ledger-plan")?,
            "--source-trust".into(),
            row_value(&values, "--source-trust")?,
            "--scenario".into(),
            phase.scenario_id.clone(),
            "--phase-index".into(),
            phase.phase_index.to_string(),
            "--supervisor-generation".into(),
            "1".into(),
        ])?;
    }
    complete_typed_source_row(QualificationEvidenceSource::ClientProxy, &values, &plan)
}

#[cfg(target_os = "linux")]
fn run_credential_broker_ordinary_row(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values_for(
        arguments,
        "serve-ordinary-row-session",
        &[
            "--runtime-root",
            "--signer-socket",
            "--sequencer-socket",
            "--ledger-plan",
            "--source-trust",
            "--connection-store",
            "--credential-store",
        ],
        typed_source_usage,
    )?;
    let plan = ordinary_row_plan(&values)?;
    let runtime_root = Path::new(value_for(&values, "--runtime-root", typed_source_usage)?);
    for phase in ordinary_row_phases(&plan) {
        let root = ordinary_row_phase_root(runtime_root, phase)?;
        run_credential_broker_reader(&[
            "serve-reader-session".into(),
            "--socket".into(),
            path_text(&root.join("credential-broker/agent.sock"))?,
            "--checkpoint-socket".into(),
            path_text(&root.join("credential-broker/checkpoint.sock"))?,
            "--control-socket".into(),
            path_text(&root.join("credential-broker/control.sock"))?,
            "--signer-socket".into(),
            row_value(&values, "--signer-socket")?,
            "--sequencer-socket".into(),
            row_value(&values, "--sequencer-socket")?,
            "--ledger-plan".into(),
            row_value(&values, "--ledger-plan")?,
            "--source-trust".into(),
            row_value(&values, "--source-trust")?,
            "--connection-store".into(),
            row_value(&values, "--connection-store")?,
            "--credential-store".into(),
            row_value(&values, "--credential-store")?,
            "--scenario".into(),
            phase.scenario_id.clone(),
            "--phase-index".into(),
            phase.phase_index.to_string(),
            "--supervisor-generation".into(),
            "1".into(),
        ])?;
    }
    complete_typed_source_row(
        QualificationEvidenceSource::CredentialBroker,
        &values,
        &plan,
    )
}

#[cfg(target_os = "linux")]
fn run_profile_state_ordinary_row(arguments: &[String]) -> Result<(), String> {
    run_controller_reader_ordinary_row(arguments, QualificationEvidenceSource::ProfileStateReader)
}

#[cfg(target_os = "linux")]
fn run_provider_proxy_ordinary_row(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values_for(
        arguments,
        "serve-ordinary-row-session",
        &[
            "--runtime-root",
            "--signer-socket",
            "--sequencer-socket",
            "--ledger-plan",
            "--source-trust",
        ],
        typed_source_usage,
    )?;
    let plan = ordinary_row_plan(&values)?;
    let runtime_root = Path::new(value_for(&values, "--runtime-root", typed_source_usage)?);
    for phase in ordinary_row_phases(&plan) {
        let root = ordinary_row_phase_root(runtime_root, phase)?;
        run_provider_proxy_reader(&[
            "serve-reader-session".into(),
            "--socket".into(),
            path_text(&root.join("provider-proxy/agent.sock"))?,
            "--checkpoint-socket".into(),
            path_text(&root.join("provider-proxy/checkpoint.sock"))?,
            "--control-socket".into(),
            path_text(&root.join("provider-proxy/control.sock"))?,
            "--signer-socket".into(),
            row_value(&values, "--signer-socket")?,
            "--sequencer-socket".into(),
            row_value(&values, "--sequencer-socket")?,
            "--ledger-plan".into(),
            row_value(&values, "--ledger-plan")?,
            "--source-trust".into(),
            row_value(&values, "--source-trust")?,
            "--credential-broker-socket".into(),
            path_text(&root.join("credential-broker/agent.sock"))?,
            "--transport-root".into(),
            path_text(
                &runtime_root
                    .join("provider-proxy-reader")
                    .join("transport")
                    .join(&phase.scenario_id),
            )?,
            "--scenario".into(),
            phase.scenario_id.clone(),
            "--phase-index".into(),
            phase.phase_index.to_string(),
            "--supervisor-generation".into(),
            "1".into(),
        ])?;
    }
    complete_typed_source_row(QualificationEvidenceSource::ProviderProxy, &values, &plan)
}

#[cfg(target_os = "linux")]
fn run_provider_observer_ordinary_row(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values_for(
        arguments,
        "serve-ordinary-row-session",
        &[
            "--runtime-root",
            "--signer-socket",
            "--sequencer-socket",
            "--ledger-plan",
            "--source-trust",
        ],
        typed_source_usage,
    )?;
    reject_secret_environment()?;
    let credential = read_runtime_read_credential()?;
    let plan = ordinary_row_plan(&values)?;
    let runtime_root = Path::new(value_for(&values, "--runtime-root", typed_source_usage)?);
    for phase in ordinary_row_phases(&plan) {
        let root = ordinary_row_phase_root(runtime_root, phase)?;
        run_provider_observer_reader_with_credential(
            &[
                "serve-reader-session".into(),
                "--controller-socket".into(),
                path_text(&root.join("provider-observer/controller.sock"))?,
                "--observer-root".into(),
                path_text(
                    &runtime_root
                        .join("provider-observer-reader")
                        .join("observe")
                        .join(&phase.scenario_id),
                )?,
                "--signer-socket".into(),
                row_value(&values, "--signer-socket")?,
                "--sequencer-socket".into(),
                row_value(&values, "--sequencer-socket")?,
                "--ledger-plan".into(),
                row_value(&values, "--ledger-plan")?,
                "--source-trust".into(),
                row_value(&values, "--source-trust")?,
                "--scenario".into(),
                phase.scenario_id.clone(),
                "--phase-index".into(),
                phase.phase_index.to_string(),
            ],
            &credential,
        )?;
    }
    complete_typed_source_row(
        QualificationEvidenceSource::ProviderObserver,
        &values,
        &plan,
    )
}

#[cfg(target_os = "linux")]
fn run_receipt_verifier_ordinary_row(arguments: &[String]) -> Result<(), String> {
    run_controller_reader_ordinary_row(arguments, QualificationEvidenceSource::ReceiptVerifier)
}

#[cfg(target_os = "linux")]
fn run_controller_reader_ordinary_row(
    arguments: &[String],
    source: QualificationEvidenceSource,
) -> Result<(), String> {
    let mut flags = vec![
        "--runtime-root",
        "--signer-socket",
        "--sequencer-socket",
        "--ledger-plan",
        "--source-trust",
    ];
    if source == QualificationEvidenceSource::ReceiptVerifier {
        flags.push("--receipt-trust");
    }
    let values = exact_flag_values_for(
        arguments,
        "serve-ordinary-row-session",
        &flags,
        typed_source_usage,
    )?;
    let plan = ordinary_row_plan(&values)?;
    let runtime_root = Path::new(value_for(&values, "--runtime-root", typed_source_usage)?);
    for phase in ordinary_row_phases(&plan) {
        let root = ordinary_row_phase_root(runtime_root, phase)?;
        let (directory, runner): (&str, fn(&[String]) -> Result<(), String>) = match source {
            QualificationEvidenceSource::ProfileStateReader => {
                ("profile-state-reader", run_profile_state_reader)
            }
            QualificationEvidenceSource::ReceiptVerifier => {
                ("receipt-verifier", run_receipt_verifier_reader)
            }
            _ => return Err("ordinary controller reader role is unsupported".into()),
        };
        let mut request = vec![
            "serve-reader-session".into(),
            "--controller-socket".into(),
            path_text(&root.join(directory).join("controller.sock"))?,
            "--signer-socket".into(),
            row_value(&values, "--signer-socket")?,
            "--sequencer-socket".into(),
            row_value(&values, "--sequencer-socket")?,
            "--ledger-plan".into(),
            row_value(&values, "--ledger-plan")?,
            "--source-trust".into(),
            row_value(&values, "--source-trust")?,
            "--scenario".into(),
            phase.scenario_id.clone(),
            "--phase-index".into(),
            phase.phase_index.to_string(),
        ];
        if source == QualificationEvidenceSource::ReceiptVerifier {
            request.extend([
                "--receipt-trust".into(),
                row_value(&values, "--receipt-trust")?,
            ]);
        }
        runner(&request)?;
    }
    complete_typed_source_row(source, &values, &plan)
}

#[cfg(target_os = "linux")]
fn complete_typed_source_row(
    source: QualificationEvidenceSource,
    values: &BTreeMap<&str, &str>,
    plan: &QualificationEvidenceLedgerPlanV1,
) -> Result<(), String> {
    let trust = QualificationEvidenceSourceTrustRegistry::from_json(&read_bounded(
        Path::new(value_for(values, "--source-trust", typed_source_usage)?),
        MAX_TRUST_BYTES,
        false,
    )?)
    .map_err(string_error)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let remaining = plan
        .deadline_at_unix_seconds
        .checked_sub(now)
        .filter(|seconds| *seconds != 0)
        .ok_or_else(|| "typed source row completed outside the protected interval".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(remaining);
    let reader_uid = rustix::process::geteuid().as_raw();
    let reader_artifact = qualification_source_process_executable_sha256()?;
    if trust
        .fixed_source_for_reader_process(
            reader_uid,
            &reader_artifact,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?
        != source
    {
        return Err("row-complete caller differs from protected source trust".into());
    }
    let (_, _, signer_artifact, signer_uid) = trust
        .current_source_process_binding(
            source,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
    let mut signer = connect_before(
        Path::new(value_for(values, "--signer-socket", typed_source_usage)?),
        deadline,
        "typed source row completion",
    )?;
    let signer_peer = QualificationSourceSessionPeer::observe(&signer)?;
    if signer_peer.uid() != signer_uid || signer_peer.executable_sha256() != signer_artifact {
        return Err("row-complete signer differs from protected source trust".into());
    }
    write_source_session_frame_before(&mut signer, TYPED_SOURCE_ROW_COMPLETE, deadline)?;
    signer.shutdown(Shutdown::Write).map_err(string_error)?;
    let acknowledgement = read_source_session_frame_before(&mut signer, deadline)?
        .ok_or_else(|| "typed source closed before row-complete acknowledgement".to_owned())?;
    if acknowledgement != TYPED_SOURCE_ROW_COMPLETE_ACK {
        return Err("typed source returned the wrong row-complete acknowledgement".into());
    }
    if read_source_session_frame_before(&mut signer, deadline)?.is_some() {
        return Err("typed source returned data after row-complete acknowledgement".into());
    }
    signer_peer.verify_unchanged()
}

#[cfg(not(target_os = "linux"))]
fn run_client_proxy_ordinary_row(_arguments: &[String]) -> Result<(), String> {
    Err("ordinary row readers require Linux process identity".into())
}

#[cfg(not(target_os = "linux"))]
fn run_credential_broker_ordinary_row(_arguments: &[String]) -> Result<(), String> {
    Err("ordinary row readers require Linux process identity".into())
}

#[cfg(not(target_os = "linux"))]
fn run_profile_state_ordinary_row(_arguments: &[String]) -> Result<(), String> {
    Err("ordinary row readers require Linux process identity".into())
}

#[cfg(not(target_os = "linux"))]
fn run_receipt_verifier_ordinary_row(_arguments: &[String]) -> Result<(), String> {
    Err("ordinary row readers require Linux process identity".into())
}

#[cfg(not(target_os = "linux"))]
fn run_provider_proxy_ordinary_row(_arguments: &[String]) -> Result<(), String> {
    Err("ordinary row readers require Linux process identity".into())
}

#[cfg(not(target_os = "linux"))]
fn run_provider_observer_ordinary_row(_arguments: &[String]) -> Result<(), String> {
    Err("ordinary row readers require Linux process identity".into())
}

#[cfg(target_os = "linux")]
struct ProviderProxyRetainedCall {
    request_sha256: String,
    response: Zeroizing<Vec<u8>>,
}

#[cfg(target_os = "linux")]
struct ProviderProxyCheckpoint {
    stream: UnixStream,
    peer: QualificationSourceSessionPeer,
}

#[cfg(target_os = "linux")]
struct ProviderProxyCredentialBroker {
    socket: PathBuf,
    reader_uid: u32,
    reader_artifact_sha256: String,
}

#[cfg(target_os = "linux")]
fn run_provider_proxy_reader(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values_for(
        arguments,
        "serve-reader-session",
        &[
            "--socket",
            "--checkpoint-socket",
            "--control-socket",
            "--signer-socket",
            "--sequencer-socket",
            "--ledger-plan",
            "--source-trust",
            "--credential-broker-socket",
            "--transport-root",
            "--scenario",
            "--phase-index",
            "--supervisor-generation",
        ],
        typed_source_usage,
    )?;
    reject_secret_environment()?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&read_bounded(
        Path::new(value_for(&values, "--ledger-plan", typed_source_usage)?),
        MAX_TRUST_BYTES,
        true,
    )?)
    .map_err(string_error)?;
    let trust = QualificationEvidenceSourceTrustRegistry::from_json(&read_bounded(
        Path::new(value_for(&values, "--source-trust", typed_source_usage)?),
        MAX_TRUST_BYTES,
        false,
    )?)
    .map_err(string_error)?;
    let scenario = value_for(&values, "--scenario", typed_source_usage)?;
    let phase_index = value_for(&values, "--phase-index", typed_source_usage)?
        .parse::<u8>()
        .map_err(string_error)?;
    let phase = plan
        .phases
        .iter()
        .find(|phase| phase.scenario_id == scenario && phase.phase_index == phase_index)
        .cloned()
        .ok_or_else(|| "ProviderProxy phase is absent from the immutable ledger plan".to_owned())?;
    let supervisor_generation = value_for(&values, "--supervisor-generation", typed_source_usage)?
        .parse::<u32>()
        .map_err(string_error)?;
    if supervisor_generation == 0 {
        return Err("ProviderProxy supervisor generation is invalid".into());
    }
    let transport_root = PathBuf::from(value_for(&values, "--transport-root", typed_source_usage)?);
    validate_provider_proxy_transport_root(&transport_root, &plan)?;
    let deadline = qualification_plan_deadline(&plan, "ProviderProxy")?;
    let reader_uid = rustix::process::geteuid().as_raw();
    let reader_artifact = qualification_source_process_executable_sha256()?;
    let now = signing_time_before(deadline, "ProviderProxy reader")?;
    if trust
        .fixed_source_for_reader_process(
            reader_uid,
            &reader_artifact,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?
        != QualificationEvidenceSource::ProviderProxy
    {
        return Err("ProviderProxy reader differs from protected source trust".into());
    }
    let (_, _, credential_broker_signer_artifact, _) = trust
        .current_source_process_binding(
            QualificationEvidenceSource::CredentialBroker,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
    let (_, _, _, _, credential_broker_reader_artifact, credential_broker_reader_uid) = trust
        .fixed_source_process_binding(
            QualificationEvidenceSource::CredentialBroker,
            credential_broker_signer_artifact,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
    let credential_broker = ProviderProxyCredentialBroker {
        socket: PathBuf::from(value_for(
            &values,
            "--credential-broker-socket",
            typed_source_usage,
        )?),
        reader_uid: credential_broker_reader_uid,
        reader_artifact_sha256: credential_broker_reader_artifact.to_owned(),
    };
    let socket = Path::new(value_for(&values, "--socket", typed_source_usage)?);
    let checkpoint_socket = Path::new(value_for(
        &values,
        "--checkpoint-socket",
        typed_source_usage,
    )?);
    let control_socket = Path::new(value_for(&values, "--control-socket", typed_source_usage)?);
    if socket == checkpoint_socket
        || socket == control_socket
        || checkpoint_socket == control_socket
    {
        return Err("ProviderProxy agent, checkpoint, and control sockets must be distinct".into());
    }
    let listener = bind_shared_reader_listener(socket, &plan, "ProviderProxy agent")?;
    let _socket_guard = SocketPathGuard(socket.to_owned());
    let checkpoint_listener =
        bind_shared_reader_listener(checkpoint_socket, &plan, "ProviderProxy checkpoint")?;
    let _checkpoint_guard = SocketPathGuard(checkpoint_socket.to_owned());
    let control_listener =
        bind_shared_reader_listener(control_socket, &plan, "ProviderProxy control")?;
    let _control_guard = SocketPathGuard(control_socket.to_owned());
    let appender = Mutex::new(FixedSourceAppendSession::connect(
        QualificationEvidenceSource::ProviderProxy,
        plan.clone(),
        trust,
        Path::new(value_for(&values, "--signer-socket", typed_source_usage)?),
        PathBuf::from(value_for(
            &values,
            "--sequencer-socket",
            typed_source_usage,
        )?),
        deadline,
    )?);
    let in_flight = AtomicUsize::new(0);
    let mut checkpoint = None;
    let mut authorization = None;
    let mut calls =
        BTreeMap::<(String, QualificationProviderCallKind), ProviderProxyRetainedCall>::new();
    loop {
        if Instant::now() >= deadline {
            return Err("ProviderProxy exceeded the protected run deadline".into());
        }
        if let Some(mut control) = accept_optional_before(&control_listener)? {
            let ready = || in_flight.load(Ordering::Acquire) == 0;
            accept_phase_reader_stop(
                &mut control,
                &plan,
                &in_flight,
                &ready,
                deadline,
                "ProviderProxy",
            )?;
            return Ok(());
        }
        if let Some(stream) = accept_optional_before(&checkpoint_listener)? {
            let (code, enrolled) = enroll_provider_proxy_checkpoint(stream, &plan, deadline)?;
            match code {
                SOURCE_CHECKPOINT_PROVIDER_AUTHORIZATION if authorization.is_none() => {
                    authorization = Some(enrolled);
                }
                SOURCE_CHECKPOINT_AFTER_REQUEST_WRITE
                    if checkpoint.is_none()
                        && phase.failpoint == Some(QualificationFailpoint::AfterRequestWrite) =>
                {
                    checkpoint = Some(enrolled);
                }
                _ => {
                    return Err(
                        "ProviderProxy checkpoint is duplicate or outside its phase policy".into(),
                    );
                }
            }
        }
        if let Some(mut stream) = accept_optional_before(&listener)? {
            in_flight.store(1, Ordering::Release);
            let result = handle_provider_proxy_connection(
                &mut stream,
                &plan,
                &phase,
                supervisor_generation,
                &appender,
                &mut authorization,
                &mut checkpoint,
                &mut calls,
                &transport_root,
                &credential_broker,
                deadline,
            );
            in_flight.store(0, Ordering::Release);
            result?;
        } else {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_provider_proxy_reader(_arguments: &[String]) -> Result<(), String> {
    Err("ProviderProxy reader requires Linux process identity".into())
}

#[cfg(target_os = "linux")]
fn bind_shared_reader_listener(
    socket: &Path,
    plan: &QualificationEvidenceLedgerPlanV1,
    label: &str,
) -> Result<UnixListener, String> {
    let parent = validate_shared_reader_socket_path(socket, plan)?;
    let listener = UnixListener::bind(socket).map_err(string_error)?;
    if validate_shared_reader_socket_path_after_bind(socket, plan)? != parent {
        return Err(format!("{label} socket parent changed while binding"));
    }
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660)).map_err(string_error)?;
    listener.set_nonblocking(true).map_err(string_error)?;
    Ok(listener)
}

#[cfg(target_os = "linux")]
fn enroll_provider_proxy_checkpoint(
    mut stream: UnixStream,
    plan: &QualificationEvidenceLedgerPlanV1,
    deadline: Instant,
) -> Result<(u8, ProviderProxyCheckpoint), String> {
    let peer = QualificationSourceSessionPeer::observe(&stream)?;
    if peer.uid() != plan.supervisor_controller_uid
        || peer.executable_sha256() != plan.supervisor_controller_artifact_sha256
    {
        return Err("ProviderProxy checkpoint peer differs from the protected controller".into());
    }
    let enrollment = read_source_session_frame_before(&mut stream, deadline)?
        .ok_or_else(|| "ProviderProxy checkpoint enrollment is absent".to_owned())?;
    if enrollment.len() != 2
        || enrollment[0] != SOURCE_CHECKPOINT_ENROLLMENT_VERSION
        || !matches!(
            enrollment[1],
            SOURCE_CHECKPOINT_AFTER_REQUEST_WRITE | SOURCE_CHECKPOINT_PROVIDER_AUTHORIZATION
        )
    {
        return Err("ProviderProxy checkpoint enrollment is invalid".into());
    }
    peer.verify_unchanged()?;
    Ok((enrollment[1], ProviderProxyCheckpoint { stream, peer }))
}

#[cfg(target_os = "linux")]
fn authorize_provider_proxy_request(
    authorization: &mut Option<ProviderProxyCheckpoint>,
    plan: &QualificationEvidenceLedgerPlanV1,
    phase: &QualificationEvidencePhasePlanV1,
    request: &QualificationProviderCallRequest,
    deadline: Instant,
) -> Result<(), String> {
    let authorization = authorization
        .as_mut()
        .ok_or_else(|| "ProviderProxy journal authorization channel is absent".to_owned())?;
    let mut request_frame = b"AUTHS-QUALIFICATION-PROVIDER-AUTHORIZATION/1\0".to_vec();
    request_frame.extend_from_slice(request.operation_id().as_bytes());
    write_source_session_frame_before(&mut authorization.stream, &request_frame, deadline)?;
    let Some((response, mut snapshot)) =
        read_framed_request_and_snapshot_before(&mut authorization.stream, 64, deadline)?
    else {
        return Err("ProviderProxy controller supplied no authorization snapshot".into());
    };
    if response != b"AUTHS-QUALIFICATION-PROVIDER-AUTHORIZED/1" {
        return Err("ProviderProxy controller authorization response is invalid".into());
    }
    authorization.peer.verify_unchanged()?;
    let records =
        read_persisted_operation_records_from_qualification_snapshot(&mut snapshot, plan.agent_uid)
            .map_err(string_error)?;
    let mut matching = records
        .iter()
        .filter(|record| record.operation_id().as_str() == request.operation_id());
    let record = matching
        .next()
        .ok_or_else(|| "ProviderProxy authorization names no durable operation".to_owned())?;
    if matching.next().is_some() {
        return Err("ProviderProxy authorization operation is duplicated".into());
    }
    let connection = record
        .binding()
        .connection()
        .ok_or_else(|| "ProviderProxy authorization has no connection binding".to_owned())?;
    let configuration_sha256: [u8; 32] = request
        .configuration()
        .map(Sha256::digest)
        .map(Into::into)
        .unwrap_or([0; 32]);
    if format!(
        "{}/{}",
        record.binding().profile().id(),
        record.binding().profile().version()
    ) != phase.profile
        || record.binding().profile().id() != request.profile_id()
        || record.binding().profile().version() != request.profile_version()
        || connection.generation() != request.connection_generation()
        || !record.provider_entered()
        || record.sealed_command() != Some(request.command())
        || record.profile_state() != request.profile_state()
        || record.binding().configuration_commitment() != &configuration_sha256
    {
        return Err("ProviderProxy request differs from the pinned durable authorization".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn handle_provider_proxy_connection(
    stream: &mut UnixStream,
    plan: &QualificationEvidenceLedgerPlanV1,
    phase: &QualificationEvidencePhasePlanV1,
    supervisor_generation: u32,
    appender: &Mutex<FixedSourceAppendSession>,
    authorization: &mut Option<ProviderProxyCheckpoint>,
    checkpoint: &mut Option<ProviderProxyCheckpoint>,
    calls: &mut BTreeMap<(String, QualificationProviderCallKind), ProviderProxyRetainedCall>,
    transport_root: &Path,
    credential_broker: &ProviderProxyCredentialBroker,
    deadline: Instant,
) -> Result<(), String> {
    let peer = QualificationSourceSessionPeer::observe(stream)?;
    if peer.uid() != plan.agent_uid
        || peer.gid() != plan.agent_gid
        || peer.executable_sha256() != plan.agent_executable_sha256
    {
        return Err("ProviderProxy caller differs from the qualification agent".into());
    }
    let Some(mut request_bytes) =
        read_provider_proxy_request_before(stream, 52 * 1_024 * 1_024, deadline)?
    else {
        // An authenticated connection that disappears mid-frame is
        // transport ambiguity, not a row-level protocol failure. The agent
        // reconnects with the exact canonical request under the same deadline.
        return Ok(());
    };
    peer.verify_unchanged()?;
    let request = QualificationProviderCallRequest::from_cbor(&mut request_bytes)
        .map_err(|()| "ProviderProxy request is not canonical".to_owned())?;
    let expected_profile = format!("{}/{}", request.profile_id(), request.profile_version());
    let mut expected_source_context = [0_u8; 32];
    hex::decode_to_slice(
        plan.source_context_sha256().map_err(string_error)?,
        &mut expected_source_context,
    )
    .map_err(string_error)?;
    if request.source_context_sha256() != &expected_source_context
        || expected_profile != phase.profile
    {
        return Err("ProviderProxy request differs from the immutable phase".into());
    }
    let request_sha256 = qualification_provider_request_sha256(&request);
    let retained_key = (request.operation_id().to_owned(), request.kind());
    if let Some(retained) = calls.get(&retained_key) {
        if retained.request_sha256 != request_sha256 {
            return Err("ProviderProxy reattachment changed the canonical request".into());
        }
        if write_source_session_frame_before(stream, &retained.response, deadline).is_err()
            || stream.shutdown(Shutdown::Write).is_err()
        {
            return Ok(());
        }
        return peer.verify_unchanged();
    }
    if calls.len() >= 16 {
        return Err("ProviderProxy retained call bound is exhausted".into());
    }
    authorize_provider_proxy_request(authorization, plan, phase, &request, deadline)?;
    // The credential is redeemed before the request is accepted by the
    // transport owner, so a failed redemption cannot be misreported as a
    // provider write.  Once the source event below is durably acknowledged,
    // ProviderProxy owns an exact at-most-once obligation to execute this
    // canonical request even if the candidate agent is killed at the selected
    // after-request-write checkpoint.
    let credential = redeem_provider_proxy_credential(&request, credential_broker, deadline)?;
    let request_observation = match request.kind() {
        QualificationProviderCallKind::Execute => {
            QualificationProviderProxyObservationV1::ProviderRequestWritten {
                request_sha256: request_sha256.clone(),
                credential_lease_sha256: hex::encode(request.credential_lease_sha256()),
            }
        }
        QualificationProviderCallKind::Reconcile => {
            QualificationProviderProxyObservationV1::ProviderReconciliationRequested {
                request_sha256: request_sha256.clone(),
                credential_lease_sha256: hex::encode(request.credential_lease_sha256()),
            }
        }
    };
    append_provider_proxy_observation(
        appender,
        plan,
        phase,
        supervisor_generation,
        request.operation_id(),
        request.connection_generation(),
        request_observation,
        deadline,
    )?;
    if phase.failpoint == Some(QualificationFailpoint::AfterRequestWrite) {
        let checkpoint = checkpoint
            .as_mut()
            .ok_or_else(|| "ProviderProxy crash checkpoint controller is absent".to_owned())?;
        write_source_session_frame_before(
            &mut checkpoint.stream,
            &[SOURCE_CHECKPOINT_AFTER_REQUEST_WRITE],
            deadline,
        )?;
        let release = read_source_session_frame_before(&mut checkpoint.stream, deadline)?
            .ok_or_else(|| "ProviderProxy checkpoint closed before release".to_owned())?;
        if release != [SOURCE_CHECKPOINT_CLEAN] {
            return Err("ProviderProxy checkpoint release is invalid".into());
        }
        checkpoint.peer.verify_unchanged()?;
    }
    let response = execute_provider_proxy_call(&request, transport_root, &credential, deadline)?;
    if matches!(
        response,
        QualificationProviderCallResponse::PreEntry(_)
            | QualificationProviderCallResponse::PreEntryPending
            | QualificationProviderCallResponse::Invalid
    ) {
        return Err(
            "ProviderProxy accepted an authorized request that failed before provider entry".into(),
        );
    }
    let response_bytes = Zeroizing::new(
        response
            .to_cbor()
            .map_err(|()| "ProviderProxy response exceeds its canonical bound".to_owned())?,
    );
    let response_observation = match (request.kind(), &response) {
        (QualificationProviderCallKind::Execute, QualificationProviderCallResponse::Success(_)) => {
            Some(
                QualificationProviderProxyObservationV1::ProviderResponseObserved {
                    response_sha256: hex::encode(Sha256::digest(&response_bytes)),
                },
            )
        }
        (
            QualificationProviderCallKind::Reconcile,
            QualificationProviderCallResponse::Success(_)
            | QualificationProviderCallResponse::NotApplied,
        ) => Some(
            QualificationProviderProxyObservationV1::ProviderReconciliationObserved {
                response_sha256: hex::encode(Sha256::digest(&response_bytes)),
            },
        ),
        _ => None,
    };
    if let Some(response_observation) = response_observation {
        append_provider_proxy_observation(
            appender,
            plan,
            phase,
            supervisor_generation,
            request.operation_id(),
            request.connection_generation(),
            response_observation,
            deadline,
        )?;
    }
    calls.insert(
        retained_key.clone(),
        ProviderProxyRetainedCall {
            request_sha256,
            response: response_bytes,
        },
    );
    if peer.verify_unchanged().is_err() {
        return Ok(());
    }
    let retained = calls
        .get(&retained_key)
        .ok_or_else(|| "ProviderProxy lost its retained response".to_owned())?;
    if write_source_session_frame_before(stream, &retained.response, deadline).is_err()
        || stream.shutdown(Shutdown::Write).is_err()
    {
        return Ok(());
    }
    peer.verify_unchanged()
}

#[cfg(target_os = "linux")]
fn read_provider_proxy_request_before(
    stream: &mut UnixStream,
    maximum: usize,
    deadline: Instant,
) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    let mut header = [0_u8; 4];
    let mut offset = 0_usize;
    while offset < header.len() {
        if Instant::now() >= deadline {
            return Ok(None);
        }
        match stream.read(&mut header[offset..]) {
            Ok(0) => return Ok(None),
            Ok(read) => offset += read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return Ok(None),
        }
    }
    let length = usize::try_from(u32::from_be_bytes(header)).map_err(string_error)?;
    if length == 0 || length > maximum {
        return Err("ProviderProxy request length is outside its bound".into());
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    let mut offset = 0_usize;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Ok(None);
        }
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Ok(None),
            Ok(read) => offset += read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return Ok(None),
        }
    }
    Ok(Some(bytes))
}

#[cfg(target_os = "linux")]
fn read_zeroizing_frame_before(
    stream: &mut UnixStream,
    maximum: usize,
    deadline: Instant,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut header = [0_u8; 4];
    read_exact_zeroizing_before(stream, &mut header, deadline, label)?;
    let length = usize::try_from(u32::from_be_bytes(header)).map_err(string_error)?;
    if length == 0 || length > maximum {
        return Err(format!("{label} length is outside its bound"));
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    read_exact_zeroizing_before(stream, &mut bytes, deadline, label)?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn read_exact_zeroizing_before(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
    label: &str,
) -> Result<(), String> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(format!("{label} exceeded its total deadline"));
        }
        match stream.read(bytes) {
            Ok(0) => return Err(format!("{label} ended before its complete frame")),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn qualification_provider_request_sha256(request: &QualificationProviderCallRequest) -> String {
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-QUALIFICATION-PROVIDER-REQUEST\0\x01");
    for part in [
        request.source_context_sha256().as_slice(),
        request.operation_id().as_bytes(),
        request.profile_id().as_bytes(),
        &request.profile_version().to_be_bytes(),
        &request.connection_generation().to_be_bytes(),
        &[match request.kind() {
            auths_connections::QualificationProviderCallKind::Execute => 0,
            auths_connections::QualificationProviderCallKind::Reconcile => 1,
        }],
        request.credential_lease_sha256().as_slice(),
        Sha256::digest(request.credential_capability()).as_slice(),
        request.command(),
        request.profile_state(),
        request.configuration_format().unwrap_or("").as_bytes(),
        request.configuration().unwrap_or(&[]),
        &request.now_unix_seconds().to_be_bytes(),
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    hex::encode(digest.finalize())
}

#[cfg(target_os = "linux")]
fn redeem_provider_proxy_credential(
    request: &QualificationProviderCallRequest,
    broker: &ProviderProxyCredentialBroker,
    deadline: Instant,
) -> Result<ProviderCredentialLease, String> {
    let mut stream = connect_before(&broker.socket, deadline, "CredentialBroker redemption")?;
    stream.set_nonblocking(true).map_err(string_error)?;
    let peer = QualificationSourceSessionPeer::observe(&stream)?;
    if peer.uid() != broker.reader_uid || peer.executable_sha256() != broker.reader_artifact_sha256
    {
        return Err("ProviderProxy connected to an untrusted CredentialBroker".into());
    }
    let mut redemption = Zeroizing::new(Vec::with_capacity(65 + request.operation_id().len()));
    redemption.push(CREDENTIAL_BROKER_PROXY_REDEEM);
    redemption.extend_from_slice(request.credential_capability());
    redemption.extend_from_slice(request.credential_lease_sha256());
    redemption.extend_from_slice(request.operation_id().as_bytes());
    write_source_session_frame_before(&mut stream, &redemption, deadline)?;
    let credential = read_zeroizing_frame_before(
        &mut stream,
        65_536,
        deadline,
        "CredentialBroker redemption response",
    )?;
    peer.verify_unchanged()?;
    let credential =
        ProviderCredentialLease::from_adapter(credential.as_slice().to_vec(), deadline)
            .map_err(string_error)?;
    write_source_session_frame_before(&mut stream, &[1], deadline)?;
    stream.shutdown(Shutdown::Write).map_err(string_error)?;
    peer.verify_unchanged()?;
    Ok(credential)
}

#[cfg(target_os = "linux")]
fn execute_provider_proxy_call(
    request: &QualificationProviderCallRequest,
    transport_root: &Path,
    credential: &ProviderCredentialLease,
    deadline: Instant,
) -> Result<QualificationProviderCallResponse, String> {
    let profile = format!("{}/{}", request.profile_id(), request.profile_version());
    let route = QualificationRoute::for_profile(&profile)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(string_error)?;
    let result = match block_on_protected_provider_operation(
        &runtime,
        deadline,
        route.dispatch_provider_transport(
            &profile,
            request.kind(),
            request.command(),
            request.profile_state(),
            credential,
            request.configuration(),
            transport_root,
            request.operation_id(),
            request.now_unix_seconds(),
            deadline,
        ),
    ) {
        Ok(result) => result,
        Err(ProtectedProviderDeadline) => {
            return Ok(QualificationProviderCallResponse::PostEntryTimeout);
        }
    };
    Ok(match result {
        Ok(Some(value)) => QualificationProviderCallResponse::Success(value),
        Ok(None) => QualificationProviderCallResponse::NotApplied,
        Err(error) => provider_call_response(Err(error)),
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProtectedProviderDeadline;

#[cfg(target_os = "linux")]
fn block_on_protected_provider_operation<F, T>(
    runtime: &tokio::runtime::Runtime,
    deadline: Instant,
    operation: F,
) -> Result<T, ProtectedProviderDeadline>
where
    F: Future<Output = T>,
{
    let provider_deadline = deadline
        .checked_sub(Duration::from_secs(1))
        .unwrap_or(deadline);
    if Instant::now() >= provider_deadline {
        return Err(ProtectedProviderDeadline);
    }
    runtime
        .block_on(tokio::time::timeout_at(
            tokio::time::Instant::from_std(provider_deadline),
            operation,
        ))
        .map_err(|_| ProtectedProviderDeadline)
}

#[cfg(target_os = "linux")]
fn provider_call_response(
    result: Result<Vec<u8>, ProfileRuntimeError>,
) -> QualificationProviderCallResponse {
    match result {
        Ok(value) => QualificationProviderCallResponse::Success(value),
        Err(ProfileRuntimeError::PreEntry(issue)) => {
            QualificationProviderCallResponse::PreEntry(issue)
        }
        Err(ProfileRuntimeError::PreEntryPending) => {
            QualificationProviderCallResponse::PreEntryPending
        }
        Err(ProfileRuntimeError::Possible(issue)) => {
            QualificationProviderCallResponse::Possible(issue)
        }
        Err(ProfileRuntimeError::PossibleWithProfileState {
            issue,
            profile_state,
        }) => QualificationProviderCallResponse::PossibleWithProfileState {
            issue,
            profile_state,
        },
        Err(ProfileRuntimeError::Invalid) => QualificationProviderCallResponse::Invalid,
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn append_provider_proxy_observation(
    appender: &Mutex<FixedSourceAppendSession>,
    plan: &QualificationEvidenceLedgerPlanV1,
    phase: &QualificationEvidencePhasePlanV1,
    supervisor_generation: u32,
    operation_id: &str,
    connection_generation: u64,
    observation: QualificationProviderProxyObservationV1,
    deadline: Instant,
) -> Result<(), String> {
    let mut record = QualificationProviderProxyRecordV1 {
        schema: "auths.qualification-provider-proxy-record/1".into(),
        context: QualificationSourceEventContextV1 {
            sequence: 1,
            previous_event_sha256: "0".repeat(64),
            scenario_id: phase.scenario_id.clone(),
            phase_index: phase.phase_index,
            role: phase.role,
            profile: phase.profile.clone(),
            failpoint: phase.failpoint,
            supervisor_generation,
            operation_id: Some(operation_id.to_owned()),
            request_id: None,
            connection_generation: Some(connection_generation.to_string()),
        },
        observation,
    };
    let intent =
        hex::decode(record.intent_sha256().map_err(string_error)?).map_err(string_error)?;
    appender
        .lock()
        .map_err(string_error)?
        .resume_or_append_record(intent, deadline, move |sequence, previous| {
            record.context.sequence = sequence;
            record.context.previous_event_sha256 = previous;
            record.to_json().map_err(string_error)
        })?;
    let _ = plan;
    Ok(())
}

#[cfg(target_os = "linux")]
struct CredentialBrokerLease {
    request: QualificationCredentialLeaseRequest,
    credential: ProviderCredentialLease,
    lease_sha256: String,
    requested_scope_sha256: String,
    effective_scope_sha256: String,
    capability: Zeroizing<[u8; 32]>,
    attached: bool,
    proxy_in_flight: bool,
}

#[cfg(target_os = "linux")]
struct CredentialBrokerAppender {
    append: QualificationSourceAppendSession,
    plan: QualificationEvidenceLedgerPlanV1,
    trust: QualificationEvidenceSourceTrustRegistry,
    signer_socket: PathBuf,
}

#[cfg(target_os = "linux")]
struct CredentialBrokerShared {
    plan: QualificationEvidenceLedgerPlanV1,
    phase: QualificationEvidencePhasePlanV1,
    supervisor_generation: u32,
    connections: PersistentConnectionStore,
    credentials: PersistentCredentialStore,
    provider_proxy_reader_uid: u32,
    provider_proxy_reader_artifact_sha256: String,
    appender: Mutex<CredentialBrokerAppender>,
    leases: Mutex<BTreeMap<String, CredentialBrokerLease>>,
    checkpoint: Mutex<Option<CredentialBrokerCheckpoint>>,
    in_flight: Arc<AtomicUsize>,
}

#[cfg(target_os = "linux")]
struct CredentialBrokerCheckpoint {
    stream: UnixStream,
    peer: QualificationSourceSessionPeer,
    code: u8,
}

#[cfg(target_os = "linux")]
fn run_credential_broker_reader(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values_for(
        arguments,
        "serve-reader-session",
        &[
            "--socket",
            "--checkpoint-socket",
            "--control-socket",
            "--signer-socket",
            "--sequencer-socket",
            "--ledger-plan",
            "--source-trust",
            "--connection-store",
            "--credential-store",
            "--scenario",
            "--phase-index",
            "--supervisor-generation",
        ],
        typed_source_usage,
    )?;
    reject_secret_environment()?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&read_bounded(
        Path::new(value_for(&values, "--ledger-plan", typed_source_usage)?),
        MAX_TRUST_BYTES,
        true,
    )?)
    .map_err(string_error)?;
    let trust = QualificationEvidenceSourceTrustRegistry::from_json(&read_bounded(
        Path::new(value_for(&values, "--source-trust", typed_source_usage)?),
        MAX_TRUST_BYTES,
        false,
    )?)
    .map_err(string_error)?;
    let scenario = value_for(&values, "--scenario", typed_source_usage)?;
    let phase_index = value_for(&values, "--phase-index", typed_source_usage)?
        .parse::<u8>()
        .map_err(string_error)?;
    let phase = plan
        .phases
        .iter()
        .find(|phase| phase.scenario_id == scenario && phase.phase_index == phase_index)
        .cloned()
        .ok_or_else(|| {
            "CredentialBroker phase is absent from the immutable ledger plan".to_owned()
        })?;
    let supervisor_generation = value_for(&values, "--supervisor-generation", typed_source_usage)?
        .parse::<u32>()
        .map_err(string_error)?;
    if supervisor_generation == 0 {
        return Err("CredentialBroker supervisor generation is invalid".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let remaining = plan
        .deadline_at_unix_seconds
        .checked_sub(now)
        .filter(|seconds| *seconds != 0)
        .ok_or_else(|| "CredentialBroker started outside the protected run interval".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(remaining);
    let reader_uid = rustix::process::geteuid().as_raw();
    let reader_artifact_sha256 = qualification_source_process_executable_sha256()?;
    if trust
        .fixed_source_for_reader_process(
            reader_uid,
            &reader_artifact_sha256,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?
        != QualificationEvidenceSource::CredentialBroker
    {
        return Err("CredentialBroker reader differs from protected source trust".into());
    }
    let (_, _, provider_proxy_signer_artifact, _) = trust
        .current_source_process_binding(
            QualificationEvidenceSource::ProviderProxy,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
    let (_, _, _, _, provider_proxy_reader_artifact, provider_proxy_reader_uid) = trust
        .fixed_source_process_binding(
            QualificationEvidenceSource::ProviderProxy,
            provider_proxy_signer_artifact,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
    let connection_store = Path::new(value_for(
        &values,
        "--connection-store",
        typed_source_usage,
    )?);
    let credential_store = Path::new(value_for(
        &values,
        "--credential-store",
        typed_source_usage,
    )?);
    if connection_store == credential_store {
        return Err("CredentialBroker stores must be distinct".into());
    }
    validate_broker_store_path(connection_store, reader_uid)?;
    validate_broker_store_path(credential_store, reader_uid)?;
    let limits = RegistryLimits {
        maximum_records: std::num::NonZeroUsize::new(10_000)
            .ok_or_else(|| "CredentialBroker connection bound is invalid".to_owned())?,
        maximum_encoded_bytes: std::num::NonZeroUsize::new(268_435_456)
            .ok_or_else(|| "CredentialBroker connection byte bound is invalid".to_owned())?,
    };
    let connections =
        PersistentConnectionStore::open(connection_store, limits).map_err(string_error)?;
    let credentials = PersistentCredentialStore::open(credential_store).map_err(string_error)?;
    let socket = Path::new(value_for(&values, "--socket", typed_source_usage)?);
    let checkpoint_socket = Path::new(value_for(
        &values,
        "--checkpoint-socket",
        typed_source_usage,
    )?);
    let control_socket = Path::new(value_for(&values, "--control-socket", typed_source_usage)?);
    if socket == control_socket
        || socket == checkpoint_socket
        || control_socket == checkpoint_socket
    {
        return Err(
            "CredentialBroker agent, checkpoint, and control sockets must be distinct".into(),
        );
    }
    let socket_parent = validate_shared_reader_socket_path(socket, &plan)?;
    let listener = UnixListener::bind(socket).map_err(string_error)?;
    if validate_shared_reader_socket_path_after_bind(socket, &plan)? != socket_parent {
        return Err("CredentialBroker socket parent changed while binding".into());
    }
    let _socket_guard = SocketPathGuard(socket.to_owned());
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660)).map_err(string_error)?;
    listener.set_nonblocking(true).map_err(string_error)?;
    let checkpoint_parent = validate_shared_reader_socket_path(checkpoint_socket, &plan)?;
    let checkpoint_listener = UnixListener::bind(checkpoint_socket).map_err(string_error)?;
    if validate_shared_reader_socket_path_after_bind(checkpoint_socket, &plan)? != checkpoint_parent
    {
        return Err("CredentialBroker checkpoint socket parent changed while binding".into());
    }
    let _checkpoint_socket_guard = SocketPathGuard(checkpoint_socket.to_owned());
    fs::set_permissions(checkpoint_socket, fs::Permissions::from_mode(0o660))
        .map_err(string_error)?;
    checkpoint_listener
        .set_nonblocking(true)
        .map_err(string_error)?;
    let control_parent = validate_shared_reader_socket_path(control_socket, &plan)?;
    let control_listener = UnixListener::bind(control_socket).map_err(string_error)?;
    if validate_shared_reader_socket_path_after_bind(control_socket, &plan)? != control_parent {
        return Err("CredentialBroker control socket parent changed while binding".into());
    }
    let _control_socket_guard = SocketPathGuard(control_socket.to_owned());
    fs::set_permissions(control_socket, fs::Permissions::from_mode(0o660)).map_err(string_error)?;
    control_listener
        .set_nonblocking(true)
        .map_err(string_error)?;
    let shared = Arc::new(CredentialBrokerShared {
        plan: plan.clone(),
        phase,
        supervisor_generation,
        connections,
        credentials,
        provider_proxy_reader_uid,
        provider_proxy_reader_artifact_sha256: provider_proxy_reader_artifact.to_owned(),
        appender: Mutex::new(CredentialBrokerAppender {
            append: QualificationSourceAppendSession::new(
                QualificationEvidenceSource::CredentialBroker,
                plan.clone(),
                trust.clone(),
                PathBuf::from(value_for(
                    &values,
                    "--sequencer-socket",
                    typed_source_usage,
                )?),
            ),
            plan,
            trust,
            signer_socket: PathBuf::from(value_for(
                &values,
                "--signer-socket",
                typed_source_usage,
            )?),
        }),
        leases: Mutex::new(BTreeMap::new()),
        checkpoint: Mutex::new(None),
        in_flight: Arc::new(AtomicUsize::new(0)),
    });
    let (failures, errors) = mpsc::channel();
    loop {
        if Instant::now() >= deadline {
            return Err("CredentialBroker exceeded the protected run deadline".into());
        }
        if let Ok(error) = errors.try_recv() {
            return Err(error);
        }
        if let Some(mut control) = accept_optional_before(&control_listener)? {
            let ready = || shared.leases.lock().is_ok_and(|leases| leases.is_empty());
            accept_phase_reader_stop(
                &mut control,
                &shared.plan,
                &shared.in_flight,
                &ready,
                deadline,
                "CredentialBroker",
            )?;
            return Ok(());
        }
        match checkpoint_listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(true).map_err(string_error)?;
                let peer = QualificationSourceSessionPeer::observe(&stream)?;
                if peer.uid() != shared.plan.supervisor_controller_uid
                    || peer.executable_sha256() != shared.plan.supervisor_controller_artifact_sha256
                {
                    return Err(
                        "CredentialBroker checkpoint peer differs from the protected controller"
                            .into(),
                    );
                }
                let enrollment = read_source_session_frame_before(&mut stream, deadline)?
                    .ok_or_else(|| "CredentialBroker checkpoint enrollment is absent".to_owned())?;
                let expected = match shared.phase.failpoint {
                    Some(QualificationFailpoint::AfterReread) => SOURCE_CHECKPOINT_AFTER_REREAD,
                    Some(QualificationFailpoint::AfterLease) => SOURCE_CHECKPOINT_AFTER_LEASE,
                    _ => return Err(
                        "CredentialBroker checkpoint was opened outside its immutable failpoint"
                            .into(),
                    ),
                };
                if enrollment != [SOURCE_CHECKPOINT_ENROLLMENT_VERSION, expected] {
                    return Err(
                        "CredentialBroker checkpoint enrollment differs from the immutable phase"
                            .into(),
                    );
                }
                peer.verify_unchanged()?;
                let mut checkpoint = shared.checkpoint.lock().map_err(string_error)?;
                if checkpoint.is_some() {
                    return Err("CredentialBroker checkpoint controller is duplicated".into());
                }
                *checkpoint = Some(CredentialBrokerCheckpoint {
                    stream,
                    peer,
                    code: expected,
                });
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(string_error(error)),
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(true).map_err(string_error)?;
                let permit = acquire_in_flight_permit(
                    &shared.in_flight,
                    MAX_CREDENTIAL_BROKER_IN_FLIGHT,
                    "CredentialBroker",
                )?;
                let shared = Arc::clone(&shared);
                let failures = failures.clone();
                thread::spawn(move || {
                    let _permit = permit;
                    if let Err(error) =
                        handle_credential_broker_connection(shared, stream, deadline)
                    {
                        let _ = failures.send(error);
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_credential_broker_reader(_arguments: &[String]) -> Result<(), String> {
    Err("the protected CredentialBroker reader is supported only on Linux".into())
}

#[cfg(target_os = "linux")]
fn validate_broker_store_path(path: &Path, owner_uid: u32) -> Result<(), String> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err("CredentialBroker store path is not normalized and absolute".into());
    }
    let parent = open_directory_componentwise(
        path.parent()
            .ok_or_else(|| "CredentialBroker store path has no parent".to_owned())?,
    )?;
    let parent = parent.metadata().map_err(string_error)?;
    let file = fs::symlink_metadata(path).map_err(string_error)?;
    if parent.uid() != owner_uid
        || parent.mode() & 0o777 != 0o700
        || !file.file_type().is_file()
        || file.file_type().is_symlink()
        || file.uid() != owner_uid
        || file.nlink() != 1
        || file.mode() & 0o777 != 0o600
    {
        return Err("CredentialBroker store ownership or mode is invalid".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_credential_broker_connection(
    shared: Arc<CredentialBrokerShared>,
    mut stream: UnixStream,
    deadline: Instant,
) -> Result<(), String> {
    let peer = QualificationSourceSessionPeer::observe(&stream)?;
    let request = read_source_session_frame_before(&mut stream, deadline)?
        .ok_or_else(|| "CredentialBroker agent supplied no lease request".to_owned())?;
    let (&mode, request) = request
        .split_first()
        .ok_or_else(|| "CredentialBroker lease request omitted its mode".to_owned())?;
    if mode == CREDENTIAL_BROKER_PROXY_REDEEM {
        if peer.uid() != shared.provider_proxy_reader_uid
            || peer.gid() != shared.plan.agent_gid
            || peer.executable_sha256() != shared.provider_proxy_reader_artifact_sha256
        {
            return Err("CredentialBroker redemption peer differs from ProviderProxy trust".into());
        }
        peer.verify_unchanged()?;
        return redeem_credential_for_provider_proxy(
            &shared,
            &mut stream,
            &peer,
            request,
            deadline,
        );
    }
    if peer.uid() != shared.plan.agent_uid
        || peer.gid() != shared.plan.agent_gid
        || peer.executable_sha256() != shared.plan.agent_executable_sha256
    {
        return Err("CredentialBroker peer differs from the immutable agent".into());
    }
    if request.len() > 16_384 {
        return Err("CredentialBroker lease request exceeds its hard bound".into());
    }
    let request = QualificationCredentialLeaseRequest::from_cbor(request)
        .map_err(|_| "CredentialBroker lease request is malformed".to_owned())?;
    peer.verify_unchanged()?;
    if request.source_context_sha256()
        != &decode_digest(&shared.plan.source_context_sha256().map_err(string_error)?)?
        || format!("{}/{}", request.profile_id(), request.profile_version()) != shared.phase.profile
        || hex::encode(Sha256::digest(request.workload_id().as_bytes()))
            != shared.phase.credential_requirement.workload_id_sha256
        || request.provider_kind() != shared.phase.credential_requirement.provider_kind
        || request.contract() != shared.phase.credential_requirement.contract
        || request.descriptor_schema() != shared.phase.credential_requirement.descriptor_schema
        || request.credential_scope() != shared.phase.credential_requirement.credential_scope
    {
        return Err("CredentialBroker request differs from the immutable phase".into());
    }
    if mode == CREDENTIAL_BROKER_CLOSE_RETRY {
        retry_credential_lease_close(&shared, &request, deadline)?;
        peer.verify_unchanged()?;
        if write_source_session_frame_before(&mut stream, &[1], deadline).is_ok() {
            let _ = stream.shutdown(Shutdown::Write);
        }
        return Ok(());
    }
    if mode != CREDENTIAL_BROKER_ACQUIRE {
        return Err("CredentialBroker lease request mode is invalid".into());
    }
    let Some(mut response) = acquire_credential_lease(&shared, &request, deadline)? else {
        let _ = stream.shutdown(Shutdown::Both);
        return Ok(());
    };
    if shared.phase.failpoint == Some(QualificationFailpoint::AfterLease)
        && !credential_broker_checkpoint(&shared, SOURCE_CHECKPOINT_AFTER_LEASE, deadline)?
    {
        response.fill(0);
        close_credential_lease(&shared, &request, deadline)?;
        credential_broker_checkpoint_clean(&shared, deadline)?;
        let _ = stream.shutdown(Shutdown::Both);
        return Ok(());
    }
    peer.verify_unchanged()?;
    if write_bounded_session_frame_before(&mut stream, response.as_slice(), 65_536, deadline)
        .is_err()
    {
        response.fill(0);
        detach_credential_lease(&shared, &request, deadline)?;
        return Ok(());
    }
    response.fill(0);
    match read_source_session_frame_before(&mut stream, deadline)? {
        Some(frame) if frame == [1] => {
            peer.verify_unchanged()?;
            close_credential_lease(&shared, &request, deadline)?;
            if write_source_session_frame_before(&mut stream, &[1], deadline).is_ok() {
                let _ = stream.shutdown(Shutdown::Write);
            }
            Ok(())
        }
        None => detach_credential_lease(&shared, &request, deadline),
        Some(_) => Err("CredentialBroker agent returned a malformed lease close".into()),
    }
}

#[cfg(target_os = "linux")]
fn redeem_credential_for_provider_proxy(
    shared: &CredentialBrokerShared,
    stream: &mut UnixStream,
    peer: &QualificationSourceSessionPeer,
    request: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    if request.len() < 65 || request.len() > 225 {
        return Err("CredentialBroker redemption request is outside its bound".into());
    }
    let capability: [u8; 32] = request[..32]
        .try_into()
        .map_err(|_| "CredentialBroker redemption capability is malformed".to_owned())?;
    let lease_sha256 = hex::encode(&request[32..64]);
    let operation_id = std::str::from_utf8(&request[64..]).map_err(string_error)?;
    if !matches!(OperationIdV1::parse(operation_id), Ok(value) if value.as_str() == operation_id) {
        return Err("CredentialBroker redemption operation is malformed".into());
    }
    let mut response = {
        let mut leases = shared
            .leases
            .lock()
            .map_err(|_| "CredentialBroker lease state is unavailable".to_owned())?;
        let lease = leases
            .get_mut(operation_id)
            .ok_or_else(|| "CredentialBroker redemption names no active lease".to_owned())?;
        if lease.lease_sha256 != lease_sha256
            || lease.capability.as_slice() != capability
            || !lease.attached
            || lease.proxy_in_flight
        {
            return Err("CredentialBroker redemption differs from the active lease".into());
        }
        lease.proxy_in_flight = true;
        Zeroizing::new(
            lease
                .credential
                .expose(Instant::now())
                .map(<[u8]>::to_vec)
                .map_err(string_error)?,
        )
    };
    peer.verify_unchanged()?;
    let exchange =
        if write_bounded_session_frame_before(stream, response.as_slice(), 65_536, deadline)
            .is_err()
        {
            // The protected proxy can reconnect with the same capability. A
            // partial response write does not invalidate or duplicate the lease.
            Ok(())
        } else {
            response.fill(0);
            match read_source_session_frame_before(stream, deadline) {
                Ok(Some(acknowledgement)) if acknowledgement == [1] => {
                    match read_source_session_frame_before(stream, deadline) {
                        Ok(None) => peer.verify_unchanged(),
                        Ok(Some(_)) => {
                            Err("ProviderProxy credential acknowledgement is malformed".into())
                        }
                        Err(_) => Ok(()),
                    }
                }
                Ok(None) | Err(_) => Ok(()),
                Ok(Some(_)) => Err("ProviderProxy credential acknowledgement is malformed".into()),
            }
        };
    response.fill(0);
    let mut leases = shared
        .leases
        .lock()
        .map_err(|_| "CredentialBroker lease state is unavailable".to_owned())?;
    let lease = leases
        .get_mut(operation_id)
        .ok_or_else(|| "CredentialBroker lease disappeared during redemption".to_owned())?;
    lease.proxy_in_flight = false;
    exchange
}

#[cfg(target_os = "linux")]
fn acquire_credential_lease(
    shared: &CredentialBrokerShared,
    request: &QualificationCredentialLeaseRequest,
    deadline: Instant,
) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    let mut leases = shared
        .leases
        .lock()
        .map_err(|_| "CredentialBroker lease state is unavailable".to_owned())?;
    if let Some(existing) = leases.get_mut(request.operation_id()) {
        if existing.request != *request || existing.attached {
            return Err("CredentialBroker lease reattachment conflicts with retained state".into());
        }
        existing.attached = true;
        let mut grant = Zeroizing::new(Vec::with_capacity(33));
        grant.push(1);
        grant.extend_from_slice(existing.capability.as_slice());
        return Ok(Some(grant));
    }
    if leases.len() >= 8 {
        return Err("CredentialBroker active lease bound is exhausted".into());
    }
    let provider = ProviderKind::parse(request.provider_kind()).map_err(string_error)?;
    let alias = ConnectionAlias::parse(request.connection_alias()).map_err(string_error)?;
    let profile = ConnectionProfile::new(
        SemanticId::parse(request.profile_id()).map_err(string_error)?,
        request.profile_version(),
    )
    .map_err(string_error)?;
    let binding = shared
        .connections
        .resolve(&provider, Some(&alias), request.workload_id(), &profile)
        .map_err(string_error)?;
    if binding.connection_id().as_str() != request.connection_id()
        || binding.generation().get() != request.connection_generation()
        || binding.descriptor_commitment() != request.descriptor_sha256()
        || binding.account_commitment() != request.account_sha256()
        || binding.contract().as_str() != request.contract()
        || binding.descriptor_schema().as_str() != request.descriptor_schema()
    {
        return Err("CredentialBroker resolved binding differs from the agent request".into());
    }
    let record = shared
        .connections
        .reread_before_lease(&binding, request.workload_id(), &profile)
        .map_err(string_error)?;
    append_credential_observation(
        shared,
        request,
        QualificationCredentialBrokerObservationV1::ConnectionReread {
            connection_id_sha256: Some(hex::encode(Sha256::digest(
                record.connection_id().as_str().as_bytes(),
            ))),
            connection_alias_sha256: Some(hex::encode(Sha256::digest(
                record.alias().as_str().as_bytes(),
            ))),
            descriptor_sha256: Some(hex::encode(record.descriptor_commitment())),
            account_sha256: Some(hex::encode(record.account_commitment())),
        },
        deadline,
    )?;
    if shared.phase.failpoint == Some(QualificationFailpoint::AfterReread)
        && !credential_broker_checkpoint(shared, SOURCE_CHECKPOINT_AFTER_REREAD, deadline)?
    {
        credential_broker_checkpoint_clean(shared, deadline)?;
        return Ok(None);
    }
    let requested_scope_sha256 = hex::encode(Sha256::digest(request.credential_scope().as_bytes()));
    let effective_scope_sha256 = requested_scope_sha256.clone();
    let lease_sha256 = qualification_credential_lease_sha256(request)?;
    append_credential_observation(
        shared,
        request,
        QualificationCredentialBrokerObservationV1::CredentialLeaseAttempted {
            lease_sha256: lease_sha256.clone(),
            requested_scope_sha256: requested_scope_sha256.clone(),
            effective_scope_sha256: effective_scope_sha256.clone(),
        },
        deadline,
    )?;
    let credential = lease_provider_credential(
        request.provider_kind(),
        record.descriptor(),
        &binding,
        request.credential_scope(),
        &shared.credentials,
        deadline,
    )?;
    let mut capability = Zeroizing::new([0_u8; 32]);
    File::open("/dev/urandom")
        .map_err(string_error)?
        .read_exact(capability.as_mut())
        .map_err(string_error)?;
    if capability.iter().all(|byte| *byte == 0) {
        return Err("CredentialBroker generated an invalid lease capability".into());
    }
    append_credential_observation(
        shared,
        request,
        QualificationCredentialBrokerObservationV1::CredentialLeaseSucceeded {
            lease_sha256: lease_sha256.clone(),
            requested_scope_sha256: requested_scope_sha256.clone(),
            effective_scope_sha256: effective_scope_sha256.clone(),
        },
        deadline,
    )?;
    leases.insert(
        request.operation_id().to_owned(),
        CredentialBrokerLease {
            request: request.clone(),
            credential,
            lease_sha256,
            requested_scope_sha256,
            effective_scope_sha256,
            capability,
            attached: true,
            proxy_in_flight: false,
        },
    );
    let retained = leases
        .get(request.operation_id())
        .ok_or_else(|| "CredentialBroker lost the inserted lease".to_owned())?;
    let mut grant = Zeroizing::new(Vec::with_capacity(33));
    grant.push(1);
    grant.extend_from_slice(retained.capability.as_slice());
    Ok(Some(grant))
}

#[cfg(target_os = "linux")]
fn credential_broker_checkpoint(
    shared: &CredentialBrokerShared,
    expected_code: u8,
    deadline: Instant,
) -> Result<bool, String> {
    let mut checkpoint = shared
        .checkpoint
        .lock()
        .map_err(|_| "CredentialBroker checkpoint state is unavailable".to_owned())?;
    let checkpoint = checkpoint
        .as_mut()
        .ok_or_else(|| "CredentialBroker checkpoint controller is absent".to_owned())?;
    if checkpoint.code != expected_code {
        return Err("CredentialBroker reached a checkpoint outside the immutable phase".into());
    }
    checkpoint.peer.verify_unchanged()?;
    write_source_session_frame_before(&mut checkpoint.stream, &[expected_code], deadline)?;
    let response =
        read_source_session_frame_before(&mut checkpoint.stream, deadline)?.ok_or_else(|| {
            "CredentialBroker checkpoint controller returned no disposition".to_owned()
        })?;
    checkpoint.peer.verify_unchanged()?;
    match response.as_slice() {
        [SOURCE_CHECKPOINT_ABORT] => Ok(false),
        [SOURCE_CHECKPOINT_CLEAN] => Ok(true),
        _ => Err("CredentialBroker checkpoint disposition is malformed".into()),
    }
}

#[cfg(target_os = "linux")]
fn credential_broker_checkpoint_clean(
    shared: &CredentialBrokerShared,
    deadline: Instant,
) -> Result<(), String> {
    let mut checkpoint = shared
        .checkpoint
        .lock()
        .map_err(|_| "CredentialBroker checkpoint state is unavailable".to_owned())?;
    let mut checkpoint = checkpoint
        .take()
        .ok_or_else(|| "CredentialBroker checkpoint controller is absent".to_owned())?;
    checkpoint.peer.verify_unchanged()?;
    write_source_session_frame_before(
        &mut checkpoint.stream,
        &[SOURCE_CHECKPOINT_CLEAN],
        deadline,
    )?;
    checkpoint
        .stream
        .shutdown(Shutdown::Write)
        .map_err(string_error)?;
    if read_source_session_frame_before(&mut checkpoint.stream, deadline)?.is_some() {
        return Err("CredentialBroker checkpoint controller sent trailing data".into());
    }
    checkpoint.peer.verify_unchanged()
}

#[cfg(target_os = "linux")]
fn close_credential_lease(
    shared: &CredentialBrokerShared,
    request: &QualificationCredentialLeaseRequest,
    deadline: Instant,
) -> Result<(), String> {
    let lease = shared
        .leases
        .lock()
        .map_err(|_| "CredentialBroker lease state is unavailable".to_owned())?
        .remove(request.operation_id())
        .ok_or_else(|| "CredentialBroker close names no active lease".to_owned())?;
    if lease.request != *request || !lease.attached {
        return Err("CredentialBroker close differs from the active lease".into());
    }
    let CredentialBrokerLease {
        credential,
        lease_sha256,
        requested_scope_sha256,
        effective_scope_sha256,
        ..
    } = lease;
    drop(credential);
    append_credential_observation(
        shared,
        request,
        QualificationCredentialBrokerObservationV1::CredentialLeaseClosed {
            lease_sha256,
            requested_scope_sha256,
            effective_scope_sha256,
        },
        deadline,
    )
}

#[cfg(target_os = "linux")]
fn retry_credential_lease_close(
    shared: &CredentialBrokerShared,
    request: &QualificationCredentialLeaseRequest,
    deadline: Instant,
) -> Result<(), String> {
    let lease_sha256 = qualification_credential_lease_sha256(request)?;
    let scope_sha256 = hex::encode(Sha256::digest(request.credential_scope().as_bytes()));
    append_credential_observation_mode(
        shared,
        request,
        QualificationCredentialBrokerObservationV1::CredentialLeaseClosed {
            lease_sha256,
            requested_scope_sha256: scope_sha256.clone(),
            effective_scope_sha256: scope_sha256,
        },
        true,
        deadline,
    )
}

#[cfg(target_os = "linux")]
fn detach_credential_lease(
    shared: &CredentialBrokerShared,
    request: &QualificationCredentialLeaseRequest,
    deadline: Instant,
) -> Result<(), String> {
    let close_after_lease_crash =
        shared.phase.failpoint == Some(QualificationFailpoint::AfterLease);
    if close_after_lease_crash {
        return close_credential_lease(shared, request, deadline);
    }
    let mut leases = shared
        .leases
        .lock()
        .map_err(|_| "CredentialBroker lease state is unavailable".to_owned())?;
    let lease = leases
        .get_mut(request.operation_id())
        .ok_or_else(|| "CredentialBroker detach names no active lease".to_owned())?;
    if lease.request != *request || !lease.attached {
        return Err("CredentialBroker detach differs from the active lease".into());
    }
    lease.attached = false;
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn qualification_credential_lease_sha256(
    request: &QualificationCredentialLeaseRequest,
) -> Result<String, String> {
    request
        .lease_sha256()
        .map(hex::encode)
        .map_err(|()| "CredentialBroker canonical request is invalid".to_owned())
}

#[cfg(target_os = "linux")]
fn lease_provider_credential(
    provider: &str,
    descriptor: &[u8],
    binding: &auths_connections::ConnectionBinding,
    scope: &str,
    store: &PersistentCredentialStore,
    deadline: Instant,
) -> Result<ProviderCredentialLease, String> {
    let scope = CredentialScope::parse(scope).map_err(string_error)?;
    let result = match provider {
        "opentofu" => {
            let adapter = auths_opentofu::connection::adapter();
            let validated = adapter
                .validate_descriptor(descriptor)
                .map_err(string_error)?;
            adapter
                .permits_scope(&validated, &scope)
                .map_err(string_error)?;
            poll_immediate(adapter.lease_credential(binding, &scope, store, deadline))?
        }
        "postgresql" => {
            let adapter = auths_postgresql::connection::adapter();
            let validated = adapter
                .validate_descriptor(descriptor)
                .map_err(string_error)?;
            adapter
                .permits_scope(&validated, &scope)
                .map_err(string_error)?;
            poll_immediate(adapter.lease_credential(binding, &scope, store, deadline))?
        }
        "stripe" => {
            let adapter = auths_stripe::connection::adapter();
            let validated = adapter
                .validate_descriptor(descriptor)
                .map_err(string_error)?;
            adapter
                .permits_scope(&validated, &scope)
                .map_err(string_error)?;
            poll_immediate(adapter.lease_credential(binding, &scope, store, deadline))?
        }
        _ => return Err("CredentialBroker provider is not statically registered".into()),
    };
    result.map_err(string_error)
}

#[cfg(target_os = "linux")]
fn poll_immediate<F: std::future::Future>(future: F) -> Result<F::Output, String> {
    use std::{
        pin::pin,
        task::{Context, Poll, Waker},
    };
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => Ok(value),
        Poll::Pending => Err("CredentialBroker adapter requires an unaudited async driver".into()),
    }
}

#[cfg(target_os = "linux")]
fn append_credential_observation(
    shared: &CredentialBrokerShared,
    request: &QualificationCredentialLeaseRequest,
    observation: QualificationCredentialBrokerObservationV1,
    deadline: Instant,
) -> Result<(), String> {
    append_credential_observation_mode(shared, request, observation, false, deadline)
}

#[cfg(target_os = "linux")]
fn append_credential_observation_mode(
    shared: &CredentialBrokerShared,
    request: &QualificationCredentialLeaseRequest,
    observation: QualificationCredentialBrokerObservationV1,
    retry_only: bool,
    deadline: Instant,
) -> Result<(), String> {
    let mut record = QualificationCredentialBrokerRecordV1 {
        schema: "auths.qualification-credential-broker-record/1".into(),
        context: QualificationSourceEventContextV1 {
            sequence: 1,
            previous_event_sha256: "0".repeat(64),
            scenario_id: shared.phase.scenario_id.clone(),
            phase_index: shared.phase.phase_index,
            role: shared.phase.role,
            profile: shared.phase.profile.clone(),
            failpoint: shared.phase.failpoint,
            supervisor_generation: shared.supervisor_generation,
            operation_id: Some(request.operation_id().to_owned()),
            request_id: None,
            connection_generation: Some(request.connection_generation().to_string()),
        },
        observation,
    };
    let intent =
        hex::decode(record.intent_sha256().map_err(string_error)?).map_err(string_error)?;
    let appender = shared
        .appender
        .lock()
        .map_err(|_| "CredentialBroker appender is unavailable".to_owned())?;
    let signer_socket = appender.signer_socket.clone();
    let plan = appender.plan.clone();
    let trust = appender.trust.clone();
    let mut sign = move |sequence, previous_event_sha256| {
        record.context.sequence = sequence;
        record.context.previous_event_sha256 = previous_event_sha256;
        sign_one_fixed_source_record(
            QualificationEvidenceSource::CredentialBroker,
            &plan,
            &trust,
            &signer_socket,
            &record.to_json().map_err(string_error)?,
            deadline,
        )
    };
    if retry_only {
        appender.append.append(intent, true, deadline, &mut sign)?;
    } else {
        appender
            .append
            .resume_or_append(intent, deadline, &mut sign)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sign_one_fixed_source_record(
    source: QualificationEvidenceSource,
    plan: &QualificationEvidenceLedgerPlanV1,
    trust: &QualificationEvidenceSourceTrustRegistry,
    signer_socket: &Path,
    record: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let (_, _, signer_artifact, signer_uid) = trust
        .current_source_process_binding(
            source,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            signing_time_before(deadline, "CredentialBroker signer")?,
        )
        .map_err(string_error)?;
    let mut signer = connect_before(signer_socket, deadline, "CredentialBroker signer")?;
    signer.set_nonblocking(true).map_err(string_error)?;
    let peer = QualificationSourceSessionPeer::observe(&signer)?;
    if peer.uid() != signer_uid || peer.executable_sha256() != signer_artifact {
        return Err("CredentialBroker signer differs from protected source trust".into());
    }
    write_source_session_frame_before(&mut signer, record, deadline)?;
    signer.shutdown(Shutdown::Write).map_err(string_error)?;
    let signed = read_source_session_frame_before(&mut signer, deadline)?
        .ok_or_else(|| "CredentialBroker signer returned no event".to_owned())?;
    if read_source_session_frame_before(&mut signer, deadline)?.is_some() {
        return Err("CredentialBroker signer returned trailing data".into());
    }
    peer.verify_unchanged()?;
    Ok(signed)
}

#[cfg(target_os = "linux")]
fn decode_digest(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(string_error)?;
    bytes
        .try_into()
        .map_err(|_| "digest is not one SHA-256 value".to_owned())
}

#[cfg(target_os = "linux")]
fn run_receipt_verifier_reader(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values_for(
        arguments,
        "serve-reader-session",
        &[
            "--controller-socket",
            "--signer-socket",
            "--sequencer-socket",
            "--ledger-plan",
            "--source-trust",
            "--receipt-trust",
            "--scenario",
            "--phase-index",
        ],
        typed_source_usage,
    )?;
    reject_secret_environment()?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&read_bounded(
        Path::new(value_for(&values, "--ledger-plan", typed_source_usage)?),
        MAX_TRUST_BYTES,
        true,
    )?)
    .map_err(string_error)?;
    let trust = QualificationEvidenceSourceTrustRegistry::from_json(&read_bounded(
        Path::new(value_for(&values, "--source-trust", typed_source_usage)?),
        MAX_TRUST_BYTES,
        false,
    )?)
    .map_err(string_error)?;
    let receipt_trust_bytes = read_bounded(
        Path::new(value_for(&values, "--receipt-trust", typed_source_usage)?),
        MAX_TRUST_BYTES,
        false,
    )?;
    decode_receipt_trust_anchors(&receipt_trust_bytes).map_err(string_error)?;
    let scenario = value_for(&values, "--scenario", typed_source_usage)?;
    let phase_index = value_for(&values, "--phase-index", typed_source_usage)?
        .parse::<u8>()
        .map_err(string_error)?;
    let phase = plan
        .phases
        .iter()
        .find(|phase| phase.scenario_id == scenario && phase.phase_index == phase_index)
        .cloned()
        .ok_or_else(|| {
            "ReceiptVerifier phase is absent from the immutable ledger plan".to_owned()
        })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let remaining = plan
        .deadline_at_unix_seconds
        .checked_sub(now)
        .filter(|seconds| *seconds != 0)
        .ok_or_else(|| "ReceiptVerifier started outside the protected run interval".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(remaining);
    let reader_uid = rustix::process::geteuid().as_raw();
    let reader_artifact_sha256 = qualification_source_process_executable_sha256()?;
    if trust
        .fixed_source_for_reader_process(
            reader_uid,
            &reader_artifact_sha256,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?
        != QualificationEvidenceSource::ReceiptVerifier
    {
        return Err("ReceiptVerifier reader differs from protected source trust".into());
    }
    let controller_socket = Path::new(value_for(
        &values,
        "--controller-socket",
        typed_source_usage,
    )?);
    let socket_parent = validate_shared_reader_socket_path(controller_socket, &plan)?;
    let listener = UnixListener::bind(controller_socket).map_err(string_error)?;
    if validate_shared_reader_socket_path_after_bind(controller_socket, &plan)? != socket_parent {
        return Err("ReceiptVerifier socket parent changed while binding".into());
    }
    let _socket_guard = SocketPathGuard(controller_socket.to_owned());
    fs::set_permissions(controller_socket, fs::Permissions::from_mode(0o660))
        .map_err(string_error)?;
    listener.set_nonblocking(true).map_err(string_error)?;
    let (mut controller, _) = accept_before(&listener, deadline, "ReceiptVerifier controller")?;
    controller.set_nonblocking(true).map_err(string_error)?;
    let controller_peer = QualificationSourceSessionPeer::observe(&controller)?;
    if controller_peer.uid() != plan.supervisor_controller_uid
        || controller_peer.executable_sha256() != plan.supervisor_controller_artifact_sha256
    {
        return Err("ReceiptVerifier controller differs from the immutable ledger plan".into());
    }
    let (request, mut snapshot) =
        read_framed_request_and_snapshot_before(&mut controller, 64, deadline)?
            .ok_or_else(|| "ReceiptVerifier controller supplied no snapshot request".to_owned())?;
    if request != b"AUTHS-QUALIFICATION-RECEIPTS/1" {
        return Err("ReceiptVerifier snapshot request is invalid".into());
    }
    controller_peer.verify_unchanged()?;
    let records =
        read_persisted_operation_records_from_qualification_snapshot(&mut snapshot, plan.agent_uid)
            .map_err(string_error)?;
    let admitted_profiles = admitted_phase_profiles(&plan, &phase);
    if records.iter().any(|record| {
        !admitted_profiles.contains(
            format!(
                "{}/{}",
                record.binding().profile().id(),
                record.binding().profile().version()
            )
            .as_str(),
        )
    }) {
        return Err("ReceiptVerifier journal roster differs from the exact phase".into());
    }
    let records = records
        .into_iter()
        .filter(|record| {
            format!(
                "{}/{}",
                record.binding().profile().id(),
                record.binding().profile().version()
            ) == phase.profile
        })
        .collect::<Vec<_>>();
    let empty_phase = qualification_pre_admission_attempt_count(&phase.scenario_id).is_some();
    if records.len() > 8 || records.is_empty() && !empty_phase {
        return Err(
            "ReceiptVerifier current-phase journal roster is empty or exceeds the bound".into(),
        );
    }
    let mut appender = FixedSourceAppendSession::connect(
        QualificationEvidenceSource::ReceiptVerifier,
        plan.clone(),
        trust,
        Path::new(value_for(&values, "--signer-socket", typed_source_usage)?),
        PathBuf::from(value_for(
            &values,
            "--sequencer-socket",
            typed_source_usage,
        )?),
        deadline,
    )?;
    let mut operations = Vec::with_capacity(records.len());
    for record in records {
        let connection_generation = record
            .binding()
            .connection()
            .ok_or_else(|| "ReceiptVerifier operation has no connection binding".to_owned())?
            .generation()
            .to_string();
        let verified = verify_receipt_artifacts(&record, &receipt_trust_bytes)?;
        let inspection_sha256 = hex::encode(Sha256::digest(&verified.inspection_bytes));
        for receipt in &verified.receipts {
            let mut source_record = QualificationReceiptVerifierRecordV1 {
                schema: "auths.qualification-receipt-verifier-record/1".into(),
                context: QualificationSourceEventContextV1 {
                    sequence: 1,
                    previous_event_sha256: "0".repeat(64),
                    scenario_id: phase.scenario_id.clone(),
                    phase_index: phase.phase_index,
                    role: phase.role,
                    profile: phase.profile.clone(),
                    failpoint: phase.failpoint,
                    supervisor_generation: 1,
                    operation_id: Some(record.operation_id().as_str().to_owned()),
                    request_id: None,
                    connection_generation: Some(connection_generation.clone()),
                },
                receipt_id: receipt.receipt_id.clone(),
                receipt_bytes_sha256: hex::encode(Sha256::digest(&receipt.bytes)),
                decoded_claims_sha256: receipt.decoded_claims_sha256.clone(),
                profile_inspection_sha256: inspection_sha256.clone(),
            };
            let intent = hex::decode(source_record.intent_sha256().map_err(string_error)?)
                .map_err(string_error)?;
            appender.resume_or_append_record(
                intent,
                deadline,
                |sequence, previous_event_sha256| {
                    source_record.context.sequence = sequence;
                    source_record.context.previous_event_sha256 = previous_event_sha256;
                    source_record.to_json().map_err(string_error)
                },
            )?;
        }
        operations.push(QualificationReceiptVerifierOperationV1 {
            operation_id: record.operation_id().as_str().to_owned(),
            inspection_base64url: Base64UrlUnpadded::encode_string(&verified.inspection_bytes),
            receipts: verified
                .receipts
                .iter()
                .enumerate()
                .map(|(index, receipt)| QualificationReceiptVerifierArtifactV1 {
                    sequence: u8::try_from(index).unwrap_or(u8::MAX),
                    receipt_id: receipt.receipt_id.clone(),
                    bytes_base64url: Base64UrlUnpadded::encode_string(&receipt.bytes),
                })
                .collect(),
        });
    }
    let response = QualificationReceiptVerifierResponseV1 {
        schema: "auths.qualification-receipt-verifier-response/1".into(),
        operations,
    }
    .to_json()?;
    write_bounded_session_frame_before(&mut controller, &response, 67_108_864, deadline)?;
    let acknowledgement =
        read_source_session_frame_before(&mut controller, deadline)?.ok_or_else(|| {
            "ReceiptVerifier controller closed before acknowledging response".to_owned()
        })?;
    if acknowledgement != [1] {
        return Err(
            "ReceiptVerifier controller returned the wrong response acknowledgement".into(),
        );
    }
    if read_source_session_frame_before(&mut controller, deadline)?.is_some() {
        return Err("ReceiptVerifier controller sent data after its acknowledgement".into());
    }
    controller_peer.verify_unchanged()?;
    controller.shutdown(Shutdown::Write).map_err(string_error)
}

#[cfg(target_os = "linux")]
fn admitted_phase_profiles<'a>(
    plan: &'a QualificationEvidenceLedgerPlanV1,
    phase: &QualificationEvidencePhasePlanV1,
) -> BTreeSet<&'a str> {
    plan.phases
        .iter()
        .filter(|candidate| {
            candidate.scenario_id == phase.scenario_id && candidate.phase_index <= phase.phase_index
        })
        .map(|candidate| candidate.profile.as_str())
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn run_receipt_verifier_reader(_arguments: &[String]) -> Result<(), String> {
    Err("the protected ReceiptVerifier reader is supported only on Linux".into())
}

#[cfg(target_os = "linux")]
fn run_profile_state_reader(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values_for(
        arguments,
        "serve-reader-session",
        &[
            "--controller-socket",
            "--signer-socket",
            "--sequencer-socket",
            "--ledger-plan",
            "--source-trust",
            "--scenario",
            "--phase-index",
        ],
        typed_source_usage,
    )?;
    reject_secret_environment()?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&read_bounded(
        Path::new(value_for(&values, "--ledger-plan", typed_source_usage)?),
        MAX_TRUST_BYTES,
        true,
    )?)
    .map_err(string_error)?;
    let trust = QualificationEvidenceSourceTrustRegistry::from_json(&read_bounded(
        Path::new(value_for(&values, "--source-trust", typed_source_usage)?),
        MAX_TRUST_BYTES,
        false,
    )?)
    .map_err(string_error)?;
    let scenario = value_for(&values, "--scenario", typed_source_usage)?;
    let phase_index = value_for(&values, "--phase-index", typed_source_usage)?
        .parse::<u8>()
        .map_err(string_error)?;
    let phase = plan
        .phases
        .iter()
        .find(|phase| phase.scenario_id == scenario && phase.phase_index == phase_index)
        .cloned()
        .ok_or_else(|| "ProfileStateReader phase is absent from the ledger plan".to_owned())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let remaining = plan
        .deadline_at_unix_seconds
        .checked_sub(now)
        .filter(|seconds| *seconds != 0)
        .ok_or_else(|| "ProfileStateReader started outside the ledger interval".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(remaining);
    let reader_uid = rustix::process::geteuid().as_raw();
    let reader_artifact_sha256 = qualification_source_process_executable_sha256()?;
    if trust
        .fixed_source_for_reader_process(
            reader_uid,
            &reader_artifact_sha256,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?
        != QualificationEvidenceSource::ProfileStateReader
    {
        return Err("ProfileStateReader reader differs from source trust".into());
    }
    let controller_socket = Path::new(value_for(
        &values,
        "--controller-socket",
        typed_source_usage,
    )?);
    let socket_parent = validate_shared_reader_socket_path(controller_socket, &plan)?;
    let listener = UnixListener::bind(controller_socket).map_err(string_error)?;
    if validate_shared_reader_socket_path_after_bind(controller_socket, &plan)? != socket_parent {
        return Err("ProfileStateReader socket parent changed while binding".into());
    }
    let _socket_guard = SocketPathGuard(controller_socket.to_owned());
    fs::set_permissions(controller_socket, fs::Permissions::from_mode(0o660))
        .map_err(string_error)?;
    listener.set_nonblocking(true).map_err(string_error)?;
    let mut appender = FixedSourceAppendSession::connect(
        QualificationEvidenceSource::ProfileStateReader,
        plan.clone(),
        trust,
        Path::new(value_for(&values, "--signer-socket", typed_source_usage)?),
        PathBuf::from(value_for(
            &values,
            "--sequencer-socket",
            typed_source_usage,
        )?),
        deadline,
    )?;
    while Instant::now() < deadline {
        let (mut controller, _) =
            accept_before(&listener, deadline, "ProfileStateReader controller")?;
        controller.set_nonblocking(true).map_err(string_error)?;
        let controller_peer = QualificationSourceSessionPeer::observe(&controller)?;
        if controller_peer.uid() != plan.supervisor_controller_uid
            || controller_peer.executable_sha256() != plan.supervisor_controller_artifact_sha256
        {
            return Err("ProfileStateReader controller differs from the ledger plan".into());
        }
        loop {
            let Some((request, mut snapshots)) =
                read_framed_request_and_snapshots_before(&mut controller, 64, 2, deadline)?
            else {
                break;
            };
            let require_current_fact =
                request == b"AUTHS-QUALIFICATION-PROFILE-STATE-REQUIRE-CURRENT/1";
            let empty_phase = request == b"AUTHS-QUALIFICATION-PROFILE-STATE-EMPTY/1"
                && qualification_pre_admission_attempt_count(&phase.scenario_id).is_some();
            if request != b"AUTHS-QUALIFICATION-PROFILE-STATE/1"
                && !require_current_fact
                && !empty_phase
            {
                return Err("ProfileStateReader snapshot request is invalid".into());
            }
            controller_peer.verify_unchanged()?;
            let mut journal = snapshots.remove(0);
            let mut store = snapshots.remove(0);
            let records = read_persisted_operation_records_from_qualification_snapshot(
                &mut journal,
                plan.agent_uid,
            )
            .map_err(string_error)?;
            let admitted_profiles = admitted_phase_profiles(&plan, &phase);
            let record_bound = admitted_profiles
                .len()
                .checked_mul(8)
                .ok_or_else(|| "ProfileStateReader journal bound overflowed".to_owned())?;
            if records.len() > record_bound
                || records.is_empty() && !empty_phase
                || records.iter().any(|record| {
                    !admitted_profiles.contains(
                        format!(
                            "{}/{}",
                            record.binding().profile().id(),
                            record.binding().profile().version()
                        )
                        .as_str(),
                    )
                })
            {
                return Err(
                    "ProfileStateReader journal roster differs from the exact phase".into(),
                );
            }
            let facts = if empty_phase {
                let metadata = store.metadata().map_err(string_error)?;
                if !metadata.file_type().is_dir()
                    || metadata.uid() != plan.agent_uid
                    || metadata.mode() & 0o777 != 0o700
                    || records.iter().any(|record| {
                        format!(
                            "{}/{}",
                            record.binding().profile().id(),
                            record.binding().profile().version()
                        ) == phase.profile
                    })
                {
                    return Err(
                        "ProfileStateReader empty phase contains current durable state".into(),
                    );
                }
                Vec::new()
            } else {
                let store_bytes = read_profile_state_snapshot(&mut store, plan.agent_uid)?;
                inspect_profile_state(&phase.profile, &records, &store_bytes)?
            };
            if require_current_fact && facts.is_empty() {
                return Err(
                    "ProfileStateReader found no current-phase fact at the required checkpoint"
                        .into(),
                );
            }
            let mut unique = BTreeSet::new();
            if facts.len() > 16
                || facts.iter().any(|fact| {
                    !unique.insert((
                        fact.operation_id.clone(),
                        profile_state_observation_kind(&fact.observation),
                    ))
                })
            {
                return Err("ProfileStateReader fact roster is duplicated or oversized".into());
            }
            for fact in facts {
                let mut source_record = QualificationProfileStateRecordV1 {
                    schema: "auths.qualification-profile-state-record/1".into(),
                    context: QualificationSourceEventContextV1 {
                        sequence: 1,
                        previous_event_sha256: "0".repeat(64),
                        scenario_id: phase.scenario_id.clone(),
                        phase_index: phase.phase_index,
                        role: phase.role,
                        profile: phase.profile.clone(),
                        failpoint: phase.failpoint,
                        supervisor_generation: 1,
                        operation_id: Some(fact.operation_id),
                        request_id: None,
                        connection_generation: Some(fact.connection_generation.to_string()),
                    },
                    observation: fact.observation,
                };
                let intent = hex::decode(source_record.intent_sha256().map_err(string_error)?)
                    .map_err(string_error)?;
                appender.resume_or_append_record(
                    intent,
                    deadline,
                    |sequence, previous_event_sha256| {
                        source_record.context.sequence = sequence;
                        source_record.context.previous_event_sha256 = previous_event_sha256;
                        source_record.to_json().map_err(string_error)
                    },
                )?;
            }
            controller_peer.verify_unchanged()?;
            write_source_session_frame_before(&mut controller, &[1], deadline)?;
            let acknowledgement = read_source_session_frame_before(&mut controller, deadline)?
                .ok_or_else(|| {
                    "ProfileStateReader controller closed before acknowledging drain".to_owned()
                })?;
            if acknowledgement != [1] {
                return Err(
                    "ProfileStateReader controller returned the wrong acknowledgement".into(),
                );
            }
        }
        controller_peer.verify_unchanged()?;
        controller.shutdown(Shutdown::Write).map_err(string_error)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_profile_state_reader(_arguments: &[String]) -> Result<(), String> {
    Err("the protected ProfileStateReader is supported only on Linux".into())
}

#[cfg(target_os = "linux")]
fn read_runtime_read_credential() -> Result<Zeroizing<Vec<u8>>, String> {
    let mut encoded = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(131_073)
        .read_to_end(&mut encoded)
        .map_err(string_error)?;
    while encoded
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        encoded.pop();
    }
    if encoded.is_empty()
        || encoded.len() > 131_072
        || !encoded
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("ProviderObserver runtime-read credential is malformed".into());
    }
    let text = std::str::from_utf8(&encoded).map_err(string_error)?;
    let credential = Zeroizing::new(Base64UrlUnpadded::decode_vec(text).map_err(string_error)?);
    if credential.is_empty() || credential.len() > 98_304 {
        return Err("ProviderObserver runtime-read credential exceeds its bound".into());
    }
    Ok(credential)
}

#[cfg(target_os = "linux")]
fn run_provider_observer_reader(arguments: &[String]) -> Result<(), String> {
    reject_secret_environment()?;
    let credential = read_runtime_read_credential()?;
    run_provider_observer_reader_with_credential(arguments, &credential)
}

#[cfg(target_os = "linux")]
fn run_provider_observer_reader_with_credential(
    arguments: &[String],
    credential: &[u8],
) -> Result<(), String> {
    let values = exact_flag_values_for(
        arguments,
        "serve-reader-session",
        &[
            "--controller-socket",
            "--observer-root",
            "--signer-socket",
            "--sequencer-socket",
            "--ledger-plan",
            "--source-trust",
            "--scenario",
            "--phase-index",
        ],
        typed_source_usage,
    )?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&read_bounded(
        Path::new(value_for(&values, "--ledger-plan", typed_source_usage)?),
        MAX_TRUST_BYTES,
        true,
    )?)
    .map_err(string_error)?;
    let trust = QualificationEvidenceSourceTrustRegistry::from_json(&read_bounded(
        Path::new(value_for(&values, "--source-trust", typed_source_usage)?),
        MAX_TRUST_BYTES,
        false,
    )?)
    .map_err(string_error)?;
    let scenario = value_for(&values, "--scenario", typed_source_usage)?;
    let phase_index = value_for(&values, "--phase-index", typed_source_usage)?
        .parse::<u8>()
        .map_err(string_error)?;
    let phase = plan
        .phases
        .iter()
        .find(|phase| phase.scenario_id == scenario && phase.phase_index == phase_index)
        .cloned()
        .ok_or_else(|| "ProviderObserver phase is absent from the ledger plan".to_owned())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let remaining = plan
        .deadline_at_unix_seconds
        .checked_sub(now)
        .filter(|seconds| *seconds != 0)
        .ok_or_else(|| "ProviderObserver started outside the ledger interval".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(remaining);
    let reader_uid = rustix::process::geteuid().as_raw();
    let reader_artifact_sha256 = qualification_source_process_executable_sha256()?;
    if trust
        .fixed_source_for_reader_process(
            reader_uid,
            &reader_artifact_sha256,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?
        != QualificationEvidenceSource::ProviderObserver
    {
        return Err("ProviderObserver reader differs from source trust".into());
    }
    let observer_root = Path::new(value_for(&values, "--observer-root", typed_source_usage)?);
    let observer_directory = open_directory_componentwise(observer_root)?;
    let observer_metadata = observer_directory.metadata().map_err(string_error)?;
    if observer_metadata.uid() != reader_uid
        || observer_metadata.gid() != plan.agent_gid
        || observer_metadata.mode() & 0o777 != 0o700
    {
        return Err("ProviderObserver workspace differs from protected topology".into());
    }
    let controller_socket = Path::new(value_for(
        &values,
        "--controller-socket",
        typed_source_usage,
    )?);
    let socket_parent = validate_shared_reader_socket_path(controller_socket, &plan)?;
    let listener = UnixListener::bind(controller_socket).map_err(string_error)?;
    if validate_shared_reader_socket_path_after_bind(controller_socket, &plan)? != socket_parent {
        return Err("ProviderObserver socket parent changed while binding".into());
    }
    let _socket_guard = SocketPathGuard(controller_socket.to_owned());
    fs::set_permissions(controller_socket, fs::Permissions::from_mode(0o660))
        .map_err(string_error)?;
    listener.set_nonblocking(true).map_err(string_error)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(string_error)?;
    let mut appender = FixedSourceAppendSession::connect(
        QualificationEvidenceSource::ProviderObserver,
        plan.clone(),
        trust,
        Path::new(value_for(&values, "--signer-socket", typed_source_usage)?),
        PathBuf::from(value_for(
            &values,
            "--sequencer-socket",
            typed_source_usage,
        )?),
        deadline,
    )?;
    let mut retained_response: Option<([u8; 32], Vec<u8>)> = None;
    loop {
        let (mut controller, _) =
            accept_before(&listener, deadline, "ProviderObserver controller")?;
        controller.set_nonblocking(true).map_err(string_error)?;
        let controller_peer = QualificationSourceSessionPeer::observe(&controller)?;
        if controller_peer.uid() != plan.supervisor_controller_uid
            || controller_peer.executable_sha256() != plan.supervisor_controller_artifact_sha256
        {
            return Err("ProviderObserver controller differs from the ledger plan".into());
        }
        let Some((request, mut snapshot)) =
            read_framed_request_and_snapshot_before(&mut controller, 64, deadline)?
        else {
            return Err("ProviderObserver controller supplied no snapshot request".into());
        };
        if request != b"AUTHS-QUALIFICATION-PROVIDER-TRUTH/1" {
            return Err("ProviderObserver snapshot request is invalid".into());
        }
        controller_peer.verify_unchanged()?;
        let mut snapshot_bytes = Vec::new();
        snapshot
            .read_to_end(&mut snapshot_bytes)
            .map_err(string_error)?;
        if snapshot_bytes.is_empty() || snapshot_bytes.len() > 64 * 1_024 * 1_024 {
            return Err("ProviderObserver snapshot is outside its bound".into());
        }
        let snapshot_sha256: [u8; 32] = Sha256::digest(&snapshot_bytes).into();
        snapshot.seek(SeekFrom::Start(0)).map_err(string_error)?;
        if let Some((retained_snapshot_sha256, response)) = retained_response.as_ref() {
            if retained_snapshot_sha256 != &snapshot_sha256 {
                return Err("ProviderObserver retry changed the pinned snapshot".into());
            }
            controller_peer.verify_unchanged()?;
            if write_bounded_session_frame_before(
                &mut controller,
                response,
                16 * 1_024 * 1_024,
                deadline,
            )
            .is_err()
            {
                continue;
            }
            match read_source_session_frame_before(&mut controller, deadline) {
                Ok(Some(acknowledgement)) if acknowledgement == [1] => {}
                Ok(None) | Err(_) => continue,
                Ok(Some(_)) => {
                    return Err(
                        "ProviderObserver controller returned the wrong acknowledgement".into(),
                    );
                }
            }
            if read_source_session_frame_before(&mut controller, deadline)?.is_some() {
                return Err("ProviderObserver controller sent trailing data".into());
            }
            controller_peer.verify_unchanged()?;
            controller.shutdown(Shutdown::Write).map_err(string_error)?;
            return Ok(());
        }
        let records = read_persisted_operation_records_from_qualification_snapshot(
            &mut snapshot,
            plan.agent_uid,
        )
        .map_err(string_error)?;
        let admitted_profiles = admitted_phase_profiles(&plan, &phase);
        if records.iter().any(|record| {
            !admitted_profiles.contains(
                format!(
                    "{}/{}",
                    record.binding().profile().id(),
                    record.binding().profile().version()
                )
                .as_str(),
            )
        }) {
            return Err("ProviderObserver journal roster differs from the exact phase".into());
        }
        let mut records = records
            .into_iter()
            .filter(|record| {
                record.provider_entered()
                    && format!(
                        "{}/{}",
                        record.binding().profile().id(),
                        record.binding().profile().version()
                    ) == phase.profile
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.operation_id().cmp(right.operation_id()));
        if records.len() > 8 {
            return Err("ProviderObserver operation roster exceeds its bound".into());
        }
        let mut operations = Vec::with_capacity(records.len());
        for record in records {
            let (effect, facts) = block_on_protected_provider_operation(
                &runtime,
                deadline,
                observe_profile_provider_truth(
                    &phase.profile,
                    &record,
                    credential,
                    observer_root,
                    signing_time_before(deadline, "ProviderObserver provider read")?,
                ),
            )
            .map_err(|_| "protected provider observation exceeded the immutable deadline")??;
            if effect != qualification_effect(record.projection().effect()) {
                return Err("ProviderObserver effect differs from durable journal truth".into());
            }
            validate_profile_provider_truth(&phase.profile, &facts, effect)?;
            let provider_truth_sha256 = hex::encode(Sha256::digest(&facts));
            let connection_generation = record
                .binding()
                .connection()
                .ok_or_else(|| "ProviderObserver operation has no connection binding".to_owned())?
                .generation()
                .to_string();
            let mut source_record = QualificationProviderObserverRecordV1 {
                schema: "auths.qualification-provider-observer-record/1".into(),
                context: QualificationSourceEventContextV1 {
                    sequence: 1,
                    previous_event_sha256: "0".repeat(64),
                    scenario_id: phase.scenario_id.clone(),
                    phase_index: phase.phase_index,
                    role: phase.role,
                    profile: phase.profile.clone(),
                    failpoint: phase.failpoint,
                    supervisor_generation: 1,
                    operation_id: Some(record.operation_id().as_str().to_owned()),
                    request_id: None,
                    connection_generation: Some(connection_generation),
                },
                effect,
                provider_truth_sha256: provider_truth_sha256.clone(),
            };
            let intent = hex::decode(source_record.intent_sha256().map_err(string_error)?)
                .map_err(string_error)?;
            appender.resume_or_append_record(
                intent,
                deadline,
                |sequence, previous_event_sha256| {
                    source_record.context.sequence = sequence;
                    source_record.context.previous_event_sha256 = previous_event_sha256;
                    source_record.to_json().map_err(string_error)
                },
            )?;
            operations.push(QualificationProviderObserverOperationV1 {
                operation_id: record.operation_id().as_str().to_owned(),
                effect,
                provider_truth_sha256,
                domain_facts_base64url: Base64UrlUnpadded::encode_string(&facts),
            });
        }
        let response = QualificationProviderObserverResponseV1 {
            schema: "auths.qualification-provider-observer-response/1".into(),
            operations,
        }
        .to_json()?;
        retained_response = Some((snapshot_sha256, response));
        let response = &retained_response
            .as_ref()
            .ok_or_else(|| "ProviderObserver lost its retained response".to_owned())?
            .1;
        controller_peer.verify_unchanged()?;
        if write_bounded_session_frame_before(
            &mut controller,
            response,
            16 * 1_024 * 1_024,
            deadline,
        )
        .is_err()
        {
            continue;
        }
        match read_source_session_frame_before(&mut controller, deadline) {
            Ok(Some(acknowledgement)) if acknowledgement == [1] => {}
            Ok(None) | Err(_) => continue,
            Ok(Some(_)) => {
                return Err(
                    "ProviderObserver controller returned the wrong acknowledgement".into(),
                );
            }
        }
        if read_source_session_frame_before(&mut controller, deadline)?.is_some() {
            return Err("ProviderObserver controller sent trailing data".into());
        }
        controller_peer.verify_unchanged()?;
        controller.shutdown(Shutdown::Write).map_err(string_error)?;
        return Ok(());
    }
}

#[cfg(target_os = "linux")]
async fn observe_profile_provider_truth(
    profile: &str,
    record: &JournalRecordV1,
    credential: &[u8],
    observer_root: &Path,
    now_unix_seconds: u64,
) -> Result<(QualificationEffect, Vec<u8>), String> {
    let result = QualificationRoute::for_profile(profile)?
        .observe_provider_truth(record, credential, observer_root, now_unix_seconds)
        .await;
    result.map_err(|error| format!("protected provider observation failed: {error:?}"))
}

#[cfg(target_os = "linux")]
fn validate_profile_provider_truth(
    profile: &str,
    facts: &[u8],
    effect: QualificationEffect,
) -> Result<(), String> {
    let result = QualificationRoute::for_profile(profile)?.validate_provider_truth(facts, effect);
    result.map_err(|error| format!("provider truth facts are invalid: {error:?}"))
}

#[cfg(not(target_os = "linux"))]
fn run_provider_observer_reader(_arguments: &[String]) -> Result<(), String> {
    Err("the protected ProviderObserver reader is supported only on Linux".into())
}

#[cfg(target_os = "linux")]
fn inspect_profile_state(
    profile: &str,
    records: &[JournalRecordV1],
    store_bytes: &[u8],
) -> Result<Vec<QualificationProfileStateFactV1>, String> {
    let result = QualificationRoute::for_profile(profile)?.inspect_profile_state(
        profile,
        records,
        store_bytes,
    );
    result.map_err(|error| format!("profile-state inspection failed: {error:?}"))
}

/// Returns the fixed protected-state snapshot path for one reviewed profile.
#[cfg(target_os = "linux")]
#[must_use]
pub fn qualification_profile_state_snapshot_path(profile: &str) -> Option<&'static str> {
    QualificationRoute::for_profile(profile)
        .ok()
        .map(QualificationRoute::profile_state_snapshot_path)
}

#[cfg(target_os = "linux")]
fn read_profile_state_snapshot(file: &mut File, owner_uid: u32) -> Result<Vec<u8>, String> {
    const MAXIMUM: usize = 64 * 1024 * 1024;
    let access = rustix::fs::fcntl_getfl(&*file).map_err(string_error)?;
    let metadata = file.metadata().map_err(string_error)?;
    if access & OFlags::ACCMODE != OFlags::RDONLY
        || !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > MAXIMUM as u64
    {
        return Err("profile-state snapshot file identity is invalid".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(string_error)?);
    file.take((MAXIMUM + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    if bytes.is_empty() || bytes.len() > MAXIMUM {
        return Err("profile-state snapshot exceeds its bound".into());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
const fn profile_state_observation_kind(value: &QualificationProfileStateObservationV1) -> u8 {
    match value {
        QualificationProfileStateObservationV1::ReservationDurable { .. } => 0,
        QualificationProfileStateObservationV1::ReservationReleased { .. } => 1,
        QualificationProfileStateObservationV1::ReservationConsumed { .. } => 2,
        QualificationProfileStateObservationV1::ReservationRetained { .. } => 3,
    }
}

#[cfg(target_os = "linux")]
fn run_typed_source(
    source: QualificationEvidenceSource,
    arguments: &[String],
) -> Result<(), String> {
    if matches!(
        source,
        QualificationEvidenceSource::Supervisor | QualificationEvidenceSource::JournalReader
    ) {
        return Err("typed source dispatcher cannot assume a supervisor-owned role".into());
    }
    let usage = typed_source_usage;
    let command = arguments
        .first()
        .map(String::as_str)
        .filter(|command| *command == "serve-session")
        .ok_or_else(usage)?;
    let values = exact_flag_values_for(
        arguments,
        command,
        &["--socket", "--source-trust", "--ledger-plan"],
        usage,
    )?;
    reject_secret_environment()?;
    let trust_bytes = read_bounded(
        Path::new(value_for(&values, "--source-trust", usage)?),
        MAX_TRUST_BYTES,
        false,
    )?;
    let trust =
        QualificationEvidenceSourceTrustRegistry::from_json(&trust_bytes).map_err(string_error)?;
    let plan_bytes = read_bounded(
        Path::new(value_for(&values, "--ledger-plan", usage)?),
        MAX_TRUST_BYTES,
        true,
    )?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&plan_bytes).map_err(string_error)?;
    let source_context_sha256 = plan.source_context_sha256().map_err(string_error)?;
    let domain = plan.domain.as_str();
    let started_at = plan.started_at_unix_seconds;
    let completed_at = plan.deadline_at_unix_seconds;
    let signer_uid = rustix::process::geteuid().as_raw();
    if started_at >= completed_at {
        return Err("typed source identity or key interval is malformed".into());
    }
    let signer_executable_sha256 =
        hash_peer_executable(i32::try_from(std::process::id()).map_err(string_error)?)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let (
        key_id,
        source_identity,
        expected_signer_uid,
        reader_identity,
        expected_reader_sha256,
        expected_reader_uid,
    ) = trust
        .fixed_source_process_binding(
            source,
            &signer_executable_sha256,
            domain,
            started_at,
            completed_at,
            now,
        )
        .map_err(string_error)?;
    if signer_uid != expected_signer_uid {
        return Err("typed source signer used the wrong protected OS identity".into());
    }
    let process = QualificationSourceProcessBindingV1 {
        source_identity: source_identity.to_owned(),
        source_artifact_sha256: signer_executable_sha256,
        source_uid: signer_uid,
        reader_identity: reader_identity.to_owned(),
        reader_artifact_sha256: expected_reader_sha256.to_owned(),
        reader_uid: expected_reader_uid,
    };

    let socket = Path::new(value_for(&values, "--socket", usage)?);
    validate_private_socket_path(socket)?;
    let listener = UnixListener::bind(socket).map_err(string_error)?;
    let _socket_guard = SocketPathGuard(socket.to_owned());
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660)).map_err(string_error)?;
    File::open(
        socket
            .parent()
            .ok_or_else(|| "typed source socket has no parent".to_owned())?,
    )
    .map_err(string_error)?
    .sync_all()
    .map_err(string_error)?;
    listener.set_nonblocking(true).map_err(string_error)?;
    let remaining = completed_at
        .checked_sub(now)
        .filter(|seconds| *seconds != 0)
        .ok_or_else(|| "typed source session started outside the protected interval".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(remaining);
    let mut seed = None;
    let mut messages = 0_u16;
    loop {
        let (mut stream, _) = loop {
            if Instant::now() >= deadline {
                return if messages == 0 || seed.is_none() {
                    Err("typed source session received no validated reader record".into())
                } else {
                    Ok(())
                };
            }
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(string_error(error)),
            }
        };
        stream.set_nonblocking(true).map_err(string_error)?;
        let peer = rustix::net::sockopt::socket_peercred(&stream).map_err(string_error)?;
        if peer.uid.as_raw() != process.reader_uid {
            return Err("typed source reader used the wrong protected OS identity".into());
        }
        let peer_pid = peer.pid.as_raw_pid();
        let peer_start_time = process_start_time_ticks(peer_pid)?;
        let peer_executable_sha256 = hash_peer_executable(peer_pid)?;
        if peer_executable_sha256 != process.reader_artifact_sha256 {
            return Err("typed source reader executable differs from protected policy".into());
        }
        let mut session_messages = 0_u16;
        let mut row_complete = false;
        while let Some(record_bytes) = read_source_session_frame_before(&mut stream, deadline)? {
            if record_bytes == TYPED_SOURCE_ROW_COMPLETE {
                if session_messages != 0 || row_complete {
                    return Err("typed source row-complete request was not isolated".into());
                }
                row_complete = true;
                continue;
            }
            if row_complete {
                return Err("typed source received data after row-complete request".into());
            }
            session_messages = session_messages
                .checked_add(1)
                .filter(|value| *value <= MAX_TYPED_SOURCE_SESSION_EVENTS)
                .ok_or_else(|| {
                    "typed source reader connection exceeds its event bound".to_owned()
                })?;
            messages = messages
                .checked_add(1)
                .filter(|value| *value <= MAX_TYPED_SOURCE_SESSION_EVENTS)
                .ok_or_else(|| "typed source session exceeds its event bound".to_owned())?;
            let event = validate_typed_reader_event(
                source,
                &record_bytes,
                &process,
                &source_context_sha256,
                key_id,
                &plan,
                &trust,
                signing_time_before(deadline, "typed source session")?,
            )?;
            verify_peer_unchanged(peer_pid, peer_start_time, &peer_executable_sha256)?;
            if seed.is_none() {
                seed = Some(read_seed_from_stdin_before(deadline)?);
            }
            let signed = sign_typed_reader_event(
                event,
                source,
                &source_context_sha256,
                seed.as_ref()
                    .ok_or_else(|| "typed source session seed is absent".to_owned())?,
                &trust,
                &plan,
                deadline,
            )?;
            write_source_session_frame_before(&mut stream, &signed, deadline)?;
        }
        if row_complete {
            verify_peer_unchanged(peer_pid, peer_start_time, &peer_executable_sha256)?;
            write_source_session_frame_before(
                &mut stream,
                TYPED_SOURCE_ROW_COMPLETE_ACK,
                deadline,
            )?;
            stream.shutdown(Shutdown::Write).map_err(string_error)?;
            return Ok(());
        }
        if session_messages == 0 {
            return Err("typed source reader connection carried no validated record".into());
        }
        verify_peer_unchanged(peer_pid, peer_start_time, &peer_executable_sha256)?;
        stream.shutdown(Shutdown::Write).map_err(string_error)?;
    }
}

#[cfg(target_os = "linux")]
pub struct QualificationSourceAppendSession {
    source: QualificationEvidenceSource,
    plan: QualificationEvidenceLedgerPlanV1,
    trust: QualificationEvidenceSourceTrustRegistry,
    sequencer_socket: PathBuf,
}

#[cfg(target_os = "linux")]
struct FixedSourceAppendSession {
    append: QualificationSourceAppendSession,
    signer: UnixStream,
    signer_peer: QualificationSourceSessionPeer,
}

#[cfg(target_os = "linux")]
impl QualificationSourceAppendSession {
    /// Creates one client for the single protected append sequencer. The
    /// sequencer independently authenticates this process and chooses its
    /// source role from protected policy before reserving an ordering slot.
    #[must_use]
    pub fn new(
        source: QualificationEvidenceSource,
        plan: QualificationEvidenceLedgerPlanV1,
        trust: QualificationEvidenceSourceTrustRegistry,
        sequencer_socket: PathBuf,
    ) -> Self {
        Self {
            source,
            plan,
            trust,
            sequencer_socket,
        }
    }

    /// Signs and durably appends one semantic event under the sequencer's
    /// locked global position. Explicit retries are read-only and return the
    /// exact retained event rather than creating a duplicate.
    pub fn append(
        &self,
        intent: Vec<u8>,
        retry: bool,
        deadline: Instant,
        mut sign_event: impl FnMut(u32, String) -> Result<Vec<u8>, String>,
    ) -> Result<(QualificationEvidenceEvent, Vec<u8>), String> {
        self.append_transaction(intent, retry, deadline, &mut sign_event)?
            .ok_or_else(|| "explicit append retry has no retained matching event".to_owned())
    }

    /// Resumes an exact retained intent when present, or appends it once when
    /// absent. ReceiptVerifier uses this for deterministic multi-event rosters
    /// so a reader restart after any durable prefix cannot duplicate evidence.
    pub fn resume_or_append(
        &self,
        intent: Vec<u8>,
        deadline: Instant,
        mut sign_event: impl FnMut(u32, String) -> Result<Vec<u8>, String>,
    ) -> Result<(QualificationEvidenceEvent, Vec<u8>), String> {
        if let Some(retained) =
            self.append_transaction(intent.clone(), true, deadline, &mut sign_event)?
        {
            return Ok(retained);
        }
        self.append_transaction(intent, false, deadline, &mut sign_event)?
            .ok_or_else(|| "new append transaction returned no event".to_owned())
    }

    fn append_transaction(
        &self,
        intent: Vec<u8>,
        retry: bool,
        deadline: Instant,
        sign_event: &mut impl FnMut(u32, String) -> Result<Vec<u8>, String>,
    ) -> Result<Option<(QualificationEvidenceEvent, Vec<u8>)>, String> {
        if intent.len() != 32 {
            return Err("append intent is not one SHA-256 digest".into());
        }
        let mut retrying = retry;
        let mut retained_signed = None::<Vec<u8>>;
        loop {
            if Instant::now() >= deadline {
                return Err("append transaction exceeded its total deadline".into());
            }
            let mut sequencer =
                match connect_before(&self.sequencer_socket, deadline, "append sequencer") {
                    Ok(sequencer) => sequencer,
                    Err(error) if retrying => {
                        thread::sleep(Duration::from_millis(10));
                        let _ = error;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
            let sequencer_peer = match QualificationSourceSessionPeer::observe(&sequencer) {
                Ok(peer) => peer,
                Err(error) if retrying => {
                    thread::sleep(Duration::from_millis(10));
                    let _ = error;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if sequencer_peer.uid() != self.plan.supervisor_controller_uid
                || sequencer_peer.executable_sha256() != self.plan.ledger_appender_artifact_sha256
            {
                return Err("append sequencer differs from the immutable ledger plan".into());
            }
            let mut transaction = Vec::with_capacity(33);
            transaction.push(u8::from(retrying));
            transaction.extend_from_slice(&intent);
            if let Err(error) =
                write_source_session_frame_before(&mut sequencer, &transaction, deadline)
            {
                if retrying {
                    thread::sleep(Duration::from_millis(10));
                    let _ = error;
                    continue;
                }
                return Err(error);
            }
            let ordering = match read_source_session_frame_before(&mut sequencer, deadline) {
                Ok(Some(ordering)) => ordering,
                Err(_) if retrying => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Ok(None) if retrying && retained_signed.is_some() => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Ok(None) if retrying => {
                    return Ok(None);
                }
                Ok(None) => {
                    return Err("append sequencer closed before returning ordering".into());
                }
                Err(error) => return Err(error),
            };
            if ordering.len() != 36 {
                return Err("append sequencer returned a malformed ordering prefix".into());
            }
            let sequence = u32::from_be_bytes(
                ordering[..4]
                    .try_into()
                    .map_err(|_| "append sequence is malformed".to_owned())?,
            );
            let previous_event_sha256 = hex::encode(&ordering[4..]);
            sequencer_peer.verify_unchanged()?;

            let signed = if retrying {
                if sequencer.shutdown(Shutdown::Write).is_err() {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                match read_source_session_frame_before(&mut sequencer, deadline) {
                    Ok(Some(signed)) => signed,
                    Ok(None) | Err(_) => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                }
            } else {
                let signed = sign_event(sequence, previous_event_sha256.clone())?;
                retained_signed = Some(signed.clone());
                if write_source_session_frame_before(&mut sequencer, &signed, deadline).is_err() {
                    retained_signed = None;
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                if sequencer.shutdown(Shutdown::Write).is_err() {
                    retrying = true;
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                signed
            };
            if retained_signed
                .as_ref()
                .is_some_and(|retained| retained != &signed)
            {
                return Err("append retry returned different signed event bytes".into());
            }
            let event = QualificationEvidenceEvent::verify_json(
                &signed,
                self.source,
                &self.plan.source_context_sha256().map_err(string_error)?,
                &self.trust,
                &self.plan.domain,
                self.plan.started_at_unix_seconds,
                self.plan.deadline_at_unix_seconds,
                signing_time_before(deadline, "source event append")?,
            )
            .map_err(string_error)?;
            if event.sequence != sequence
                || event.previous_event_sha256 != previous_event_sha256
                || hex::decode(event.intent_sha256().map_err(string_error)?)
                    .map_err(string_error)?
                    != intent
            {
                return Err("source signer changed the reader-owned event".into());
            }
            let acknowledgement = match read_source_session_frame_before(&mut sequencer, deadline) {
                Ok(Some(acknowledgement)) => acknowledgement,
                Ok(None) | Err(_) => {
                    retrying = true;
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };
            let expected = hex::decode(qualification_event_marker_sha256(
                event.sequence,
                self.source,
            ))
            .map_err(string_error)?;
            if acknowledgement != expected {
                return Err("append sequencer returned the wrong durable acknowledgement".into());
            }
            match read_source_session_frame_before(&mut sequencer, deadline) {
                Ok(None) => {}
                Ok(Some(_)) => {
                    return Err(
                        "append sequencer returned data after its durable acknowledgement".into(),
                    );
                }
                Err(_) => {
                    retrying = true;
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            }
            if sequencer_peer.verify_unchanged().is_err() {
                retrying = true;
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Ok(Some((event, signed)));
        }
    }
}

#[cfg(target_os = "linux")]
impl FixedSourceAppendSession {
    fn connect(
        source: QualificationEvidenceSource,
        plan: QualificationEvidenceLedgerPlanV1,
        trust: QualificationEvidenceSourceTrustRegistry,
        signer_socket: &Path,
        sequencer_socket: PathBuf,
        deadline: Instant,
    ) -> Result<Self, String> {
        let reader_uid = rustix::process::geteuid().as_raw();
        let reader_artifact = qualification_source_process_executable_sha256()?;
        if trust
            .fixed_source_for_reader_process(
                reader_uid,
                &reader_artifact,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                signing_time_before(deadline, "fixed source reader")?,
            )
            .map_err(string_error)?
            != source
        {
            return Err("fixed source reader differs from protected source trust".into());
        }
        let (_, _, signer_artifact, signer_uid) = trust
            .current_source_process_binding(
                source,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                signing_time_before(deadline, "fixed source signer")?,
            )
            .map_err(string_error)?;
        let signer = connect_before(signer_socket, deadline, "fixed source signer")?;
        let signer_peer = QualificationSourceSessionPeer::observe(&signer)?;
        if signer_peer.uid() != signer_uid || signer_peer.executable_sha256() != signer_artifact {
            return Err("fixed source signer differs from protected source trust".into());
        }
        Ok(Self {
            append: QualificationSourceAppendSession::new(source, plan, trust, sequencer_socket),
            signer,
            signer_peer,
        })
    }

    fn append_record(
        &mut self,
        intent: Vec<u8>,
        retry: bool,
        deadline: Instant,
        mut record_for_ordering: impl FnMut(u32, String) -> Result<Vec<u8>, String>,
    ) -> Result<QualificationEvidenceEvent, String> {
        let signer = &mut self.signer;
        let signer_peer = &self.signer_peer;
        self.append
            .append(
                intent,
                retry,
                deadline,
                move |sequence, previous_event_sha256| {
                    let record_bytes = record_for_ordering(sequence, previous_event_sha256)?;
                    write_source_session_frame_before(signer, &record_bytes, deadline)?;
                    let signed =
                        read_source_session_frame_before(signer, deadline)?.ok_or_else(|| {
                            "fixed source signer closed before returning an event".to_owned()
                        })?;
                    signer_peer.verify_unchanged()?;
                    Ok(signed)
                },
            )
            .map(|(event, _)| event)
    }

    fn resume_or_append_record(
        &mut self,
        intent: Vec<u8>,
        deadline: Instant,
        mut record_for_ordering: impl FnMut(u32, String) -> Result<Vec<u8>, String>,
    ) -> Result<QualificationEvidenceEvent, String> {
        let signer = &mut self.signer;
        let signer_peer = &self.signer_peer;
        self.append
            .resume_or_append(intent, deadline, move |sequence, previous_event_sha256| {
                let record_bytes = record_for_ordering(sequence, previous_event_sha256)?;
                write_source_session_frame_before(signer, &record_bytes, deadline)?;
                let signed =
                    read_source_session_frame_before(signer, deadline)?.ok_or_else(|| {
                        "fixed source signer closed before returning an event".to_owned()
                    })?;
                signer_peer.verify_unchanged()?;
                Ok(signed)
            })
            .map(|(event, _)| event)
    }

    fn append_client_proxy(
        &mut self,
        mut record: QualificationClientProxyRecordV1,
        retry: bool,
        deadline: Instant,
    ) -> Result<QualificationEvidenceEvent, String> {
        let intent =
            hex::decode(record.intent_sha256().map_err(string_error)?).map_err(string_error)?;
        self.append_record(
            intent,
            retry,
            deadline,
            move |sequence, previous_event_sha256| {
                record.context.sequence = sequence;
                record.context.previous_event_sha256 = previous_event_sha256;
                record.to_json().map_err(string_error)
            },
        )
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientProcessIdentity {
    uid: u32,
    gid: u32,
    pid: u32,
    start_time_ticks: u64,
    executable_sha256: String,
}

#[cfg(target_os = "linux")]
impl ClientProcessIdentity {
    fn from_peer(peer: &QualificationSourceSessionPeer) -> Result<Self, String> {
        Ok(Self {
            uid: peer.uid(),
            gid: peer.gid(),
            pid: u32::try_from(peer.pid()).map_err(string_error)?,
            start_time_ticks: peer.start_time_ticks(),
            executable_sha256: peer.executable_sha256().to_owned(),
        })
    }

    fn bridge_binding(
        &self,
        source_context_sha256: String,
        fault: Option<QualificationAdmissionFaultV1>,
    ) -> QualificationClientBridgeBindingV1 {
        QualificationClientBridgeBindingV1 {
            schema: "auths.qualification-client-bridge-binding/1".into(),
            source_context_sha256,
            client_uid: self.uid,
            client_gid: self.gid,
            client_process_id: self.pid,
            client_start_time_ticks: self.start_time_ticks,
            client_executable_sha256: self.executable_sha256.clone(),
            fault,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct ClientSessionState {
    principal: String,
    principal_sha256: String,
    process: ClientProcessIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct ClientAttemptState {
    sequence: u16,
    process: ClientProcessIdentity,
    principal_sha256: String,
    idempotency_sha256: Option<String>,
    preparation_input_sha256: Option<String>,
    recovery_request_sha256: Option<String>,
    transports_in_flight: u16,
    tail: ClientTransportTail,
    journal_projection_kinds: Vec<QualificationEvidenceEventKind>,
    projected_outcome: Option<ClientOutcomeProjection>,
    last_result: Option<ClientResultCommitment>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
enum ClientTransportTail {
    Intermediate,
    ResponseProjected(String),
    DeliveryFailed,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientResultKind {
    ResponseProjected,
    CancellationObserved,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientResultCommitment {
    kind: ClientResultKind,
    result_sha256: String,
    outcome: ClientOutcomeProjection,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientOutcomeProjection {
    operation_id: Option<String>,
    outcome: QualificationOutcomeKind,
    completion: Option<QualificationCompletion>,
    recovery_id: Option<String>,
    error_code: Option<String>,
    issue_metadata_sha256: Option<String>,
    receipt_ids: Vec<String>,
}

#[cfg(target_os = "linux")]
struct InFlightPermit(Arc<AtomicUsize>);

#[cfg(target_os = "linux")]
impl Drop for InFlightPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(target_os = "linux")]
struct ClientProxyState {
    sessions: BTreeMap<String, ClientSessionState>,
    attempts: BTreeMap<String, ClientAttemptState>,
    operations: BTreeMap<String, String>,
}

#[cfg(target_os = "linux")]
struct ClientProxyShared {
    plan: QualificationEvidenceLedgerPlanV1,
    phase: auths_profile_kit::QualificationEvidencePhasePlanV1,
    supervisor_generation: u32,
    agent_socket: PathBuf,
    appender: Mutex<FixedSourceAppendSession>,
    state: Mutex<ClientProxyState>,
    in_flight: Arc<AtomicUsize>,
}

#[cfg(target_os = "linux")]
struct ClientTransportGuard<'a> {
    shared: &'a ClientProxyShared,
    request_id: String,
    expected_operation_id: Option<String>,
    projection_route: Option<ClientProjectionRoute>,
    finished: bool,
}

#[cfg(target_os = "linux")]
struct ClientExchangeBinding {
    request_id: String,
    expected_operation_id: Option<String>,
    projection_route: Option<ClientProjectionRoute>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientProjectionRoute {
    ReplayCandidate,
    Status,
    Recovery,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
enum ClientOperationAction {
    Execute,
    Recover,
    Status,
    Receipts,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
enum ClientRoute<'a> {
    Session,
    SessionClose,
    PreparationEvidence,
    Prepare,
    CommonRecover,
    Pending,
    Operation {
        operation_id: &'a str,
        action: ClientOperationAction,
    },
}

#[cfg(target_os = "linux")]
impl ClientTransportGuard<'_> {
    fn finish(
        mut self,
        delivered: bool,
        outcome: Option<&auths_production_client::LocalOperationOutcome>,
    ) -> Result<(), String> {
        let mut state = self.shared.state.lock().map_err(string_error)?;
        let attempt = state
            .attempts
            .get(&self.request_id)
            .ok_or_else(|| "ClientProxy transport lost its observed request".to_owned())?;
        let transports_in_flight = attempt
            .transports_in_flight
            .checked_sub(1)
            .ok_or_else(|| "ClientProxy transport state underflowed".to_owned())?;
        let projected_result_sha256 = outcome
            .and_then(|outcome| outcome.projected_result())
            .map(|result| hex::encode(Sha256::digest(result)));
        let projected_outcome = outcome
            .map(client_outcome_projection)
            .transpose()?
            .flatten();
        let journal_projection_kind = match (self.projection_route, outcome) {
            (Some(ClientProjectionRoute::ReplayCandidate), Some(outcome))
                if outcome.completion() == Some(LocalOperationCompletion::Replayed) =>
            {
                Some(QualificationEvidenceEventKind::ReplayObserved)
            }
            (Some(ClientProjectionRoute::Status), Some(_)) => {
                Some(QualificationEvidenceEventKind::StatusObserved)
            }
            (Some(ClientProjectionRoute::Recovery), Some(_)) => {
                Some(QualificationEvidenceEventKind::RecoveryObserved)
            }
            _ => None,
        };
        let operation_id = outcome
            .and_then(|outcome| outcome.operation_id())
            .map(|operation| operation.as_str().to_owned());
        if let Some(operation_id) = operation_id.as_deref() {
            if state.operations.len() >= 1_024 && !state.operations.contains_key(operation_id) {
                return Err("ClientProxy operation state exceeds its hard bound".into());
            }
        }
        let attempt = state
            .attempts
            .get_mut(&self.request_id)
            .expect("the observed attempt was retained while its lock was held");
        attempt.transports_in_flight = transports_in_flight;
        if let Some(kind) = journal_projection_kind {
            if attempt.journal_projection_kinds.len() >= 64 {
                return Err("ClientProxy journal projection roster exceeds its hard bound".into());
            }
            attempt.journal_projection_kinds.push(kind);
        }
        attempt.tail = match (delivered, projected_result_sha256) {
            (true, Some(result_sha256)) => ClientTransportTail::ResponseProjected(result_sha256),
            (true, None) => ClientTransportTail::Intermediate,
            (false, _) => ClientTransportTail::DeliveryFailed,
        };
        if let Some(projected_outcome) = projected_outcome {
            attempt.projected_outcome = Some(projected_outcome);
        }
        if let Some(operation_id) = operation_id {
            state
                .operations
                .entry(operation_id)
                .or_insert_with(|| self.request_id.clone());
        }
        self.finished = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn client_outcome_projection(
    outcome: &auths_production_client::LocalOperationOutcome,
) -> Result<Option<ClientOutcomeProjection>, String> {
    use auths_production_client::LocalOperationOutcome as Outcome;

    let completion = |value| match value {
        LocalOperationCompletion::Fresh => QualificationCompletion::Fresh,
        LocalOperationCompletion::Replayed => QualificationCompletion::Replayed,
        LocalOperationCompletion::Reconciled => QualificationCompletion::Reconciled,
    };
    let receipts = |values: &[Vec<u8>]| {
        values
            .iter()
            .map(|value| portable_receipt_id(value).map_err(string_error))
            .collect::<Result<Vec<_>, _>>()
    };
    let issue = |bytes: &[u8]| {
        let envelope = ErrorEnvelope::from_canonical_cbor(bytes)
            .map_err(|_| "ClientProxy received a malformed canonical error envelope".to_owned())?;
        Ok::<_, String>((envelope.code, hex::encode(Sha256::digest(bytes))))
    };
    let projected = match outcome {
        Outcome::Ready { .. } | Outcome::InProgress { .. } => return Ok(None),
        Outcome::Denied {
            operation_id,
            issue: bytes,
            decision_receipt,
            ..
        } => {
            let (error_code, issue_metadata_sha256) = issue(bytes)?;
            ClientOutcomeProjection {
                operation_id: Some(operation_id.as_str().to_owned()),
                outcome: QualificationOutcomeKind::Denied,
                completion: None,
                recovery_id: None,
                error_code: Some(error_code),
                issue_metadata_sha256: Some(issue_metadata_sha256),
                receipt_ids: receipts(core::slice::from_ref(decision_receipt))?,
            }
        }
        Outcome::Unavailable {
            operation_id,
            issue: bytes,
            receipts: values,
            ..
        } => {
            let (error_code, issue_metadata_sha256) = issue(bytes)?;
            ClientOutcomeProjection {
                operation_id: operation_id
                    .as_ref()
                    .map(|operation| operation.as_str().to_owned()),
                outcome: QualificationOutcomeKind::Unavailable,
                completion: None,
                recovery_id: None,
                error_code: Some(error_code),
                issue_metadata_sha256: Some(issue_metadata_sha256),
                receipt_ids: receipts(values)?,
            }
        }
        Outcome::Conflict {
            operation_id,
            issue: bytes,
            receipts: values,
            ..
        } => {
            let (error_code, issue_metadata_sha256) = issue(bytes)?;
            let operation_id = operation_id.as_str().to_owned();
            ClientOutcomeProjection {
                operation_id: Some(operation_id.clone()),
                outcome: QualificationOutcomeKind::Conflict,
                completion: None,
                recovery_id: Some(operation_id),
                error_code: Some(error_code),
                issue_metadata_sha256: Some(issue_metadata_sha256),
                receipt_ids: receipts(values)?,
            }
        }
        Outcome::Completed {
            operation_id,
            receipts: values,
            completion: value,
            ..
        } => ClientOutcomeProjection {
            operation_id: Some(operation_id.as_str().to_owned()),
            outcome: QualificationOutcomeKind::Completed,
            completion: Some(completion(*value)),
            recovery_id: None,
            error_code: None,
            issue_metadata_sha256: None,
            receipt_ids: receipts(values)?,
        },
        Outcome::Partial {
            operation_id,
            issue: bytes,
            receipts: values,
            completion: value,
            ..
        } => {
            let (error_code, issue_metadata_sha256) = issue(bytes)?;
            ClientOutcomeProjection {
                operation_id: Some(operation_id.as_str().to_owned()),
                outcome: QualificationOutcomeKind::Partial,
                completion: Some(completion(*value)),
                recovery_id: None,
                error_code: Some(error_code),
                issue_metadata_sha256: Some(issue_metadata_sha256),
                receipt_ids: receipts(values)?,
            }
        }
        Outcome::NotApplied {
            operation_id,
            issue: bytes,
            receipts: values,
            completion: value,
            ..
        } => {
            let (error_code, issue_metadata_sha256) = issue(bytes)?;
            ClientOutcomeProjection {
                operation_id: Some(operation_id.as_str().to_owned()),
                outcome: QualificationOutcomeKind::NotApplied,
                completion: Some(completion(*value)),
                recovery_id: None,
                error_code: Some(error_code),
                issue_metadata_sha256: Some(issue_metadata_sha256),
                receipt_ids: receipts(values)?,
            }
        }
        Outcome::RecoveryRequired {
            operation_id,
            issue: bytes,
            receipts: values,
            ..
        } => {
            let (error_code, issue_metadata_sha256) = issue(bytes)?;
            let operation_id = operation_id.as_str().to_owned();
            ClientOutcomeProjection {
                operation_id: Some(operation_id.clone()),
                outcome: QualificationOutcomeKind::RecoveryRequired,
                completion: None,
                recovery_id: Some(operation_id),
                error_code: Some(error_code),
                issue_metadata_sha256: Some(issue_metadata_sha256),
                receipt_ids: receipts(values)?,
            }
        }
        Outcome::ReceiptIntegrityFailed { .. } => {
            return Err(
                "qualification cannot project a receipt-integrity failure as another outcome"
                    .into(),
            );
        }
    };
    Ok(Some(projected))
}

#[cfg(target_os = "linux")]
impl Drop for ClientTransportGuard<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Ok(mut state) = self.shared.state.lock()
            && let Some(attempt) = state.attempts.get_mut(&self.request_id)
        {
            attempt.transports_in_flight = attempt.transports_in_flight.saturating_sub(1);
            attempt.tail = ClientTransportTail::DeliveryFailed;
        }
    }
}

#[cfg(target_os = "linux")]
fn run_client_proxy_reader(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values_for(
        arguments,
        "serve-reader-session",
        &[
            "--client-socket",
            "--result-socket",
            "--control-socket",
            "--agent-socket",
            "--signer-socket",
            "--sequencer-socket",
            "--ledger-plan",
            "--source-trust",
            "--scenario",
            "--phase-index",
            "--supervisor-generation",
        ],
        typed_source_usage,
    )?;
    reject_secret_environment()?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&read_bounded(
        Path::new(value_for(&values, "--ledger-plan", typed_source_usage)?),
        MAX_TRUST_BYTES,
        true,
    )?)
    .map_err(string_error)?;
    let trust = QualificationEvidenceSourceTrustRegistry::from_json(&read_bounded(
        Path::new(value_for(&values, "--source-trust", typed_source_usage)?),
        MAX_TRUST_BYTES,
        false,
    )?)
    .map_err(string_error)?;
    let scenario = value_for(&values, "--scenario", typed_source_usage)?;
    let phase_index = value_for(&values, "--phase-index", typed_source_usage)?
        .parse::<u8>()
        .map_err(string_error)?;
    let phase = plan
        .phases
        .iter()
        .find(|phase| phase.scenario_id == scenario && phase.phase_index == phase_index)
        .cloned()
        .ok_or_else(|| "ClientProxy phase is absent from the immutable ledger plan".to_owned())?;
    let supervisor_generation = value_for(&values, "--supervisor-generation", typed_source_usage)?
        .parse::<u32>()
        .map_err(string_error)?;
    if supervisor_generation == 0 {
        return Err("ClientProxy supervisor generation is invalid".into());
    }
    let client_socket = Path::new(value_for(&values, "--client-socket", typed_source_usage)?);
    let result_socket = Path::new(value_for(&values, "--result-socket", typed_source_usage)?);
    let control_socket = Path::new(value_for(&values, "--control-socket", typed_source_usage)?);
    if client_socket == result_socket
        || client_socket == control_socket
        || result_socket == control_socket
    {
        return Err("ClientProxy transport, result, and control sockets must be distinct".into());
    }
    let client_parent = validate_shared_reader_socket_path(client_socket, &plan)?;
    let listener = UnixListener::bind(client_socket).map_err(string_error)?;
    if validate_shared_reader_socket_path_after_bind(client_socket, &plan)? != client_parent {
        return Err("ClientProxy socket parent changed while the listener was bound".into());
    }
    let _socket_guard = SocketPathGuard(client_socket.to_owned());
    fs::set_permissions(client_socket, fs::Permissions::from_mode(0o660)).map_err(string_error)?;
    listener.set_nonblocking(true).map_err(string_error)?;
    let result_parent = validate_shared_reader_socket_path(result_socket, &plan)?;
    let result_listener = UnixListener::bind(result_socket).map_err(string_error)?;
    if validate_shared_reader_socket_path_after_bind(result_socket, &plan)? != result_parent {
        return Err("ClientProxy result socket parent changed while the listener was bound".into());
    }
    let _result_socket_guard = SocketPathGuard(result_socket.to_owned());
    fs::set_permissions(result_socket, fs::Permissions::from_mode(0o660)).map_err(string_error)?;
    result_listener
        .set_nonblocking(true)
        .map_err(string_error)?;
    let control_parent = validate_shared_reader_socket_path(control_socket, &plan)?;
    let control_listener = UnixListener::bind(control_socket).map_err(string_error)?;
    if validate_shared_reader_socket_path_after_bind(control_socket, &plan)? != control_parent {
        return Err("ClientProxy control socket parent changed while binding".into());
    }
    let _control_socket_guard = SocketPathGuard(control_socket.to_owned());
    fs::set_permissions(control_socket, fs::Permissions::from_mode(0o660)).map_err(string_error)?;
    control_listener
        .set_nonblocking(true)
        .map_err(string_error)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let remaining = plan
        .deadline_at_unix_seconds
        .checked_sub(now)
        .filter(|seconds| *seconds != 0)
        .ok_or_else(|| "ClientProxy session started outside the protected interval".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(remaining);
    let appender = FixedSourceAppendSession::connect(
        QualificationEvidenceSource::ClientProxy,
        plan.clone(),
        trust,
        Path::new(value_for(&values, "--signer-socket", typed_source_usage)?),
        PathBuf::from(value_for(
            &values,
            "--sequencer-socket",
            typed_source_usage,
        )?),
        deadline,
    )?;
    let shared = Arc::new(ClientProxyShared {
        plan,
        phase,
        supervisor_generation,
        agent_socket: PathBuf::from(value_for(&values, "--agent-socket", typed_source_usage)?),
        appender: Mutex::new(appender),
        state: Mutex::new(ClientProxyState {
            sessions: BTreeMap::new(),
            attempts: BTreeMap::new(),
            operations: BTreeMap::new(),
        }),
        in_flight: Arc::new(AtomicUsize::new(0)),
    });
    let (errors, failures) = mpsc::channel();
    loop {
        if Instant::now() >= deadline {
            return Err("ClientProxy reader exceeded its phase deadline".into());
        }
        if let Ok(error) = failures.try_recv() {
            return Err(error);
        }
        if let Some(mut control) = accept_optional_before(&control_listener)? {
            let ready = || {
                shared.state.lock().is_ok_and(|state| {
                    !state.attempts.is_empty()
                        && state.attempts.values().all(|attempt| {
                            attempt.transports_in_flight == 0 && attempt.last_result.is_some()
                        })
                })
            };
            accept_phase_reader_stop(
                &mut control,
                &shared.plan,
                &shared.in_flight,
                &ready,
                deadline,
                "ClientProxy",
            )?;
            return Ok(());
        }
        let mut accepted = false;
        for (listener, result_handoff) in [(&listener, false), (&result_listener, true)] {
            match listener.accept() {
                Ok((stream, _)) => {
                    accepted = true;
                    stream.set_nonblocking(true).map_err(string_error)?;
                    let permit = acquire_in_flight_permit(
                        &shared.in_flight,
                        MAX_CLIENT_PROXY_IN_FLIGHT,
                        "ClientProxy",
                    )?;
                    let shared = Arc::clone(&shared);
                    let errors = errors.clone();
                    thread::spawn(move || {
                        let _permit = permit;
                        let result = if result_handoff {
                            accept_client_result_handoff(stream, &shared)
                        } else {
                            relay_client_proxy_connection(stream, &shared)
                        };
                        if let Err(error) = result {
                            let _ = errors.send(error);
                        }
                    });
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(string_error(error)),
            }
        }
        if !accepted {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "linux")]
fn acquire_in_flight_permit(
    counter: &Arc<AtomicUsize>,
    maximum: usize,
    label: &str,
) -> Result<InFlightPermit, String> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < maximum).then_some(current + 1)
        })
        .map_err(|_| format!("{label} concurrent connection bound was exceeded"))?;
    Ok(InFlightPermit(Arc::clone(counter)))
}

#[cfg(not(target_os = "linux"))]
fn run_client_proxy_reader(_arguments: &[String]) -> Result<(), String> {
    Err("the qualification ClientProxy reader is supported only on Linux".into())
}

#[cfg(target_os = "linux")]
fn relay_client_proxy_connection(
    mut client: UnixStream,
    shared: &ClientProxyShared,
) -> Result<(), String> {
    let ingress_deadline = Instant::now() + Duration::from_secs(30);
    let client_peer = QualificationSourceSessionPeer::observe(&client)?;
    let client_process = ClientProcessIdentity::from_peer(&client_peer)?;
    let request_bytes = read_http_message_before(
        &mut client,
        MAX_LOCAL_REQUEST_BYTES,
        ingress_deadline,
        "ClientProxy SDK request",
    )?;
    client_peer.verify_unchanged()?;
    let request = decode_local_agent_http_request(&request_bytes).map_err(string_error)?;
    let deadline = qualification_plan_deadline(&shared.plan, "ClientProxy SDK exchange")?;

    let session = request
        .session()
        .map(|session| {
            let state = shared.state.lock().map_err(string_error)?;
            let session = state
                .sessions
                .get(session)
                .cloned()
                .ok_or_else(|| "ClientProxy request used an unknown session".to_owned())?;
            if session.process != client_process {
                return Err("ClientProxy session moved to another SDK process".to_owned());
            }
            Ok::<ClientSessionState, String>(session)
        })
        .transpose()?;

    if let (Some(session), Some(facts)) = (
        session.as_ref(),
        client_request_facts(&request, &shared.phase.profile)?,
    ) {
        let mut state = shared.state.lock().map_err(string_error)?;
        if state.attempts.len() >= 1_024 {
            return Err("ClientProxy attempt state exceeds its hard bound".into());
        }
        if !state.attempts.contains_key(&facts.request_id) {
            let attempt_sequence = u16::try_from(state.attempts.len() + 1)
                .map_err(|_| "ClientProxy attempt sequence exceeds its hard bound".to_owned())?;
            let principal_sha256 = session.principal_sha256.clone();
            let record = client_proxy_record(
                shared,
                facts.request_id.clone(),
                None,
                QualificationClientProxyObservationV1::RequestReceived {
                    request_input_sha256: facts.request_input_sha256,
                    principal_sha256: principal_sha256.clone(),
                    idempotency_sha256: facts.idempotency_sha256.clone(),
                    preparation_input_sha256: facts.preparation_input_sha256.clone(),
                },
            );
            shared
                .appender
                .lock()
                .map_err(string_error)?
                .append_client_proxy(record, false, deadline)?;
            state.attempts.insert(
                facts.request_id,
                ClientAttemptState {
                    sequence: attempt_sequence,
                    process: session.process.clone(),
                    principal_sha256,
                    idempotency_sha256: facts.idempotency_sha256,
                    preparation_input_sha256: facts.preparation_input_sha256,
                    recovery_request_sha256: facts.recovery_request_sha256,
                    transports_in_flight: 0,
                    tail: ClientTransportTail::Intermediate,
                    journal_projection_kinds: Vec::new(),
                    projected_outcome: None,
                    last_result: None,
                },
            );
        } else {
            let attempt = state
                .attempts
                .get(&facts.request_id)
                .expect("the observed attempt remains present while its lock is held");
            if attempt.process != session.process
                || attempt.principal_sha256 != session.principal_sha256
                || attempt.idempotency_sha256 != facts.idempotency_sha256
                || attempt.preparation_input_sha256 != facts.preparation_input_sha256
                || attempt.recovery_request_sha256 != facts.recovery_request_sha256
            {
                return Err("ClientProxy request changed its durable ingress commitments".into());
            }
        }
    }

    let transport = if session.is_some() {
        client_exchange_request_id(
            &request,
            &shared.phase.profile,
            session.as_ref().map(|session| session.principal.as_str()),
            &shared.plan,
            &shared.state,
            deadline,
        )?
        .map(|binding| {
            let mut state = shared.state.lock().map_err(string_error)?;
            let attempt = state
                .attempts
                .get_mut(&binding.request_id)
                .ok_or_else(|| "ClientProxy exchange has no durably observed request".to_owned())?;
            if attempt.process != client_process {
                return Err("ClientProxy exchange moved to another SDK process".into());
            }
            if attempt.last_result.is_some() {
                return Err("ClientProxy request continued after its terminal result".into());
            }
            attempt.transports_in_flight = attempt
                .transports_in_flight
                .checked_add(1)
                .ok_or_else(|| "ClientProxy transport concurrency exceeded its bound".to_owned())?;
            Ok::<ClientTransportGuard<'_>, String>(ClientTransportGuard {
                shared,
                request_id: binding.request_id,
                expected_operation_id: binding.expected_operation_id,
                projection_route: binding.projection_route,
                finished: false,
            })
        })
        .transpose()?
    } else {
        None
    };

    let admission_fault = client_admission_fault(shared, &request)?;
    let binding = client_process
        .bridge_binding(
            shared.plan.source_context_sha256().map_err(string_error)?,
            admission_fault,
        )
        .to_json()
        .map_err(string_error)?;
    let response_bytes = relay_request_to_qualification_agent(
        shared,
        &client_peer,
        &binding,
        &request_bytes,
        deadline,
    )?;
    let response = match decode_local_agent_http_response(&response_bytes) {
        Ok(response) => response,
        Err(_) => return Ok(()),
    };
    let session_response = if request.path() == "/v1/session" && response.status() == 200 {
        let request = decode_session_request(request.body()).map_err(string_error)?;
        let response = decode_session_response(response.body()).map_err(string_error)?;
        if request.request_id() != response.request_id() {
            return Err("ClientProxy session response changed the request identity".into());
        }
        let mut state = shared.state.lock().map_err(string_error)?;
        if state.sessions.len() >= 64
            || state
                .sessions
                .insert(
                    response.session_id().to_owned(),
                    ClientSessionState {
                        principal: response.principal().to_owned(),
                        principal_sha256: hex::encode(local_principal_commitment(
                            response.principal(),
                        )),
                        process: client_process.clone(),
                    },
                )
                .is_some()
        {
            return Err("ClientProxy session roster is duplicate or over its bound".into());
        }
        true
    } else {
        false
    };

    let outcome = client_operation_response_outcome(
        &request,
        &response,
        &shared.phase.profile,
        session_response,
    )
    .unwrap_or(None);
    if let (Some(transport), Some(outcome)) = (transport.as_ref(), outcome.as_ref())
        && outcome.request_id().to_base64url() != transport.request_id
    {
        return Err("ClientProxy response changed the request identity".into());
    }
    if let (Some(transport), Some(outcome)) = (transport.as_ref(), outcome.as_ref())
        && let Some(expected) = transport.expected_operation_id.as_deref()
        && outcome.operation_id().map(|operation| operation.as_str()) != Some(expected)
    {
        return Err("ClientProxy response changed the operation identity".into());
    }
    let delivered = match write_client_response_before(&mut client, &response_bytes, deadline) {
        Ok(delivered) => delivered,
        Err(error) => {
            if let Some(transport) = transport {
                transport.finish(false, outcome.as_ref())?;
            }
            let _ = error;
            return Ok(());
        }
    };
    if delivered {
        if client.shutdown(Shutdown::Write).is_err() {
            if let Some(transport) = transport {
                transport.finish(false, outcome.as_ref())?;
            }
            return Ok(());
        }
    }
    if client_peer.verify_unchanged().is_err() {
        if let Some(transport) = transport {
            transport.finish(false, outcome.as_ref())?;
        }
        return Ok(());
    }
    if let Some(transport) = transport {
        transport.finish(delivered, outcome.as_ref())?;
    }
    if session_response && !delivered {
        return Err("ClientProxy could not deliver the authenticated session response".into());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn qualification_plan_deadline(
    plan: &QualificationEvidenceLedgerPlanV1,
    label: &str,
) -> Result<Instant, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let remaining = plan
        .deadline_at_unix_seconds
        .checked_sub(now)
        .filter(|seconds| *seconds != 0)
        .ok_or_else(|| format!("{label} started outside the protected interval"))?;
    Ok(Instant::now() + Duration::from_secs(remaining))
}

#[cfg(target_os = "linux")]
fn relay_request_to_qualification_agent(
    shared: &ClientProxyShared,
    client_peer: &QualificationSourceSessionPeer,
    binding: &[u8],
    request: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let retry_after_agent_loss = shared.phase.failpoint.is_some();
    let binding_length = u32::try_from(binding.len())
        .map_err(string_error)?
        .to_be_bytes();
    loop {
        client_peer.verify_unchanged()?;
        validate_agent_socket_path(&shared.agent_socket, &shared.plan)?;
        let exchange = (|| {
            let mut agent = connect_before(&shared.agent_socket, deadline, "qualification agent")
                .map_err(AgentExchangeError::Ambiguous)?;
            let agent_peer = QualificationSourceSessionPeer::observe(&agent)
                .map_err(AgentExchangeError::Ambiguous)?;
            if agent_peer.uid() != shared.plan.agent_uid
                || agent_peer.gid() != shared.plan.agent_gid
                || agent_peer.executable_sha256() != shared.plan.agent_executable_sha256
            {
                return Err(AgentExchangeError::Fatal(
                    "ClientProxy connected to a different qualification agent".into(),
                ));
            }
            write_raw_before(&mut agent, &binding_length, deadline)
                .map_err(AgentExchangeError::Ambiguous)?;
            write_raw_before(&mut agent, binding, deadline)
                .map_err(AgentExchangeError::Ambiguous)?;
            write_raw_before(&mut agent, request, deadline)
                .map_err(AgentExchangeError::Ambiguous)?;
            agent
                .shutdown(Shutdown::Write)
                .map_err(string_error)
                .map_err(AgentExchangeError::Ambiguous)?;
            let response = read_agent_response_before(&mut agent, deadline)?;
            agent_peer
                .verify_unchanged()
                .map_err(AgentExchangeError::Fatal)?;
            Ok::<Vec<u8>, AgentExchangeError>(response)
        })();
        match exchange {
            Ok(response) => return Ok(response),
            Err(AgentExchangeError::Ambiguous(error))
                if retry_after_agent_loss && Instant::now() < deadline =>
            {
                client_peer.verify_unchanged()?;
                thread::sleep(Duration::from_millis(10));
                let _ = error;
            }
            Err(AgentExchangeError::Ambiguous(error) | AgentExchangeError::Fatal(error)) => {
                return Err(error);
            }
        }
    }
}

#[cfg(target_os = "linux")]
enum AgentExchangeError {
    Ambiguous(String),
    Fatal(String),
}

#[cfg(target_os = "linux")]
fn read_agent_response_before(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, AgentExchangeError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 16_384];
    loop {
        if Instant::now() >= deadline {
            return Err(AgentExchangeError::Ambiguous(
                "ClientProxy agent response exceeded its total deadline".into(),
            ));
        }
        match local_agent_http_message_length(&bytes, MAX_LOCAL_RESPONSE_BYTES) {
            Ok(Some(length)) if bytes.len() == length => return Ok(bytes),
            Ok(_) => {}
            Err(error) => return Err(AgentExchangeError::Fatal(string_error(error))),
        }
        match stream.read(&mut buffer) {
            Ok(0) => {
                return Err(AgentExchangeError::Ambiguous(
                    "ClientProxy agent response ended before its complete frame".into(),
                ));
            }
            Ok(read) => bytes.extend_from_slice(&buffer[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(AgentExchangeError::Ambiguous(string_error(error))),
        }
    }
}

#[cfg(target_os = "linux")]
fn client_operation_response_outcome(
    request: &auths_production_client::LocalAgentHttpRequest,
    response: &auths_production_client::LocalAgentHttpResponse,
    profile: &str,
    session_response: bool,
) -> Result<Option<auths_production_client::LocalOperationOutcome>, String> {
    if session_response || response.status() != 200 {
        return Ok(None);
    }
    match classify_client_route(request.path(), profile)? {
        ClientRoute::PreparationEvidence => {
            decode_preparation_evidence_outcome(response.body()).map_err(string_error)
        }
        ClientRoute::Prepare
        | ClientRoute::CommonRecover
        | ClientRoute::Operation {
            action:
                ClientOperationAction::Execute
                | ClientOperationAction::Recover
                | ClientOperationAction::Status,
            ..
        } => decode_local_operation_outcome(response.body())
            .map(Some)
            .map_err(string_error),
        ClientRoute::Session
        | ClientRoute::SessionClose
        | ClientRoute::Pending
        | ClientRoute::Operation {
            action: ClientOperationAction::Receipts,
            ..
        } => Ok(None),
    }
}

#[cfg(target_os = "linux")]
fn client_admission_fault(
    shared: &ClientProxyShared,
    request: &auths_production_client::LocalAgentHttpRequest,
) -> Result<Option<QualificationAdmissionFaultV1>, String> {
    if classify_client_route(request.path(), &shared.phase.profile)? != ClientRoute::Prepare {
        return Ok(None);
    }
    let request =
        decode_prepare_operation_request(request.body(), 25_165_824).map_err(string_error)?;
    let sequence = shared
        .state
        .lock()
        .map_err(string_error)?
        .attempts
        .get(&request.request_id().to_base64url())
        .map(|attempt| attempt.sequence)
        .ok_or_else(|| "ClientProxy admission fault has no authenticated attempt".to_owned())?;
    Ok(match shared.phase.scenario_id.as_str() {
        "configuration-mismatch" => Some(QualificationAdmissionFaultV1::ConfigurationMismatch),
        "connection-substitution" => Some(QualificationAdmissionFaultV1::ConnectionSubstitution),
        "principal-substitution" => Some(QualificationAdmissionFaultV1::PrincipalSubstitution),
        "stale-evidence" if sequence == 1 => {
            Some(QualificationAdmissionFaultV1::EvidenceFreshnessEdge)
        }
        "stale-evidence" if sequence == 2 => Some(QualificationAdmissionFaultV1::StaleEvidence),
        "stale-evidence" => {
            return Err("stale-evidence exceeded its exact two-attempt contract".into());
        }
        _ => None,
    })
}

#[cfg(target_os = "linux")]
fn client_exchange_request_id(
    request: &auths_production_client::LocalAgentHttpRequest,
    profile: &str,
    principal: Option<&str>,
    plan: &QualificationEvidenceLedgerPlanV1,
    state: &Mutex<ClientProxyState>,
    deadline: Instant,
) -> Result<Option<ClientExchangeBinding>, String> {
    let route = classify_client_route(request.path(), profile)?;
    if route == ClientRoute::PreparationEvidence {
        return decode_preparation_evidence_request(request.body(), 25_165_824)
            .map(|request| {
                Some(ClientExchangeBinding {
                    request_id: request.preparation().request_id().to_base64url(),
                    expected_operation_id: None,
                    projection_route: Some(ClientProjectionRoute::ReplayCandidate),
                })
            })
            .map_err(string_error);
    }
    if route == ClientRoute::Prepare {
        return decode_prepare_operation_request(request.body(), 25_165_824)
            .map(|request| {
                Some(ClientExchangeBinding {
                    request_id: request.request_id().to_base64url(),
                    expected_operation_id: None,
                    projection_route: Some(ClientProjectionRoute::ReplayCandidate),
                })
            })
            .map_err(string_error);
    }
    if route == ClientRoute::CommonRecover {
        let request = decode_recover_operation_request(request.body()).map_err(string_error)?;
        let principal = principal
            .ok_or_else(|| "ClientProxy recovery has no authenticated principal".to_owned())?;
        let binding = verify_recovery_handle_binding(
            request.recovery_handle(),
            principal,
            &plan.recovery_key_id,
            &plan.recovery_public_key_base64url,
            signing_time_before(deadline, "ClientProxy recovery verification")?,
        )?;
        let (profile_id, profile_version) = profile
            .split_once('/')
            .ok_or_else(|| "ClientProxy phase profile is malformed".to_owned())?;
        if binding.profile.id() != profile_id
            || binding.profile.version() != profile_version.parse::<u16>().map_err(string_error)?
        {
            return Err("ClientProxy recovery handle differs from its immutable phase".into());
        }
        return Ok(Some(ClientExchangeBinding {
            request_id: request.request_id().to_base64url(),
            expected_operation_id: Some(binding.operation.as_str().to_owned()),
            projection_route: Some(ClientProjectionRoute::Recovery),
        }));
    }
    let (operation_id, action) = match route {
        ClientRoute::Session | ClientRoute::SessionClose | ClientRoute::Pending => return Ok(None),
        ClientRoute::Operation {
            operation_id,
            action,
        } => (operation_id, action),
        ClientRoute::PreparationEvidence | ClientRoute::Prepare | ClientRoute::CommonRecover => {
            unreachable!("request-bearing routes returned above")
        }
    };

    let mapped_request_id = {
        let state = state.lock().map_err(string_error)?;
        state
            .operations
            .get(operation_id)
            .cloned()
            .ok_or_else(|| "ClientProxy request used an unknown operation".to_owned())?
    };
    match action {
        ClientOperationAction::Execute => {
            let decoded = decode_execute_operation_request(request.body()).map_err(string_error)?;
            if decoded.operation_id().as_str() != operation_id
                || decoded.request_id().to_base64url() != mapped_request_id
            {
                return Err("ClientProxy execute request changed its operation binding".into());
            }
        }
        ClientOperationAction::Recover => {
            let decoded = decode_recover_operation_request(request.body()).map_err(string_error)?;
            if decoded.request_id().to_base64url() != mapped_request_id {
                return Err("ClientProxy recovery request changed its operation binding".into());
            }
        }
        ClientOperationAction::Status | ClientOperationAction::Receipts => {
            if !request.body().is_empty() {
                return Err("ClientProxy read request carried an unexpected body".into());
            }
        }
    }
    Ok(Some(ClientExchangeBinding {
        request_id: mapped_request_id,
        expected_operation_id: Some(operation_id.to_owned()),
        projection_route: match action {
            ClientOperationAction::Status => Some(ClientProjectionRoute::Status),
            ClientOperationAction::Recover => Some(ClientProjectionRoute::Recovery),
            ClientOperationAction::Execute | ClientOperationAction::Receipts => None,
        },
    }))
}

#[cfg(target_os = "linux")]
fn split_operation_action(remainder: &str) -> Result<(&str, ClientOperationAction), String> {
    if remainder.is_empty() {
        return Err("ClientProxy operation route omitted its operation ID".into());
    }
    match remainder.split_once('/') {
        Some((operation_id, "execute")) if !operation_id.is_empty() => {
            Ok((operation_id, ClientOperationAction::Execute))
        }
        Some((operation_id, "recover")) if !operation_id.is_empty() => {
            Ok((operation_id, ClientOperationAction::Recover))
        }
        Some((operation_id, "receipts")) if !operation_id.is_empty() => {
            Ok((operation_id, ClientOperationAction::Receipts))
        }
        None => Ok((remainder, ClientOperationAction::Status)),
        _ => Err("ClientProxy operation route is malformed".into()),
    }
}

#[cfg(target_os = "linux")]
fn classify_client_route<'a>(path: &'a str, profile: &str) -> Result<ClientRoute<'a>, String> {
    let (profile_id, version) = profile
        .split_once('/')
        .ok_or_else(|| "ClientProxy phase profile is malformed".to_owned())?;
    let route = ProfileRoute::new(profile_id, version.parse::<u16>().map_err(string_error)?)
        .map_err(string_error)?;
    if path == "/v1/session" {
        return Ok(ClientRoute::Session);
    }
    if path.starts_with("/v1/session/") {
        return Ok(ClientRoute::SessionClose);
    }
    if path == route.preparation_evidence() {
        return Ok(ClientRoute::PreparationEvidence);
    }
    if path == route.collection() {
        return Ok(ClientRoute::Prepare);
    }
    if path == "/v1/operations/recover" {
        return Ok(ClientRoute::CommonRecover);
    }
    if path == "/v1/operations/pending" {
        return Ok(ClientRoute::Pending);
    }
    if let Some(remainder) = path.strip_prefix(&format!("{}/", route.collection())) {
        let (operation_id, action) = split_operation_action(remainder)?;
        return Ok(ClientRoute::Operation {
            operation_id,
            action,
        });
    }
    if let Some(remainder) = path.strip_prefix("/v1/operations/") {
        let (operation_id, action) = split_operation_action(remainder)?;
        if action == ClientOperationAction::Receipts {
            return Ok(ClientRoute::Operation {
                operation_id,
                action,
            });
        }
    }
    Err("ClientProxy request used a route outside its immutable phase".into())
}

#[cfg(target_os = "linux")]
fn accept_client_result_handoff(
    mut stream: UnixStream,
    shared: &ClientProxyShared,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let peer = QualificationSourceSessionPeer::observe(&stream)?;
    let process = ClientProcessIdentity::from_peer(&peer)?;
    let mut header = [0_u8; CLIENT_RESULT_HEADER_BYTES];
    read_exact_raw_before(
        &mut stream,
        &mut header,
        deadline,
        "ClientProxy result header",
    )?;
    if header[0] != 1 || !matches!(header[1], 0..=3) {
        return Err("ClientProxy result handoff has an unknown version or mode".into());
    }
    let retry = header[1] >= 2;
    let kind = if header[1] % 2 == 0 {
        ClientResultKind::ResponseProjected
    } else {
        ClientResultKind::CancellationObserved
    };
    let request_id = ClientRequestId::from_bytes(
        header[2..18]
            .try_into()
            .map_err(|_| "ClientProxy result request ID is malformed".to_owned())?,
    );
    let request_token = request_id.to_base64url();
    let result_length = usize::try_from(u32::from_be_bytes(
        header[18..]
            .try_into()
            .map_err(|_| "ClientProxy result length is malformed".to_owned())?,
    ))
    .map_err(string_error)?;
    if result_length == 0 || result_length > MAX_LOCAL_RESPONSE_BYTES {
        return Err("ClientProxy result exceeds its public projection bound".into());
    }
    let result_sha256 = read_result_digest_before(&mut stream, result_length, deadline)?;
    peer.verify_unchanged()?;
    loop {
        if Instant::now() >= deadline {
            return Err("ClientProxy result waited too long for its transport transcript".into());
        }
        let mut state = shared.state.lock().map_err(string_error)?;
        let attempt = state
            .attempts
            .get_mut(&request_token)
            .ok_or_else(|| "ClientProxy result has no durably observed request".to_owned())?;
        if attempt.process != process {
            return Err("ClientProxy result moved to another SDK process".into());
        }
        if attempt.transports_in_flight != 0 {
            drop(state);
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        let transport_matches = match (&attempt.tail, kind) {
            (
                ClientTransportTail::ResponseProjected(expected),
                ClientResultKind::ResponseProjected,
            ) => expected == &result_sha256,
            (
                ClientTransportTail::DeliveryFailed | ClientTransportTail::ResponseProjected(_),
                ClientResultKind::CancellationObserved,
            ) => {
                hex::encode(Sha256::digest(qualification_client_cancellation_result(
                    request_id.as_bytes(),
                ))) == result_sha256
            }
            _ => false,
        };
        if !transport_matches {
            return Err("ClientProxy result differs from the observed transport outcome".into());
        }
        let outcome = attempt
            .projected_outcome
            .clone()
            .ok_or_else(|| "ClientProxy result has no authenticated terminal outcome".to_owned())?;
        let commitment = ClientResultCommitment {
            kind,
            result_sha256: result_sha256.clone(),
            outcome,
        };
        if retry {
            if attempt.last_result.as_ref() != Some(&commitment) {
                return Err("ClientProxy result retry differs from the last durable result".into());
            }
        } else if attempt.last_result.is_some() {
            return Err("ClientProxy request already has a durable terminal result".into());
        }
        peer.verify_unchanged()?;
        let observation = match kind {
            ClientResultKind::ResponseProjected => {
                QualificationClientProxyObservationV1::ResponseProjected {
                    result_sha256: commitment.result_sha256.clone(),
                    journal_projection_kinds: attempt.journal_projection_kinds.clone(),
                    outcome: commitment.outcome.outcome,
                    completion: commitment.outcome.completion,
                    recovery_id: commitment.outcome.recovery_id.clone(),
                    error_code: commitment.outcome.error_code.clone(),
                    issue_metadata_sha256: commitment.outcome.issue_metadata_sha256.clone(),
                    receipt_ids: commitment.outcome.receipt_ids.clone(),
                }
            }
            ClientResultKind::CancellationObserved => {
                QualificationClientProxyObservationV1::CancellationObserved {
                    result_sha256: commitment.result_sha256.clone(),
                    journal_projection_kinds: attempt.journal_projection_kinds.clone(),
                    outcome: commitment.outcome.outcome,
                    completion: commitment.outcome.completion,
                    recovery_id: commitment.outcome.recovery_id.clone(),
                    error_code: commitment.outcome.error_code.clone(),
                    issue_metadata_sha256: commitment.outcome.issue_metadata_sha256.clone(),
                    receipt_ids: commitment.outcome.receipt_ids.clone(),
                }
            }
        };
        let event = shared
            .appender
            .lock()
            .map_err(string_error)?
            .append_client_proxy(
                client_proxy_record(
                    shared,
                    request_token.clone(),
                    commitment.outcome.operation_id.clone(),
                    observation,
                ),
                retry,
                deadline,
            )?;
        attempt.last_result = Some(commitment);
        drop(state);
        if peer.verify_unchanged().is_err() {
            return Ok(());
        }
        let acknowledgement = hex::decode(qualification_event_marker_sha256(
            event.sequence,
            QualificationEvidenceSource::ClientProxy,
        ))
        .map_err(string_error)?;
        if write_raw_before(&mut stream, &acknowledgement, deadline).is_err() {
            return Ok(());
        }
        let _ = stream.shutdown(Shutdown::Write);
        return Ok(());
    }
}

#[cfg(target_os = "linux")]
fn read_exact_raw_before(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
    label: &str,
) -> Result<(), String> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(format!("{label} exceeded its total deadline"));
        }
        match stream.read(bytes) {
            Ok(0) => return Err(format!("{label} ended before its declared length")),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_result_digest_before(
    stream: &mut UnixStream,
    mut remaining: usize,
    deadline: Instant,
) -> Result<String, String> {
    let mut digest = Sha256::new();
    let mut chunk = [0_u8; 16_384];
    while remaining != 0 {
        if Instant::now() >= deadline {
            return Err("ClientProxy result exceeded its total deadline".into());
        }
        let limit = remaining.min(chunk.len());
        match stream.read(&mut chunk[..limit]) {
            Ok(0) => return Err("ClientProxy result ended before its declared length".into()),
            Ok(read) => {
                digest.update(&chunk[..read]);
                remaining -= read;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
    let mut extra = [0_u8; 1];
    loop {
        if Instant::now() >= deadline {
            return Err("ClientProxy result did not close its write side".into());
        }
        match stream.read(&mut extra) {
            Ok(0) => return Ok(hex::encode(digest.finalize())),
            Ok(_) => return Err("ClientProxy result exceeds its declared length".into()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
}

#[cfg(target_os = "linux")]
fn write_client_response_before(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<bool, String> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err("ClientProxy response write exceeded its total deadline".into());
        }
        match stream.write(bytes) {
            Ok(0) => return Ok(false),
            Ok(written) => bytes = &bytes[written..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotConnected
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(string_error(error)),
        }
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
struct ClientRequestFacts {
    request_id: String,
    request_input_sha256: String,
    idempotency_sha256: Option<String>,
    preparation_input_sha256: Option<String>,
    recovery_request_sha256: Option<String>,
}

#[cfg(target_os = "linux")]
fn client_request_facts(
    request: &auths_production_client::LocalAgentHttpRequest,
    profile: &str,
) -> Result<Option<ClientRequestFacts>, String> {
    let route = classify_client_route(request.path(), profile)?;
    let preparation = match route {
        ClientRoute::PreparationEvidence => Some(
            decode_preparation_evidence_request(request.body(), 25_165_824)
                .map_err(string_error)?
                .preparation()
                .clone(),
        ),
        ClientRoute::Prepare => Some(
            decode_prepare_operation_request(request.body(), 25_165_824).map_err(string_error)?,
        ),
        _ => None,
    };
    if let Some(preparation) = preparation {
        return Ok(Some(ClientRequestFacts {
            request_id: preparation.request_id().to_base64url(),
            request_input_sha256: hex::encode(local_request_commitment(request.body())),
            idempotency_sha256: preparation
                .idempotency_key()
                .map(local_idempotency_commitment)
                .map(hex::encode),
            preparation_input_sha256: Some(hex::encode(local_preparation_input_commitment(
                preparation.profile_input(),
            ))),
            recovery_request_sha256: None,
        }));
    }
    if route == ClientRoute::CommonRecover {
        let recovery = decode_recover_operation_request(request.body()).map_err(string_error)?;
        return Ok(Some(ClientRequestFacts {
            request_id: recovery.request_id().to_base64url(),
            request_input_sha256: hex::encode(local_request_commitment(request.body())),
            idempotency_sha256: None,
            preparation_input_sha256: None,
            recovery_request_sha256: Some(hex::encode(local_request_commitment(request.body()))),
        }));
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
fn client_proxy_record(
    shared: &ClientProxyShared,
    request_id: String,
    operation_id: Option<String>,
    observation: QualificationClientProxyObservationV1,
) -> QualificationClientProxyRecordV1 {
    QualificationClientProxyRecordV1 {
        schema: "auths.qualification-client-proxy-record/1".into(),
        context: QualificationSourceEventContextV1 {
            sequence: 1,
            previous_event_sha256: "0".repeat(64),
            scenario_id: shared.phase.scenario_id.clone(),
            phase_index: shared.phase.phase_index,
            role: shared.phase.role,
            profile: shared.phase.profile.clone(),
            failpoint: shared.phase.failpoint,
            supervisor_generation: shared.supervisor_generation,
            operation_id,
            request_id: Some(request_id),
            connection_generation: None,
        },
        observation,
    }
}

#[cfg(target_os = "linux")]
fn read_http_message_before(
    stream: &mut UnixStream,
    maximum: usize,
    deadline: Instant,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 16_384];
    loop {
        if Instant::now() >= deadline {
            return Err(format!("{label} exceeded its total deadline"));
        }
        if let Some(length) =
            local_agent_http_message_length(&bytes, maximum).map_err(string_error)?
        {
            if bytes.len() == length {
                return Ok(bytes);
            }
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Err(format!("{label} ended before its complete frame")),
            Ok(read) => bytes.extend_from_slice(&buffer[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
}

#[cfg(target_os = "linux")]
fn write_raw_before(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err("protected socket write exceeded its total deadline".into());
        }
        match stream.write(bytes) {
            Ok(0) => return Err("protected socket peer closed during write".into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn validate_typed_reader_event(
    source: QualificationEvidenceSource,
    record_bytes: &[u8],
    process: &QualificationSourceProcessBindingV1,
    source_context_sha256: &str,
    key_id: &str,
    plan: &QualificationEvidenceLedgerPlanV1,
    trust: &QualificationEvidenceSourceTrustRegistry,
    now: u64,
) -> Result<QualificationEvidenceEvent, String> {
    let event = typed_source_event(source, record_bytes, process, source_context_sha256, key_id)?;
    if !plan.phases.iter().any(|phase| {
        event.scenario_id == phase.scenario_id
            && event.phase_index == phase.phase_index
            && event.role == phase.role
            && event.profile == phase.profile
            && event.failpoint == phase.failpoint
    }) {
        return Err("typed source record differs from the immutable ledger phase plan".into());
    }
    event
        .validate_for_signing(
            source,
            source_context_sha256,
            trust,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
    Ok(event)
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn sign_typed_reader_event(
    event: QualificationEvidenceEvent,
    source: QualificationEvidenceSource,
    source_context_sha256: &str,
    seed: &str,
    trust: &QualificationEvidenceSourceTrustRegistry,
    plan: &QualificationEvidenceLedgerPlanV1,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let signing_now = signing_time_before(deadline, "typed source signing")?;
    event
        .sign_json(
            source,
            source_context_sha256,
            seed,
            trust,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            signing_now,
        )
        .map_err(string_error)
}

#[cfg(target_os = "linux")]
fn verify_peer_unchanged(pid: i32, start_time: u64, executable_sha256: &str) -> Result<(), String> {
    if process_start_time_ticks(pid)? != start_time
        || hash_peer_executable(pid)? != executable_sha256
    {
        return Err("typed source reader identity changed during handoff".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_typed_source(
    _source: QualificationEvidenceSource,
    _arguments: &[String],
) -> Result<(), String> {
    Err("authenticated qualification source services are supported only on Linux".into())
}

#[cfg(any(target_os = "linux", test))]
fn typed_source_event(
    source: QualificationEvidenceSource,
    bytes: &[u8],
    process: &QualificationSourceProcessBindingV1,
    source_context_sha256: &str,
    key_id: &str,
) -> Result<QualificationEvidenceEvent, String> {
    let context = || source_context_sha256.to_owned();
    let key = || key_id.to_owned();
    let event = match source {
        QualificationEvidenceSource::ClientProxy => {
            QualificationClientProxyRecordV1::from_json(bytes)
                .map_err(string_error)?
                .unsigned_event(process, context(), key())
        }
        QualificationEvidenceSource::CredentialBroker => {
            QualificationCredentialBrokerRecordV1::from_json(bytes)
                .map_err(string_error)?
                .unsigned_event(process, context(), key())
        }
        QualificationEvidenceSource::ProfileStateReader => {
            QualificationProfileStateRecordV1::from_json(bytes)
                .map_err(string_error)?
                .unsigned_event(process, context(), key())
        }
        QualificationEvidenceSource::ProviderProxy => {
            QualificationProviderProxyRecordV1::from_json(bytes)
                .map_err(string_error)?
                .unsigned_event(process, context(), key())
        }
        QualificationEvidenceSource::ReceiptVerifier => {
            QualificationReceiptVerifierRecordV1::from_json(bytes)
                .map_err(string_error)?
                .unsigned_event(process, context(), key())
        }
        QualificationEvidenceSource::ProviderObserver => {
            QualificationProviderObserverRecordV1::from_json(bytes)
                .map_err(string_error)?
                .unsigned_event(process, context(), key())
        }
        QualificationEvidenceSource::Supervisor | QualificationEvidenceSource::JournalReader => {
            return Err("typed source record named a separately implemented role".into());
        }
    };
    Ok(event)
}

/// Runs the minimal supervisor-source signer. The unsigned record is accepted
/// only from an owner-only local socket peer whose kernel UID and executable
/// digest are bound by the protected record and source trust registry.
pub fn main_for_supervisor() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let result = run_supervisor_ordinary_row(&arguments);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification supervisor source failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run_supervisor_ordinary_row(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values_for(
        arguments,
        "serve-ordinary-row-session",
        &["--socket", "--ledger-plan", "--source-trust"],
        supervisor_usage,
    )?;
    reject_secret_environment()?;
    let trust = QualificationEvidenceSourceTrustRegistry::from_json(&read_bounded(
        Path::new(value_for(&values, "--source-trust", supervisor_usage)?),
        MAX_TRUST_BYTES,
        false,
    )?)
    .map_err(string_error)?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&read_bounded(
        Path::new(value_for(&values, "--ledger-plan", supervisor_usage)?),
        MAX_TRUST_BYTES,
        true,
    )?)
    .map_err(string_error)?;
    let now = signing_time_before(
        immutable_plan_deadline(&plan)?,
        "ordinary Supervisor row policy",
    )?;
    let (key_id, source_identity, source_artifact, source_uid) = trust
        .current_source_process_binding(
            QualificationEvidenceSource::Supervisor,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
    let (_, journal_identity, journal_artifact, journal_uid) = trust
        .current_source_process_binding(
            QualificationEvidenceSource::JournalReader,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
    let self_digest = qualification_source_process_executable_sha256()?;
    if rustix::process::geteuid().as_raw() != source_uid || self_digest != source_artifact {
        return Err("ordinary Supervisor row process differs from source trust".into());
    }
    let socket = Path::new(value_for(&values, "--socket", supervisor_usage)?);
    validate_private_socket_path(socket)?;
    let listener = UnixListener::bind(socket).map_err(string_error)?;
    let _socket_guard = SocketPathGuard(socket.to_owned());
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660)).map_err(string_error)?;
    File::open(
        socket
            .parent()
            .ok_or_else(|| "ordinary Supervisor row socket has no parent".to_owned())?,
    )
    .map_err(string_error)?
    .sync_all()
    .map_err(string_error)?;
    listener.set_nonblocking(true).map_err(string_error)?;
    let deadline = immutable_plan_deadline(&plan)?;
    let source_context_sha256 = plan.source_context_sha256().map_err(string_error)?;
    let expected_phases = plan
        .phases
        .iter()
        .map(|phase| (phase.scenario_id.clone(), phase.phase_index))
        .collect::<BTreeSet<_>>();
    if expected_phases.is_empty() {
        return Err("ordinary Supervisor row session has no non-crash phases".into());
    }
    let mut completed_phases = BTreeSet::new();
    let mut request_count = 0_usize;
    let mut seed = None;
    while completed_phases != expected_phases {
        let (mut stream, _) =
            accept_before(&listener, deadline, "ordinary Supervisor row controller")?;
        stream.set_nonblocking(true).map_err(string_error)?;
        let peer = QualificationSourceSessionPeer::observe(&stream)?;
        if peer.uid() != plan.supervisor_controller_uid
            || peer.executable_sha256() != plan.supervisor_controller_artifact_sha256
        {
            return Err("ordinary Supervisor row peer differs from the ledger plan".into());
        }
        let bytes = read_source_session_frame_before(&mut stream, deadline)?
            .ok_or_else(|| "ordinary Supervisor row received no request".to_owned())?;
        if read_source_session_frame_before(&mut stream, deadline)?.is_some() {
            return Err("ordinary Supervisor row accepts one request per connection".into());
        }
        peer.verify_unchanged()?;
        request_count = request_count
            .checked_add(1)
            .filter(|count| *count <= 2_048)
            .ok_or_else(|| "ordinary Supervisor row request roster exceeds its bound".to_owned())?;

        let signed = if let Ok(request) = QualificationSupervisorPhaseRequestV1::from_json(&bytes) {
            let event = request
                .unsigned_event(&plan, source_identity, source_artifact, source_uid, key_id)
                .map_err(string_error)?;
            event
                .validate_for_signing(
                    QualificationEvidenceSource::Supervisor,
                    &source_context_sha256,
                    &trust,
                    &plan.domain,
                    plan.started_at_unix_seconds,
                    plan.deadline_at_unix_seconds,
                    signing_time_before(deadline, "ordinary Supervisor phase")?,
                )
                .map_err(string_error)?;
            if seed.is_none() {
                seed = Some(read_seed_from_stdin_before(deadline)?);
            }
            let signed = event
                .sign_json(
                    QualificationEvidenceSource::Supervisor,
                    &source_context_sha256,
                    seed.as_ref().expect("source seed was read before signing"),
                    &trust,
                    &plan.domain,
                    plan.started_at_unix_seconds,
                    plan.deadline_at_unix_seconds,
                    signing_time_before(deadline, "ordinary Supervisor phase")?,
                )
                .map_err(string_error)?;
            if request.kind == QualificationEvidenceEventKind::ScenarioCompleted {
                completed_phases.insert((request.scenario_id, request.phase_index));
            }
            signed
        } else if let Ok(record) =
            serde_json::from_slice::<QualificationJournalDecisionContextRecord>(&bytes)
        {
            if serde_json_canonicalizer::to_vec(&record).map_err(string_error)? != bytes
                || record.validate().is_err()
                || !plan
                    .binds_decision_context_common(&record)
                    .map_err(string_error)?
                || !decision_crash_identity_is_coherent(&record)
                || record.supervisor_controller_uid != peer.uid()
                || record.supervisor_source_uid != source_uid
                || record.supervisor_source_identity != source_identity
                || record.supervisor_source_artifact_sha256 != source_artifact
                || record.supervisor_controller_artifact_sha256
                    != plan.supervisor_controller_artifact_sha256
                || record.journal_reader_uid != journal_uid
                || record.journal_reader_source_identity != journal_identity
                || record.journal_reader_source_artifact_sha256 != journal_artifact
            {
                return Err(
                    "ordinary Supervisor decision context differs from protected policy".into(),
                );
            }
            if seed.is_none() {
                seed = Some(read_seed_from_stdin_before(deadline)?);
            }
            QualificationJournalDecisionContext::sign_json(
                record,
                key_id,
                seed.as_ref().expect("source seed was read before signing"),
                &trust,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                signing_time_before(deadline, "ordinary Supervisor decision")?,
            )
            .map_err(string_error)?
        } else {
            let record: QualificationCrashActionRecordV1 =
                serde_json::from_slice(&bytes).map_err(string_error)?;
            if serde_json_canonicalizer::to_vec(&record).map_err(string_error)? != bytes
                || record.validate().is_err()
                || !record
                    .crash_context
                    .binds_ledger_plan(&plan)
                    .map_err(string_error)?
                || record.supervisor_controller_uid != peer.uid()
                || record.crash_context.supervisor_source_uid != source_uid
                || record.crash_context.supervisor_source_identity != source_identity
                || record.supervisor_source_artifact_sha256 != source_artifact
                || record.supervisor_controller_artifact_sha256
                    != plan.supervisor_controller_artifact_sha256
            {
                return Err(
                    "ordinary Supervisor crash action differs from protected policy".into(),
                );
            }
            if seed.is_none() {
                seed = Some(read_seed_from_stdin_before(deadline)?);
            }
            let signing_now = signing_time_before(deadline, "ordinary Supervisor crash action")?;
            let context = QualificationCrashActionContextV1::sign_json(
                record.clone(),
                key_id,
                seed.as_ref().expect("source seed was read before signing"),
                &trust,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                signing_now,
            )
            .map_err(string_error)?;
            let event = record
                .unsigned_event(key_id.to_owned(), hex::encode(Sha256::digest(&context)))
                .sign_json(
                    QualificationEvidenceSource::Supervisor,
                    &source_context_sha256,
                    seed.as_ref().expect("source seed was read before signing"),
                    &trust,
                    &plan.domain,
                    plan.started_at_unix_seconds,
                    plan.deadline_at_unix_seconds,
                    signing_now,
                )
                .map_err(string_error)?;
            QualificationCrashActionResponseV1 {
                schema: "auths.qualification-crash-action-response/1".into(),
                action_context_base64url: Base64UrlUnpadded::encode_string(&context),
                event_base64url: Base64UrlUnpadded::encode_string(&event),
            }
            .to_json()?
        };
        peer.verify_unchanged()?;
        write_source_session_frame_before(&mut stream, &signed, deadline)?;
        stream.shutdown(Shutdown::Write).map_err(string_error)?;
    }
    if seed.is_none() || request_count < expected_phases.len().saturating_mul(2) {
        return Err("ordinary Supervisor row completed without its exact phase roster".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn decision_crash_identity_is_coherent(record: &QualificationJournalDecisionContextRecord) -> bool {
    match (
        record.failpoint,
        record.control_operation_id.as_deref(),
        record.controller_nonce_sha256.as_deref(),
    ) {
        (None, None, None) => true,
        (Some(_), Some(control), Some(nonce)) => {
            qualification_registered_token(control) && qualification_digest(nonce)
        }
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn qualification_registered_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(target_os = "linux")]
fn qualification_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(not(target_os = "linux"))]
fn run_supervisor_ordinary_row(_arguments: &[String]) -> Result<(), String> {
    Err("ordinary Supervisor row signing requires Linux process identity".into())
}

#[cfg(target_os = "linux")]
fn connect_before(path: &Path, deadline: Instant, label: &str) -> Result<UnixStream, String> {
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "{label} did not become available before the deadline"
            ));
        }
        match UnixStream::connect(path) {
            Ok(stream) => {
                stream.set_nonblocking(true).map_err(string_error)?;
                return Ok(stream);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
}

/// Runs the journal-reader producer, whose decision payload is derived only
/// from a directly decoded durable operation and deployed public trust.
pub fn main_for_journal_reader() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let result = run_journal_reader(&arguments);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification journal reader failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run_journal_reader(arguments: &[String]) -> Result<(), String> {
    match arguments.first().map(String::as_str) {
        Some("serve-decision") => run_journal_decision(arguments),
        Some("serve-boundary-session") => run_journal_boundary_session(arguments),
        Some("serve-ordinary-row-session") => run_journal_ordinary_row(arguments),
        _ => Err(journal_reader_usage()),
    }
}

#[cfg(target_os = "linux")]
fn run_journal_ordinary_row(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values(
        arguments,
        "serve-ordinary-row-session",
        &[
            "--runtime-root",
            "--sequencer-socket",
            "--source-trust",
            "--ledger-plan",
            "--receipt-trust",
        ],
    )?;
    let plan = ordinary_row_plan(&values)?;
    let runtime_root = Path::new(value(&values, "--runtime-root")?);
    let mut seed = None;
    for phase in ordinary_row_phases(&plan) {
        let root = ordinary_row_phase_root(runtime_root, phase)?;
        run_journal_boundary_session_with_seed(
            &[
                "serve-boundary-session".into(),
                "--socket".into(),
                path_text(&root.join("journal-reader/boundary.sock"))?,
                "--sequencer-socket".into(),
                value(&values, "--sequencer-socket")?.into(),
                "--source-trust".into(),
                value(&values, "--source-trust")?.into(),
                "--ledger-plan".into(),
                value(&values, "--ledger-plan")?.into(),
                "--receipt-trust".into(),
                value(&values, "--receipt-trust")?.into(),
                "--scenario".into(),
                phase.scenario_id.clone(),
                "--phase-index".into(),
                phase.phase_index.to_string(),
            ],
            &mut seed,
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_journal_decision(arguments: &[String]) -> Result<(), String> {
    let values = exact_flag_values(
        arguments,
        "serve-decision",
        &[
            "--socket",
            "--sequencer-socket",
            "--append-mode",
            "--source-trust",
            "--ledger-plan",
        ],
    )?;
    reject_secret_environment()?;
    let append_retry = match value(&values, "--append-mode")? {
        "new" => false,
        "retry" => true,
        _ => return Err(journal_reader_usage()),
    };
    let trust_bytes = read_bounded(
        Path::new(value(&values, "--source-trust")?),
        MAX_TRUST_BYTES,
        false,
    )?;
    let trust =
        QualificationEvidenceSourceTrustRegistry::from_json(&trust_bytes).map_err(string_error)?;
    let ledger_plan_bytes = read_bounded(
        Path::new(value(&values, "--ledger-plan")?),
        MAX_TRUST_BYTES,
        true,
    )?;
    let ledger_plan =
        QualificationEvidenceLedgerPlanV1::from_json(&ledger_plan_bytes).map_err(string_error)?;
    let domain = ledger_plan.domain.as_str();
    let source_context_sha256 = ledger_plan.source_context_sha256().map_err(string_error)?;
    let started_at = ledger_plan.started_at_unix_seconds;
    let completed_at = ledger_plan.deadline_at_unix_seconds;
    let socket = Path::new(value(&values, "--socket")?);
    validate_private_socket_path(socket)?;
    let listener = UnixListener::bind(socket).map_err(string_error)?;
    let _socket_guard = SocketPathGuard(socket.to_owned());
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660)).map_err(string_error)?;
    listener.set_nonblocking(true).map_err(string_error)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(
                        "journal-reader controller did not connect before the deadline".into(),
                    );
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    };
    stream.set_nonblocking(true).map_err(string_error)?;
    let peer = rustix::net::sockopt::socket_peercred(&stream).map_err(string_error)?;
    if peer.uid.as_raw() == rustix::process::geteuid().as_raw() {
        return Err("journal-reader and controller must use distinct OS identities".into());
    }
    let peer_pid = peer.pid.as_raw_pid();
    let peer_start_time = process_start_time_ticks(peer_pid)?;
    let peer_digest = hash_peer_executable(peer_pid)?;
    let (request_bytes, mut journal_snapshot) =
        read_request_and_snapshot_before(&mut stream, 524_288, deadline)?;
    if process_start_time_ticks(peer_pid)? != peer_start_time
        || hash_peer_executable(peer_pid)? != peer_digest
    {
        return Err("journal-reader peer executable changed during request".into());
    }
    let request = QualificationJournalDecisionRequestV1::from_json(&request_bytes)?;
    let context_bytes =
        Base64UrlUnpadded::decode_vec(&request.event_context_base64url).map_err(string_error)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let context = QualificationJournalDecisionContext::verify_json(
        &context_bytes,
        &trust,
        started_at,
        completed_at,
        now,
    )
    .map_err(string_error)?;
    let self_digest =
        hash_peer_executable(i32::try_from(std::process::id()).map_err(string_error)?)?;
    let (
        journal_reader_key_id,
        journal_reader_identity,
        journal_reader_artifact,
        journal_reader_uid,
    ) = trust
        .current_source_process_binding(
            QualificationEvidenceSource::JournalReader,
            domain,
            started_at,
            completed_at,
            now,
        )
        .map_err(string_error)?;
    let context_phase_matches = ledger_plan.phases.iter().any(|phase| {
        phase.scenario_id == context.record().scenario_id
            && phase.phase_index == context.record().phase_index
            && phase.role == context.record().role
            && phase.profile == context.record().profile
            && phase.operation_plan_sha256 == context.record().operation_plan_sha256
            && phase.failpoint == context.record().failpoint
    });
    if context.record().supervisor_controller_uid != peer.uid.as_raw()
        || context.record().journal_reader_uid != rustix::process::geteuid().as_raw()
        || context.record().supervisor_source_uid == context.record().journal_reader_uid
        || context.record().supervisor_source_uid == context.record().supervisor_controller_uid
        || context.record().supervisor_controller_artifact_sha256 != peer_digest
        || context.record().journal_reader_key_id != journal_reader_key_id
        || context.record().journal_reader_source_identity != journal_reader_identity
        || context.record().journal_reader_source_artifact_sha256 != journal_reader_artifact
        || context.record().journal_reader_uid != journal_reader_uid
        || rustix::process::geteuid().as_raw() != journal_reader_uid
        || self_digest != journal_reader_artifact
        || context.record().domain != domain
        || context.record().source_context_sha256 != source_context_sha256
        || !context_phase_matches
    {
        return Err("journal-reader request is not bound to its authenticated controller".into());
    }
    let journal_metadata = journal_snapshot.metadata().map_err(string_error)?;
    if request.journal_owner_uid != context.record().journal_owner_uid
        || journal_metadata.dev() != context.record().journal_device
        || journal_metadata.ino() != context.record().journal_inode
        || journal_metadata.uid() != context.record().journal_owner_uid
        || journal_metadata.mode() & 0o777 != context.record().journal_mode
        || journal_metadata.len() != context.record().journal_length
    {
        return Err(
            "journal snapshot descriptor differs from the signed supervisor context".into(),
        );
    }
    let (snapshot, event) = prepare_journal_decision(
        &request,
        &mut journal_snapshot,
        &context_bytes,
        &trust,
        domain,
        &source_context_sha256,
        started_at,
        completed_at,
        now,
    )?;
    let intent = hex::decode(event.intent_sha256().map_err(string_error)?).map_err(string_error)?;
    let append = QualificationSourceAppendSession::new(
        QualificationEvidenceSource::JournalReader,
        ledger_plan.clone(),
        trust.clone(),
        PathBuf::from(value(&values, "--sequencer-socket")?),
    );
    let mut seed = None;
    let (_, event) = append.append(
        intent,
        append_retry,
        deadline,
        |sequence, previous_event_sha256| {
            let mut event = event.clone();
            event.sequence = sequence;
            event.previous_event_sha256 = previous_event_sha256;
            event.durable_ack_sha256 = qualification_event_marker_sha256(
                sequence,
                QualificationEvidenceSource::JournalReader,
            );
            let signing_now = signing_time_before(deadline, "journal-reader source")?;
            event
                .validate_for_signing(
                    QualificationEvidenceSource::JournalReader,
                    &source_context_sha256,
                    &trust,
                    domain,
                    started_at,
                    completed_at,
                    signing_now,
                )
                .map_err(string_error)?;
            if seed.is_none() {
                seed = Some(read_seed_from_stdin_before(deadline)?);
            }
            event
                .clone()
                .sign_json(
                    QualificationEvidenceSource::JournalReader,
                    &source_context_sha256,
                    seed.as_ref()
                        .ok_or_else(|| "JournalReader source seed is absent".to_owned())?,
                    &trust,
                    domain,
                    started_at,
                    completed_at,
                    signing_now,
                )
                .map_err(string_error)
        },
    )?;
    signing_time_before(deadline, "journal-reader source response")?;
    let response = QualificationJournalDecisionResponseV1 {
        schema: "auths.qualification-journal-decision-response/1".into(),
        decision_snapshot_base64url: Base64UrlUnpadded::encode_string(&snapshot),
        event_base64url: Base64UrlUnpadded::encode_string(&event),
    }
    .to_json()?;
    stream.write_all(&response).map_err(string_error)?;
    stream.shutdown(Shutdown::Write).map_err(string_error)
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
fn run_journal_boundary_session(arguments: &[String]) -> Result<(), String> {
    let mut seed = None;
    run_journal_boundary_session_with_seed(arguments, &mut seed)
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
fn run_journal_boundary_session_with_seed(
    arguments: &[String],
    seed: &mut Option<Zeroizing<String>>,
) -> Result<(), String> {
    let values = exact_flag_values(
        arguments,
        "serve-boundary-session",
        &[
            "--socket",
            "--sequencer-socket",
            "--source-trust",
            "--ledger-plan",
            "--receipt-trust",
            "--scenario",
            "--phase-index",
        ],
    )?;
    reject_secret_environment()?;
    let trust = QualificationEvidenceSourceTrustRegistry::from_json(&read_bounded(
        Path::new(value(&values, "--source-trust")?),
        MAX_TRUST_BYTES,
        false,
    )?)
    .map_err(string_error)?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&read_bounded(
        Path::new(value(&values, "--ledger-plan")?),
        MAX_TRUST_BYTES,
        true,
    )?)
    .map_err(string_error)?;
    let receipt_trust = read_bounded(
        Path::new(value(&values, "--receipt-trust")?),
        MAX_RECEIPT_TRUST_BYTES,
        false,
    )?;
    decode_receipt_trust_anchors(&receipt_trust).map_err(string_error)?;
    let phase_index = value(&values, "--phase-index")?
        .parse::<u8>()
        .map_err(string_error)?;
    let phase = plan
        .phases
        .iter()
        .find(|phase| {
            phase.scenario_id == value(&values, "--scenario").unwrap_or_default()
                && phase.phase_index == phase_index
        })
        .cloned()
        .ok_or_else(|| "journal boundary phase is absent from the immutable plan".to_owned())?;
    let source_context_sha256 = plan.source_context_sha256().map_err(string_error)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let (key_id, source_identity, source_artifact, source_uid) = trust
        .current_source_process_binding(
            QualificationEvidenceSource::JournalReader,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
    let self_uid = rustix::process::geteuid().as_raw();
    let self_digest = qualification_source_process_executable_sha256()?;
    if self_uid != source_uid || self_digest != source_artifact {
        return Err("JournalReader process differs from protected source trust".into());
    }

    let socket = Path::new(value(&values, "--socket")?);
    validate_private_socket_path(socket)?;
    let listener = UnixListener::bind(socket).map_err(string_error)?;
    let _socket_guard = SocketPathGuard(socket.to_owned());
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660)).map_err(string_error)?;
    listener.set_nonblocking(true).map_err(string_error)?;
    let remaining = plan
        .deadline_at_unix_seconds
        .checked_sub(now)
        .filter(|seconds| *seconds != 0)
        .ok_or_else(|| {
            "journal boundary session started outside the protected interval".to_owned()
        })?;
    let deadline = Instant::now() + Duration::from_secs(remaining);
    let (mut controller, _) = accept_before(&listener, deadline, "JournalReader controller")?;
    controller.set_nonblocking(true).map_err(string_error)?;
    let controller_peer = QualificationSourceSessionPeer::observe(&controller)?;
    if controller_peer.uid() != plan.supervisor_controller_uid
        || controller_peer.executable_sha256() != plan.supervisor_controller_artifact_sha256
    {
        return Err("JournalReader controller differs from the immutable ledger plan".into());
    }
    let append = QualificationSourceAppendSession::new(
        QualificationEvidenceSource::JournalReader,
        plan.clone(),
        trust.clone(),
        PathBuf::from(value(&values, "--sequencer-socket")?),
    );
    let mut requests = 0_u16;
    loop {
        let Some((request_bytes, mut snapshot)) =
            read_framed_request_and_snapshot_before(&mut controller, 2_097_152, deadline)?
        else {
            break;
        };
        requests = requests
            .checked_add(1)
            .filter(|count| *count <= MAX_TYPED_SOURCE_SESSION_EVENTS)
            .ok_or_else(|| "journal boundary session exceeds its request bound".to_owned())?;
        controller_peer.verify_unchanged()?;
        let request = QualificationJournalBoundaryDrainRequestV1::from_json(&request_bytes)?;
        if request.journal_owner_uid != plan.agent_uid {
            return Err("journal boundary owner differs from the immutable agent".into());
        }
        let metadata = snapshot.metadata().map_err(string_error)?;
        if metadata.uid() != request.journal_owner_uid || metadata.mode() & 0o777 != 0o600 {
            return Err("journal boundary snapshot ownership is invalid".into());
        }
        let boundaries = read_persisted_qualification_boundaries_from_snapshot(
            &mut snapshot,
            request.journal_owner_uid,
        )
        .map_err(string_error)?;
        let records = read_persisted_operation_records_from_qualification_snapshot(
            &mut snapshot,
            request.journal_owner_uid,
        )
        .map_err(string_error)?;
        let admitted_profiles = admitted_phase_profiles(&plan, &phase);
        let record_bound = admitted_profiles
            .len()
            .checked_mul(8)
            .ok_or_else(|| "journal boundary roster bound overflowed".to_owned())?;
        let empty_phase = qualification_pre_admission_attempt_count(&phase.scenario_id).is_some();
        if records.len() > record_bound
            || (boundaries.is_empty() || records.is_empty()) && !empty_phase
        {
            return Err(
                "journal boundary roster is empty or exceeds the scenario prefix bound".into(),
            );
        }
        let records = records
            .into_iter()
            .map(|record| (record.operation_id().as_str().to_owned(), record))
            .collect::<BTreeMap<_, _>>();
        if records.values().any(|record| {
            let profile = format!(
                "{}/{}",
                record.binding().profile().id(),
                record.binding().profile().version()
            );
            record.binding().principal() != request.principal
                || !admitted_profiles.contains(profile.as_str())
        }) || boundaries.iter().any(|boundary| {
            !records.contains_key(boundary.operation_id().as_str())
                || !admitted_profiles.contains(
                    format!(
                        "{}/{}",
                        boundary.profile().id(),
                        boundary.profile().version()
                    )
                    .as_str(),
                )
        }) {
            return Err("journal boundary roster differs from the exact phase".into());
        }
        let boundaries = boundaries
            .iter()
            .filter(|boundary| {
                format!(
                    "{}/{}",
                    boundary.profile().id(),
                    boundary.profile().version()
                ) == phase.profile
            })
            .collect::<Vec<_>>();
        if boundaries.is_empty() && !empty_phase {
            return Err("journal boundary roster has no rows for the exact phase".into());
        }
        if empty_phase
            && (records.values().any(|record| {
                format!(
                    "{}/{}",
                    record.binding().profile().id(),
                    record.binding().profile().version()
                ) == phase.profile
            }) || !boundaries.is_empty())
        {
            return Err("journal boundary empty phase contains durable state".into());
        }
        if request.processes.len() != boundaries.len()
            || request
                .processes
                .iter()
                .zip(&boundaries)
                .any(|(process, boundary)| process.ordinal != boundary.ordinal())
        {
            return Err(
                "journal boundary process roster differs from the durable phase prefix".into(),
            );
        }

        let mut decisions = BTreeMap::new();
        for supplied in &request.decisions {
            let context_bytes =
                Base64UrlUnpadded::decode_vec(&supplied.supervisor_context_base64url)
                    .map_err(string_error)?;
            let snapshot_bytes =
                Base64UrlUnpadded::decode_vec(&supplied.decision_snapshot_base64url)
                    .map_err(string_error)?;
            let ack_bytes = Base64UrlUnpadded::decode_vec(&supplied.durable_ack_base64url)
                .map_err(string_error)?;
            let context = QualificationJournalDecisionContext::verify_json(
                &context_bytes,
                &trust,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                now,
            )
            .map_err(string_error)?;
            let context_record = context.record();
            let decision_snapshot = QualificationDecisionSnapshotV1::from_json(&snapshot_bytes)
                .map_err(string_error)?;
            let ack =
                QualificationDurableDecisionAckV1::from_json(&ack_bytes).map_err(string_error)?;
            let record = records
                .get(&supplied.operation_id)
                .ok_or_else(|| "decision context names an absent operation".to_owned())?;
            let decision_boundary = boundaries
                .iter()
                .find(|boundary| {
                    boundary.operation_id().as_str() == supplied.operation_id
                        && boundary.kind() == QualificationJournalBoundaryKindV1::Decision
                })
                .ok_or_else(|| "decision context has no durable boundary".to_owned())?;
            let decision_process = request
                .processes
                .iter()
                .find(|process| process.ordinal == decision_boundary.ordinal())
                .ok_or_else(|| "decision boundary process identity is absent".to_owned())?;
            let derived = derive_historical_decision_snapshot(
                record,
                &request.principal,
                &receipt_trust,
                &plan.recovery_key_id,
                &plan.recovery_public_key_base64url,
                now,
            )?;
            let decision_receipt_sha256: [u8; 32] =
                hex::decode(&decision_snapshot.decision_receipt_bytes_sha256)
                    .map_err(string_error)?
                    .try_into()
                    .map_err(|_| "decision receipt digest is malformed".to_owned())?;
            if supplied.operation_id != decision_snapshot.operation_id
                || decision_snapshot != derived
                || !plan
                    .binds_decision_context_common(context_record)
                    .map_err(string_error)?
                || context_record.scenario_id != phase.scenario_id
                || context_record.phase_index != phase.phase_index
                || context_record.role != phase.role
                || context_record.profile != phase.profile
                || context_record.operation_plan_sha256 != phase.operation_plan_sha256
                || context_record.failpoint != phase.failpoint
                || context_record.journal_reader_key_id != key_id
                || context_record.journal_reader_source_identity != source_identity
                || context_record.journal_reader_source_artifact_sha256 != source_artifact
                || context_record.journal_reader_uid != source_uid
                || context_record.operation_id != supplied.operation_id
                || context_record.boundary_ordinal != decision_boundary.ordinal()
                || context_record.boundary_projection_sha256
                    != hex::encode(decision_boundary.projection_sha256())
                || context_record.decision_snapshot_sha256
                    != hex::encode(Sha256::digest(&snapshot_bytes))
                || context_record.durable_ack_sha256 != hex::encode(Sha256::digest(&ack_bytes))
                || ack.operation_id != supplied.operation_id
                || ack.journal_revision != 1
                || ack.journal_record_sha256 != context_record.journal_record_sha256
                || ack.agent_generation != context_record.agent_generation
                || decision_process.agent_generation != context_record.agent_generation
                || decision_process.agent_process_id != context_record.agent_process_id
                || decision_process.agent_boot_sha256 != context_record.agent_boot_sha256
                || ack.control_operation_id != context_record.control_operation_id
                || ack.controller_nonce_sha256 != context_record.controller_nonce_sha256
                || decision_boundary.subject_sha256() != &decision_receipt_sha256
            {
                return Err(
                    "decision material differs from durable journal or protected policy".into(),
                );
            }
            if decisions
                .insert(
                    supplied.operation_id.clone(),
                    (context_bytes, context_record.clone(), decision_snapshot),
                )
                .is_some()
            {
                return Err("decision material is duplicated".into());
            }
        }
        let decision_count = boundaries
            .iter()
            .filter(|boundary| boundary.kind() == QualificationJournalBoundaryKindV1::Decision)
            .count();
        if decisions.len() != decision_count {
            return Err("decision material roster is incomplete".into());
        }

        let mut response_events = Vec::with_capacity(boundaries.len());
        for (boundary, process) in boundaries.iter().zip(&request.processes) {
            let record = records
                .get(boundary.operation_id().as_str())
                .ok_or_else(|| "journal boundary operation disappeared".to_owned())?;
            let decision = decisions
                .get(boundary.operation_id().as_str())
                .ok_or_else(|| "journal boundary decision context is absent".to_owned())?;
            let unsigned = journal_boundary_event(
                boundary,
                record,
                &decision.0,
                &decision.1,
                &decision.2,
                &receipt_trust,
                &phase,
                &source_context_sha256,
                key_id,
                source_identity,
                source_artifact,
                source_uid,
                process,
            )?;
            let intent = hex::decode(unsigned.intent_sha256().map_err(string_error)?)
                .map_err(string_error)?;
            let (_, signed) =
                append.resume_or_append(intent, deadline, |sequence, previous_event_sha256| {
                    let mut event = unsigned.clone();
                    event.sequence = sequence;
                    event.previous_event_sha256 = previous_event_sha256;
                    event.durable_ack_sha256 = qualification_event_marker_sha256(
                        sequence,
                        QualificationEvidenceSource::JournalReader,
                    );
                    let signing_now = signing_time_before(deadline, "journal boundary drain")?;
                    event
                        .validate_for_signing(
                            QualificationEvidenceSource::JournalReader,
                            &source_context_sha256,
                            &trust,
                            &plan.domain,
                            plan.started_at_unix_seconds,
                            plan.deadline_at_unix_seconds,
                            signing_now,
                        )
                        .map_err(string_error)?;
                    if seed.is_none() {
                        *seed = Some(read_seed_from_stdin_before(deadline)?);
                    }
                    event
                        .sign_json(
                            QualificationEvidenceSource::JournalReader,
                            &source_context_sha256,
                            seed.as_ref()
                                .ok_or_else(|| "JournalReader source seed is absent".to_owned())?,
                            &trust,
                            &plan.domain,
                            plan.started_at_unix_seconds,
                            plan.deadline_at_unix_seconds,
                            signing_now,
                        )
                        .map_err(string_error)
                })?;
            response_events.push(QualificationJournalBoundaryEventV1 {
                ordinal: boundary.ordinal(),
                operation_id: boundary.operation_id().as_str().to_owned(),
                event_sha256: hex::encode(Sha256::digest(&signed)),
            });
        }
        let response = QualificationJournalBoundaryDrainResponseV1 {
            schema: "auths.qualification-journal-boundary-drain-response/1".into(),
            events: response_events,
        }
        .to_json()?;
        write_bounded_session_frame_before(&mut controller, &response, 2_097_152, deadline)?;
        let acknowledgement = read_source_session_frame_before(&mut controller, deadline)?
            .ok_or_else(|| {
                "JournalReader controller closed before acknowledging drain".to_owned()
            })?;
        if acknowledgement != [1] {
            return Err("JournalReader controller acknowledgement is malformed".into());
        }
        controller_peer.verify_unchanged()?;
    }
    if requests == 0 {
        return Err("journal boundary session received no durable boundary".into());
    }
    controller.shutdown(Shutdown::Write).map_err(string_error)
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn journal_boundary_event(
    boundary: &QualificationJournalBoundaryV1,
    record: &JournalRecordV1,
    context_bytes: &[u8],
    context: &QualificationJournalDecisionContextRecord,
    decision: &QualificationDecisionSnapshotV1,
    receipt_trust: &[u8],
    phase: &QualificationEvidencePhasePlanV1,
    source_context_sha256: &str,
    source_key_id: &str,
    source_identity: &str,
    source_artifact_sha256: &str,
    source_uid: u32,
    process: &QualificationJournalBoundaryProcessV1,
) -> Result<QualificationEvidenceEvent, String> {
    if boundary.operation_id() != record.operation_id()
        || context.operation_id != record.operation_id().as_str()
        || decision.operation_id != record.operation_id().as_str()
        || process.ordinal != boundary.ordinal()
    {
        return Err("journal boundary operation binding is inconsistent".into());
    }
    let request_id = boundary
        .request_id()
        .map(|request| Base64UrlUnpadded::encode_string(request.as_bytes()));
    let subject_sha256 = hex::encode(boundary.subject_sha256());
    let projection_sha256 = hex::encode(boundary.projection_sha256());
    let (kind, payload) = match boundary.kind() {
        QualificationJournalBoundaryKindV1::Decision => (
            QualificationEvidenceEventKind::DecisionDurable,
            decision.decision_payload(hex::encode(Sha256::digest(context_bytes))),
        ),
        QualificationJournalBoundaryKindV1::Command => (
            QualificationEvidenceEventKind::CommandDurable,
            QualificationEvidenceEventPayload::Command {
                sealed_command_sha256: subject_sha256,
            },
        ),
        QualificationJournalBoundaryKindV1::ProviderEntry => (
            QualificationEvidenceEventKind::ProviderEntryDurable,
            QualificationEvidenceEventPayload::ProviderEntry {
                sealed_command_sha256: subject_sha256,
            },
        ),
        QualificationJournalBoundaryKindV1::ProviderResult => (
            QualificationEvidenceEventKind::ProviderResultDurable,
            QualificationEvidenceEventPayload::ProviderResult {
                provider_result_sha256: subject_sha256,
            },
        ),
        QualificationJournalBoundaryKindV1::Observation => (
            QualificationEvidenceEventKind::ObservationDurable,
            QualificationEvidenceEventPayload::Observation {
                observation_sha256: subject_sha256,
            },
        ),
        QualificationJournalBoundaryKindV1::ExecutionReceipt => {
            let artifact = verified_execution_receipt_artifact(record, boundary, receipt_trust)?;
            (
                QualificationEvidenceEventKind::ExecutionReceiptDurable,
                QualificationEvidenceEventPayload::ExecutionReceipt {
                    execution_receipt_id: artifact.receipt_id,
                    receipt_bytes_sha256: hex::encode(boundary.subject_sha256()),
                    decoded_claims_sha256: artifact.decoded_claims_sha256,
                    execution_result_sha256: record.execution_result_commitment().map(hex::encode),
                    execution_outcome: match record
                        .execution_outcome()
                        .ok_or_else(|| "execution receipt has no durable outcome".to_owned())?
                    {
                        JournalExecutionOutcomeV1::Succeeded => {
                            QualificationReceiptExecutionOutcome::Succeeded
                        }
                        JournalExecutionOutcomeV1::Failed => {
                            QualificationReceiptExecutionOutcome::Failed
                        }
                        JournalExecutionOutcomeV1::Indeterminate => {
                            QualificationReceiptExecutionOutcome::Indeterminate
                        }
                    },
                },
            )
        }
        QualificationJournalBoundaryKindV1::RecoveryRequired => (
            QualificationEvidenceEventKind::RecoveryRequiredDurable,
            journal_projection_payload(boundary, projection_sha256)?,
        ),
        QualificationJournalBoundaryKindV1::Terminal => (
            QualificationEvidenceEventKind::TerminalDurable,
            QualificationEvidenceEventPayload::Terminal {
                state: qualification_outcome(boundary.state())?,
                effect: qualification_effect(boundary.effect()),
                execution_result_sha256: record.execution_result_commitment().map(hex::encode),
                completion: boundary.completion().map(qualification_completion),
            },
        ),
        QualificationJournalBoundaryKindV1::Replay => (
            QualificationEvidenceEventKind::ReplayObserved,
            journal_projection_payload(boundary, projection_sha256)?,
        ),
        QualificationJournalBoundaryKindV1::Status => (
            QualificationEvidenceEventKind::StatusObserved,
            journal_projection_payload(boundary, projection_sha256)?,
        ),
        QualificationJournalBoundaryKindV1::Recovery => (
            QualificationEvidenceEventKind::RecoveryObserved,
            journal_projection_payload(boundary, projection_sha256)?,
        ),
    };
    Ok(QualificationEvidenceEvent {
        sequence: 0,
        previous_event_sha256: "0".repeat(64),
        scenario_id: phase.scenario_id.clone(),
        phase_index: phase.phase_index,
        role: phase.role,
        profile: phase.profile.clone(),
        failpoint: phase.failpoint,
        source: QualificationEvidenceSource::JournalReader,
        source_identity: source_identity.to_owned(),
        source_artifact_sha256: source_artifact_sha256.to_owned(),
        source_uid: Some(source_uid),
        reader_identity: None,
        reader_artifact_sha256: None,
        reader_uid: None,
        source_context_sha256: source_context_sha256.to_owned(),
        source_key_id: source_key_id.to_owned(),
        source_signature_base64url: String::new(),
        supervisor_generation: context.supervisor_generation,
        agent_generation: Some(process.agent_generation),
        agent_process_id: Some(process.agent_process_id),
        agent_boot_sha256: Some(process.agent_boot_sha256.clone()),
        operation_id: Some(record.operation_id().as_str().to_owned()),
        control_operation_id: None,
        request_id,
        client_result_sha256: None,
        receipt_id: None,
        connection_generation: Some(
            boundary
                .connection_generation()
                .ok_or_else(|| "journal boundary has no connection generation".to_owned())?
                .to_string(),
        ),
        journal_revision: Some(boundary.journal_revision()),
        kind,
        payload,
        durable_ack_sha256: String::new(),
    })
}

#[cfg(target_os = "linux")]
fn journal_projection_payload(
    boundary: &QualificationJournalBoundaryV1,
    projection_sha256: String,
) -> Result<QualificationEvidenceEventPayload, String> {
    let state = match boundary.state() {
        OperationStateV1::Ready => QualificationJournalState::Ready,
        OperationStateV1::Executing => QualificationJournalState::Executing,
        OperationStateV1::RecoveryRequired => QualificationJournalState::RecoveryRequired,
        OperationStateV1::Denied => QualificationJournalState::Denied,
        OperationStateV1::Unavailable => QualificationJournalState::Unavailable,
        OperationStateV1::Completed => QualificationJournalState::Completed,
        OperationStateV1::Partial => QualificationJournalState::Partial,
        OperationStateV1::NotApplied => QualificationJournalState::NotApplied,
        OperationStateV1::Preparing => {
            return Err("journal boundary exposes a preparing projection".into());
        }
    };
    Ok(QualificationEvidenceEventPayload::JournalProjection {
        projection_sha256,
        state,
        effect: qualification_effect(boundary.effect()),
        terminal: boundary.terminal(),
        completion: boundary.completion().map(qualification_completion),
    })
}

#[cfg(target_os = "linux")]
fn verified_execution_receipt_artifact(
    record: &JournalRecordV1,
    boundary: &QualificationJournalBoundaryV1,
    receipt_trust: &[u8],
) -> Result<VerifiedReceiptArtifact, String> {
    let index = usize::from(
        boundary
            .subject_index()
            .ok_or_else(|| "execution receipt boundary has no subject index".to_owned())?,
    );
    if index != 1 {
        return Err("execution receipt boundary does not name the linked receipt".into());
    }
    let receipt = record
        .receipts()
        .get(index)
        .ok_or_else(|| "execution receipt boundary names an absent receipt".to_owned())?;
    let anchors = decode_receipt_trust_anchors(receipt_trust).map_err(string_error)?;
    let profile = record.binding().profile();
    let profile_ref = auths_model::ProfileRef::new(
        auths_model::ProfileId::parse(profile.id()).map_err(string_error)?,
        profile.version(),
    )
    .map_err(string_error)?;
    let verified = verify_portable_receipt_with_anchors(
        receipt.bytes(),
        &anchors,
        Some(&profile_ref),
        Some(record.operation_id().as_str()),
    )
    .map_err(string_error)?;
    let expected_outcome = record.execution_outcome().map(|outcome| match outcome {
        JournalExecutionOutcomeV1::Succeeded => ExecutionOutcome::Succeeded,
        JournalExecutionOutcomeV1::Failed => ExecutionOutcome::Failed,
        JournalExecutionOutcomeV1::Indeterminate => ExecutionOutcome::Indeterminate,
    });
    if verified.portable_id() != receipt.receipt_id()
        || verified.execution_outcome() != expected_outcome
        || verified.execution_result() != record.execution_result_commitment()
        || verified.execution_command().copied()
            != record
                .sealed_command()
                .map(|command| Sha256::digest(command).into())
    {
        return Err("execution receipt differs from durable journal truth".into());
    }
    Ok(VerifiedReceiptArtifact {
        receipt_id: receipt.receipt_id().to_owned(),
        bytes: receipt.bytes().to_vec(),
        decoded_claims_sha256: hex::encode(
            verified_portable_receipt_claims_digest(
                &verified,
                Some(record.operation_id().as_str()),
            )
            .map_err(string_error)?,
        ),
    })
}

#[cfg(target_os = "linux")]
fn qualification_outcome(state: OperationStateV1) -> Result<QualificationOutcomeKind, String> {
    match state {
        OperationStateV1::Denied => Ok(QualificationOutcomeKind::Denied),
        OperationStateV1::Unavailable => Ok(QualificationOutcomeKind::Unavailable),
        OperationStateV1::Completed => Ok(QualificationOutcomeKind::Completed),
        OperationStateV1::Partial => Ok(QualificationOutcomeKind::Partial),
        OperationStateV1::NotApplied => Ok(QualificationOutcomeKind::NotApplied),
        _ => Err("terminal journal boundary has a nonterminal state".into()),
    }
}

#[cfg(target_os = "linux")]
const fn qualification_effect(effect: OperationEffectV1) -> QualificationEffect {
    match effect {
        OperationEffectV1::NotApplied => QualificationEffect::NotApplied,
        OperationEffectV1::Possible => QualificationEffect::Possible,
        OperationEffectV1::Applied => QualificationEffect::Applied,
    }
}

#[cfg(target_os = "linux")]
const fn qualification_completion(completion: JournalCompletionV1) -> QualificationCompletion {
    match completion {
        JournalCompletionV1::Fresh => QualificationCompletion::Fresh,
        JournalCompletionV1::Replayed => QualificationCompletion::Replayed,
        JournalCompletionV1::Reconciled => QualificationCompletion::Reconciled,
    }
}

#[cfg(not(target_os = "linux"))]
fn run_journal_reader(_arguments: &[String]) -> Result<(), String> {
    Err("the authenticated journal-reader channel is supported only on Linux".into())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn prepare_journal_decision(
    request: &QualificationJournalDecisionRequestV1,
    journal_snapshot: &mut File,
    context_bytes: &[u8],
    trust: &QualificationEvidenceSourceTrustRegistry,
    domain: &str,
    source_context_sha256: &str,
    started_at: u64,
    completed_at: u64,
    now: u64,
) -> Result<(Vec<u8>, QualificationEvidenceEvent), String> {
    let operation = auths_lifecycle::OperationIdV1::parse(&request.operation)
        .map_err(|_| "operation ID is malformed".to_owned())?;
    let boundaries = read_persisted_qualification_boundaries_from_snapshot(
        journal_snapshot,
        request.journal_owner_uid,
    )
    .map_err(string_error)?;
    let mut decisions = boundaries.iter().filter(|boundary| {
        boundary.operation_id() == &operation
            && boundary.kind() == QualificationJournalBoundaryKindV1::Decision
    });
    let decision_boundary = decisions
        .next()
        .ok_or_else(|| "durable decision boundary is absent from the journal".to_owned())?;
    if decisions.next().is_some() {
        return Err("durable decision boundary is duplicated in the journal".into());
    }
    let record = read_persisted_operation_record_from_qualification_snapshot(
        journal_snapshot,
        request.journal_owner_uid,
        &request.principal,
        &operation,
    )
    .map_err(string_error)?;
    record.validate_exact_decision_snapshot().map_err(|_| {
        "journal record is not the exact first durable decision snapshot".to_owned()
    })?;
    let context = QualificationJournalDecisionContext::verify_json(
        context_bytes,
        trust,
        started_at,
        completed_at,
        now,
    )
    .map_err(string_error)?;
    let context = context.record();
    if context.domain != domain
        || context.source_context_sha256 != source_context_sha256
        || context.operation_id != record.operation_id().as_str()
        || context.journal_revision != record.revision()
        || context.boundary_ordinal != decision_boundary.ordinal()
        || context.boundary_projection_sha256 != hex::encode(decision_boundary.projection_sha256())
        || context.journal_record_sha256
            != hex::encode(Sha256::digest(
                serde_json_canonicalizer::to_vec(&record).map_err(string_error)?,
            ))
    {
        return Err("supervisor context differs from the durable decision or run".into());
    }
    let receipt_trust_bytes =
        Base64UrlUnpadded::decode_vec(&request.receipt_trust_base64url).map_err(string_error)?;
    if receipt_trust_bytes.is_empty()
        || u64::try_from(receipt_trust_bytes.len()).map_err(string_error)? > MAX_RECEIPT_TRUST_BYTES
    {
        return Err("receipt trust exceeds its hard bound".into());
    }
    let decision_snapshot = derive_qualification_decision_snapshot(
        &record,
        &request.principal,
        &receipt_trust_bytes,
        &request.recovery_key_id,
        &request.recovery_public_key_base64url,
        now,
    )?;
    let decision_snapshot_bytes = decision_snapshot.to_json().map_err(string_error)?;
    if hex::encode(Sha256::digest(&decision_snapshot_bytes)) != context.decision_snapshot_sha256 {
        return Err("supervisor context differs from the public decision snapshot".into());
    }
    let event = QualificationEvidenceEvent {
        sequence: 0,
        previous_event_sha256: "0".repeat(64),
        scenario_id: context.scenario_id.clone(),
        phase_index: context.phase_index,
        role: context.role,
        profile: decision_snapshot.profile.clone(),
        failpoint: context.failpoint,
        source: QualificationEvidenceSource::JournalReader,
        source_identity: context.journal_reader_source_identity.clone(),
        source_artifact_sha256: context.journal_reader_source_artifact_sha256.clone(),
        source_uid: Some(context.journal_reader_uid),
        reader_identity: None,
        reader_artifact_sha256: None,
        reader_uid: None,
        source_context_sha256: context.source_context_sha256.clone(),
        source_key_id: context.journal_reader_key_id.clone(),
        source_signature_base64url: String::new(),
        supervisor_generation: context.supervisor_generation,
        agent_generation: Some(context.agent_generation),
        agent_process_id: Some(context.agent_process_id),
        agent_boot_sha256: Some(context.agent_boot_sha256.clone()),
        operation_id: Some(record.operation_id().as_str().to_owned()),
        // DecisionDurable is the journal reader's observation of the durable
        // business operation, not one of the supervisor's three crash-control
        // actions. The retained signed context and durable acknowledgement
        // carry the launch control identity without widening the public event
        // grammar for decision events.
        control_operation_id: None,
        request_id: None,
        client_result_sha256: None,
        receipt_id: None,
        connection_generation: Some(decision_snapshot.connection_generation.clone()),
        journal_revision: Some(record.revision()),
        kind: QualificationEvidenceEventKind::DecisionDurable,
        payload: decision_snapshot.decision_payload(hex::encode(Sha256::digest(context_bytes))),
        durable_ack_sha256: String::new(),
    };
    Ok((decision_snapshot_bytes, event))
}

#[cfg(any(target_os = "linux", test))]
fn exact_flag_values<'a>(
    arguments: &'a [String],
    command: &str,
    expected_flags: &[&str],
) -> Result<BTreeMap<&'a str, &'a str>, String> {
    exact_flag_values_for(arguments, command, expected_flags, journal_reader_usage)
}

#[cfg(any(target_os = "linux", test))]
fn exact_flag_values_for<'a>(
    arguments: &'a [String],
    command: &str,
    expected_flags: &[&str],
    usage: fn() -> String,
) -> Result<BTreeMap<&'a str, &'a str>, String> {
    if arguments.first().map(String::as_str) != Some(command)
        || arguments.len() != 1 + expected_flags.len() * 2
    {
        return Err(usage());
    }
    let expected = expected_flags.iter().copied().collect::<BTreeSet<_>>();
    let mut values = BTreeMap::new();
    for pair in arguments[1..].chunks_exact(2) {
        let flag = pair[0].as_str();
        if !expected.contains(flag)
            || pair[1].is_empty()
            || values.insert(flag, pair[1].as_str()).is_some()
        {
            return Err(usage());
        }
    }
    if values.len() != expected.len() {
        return Err(usage());
    }
    Ok(values)
}

#[cfg(target_os = "linux")]
fn value<'a>(values: &'a BTreeMap<&str, &'a str>, flag: &str) -> Result<&'a str, String> {
    values.get(flag).copied().ok_or_else(journal_reader_usage)
}

#[cfg(target_os = "linux")]
fn value_for<'a>(
    values: &'a BTreeMap<&str, &'a str>,
    flag: &str,
    usage: fn() -> String,
) -> Result<&'a str, String> {
    values.get(flag).copied().ok_or_else(usage)
}

#[cfg(target_os = "linux")]
fn open_directory_componentwise(path: &Path) -> Result<File, String> {
    let mut directory = File::from(
        open(
            if path.is_absolute() {
                Path::new("/")
            } else {
                Path::new(".")
            },
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    for component in path.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            _ => return Err("qualification source path has an unsafe component".into()),
        };
        directory = File::from(
            openat(
                &directory,
                Path::new(name),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn validate_provider_proxy_transport_root(
    path: &Path,
    plan: &QualificationEvidenceLedgerPlanV1,
) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err("ProviderProxy transport root is not normalized and absolute".into());
    }
    let directory = open_directory_componentwise(path)?;
    let metadata = directory.metadata().map_err(string_error)?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.gid() != plan.agent_gid
        || metadata.mode() & 0o777 != 0o700
        || metadata.nlink() < 2
    {
        return Err("ProviderProxy transport root differs from protected topology".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_shared_reader_socket_path(
    path: &Path,
    plan: &QualificationEvidenceLedgerPlanV1,
) -> Result<(u64, u64), String> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err("protected reader socket path is not normalized and absolute".into());
    }
    let parent = open_directory_componentwise(
        path.parent()
            .ok_or_else(|| "protected reader socket has no parent".to_owned())?,
    )?;
    let metadata = parent.metadata().map_err(string_error)?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.gid() != plan.agent_gid
        || rustix::process::getegid().as_raw() != plan.agent_gid
        || metadata.mode() & 0o777 != 0o710
    {
        return Err("reader socket parent is not exact protected shared state".into());
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok((metadata.dev(), metadata.ino()))
        }
        Err(error) => Err(string_error(error)),
        Ok(_) => Err("protected reader socket path already exists".into()),
    }
}

#[cfg(target_os = "linux")]
fn validate_shared_reader_socket_path_after_bind(
    path: &Path,
    plan: &QualificationEvidenceLedgerPlanV1,
) -> Result<(u64, u64), String> {
    let parent = open_directory_componentwise(
        path.parent()
            .ok_or_else(|| "protected reader socket has no parent".to_owned())?,
    )?;
    let parent_metadata = parent.metadata().map_err(string_error)?;
    let socket = fs::symlink_metadata(path).map_err(string_error)?;
    if parent_metadata.uid() != rustix::process::geteuid().as_raw()
        || parent_metadata.gid() != plan.agent_gid
        || parent_metadata.mode() & 0o777 != 0o710
        || !socket.file_type().is_socket()
        || socket.uid() != rustix::process::geteuid().as_raw()
        || socket.gid() != plan.agent_gid
    {
        return Err("reader listener is not exact protected shared state".into());
    }
    Ok((parent_metadata.dev(), parent_metadata.ino()))
}

#[cfg(target_os = "linux")]
fn validate_agent_socket_path(
    path: &Path,
    plan: &QualificationEvidenceLedgerPlanV1,
) -> Result<(), String> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err("qualification agent socket path is not normalized and absolute".into());
    }
    let parent = open_directory_componentwise(
        path.parent()
            .ok_or_else(|| "qualification agent socket has no parent".to_owned())?,
    )?;
    let parent = parent.metadata().map_err(string_error)?;
    let socket = fs::symlink_metadata(path).map_err(string_error)?;
    if parent.uid() != plan.agent_uid
        || parent.gid() != plan.agent_gid
        || parent.mode() & 0o777 != 0o710
        || !socket.file_type().is_socket()
        || socket.uid() != plan.agent_uid
        || socket.gid() != plan.agent_gid
        || socket.mode() & 0o777 != 0o660
    {
        return Err("qualification agent socket differs from immutable launch policy".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_private_socket_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > 1_024
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.file_name().is_none()
    {
        return Err("supervisor source socket path is not normalized and absolute".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "supervisor source socket has no parent".to_owned())?;
    let metadata = fs::symlink_metadata(parent).map_err(string_error)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o007 != 0
    {
        return Err("supervisor source socket parent is not owner-only".into());
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(string_error(error)),
        Ok(_) => Err("supervisor source socket path already exists".into()),
    }
}

#[cfg(target_os = "linux")]
fn accept_optional_before(listener: &UnixListener) -> Result<Option<UnixStream>, String> {
    match listener.accept() {
        Ok((stream, _)) => {
            stream.set_nonblocking(true).map_err(string_error)?;
            Ok(Some(stream))
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(string_error(error)),
    }
}

#[cfg(target_os = "linux")]
fn accept_phase_reader_stop(
    stream: &mut UnixStream,
    plan: &QualificationEvidenceLedgerPlanV1,
    in_flight: &AtomicUsize,
    ready: &dyn Fn() -> bool,
    deadline: Instant,
    role: &str,
) -> Result<(), String> {
    const STOP: &[u8] = b"AUTHS-QUALIFICATION-PHASE-READER-STOP/1";
    let peer = QualificationSourceSessionPeer::observe(stream)?;
    if peer.uid() != plan.supervisor_controller_uid
        || peer.executable_sha256() != plan.supervisor_controller_artifact_sha256
    {
        return Err(format!(
            "{role} control peer differs from the immutable controller"
        ));
    }
    let request = read_source_session_frame_before(stream, deadline)?
        .ok_or_else(|| format!("{role} control peer sent no stop request"))?;
    if request != STOP || read_source_session_frame_before(stream, deadline)?.is_some() {
        return Err(format!("{role} control request is malformed"));
    }
    while in_flight.load(Ordering::Acquire) != 0 || !ready() {
        if Instant::now() >= deadline {
            return Err(format!(
                "{role} did not become quiescent before its deadline"
            ));
        }
        thread::sleep(Duration::from_millis(2));
    }
    peer.verify_unchanged()?;
    write_source_session_frame_before(stream, &[1], deadline)?;
    let acknowledgement = read_source_session_frame_before(stream, deadline)?
        .ok_or_else(|| format!("{role} controller closed before its final acknowledgement"))?;
    if acknowledgement != [1] || read_source_session_frame_before(stream, deadline)?.is_some() {
        return Err(format!(
            "{role} controller final acknowledgement is malformed"
        ));
    }
    peer.verify_unchanged()?;
    stream.shutdown(Shutdown::Write).map_err(string_error)
}

#[cfg(target_os = "linux")]
fn accept_before(
    listener: &UnixListener,
    deadline: Instant,
    peer_label: &str,
) -> Result<(UnixStream, std::os::unix::net::SocketAddr), String> {
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "{peer_label} did not connect before the total deadline"
            ));
        }
        match listener.accept() {
            Ok(connection) => return Ok(connection),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
}

#[cfg(target_os = "linux")]
fn read_request_and_snapshot_before(
    stream: &mut std::os::unix::net::UnixStream,
    maximum: usize,
    deadline: Instant,
) -> Result<(Vec<u8>, File), String> {
    let mut first = [0_u8; 8_192];
    let (length, descriptors) = loop {
        if Instant::now() >= deadline {
            return Err("journal-reader descriptor request exceeded its deadline".into());
        }
        let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = rustix::net::RecvAncillaryBuffer::new(&mut ancillary_space);
        let result = {
            let mut slices = [IoSliceMut::new(&mut first)];
            rustix::net::recvmsg(
                &*stream,
                &mut slices,
                &mut ancillary,
                rustix::net::RecvFlags::CMSG_CLOEXEC,
            )
        };
        match result {
            Ok(message) => {
                if !message.flags.is_empty() {
                    return Err(
                        "journal-reader request ancillary data was truncated or malformed".into(),
                    );
                }
                let mut descriptors = Vec::<OwnedFd>::new();
                for message in ancillary.drain() {
                    if let rustix::net::RecvAncillaryMessage::ScmRights(rights) = message {
                        descriptors.extend(rights);
                    } else {
                        return Err(
                            "journal-reader request carried a forbidden ancillary message".into(),
                        );
                    }
                }
                break (message.bytes, descriptors);
            }
            Err(error) if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::INTR => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    };
    if length == 0 || length > maximum || descriptors.len() != 1 {
        return Err(
            "journal-reader request must carry exactly one bounded snapshot descriptor".into(),
        );
    }
    let mut bytes = first[..length].to_vec();
    let remaining = read_socket_before(stream, maximum - bytes.len(), deadline)?;
    if bytes
        .len()
        .checked_add(remaining.len())
        .is_none_or(|total| total > maximum)
    {
        return Err("journal-reader request exceeds its hard bound".into());
    }
    bytes.extend_from_slice(&remaining);
    let descriptor = descriptors
        .into_iter()
        .next()
        .ok_or_else(|| "journal snapshot descriptor is absent".to_owned())?;
    Ok((bytes, File::from(descriptor)))
}

#[cfg(target_os = "linux")]
fn read_framed_request_and_snapshot_before(
    stream: &mut UnixStream,
    maximum: usize,
    deadline: Instant,
) -> Result<Option<(Vec<u8>, File)>, String> {
    let Some((request, mut descriptors)) =
        read_framed_request_and_snapshots_before(stream, maximum, 1, deadline)?
    else {
        return Ok(None);
    };
    let descriptor = descriptors
        .pop()
        .ok_or_else(|| "snapshot descriptor is absent".to_owned())?;
    Ok(Some((request, descriptor)))
}

#[cfg(target_os = "linux")]
fn read_framed_request_and_snapshots_before(
    stream: &mut UnixStream,
    maximum: usize,
    descriptor_count: usize,
    deadline: Instant,
) -> Result<Option<(Vec<u8>, Vec<File>)>, String> {
    if maximum == 0 || maximum > u32::MAX as usize {
        return Err("snapshot request frame bound is invalid".into());
    }
    if !(1..=2).contains(&descriptor_count) {
        return Err("snapshot descriptor count is outside its bound".into());
    }
    let mut first = [0_u8; 8_192];
    let (length, descriptors) = loop {
        if Instant::now() >= deadline {
            return Err("snapshot request frame exceeded its deadline".into());
        }
        let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = rustix::net::RecvAncillaryBuffer::new(&mut ancillary_space);
        let result = {
            let mut slices = [IoSliceMut::new(&mut first)];
            rustix::net::recvmsg(
                &*stream,
                &mut slices,
                &mut ancillary,
                rustix::net::RecvFlags::CMSG_CLOEXEC,
            )
        };
        match result {
            Ok(message) => {
                if !message.flags.is_empty() {
                    return Err("snapshot request ancillary data was malformed".into());
                }
                let mut descriptors = Vec::<OwnedFd>::new();
                for message in ancillary.drain() {
                    if let rustix::net::RecvAncillaryMessage::ScmRights(rights) = message {
                        descriptors.extend(rights);
                    } else {
                        return Err("snapshot request carried forbidden ancillary data".into());
                    }
                }
                break (message.bytes, descriptors);
            }
            Err(error) if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::INTR => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    };
    if length == 0 && descriptors.is_empty() {
        return Ok(None);
    }
    if length == 0 || descriptors.len() != descriptor_count {
        return Err("snapshot request carried the wrong descriptor count".into());
    }
    let mut frame = first[..length].to_vec();
    while frame.len() < 4 {
        let mut header = [0_u8; 4];
        let read = read_exact_before(stream, &mut header[..4 - frame.len()], deadline)?;
        frame.extend_from_slice(&header[..read]);
    }
    let payload_length = usize::try_from(u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| "snapshot request frame header is malformed".to_owned())?,
    ))
    .map_err(string_error)?;
    if payload_length == 0 || payload_length > maximum {
        return Err("snapshot request frame length is outside its bound".into());
    }
    let frame_length = payload_length
        .checked_add(4)
        .ok_or_else(|| "snapshot request frame length overflowed".to_owned())?;
    if frame.len() > frame_length {
        return Err("snapshot request carried trailing frame bytes".into());
    }
    if frame.len() < frame_length {
        let mut remaining = vec![0_u8; frame_length - frame.len()];
        read_exact_before(stream, &mut remaining, deadline)?;
        frame.extend_from_slice(&remaining);
    }
    Ok(Some((
        frame[4..].to_vec(),
        descriptors.into_iter().map(File::from).collect(),
    )))
}

#[cfg(target_os = "linux")]
fn read_exact_before(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<usize, String> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err("protected socket read exceeded its deadline".into());
        }
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err("protected socket closed inside a frame".into()),
            Ok(read) => offset += read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
    Ok(offset)
}

#[cfg(target_os = "linux")]
fn read_socket_before(
    stream: &mut impl Read,
    maximum: usize,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8_192];
    loop {
        if Instant::now() >= deadline {
            return Err("journal-reader request exceeded its total deadline".into());
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(length) => {
                if bytes
                    .len()
                    .checked_add(length)
                    .is_none_or(|total| total > maximum)
                {
                    return Err("journal-reader request exceeds its hard bound".into());
                }
                bytes.extend_from_slice(&chunk[..length]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
    Ok(bytes)
}

#[cfg(any(target_os = "linux", test))]
/// Reads one bounded big-endian length-prefixed protected-source frame before
/// the shared monotonic deadline. EOF before a new header ends the session.
pub fn read_source_session_frame_before(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Option<Vec<u8>>, String> {
    read_bounded_session_frame_before(stream, MAX_CONTEXT_BYTES as usize, deadline)
}

#[cfg(any(target_os = "linux", test))]
/// Reads one big-endian length-prefixed frame under a caller-owned hard bound.
pub fn read_bounded_session_frame_before(
    stream: &mut UnixStream,
    maximum: usize,
    deadline: Instant,
) -> Result<Option<Vec<u8>>, String> {
    if maximum == 0 || maximum > u32::MAX as usize {
        return Err("protected frame bound is invalid".into());
    }
    let mut header = [0_u8; 4];
    let mut offset = 0_usize;
    while offset < header.len() {
        if Instant::now() >= deadline {
            return Err("typed source frame exceeded its total deadline".into());
        }
        match stream.read(&mut header[offset..]) {
            Ok(0) if offset == 0 => return Ok(None),
            Ok(0) => return Err("typed source frame ended inside its length header".into()),
            Ok(length) => offset += length,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
    let length = usize::try_from(u32::from_be_bytes(header)).map_err(string_error)?;
    if length == 0 || length > maximum {
        return Err("typed source frame length is outside its bound".into());
    }
    let mut bytes = vec![0_u8; length];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err("typed source frame exceeded its total deadline".into());
        }
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err("typed source frame ended before its declared length".into()),
            Ok(length) => offset += length,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
    Ok(Some(bytes))
}

#[cfg(any(target_os = "linux", test))]
/// Writes one bounded big-endian length-prefixed protected-source frame before
/// the shared monotonic deadline.
pub fn write_source_session_frame_before(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    write_bounded_session_frame_before(stream, bytes, MAX_CONTEXT_BYTES as usize, deadline)
}

#[cfg(any(target_os = "linux", test))]
/// Writes one big-endian length-prefixed frame under a caller-owned hard bound.
pub fn write_bounded_session_frame_before(
    stream: &mut UnixStream,
    bytes: &[u8],
    maximum: usize,
    deadline: Instant,
) -> Result<(), String> {
    if maximum == 0 || maximum > u32::MAX as usize {
        return Err("protected frame bound is invalid".into());
    }
    let length = u32::try_from(bytes.len())
        .ok()
        .filter(|length| *length != 0 && *length as usize <= maximum)
        .ok_or_else(|| "typed source response frame is outside its bound".to_owned())?;
    let mut frame = Vec::with_capacity(bytes.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(bytes);
    let mut offset = 0_usize;
    while offset < frame.len() {
        if Instant::now() >= deadline {
            return Err("typed source response exceeded its total deadline".into());
        }
        match stream.write(&frame[offset..]) {
            Ok(0) => return Err("typed source response made no write progress".into()),
            Ok(length) => offset += length,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(string_error(error)),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn hash_peer_executable(pid: i32) -> Result<String, String> {
    const MAX_EXECUTABLE_BYTES: u64 = 536_870_912;
    if pid <= 0 {
        return Err("supervisor source peer PID is invalid".into());
    }
    let path = PathBuf::from(format!("/proc/{pid}/exe"));
    let mut file = File::open(path).map_err(string_error)?;
    let before = file.metadata().map_err(string_error)?;
    if !before.file_type().is_file() || before.len() == 0 || before.len() > MAX_EXECUTABLE_BYTES {
        return Err("supervisor source peer executable is not a bounded regular file".into());
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = file.read(&mut buffer).map_err(string_error)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(string_error)?)
            .ok_or_else(|| "supervisor source peer executable size overflow".to_owned())?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err("supervisor source peer executable exceeds its hard bound".into());
        }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(string_error)?;
    if total != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
    {
        return Err("supervisor source peer executable changed while it was read".into());
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(target_os = "linux")]
fn process_start_time_ticks(pid: i32) -> Result<u64, String> {
    if pid <= 0 {
        return Err("protected peer PID is invalid".into());
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(string_error)?;
    let tail = stat
        .rsplit_once(") ")
        .ok_or_else(|| "protected peer process status is malformed".to_owned())?
        .1;
    tail.split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| "protected peer process start time is absent".to_owned())?
        .parse::<u64>()
        .map_err(string_error)
}

#[cfg(target_os = "linux")]
struct SocketPathGuard(PathBuf);

#[cfg(target_os = "linux")]
impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        if let Some(parent) = self.0.parent() {
            let _ = File::open(parent).and_then(|directory| directory.sync_all());
        }
    }
}

#[cfg(target_os = "linux")]
fn signing_time_before(deadline: Instant, label: &str) -> Result<u64, String> {
    if Instant::now() >= deadline {
        return Err(format!("{label} exceeded its total deadline"));
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)
        .map(|duration| duration.as_secs())
}

#[cfg(target_os = "linux")]
fn immutable_plan_deadline(plan: &QualificationEvidenceLedgerPlanV1) -> Result<Instant, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let remaining = plan
        .deadline_at_unix_seconds
        .checked_sub(now)
        .filter(|seconds| *seconds != 0)
        .ok_or_else(|| "protected source ledger deadline has elapsed".to_owned())?;
    Instant::now()
        .checked_add(Duration::from_secs(remaining))
        .ok_or_else(|| "protected source ledger deadline exceeds the monotonic clock".to_owned())
}

#[cfg(target_os = "linux")]
fn read_seed_from_stdin_before(deadline: Instant) -> Result<Zeroizing<String>, String> {
    let mut stdin = std::io::stdin();
    let original = rustix::fs::fcntl_getfl(&stdin).map_err(string_error)?;
    rustix::fs::fcntl_setfl(&stdin, original | OFlags::NONBLOCK).map_err(string_error)?;
    let result = (|| {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut chunk = [0_u8; 1_024];
        loop {
            if Instant::now() >= deadline {
                return Err("source signing seed exceeded its total read deadline".into());
            }
            match stdin.read(&mut chunk) {
                Ok(0) => break,
                Ok(length) => {
                    if bytes.len().checked_add(length).is_none_or(|total| {
                        u64::try_from(total).map_or(true, |total| total > MAX_SEED_BYTES)
                    }) {
                        return Err("source signing seed exceeds its hard bound".into());
                    }
                    bytes.extend_from_slice(&chunk[..length]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(string_error(error)),
            }
        }
        let mut seed = Zeroizing::new(
            std::str::from_utf8(&bytes)
                .map_err(string_error)?
                .to_owned(),
        );
        while seed.ends_with(['\r', '\n']) {
            seed.pop();
        }
        if seed.is_empty() {
            return Err("source signing seed is empty".into());
        }
        Ok(seed)
    })();
    let restored = rustix::fs::fcntl_setfl(&stdin, original).map_err(string_error);
    match (result, restored) {
        (Ok(seed), Ok(())) => Ok(seed),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_recovery_handle(
    bytes: &[u8],
    principal: &str,
    expected_operation: &auths_lifecycle::OperationIdV1,
    expected_profile: &auths_lifecycle::OperationProfileV1,
    expected_key_id: &str,
    public_key_base64url: &str,
    now_unix_seconds: u64,
) -> Result<(), String> {
    let binding = verify_recovery_handle_binding(
        bytes,
        principal,
        expected_key_id,
        public_key_base64url,
        now_unix_seconds,
    )?;
    if binding.operation != *expected_operation
        || binding.profile.id() != expected_profile.id()
        || binding.profile.version() != expected_profile.version()
    {
        return Err("durable recovery handle differs from its operation or profile".into());
    }
    Ok(())
}

struct VerifiedRecoveryHandleBinding {
    operation: auths_lifecycle::OperationIdV1,
    profile: auths_lifecycle::OperationProfileV1,
}

fn verify_recovery_handle_binding(
    bytes: &[u8],
    principal: &str,
    expected_key_id: &str,
    public_key_base64url: &str,
    now_unix_seconds: u64,
) -> Result<VerifiedRecoveryHandleBinding, String> {
    if bytes.is_empty()
        || bytes.len() > 16 * 1024
        || principal.is_empty()
        || principal.len() > 512
        || principal.chars().any(char::is_control)
        || now_unix_seconds == 0
    {
        return Err("durable recovery handle is malformed".into());
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.map().map_err(string_error)? != Some(11) {
        return Err("durable recovery handle has the wrong field count".into());
    }
    expect_key(&mut decoder, 1)?;
    if decoder.u8().map_err(string_error)? != 1 {
        return Err("durable recovery handle has the wrong version".into());
    }
    expect_key(&mut decoder, 2)?;
    let operation = decoder.str().map_err(string_error)?.to_owned();
    expect_key(&mut decoder, 3)?;
    let profile_id = decoder.str().map_err(string_error)?.to_owned();
    expect_key(&mut decoder, 4)?;
    let profile_version = decoder.u16().map_err(string_error)?;
    expect_key(&mut decoder, 5)?;
    let principal_sha256 = exact_bytes::<32>(&mut decoder)?;
    expect_key(&mut decoder, 6)?;
    let issued_at = decoder.u64().map_err(string_error)?;
    expect_key(&mut decoder, 7)?;
    let expires_at = if decoder.datatype().map_err(string_error)? == minicbor::data::Type::Null {
        decoder.null().map_err(string_error)?;
        None
    } else {
        Some(decoder.u64().map_err(string_error)?)
    };
    expect_key(&mut decoder, 8)?;
    let nonce = exact_bytes::<32>(&mut decoder)?;
    expect_key(&mut decoder, 9)?;
    if decoder.str().map_err(string_error)? != "Ed25519" {
        return Err("durable recovery handle has the wrong algorithm".into());
    }
    expect_key(&mut decoder, 10)?;
    let key_id = decoder.str().map_err(string_error)?.to_owned();
    expect_key(&mut decoder, 11)?;
    let signature = exact_bytes::<64>(&mut decoder)?;
    if decoder.position() != bytes.len()
        || key_id != expected_key_id
        || principal_sha256 != recovery_principal_commitment(principal)
        || issued_at == 0
        || issued_at > now_unix_seconds
        || expires_at.is_some_and(|expiry| expiry < issued_at || now_unix_seconds > expiry)
    {
        return Err(
            "durable recovery handle differs from its operation or deployed identity".into(),
        );
    }
    let operation = auths_lifecycle::OperationIdV1::parse(operation)
        .map_err(|_| "durable recovery handle has an invalid operation ID".to_owned())?;
    let profile = auths_lifecycle::OperationProfileV1::new(profile_id, profile_version, [0; 32])
        .map_err(|_| "durable recovery handle has an invalid profile".to_owned())?;
    let public_key = Base64UrlUnpadded::decode_vec(public_key_base64url)
        .map_err(|_| "deployed recovery public key is malformed".to_owned())?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "deployed recovery public key has the wrong length".to_owned())?;
    let unsigned = encode_recovery_handle(
        &operation,
        &profile,
        principal_sha256,
        issued_at,
        expires_at,
        nonce,
        expected_key_id,
        None,
    )?;
    let mut preimage = Vec::with_capacity(RECOVERY_HANDLE_SEMANTIC_ID.len() + 1 + unsigned.len());
    preimage.extend_from_slice(RECOVERY_HANDLE_SEMANTIC_ID);
    preimage.push(0);
    preimage.extend_from_slice(&unsigned);
    VerifyingKey::from_bytes(&public_key)
        .map_err(string_error)?
        .verify(&preimage, &Signature::from_bytes(&signature))
        .map_err(|_| "durable recovery handle was not signed by the deployed key".to_owned())?;
    let canonical = encode_recovery_handle(
        &operation,
        &profile,
        principal_sha256,
        issued_at,
        expires_at,
        nonce,
        expected_key_id,
        Some(signature),
    )?;
    if canonical != bytes {
        return Err("durable recovery handle is not canonical".into());
    }
    Ok(VerifiedRecoveryHandleBinding { operation, profile })
}

#[allow(clippy::too_many_arguments)]
fn encode_recovery_handle(
    operation: &auths_lifecycle::OperationIdV1,
    profile: &auths_lifecycle::OperationProfileV1,
    principal_sha256: [u8; 32],
    issued_at: u64,
    expires_at: Option<u64>,
    nonce: [u8; 32],
    key_id: &str,
    signature: Option<[u8; 64]>,
) -> Result<Vec<u8>, String> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(if signature.is_some() { 11 } else { 10 })
        .map_err(string_error)?;
    pair_u8(&mut encoder, 1, 1)?;
    pair_text(&mut encoder, 2, operation.as_str())?;
    pair_text(&mut encoder, 3, profile.id())?;
    encoder
        .u8(4)
        .and_then(|value| value.u16(profile.version()))
        .map_err(string_error)?;
    pair_bytes(&mut encoder, 5, &principal_sha256)?;
    encoder
        .u8(6)
        .and_then(|value| value.u64(issued_at))
        .map_err(string_error)?;
    encoder.u8(7).map_err(string_error)?;
    match expires_at {
        Some(value) => {
            encoder.u64(value).map_err(string_error)?;
        }
        None => {
            encoder.null().map_err(string_error)?;
        }
    }
    pair_bytes(&mut encoder, 8, &nonce)?;
    pair_text(&mut encoder, 9, "Ed25519")?;
    pair_text(&mut encoder, 10, key_id)?;
    if let Some(signature) = signature {
        pair_bytes(&mut encoder, 11, &signature)?;
    }
    Ok(encoder.into_writer())
}

fn recovery_principal_commitment(principal: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-RECOVERY-PRINCIPAL\x00\x01");
    digest.update((principal.len() as u64).to_be_bytes());
    digest.update(principal.as_bytes());
    digest.finalize().into()
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), String> {
    if decoder.u8().map_err(string_error)? != expected {
        return Err("durable recovery handle keys are not canonical".into());
    }
    Ok(())
}

fn exact_bytes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], String> {
    decoder
        .bytes()
        .map_err(string_error)?
        .try_into()
        .map_err(|_| "durable recovery handle byte field has the wrong length".to_owned())
}

fn pair_u8(encoder: &mut Encoder<Vec<u8>>, key: u8, value: u8) -> Result<(), String> {
    encoder
        .u8(key)
        .and_then(|encoder| encoder.u8(value))
        .map_err(string_error)?;
    Ok(())
}

fn pair_text(encoder: &mut Encoder<Vec<u8>>, key: u8, value: &str) -> Result<(), String> {
    encoder
        .u8(key)
        .and_then(|encoder| encoder.str(value))
        .map_err(string_error)?;
    Ok(())
}

fn pair_bytes(encoder: &mut Encoder<Vec<u8>>, key: u8, value: &[u8]) -> Result<(), String> {
    encoder
        .u8(key)
        .and_then(|encoder| encoder.bytes(value))
        .map_err(string_error)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn reject_secret_environment() -> Result<(), String> {
    const FORBIDDEN: [&str; 6] = [
        "CREDENTIAL",
        "PASSWORD",
        "PRIVATE_KEY",
        "SECRET",
        "SEED",
        "TOKEN",
    ];
    if env::vars_os().any(|(name, _)| {
        let name = name.to_string_lossy().to_ascii_uppercase();
        FORBIDDEN.iter().any(|part| name.contains(part))
    }) {
        return Err("source signer inherited a forbidden secret environment slot".into());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn read_bounded(path: &Path, maximum: u64, owner_only: bool) -> Result<Vec<u8>, String> {
    let mut file = File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    let before = file.metadata().map_err(string_error)?;
    let permissions_invalid = if owner_only {
        before.mode() & 0o077 != 0
    } else {
        before.mode() & 0o022 != 0
    };
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != rustix::process::geteuid().as_raw()
        || permissions_invalid
        || before.len() > maximum
    {
        return Err("source signer input is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    let after = file.metadata().map_err(string_error)?;
    if u64::try_from(bytes.len()).map_err(string_error)? > maximum
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || after.len() != u64::try_from(bytes.len()).map_err(string_error)?
    {
        return Err("source signer input changed while it was read".into());
    }
    Ok(bytes)
}

#[cfg(test)]
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "source signer output has no parent".to_owned())?;
    let name = path
        .file_name()
        .ok_or_else(|| "source signer output has no file name".to_owned())?;
    let parent_directory = File::from(
        open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    let parent_metadata = parent_directory.metadata().map_err(string_error)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != rustix::process::geteuid().as_raw()
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err("source signer output parent is not owner-only".into());
    }
    let mut file = File::from(
        openat(
            &parent_directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(string_error)?,
    );
    file.write_all(bytes).map_err(string_error)?;
    file.sync_all().map_err(string_error)?;
    parent_directory.sync_all().map_err(string_error)
}

#[cfg(any(target_os = "linux", test))]
fn journal_reader_usage() -> String {
    "usage: qualification-source-journal-reader serve-ordinary-row-session --runtime-root <protected-row-root> --sequencer-socket <protected-append-socket> --source-trust <registry> --ledger-plan <owner-only-canonical-plan> --receipt-trust <anchors> | qualification-source-journal-reader serve-decision --socket <new-protected-unix-socket> --sequencer-socket <protected-append-socket> --append-mode <new|retry> --source-trust <registry> --ledger-plan <owner-only-canonical-plan> | qualification-source-journal-reader serve-boundary-session --socket <new-protected-unix-socket> --sequencer-socket <protected-append-socket> --source-trust <registry> --ledger-plan <owner-only-canonical-plan> --receipt-trust <anchors> --scenario <id> --phase-index <index>; the ordinary row session owns the single JournalReader seed for the immutable non-crash phase roster; each phase accepts repeated framed fresh journal descriptors from the exact protected controller, authenticates the complete store-owned boundary roster without a caller cursor, and resume-or-appends each deterministic event in ordinal order; the seed is not read for an all-retained retry".into()
}

#[cfg(target_os = "linux")]
fn typed_source_usage() -> String {
    "usage: qualification-source-<fixed-role> serve-session --socket <row-scoped-protected-unix-socket> --source-trust <registry> --ledger-plan <owner-only-canonical-plan> | qualification-source-client-proxy serve-ordinary-row-session --runtime-root <protected-row-root> --signer-socket <row-signer-socket> --sequencer-socket <protected-append-socket> --ledger-plan <plan> --source-trust <registry> | qualification-source-credential-broker initialize-stores --agent-config <protected-config> --connection-store <new-broker-owned-public-store> --credential-store <new-broker-owned-secret-store> --ledger-plan <plan> --source-trust <registry> | qualification-source-credential-broker serve-ordinary-row-session --runtime-root <protected-row-root> --signer-socket <row-signer-socket> --sequencer-socket <protected-append-socket> --ledger-plan <plan> --source-trust <registry> --connection-store <broker-owned-public-store> --credential-store <broker-owned-secret-store> | qualification-source-profile-state-reader serve-ordinary-row-session --runtime-root <protected-row-root> --signer-socket <row-signer-socket> --sequencer-socket <protected-append-socket> --ledger-plan <plan> --source-trust <registry> | qualification-source-receipt-verifier serve-ordinary-row-session --runtime-root <protected-row-root> --signer-socket <row-signer-socket> --sequencer-socket <protected-append-socket> --ledger-plan <plan> --source-trust <registry> --receipt-trust <anchors>; CredentialBroker initialization receives one bounded canonical descriptor-and-credential document only on stdin, creates both owner-only stores, and never exposes the secret store to the candidate; single-phase serve-reader-session commands remain available only for crash orchestration; the immutable plan fixes the run, phase roster, exercised agent, source context, workload commitment, connection requirement, and key interval; protected source trust uniquely selects the current key and fixes the signer and reader identities; a row reader ends its signer through the isolated authenticated row-complete frame; ClientProxy alone owns the real SDK socket, CredentialBroker alone owns the real credential store, ProfileStateReader accepts only controller-transferred pinned journal and profile-store descriptors, and ReceiptVerifier accepts only the controller-transferred pinned journal descriptor; deterministic retained intents resume before an absent event is appended, so durable prefixes are restart-safe".into()
}

#[cfg(any(target_os = "linux", test))]
fn supervisor_usage() -> String {
    "usage: qualification-source-supervisor serve-ordinary-row-session --socket <row-scoped-protected-unix-socket> --ledger-plan <owner-only-canonical-ledger-plan> --source-trust <registry>; the row session is the sole Supervisor protocol and signs exactly one authenticated phase, decision, or crash-action request per connection; protected source trust selects the current Supervisor and JournalReader identities; the process has no append authority and reads its one source seed only after validating the first request".into()
}

fn string_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink},
    };

    #[test]
    fn credential_lease_identity_binds_the_complete_canonical_request() {
        let request = |alias: &str| {
            QualificationCredentialLeaseRequest::new(
                [1; 32],
                "operation-1",
                "did:key:workload",
                "auths.stripe.refund",
                1,
                "stripe",
                alias,
                "connection-1",
                1,
                [2; 32],
                [3; 32],
                "auths.stripe.connection/1",
                "auths.stripe.connection-descriptor/1",
                "stripe.refunds.write/1",
            )
            .unwrap()
        };
        let first = request("primary");
        let second = request("secondary");
        assert_eq!(
            qualification_credential_lease_sha256(&first).unwrap(),
            qualification_credential_lease_sha256(&first).unwrap()
        );
        assert_ne!(
            qualification_credential_lease_sha256(&first).unwrap(),
            qualification_credential_lease_sha256(&second).unwrap()
        );
    }

    #[test]
    fn input_is_one_open_nofollow_snapshot_and_output_never_clobbers() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let input = directory.path().join("event.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&input)
            .unwrap();
        file.write_all(b"{}").unwrap();
        file.sync_all().unwrap();
        assert_eq!(read_bounded(&input, 2, true).unwrap(), b"{}");
        let link = directory.path().join("link.json");
        symlink(&input, &link).unwrap();
        assert!(read_bounded(&link, 2, true).is_err());
        let output = directory.path().join("signed.json");
        write_new(&output, b"first").unwrap();
        assert!(write_new(&output, b"second").is_err());
        let real_parent = directory.path().join("real-output");
        fs::create_dir(&real_parent).unwrap();
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let redirected_parent = directory.path().join("redirected-output");
        symlink(&real_parent, &redirected_parent).unwrap();
        assert!(write_new(&redirected_parent.join("event.json"), b"redirected").is_err());
        assert!(!real_parent.join("event.json").exists());
    }

    #[test]
    fn journal_reader_cannot_accept_a_caller_authored_event() {
        let arguments = vec![
            "sign-event".to_owned(),
            "--event".to_owned(),
            "event.json".into(),
        ];
        assert!(exact_flag_values(&arguments, "sign-decision", &["--journal"]).is_err());
    }

    #[test]
    fn journal_reader_and_supervisor_accept_only_their_exact_output_flags() {
        assert!(!supervisor_usage().contains("append-phase"));
        let journal_reader = vec![
            "serve-decision".to_owned(),
            "--socket".to_owned(),
            "/protected/journal-reader.sock".to_owned(),
            "--sequencer-socket".to_owned(),
            "/protected/append.sock".to_owned(),
            "--append-mode".to_owned(),
            "new".to_owned(),
            "--source-trust".to_owned(),
            "source-trust.json".to_owned(),
            "--ledger-plan".to_owned(),
            "ledger-plan.json".to_owned(),
        ];
        assert!(
            exact_flag_values(
                &journal_reader,
                "serve-decision",
                &[
                    "--socket",
                    "--sequencer-socket",
                    "--append-mode",
                    "--source-trust",
                    "--ledger-plan",
                ],
            )
            .is_ok()
        );
        let mut missing_snapshot = journal_reader.clone();
        missing_snapshot.drain(1..=2);
        assert!(
            exact_flag_values(
                &missing_snapshot,
                "serve-decision",
                &[
                    "--socket",
                    "--sequencer-socket",
                    "--append-mode",
                    "--source-trust",
                    "--ledger-plan",
                ],
            )
            .is_err()
        );
        let boundary_reader = vec![
            "serve-boundary-session".to_owned(),
            "--socket".to_owned(),
            "/protected/journal-reader.sock".to_owned(),
            "--sequencer-socket".to_owned(),
            "/protected/append.sock".to_owned(),
            "--source-trust".to_owned(),
            "source-trust.json".to_owned(),
            "--ledger-plan".to_owned(),
            "ledger-plan.json".to_owned(),
            "--receipt-trust".to_owned(),
            "receipt-trust.json".to_owned(),
            "--scenario".to_owned(),
            "happy-path".to_owned(),
            "--phase-index".to_owned(),
            "1".to_owned(),
        ];
        assert!(
            exact_flag_values(
                &boundary_reader,
                "serve-boundary-session",
                &[
                    "--socket",
                    "--sequencer-socket",
                    "--source-trust",
                    "--ledger-plan",
                    "--receipt-trust",
                    "--scenario",
                    "--phase-index",
                ],
            )
            .is_ok()
        );

        let supervisor = vec![
            "serve-ordinary-row-session".to_owned(),
            "--socket".to_owned(),
            "source.sock".to_owned(),
            "--ledger-plan".to_owned(),
            "ledger-plan.json".to_owned(),
            "--source-trust".to_owned(),
            "source-trust.json".to_owned(),
        ];
        assert!(
            exact_flag_values_for(
                &supervisor,
                "serve-ordinary-row-session",
                &["--socket", "--ledger-plan", "--source-trust"],
                supervisor_usage,
            )
            .is_ok()
        );
        let mut obsolete = supervisor;
        obsolete[0] = "sign-crash-action-context".to_owned();
        assert!(
            exact_flag_values_for(
                &obsolete,
                "serve-ordinary-row-session",
                &["--socket", "--ledger-plan", "--source-trust"],
                supervisor_usage,
            )
            .is_err()
        );
    }

    #[test]
    fn typed_source_session_uses_exact_bounded_frames() {
        let (mut reader, mut signer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        signer.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        write_source_session_frame_before(&mut reader, b"first", deadline).unwrap();
        write_source_session_frame_before(&mut reader, b"second", deadline).unwrap();
        reader.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            read_source_session_frame_before(&mut signer, deadline).unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(
            read_source_session_frame_before(&mut signer, deadline).unwrap(),
            Some(b"second".to_vec())
        );
        assert_eq!(
            read_source_session_frame_before(&mut signer, deadline).unwrap(),
            None
        );
        assert_eq!(MAX_TYPED_SOURCE_SESSION_EVENTS, 1_024);

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        let payload = vec![0x5a; 70_000];
        let expected = payload.clone();
        let handle = thread::spawn(move || {
            write_bounded_session_frame_before(
                &mut writer,
                &payload,
                100_000,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        });
        assert_eq!(
            read_bounded_session_frame_before(
                &mut reader,
                100_000,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap(),
            Some(expected)
        );
        handle.join().unwrap();
    }

    #[test]
    fn typed_source_session_rejects_malformed_frames_and_deadlines() {
        for bytes in [
            0_u32.to_be_bytes().to_vec(),
            u32::try_from(MAX_CONTEXT_BYTES + 1)
                .unwrap()
                .to_be_bytes()
                .to_vec(),
            [3_u32.to_be_bytes().as_slice(), b"ab"].concat(),
        ] {
            let (mut reader, mut signer) = UnixStream::pair().unwrap();
            signer.set_nonblocking(true).unwrap();
            reader.write_all(&bytes).unwrap();
            reader.shutdown(Shutdown::Write).unwrap();
            assert!(
                read_source_session_frame_before(
                    &mut signer,
                    Instant::now() + Duration::from_secs(1),
                )
                .is_err()
            );
        }

        let (_reader, mut signer) = UnixStream::pair().unwrap();
        signer.set_nonblocking(true).unwrap();
        assert!(
            read_source_session_frame_before(
                &mut signer,
                Instant::now() + Duration::from_millis(20),
            )
            .is_err()
        );
    }

    #[test]
    fn receipt_verifier_response_is_canonical_bounded_and_ordered() {
        let operation = auths_lifecycle::OperationIdV1::from_random_bytes([7; 16]).unwrap();
        let response = QualificationReceiptVerifierResponseV1 {
            schema: "auths.qualification-receipt-verifier-response/1".into(),
            operations: vec![QualificationReceiptVerifierOperationV1 {
                operation_id: operation.as_str().into(),
                inspection_base64url: Base64UrlUnpadded::encode_string(b"inspection"),
                receipts: vec![
                    QualificationReceiptVerifierArtifactV1 {
                        sequence: 0,
                        receipt_id: format!("rcpt_{}", Base64UrlUnpadded::encode_string(&[1; 32])),
                        bytes_base64url: Base64UrlUnpadded::encode_string(b"decision"),
                    },
                    QualificationReceiptVerifierArtifactV1 {
                        sequence: 1,
                        receipt_id: format!("rcpt_{}", Base64UrlUnpadded::encode_string(&[2; 32])),
                        bytes_base64url: Base64UrlUnpadded::encode_string(b"execution"),
                    },
                ],
            }],
        };
        let bytes = response.to_json().unwrap();
        assert_eq!(
            QualificationReceiptVerifierResponseV1::from_json(&bytes)
                .unwrap()
                .operations[0]
                .operation_id,
            operation.as_str()
        );

        let mut noncanonical = bytes.clone();
        noncanonical.push(b'\n');
        assert!(QualificationReceiptVerifierResponseV1::from_json(&noncanonical).is_err());

        let mut wrong_sequence = response.clone();
        wrong_sequence.operations[0].receipts[1].sequence = 0;
        assert!(wrong_sequence.to_json().is_err());

        let mut invalid_base64 = response;
        invalid_base64.operations[0].inspection_base64url = "padding=".into();
        assert!(invalid_base64.to_json().is_err());

        let empty = QualificationReceiptVerifierResponseV1 {
            schema: "auths.qualification-receipt-verifier-response/1".into(),
            operations: Vec::new(),
        };
        assert!(
            QualificationReceiptVerifierResponseV1::from_json(&empty.to_json().unwrap())
                .unwrap()
                .operations
                .is_empty()
        );
    }

    #[test]
    fn durable_recovery_handle_must_match_the_deployed_agent_key() {
        let operation = auths_lifecycle::OperationIdV1::from_random_bytes([7; 16]).unwrap();
        let profile =
            auths_lifecycle::OperationProfileV1::new("auths.stripe.refund", 1, [9; 32]).unwrap();
        let principal = "spiffe://qualification.example/workload";
        let key_id = "qualification-recovery-v1";
        let signing = SigningKey::from_bytes(&[11; 32]);
        let principal_sha256 = recovery_principal_commitment(principal);
        let nonce = [13; 32];
        let issued_at = 1_700_000_000;
        let unsigned = encode_recovery_handle(
            &operation,
            &profile,
            principal_sha256,
            issued_at,
            None,
            nonce,
            key_id,
            None,
        )
        .unwrap();
        let mut preimage = Vec::new();
        preimage.extend_from_slice(RECOVERY_HANDLE_SEMANTIC_ID);
        preimage.push(0);
        preimage.extend_from_slice(&unsigned);
        let handle = encode_recovery_handle(
            &operation,
            &profile,
            principal_sha256,
            issued_at,
            None,
            nonce,
            key_id,
            Some(signing.sign(&preimage).to_bytes()),
        )
        .unwrap();
        let public = Base64UrlUnpadded::encode_string(signing.verifying_key().as_bytes());
        let binding =
            verify_recovery_handle_binding(&handle, principal, key_id, &public, issued_at + 1)
                .unwrap();
        assert_eq!(binding.operation, operation);
        assert_eq!(binding.profile.id(), profile.id());
        assert_eq!(binding.profile.version(), profile.version());
        verify_recovery_handle(
            &handle,
            principal,
            &operation,
            &profile,
            key_id,
            &public,
            issued_at + 1,
        )
        .unwrap();

        let substituted = SigningKey::from_bytes(&[12; 32]);
        let substituted_public =
            Base64UrlUnpadded::encode_string(substituted.verifying_key().as_bytes());
        assert!(
            verify_recovery_handle(
                &handle,
                principal,
                &operation,
                &profile,
                key_id,
                &substituted_public,
                issued_at + 1,
            )
            .is_err()
        );
        assert!(
            verify_recovery_handle(
                &handle,
                principal,
                &operation,
                &profile,
                "substituted-recovery-v1",
                &public,
                issued_at + 1,
            )
            .is_err()
        );
    }

    #[test]
    fn typed_source_record_cannot_select_another_source_role() {
        let record = QualificationClientProxyRecordV1 {
            schema: "auths.qualification-client-proxy-record/1".into(),
            context: QualificationSourceEventContextV1 {
                sequence: 1,
                previous_event_sha256: "0".repeat(64),
                scenario_id: "happy-path".into(),
                phase_index: 1,
                role: QualificationOperationRole::Effect,
                profile: "auths.stripe.refund/1".into(),
                failpoint: None,
                supervisor_generation: 1,
                operation_id: Some("operation-1".into()),
                request_id: Some("request-1".into()),
                connection_generation: Some("1".into()),
            },
            observation: QualificationClientProxyObservationV1::ResponseProjected {
                result_sha256: "2".repeat(64),
                journal_projection_kinds: vec![QualificationEvidenceEventKind::StatusObserved],
                outcome: QualificationOutcomeKind::Completed,
                completion: Some(QualificationCompletion::Fresh),
                recovery_id: None,
                error_code: None,
                issue_metadata_sha256: None,
                receipt_ids: Vec::new(),
            },
        };
        let bytes = serde_json_canonicalizer::to_vec(&record).unwrap();
        let process = QualificationSourceProcessBindingV1 {
            source_identity: "client-proxy-signer".into(),
            source_artifact_sha256: "3".repeat(64),
            source_uid: 1_101,
            reader_identity: "client-proxy-reader".into(),
            reader_artifact_sha256: "4".repeat(64),
            reader_uid: 1_102,
        };
        let event = typed_source_event(
            QualificationEvidenceSource::ClientProxy,
            &bytes,
            &process,
            &"5".repeat(64),
            "client-proxy-key",
        )
        .unwrap();
        assert_eq!(event.source, QualificationEvidenceSource::ClientProxy);
        assert_eq!(
            event.reader_identity.as_deref(),
            Some("client-proxy-reader")
        );
        assert!(
            typed_source_event(
                QualificationEvidenceSource::ProviderProxy,
                &bytes,
                &process,
                &"5".repeat(64),
                "provider-proxy-key",
            )
            .is_err()
        );
    }
}
