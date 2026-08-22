//! Authenticated protected-supervisor event ledger for live qualification.
//!
//! Candidate code may emit timing hints, but no candidate- or domain-authored
//! value can establish a common lifecycle fact. The protected supervisor
//! commits independently observed, source-owned events here and signs the
//! complete hash chain before common phase evidence can be consumed.

// This canonical evidence schema deliberately exposes one fail-closed error
// type. Callers must not branch on parser/validator internals.
#![allow(clippy::missing_errors_doc)]

use crate::{
    QualificationCompletion, QualificationEffect, QualificationFailpoint,
    QualificationOperationRole, QualificationOutcomeKind, QualificationReceiptDecisionClass,
    QualificationReceiptExecutionOutcome, QualificationTarget, QualificationTrustIdentity,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(any(feature = "qualification-ledger-producer", test))]
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_LEDGER_BYTES: usize = 16_777_216;
const MAX_EVENTS: usize = 16_384;
const MAX_PHASES: usize = 2_048;
const MAX_QUALIFICATION_SECONDS: u64 = 21_600;
const CLOCK_SKEW_SECONDS: u64 = 300;
const SIGNATURE_DOMAIN: &[u8] = b"auths.profile-qualification-evidence-ledger/1";
const JOURNAL_CONTEXT_SIGNATURE_DOMAIN: &[u8] = b"auths.qualification-journal-decision-context/1";
const CRASH_ACTION_CONTEXT_SIGNATURE_DOMAIN: &[u8] = b"auths.qualification-crash-action-context/1";
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Commits one normalized qualification state-directory path to the exact
/// directory inode opened by the protected launcher.
///
/// The commitment deliberately includes the owner and complete permission
/// bits so a pathname replacement cannot preserve the signed state identity.
pub fn qualification_state_directory_commitment(
    path: &str,
    device: u64,
    inode: u64,
    owner_uid: u32,
    mode: u32,
) -> Result<String, QualificationEvidenceLedgerError> {
    if !path.starts_with('/')
        || path.len() < 2
        || path.len() > 1_024
        || path.ends_with('/')
        || path.contains("//")
        || path.split('/').any(|part| matches!(part, "." | ".."))
        || device == 0
        || inode == 0
        || owner_uid == 0
        || mode != 0o700
    {
        return Err(QualificationEvidenceLedgerError::InvalidRecord);
    }
    let mut bytes = Vec::with_capacity(path.len() + 96);
    bytes.extend_from_slice(b"auths.qualification-state-directory/1\0");
    bytes.extend_from_slice(path.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(device.to_string().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(inode.to_string().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(owner_uid.to_string().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(mode.to_string().as_bytes());
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Independently controlled origin allowed to establish one event class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationEvidenceSource {
    /// Protected process controller and failpoint acknowledgement channel.
    Supervisor,
    /// Protected public-client IPC proxy.
    ClientProxy,
    /// Independent decoder of the common durable journal.
    JournalReader,
    /// Protected connection and credential broker audit source.
    CredentialBroker,
    /// Independent profile reservation/state reader.
    ProfileStateReader,
    /// Protected provider transport proxy or provider audit log.
    ProviderProxy,
    /// Native portable-receipt verifier over retained receipt bytes.
    ReceiptVerifier,
    /// Protected read-only provider truth observer.
    ProviderObserver,
}

/// Protected registry of independently owned event-source verification keys.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationEvidenceSourceTrustRegistry {
    schema: String,
    keys: Vec<QualificationEvidenceSourceTrustKey>,
}

/// Protected registry of common evidence-ledger sealer verification keys.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationEvidenceLedgerTrustRegistry {
    schema: String,
    keys: Vec<QualificationEvidenceLedgerTrustKey>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationEvidenceLedgerTrustKey {
    key_id: String,
    algorithm: String,
    public_key_base64url: String,
    allowed_domains: Vec<String>,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationEvidenceSourceTrustKey {
    source: QualificationEvidenceSource,
    key_id: String,
    algorithm: String,
    public_key_base64url: String,
    source_identity: String,
    source_artifact_sha256: String,
    source_uid: Option<u32>,
    reader_identity: Option<String>,
    reader_artifact_sha256: Option<String>,
    reader_uid: Option<u32>,
    allowed_domains: Vec<String>,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
}

/// Closed event vocabulary from which attempts and counters are derived.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationEvidenceEventKind {
    ScenarioStarted,
    RequestReceived,
    DecisionDurable,
    ReservationDurable,
    ReservationReleased,
    ReservationConsumed,
    ReservationRetained,
    CommandDurable,
    ConnectionReread,
    CredentialLeaseAttempted,
    CredentialLeaseSucceeded,
    CredentialLeaseClosed,
    ProviderEntryDurable,
    ProviderRequestWritten,
    ProviderResponseObserved,
    ProviderReconciliationRequested,
    ProviderReconciliationObserved,
    ProviderResultDurable,
    ObservationDurable,
    ExecutionReceiptDurable,
    RecoveryRequiredDurable,
    TerminalDurable,
    NativeReceiptVerified,
    ResponseProjected,
    ReplayObserved,
    StatusObserved,
    RecoveryObserved,
    CancellationObserved,
    FailpointAcknowledged,
    ProcessKilled,
    ProcessRestarted,
    ProviderTruthObserved,
    ScenarioCompleted,
}

/// Capability-free durable journal state exposed by replay, status, recovery,
/// and recovery-required projections.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationJournalState {
    Ready,
    Executing,
    RecoveryRequired,
    Denied,
    Unavailable,
    Completed,
    Partial,
    NotApplied,
}

/// Closed, kind-specific public facts authenticated by one source event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum QualificationEvidenceEventPayload {
    Control {
        context_sha256: String,
    },
    FailpointAcknowledgement {
        action_context_sha256: String,
        controller_nonce_sha256: String,
        agent_start_time_ticks: u64,
        agent_executable_sha256: String,
        agent_configuration_sha256: String,
        agent_state_directory_sha256: String,
        agent_cgroup_sha256: String,
        boundary_event_sha256: String,
    },
    ProcessKill {
        action_context_sha256: String,
        controller_nonce_sha256: String,
        agent_start_time_ticks: u64,
        agent_executable_sha256: String,
        agent_configuration_sha256: String,
        agent_state_directory_sha256: String,
        agent_cgroup_sha256: String,
        acknowledgement_event_sha256: String,
        signal: String,
        cgroup_empty_after_kill: bool,
    },
    ProcessRestart {
        action_context_sha256: String,
        controller_nonce_sha256: String,
        prior_agent_generation: u32,
        prior_agent_process_id: u32,
        prior_agent_start_time_ticks: u64,
        restarted_agent_start_time_ticks: u64,
        agent_executable_sha256: String,
        agent_configuration_sha256: String,
        agent_state_directory_sha256: String,
        restarted_agent_cgroup_sha256: String,
        kill_event_sha256: String,
        control_plane_ready: bool,
    },
    Request {
        request_input_sha256: String,
        principal_sha256: String,
        idempotency_sha256: Option<String>,
        preparation_input_sha256: Option<String>,
    },
    Decision {
        canonical_input_sha256: String,
        idempotency_sha256: Option<String>,
        canonical_action_sha256: String,
        receipt_action_sha256: String,
        receipt_context_sha256: String,
        authority_sha256: String,
        configuration_sha256: String,
        runtime_contract_sha256: String,
        preparation_sha256: String,
        decision_class: QualificationReceiptDecisionClass,
        decision_receipt_id: String,
        decision_receipt_bytes_sha256: String,
        decoded_claims_sha256: String,
        supervisor_context_sha256: String,
        recovery_key_id: String,
        recovery_public_key_base64url: String,
        receipt_trust_anchor_sha256: String,
    },
    Reservation {
        reservation_sha256: String,
    },
    Command {
        sealed_command_sha256: String,
    },
    Connection {
        connection_id_sha256: Option<String>,
        connection_alias_sha256: Option<String>,
        descriptor_sha256: Option<String>,
        account_sha256: Option<String>,
    },
    Credential {
        lease_sha256: String,
        requested_scope_sha256: String,
        effective_scope_sha256: String,
    },
    ProviderEntry {
        sealed_command_sha256: String,
    },
    ProviderRequest {
        request_sha256: String,
        credential_lease_sha256: String,
    },
    ProviderResponse {
        response_sha256: String,
    },
    ProviderResult {
        provider_result_sha256: String,
    },
    Observation {
        observation_sha256: String,
    },
    ExecutionReceipt {
        execution_receipt_id: String,
        receipt_bytes_sha256: String,
        decoded_claims_sha256: String,
        execution_result_sha256: Option<String>,
        execution_outcome: QualificationReceiptExecutionOutcome,
    },
    Terminal {
        state: QualificationOutcomeKind,
        effect: QualificationEffect,
        execution_result_sha256: Option<String>,
        completion: Option<QualificationCompletion>,
    },
    ReceiptVerification {
        receipt_bytes_sha256: String,
        decoded_claims_sha256: String,
        profile_inspection_sha256: String,
    },
    ClientResult {
        result_sha256: String,
        journal_projection_kinds: Vec<QualificationEvidenceEventKind>,
        outcome: QualificationOutcomeKind,
        completion: Option<QualificationCompletion>,
        recovery_id: Option<String>,
        error_code: Option<String>,
        issue_metadata_sha256: Option<String>,
        receipt_ids: Vec<String>,
    },
    JournalProjection {
        projection_sha256: String,
        state: QualificationJournalState,
        effect: QualificationEffect,
        terminal: bool,
        completion: Option<QualificationCompletion>,
    },
    ProviderTruth {
        effect: QualificationEffect,
        provider_truth_sha256: String,
    },
}

/// One exact source-owned event in the protected append-only transcript.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationEvidenceEvent {
    pub sequence: u32,
    pub previous_event_sha256: String,
    pub scenario_id: String,
    pub phase_index: u8,
    pub role: QualificationOperationRole,
    pub profile: String,
    pub failpoint: Option<QualificationFailpoint>,
    pub source: QualificationEvidenceSource,
    pub source_identity: String,
    pub source_artifact_sha256: String,
    /// Protected OS identity of the seed-bearing fixed-role signer.
    pub source_uid: Option<u32>,
    /// Exact protected reader that independently derived this observation.
    pub reader_identity: Option<String>,
    pub reader_artifact_sha256: Option<String>,
    pub reader_uid: Option<u32>,
    /// Commitment to the immutable protected run/session context. This is
    /// included in the per-source signature and prevents cross-run replay.
    pub source_context_sha256: String,
    pub source_key_id: String,
    pub source_signature_base64url: String,
    pub supervisor_generation: u32,
    pub agent_generation: Option<u32>,
    pub agent_process_id: Option<u32>,
    pub agent_boot_sha256: Option<String>,
    pub operation_id: Option<String>,
    /// Supervisor-minted crash-control identity. Before a durable decision
    /// this is intentionally not a durable operation ID.
    pub control_operation_id: Option<String>,
    pub request_id: Option<String>,
    /// SHA-256 of the complete canonical protected attempt projection for a
    /// response/cancellation event.
    pub client_result_sha256: Option<String>,
    /// Exact portable receipt ID for one native-verification event.
    pub receipt_id: Option<String>,
    pub connection_generation: Option<String>,
    pub journal_revision: Option<u64>,
    pub kind: QualificationEvidenceEventKind,
    pub payload: QualificationEvidenceEventPayload,
    pub durable_ack_sha256: String,
}

/// Run- and phase-bound fields supplied to one fixed-role protected source.
///
/// The source process supplies its own role, identity, executable digest,
/// key identifier, and immutable run-context digest. Those security fields
/// are deliberately absent here so an authenticated reader cannot select a
/// different signer identity or reuse a record across runs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationSourceEventContextV1 {
    pub sequence: u32,
    pub previous_event_sha256: String,
    pub scenario_id: String,
    pub phase_index: u8,
    pub role: QualificationOperationRole,
    pub profile: String,
    pub failpoint: Option<QualificationFailpoint>,
    pub supervisor_generation: u32,
    pub operation_id: Option<String>,
    pub request_id: Option<String>,
    pub connection_generation: Option<String>,
}

/// Minimal controller request for one Supervisor-owned phase boundary.
///
/// The protected controller supplies only the locked append position and the
/// boundary to derive from the immutable ledger plan. The source signer owns
/// every phase fact and its signing identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationSupervisorPhaseRequestV1 {
    pub schema: String,
    pub sequence: u32,
    pub previous_event_sha256: String,
    pub scenario_id: String,
    pub phase_index: u8,
    pub supervisor_generation: u32,
    pub kind: QualificationEvidenceEventKind,
}

impl QualificationSupervisorPhaseRequestV1 {
    /// Decodes one exact canonical, capability-free phase request.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationEvidenceLedgerError> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)?;
        value.validate()?;
        if canonical(&value)? != bytes {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        Ok(value)
    }

    /// Encodes one exact canonical, capability-free phase request.
    pub fn to_json(&self) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
        self.validate()?;
        canonical(self)
    }

    fn validate(&self) -> Result<(), QualificationEvidenceLedgerError> {
        if self.schema != "auths.qualification-supervisor-phase-request/1"
            || usize::try_from(self.sequence)
                .map_or(true, |sequence| !(1..=MAX_EVENTS).contains(&sequence))
            || !digest(&self.previous_event_sha256)
            || !registered_token(&self.scenario_id)
            || !(1..=8).contains(&self.phase_index)
            || self.supervisor_generation == 0
            || !matches!(
                self.kind,
                QualificationEvidenceEventKind::ScenarioStarted
                    | QualificationEvidenceEventKind::ScenarioCompleted
            )
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        Ok(())
    }

    /// Derives the semantic intent committed before the append sequencer
    /// reserves a position in the global event chain.
    pub fn intent_sha256(
        &self,
        plan: &QualificationEvidenceLedgerPlanV1,
    ) -> Result<String, QualificationEvidenceLedgerError> {
        self.unsigned_event(plan, "", "", 0, "")?.intent_sha256()
    }

    /// Constructs the only unsigned Supervisor event represented by this
    /// phase request. Signing identity fields are supplied by the signer;
    /// every semantic phase fact comes from the immutable ledger plan.
    pub fn unsigned_event(
        &self,
        plan: &QualificationEvidenceLedgerPlanV1,
        source_identity: &str,
        source_artifact_sha256: &str,
        source_uid: u32,
        source_key_id: &str,
    ) -> Result<QualificationEvidenceEvent, QualificationEvidenceLedgerError> {
        self.validate()?;
        plan.validate()?;
        let phase = plan
            .phases
            .iter()
            .find(|phase| {
                phase.scenario_id == self.scenario_id && phase.phase_index == self.phase_index
            })
            .ok_or(QualificationEvidenceLedgerError::InvalidPhase)?;
        let source_context_sha256 = plan.source_context_sha256()?;
        Ok(QualificationEvidenceEvent {
            sequence: self.sequence,
            previous_event_sha256: self.previous_event_sha256.clone(),
            scenario_id: phase.scenario_id.clone(),
            phase_index: phase.phase_index,
            role: phase.role,
            profile: phase.profile.clone(),
            failpoint: phase.failpoint,
            source: QualificationEvidenceSource::Supervisor,
            source_identity: source_identity.to_owned(),
            source_artifact_sha256: source_artifact_sha256.to_owned(),
            source_uid: Some(source_uid),
            reader_identity: None,
            reader_artifact_sha256: None,
            reader_uid: None,
            source_context_sha256,
            source_key_id: source_key_id.to_owned(),
            source_signature_base64url: String::new(),
            supervisor_generation: self.supervisor_generation,
            agent_generation: None,
            agent_process_id: None,
            agent_boot_sha256: None,
            operation_id: None,
            control_operation_id: None,
            request_id: None,
            client_result_sha256: None,
            receipt_id: None,
            connection_generation: None,
            journal_revision: None,
            kind: self.kind,
            payload: QualificationEvidenceEventPayload::Control {
                context_sha256: qualification_supervisor_phase_context_sha256(
                    phase,
                    &plan.supervisor_controller_artifact_sha256,
                )?,
            },
            durable_ack_sha256: qualification_event_marker_sha256(
                self.sequence,
                QualificationEvidenceSource::Supervisor,
            ),
        })
    }
}

/// Protected signer/reader process identities for one fixed evidence source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationSourceProcessBindingV1 {
    pub source_identity: String,
    pub source_artifact_sha256: String,
    pub source_uid: u32,
    pub reader_identity: String,
    pub reader_artifact_sha256: String,
    pub reader_uid: u32,
}

/// Capability-free kernel identity forwarded only by the protected
/// qualification `ClientProxy` after accepting the real SDK socket.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationAdmissionFaultV1 {
    /// The executed configuration commitment differs from the evidence-bound requirement.
    ConfigurationMismatch,
    /// The requested connection identity differs from the reviewed binding.
    ConnectionSubstitution,
    /// The operation request is evaluated as a different authenticated IPC principal.
    PrincipalSubstitution,
    /// The preparation evidence is evaluated at the last valid second.
    EvidenceFreshnessEdge,
    /// The preparation evidence is evaluated at its first expired second.
    StaleEvidence,
}

/// Capability-free kernel identity forwarded only by the protected
/// qualification `ClientProxy` after accepting the real SDK socket. The
/// optional fault is selected from the immutable phase by that protected
/// source and is never accepted on the production listener.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationClientBridgeBindingV1 {
    pub schema: String,
    pub source_context_sha256: String,
    pub client_uid: u32,
    pub client_gid: u32,
    pub client_process_id: u32,
    pub client_start_time_ticks: u64,
    pub client_executable_sha256: String,
    pub fault: Option<QualificationAdmissionFaultV1>,
}

impl QualificationClientBridgeBindingV1 {
    /// Decodes one exact canonical protected bridge binding.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationEvidenceLedgerError> {
        if bytes.is_empty() || bytes.len() > 4_096 {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)?;
        value.validate()?;
        if canonical(&value)? != bytes {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        Ok(value)
    }

    /// Encodes one exact canonical protected bridge binding.
    pub fn to_json(&self) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
        self.validate()?;
        canonical(self)
    }

    fn validate(&self) -> Result<(), QualificationEvidenceLedgerError> {
        if self.schema != "auths.qualification-client-bridge-binding/1"
            || !digest(&self.source_context_sha256)
            || self.client_uid == 0
            || self.client_uid == u32::MAX
            || self.client_gid == u32::MAX
            || self.client_process_id == 0
            || self.client_start_time_ticks == 0
            || !digest(&self.client_executable_sha256)
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        Ok(())
    }
}

/// Closed client-proxy observation accepted by the client-proxy source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum QualificationClientProxyObservationV1 {
    RequestReceived {
        request_input_sha256: String,
        principal_sha256: String,
        idempotency_sha256: Option<String>,
        preparation_input_sha256: Option<String>,
    },
    ResponseProjected {
        result_sha256: String,
        journal_projection_kinds: Vec<QualificationEvidenceEventKind>,
        outcome: QualificationOutcomeKind,
        completion: Option<QualificationCompletion>,
        recovery_id: Option<String>,
        error_code: Option<String>,
        issue_metadata_sha256: Option<String>,
        receipt_ids: Vec<String>,
    },
    CancellationObserved {
        result_sha256: String,
        journal_projection_kinds: Vec<QualificationEvidenceEventKind>,
        outcome: QualificationOutcomeKind,
        completion: Option<QualificationCompletion>,
        recovery_id: Option<String>,
        error_code: Option<String>,
        issue_metadata_sha256: Option<String>,
        receipt_ids: Vec<String>,
    },
}

/// One typed public-client boundary record. It cannot express another
/// source's event kinds or payloads.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationClientProxyRecordV1 {
    pub schema: String,
    pub context: QualificationSourceEventContextV1,
    pub observation: QualificationClientProxyObservationV1,
}

/// Closed connection/credential observation accepted by the broker source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum QualificationCredentialBrokerObservationV1 {
    ConnectionReread {
        connection_id_sha256: Option<String>,
        connection_alias_sha256: Option<String>,
        descriptor_sha256: Option<String>,
        account_sha256: Option<String>,
    },
    CredentialLeaseAttempted {
        lease_sha256: String,
        requested_scope_sha256: String,
        effective_scope_sha256: String,
    },
    CredentialLeaseSucceeded {
        lease_sha256: String,
        requested_scope_sha256: String,
        effective_scope_sha256: String,
    },
    CredentialLeaseClosed {
        lease_sha256: String,
        requested_scope_sha256: String,
        effective_scope_sha256: String,
    },
}

/// One typed broker audit record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCredentialBrokerRecordV1 {
    pub schema: String,
    pub context: QualificationSourceEventContextV1,
    pub observation: QualificationCredentialBrokerObservationV1,
}

/// Closed profile-state transition accepted by the independent state reader.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum QualificationProfileStateObservationV1 {
    ReservationDurable { reservation_sha256: String },
    ReservationReleased { reservation_sha256: String },
    ReservationConsumed { reservation_sha256: String },
    ReservationRetained { reservation_sha256: String },
}

/// One typed profile-state reader record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationProfileStateRecordV1 {
    pub schema: String,
    pub context: QualificationSourceEventContextV1,
    pub observation: QualificationProfileStateObservationV1,
}

/// Capability-free state fact returned by one domain-owned protected
/// profile-state inspector. The reader supplies ordering and source identity;
/// concrete profiles remain responsible for deriving these facts from their
/// own canonical durable store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationProfileStateFactV1 {
    pub operation_id: String,
    pub connection_generation: u64,
    pub observation: QualificationProfileStateObservationV1,
}

/// Closed provider-transport boundary accepted by the provider proxy source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum QualificationProviderProxyObservationV1 {
    ProviderRequestWritten {
        request_sha256: String,
        credential_lease_sha256: String,
    },
    ProviderResponseObserved {
        response_sha256: String,
    },
    ProviderReconciliationRequested {
        request_sha256: String,
        credential_lease_sha256: String,
    },
    ProviderReconciliationObserved {
        response_sha256: String,
    },
}

/// One typed provider-transport proxy record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationProviderProxyRecordV1 {
    pub schema: String,
    pub context: QualificationSourceEventContextV1,
    pub observation: QualificationProviderProxyObservationV1,
}

/// One native portable-receipt verification record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationReceiptVerifierRecordV1 {
    pub schema: String,
    pub context: QualificationSourceEventContextV1,
    pub receipt_id: String,
    pub receipt_bytes_sha256: String,
    pub decoded_claims_sha256: String,
    pub profile_inspection_sha256: String,
}

/// One independently credentialed provider-truth observation record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationProviderObserverRecordV1 {
    pub schema: String,
    pub context: QualificationSourceEventContextV1,
    pub effect: QualificationEffect,
    pub provider_truth_sha256: String,
}

/// Narrow Supervisor-owned context for one crash phase.
///
/// The immutable ledger plan owns repository, workflow, run, provider-row,
/// ordering, and recovery-key policy. This context names only the selected
/// phase, protected process identities, and controller-minted crash identity;
/// it deliberately does not duplicate the ledger plan or append sequence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCrashPhaseContextV1 {
    pub schema: String,
    pub source_context_sha256: String,
    pub domain: String,
    pub phase: QualificationEvidencePhasePlanV1,
    pub supervisor_source_uid: u32,
    pub agent_uid: u32,
    pub agent_gid: u32,
    pub supervisor_source_identity: String,
    pub supervisor_generation: u32,
    pub agent_generation: u32,
    pub agent_launcher_artifact_sha256: String,
    pub agent_executable_sha256: String,
    pub control_operation_id: String,
    pub controller_nonce_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationJournalDecisionContextRecord {
    pub schema: String,
    pub repository_id: String,
    pub workflow_path: String,
    pub workflow_revision: String,
    pub candidate_revision: String,
    pub attester_revision: String,
    pub run_id: String,
    pub run_attempt: u32,
    pub domain: String,
    pub target: QualificationTarget,
    pub protected_environment: String,
    pub provider_run_id: String,
    pub ledger_id: String,
    pub session_nonce_sha256: String,
    pub scenario_id: String,
    pub phase_index: u8,
    pub role: QualificationOperationRole,
    pub profile: String,
    pub operation_plan_sha256: String,
    pub scenario_program_sha256: String,
    pub failpoint: Option<QualificationFailpoint>,
    pub supervisor_controller_uid: u32,
    pub supervisor_source_uid: u32,
    pub journal_reader_uid: u32,
    pub agent_uid: u32,
    pub agent_gid: u32,
    pub supervisor_source_identity: String,
    pub supervisor_source_artifact_sha256: String,
    pub supervisor_controller_artifact_sha256: String,
    pub journal_reader_source_identity: String,
    pub journal_reader_source_artifact_sha256: String,
    pub journal_reader_key_id: String,
    pub source_context_sha256: String,
    pub supervisor_generation: u32,
    pub agent_generation: u32,
    pub agent_process_id: u32,
    pub agent_boot_sha256: String,
    pub agent_start_time_ticks: u64,
    pub agent_launcher_artifact_sha256: String,
    pub agent_executable_sha256: String,
    pub agent_configuration_sha256: String,
    pub agent_state_directory_sha256: String,
    pub agent_cgroup_sha256: String,
    pub journal_path_sha256: String,
    pub journal_device: u64,
    pub journal_inode: u64,
    pub journal_owner_uid: u32,
    pub journal_mode: u32,
    pub journal_length: u64,
    pub boundary_ordinal: u32,
    pub boundary_projection_sha256: String,
    pub operation_id: String,
    pub control_operation_id: Option<String>,
    pub controller_nonce_sha256: Option<String>,
    pub journal_revision: u64,
    pub journal_record_sha256: String,
    pub decision_snapshot_sha256: String,
    pub durable_ack_sha256: String,
}

/// Exact process identity independently observed for one protected crash action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCrashProcessIdentityV1 {
    pub agent_generation: u32,
    pub agent_process_id: u32,
    pub agent_boot_sha256: String,
    pub agent_start_time_ticks: u64,
    pub agent_launcher_artifact_sha256: String,
    pub agent_executable_sha256: String,
    pub agent_configuration_sha256: String,
    pub agent_state_directory_sha256: String,
    pub agent_cgroup_sha256: String,
}

/// Action-specific kernel and durability facts retained for a crash phase.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum QualificationCrashActionFactsV1 {
    FailpointAcknowledged {
        process: QualificationCrashProcessIdentityV1,
        durable_ack_sha256: Option<String>,
        boundary_event_sha256: String,
    },
    ProcessKilled {
        process: QualificationCrashProcessIdentityV1,
        acknowledgement_event_sha256: String,
        signal: String,
        cgroup_empty_after_kill: bool,
    },
    ProcessRestarted {
        killed_process: QualificationCrashProcessIdentityV1,
        restarted_process: QualificationCrashProcessIdentityV1,
        kill_event_sha256: String,
        control_plane_ready: bool,
    },
}

/// Supervisor-owned retained record for one acknowledgement, kill, or restart.
///
/// The compact crash context names one phase from the immutable ledger plan
/// plus the protected process and control identities. Repository, run,
/// ordering, and recovery policy remain owned by the ledger plan and appender.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCrashActionRecordV1 {
    pub schema: String,
    pub crash_context: QualificationCrashPhaseContextV1,
    pub sequence: u32,
    pub previous_event_sha256: String,
    pub profile: String,
    pub supervisor_controller_uid: u32,
    pub supervisor_source_artifact_sha256: String,
    pub supervisor_controller_artifact_sha256: String,
    pub operation_id: Option<String>,
    pub connection_generation: Option<String>,
    pub durable_ack_sha256: Option<String>,
    pub facts: QualificationCrashActionFactsV1,
}

impl QualificationCrashPhaseContextV1 {
    /// Validates the compact crash-phase context grammar.
    pub fn validate(&self) -> Result<(), QualificationEvidenceLedgerError> {
        let expected_scenario = self
            .phase
            .failpoint
            .map(|failpoint| format!("crash-{}", failpoint.as_str()));
        if self.schema != "auths.qualification-crash-phase-context/1"
            || !digest(&self.source_context_sha256)
            || !lower_token(&self.domain)
            || self.phase.failpoint.is_none()
            || expected_scenario.as_deref() != Some(self.phase.scenario_id.as_str())
            || !(1..=8).contains(&self.phase.phase_index)
            || !semantic_profile(&self.phase.profile)
            || !digest(&self.phase.operation_plan_sha256)
            || !digest(&self.phase.scenario_program_sha256)
            || !self.phase.credential_requirement.valid()
            || self.supervisor_source_uid == 0
            || self.agent_uid == 0
            || self.agent_gid == 0
            || self.supervisor_source_uid == self.agent_uid
            || !registered_token(&self.supervisor_source_identity)
            || self.supervisor_generation == 0
            || self.agent_generation == 0
            || !digest(&self.agent_launcher_artifact_sha256)
            || !digest(&self.agent_executable_sha256)
            || !registered_token(&self.control_operation_id)
            || !digest(&self.controller_nonce_sha256)
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        Ok(())
    }

    /// Exact-binds every plan-owned field to the Supervisor context.
    #[must_use]
    pub fn binds_context(&self, context: &QualificationJournalDecisionContextRecord) -> bool {
        self.phase.scenario_id == context.scenario_id
            && self.phase.phase_index == context.phase_index
            && self.phase.role == context.role
            && self.phase.profile == context.profile
            && self.phase.operation_plan_sha256 == context.operation_plan_sha256
            && self.phase.scenario_program_sha256 == context.scenario_program_sha256
            && self.phase.failpoint == context.failpoint
            && self.supervisor_source_uid == context.supervisor_source_uid
            && self.agent_uid == context.agent_uid
            && self.agent_gid == context.agent_gid
            && self.supervisor_source_identity == context.supervisor_source_identity
            && self.source_context_sha256 == context.source_context_sha256
            && self.supervisor_generation == context.supervisor_generation
            && self.agent_generation == context.agent_generation
            && self.agent_launcher_artifact_sha256 == context.agent_launcher_artifact_sha256
            && self.agent_executable_sha256 == context.agent_executable_sha256
            && context.control_operation_id.as_deref() == Some(self.control_operation_id.as_str())
            && context.controller_nonce_sha256.as_deref()
                == Some(self.controller_nonce_sha256.as_str())
    }

    /// Exact-binds the crash-only phase plan to the immutable provider-row
    /// ledger plan that owns its run, source context, and key-validity window.
    pub fn binds_ledger_plan(
        &self,
        ledger: &QualificationEvidenceLedgerPlanV1,
    ) -> Result<bool, QualificationEvidenceLedgerError> {
        self.validate()?;
        ledger.validate()?;
        Ok(
            self.source_context_sha256 == ledger.source_context_sha256()?
                && self.domain == ledger.domain
                && self.agent_uid == ledger.agent_uid
                && self.agent_gid == ledger.agent_gid
                && self.agent_executable_sha256 == ledger.agent_executable_sha256
                && ledger.phases.iter().any(|phase| phase == &self.phase),
        )
    }
}

/// Public, capability-free projection of the exact first durable decision.
///
/// The protected journal reader constructs this only after validating the
/// complete private journal record at revision one. Recovery handles, opaque
/// profile state, issue/value/progress bytes, provider data, and raw receipt
/// bytes are intentionally absent from retained evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationDecisionSnapshotV1 {
    pub schema: String,
    pub operation_id: String,
    pub profile: String,
    pub connection_generation: String,
    pub journal_revision: u64,
    pub state: QualificationDecisionSnapshotState,
    pub decision_class: QualificationReceiptDecisionClass,
    pub canonical_input_sha256: String,
    pub idempotency_sha256: Option<String>,
    pub canonical_action_sha256: String,
    pub receipt_action_sha256: String,
    pub receipt_context_sha256: String,
    pub authority_sha256: String,
    pub configuration_sha256: String,
    pub runtime_contract_sha256: String,
    pub preparation_sha256: String,
    pub decision_receipt_id: String,
    pub decision_receipt_bytes_sha256: String,
    pub decoded_claims_sha256: String,
    pub recovery_key_id: String,
    pub recovery_public_key_base64url: String,
    pub receipt_trust_anchor_sha256: String,
}

/// Capability-free acknowledgement emitted only after the first decision
/// record is durably committed by the qualification agent.
///
/// The record digest commits the private store representation without
/// exporting its recovery handle or opaque profile state. The protected
/// controller independently rereads that store record before deriving the
/// public decision snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationDurableDecisionAckV1 {
    /// Exact versioned record identity.
    pub schema: String,
    /// Agent-minted operation identity selected by the durable record.
    pub operation_id: String,
    /// Exact first-decision journal revision. This is always one.
    pub journal_revision: u64,
    /// SHA-256 of the canonical private journal record, never its bytes.
    pub journal_record_sha256: String,
    /// Nonzero deployment generation of the exercised agent process.
    pub agent_generation: u32,
    /// Controller-minted identity bound to this one launched child.
    pub control_operation_id: Option<String>,
    /// Controller-minted nonce commitment delivered over the connected launch
    /// channel rather than discovered through a filesystem socket.
    pub controller_nonce_sha256: Option<String>,
}

/// Closed public state at the first durable decision boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationDecisionSnapshotState {
    Ready,
    Denied,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationJournalDecisionContextSigning {
    algorithm: String,
    key_id: String,
    signature_base64url: String,
}

/// Canonical supervisor-signed decision context consumed by the journal
/// reader. Candidate output cannot author a process identity or durable ack.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationJournalDecisionContext {
    schema: String,
    record: QualificationJournalDecisionContextRecord,
    signing: QualificationJournalDecisionContextSigning,
}

/// Canonical Supervisor signature over one exact crash-action record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCrashActionContextV1 {
    schema: String,
    record: QualificationCrashActionRecordV1,
    signing: QualificationJournalDecisionContextSigning,
}

/// Commitment from one reviewed phase to its canonical common projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationEvidencePhaseCommitment {
    pub scenario_id: String,
    pub phase_index: u8,
    pub role: QualificationOperationRole,
    pub profile: String,
    pub failpoint: Option<QualificationFailpoint>,
    pub operation_plan_sha256: String,
    pub scenario_program_sha256: String,
    pub credential_requirement: QualificationCredentialRequirementV1,
    pub common_phase_evidence_sha256: String,
    pub first_event_sequence: u32,
    pub last_event_sequence: u32,
}

/// Immutable public authorization facts for the phase's one credential
/// lease. The workload itself remains redacted behind its commitment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCredentialRequirementV1 {
    pub workload_id_sha256: String,
    pub provider_kind: String,
    pub contract: String,
    pub descriptor_schema: String,
    pub credential_scope: String,
}

impl QualificationCredentialRequirementV1 {
    fn valid(&self) -> bool {
        digest(&self.workload_id_sha256)
            && lower_token(&self.provider_kind)
            && semantic_profile(&self.contract)
            && semantic_profile(&self.descriptor_schema)
            && semantic_profile(&self.credential_scope)
    }
}

/// Immutable source-signing plan for one reviewed qualification phase.
///
/// Event ranges and the protected common-projection digest are deliberately
/// absent: the provider-free ledger assembler derives those values from the
/// exact signed source-record roster and phase projection bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationEvidencePhasePlanV1 {
    pub scenario_id: String,
    pub phase_index: u8,
    pub role: QualificationOperationRole,
    pub profile: String,
    pub failpoint: Option<QualificationFailpoint>,
    pub operation_plan_sha256: String,
    pub scenario_program_sha256: String,
    pub credential_requirement: QualificationCredentialRequirementV1,
}

/// Recomputes the Supervisor-owned commitment for one reviewed phase.
///
/// The controller is a distinct-UID process of the exact same protected
/// Supervisor artifact as the seed-bearing signer, so the artifact digest is
/// part of the commitment without adding another mutable policy field.
pub fn qualification_supervisor_phase_context_sha256(
    phase: &QualificationEvidencePhasePlanV1,
    supervisor_artifact_sha256: &str,
) -> Result<String, QualificationEvidenceLedgerError> {
    if !digest(supervisor_artifact_sha256)
        || !registered_token(&phase.scenario_id)
        || !(1..=8).contains(&phase.phase_index)
        || !semantic_profile(&phase.profile)
        || !digest(&phase.operation_plan_sha256)
        || !digest(&phase.scenario_program_sha256)
        || !phase.credential_requirement.valid()
    {
        return Err(QualificationEvidenceLedgerError::InvalidPhase);
    }
    let mut preimage = b"AUTHS-QUALIFICATION-PHASE-CONTEXT\0\x01".to_vec();
    preimage.extend_from_slice(supervisor_artifact_sha256.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&canonical(phase)?);
    Ok(hex::encode(Sha256::digest(preimage)))
}

/// Returns the commitment to the exact canonical marker durably published by
/// the common appender for an ordinary source event.
#[must_use]
pub fn qualification_event_marker_sha256(
    sequence: u32,
    source: QualificationEvidenceSource,
) -> String {
    let marker = format!(
        "{{\"sequence\":{sequence},\"source\":\"{}\"}}",
        source_token(source)
    );
    hex::encode(Sha256::digest(marker.as_bytes()))
}

/// Canonical provider-free plan shared by all protected source signers and
/// the ledger assembler.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationEvidenceLedgerPlanV1 {
    pub schema: String,
    pub repository_id: String,
    pub workflow_path: String,
    pub workflow_revision: String,
    pub candidate_revision: String,
    pub attester_revision: String,
    pub run_id: String,
    pub run_attempt: u32,
    pub domain: String,
    pub target: QualificationTarget,
    pub protected_environment: String,
    pub provider_run_id: String,
    pub ledger_id: String,
    pub session_nonce_sha256: String,
    /// Protected no-secret controller identity allowed to request phase
    /// boundary signatures from the Supervisor source.
    pub supervisor_controller_uid: u32,
    /// Exact protected Supervisor controller executable allowed to sequence
    /// phase boundaries without holding the Supervisor signing seed.
    pub supervisor_controller_artifact_sha256: String,
    /// Exact protected provider-free ledger appender/sequencer executable.
    pub ledger_appender_artifact_sha256: String,
    /// Exact unprivileged identity of the exercised qualification agent.
    pub agent_uid: u32,
    pub agent_gid: u32,
    /// Digest of the verified release-built qualification agent executable.
    pub agent_executable_sha256: String,
    /// Deployed public recovery-handle verification identity.
    pub recovery_key_id: String,
    pub recovery_public_key_base64url: String,
    pub phases: Vec<QualificationEvidencePhasePlanV1>,
    pub started_at_unix_seconds: u64,
    pub deadline_at_unix_seconds: u64,
}

/// Unsigned exact record produced from protected, independently sourced facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationEvidenceLedgerRecord {
    pub schema: String,
    pub repository_id: String,
    pub workflow_path: String,
    pub workflow_revision: String,
    pub candidate_revision: String,
    pub attester_revision: String,
    pub run_id: String,
    pub run_attempt: u32,
    pub domain: String,
    pub target: QualificationTarget,
    pub protected_environment: String,
    pub provider_run_id: String,
    pub ledger_id: String,
    pub session_nonce_sha256: String,
    pub supervisor_controller_uid: u32,
    pub supervisor_controller_artifact_sha256: String,
    pub ledger_appender_artifact_sha256: String,
    pub agent_uid: u32,
    pub agent_gid: u32,
    pub agent_executable_sha256: String,
    pub recovery_key_id: String,
    pub recovery_public_key_base64url: String,
    pub phase_commitments: Vec<QualificationEvidencePhaseCommitment>,
    pub events: Vec<QualificationEvidenceEvent>,
    pub started_at_unix_seconds: u64,
    pub deadline_at_unix_seconds: u64,
    pub completed_at_unix_seconds: u64,
}

/// Actual agent trust identity independently read from durable decision state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationAgentTrust<'a> {
    recovery_key_id: &'a str,
    recovery_public_key_base64url: &'a str,
    receipt_trust_anchor_sha256: &'a str,
}

impl<'a> QualificationAgentTrust<'a> {
    /// Returns the exercised agent's recovery verification key ID.
    #[must_use]
    pub const fn recovery_key_id(self) -> &'a str {
        self.recovery_key_id
    }

    /// Returns the exercised agent's recovery Ed25519 public key.
    #[must_use]
    pub const fn recovery_public_key_base64url(self) -> &'a str {
        self.recovery_public_key_base64url
    }

    /// Returns the exercised agent's canonical receipt-anchor commitment.
    #[must_use]
    pub const fn receipt_trust_anchor_sha256(self) -> &'a str {
        self.receipt_trust_anchor_sha256
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationEvidenceLedgerSigning {
    algorithm: String,
    key_id: String,
    signature_base64url: String,
}

/// Canonical signed protected-supervisor event ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationEvidenceLedger {
    schema: String,
    record: QualificationEvidenceLedgerRecord,
    signing: QualificationEvidenceLedgerSigning,
}

impl QualificationEvidenceLedgerRecord {
    /// Validates context, phase coverage, source ownership, and the hash chain.
    pub fn validate(&self) -> Result<(), QualificationEvidenceLedgerError> {
        if self.schema != "auths.profile-qualification-evidence-ledger-record/1"
            || !decimal(&self.repository_id)
            || !workflow_path(&self.workflow_path)
            || !lower_hex(&self.workflow_revision, 40)
            || !lower_hex(&self.candidate_revision, 40)
            || !lower_hex(&self.attester_revision, 40)
            || !decimal(&self.run_id)
            || self.run_attempt == 0
            || !lower_token(&self.domain)
            || !registered_token(&self.protected_environment)
            || !registered_token(&self.provider_run_id)
            || !registered_token(&self.ledger_id)
            || !digest(&self.session_nonce_sha256)
            || self.supervisor_controller_uid == 0
            || self.supervisor_controller_uid == u32::MAX
            || !digest(&self.supervisor_controller_artifact_sha256)
            || !digest(&self.ledger_appender_artifact_sha256)
            || self.agent_uid == 0
            || self.agent_uid == u32::MAX
            || self.agent_gid == 0
            || self.agent_gid == u32::MAX
            || self.agent_uid == self.supervisor_controller_uid
            || !digest(&self.agent_executable_sha256)
            || !registered_token(&self.recovery_key_id)
            || decode_fixed::<32>(&self.recovery_public_key_base64url).is_err()
            || self.phase_commitments.is_empty()
            || self.phase_commitments.len() > MAX_PHASES
            || self.events.is_empty()
            || self.events.len() > MAX_EVENTS
            || self.started_at_unix_seconds >= self.completed_at_unix_seconds
            || self.completed_at_unix_seconds > self.deadline_at_unix_seconds
            || self
                .deadline_at_unix_seconds
                .checked_sub(self.started_at_unix_seconds)
                .is_none_or(|duration| duration > MAX_QUALIFICATION_SECONDS)
        {
            return Err(QualificationEvidenceLedgerError::InvalidRecord);
        }
        let source_context_sha256 = self.source_context_sha256()?;
        if self
            .events
            .iter()
            .any(|event| event.source_context_sha256 != source_context_sha256)
        {
            return Err(QualificationEvidenceLedgerError::InvalidRecord);
        }
        validate_events(&self.events)?;
        validate_agent_trust(&self.events)?;
        if self.events.iter().any(|event| {
            matches!(
                &event.payload,
                QualificationEvidenceEventPayload::Decision {
                    recovery_key_id,
                    recovery_public_key_base64url,
                    ..
                } if recovery_key_id != &self.recovery_key_id
                    || recovery_public_key_base64url != &self.recovery_public_key_base64url
            )
        }) {
            return Err(QualificationEvidenceLedgerError::InvalidRecord);
        }
        validate_phases(&self.phase_commitments, &self.events)
    }

    /// Returns the actual exercised agent trust identity authenticated by the
    /// independently signed journal-reader decision events.
    #[must_use]
    pub fn agent_trust(&self) -> Option<QualificationAgentTrust<'_>> {
        self.events.iter().find_map(|event| {
            if let QualificationEvidenceEventPayload::Decision {
                recovery_key_id,
                recovery_public_key_base64url,
                receipt_trust_anchor_sha256,
                ..
            } = &event.payload
            {
                Some(QualificationAgentTrust {
                    recovery_key_id,
                    recovery_public_key_base64url,
                    receipt_trust_anchor_sha256,
                })
            } else {
                None
            }
        })
    }

    /// Finds the one exact reviewed phase commitment.
    #[must_use]
    pub fn phase(
        &self,
        scenario_id: &str,
        phase_index: u8,
    ) -> Option<&QualificationEvidencePhaseCommitment> {
        self.phase_commitments
            .iter()
            .find(|phase| phase.scenario_id == scenario_id && phase.phase_index == phase_index)
    }

    /// Returns the exact byte-sorted reviewed phase roster.
    #[must_use]
    pub fn phases(&self) -> &[QualificationEvidencePhaseCommitment] {
        &self.phase_commitments
    }

    /// Returns the exact event slice committed for one reviewed phase.
    #[must_use]
    pub fn phase_events(
        &self,
        phase: &QualificationEvidencePhaseCommitment,
    ) -> Option<&[QualificationEvidenceEvent]> {
        let first = usize::try_from(phase.first_event_sequence.checked_sub(1)?).ok()?;
        let last = usize::try_from(phase.last_event_sequence).ok()?;
        self.events.get(first..last)
    }

    /// Returns the observed repository identifier.
    #[must_use]
    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    /// Returns the generated workflow entrypoint that launched the run.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Returns the protected workflow revision.
    #[must_use]
    pub fn workflow_revision(&self) -> &str {
        &self.workflow_revision
    }

    /// Returns the protected attester/supervisor code revision.
    #[must_use]
    pub fn attester_revision(&self) -> &str {
        &self.attester_revision
    }

    /// Returns the candidate revision whose installed code was exercised.
    #[must_use]
    pub fn candidate_revision(&self) -> &str {
        &self.candidate_revision
    }

    /// Returns the protected workflow run identifier.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Returns the protected workflow run attempt.
    #[must_use]
    pub const fn run_attempt(&self) -> u32 {
        self.run_attempt
    }

    /// Returns the provider domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the exact target.
    #[must_use]
    pub const fn target(&self) -> QualificationTarget {
        self.target
    }

    /// Returns the manifest-owned protected environment.
    #[must_use]
    pub fn protected_environment(&self) -> &str {
        &self.protected_environment
    }

    /// Returns the exact provider matrix row.
    #[must_use]
    pub fn provider_run_id(&self) -> &str {
        &self.provider_run_id
    }

    /// Returns the protected supervisor ledger identifier.
    #[must_use]
    pub fn ledger_id(&self) -> &str {
        &self.ledger_id
    }

    /// Returns the supervisor-minted session nonce commitment.
    #[must_use]
    pub fn session_nonce_sha256(&self) -> &str {
        &self.session_nonce_sha256
    }

    /// Returns the first protected event time in the ledger interval.
    #[must_use]
    pub const fn started_at_unix_seconds(&self) -> u64 {
        self.started_at_unix_seconds
    }

    /// Returns the last protected event time in the ledger interval.
    #[must_use]
    pub const fn completed_at_unix_seconds(&self) -> u64 {
        self.completed_at_unix_seconds
    }

    /// Returns the immutable protected deadline used by every source signer.
    #[must_use]
    pub const fn deadline_at_unix_seconds(&self) -> u64 {
        self.deadline_at_unix_seconds
    }

    /// Recomputes the immutable source-signing context shared by every event.
    pub fn source_context_sha256(&self) -> Result<String, QualificationEvidenceLedgerError> {
        self.source_plan().source_context_sha256()
    }

    /// Projects the exact immutable source-signing plan from a complete
    /// record. This is also used by retained verifiers to prevent the source
    /// context and sealed record grammars from drifting apart.
    #[must_use]
    pub fn source_plan(&self) -> QualificationEvidenceLedgerPlanV1 {
        QualificationEvidenceLedgerPlanV1 {
            schema: "auths.profile-qualification-evidence-ledger-plan/1".into(),
            repository_id: self.repository_id.clone(),
            workflow_path: self.workflow_path.clone(),
            workflow_revision: self.workflow_revision.clone(),
            candidate_revision: self.candidate_revision.clone(),
            attester_revision: self.attester_revision.clone(),
            run_id: self.run_id.clone(),
            run_attempt: self.run_attempt,
            domain: self.domain.clone(),
            target: self.target,
            protected_environment: self.protected_environment.clone(),
            provider_run_id: self.provider_run_id.clone(),
            ledger_id: self.ledger_id.clone(),
            session_nonce_sha256: self.session_nonce_sha256.clone(),
            supervisor_controller_uid: self.supervisor_controller_uid,
            supervisor_controller_artifact_sha256: self
                .supervisor_controller_artifact_sha256
                .clone(),
            ledger_appender_artifact_sha256: self.ledger_appender_artifact_sha256.clone(),
            agent_uid: self.agent_uid,
            agent_gid: self.agent_gid,
            agent_executable_sha256: self.agent_executable_sha256.clone(),
            recovery_key_id: self.recovery_key_id.clone(),
            recovery_public_key_base64url: self.recovery_public_key_base64url.clone(),
            phases: self
                .phase_commitments
                .iter()
                .map(|phase| QualificationEvidencePhasePlanV1 {
                    scenario_id: phase.scenario_id.clone(),
                    phase_index: phase.phase_index,
                    role: phase.role,
                    profile: phase.profile.clone(),
                    failpoint: phase.failpoint,
                    operation_plan_sha256: phase.operation_plan_sha256.clone(),
                    scenario_program_sha256: phase.scenario_program_sha256.clone(),
                    credential_requirement: phase.credential_requirement.clone(),
                })
                .collect(),
            started_at_unix_seconds: self.started_at_unix_seconds,
            deadline_at_unix_seconds: self.deadline_at_unix_seconds,
        }
    }

    fn signature_preimage(&self) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
        let canonical = canonical(self)?;
        let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 1 + canonical.len());
        preimage.extend_from_slice(SIGNATURE_DOMAIN);
        preimage.push(0);
        preimage.extend_from_slice(&canonical);
        Ok(preimage)
    }
}

const fn journal_projection_for_outcome(
    outcome: crate::QualificationOutcomeKind,
) -> Option<(QualificationJournalState, crate::QualificationEffect, bool)> {
    match outcome {
        crate::QualificationOutcomeKind::Denied => Some((
            QualificationJournalState::Denied,
            crate::QualificationEffect::NotApplied,
            true,
        )),
        crate::QualificationOutcomeKind::Unavailable => Some((
            QualificationJournalState::Unavailable,
            crate::QualificationEffect::NotApplied,
            true,
        )),
        crate::QualificationOutcomeKind::Completed => Some((
            QualificationJournalState::Completed,
            crate::QualificationEffect::Applied,
            true,
        )),
        crate::QualificationOutcomeKind::Partial => Some((
            QualificationJournalState::Partial,
            crate::QualificationEffect::Applied,
            true,
        )),
        crate::QualificationOutcomeKind::NotApplied => Some((
            QualificationJournalState::NotApplied,
            crate::QualificationEffect::NotApplied,
            true,
        )),
        crate::QualificationOutcomeKind::RecoveryRequired => Some((
            QualificationJournalState::RecoveryRequired,
            crate::QualificationEffect::Possible,
            false,
        )),
        crate::QualificationOutcomeKind::Conflict => None,
    }
}

/// Exact-compares one protected common phase projection to the authenticated
/// source events from which every field is derived.
///
/// This provider-free check is shared by the ledger assembler and every later
/// observer/attester pass. A well-shaped caller-authored projection is never
/// sufficient by itself.
#[allow(clippy::too_many_lines)]
pub fn qualification_common_phase_matches_ledger(
    ledger: &QualificationEvidenceLedgerRecord,
    commitment: &QualificationEvidencePhaseCommitment,
    phase: &crate::QualificationCommonPhaseEvidence,
) -> Result<bool, QualificationEvidenceLedgerError> {
    use QualificationEvidenceEventKind as Kind;
    use QualificationEvidenceEventPayload as Payload;
    use QualificationEvidenceSource as Source;

    let Some(events) = ledger.phase_events(commitment) else {
        return Ok(false);
    };
    if phase.schema != "auths.profile-qualification-common-phase-evidence/1"
        || phase.repository_id != ledger.repository_id
        || phase.workflow_run_id != ledger.run_id
        || phase.workflow_run_attempt != ledger.run_attempt
        || phase.candidate_revision != ledger.candidate_revision
        || phase.domain != ledger.domain
        || phase.target != ledger.target
        || phase.protected_environment != ledger.protected_environment
        || phase.provider_run_id != ledger.provider_run_id
        || phase.ledger_id != ledger.ledger_id
        || phase.session_nonce_sha256 != ledger.session_nonce_sha256
        || phase.scenario_id != commitment.scenario_id
        || phase.phase_index != commitment.phase_index
        || phase.role != commitment.role
        || phase.profile != commitment.profile
        || phase.failpoint != commitment.failpoint
        || phase.operation_plan_sha256 != commitment.operation_plan_sha256
        || phase.scenario_program_sha256 != commitment.scenario_program_sha256
        || phase.first_event_sequence != commitment.first_event_sequence
        || phase.last_event_sequence != commitment.last_event_sequence
        || phase.supervisor_generation == 0
        || events
            .iter()
            .any(|event| event.supervisor_generation != phase.supervisor_generation)
        || phase.instances.len() > 8
        || phase
            .instances
            .windows(2)
            .any(|pair| pair[0].projection.operation_id >= pair[1].projection.operation_id)
        || phase.attempts.is_empty()
        || phase.attempts.len() > 8
        || phase.attempts.iter().enumerate().any(|(index, attempt)| {
            attempt.sequence != u8::try_from(index + 1).unwrap_or(u8::MAX)
                || attempt.validate().is_err()
        })
        || phase.instances.iter().any(|instance| {
            instance.projection.validate().is_err()
                || instance.receipt_claims.len() > 16
                || instance
                    .receipt_claims
                    .iter()
                    .enumerate()
                    .any(|(index, claim)| {
                        claim.sequence != u8::try_from(index + 1).unwrap_or(u8::MAX)
                            || claim.validate().is_err()
                            || claim.operation_id != instance.projection.operation_id
                            || claim.profile != phase.profile
                            || claim.connection_generation
                                != instance.projection.connection_generation
                            || !phase.attempts.iter().any(|attempt| {
                                claim.attempt_sequence == attempt.sequence
                                    && claim.request_id == attempt.request_id
                                    && attempt.operation_id.as_deref()
                                        == Some(claim.operation_id.as_str())
                                    && attempt.connection_generation.as_deref()
                                        == Some(claim.connection_generation.as_str())
                            })
                    })
                || !common_receipt_claims_match_attempts(instance, &phase.attempts, &phase.profile)
        })
    {
        return Ok(false);
    }
    let instance_ids = phase
        .instances
        .iter()
        .map(|instance| instance.projection.operation_id.as_str())
        .collect::<BTreeSet<_>>();
    if instance_ids.len() != phase.instances.len() {
        return Ok(false);
    }
    let event_operation_ids = events
        .iter()
        .filter_map(|event| event.operation_id.as_deref())
        .collect::<BTreeSet<_>>();
    if instance_ids != event_operation_ids {
        return Ok(false);
    }

    let attempt_request_ids = phase
        .attempts
        .iter()
        .map(|attempt| attempt.request_id.as_str())
        .collect::<BTreeSet<_>>();
    if attempt_request_ids.len() != phase.attempts.len() {
        return Ok(false);
    }
    let ingress = events
        .iter()
        .filter(|event| event.source == Source::ClientProxy && event.kind == Kind::RequestReceived)
        .collect::<Vec<_>>();
    let terminal_attempts = events
        .iter()
        .filter(|event| {
            event.source == Source::ClientProxy
                && matches!(
                    event.kind,
                    Kind::ResponseProjected | Kind::CancellationObserved
                )
        })
        .collect::<Vec<_>>();
    if ingress.len() != attempt_request_ids.len()
        || ingress
            .iter()
            .filter_map(|event| event.request_id.as_deref())
            .collect::<BTreeSet<_>>()
            != attempt_request_ids
        || terminal_attempts.len() != phase.attempts.len()
    {
        return Ok(false);
    }
    for attempt in &phase.attempts {
        let matching_terminal = terminal_attempts
            .iter()
            .filter(|event| {
                event.request_id.as_deref() == Some(attempt.request_id.as_str())
                    && event.client_result_sha256.as_deref() == Some(attempt.result_sha256.as_str())
            })
            .copied()
            .collect::<Vec<_>>();
        let journal_projection_kinds = events
            .iter()
            .filter(|event| {
                event.request_id.as_deref() == Some(attempt.request_id.as_str())
                    && matches!(
                        event.kind,
                        Kind::ReplayObserved | Kind::StatusObserved | Kind::RecoveryObserved
                    )
            })
            .map(|event| event.kind)
            .collect::<Vec<_>>();
        if matching_terminal.len() != 1
            || !matches!(
                &matching_terminal[0].payload,
                Payload::ClientResult {
                    journal_projection_kinds: observed,
                    ..
                } if observed == &journal_projection_kinds
            )
            || ingress
                .iter()
                .filter(|event| {
                    event.request_id.as_deref() == Some(attempt.request_id.as_str())
                        && matches!(
                            &event.payload,
                            Payload::Request {
                                request_input_sha256,
                                principal_sha256,
                                idempotency_sha256,
                                preparation_input_sha256,
                            } if request_input_sha256 == &attempt.request_input_sha256
                                && principal_sha256 == &attempt.principal_sha256
                                && idempotency_sha256 == &attempt.idempotency_sha256
                                && preparation_input_sha256 == &attempt.preparation_input_sha256
                        )
                })
                .count()
                != 1
        {
            return Ok(false);
        }
    }

    let claimed_receipts = phase
        .instances
        .iter()
        .flat_map(|instance| &instance.receipt_claims)
        .flat_map(|claim| {
            [
                claim.decision_receipt_id.as_deref(),
                claim.execution_receipt_id.as_deref(),
            ]
        })
        .flatten()
        .collect::<BTreeSet<_>>();
    let verified_receipts = events
        .iter()
        .filter(|event| event.kind == Kind::NativeReceiptVerified)
        .filter_map(|event| event.receipt_id.as_deref())
        .collect::<Vec<_>>();
    if verified_receipts.len() != claimed_receipts.len()
        || verified_receipts.into_iter().collect::<BTreeSet<_>>() != claimed_receipts
    {
        return Ok(false);
    }

    for instance in &phase.instances {
        let projection = &instance.projection;
        let operation_id = projection.operation_id.as_str();
        let operation_claimed_receipts = instance
            .receipt_claims
            .iter()
            .flat_map(|claim| {
                [
                    claim.decision_receipt_id.as_deref(),
                    claim.execution_receipt_id.as_deref(),
                ]
            })
            .flatten()
            .collect::<BTreeSet<_>>();
        let operation_verified_receipts = events
            .iter()
            .filter(|event| {
                event.kind == Kind::NativeReceiptVerified
                    && event.operation_id.as_deref() == Some(operation_id)
            })
            .filter_map(|event| event.receipt_id.as_deref())
            .collect::<Vec<_>>();
        if operation_verified_receipts.len() != operation_claimed_receipts.len()
            || operation_verified_receipts
                .into_iter()
                .collect::<BTreeSet<_>>()
                != operation_claimed_receipts
        {
            return Ok(false);
        }
        if events.iter().any(|event| {
            event.operation_id.as_deref() == Some(operation_id)
                && event.connection_generation.as_deref()
                    != Some(projection.connection_generation.as_str())
        }) {
            return Ok(false);
        }
        let count = |kind: Kind| {
            u32::try_from(
                events
                    .iter()
                    .filter(|event| {
                        event.operation_id.as_deref() == Some(operation_id) && event.kind == kind
                    })
                    .count(),
            )
            .unwrap_or(u32::MAX)
        };
        let counters = &projection.counters;
        let operation_attempts = phase
            .attempts
            .iter()
            .filter(|attempt| attempt.operation_id.as_deref() == Some(operation_id))
            .collect::<Vec<_>>();
        let projection_events = events
            .iter()
            .filter(|event| {
                event.operation_id.as_deref() == Some(operation_id)
                    && matches!(
                        event.kind,
                        Kind::ReplayObserved | Kind::StatusObserved | Kind::RecoveryObserved
                    )
            })
            .collect::<Vec<_>>();
        if projection_events.iter().any(|event| {
            operation_attempts
                .iter()
                .filter(|attempt| event.request_id.as_deref() == Some(attempt.request_id.as_str()))
                .count()
                != 1
        }) {
            return Ok(false);
        }
        for attempt in &operation_attempts {
            let request_events = projection_events
                .iter()
                .copied()
                .filter(|event| event.request_id.as_deref() == Some(attempt.request_id.as_str()))
                .collect::<Vec<_>>();
            let required_kind = match attempt.kind {
                crate::QualificationAttemptKind::Replay => Some(Kind::ReplayObserved),
                crate::QualificationAttemptKind::Status => Some(Kind::StatusObserved),
                crate::QualificationAttemptKind::Recover => Some(Kind::RecoveryObserved),
                crate::QualificationAttemptKind::Execute
                | crate::QualificationAttemptKind::Conflict
                | crate::QualificationAttemptKind::CancelAfterWrite => None,
            };
            if required_kind
                .is_some_and(|kind| !request_events.iter().any(|event| event.kind == kind))
            {
                return Ok(false);
            }
            let Some(last) = request_events.last() else {
                continue;
            };
            let Some((state, effect, terminal)) = journal_projection_for_outcome(attempt.outcome)
            else {
                return Ok(false);
            };
            if !matches!(
                &last.payload,
                Payload::JournalProjection {
                    state: observed_state,
                    effect: observed_effect,
                    terminal: observed_terminal,
                    completion,
                    ..
                } if *observed_state == state
                    && *observed_effect == effect
                    && *observed_terminal == terminal
                    && *completion == attempt.completion
            ) {
                return Ok(false);
            }
        }
        let reconciliation_origins = operation_attempts
            .iter()
            .filter(|attempt| {
                attempt.completion == Some(crate::QualificationCompletion::Reconciled)
                    && events.iter().any(|event| {
                        event.kind == Kind::RecoveryObserved
                            && event.operation_id.as_deref() == Some(operation_id)
                            && event.request_id.as_deref() == Some(attempt.request_id.as_str())
                    })
            })
            .collect::<Vec<_>>();
        if reconciliation_origins.len() > 1 {
            return Ok(false);
        }
        let derived_reconciled = reconciliation_origins.len() == 1;
        let recovery_required = operation_attempts
            .iter()
            .any(|attempt| attempt.outcome == crate::QualificationOutcomeKind::RecoveryRequired);
        let durable_terminal_outcome = operation_attempts.iter().find_map(|attempt| {
            matches!(
                attempt.outcome,
                crate::QualificationOutcomeKind::Denied
                    | crate::QualificationOutcomeKind::Unavailable
                    | crate::QualificationOutcomeKind::Completed
                    | crate::QualificationOutcomeKind::Partial
                    | crate::QualificationOutcomeKind::NotApplied
            )
            .then_some(attempt.outcome)
        });
        if durable_terminal_outcome.is_some_and(|expected| {
            operation_attempts.iter().any(|attempt| {
                matches!(
                    attempt.outcome,
                    crate::QualificationOutcomeKind::Denied
                        | crate::QualificationOutcomeKind::Unavailable
                        | crate::QualificationOutcomeKind::Completed
                        | crate::QualificationOutcomeKind::Partial
                        | crate::QualificationOutcomeKind::NotApplied
                ) && attempt.outcome != expected
            })
        }) {
            return Ok(false);
        }
        let credential_payloads = events
            .iter()
            .filter(|event| {
                event.operation_id.as_deref() == Some(operation_id)
                    && matches!(
                        event.kind,
                        Kind::CredentialLeaseAttempted
                            | Kind::CredentialLeaseSucceeded
                            | Kind::CredentialLeaseClosed
                    )
            })
            .map(|event| &event.payload)
            .collect::<Vec<_>>();
        let credential_lease_sha256 = credential_payloads
            .iter()
            .filter_map(|payload| match payload {
                Payload::Credential { lease_sha256, .. } => Some(lease_sha256.as_str()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let provider_request_lease_sha256 = events
            .iter()
            .filter(|event| {
                event.operation_id.as_deref() == Some(operation_id)
                    && matches!(
                        event.kind,
                        Kind::ProviderRequestWritten | Kind::ProviderReconciliationRequested
                    )
            })
            .filter_map(|event| match &event.payload {
                Payload::ProviderRequest {
                    credential_lease_sha256,
                    ..
                } => Some(credential_lease_sha256.as_str()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let reservation_sha256 = events
            .iter()
            .filter(|event| {
                event.operation_id.as_deref() == Some(operation_id)
                    && matches!(
                        event.kind,
                        Kind::ReservationDurable
                            | Kind::ReservationReleased
                            | Kind::ReservationConsumed
                            | Kind::ReservationRetained
                    )
            })
            .filter_map(|event| match &event.payload {
                Payload::Reservation { reservation_sha256 } => Some(reservation_sha256.as_str()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if counters.reservation_writes != count(Kind::ReservationDurable)
            || counters.reservation_releases != count(Kind::ReservationReleased)
            || counters.reservation_consumptions != count(Kind::ReservationConsumed)
            || counters.reservation_retentions != count(Kind::ReservationRetained)
            || counters.connection_rereads != count(Kind::ConnectionReread)
            || counters.credential_lease_attempts != count(Kind::CredentialLeaseAttempted)
            || counters.credential_leases != count(Kind::CredentialLeaseSucceeded)
            || counters.credential_lease_closes != count(Kind::CredentialLeaseClosed)
            || counters.provider_entry_markers != count(Kind::ProviderEntryDurable)
            || counters.provider_calls != count(Kind::ProviderRequestWritten)
            || counters.provider_request_writes != count(Kind::ProviderRequestWritten)
            || counters.provider_responses != count(Kind::ProviderResponseObserved)
            || counters.durable_provider_results != count(Kind::ProviderResultDurable)
            || counters.observations != count(Kind::ObservationDurable)
            || counters.receipt_writes
                != count(Kind::DecisionDurable).saturating_add(count(Kind::ExecutionReceiptDurable))
            || reservation_sha256.len() > 1
            || count(Kind::CommandDurable) != u32::from(projection.sealed_command_sha256.is_some())
            || count(Kind::ProviderResultDurable)
                != u32::from(projection.provider_result_sha256.is_some())
            || recovery_required && count(Kind::RecoveryRequiredDurable) == 0
            || count(Kind::ProviderTruthObserved) != u32::from(counters.provider_calls != 0)
            || projection.reconciled != derived_reconciled
            || events.iter().any(|event| {
                event.operation_id.as_deref() == Some(operation_id)
                    && event.kind == Kind::ConnectionReread
                    && !matches!(
                        &event.payload,
                        Payload::Connection {
                            connection_id_sha256,
                            connection_alias_sha256,
                            descriptor_sha256,
                            account_sha256,
                        } if connection_id_sha256 == &projection.connection_id_sha256
                            && connection_alias_sha256 == &projection.connection_alias_sha256
                            && descriptor_sha256
                                == &projection.connection_descriptor_sha256
                            && account_sha256 == &projection.connection_account_sha256
                    )
            })
            || credential_payloads
                .windows(2)
                .any(|pair| pair[0] != pair[1])
            || (!provider_request_lease_sha256.is_empty()
                && provider_request_lease_sha256 != credential_lease_sha256)
            || credential_payloads.iter().any(|payload| {
                !matches!(
                    *payload,
                    Payload::Credential {
                        requested_scope_sha256,
                        effective_scope_sha256,
                        ..
                    } if Some(requested_scope_sha256)
                        == projection.credential_scope_sha256.as_ref()
                        && Some(effective_scope_sha256)
                            == projection.credential_scope_sha256.as_ref()
                )
            })
        {
            return Ok(false);
        }

        let decision = events
            .iter()
            .filter(|event| {
                event.kind == Kind::DecisionDurable
                    && event.operation_id.as_deref() == Some(operation_id)
                    && matches!(
                        &event.payload,
                        Payload::Decision {
                            canonical_input_sha256,
                            idempotency_sha256,
                            canonical_action_sha256,
                            receipt_action_sha256,
                            receipt_context_sha256,
                            authority_sha256,
                            configuration_sha256,
                            runtime_contract_sha256,
                            preparation_sha256,
                            decision_class,
                            decision_receipt_id,
                            decision_receipt_bytes_sha256,
                            decoded_claims_sha256,
                            ..
                        } if canonical_input_sha256 == &projection.canonical_input_sha256
                            && idempotency_sha256 == &projection.idempotency_sha256
                            && canonical_action_sha256 == &projection.canonical_action_sha256
                            && receipt_action_sha256 == &projection.receipt_action_sha256
                            && receipt_context_sha256 == &projection.receipt_context_sha256
                            && authority_sha256 == &projection.authority_sha256
                            && configuration_sha256 == &projection.configuration_sha256
                            && runtime_contract_sha256 == &projection.runtime_contract_sha256
                            && preparation_sha256 == &projection.preparation_sha256
                            && decision_class == &projection.decision_class
                            && instance.receipt_claims.iter().any(|claim| {
                                claim.decision_receipt_id.as_deref()
                                    == Some(decision_receipt_id.as_str())
                                    && claim.decision_action_sha256.as_deref()
                                        == Some(projection.receipt_action_sha256.as_str())
                                    && claim.decision_context_sha256.as_deref()
                                        == Some(projection.receipt_context_sha256.as_str())
                                    && claim.decision_class == Some(projection.decision_class)
                            })
                            && events.iter().filter(|verified| {
                                verified.kind == Kind::NativeReceiptVerified
                                    && verified.operation_id.as_deref() == Some(operation_id)
                                    && verified.receipt_id.as_deref()
                                        == Some(decision_receipt_id.as_str())
                                    && matches!(
                                        &verified.payload,
                                        Payload::ReceiptVerification {
                                            receipt_bytes_sha256,
                                            decoded_claims_sha256: verified_claims_sha256,
                                            ..
                                        } if receipt_bytes_sha256
                                            == decision_receipt_bytes_sha256
                                            && verified_claims_sha256
                                                == decoded_claims_sha256
                                    )
                            }).count() == 1
                    )
            })
            .count();
        if decision != 1
            || events
                .iter()
                .filter(|event| {
                    event.kind == Kind::CommandDurable
                        && event.operation_id.as_deref() == Some(operation_id)
                        && matches!(
                            &event.payload,
                            Payload::Command { sealed_command_sha256 }
                                if Some(sealed_command_sha256)
                                    == projection.sealed_command_sha256.as_ref()
                        )
                })
                .count()
                != usize::from(projection.sealed_command_sha256.is_some())
            || events
                .iter()
                .filter(|event| {
                    event.kind == Kind::ProviderResultDurable
                        && event.operation_id.as_deref() == Some(operation_id)
                        && matches!(
                            &event.payload,
                            Payload::ProviderResult { provider_result_sha256 }
                                if Some(provider_result_sha256)
                                    == projection.provider_result_sha256.as_ref()
                        )
                })
                .count()
                != usize::from(projection.provider_result_sha256.is_some())
            || events
                .iter()
                .filter(|event| {
                    event.kind == Kind::ExecutionReceiptDurable
                        && event.operation_id.as_deref() == Some(operation_id)
                        && matches!(
                            &event.payload,
                            Payload::ExecutionReceipt {
                                execution_receipt_id,
                                receipt_bytes_sha256,
                                decoded_claims_sha256,
                                execution_result_sha256,
                                execution_outcome,
                            } if execution_result_sha256 == &projection.execution_result_sha256
                                && instance.receipt_claims.iter().any(|claim| {
                                    claim.execution_receipt_id.as_deref()
                                        == Some(execution_receipt_id.as_str())
                                        && claim.execution_result_sha256
                                            == *execution_result_sha256
                                        && claim.execution_outcome == Some(*execution_outcome)
                                })
                                && events.iter().filter(|verified| {
                                    verified.kind == Kind::NativeReceiptVerified
                                        && verified.operation_id.as_deref()
                                            == Some(operation_id)
                                        && verified.receipt_id.as_deref()
                                            == Some(execution_receipt_id.as_str())
                                        && matches!(
                                            &verified.payload,
                                            Payload::ReceiptVerification {
                                                receipt_bytes_sha256: verified_bytes_sha256,
                                                decoded_claims_sha256: verified_claims_sha256,
                                                ..
                                            } if verified_bytes_sha256 == receipt_bytes_sha256
                                                && verified_claims_sha256
                                                    == decoded_claims_sha256
                                        )
                                }).count() == 1
                        )
                })
                .count()
                != usize::from(counters.receipt_writes == 2)
            || events
                .iter()
                .filter(|event| {
                    event.kind == Kind::TerminalDurable
                        && event.operation_id.as_deref() == Some(operation_id)
                        && matches!(
                            &event.payload,
                            Payload::Terminal { state, effect, execution_result_sha256, completion }
                                if Some(*state) == durable_terminal_outcome
                                    && effect == &projection.effect
                                    && execution_result_sha256
                                        == &projection.execution_result_sha256
                                    && *completion == match state {
                                        crate::QualificationOutcomeKind::Completed
                                        | crate::QualificationOutcomeKind::Partial
                                        | crate::QualificationOutcomeKind::NotApplied => {
                                            Some(if projection.reconciled {
                                                crate::QualificationCompletion::Reconciled
                                            } else {
                                                crate::QualificationCompletion::Fresh
                                            })
                                        }
                                        crate::QualificationOutcomeKind::Denied
                                        | crate::QualificationOutcomeKind::Unavailable
                                        | crate::QualificationOutcomeKind::Conflict
                                        | crate::QualificationOutcomeKind::RecoveryRequired => None,
                                    }
                        )
                })
                .count()
                != usize::from(projection.effect != crate::QualificationEffect::Possible)
            || projection.reconciled
                && (counters.provider_calls != 1
                    || counters.provider_request_writes != 1
                    || counters.observations == 0
                    || count(Kind::RecoveryObserved) == 0)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn common_receipt_claims_match_attempts(
    operation: &crate::QualificationCommonOperationEvidence,
    attempts: &[crate::QualificationRedactedAttempt],
    profile: &str,
) -> bool {
    let operation_attempts = attempts
        .iter()
        .filter(|attempt| {
            attempt.operation_id.as_deref() == Some(operation.projection.operation_id.as_str())
        })
        .collect::<Vec<_>>();
    if operation_attempts.is_empty()
        || operation.receipt_claims.is_empty()
        || operation.receipt_claims.iter().any(|claim| {
            !operation_attempts.iter().any(|attempt| {
                claim.attempt_sequence == attempt.sequence
                    && claim.request_id == attempt.request_id
                    && claim.operation_id == operation.projection.operation_id
                    && claim.profile == profile
                    && claim.connection_generation == operation.projection.connection_generation
            })
        })
    {
        return false;
    }
    let reconciled_with_retained_receipts = operation_attempts
        .iter()
        .any(|attempt| attempt.completion == Some(crate::QualificationCompletion::Reconciled))
        && operation.projection.counters.provider_calls == 1
        && operation.projection.counters.receipt_writes == 2
        && operation_attempts
            .iter()
            .filter(|attempt| !attempt.receipt_ids.is_empty())
            .map(|attempt| &attempt.receipt_ids)
            .collect::<BTreeSet<_>>()
            .len()
            == 1;
    for attempt in operation_attempts {
        let claims = operation
            .receipt_claims
            .iter()
            .filter(|claim| claim.attempt_sequence == attempt.sequence)
            .collect::<Vec<_>>();
        if claims.len() != 1 || attempt.receipt_ids.len() > 2 {
            return false;
        }
        let claimed_receipts = claims
            .iter()
            .flat_map(|claim| {
                [
                    claim.decision_receipt_id.as_ref(),
                    claim.execution_receipt_id.as_ref(),
                ]
                .into_iter()
                .flatten()
            })
            .collect::<Vec<_>>();
        if claimed_receipts.len() != attempt.receipt_ids.len()
            || claimed_receipts
                .iter()
                .zip(&attempt.receipt_ids)
                .any(|(claimed, expected)| claimed.as_str() != expected)
            || claims.iter().any(|claim| {
                (attempt.receipt_ids.is_empty()
                    && claim.state != crate::QualificationReceiptState::None)
                    || (attempt.receipt_ids.len() == 1
                        && claim.state != crate::QualificationReceiptState::DecisionOnly)
                    || (attempt.receipt_ids.len() >= 2
                        && claim.state != crate::QualificationReceiptState::LinkedExecution)
                    || claim.decision_action_sha256.is_some()
                        && claim.decision_action_sha256.as_deref()
                            != Some(operation.projection.receipt_action_sha256.as_str())
                    || claim.decision_context_sha256.is_some()
                        && claim.decision_context_sha256.as_deref()
                            != Some(operation.projection.receipt_context_sha256.as_str())
                    || claim.execution_command_sha256.is_some()
                        && claim.execution_command_sha256
                            != operation.projection.sealed_command_sha256
                    || claim.execution_result_sha256 != operation.projection.execution_result_sha256
                    || !common_receipt_class_matches_operation(
                        claim,
                        operation.projection.decision_class,
                        operation.projection.effect,
                        reconciled_with_retained_receipts,
                    )
            })
        {
            return false;
        }
    }
    true
}

fn common_receipt_class_matches_operation(
    claim: &crate::QualificationCommonReceiptClaims,
    decision_class: crate::QualificationReceiptDecisionClass,
    effect: crate::QualificationEffect,
    reconciled_with_retained_receipts: bool,
) -> bool {
    let decision_matches = match claim.state {
        crate::QualificationReceiptState::None => claim.decision_class.is_none(),
        crate::QualificationReceiptState::DecisionOnly
        | crate::QualificationReceiptState::LinkedExecution => {
            claim.decision_class == Some(decision_class)
        }
    };
    let execution_matches = claim
        .execution_outcome
        .is_none_or(|value| match (value, effect) {
            (
                crate::QualificationReceiptExecutionOutcome::Succeeded,
                crate::QualificationEffect::Applied,
            )
            | (
                crate::QualificationReceiptExecutionOutcome::Failed,
                crate::QualificationEffect::NotApplied,
            )
            | (
                crate::QualificationReceiptExecutionOutcome::Indeterminate,
                crate::QualificationEffect::Possible,
            ) => true,
            (
                crate::QualificationReceiptExecutionOutcome::Indeterminate,
                crate::QualificationEffect::Applied | crate::QualificationEffect::NotApplied,
            ) => reconciled_with_retained_receipts,
            _ => false,
        });
    decision_matches && execution_matches
}

impl QualificationEvidenceLedgerPlanV1 {
    /// Parses one exact canonical protected ledger plan.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationEvidenceLedgerError> {
        if bytes.is_empty() || bytes.len() > 262_144 {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        let plan: Self = serde_json::from_slice(bytes)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)?;
        plan.validate()?;
        if canonical(&plan)? != bytes {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        Ok(plan)
    }

    /// Validates the immutable provider-free run and phase roster.
    pub fn validate(&self) -> Result<(), QualificationEvidenceLedgerError> {
        if self.schema != "auths.profile-qualification-evidence-ledger-plan/1"
            || !decimal(&self.repository_id)
            || !workflow_path(&self.workflow_path)
            || !lower_hex(&self.workflow_revision, 40)
            || !lower_hex(&self.candidate_revision, 40)
            || !lower_hex(&self.attester_revision, 40)
            || !decimal(&self.run_id)
            || self.run_attempt == 0
            || !lower_token(&self.domain)
            || !registered_token(&self.protected_environment)
            || !registered_token(&self.provider_run_id)
            || !registered_token(&self.ledger_id)
            || !digest(&self.session_nonce_sha256)
            || self.supervisor_controller_uid == 0
            || self.supervisor_controller_uid == u32::MAX
            || !digest(&self.supervisor_controller_artifact_sha256)
            || !digest(&self.ledger_appender_artifact_sha256)
            || self.agent_uid == 0
            || self.agent_uid == u32::MAX
            || self.agent_gid == 0
            || self.agent_gid == u32::MAX
            || self.agent_uid == self.supervisor_controller_uid
            || !digest(&self.agent_executable_sha256)
            || !registered_token(&self.recovery_key_id)
            || decode_fixed::<32>(&self.recovery_public_key_base64url).is_err()
            || self.phases.is_empty()
            || self.phases.len() > MAX_PHASES
            || self.started_at_unix_seconds >= self.deadline_at_unix_seconds
            || self
                .deadline_at_unix_seconds
                .checked_sub(self.started_at_unix_seconds)
                .is_none_or(|duration| duration > MAX_QUALIFICATION_SECONDS)
            || self.phases.iter().any(|phase| {
                !registered_token(&phase.scenario_id)
                    || !(1..=8).contains(&phase.phase_index)
                    || !semantic_profile(&phase.profile)
                    || !digest(&phase.operation_plan_sha256)
                    || !digest(&phase.scenario_program_sha256)
                    || !phase.credential_requirement.valid()
            })
            || self.phases.windows(2).any(|pair| {
                (pair[0].scenario_id.as_str(), pair[0].phase_index)
                    >= (pair[1].scenario_id.as_str(), pair[1].phase_index)
            })
            || {
                let mut profiles = BTreeSet::new();
                self.phases.iter().any(|phase| {
                    !profiles.insert((phase.scenario_id.as_str(), phase.profile.as_str()))
                })
            }
        {
            return Err(QualificationEvidenceLedgerError::InvalidRecord);
        }
        Ok(())
    }

    /// Recomputes the one immutable source context used by every role.
    pub fn source_context_sha256(&self) -> Result<String, QualificationEvidenceLedgerError> {
        self.validate()?;
        let phases = self
            .phases
            .iter()
            .map(|phase| {
                serde_json::json!({
                    "credentialRequirement": phase.credential_requirement,
                    "failpoint": phase.failpoint,
                    "operationPlanSha256": phase.operation_plan_sha256,
                    "scenarioProgramSha256": phase.scenario_program_sha256,
                    "phaseIndex": phase.phase_index,
                    "profile": phase.profile,
                    "role": phase.role,
                    "scenarioId": phase.scenario_id,
                })
            })
            .collect::<Vec<_>>();
        let context = serde_json::json!({
            "attesterRevision": self.attester_revision,
            "agentExecutableSha256": self.agent_executable_sha256,
            "agentGid": self.agent_gid,
            "agentUid": self.agent_uid,
            "candidateRevision": self.candidate_revision,
            "domain": self.domain,
            "ledgerId": self.ledger_id,
            "ledgerAppenderArtifactSha256": self.ledger_appender_artifact_sha256,
            "phasePlans": phases,
            "protectedEnvironment": self.protected_environment,
            "providerRunId": self.provider_run_id,
            "recoveryKeyId": self.recovery_key_id,
            "recoveryPublicKeyBase64url": self.recovery_public_key_base64url,
            "repositoryId": self.repository_id,
            "runAttempt": self.run_attempt,
            "runId": self.run_id,
            "schema": "auths.profile-qualification-evidence-source-context/1",
            "sessionNonceSha256": self.session_nonce_sha256,
            "supervisorControllerArtifactSha256": self.supervisor_controller_artifact_sha256,
            "supervisorControllerUid": self.supervisor_controller_uid,
            "startedAtUnixSeconds": self.started_at_unix_seconds,
            "deadlineAtUnixSeconds": self.deadline_at_unix_seconds,
            "target": self.target,
            "workflowPath": self.workflow_path,
            "workflowRevision": self.workflow_revision,
        });
        Ok(hex::encode(Sha256::digest(canonical(&context)?)))
    }

    /// Exact-binds the immutable provider-row plan fields shared by ordinary
    /// and crash decision contexts. Source-key identities remain separately
    /// bound to the current protected source-trust registry.
    pub fn binds_decision_context_common(
        &self,
        context: &QualificationJournalDecisionContextRecord,
    ) -> Result<bool, QualificationEvidenceLedgerError> {
        self.validate()?;
        context.validate()?;
        Ok(self.repository_id == context.repository_id
            && self.workflow_path == context.workflow_path
            && self.workflow_revision == context.workflow_revision
            && self.candidate_revision == context.candidate_revision
            && self.attester_revision == context.attester_revision
            && self.run_id == context.run_id
            && self.run_attempt == context.run_attempt
            && self.domain == context.domain
            && self.target == context.target
            && self.protected_environment == context.protected_environment
            && self.provider_run_id == context.provider_run_id
            && self.ledger_id == context.ledger_id
            && self.session_nonce_sha256 == context.session_nonce_sha256
            && self.supervisor_controller_uid == context.supervisor_controller_uid
            && self.supervisor_controller_artifact_sha256
                == context.supervisor_controller_artifact_sha256
            && self.agent_uid == context.agent_uid
            && self.agent_gid == context.agent_gid
            && self.agent_executable_sha256 == context.agent_executable_sha256
            && self.source_context_sha256()? == context.source_context_sha256
            && self.phases.iter().any(|phase| {
                phase.scenario_id == context.scenario_id
                    && phase.phase_index == context.phase_index
                    && phase.role == context.role
                    && phase.profile == context.profile
                    && phase.operation_plan_sha256 == context.operation_plan_sha256
                    && phase.scenario_program_sha256 == context.scenario_program_sha256
                    && phase.failpoint == context.failpoint
            }))
    }
}

impl QualificationEvidenceSourceTrustRegistry {
    /// Parses one canonical protected source-key registry.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationEvidenceLedgerError> {
        if bytes.len() > 262_144 {
            return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
        }
        let registry: Self = serde_json::from_slice(bytes)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidSourceTrust)?;
        if canonical(&registry)? != bytes
            || registry.schema != "auths.profile-qualification-evidence-source-trust/1"
            || registry.keys.len() > 64
            || !registry.keys.windows(2).all(|pair| {
                (source_token(pair[0].source), pair[0].key_id.as_str())
                    < (source_token(pair[1].source), pair[1].key_id.as_str())
            })
            || registry.keys.iter().any(|key| {
                let needs_reader = matches!(
                    key.source,
                    QualificationEvidenceSource::ClientProxy
                        | QualificationEvidenceSource::CredentialBroker
                        | QualificationEvidenceSource::ProfileStateReader
                        | QualificationEvidenceSource::ProviderProxy
                        | QualificationEvidenceSource::ReceiptVerifier
                        | QualificationEvidenceSource::ProviderObserver
                );
                !registered_token(&key.key_id)
                    || key.algorithm != "Ed25519"
                    || decode_fixed::<32>(&key.public_key_base64url).is_err()
                    || !registered_token(&key.source_identity)
                    || !digest(&key.source_artifact_sha256)
                    || key.source_uid.is_none_or(|uid| uid == 0 || uid == u32::MAX)
                    || needs_reader != key.reader_identity.as_deref().is_some_and(registered_token)
                    || needs_reader != key.reader_artifact_sha256.as_deref().is_some_and(digest)
                    || needs_reader
                        != key
                            .reader_uid
                            .is_some_and(|uid| uid != 0 && uid != u32::MAX)
                    || !needs_reader
                        && (key.reader_identity.is_some()
                            || key.reader_artifact_sha256.is_some()
                            || key.reader_uid.is_some())
                    || needs_reader && key.reader_uid == key.source_uid
                    || key.allowed_domains.is_empty()
                    || key.allowed_domains.len() > 32
                    || !key.allowed_domains.windows(2).all(|pair| pair[0] < pair[1])
                    || key
                        .allowed_domains
                        .iter()
                        .any(|domain| !lower_token(domain))
                    || (key.not_after_unix_seconds != 0
                        && key.not_after_unix_seconds < key.not_before_unix_seconds)
            })
            || registry.keys.iter().enumerate().any(|(index, key)| {
                registry.keys[..index].iter().any(|prior| {
                    prior.key_id == key.key_id
                        || prior.public_key_base64url == key.public_key_base64url
                        || (prior.source != key.source
                            && (key.source_uid == prior.source_uid
                                || key.reader_uid.is_some()
                                    && (key.reader_uid == prior.source_uid
                                        || key.reader_uid == prior.reader_uid)
                                || prior.reader_uid.is_some()
                                    && prior.reader_uid == key.source_uid
                                || prior.source_identity == key.source_identity
                                || prior.source_artifact_sha256 == key.source_artifact_sha256
                                || key.reader_identity.as_ref().is_some_and(|identity| {
                                    identity == &prior.source_identity
                                        || prior.reader_identity.as_ref() == Some(identity)
                                })
                                || prior.reader_identity.as_ref() == Some(&key.source_identity)
                                || key.reader_artifact_sha256.as_ref().is_some_and(|artifact| {
                                    artifact == &prior.source_artifact_sha256
                                        || prior.reader_artifact_sha256.as_ref() == Some(artifact)
                                })
                                || prior.reader_artifact_sha256.as_ref()
                                    == Some(&key.source_artifact_sha256)))
                })
            })
            || registry
                .keys
                .iter()
                .map(|key| key.source)
                .collect::<BTreeSet<_>>()
                .len()
                != 8
        {
            return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
        }
        Ok(registry)
    }

    /// Returns every protected evidence-source identity for global separation.
    pub fn identities(&self) -> impl Iterator<Item = QualificationTrustIdentity<'_>> {
        self.keys
            .iter()
            .map(|key| QualificationTrustIdentity::new(&key.key_id, &key.public_key_base64url))
    }

    /// Reports whether any protected source signer or reader owns this OS UID.
    #[must_use]
    pub fn uses_process_uid(&self, uid: u32) -> bool {
        self.keys
            .iter()
            .any(|key| key.source_uid == Some(uid) || key.reader_uid == Some(uid))
    }

    /// Resolves the one current fixed source role owned by an authenticated
    /// reader process. The global source registry, rather than a socket peer,
    /// chooses the role and fails closed on key-rotation ambiguity.
    #[allow(clippy::too_many_arguments)]
    pub fn fixed_source_for_reader_process(
        &self,
        reader_uid: u32,
        reader_artifact_sha256: &str,
        domain: &str,
        started_at: u64,
        completed_at: u64,
        now: u64,
    ) -> Result<QualificationEvidenceSource, QualificationEvidenceLedgerError> {
        let mut matched = None;
        for source in [
            QualificationEvidenceSource::ClientProxy,
            QualificationEvidenceSource::CredentialBroker,
            QualificationEvidenceSource::ProfileStateReader,
            QualificationEvidenceSource::ProviderProxy,
            QualificationEvidenceSource::ReceiptVerifier,
            QualificationEvidenceSource::ProviderObserver,
        ] {
            let (key_id, _, _, _) =
                self.current_source_process_binding(source, domain, started_at, completed_at, now)?;
            let key = self
                .keys
                .iter()
                .find(|key| key.source == source && key.key_id == key_id)
                .ok_or(QualificationEvidenceLedgerError::InvalidSourceTrust)?;
            if key.reader_uid == Some(reader_uid)
                && key.reader_artifact_sha256.as_deref() == Some(reader_artifact_sha256)
                && matched.replace(source).is_some()
            {
                return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
            }
        }
        matched.ok_or(QualificationEvidenceLedgerError::InvalidSourceTrust)
    }

    /// Resolves the source role owned by one append-session peer. The six
    /// fixed readers append on behalf of their distinct seed-bearing signer;
    /// `Supervisor` and `JournalReader` append from their seed-bearing process.
    #[allow(clippy::too_many_arguments)]
    pub fn source_for_append_process(
        &self,
        uid: u32,
        artifact_sha256: &str,
        domain: &str,
        started_at: u64,
        completed_at: u64,
        now: u64,
    ) -> Result<QualificationEvidenceSource, QualificationEvidenceLedgerError> {
        if let Ok(source) = self.fixed_source_for_reader_process(
            uid,
            artifact_sha256,
            domain,
            started_at,
            completed_at,
            now,
        ) {
            return Ok(source);
        }
        let mut matched = None;
        for source in [
            QualificationEvidenceSource::Supervisor,
            QualificationEvidenceSource::JournalReader,
        ] {
            let (_, _, source_artifact, source_uid) =
                self.current_source_process_binding(source, domain, started_at, completed_at, now)?;
            if uid == source_uid
                && artifact_sha256 == source_artifact
                && matched.replace(source).is_some()
            {
                return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
            }
        }
        matched.ok_or(QualificationEvidenceLedgerError::InvalidSourceTrust)
    }

    /// Reports whether one immutable executable digest is registered for the
    /// exact source role. Socket-based minimal signers use this as an early
    /// rejection before reading any peer-authored record bytes; full identity,
    /// domain, interval, and signature validation still follows.
    #[must_use]
    pub fn permits_source_artifact(
        &self,
        source: QualificationEvidenceSource,
        source_artifact_sha256: &str,
    ) -> bool {
        digest(source_artifact_sha256)
            && self.keys.iter().any(|key| {
                key.source == source && key.source_artifact_sha256 == source_artifact_sha256
            })
    }

    /// Selects the one currently eligible signing key and resolves the
    /// immutable signer/reader process policy for one fixed role.
    ///
    /// Key selection is protected-registry-owned. Overlapping eligible keys
    /// deliberately fail closed: a launcher may not choose between rotation
    /// keys or make a seed-bearing process sign under caller-authored policy.
    #[allow(clippy::too_many_arguments)]
    pub fn fixed_source_process_binding(
        &self,
        source: QualificationEvidenceSource,
        signer_artifact_sha256: &str,
        domain: &str,
        started_at: u64,
        completed_at: u64,
        now: u64,
    ) -> Result<(&str, &str, u32, &str, &str, u32), QualificationEvidenceLedgerError> {
        let (key_id, source_identity, source_artifact, source_uid) =
            self.current_source_process_binding(source, domain, started_at, completed_at, now)?;
        if source_artifact != signer_artifact_sha256 {
            return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
        }
        let key = self
            .keys
            .iter()
            .find(|key| key.source == source && key.key_id == key_id)
            .ok_or(QualificationEvidenceLedgerError::InvalidSourceTrust)?;
        Ok((
            key_id,
            source_identity,
            source_uid,
            key.reader_identity
                .as_deref()
                .ok_or(QualificationEvidenceLedgerError::InvalidSourceTrust)?,
            key.reader_artifact_sha256
                .as_deref()
                .ok_or(QualificationEvidenceLedgerError::InvalidSourceTrust)?,
            key.reader_uid
                .ok_or(QualificationEvidenceLedgerError::InvalidSourceTrust)?,
        ))
    }

    /// Selects the unique registry-owned current key and process identity for
    /// any protected source role. This is the only supported key-rotation
    /// authority for the seed-bearing source services.
    #[allow(clippy::too_many_arguments)]
    pub fn current_source_process_binding(
        &self,
        source: QualificationEvidenceSource,
        domain: &str,
        started_at: u64,
        completed_at: u64,
        now: u64,
    ) -> Result<(&str, &str, &str, u32), QualificationEvidenceLedgerError> {
        let active = |key: &QualificationEvidenceSourceTrustKey, at: u64| {
            at >= key.not_before_unix_seconds
                && (key.not_after_unix_seconds == 0 || at <= key.not_after_unix_seconds)
        };
        let mut eligible = self.keys.iter().filter(|key| {
            key.source == source
                && key
                    .allowed_domains
                    .binary_search_by(|value| value.as_str().cmp(domain))
                    .is_ok()
                && active(key, started_at)
                && active(key, completed_at)
                && active(key, now)
        });
        let key = eligible
            .next()
            .ok_or(QualificationEvidenceLedgerError::InvalidSourceTrust)?;
        if eligible.next().is_some() {
            return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
        }
        Ok((
            &key.key_id,
            &key.source_identity,
            &key.source_artifact_sha256,
            key.source_uid
                .ok_or(QualificationEvidenceLedgerError::InvalidSourceTrust)?,
        ))
    }

    /// Verifies that one protected seed derives the registry-owned current
    /// public key for an exact source role and immutable run interval.
    #[cfg(any(feature = "qualification-ledger-producer", test))]
    #[allow(clippy::too_many_arguments)]
    pub fn verifies_current_source_seed(
        &self,
        source: QualificationEvidenceSource,
        domain: &str,
        started_at: u64,
        completed_at: u64,
        now: u64,
        seed_base64url: &str,
    ) -> Result<(), QualificationEvidenceLedgerError> {
        let (key_id, _, _, _) =
            self.current_source_process_binding(source, domain, started_at, completed_at, now)?;
        let key = self
            .keys
            .iter()
            .find(|key| key.source == source && key.key_id == key_id)
            .ok_or(QualificationEvidenceLedgerError::InvalidSourceTrust)?;
        let seed = decode_fixed::<32>(seed_base64url)?;
        let derived = Base64UrlUnpadded::encode_string(
            SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
        );
        if derived != key.public_key_base64url {
            return Err(QualificationEvidenceLedgerError::InvalidSignature);
        }
        Ok(())
    }

    fn find(
        &self,
        event: &QualificationEvidenceEvent,
        domain: &str,
        started_at: u64,
        completed_at: u64,
        now: u64,
        require_current: bool,
    ) -> Result<&QualificationEvidenceSourceTrustKey, QualificationEvidenceLedgerError> {
        let key = self.find_bound(
            event.source,
            &event.source_key_id,
            &event.source_identity,
            &event.source_artifact_sha256,
            domain,
            started_at,
            completed_at,
            now,
            require_current,
        )?;
        if event.source_uid != key.source_uid
            || event.reader_identity != key.reader_identity
            || event.reader_artifact_sha256 != key.reader_artifact_sha256
            || event.reader_uid != key.reader_uid
        {
            return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
        }
        Ok(key)
    }

    #[allow(clippy::too_many_arguments)]
    fn find_bound(
        &self,
        source: QualificationEvidenceSource,
        key_id: &str,
        source_identity: &str,
        source_artifact_sha256: &str,
        domain: &str,
        started_at: u64,
        completed_at: u64,
        now: u64,
        require_current: bool,
    ) -> Result<&QualificationEvidenceSourceTrustKey, QualificationEvidenceLedgerError> {
        let key = self
            .keys
            .iter()
            .find(|key| key.source == source && key.key_id == key_id)
            .ok_or(QualificationEvidenceLedgerError::InvalidSourceTrust)?;
        let active = |at: u64| {
            at >= key.not_before_unix_seconds
                && (key.not_after_unix_seconds == 0 || at <= key.not_after_unix_seconds)
        };
        if key.source_identity != source_identity
            || key.source_artifact_sha256 != source_artifact_sha256
            || key
                .allowed_domains
                .binary_search_by(|value| value.as_str().cmp(domain))
                .is_err()
            || !active(started_at)
            || !active(completed_at)
            || require_current && !active(now)
        {
            return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
        }
        Ok(key)
    }
}

impl QualificationEvidenceLedgerTrustRegistry {
    /// Parses one canonical protected common-ledger trust registry.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationEvidenceLedgerError> {
        if bytes.len() > 262_144 {
            return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
        }
        let registry: Self = serde_json::from_slice(bytes)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidSourceTrust)?;
        if canonical(&registry)? != bytes
            || registry.schema != "auths.profile-qualification-evidence-ledger-trust/1"
            || registry.keys.len() > 64
            || !registry
                .keys
                .windows(2)
                .all(|pair| pair[0].key_id < pair[1].key_id)
            || registry.keys.iter().any(|key| {
                !registered_token(&key.key_id)
                    || key.algorithm != "Ed25519"
                    || decode_fixed::<32>(&key.public_key_base64url).is_err()
                    || key.allowed_domains.is_empty()
                    || key.allowed_domains.len() > 64
                    || !key.allowed_domains.windows(2).all(|pair| pair[0] < pair[1])
                    || key
                        .allowed_domains
                        .iter()
                        .any(|domain| !lower_token(domain))
                    || (key.not_after_unix_seconds != 0
                        && key.not_after_unix_seconds < key.not_before_unix_seconds)
            })
            || registry.keys.iter().enumerate().any(|(index, key)| {
                registry.keys[..index]
                    .iter()
                    .any(|prior| prior.public_key_base64url == key.public_key_base64url)
            })
        {
            return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
        }
        Ok(registry)
    }

    /// Returns every protected ledger-sealer identity for global separation.
    pub fn identities(&self) -> impl Iterator<Item = QualificationTrustIdentity<'_>> {
        self.keys
            .iter()
            .map(|key| QualificationTrustIdentity::new(&key.key_id, &key.public_key_base64url))
    }

    fn find(
        &self,
        key_id: &str,
        domain: &str,
        started_at: u64,
        completed_at: u64,
        now: u64,
        require_current: bool,
    ) -> Result<&QualificationEvidenceLedgerTrustKey, QualificationEvidenceLedgerError> {
        let key = self
            .keys
            .iter()
            .find(|key| key.key_id == key_id)
            .ok_or(QualificationEvidenceLedgerError::InvalidSourceTrust)?;
        let active = |at: u64| {
            at >= key.not_before_unix_seconds
                && (key.not_after_unix_seconds == 0 || at <= key.not_after_unix_seconds)
        };
        if key
            .allowed_domains
            .binary_search_by(|value| value.as_str().cmp(domain))
            .is_err()
            || !active(started_at)
            || !active(completed_at)
            || require_current && !active(now)
        {
            return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
        }
        Ok(key)
    }
}

impl QualificationJournalDecisionContextRecord {
    /// Validates the exact protected decision-context record before a
    /// seed-bearing Supervisor process accepts it for signing.
    pub fn validate(&self) -> Result<(), QualificationEvidenceLedgerError> {
        if self.schema != "auths.qualification-journal-decision-context-record/1"
            || !decimal(&self.repository_id)
            || !workflow_path(&self.workflow_path)
            || !lower_hex(&self.workflow_revision, 40)
            || !lower_hex(&self.candidate_revision, 40)
            || !lower_hex(&self.attester_revision, 40)
            || !decimal(&self.run_id)
            || self.run_attempt == 0
            || !lower_token(&self.domain)
            || !registered_token(&self.protected_environment)
            || !registered_token(&self.provider_run_id)
            || !registered_token(&self.ledger_id)
            || !digest(&self.session_nonce_sha256)
            || !registered_token(&self.scenario_id)
            || !(1..=8).contains(&self.phase_index)
            || !semantic_profile(&self.profile)
            || !digest(&self.operation_plan_sha256)
            || !digest(&self.scenario_program_sha256)
            || self.supervisor_controller_uid == u32::MAX
            || self.supervisor_source_uid == 0
            || self.supervisor_source_uid == u32::MAX
            || self.journal_reader_uid == 0
            || self.journal_reader_uid == u32::MAX
            || self.agent_uid == 0
            || self.agent_uid == u32::MAX
            || self.agent_gid == 0
            || self.agent_gid == u32::MAX
            || !registered_token(&self.supervisor_source_identity)
            || !digest(&self.supervisor_source_artifact_sha256)
            || !digest(&self.supervisor_controller_artifact_sha256)
            || !registered_token(&self.journal_reader_source_identity)
            || !digest(&self.journal_reader_source_artifact_sha256)
            || !registered_token(&self.journal_reader_key_id)
            || self.supervisor_source_identity == self.journal_reader_source_identity
            || !digest(&self.source_context_sha256)
            || self.supervisor_generation == 0
            || self.agent_generation == 0
            || self.agent_process_id == 0
            || !digest(&self.agent_boot_sha256)
            || self.agent_start_time_ticks == 0
            || !digest(&self.agent_launcher_artifact_sha256)
            || !digest(&self.agent_executable_sha256)
            || !digest(&self.agent_configuration_sha256)
            || !digest(&self.agent_state_directory_sha256)
            || !digest(&self.agent_cgroup_sha256)
            || !digest(&self.journal_path_sha256)
            || self.journal_device == 0
            || self.journal_inode == 0
            || self.journal_owner_uid == 0
            || self.journal_owner_uid == u32::MAX
            || [
                self.supervisor_controller_uid,
                self.supervisor_source_uid,
                self.journal_reader_uid,
                self.agent_uid,
            ]
            .iter()
            .enumerate()
            .any(|(index, value)| {
                [
                    self.supervisor_controller_uid,
                    self.supervisor_source_uid,
                    self.journal_reader_uid,
                    self.agent_uid,
                ][index + 1..]
                    .contains(value)
            })
            || self.journal_owner_uid != self.agent_uid
            || self.journal_mode != 0o600
            || self.journal_length == 0
            || usize::try_from(self.boundary_ordinal)
                .map_or(true, |ordinal| !(1..=MAX_EVENTS).contains(&ordinal))
            || !digest(&self.boundary_projection_sha256)
            || !registered_token(&self.operation_id)
            || self.journal_revision != 1
            || !digest(&self.journal_record_sha256)
            || !digest(&self.decision_snapshot_sha256)
            || !digest(&self.durable_ack_sha256)
            || match (
                self.control_operation_id.as_deref(),
                self.controller_nonce_sha256.as_deref(),
            ) {
                (Some(operation), Some(nonce)) => {
                    self.failpoint.is_none() || !registered_token(operation) || !digest(nonce)
                }
                (None, None) => self.failpoint.is_some(),
                _ => true,
            }
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        Ok(())
    }
}

impl QualificationCrashProcessIdentityV1 {
    fn validate(&self) -> Result<(), QualificationEvidenceLedgerError> {
        if self.agent_generation == 0
            || self.agent_process_id == 0
            || !digest(&self.agent_boot_sha256)
            || self.agent_start_time_ticks == 0
            || !digest(&self.agent_launcher_artifact_sha256)
            || !digest(&self.agent_executable_sha256)
            || !digest(&self.agent_configuration_sha256)
            || !digest(&self.agent_state_directory_sha256)
            || !digest(&self.agent_cgroup_sha256)
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        Ok(())
    }

    fn binds_crash_context(&self, context: &QualificationCrashPhaseContextV1) -> bool {
        self.agent_generation == context.agent_generation
            && self.agent_launcher_artifact_sha256 == context.agent_launcher_artifact_sha256
            && self.agent_executable_sha256 == context.agent_executable_sha256
    }
}

impl QualificationCrashActionRecordV1 {
    /// Validates the exact action-specific crash evidence grammar.
    pub fn validate(&self) -> Result<(), QualificationEvidenceLedgerError> {
        self.crash_context.validate()?;
        if self.schema != "auths.qualification-crash-action-record/1"
            || usize::try_from(self.sequence)
                .map_or(true, |sequence| !(1..=MAX_EVENTS).contains(&sequence))
            || !digest(&self.previous_event_sha256)
            || !semantic_profile(&self.profile)
            || self.profile != self.crash_context.phase.profile
            || self.supervisor_controller_uid == u32::MAX
            || [
                self.crash_context.supervisor_source_uid,
                self.crash_context.agent_uid,
            ]
            .contains(&self.supervisor_controller_uid)
            || !digest(&self.supervisor_source_artifact_sha256)
            || !digest(&self.supervisor_controller_artifact_sha256)
            || match self.crash_context.phase.failpoint {
                None => true,
                Some(QualificationFailpoint::BeforeDecision) => {
                    self.operation_id.is_some()
                        || self.connection_generation.is_some()
                        || self.durable_ack_sha256.is_some()
                }
                Some(_) => {
                    !self.operation_id.as_deref().is_some_and(registered_token)
                        || !self.connection_generation.as_deref().is_some_and(decimal)
                        || !self.durable_ack_sha256.as_deref().is_some_and(digest)
                }
            }
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        match &self.facts {
            QualificationCrashActionFactsV1::FailpointAcknowledged {
                process,
                durable_ack_sha256,
                boundary_event_sha256,
            } => {
                process.validate()?;
                if !process.binds_crash_context(&self.crash_context)
                    || durable_ack_sha256
                        .as_deref()
                        .is_some_and(|value| !digest(value))
                    || durable_ack_sha256 != &self.durable_ack_sha256
                    || !digest(boundary_event_sha256)
                    || self.previous_event_sha256 != *boundary_event_sha256
                {
                    return Err(QualificationEvidenceLedgerError::InvalidEvent);
                }
            }
            QualificationCrashActionFactsV1::ProcessKilled {
                process,
                acknowledgement_event_sha256,
                signal,
                cgroup_empty_after_kill,
            } => {
                process.validate()?;
                if !process.binds_crash_context(&self.crash_context)
                    || !digest(acknowledgement_event_sha256)
                    || self.previous_event_sha256 != *acknowledgement_event_sha256
                    || signal != "SIGKILL"
                    || !cgroup_empty_after_kill
                {
                    return Err(QualificationEvidenceLedgerError::InvalidEvent);
                }
            }
            QualificationCrashActionFactsV1::ProcessRestarted {
                killed_process,
                restarted_process,
                kill_event_sha256,
                control_plane_ready,
            } => {
                killed_process.validate()?;
                restarted_process.validate()?;
                if !killed_process.binds_crash_context(&self.crash_context)
                    || !digest(kill_event_sha256)
                    || self.previous_event_sha256 != *kill_event_sha256
                    || killed_process.agent_generation.checked_add(1)
                        != Some(restarted_process.agent_generation)
                    || killed_process.agent_process_id == restarted_process.agent_process_id
                    || killed_process.agent_start_time_ticks
                        == restarted_process.agent_start_time_ticks
                    || killed_process.agent_boot_sha256 != restarted_process.agent_boot_sha256
                    || killed_process.agent_launcher_artifact_sha256
                        != restarted_process.agent_launcher_artifact_sha256
                    || killed_process.agent_executable_sha256
                        != restarted_process.agent_executable_sha256
                    || killed_process.agent_configuration_sha256
                        != restarted_process.agent_configuration_sha256
                    || killed_process.agent_state_directory_sha256
                        != restarted_process.agent_state_directory_sha256
                    || !control_plane_ready
                {
                    return Err(QualificationEvidenceLedgerError::InvalidEvent);
                }
            }
        }
        Ok(())
    }

    /// Returns the exact ledger kind authenticated by this action record.
    #[must_use]
    pub const fn event_kind(&self) -> QualificationEvidenceEventKind {
        match self.facts {
            QualificationCrashActionFactsV1::FailpointAcknowledged { .. } => {
                QualificationEvidenceEventKind::FailpointAcknowledged
            }
            QualificationCrashActionFactsV1::ProcessKilled { .. } => {
                QualificationEvidenceEventKind::ProcessKilled
            }
            QualificationCrashActionFactsV1::ProcessRestarted { .. } => {
                QualificationEvidenceEventKind::ProcessRestarted
            }
        }
    }

    /// Reconstructs the action-specific public ledger payload.
    #[must_use]
    pub fn event_payload(
        &self,
        action_context_sha256: String,
    ) -> QualificationEvidenceEventPayload {
        match &self.facts {
            QualificationCrashActionFactsV1::FailpointAcknowledged {
                process,
                boundary_event_sha256,
                ..
            } => QualificationEvidenceEventPayload::FailpointAcknowledgement {
                action_context_sha256,
                controller_nonce_sha256: self.crash_context.controller_nonce_sha256.clone(),
                agent_start_time_ticks: process.agent_start_time_ticks,
                agent_executable_sha256: process.agent_executable_sha256.clone(),
                agent_configuration_sha256: process.agent_configuration_sha256.clone(),
                agent_state_directory_sha256: process.agent_state_directory_sha256.clone(),
                agent_cgroup_sha256: process.agent_cgroup_sha256.clone(),
                boundary_event_sha256: boundary_event_sha256.clone(),
            },
            QualificationCrashActionFactsV1::ProcessKilled {
                process,
                acknowledgement_event_sha256,
                signal,
                cgroup_empty_after_kill,
            } => QualificationEvidenceEventPayload::ProcessKill {
                action_context_sha256,
                controller_nonce_sha256: self.crash_context.controller_nonce_sha256.clone(),
                agent_start_time_ticks: process.agent_start_time_ticks,
                agent_executable_sha256: process.agent_executable_sha256.clone(),
                agent_configuration_sha256: process.agent_configuration_sha256.clone(),
                agent_state_directory_sha256: process.agent_state_directory_sha256.clone(),
                agent_cgroup_sha256: process.agent_cgroup_sha256.clone(),
                acknowledgement_event_sha256: acknowledgement_event_sha256.clone(),
                signal: signal.clone(),
                cgroup_empty_after_kill: *cgroup_empty_after_kill,
            },
            QualificationCrashActionFactsV1::ProcessRestarted {
                killed_process,
                restarted_process,
                kill_event_sha256,
                control_plane_ready,
            } => QualificationEvidenceEventPayload::ProcessRestart {
                action_context_sha256,
                controller_nonce_sha256: self.crash_context.controller_nonce_sha256.clone(),
                prior_agent_generation: killed_process.agent_generation,
                prior_agent_process_id: killed_process.agent_process_id,
                prior_agent_start_time_ticks: killed_process.agent_start_time_ticks,
                restarted_agent_start_time_ticks: restarted_process.agent_start_time_ticks,
                agent_executable_sha256: restarted_process.agent_executable_sha256.clone(),
                agent_configuration_sha256: restarted_process.agent_configuration_sha256.clone(),
                agent_state_directory_sha256: restarted_process
                    .agent_state_directory_sha256
                    .clone(),
                restarted_agent_cgroup_sha256: restarted_process.agent_cgroup_sha256.clone(),
                kill_event_sha256: kill_event_sha256.clone(),
                control_plane_ready: *control_plane_ready,
            },
        }
    }

    /// Commits the action facts before append ordering and source signing.
    ///
    /// The separately retained action-context digest authenticates these same
    /// facts but depends on the source signature, so it is intentionally not
    /// part of the pre-sign append intent.
    pub fn intent_sha256(&self) -> Result<String, QualificationEvidenceLedgerError> {
        self.unsigned_event(String::new(), String::new())
            .intent_sha256()
    }

    /// Returns the process identity projected onto the public action event.
    #[must_use]
    pub const fn event_process(&self) -> &QualificationCrashProcessIdentityV1 {
        match &self.facts {
            QualificationCrashActionFactsV1::FailpointAcknowledged { process, .. }
            | QualificationCrashActionFactsV1::ProcessKilled { process, .. } => process,
            QualificationCrashActionFactsV1::ProcessRestarted {
                restarted_process, ..
            } => restarted_process,
        }
    }

    /// Constructs the only unsigned Supervisor event admitted for this record.
    #[must_use]
    pub fn unsigned_event(
        &self,
        source_key_id: String,
        action_context_sha256: String,
    ) -> QualificationEvidenceEvent {
        let process = self.event_process();
        QualificationEvidenceEvent {
            sequence: self.sequence,
            previous_event_sha256: self.previous_event_sha256.clone(),
            scenario_id: self.crash_context.phase.scenario_id.clone(),
            phase_index: self.crash_context.phase.phase_index,
            role: self.crash_context.phase.role,
            profile: self.profile.clone(),
            failpoint: self.crash_context.phase.failpoint,
            source: QualificationEvidenceSource::Supervisor,
            source_identity: self.crash_context.supervisor_source_identity.clone(),
            source_artifact_sha256: self.supervisor_source_artifact_sha256.clone(),
            source_uid: Some(self.crash_context.supervisor_source_uid),
            reader_identity: None,
            reader_artifact_sha256: None,
            reader_uid: None,
            source_context_sha256: self.crash_context.source_context_sha256.clone(),
            source_key_id,
            source_signature_base64url: String::new(),
            supervisor_generation: self.crash_context.supervisor_generation,
            agent_generation: Some(process.agent_generation),
            agent_process_id: Some(process.agent_process_id),
            agent_boot_sha256: Some(process.agent_boot_sha256.clone()),
            operation_id: self.operation_id.clone(),
            control_operation_id: Some(self.crash_context.control_operation_id.clone()),
            request_id: None,
            client_result_sha256: None,
            receipt_id: None,
            connection_generation: self.connection_generation.clone(),
            journal_revision: None,
            kind: self.event_kind(),
            payload: self.event_payload(action_context_sha256),
            durable_ack_sha256: qualification_event_marker_sha256(
                self.sequence,
                QualificationEvidenceSource::Supervisor,
            ),
        }
    }
}

impl QualificationDecisionSnapshotV1 {
    /// Decodes exact canonical public decision-snapshot bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationEvidenceLedgerError> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)?;
        value.validate()?;
        if canonical(&value)? != bytes {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        Ok(value)
    }

    /// Encodes exact canonical public decision-snapshot bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
        self.validate()?;
        canonical(self)
    }

    /// Reconstructs the complete signed Decision payload from public facts.
    #[must_use]
    pub fn decision_payload(
        &self,
        supervisor_context_sha256: String,
    ) -> QualificationEvidenceEventPayload {
        QualificationEvidenceEventPayload::Decision {
            canonical_input_sha256: self.canonical_input_sha256.clone(),
            idempotency_sha256: self.idempotency_sha256.clone(),
            canonical_action_sha256: self.canonical_action_sha256.clone(),
            receipt_action_sha256: self.receipt_action_sha256.clone(),
            receipt_context_sha256: self.receipt_context_sha256.clone(),
            authority_sha256: self.authority_sha256.clone(),
            configuration_sha256: self.configuration_sha256.clone(),
            runtime_contract_sha256: self.runtime_contract_sha256.clone(),
            preparation_sha256: self.preparation_sha256.clone(),
            decision_class: self.decision_class,
            decision_receipt_id: self.decision_receipt_id.clone(),
            decision_receipt_bytes_sha256: self.decision_receipt_bytes_sha256.clone(),
            decoded_claims_sha256: self.decoded_claims_sha256.clone(),
            supervisor_context_sha256,
            recovery_key_id: self.recovery_key_id.clone(),
            recovery_public_key_base64url: self.recovery_public_key_base64url.clone(),
            receipt_trust_anchor_sha256: self.receipt_trust_anchor_sha256.clone(),
        }
    }

    fn validate(&self) -> Result<(), QualificationEvidenceLedgerError> {
        if self.schema != "auths.qualification-decision-snapshot/1"
            || !registered_token(&self.operation_id)
            || !semantic_profile(&self.profile)
            || !decimal(&self.connection_generation)
            || self.journal_revision != 1
            || !matches!(
                (self.state, self.decision_class),
                (
                    QualificationDecisionSnapshotState::Ready,
                    QualificationReceiptDecisionClass::Authorized
                ) | (
                    QualificationDecisionSnapshotState::Denied,
                    QualificationReceiptDecisionClass::Denied
                ) | (
                    QualificationDecisionSnapshotState::Unavailable,
                    QualificationReceiptDecisionClass::Indeterminate
                )
            )
            || !digest(&self.canonical_input_sha256)
            || !self.idempotency_sha256.as_deref().is_none_or(digest)
            || !digest(&self.canonical_action_sha256)
            || !digest(&self.receipt_action_sha256)
            || !digest(&self.receipt_context_sha256)
            || !digest(&self.authority_sha256)
            || !digest(&self.configuration_sha256)
            || !digest(&self.runtime_contract_sha256)
            || !digest(&self.preparation_sha256)
            || !receipt_id(&self.decision_receipt_id)
            || !digest(&self.decision_receipt_bytes_sha256)
            || !digest(&self.decoded_claims_sha256)
            || !registered_token(&self.recovery_key_id)
            || !decode_fixed::<32>(&self.recovery_public_key_base64url)
                .is_ok_and(|key| key != [0; 32] && VerifyingKey::from_bytes(&key).is_ok())
            || !digest(&self.receipt_trust_anchor_sha256)
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        Ok(())
    }
}

impl QualificationDurableDecisionAckV1 {
    /// Constructs and validates one exact durable-decision acknowledgement.
    pub fn new(
        operation_id: String,
        journal_record_sha256: String,
        agent_generation: u32,
        control_operation_id: Option<String>,
        controller_nonce_sha256: Option<String>,
    ) -> Result<Self, QualificationEvidenceLedgerError> {
        let value = Self {
            schema: "auths.qualification-durable-decision-ack/1".into(),
            operation_id,
            journal_revision: 1,
            journal_record_sha256,
            agent_generation,
            control_operation_id,
            controller_nonce_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    /// Decodes exact canonical acknowledgement bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationEvidenceLedgerError> {
        if bytes.is_empty() || bytes.len() > 4_096 {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)?;
        value.validate()?;
        if canonical(&value)? != bytes {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        Ok(value)
    }

    /// Encodes exact canonical acknowledgement bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
        self.validate()?;
        canonical(self)
    }

    fn validate(&self) -> Result<(), QualificationEvidenceLedgerError> {
        if self.schema != "auths.qualification-durable-decision-ack/1"
            || !registered_token(&self.operation_id)
            || self.journal_revision != 1
            || !digest(&self.journal_record_sha256)
            || self.agent_generation == 0
            || match (
                self.control_operation_id.as_deref(),
                self.controller_nonce_sha256.as_deref(),
            ) {
                (Some(operation), Some(nonce)) => !registered_token(operation) || !digest(nonce),
                (None, None) => false,
                _ => true,
            }
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        Ok(())
    }
}

impl QualificationJournalDecisionContext {
    /// Signs one supervisor-observed durable-decision handoff.
    #[cfg(any(feature = "qualification-ledger-producer", test))]
    pub fn sign_json(
        record: QualificationJournalDecisionContextRecord,
        key_id: &str,
        seed_base64url: &str,
        registry: &QualificationEvidenceSourceTrustRegistry,
        started_at_unix_seconds: u64,
        completed_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
        record.validate()?;
        let seed = decode_fixed::<32>(seed_base64url)?;
        let key = registry.find_bound(
            QualificationEvidenceSource::Supervisor,
            key_id,
            &record.supervisor_source_identity,
            &record.supervisor_source_artifact_sha256,
            &record.domain,
            started_at_unix_seconds,
            completed_at_unix_seconds,
            now_unix_seconds,
            true,
        )?;
        let signing = SigningKey::from_bytes(&seed);
        if signing.verifying_key().as_bytes() != &decode_fixed::<32>(&key.public_key_base64url)? {
            return Err(QualificationEvidenceLedgerError::InvalidSourceSignature);
        }
        let signature = signing
            .sign(&journal_context_signature_preimage(&record)?)
            .to_bytes();
        canonical(&Self {
            schema: "auths.qualification-journal-decision-context/1".into(),
            record,
            signing: QualificationJournalDecisionContextSigning {
                algorithm: "Ed25519".into(),
                key_id: key_id.into(),
                signature_base64url: Base64UrlUnpadded::encode_string(&signature),
            },
        })
    }

    /// Verifies one exact canonical context under the distinct supervisor key.
    pub fn verify_json(
        bytes: &[u8],
        registry: &QualificationEvidenceSourceTrustRegistry,
        started_at_unix_seconds: u64,
        completed_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<Self, QualificationEvidenceLedgerError> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)?;
        if canonical(&value)? != bytes
            || value.schema != "auths.qualification-journal-decision-context/1"
            || value.signing.algorithm != "Ed25519"
        {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        value.record.validate()?;
        let key = registry.find_bound(
            QualificationEvidenceSource::Supervisor,
            &value.signing.key_id,
            &value.record.supervisor_source_identity,
            &value.record.supervisor_source_artifact_sha256,
            &value.record.domain,
            started_at_unix_seconds,
            completed_at_unix_seconds,
            now_unix_seconds,
            false,
        )?;
        let public = decode_fixed::<32>(&key.public_key_base64url)?;
        let signature = decode_fixed::<64>(&value.signing.signature_base64url)?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidSourceSignature)?
            .verify_strict(
                &journal_context_signature_preimage(&value.record)?,
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| QualificationEvidenceLedgerError::InvalidSourceSignature)?;
        Ok(value)
    }

    /// Returns the authenticated supervisor-owned context.
    #[must_use]
    pub const fn record(&self) -> &QualificationJournalDecisionContextRecord {
        &self.record
    }

    /// Returns the exact supervisor source key used for the handoff.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.signing.key_id
    }
}

fn journal_context_signature_preimage(
    record: &QualificationJournalDecisionContextRecord,
) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
    let canonical = canonical(record)?;
    let mut bytes =
        Vec::with_capacity(JOURNAL_CONTEXT_SIGNATURE_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(JOURNAL_CONTEXT_SIGNATURE_DOMAIN);
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

impl QualificationCrashActionContextV1 {
    /// Signs one exact Supervisor-observed crash action.
    #[cfg(any(feature = "qualification-ledger-producer", test))]
    pub fn sign_json(
        record: QualificationCrashActionRecordV1,
        key_id: &str,
        seed_base64url: &str,
        registry: &QualificationEvidenceSourceTrustRegistry,
        started_at_unix_seconds: u64,
        completed_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
        record.validate()?;
        let seed = decode_fixed::<32>(seed_base64url)?;
        let key = registry.find_bound(
            QualificationEvidenceSource::Supervisor,
            key_id,
            &record.crash_context.supervisor_source_identity,
            &record.supervisor_source_artifact_sha256,
            &record.crash_context.domain,
            started_at_unix_seconds,
            completed_at_unix_seconds,
            now_unix_seconds,
            true,
        )?;
        let signing = SigningKey::from_bytes(&seed);
        if signing.verifying_key().as_bytes() != &decode_fixed::<32>(&key.public_key_base64url)? {
            return Err(QualificationEvidenceLedgerError::InvalidSourceSignature);
        }
        let signature = signing
            .sign(&crash_action_context_signature_preimage(&record)?)
            .to_bytes();
        canonical(&Self {
            schema: "auths.qualification-crash-action-context/1".into(),
            record,
            signing: QualificationJournalDecisionContextSigning {
                algorithm: "Ed25519".into(),
                key_id: key_id.into(),
                signature_base64url: Base64UrlUnpadded::encode_string(&signature),
            },
        })
    }

    /// Verifies one exact retained crash-action context.
    pub fn verify_json(
        bytes: &[u8],
        registry: &QualificationEvidenceSourceTrustRegistry,
        started_at_unix_seconds: u64,
        completed_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<Self, QualificationEvidenceLedgerError> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)?;
        if canonical(&value)? != bytes
            || value.schema != "auths.qualification-crash-action-context/1"
            || value.signing.algorithm != "Ed25519"
        {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        value.record.validate()?;
        let key = registry.find_bound(
            QualificationEvidenceSource::Supervisor,
            &value.signing.key_id,
            &value.record.crash_context.supervisor_source_identity,
            &value.record.supervisor_source_artifact_sha256,
            &value.record.crash_context.domain,
            started_at_unix_seconds,
            completed_at_unix_seconds,
            now_unix_seconds,
            false,
        )?;
        let public = decode_fixed::<32>(&key.public_key_base64url)?;
        let signature = decode_fixed::<64>(&value.signing.signature_base64url)?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidSourceSignature)?
            .verify_strict(
                &crash_action_context_signature_preimage(&value.record)?,
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| QualificationEvidenceLedgerError::InvalidSourceSignature)?;
        Ok(value)
    }

    /// Returns the exact authenticated action record.
    #[must_use]
    pub const fn record(&self) -> &QualificationCrashActionRecordV1 {
        &self.record
    }

    /// Returns the exact Supervisor source key used for this action.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.signing.key_id
    }
}

fn crash_action_context_signature_preimage(
    record: &QualificationCrashActionRecordV1,
) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
    let canonical = canonical(record)?;
    let mut bytes =
        Vec::with_capacity(CRASH_ACTION_CONTEXT_SIGNATURE_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(CRASH_ACTION_CONTEXT_SIGNATURE_DOMAIN);
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

impl QualificationEvidenceLedger {
    /// Validates the complete public ledger input before a protected sealer
    /// admits its private seed.
    #[cfg(any(feature = "qualification-ledger-producer", test))]
    pub fn validate_for_signing(
        record: &QualificationEvidenceLedgerRecord,
        key_id: &str,
        source_trust: &QualificationEvidenceSourceTrustRegistry,
        ledger_trust: &QualificationEvidenceLedgerTrustRegistry,
        now_unix_seconds: u64,
    ) -> Result<(), QualificationEvidenceLedgerError> {
        record.validate()?;
        if !registered_token(key_id) {
            return Err(QualificationEvidenceLedgerError::InvalidSignature);
        }
        ledger_trust.find(
            key_id,
            &record.domain,
            record.started_at_unix_seconds,
            record.completed_at_unix_seconds,
            now_unix_seconds,
            true,
        )?;
        if source_trust.keys.iter().any(|source_key| {
            ledger_trust.keys.iter().any(|ledger_key| {
                source_key.key_id == ledger_key.key_id
                    || source_key.public_key_base64url == ledger_key.public_key_base64url
            })
        }) {
            return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
        }
        verify_source_signatures(record, source_trust, now_unix_seconds, true)
    }

    /// Signs a validated record inside the protected supervisor boundary.
    #[cfg(any(feature = "qualification-ledger-producer", test))]
    pub fn sign_json(
        record: QualificationEvidenceLedgerRecord,
        key_id: &str,
        seed_base64url: &str,
        source_trust: &QualificationEvidenceSourceTrustRegistry,
        ledger_trust: &QualificationEvidenceLedgerTrustRegistry,
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
        Self::validate_for_signing(
            &record,
            key_id,
            source_trust,
            ledger_trust,
            now_unix_seconds,
        )?;
        let seed = decode_fixed::<32>(seed_base64url)?;
        let public_key_base64url = Base64UrlUnpadded::encode_string(
            SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
        );
        let registered_key = ledger_trust.find(
            key_id,
            &record.domain,
            record.started_at_unix_seconds,
            record.completed_at_unix_seconds,
            now_unix_seconds,
            true,
        )?;
        if registered_key.public_key_base64url != public_key_base64url {
            return Err(QualificationEvidenceLedgerError::InvalidSignature);
        }
        let signature = SigningKey::from_bytes(&seed)
            .sign(&record.signature_preimage()?)
            .to_bytes();
        canonical(&Self {
            schema: "auths.profile-qualification-evidence-ledger/1".into(),
            record,
            signing: QualificationEvidenceLedgerSigning {
                algorithm: "Ed25519".into(),
                key_id: key_id.into(),
                signature_base64url: Base64UrlUnpadded::encode_string(&signature),
            },
        })
    }

    /// Verifies canonical bytes against the exact protected supervisor key.
    pub fn verify_json(
        bytes: &[u8],
        source_trust: &QualificationEvidenceSourceTrustRegistry,
        ledger_trust: &QualificationEvidenceLedgerTrustRegistry,
        now_unix_seconds: u64,
    ) -> Result<Self, QualificationEvidenceLedgerError> {
        if bytes.len() > MAX_LEDGER_BYTES {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        let ledger: Self = serde_json::from_slice(bytes)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)?;
        if canonical(&ledger)? != bytes
            || ledger.schema != "auths.profile-qualification-evidence-ledger/1"
            || ledger.signing.algorithm != "Ed25519"
            || ledger.record.completed_at_unix_seconds
                > now_unix_seconds.saturating_add(CLOCK_SKEW_SECONDS)
        {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        ledger.record.validate()?;
        let ledger_key = ledger_trust.find(
            &ledger.signing.key_id,
            &ledger.record.domain,
            ledger.record.started_at_unix_seconds,
            ledger.record.completed_at_unix_seconds,
            now_unix_seconds,
            false,
        )?;
        if source_trust.keys.iter().any(|key| {
            ledger_trust.keys.iter().any(|ledger_key| {
                key.key_id == ledger_key.key_id
                    || key.public_key_base64url == ledger_key.public_key_base64url
            })
        }) {
            return Err(QualificationEvidenceLedgerError::InvalidSourceTrust);
        }
        verify_source_signatures(&ledger.record, source_trust, now_unix_seconds, false)?;
        let public_key = decode_fixed::<32>(&ledger_key.public_key_base64url)?;
        let signature = decode_fixed::<64>(&ledger.signing.signature_base64url)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidSignature)?
            .verify_strict(
                &ledger.record.signature_preimage()?,
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| QualificationEvidenceLedgerError::InvalidSignature)?;
        Ok(ledger)
    }

    /// Returns the verified protected record.
    #[must_use]
    pub const fn record(&self) -> &QualificationEvidenceLedgerRecord {
        &self.record
    }

    /// Returns the verified ledger-sealer key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.signing.key_id
    }
}

impl QualificationEvidenceEvent {
    /// Commits the source-owned meaning of an event independently of its
    /// eventual global sequence, signing key, or append acknowledgement.
    ///
    /// Readers send this commitment before the append sequencer reserves the
    /// ledger lock. A retry can therefore recover an already durable event
    /// without signing a duplicate at the next sequence.
    pub fn intent_sha256(&self) -> Result<String, QualificationEvidenceLedgerError> {
        let mut intent = self.clone();
        intent.sequence = 0;
        ZERO_DIGEST.clone_into(&mut intent.previous_event_sha256);
        intent.source_identity.clear();
        intent.source_artifact_sha256.clear();
        intent.source_uid = None;
        intent.reader_identity = None;
        intent.reader_artifact_sha256 = None;
        intent.reader_uid = None;
        intent.source_context_sha256.clear();
        intent.source_key_id.clear();
        intent.source_signature_base64url.clear();
        intent.durable_ack_sha256.clear();
        match &mut intent.payload {
            QualificationEvidenceEventPayload::FailpointAcknowledgement {
                action_context_sha256,
                boundary_event_sha256,
                ..
            } => {
                action_context_sha256.clear();
                ZERO_DIGEST.clone_into(boundary_event_sha256);
            }
            QualificationEvidenceEventPayload::ProcessKill {
                action_context_sha256,
                acknowledgement_event_sha256,
                ..
            } => {
                action_context_sha256.clear();
                ZERO_DIGEST.clone_into(acknowledgement_event_sha256);
            }
            QualificationEvidenceEventPayload::ProcessRestart {
                action_context_sha256,
                kill_event_sha256,
                ..
            } => {
                action_context_sha256.clear();
                ZERO_DIGEST.clone_into(kill_event_sha256);
            }
            _ => {}
        }
        let mut preimage = b"AUTHS-QUALIFICATION-EVENT-INTENT\0\x01".to_vec();
        preimage.extend_from_slice(&canonical(&intent)?);
        Ok(hex::encode(Sha256::digest(preimage)))
    }

    /// Validates one unsigned event and its active source-key assignment before
    /// a protected source process admits its private signing seed.
    #[cfg(any(feature = "qualification-ledger-producer", test))]
    pub fn validate_for_signing(
        &self,
        expected_source: QualificationEvidenceSource,
        expected_source_context_sha256: &str,
        registry: &QualificationEvidenceSourceTrustRegistry,
        domain: &str,
        started_at_unix_seconds: u64,
        completed_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<(), QualificationEvidenceLedgerError> {
        if self.source != expected_source
            || self.source_context_sha256 != expected_source_context_sha256
            || !digest(expected_source_context_sha256)
            || !self.source_signature_base64url.is_empty()
            || !event_shape_valid(self, false)
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        registry.find(
            self,
            domain,
            started_at_unix_seconds,
            completed_at_unix_seconds,
            now_unix_seconds,
            true,
        )?;
        Ok(())
    }

    /// Verifies one exact canonical source event before it enters the
    /// supervisor-owned append-only ledger.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_json(
        bytes: &[u8],
        expected_source: QualificationEvidenceSource,
        expected_source_context_sha256: &str,
        registry: &QualificationEvidenceSourceTrustRegistry,
        domain: &str,
        started_at_unix_seconds: u64,
        completed_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<Self, QualificationEvidenceLedgerError> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(QualificationEvidenceLedgerError::InvalidEncoding);
        }
        let event: Self = serde_json::from_slice(bytes)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)?;
        if canonical(&event)? != bytes
            || event.source != expected_source
            || event.source_context_sha256 != expected_source_context_sha256
            || !digest(expected_source_context_sha256)
            || !event_shape_valid(&event, true)
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        let key = registry.find(
            &event,
            domain,
            started_at_unix_seconds,
            completed_at_unix_seconds,
            now_unix_seconds,
            false,
        )?;
        let public = decode_fixed::<32>(&key.public_key_base64url)?;
        let signature = decode_fixed::<64>(&event.source_signature_base64url)?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidSourceSignature)?
            .verify_strict(
                &event_signature_preimage(&event)?,
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| QualificationEvidenceLedgerError::InvalidSourceSignature)?;
        Ok(event)
    }

    /// Signs one closed source event inside a single-role protected process.
    #[cfg(any(feature = "qualification-ledger-producer", test))]
    pub fn sign_json(
        mut self,
        expected_source: QualificationEvidenceSource,
        expected_source_context_sha256: &str,
        seed_base64url: &str,
        registry: &QualificationEvidenceSourceTrustRegistry,
        domain: &str,
        started_at_unix_seconds: u64,
        completed_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
        self.validate_for_signing(
            expected_source,
            expected_source_context_sha256,
            registry,
            domain,
            started_at_unix_seconds,
            completed_at_unix_seconds,
            now_unix_seconds,
        )?;
        let seed = decode_fixed::<32>(seed_base64url)?;
        let key = registry.find(
            &self,
            domain,
            started_at_unix_seconds,
            completed_at_unix_seconds,
            now_unix_seconds,
            true,
        )?;
        let signing_key = SigningKey::from_bytes(&seed);
        if signing_key.verifying_key().as_bytes() != &decode_fixed::<32>(&key.public_key_base64url)?
        {
            return Err(QualificationEvidenceLedgerError::InvalidSourceSignature);
        }
        let signature = signing_key
            .sign(&event_signature_preimage(&self)?)
            .to_bytes();
        self.source_signature_base64url = Base64UrlUnpadded::encode_string(&signature);
        canonical(&self)
    }
}

impl QualificationSourceEventContextV1 {
    #[allow(clippy::too_many_arguments)]
    fn unsigned_event(
        &self,
        source: QualificationEvidenceSource,
        process: &QualificationSourceProcessBindingV1,
        source_context_sha256: String,
        source_key_id: String,
        kind: QualificationEvidenceEventKind,
        payload: QualificationEvidenceEventPayload,
        client_result_sha256: Option<String>,
        receipt_id: Option<String>,
    ) -> QualificationEvidenceEvent {
        QualificationEvidenceEvent {
            sequence: self.sequence,
            previous_event_sha256: self.previous_event_sha256.clone(),
            scenario_id: self.scenario_id.clone(),
            phase_index: self.phase_index,
            role: self.role,
            profile: self.profile.clone(),
            failpoint: self.failpoint,
            source,
            source_identity: process.source_identity.clone(),
            source_artifact_sha256: process.source_artifact_sha256.clone(),
            source_uid: Some(process.source_uid),
            reader_identity: Some(process.reader_identity.clone()),
            reader_artifact_sha256: Some(process.reader_artifact_sha256.clone()),
            reader_uid: Some(process.reader_uid),
            source_context_sha256,
            source_key_id,
            source_signature_base64url: String::new(),
            supervisor_generation: self.supervisor_generation,
            agent_generation: None,
            agent_process_id: None,
            agent_boot_sha256: None,
            operation_id: self.operation_id.clone(),
            control_operation_id: None,
            request_id: self.request_id.clone(),
            client_result_sha256,
            receipt_id,
            connection_generation: self.connection_generation.clone(),
            journal_revision: None,
            kind,
            payload,
            durable_ack_sha256: qualification_event_marker_sha256(self.sequence, source),
        }
    }
}

macro_rules! impl_typed_source_record_json {
    ($type:ty, $schema:literal) => {
        impl $type {
            /// Decodes one exact canonical fixed-role reader record.
            pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationEvidenceLedgerError> {
                if bytes.is_empty() || bytes.len() > 65_536 {
                    return Err(QualificationEvidenceLedgerError::InvalidEncoding);
                }
                let value: Self = serde_json::from_slice(bytes)
                    .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)?;
                if value.schema != $schema || canonical(&value)? != bytes {
                    return Err(QualificationEvidenceLedgerError::InvalidEncoding);
                }
                Ok(value)
            }

            /// Encodes one exact canonical fixed-role reader record.
            pub fn to_json(&self) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
                let bytes = canonical(self)?;
                Self::from_json(&bytes)?;
                Ok(bytes)
            }
        }
    };
}

impl_typed_source_record_json!(
    QualificationClientProxyRecordV1,
    "auths.qualification-client-proxy-record/1"
);
impl_typed_source_record_json!(
    QualificationCredentialBrokerRecordV1,
    "auths.qualification-credential-broker-record/1"
);
impl_typed_source_record_json!(
    QualificationProfileStateRecordV1,
    "auths.qualification-profile-state-record/1"
);
impl_typed_source_record_json!(
    QualificationProviderProxyRecordV1,
    "auths.qualification-provider-proxy-record/1"
);
impl_typed_source_record_json!(
    QualificationReceiptVerifierRecordV1,
    "auths.qualification-receipt-verifier-record/1"
);
impl_typed_source_record_json!(
    QualificationProviderObserverRecordV1,
    "auths.qualification-provider-observer-record/1"
);

impl QualificationClientProxyRecordV1 {
    /// Derives the only unsigned client-proxy event represented by this record.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn unsigned_event(
        &self,
        process: &QualificationSourceProcessBindingV1,
        source_context_sha256: String,
        source_key_id: String,
    ) -> QualificationEvidenceEvent {
        let (kind, payload, attempt) = match &self.observation {
            QualificationClientProxyObservationV1::RequestReceived {
                request_input_sha256,
                principal_sha256,
                idempotency_sha256,
                preparation_input_sha256,
            } => (
                QualificationEvidenceEventKind::RequestReceived,
                QualificationEvidenceEventPayload::Request {
                    request_input_sha256: request_input_sha256.clone(),
                    principal_sha256: principal_sha256.clone(),
                    idempotency_sha256: idempotency_sha256.clone(),
                    preparation_input_sha256: preparation_input_sha256.clone(),
                },
                None,
            ),
            QualificationClientProxyObservationV1::ResponseProjected {
                result_sha256,
                journal_projection_kinds,
                outcome,
                completion,
                recovery_id,
                error_code,
                issue_metadata_sha256,
                receipt_ids,
            } => (
                QualificationEvidenceEventKind::ResponseProjected,
                QualificationEvidenceEventPayload::ClientResult {
                    result_sha256: result_sha256.clone(),
                    journal_projection_kinds: journal_projection_kinds.clone(),
                    outcome: *outcome,
                    completion: *completion,
                    recovery_id: recovery_id.clone(),
                    error_code: error_code.clone(),
                    issue_metadata_sha256: issue_metadata_sha256.clone(),
                    receipt_ids: receipt_ids.clone(),
                },
                Some(result_sha256.clone()),
            ),
            QualificationClientProxyObservationV1::CancellationObserved {
                result_sha256,
                journal_projection_kinds,
                outcome,
                completion,
                recovery_id,
                error_code,
                issue_metadata_sha256,
                receipt_ids,
            } => (
                QualificationEvidenceEventKind::CancellationObserved,
                QualificationEvidenceEventPayload::ClientResult {
                    result_sha256: result_sha256.clone(),
                    journal_projection_kinds: journal_projection_kinds.clone(),
                    outcome: *outcome,
                    completion: *completion,
                    recovery_id: recovery_id.clone(),
                    error_code: error_code.clone(),
                    issue_metadata_sha256: issue_metadata_sha256.clone(),
                    receipt_ids: receipt_ids.clone(),
                },
                Some(result_sha256.clone()),
            ),
        };
        self.context.unsigned_event(
            QualificationEvidenceSource::ClientProxy,
            process,
            source_context_sha256,
            source_key_id,
            kind,
            payload,
            attempt,
            None,
        )
    }
}

impl QualificationCredentialBrokerRecordV1 {
    /// Derives the only unsigned credential-broker event represented here.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn unsigned_event(
        &self,
        process: &QualificationSourceProcessBindingV1,
        source_context_sha256: String,
        source_key_id: String,
    ) -> QualificationEvidenceEvent {
        let (kind, payload) = match &self.observation {
            QualificationCredentialBrokerObservationV1::ConnectionReread {
                connection_id_sha256,
                connection_alias_sha256,
                descriptor_sha256,
                account_sha256,
            } => (
                QualificationEvidenceEventKind::ConnectionReread,
                QualificationEvidenceEventPayload::Connection {
                    connection_id_sha256: connection_id_sha256.clone(),
                    connection_alias_sha256: connection_alias_sha256.clone(),
                    descriptor_sha256: descriptor_sha256.clone(),
                    account_sha256: account_sha256.clone(),
                },
            ),
            QualificationCredentialBrokerObservationV1::CredentialLeaseAttempted {
                lease_sha256,
                requested_scope_sha256,
                effective_scope_sha256,
            } => (
                QualificationEvidenceEventKind::CredentialLeaseAttempted,
                QualificationEvidenceEventPayload::Credential {
                    lease_sha256: lease_sha256.clone(),
                    requested_scope_sha256: requested_scope_sha256.clone(),
                    effective_scope_sha256: effective_scope_sha256.clone(),
                },
            ),
            QualificationCredentialBrokerObservationV1::CredentialLeaseSucceeded {
                lease_sha256,
                requested_scope_sha256,
                effective_scope_sha256,
            } => (
                QualificationEvidenceEventKind::CredentialLeaseSucceeded,
                QualificationEvidenceEventPayload::Credential {
                    lease_sha256: lease_sha256.clone(),
                    requested_scope_sha256: requested_scope_sha256.clone(),
                    effective_scope_sha256: effective_scope_sha256.clone(),
                },
            ),
            QualificationCredentialBrokerObservationV1::CredentialLeaseClosed {
                lease_sha256,
                requested_scope_sha256,
                effective_scope_sha256,
            } => (
                QualificationEvidenceEventKind::CredentialLeaseClosed,
                QualificationEvidenceEventPayload::Credential {
                    lease_sha256: lease_sha256.clone(),
                    requested_scope_sha256: requested_scope_sha256.clone(),
                    effective_scope_sha256: effective_scope_sha256.clone(),
                },
            ),
        };
        self.context.unsigned_event(
            QualificationEvidenceSource::CredentialBroker,
            process,
            source_context_sha256,
            source_key_id,
            kind,
            payload,
            None,
            None,
        )
    }
}

impl QualificationProfileStateRecordV1 {
    /// Derives the only unsigned profile-state event represented here.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn unsigned_event(
        &self,
        process: &QualificationSourceProcessBindingV1,
        source_context_sha256: String,
        source_key_id: String,
    ) -> QualificationEvidenceEvent {
        let (kind, reservation_sha256) = match &self.observation {
            QualificationProfileStateObservationV1::ReservationDurable { reservation_sha256 } => (
                QualificationEvidenceEventKind::ReservationDurable,
                reservation_sha256,
            ),
            QualificationProfileStateObservationV1::ReservationReleased { reservation_sha256 } => (
                QualificationEvidenceEventKind::ReservationReleased,
                reservation_sha256,
            ),
            QualificationProfileStateObservationV1::ReservationConsumed { reservation_sha256 } => (
                QualificationEvidenceEventKind::ReservationConsumed,
                reservation_sha256,
            ),
            QualificationProfileStateObservationV1::ReservationRetained { reservation_sha256 } => (
                QualificationEvidenceEventKind::ReservationRetained,
                reservation_sha256,
            ),
        };
        self.context.unsigned_event(
            QualificationEvidenceSource::ProfileStateReader,
            process,
            source_context_sha256,
            source_key_id,
            kind,
            QualificationEvidenceEventPayload::Reservation {
                reservation_sha256: reservation_sha256.clone(),
            },
            None,
            None,
        )
    }
}

impl QualificationProviderProxyRecordV1 {
    /// Derives the only unsigned provider-transport event represented here.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn unsigned_event(
        &self,
        process: &QualificationSourceProcessBindingV1,
        source_context_sha256: String,
        source_key_id: String,
    ) -> QualificationEvidenceEvent {
        let (kind, payload) = match &self.observation {
            QualificationProviderProxyObservationV1::ProviderRequestWritten {
                request_sha256,
                credential_lease_sha256,
            } => (
                QualificationEvidenceEventKind::ProviderRequestWritten,
                QualificationEvidenceEventPayload::ProviderRequest {
                    request_sha256: request_sha256.clone(),
                    credential_lease_sha256: credential_lease_sha256.clone(),
                },
            ),
            QualificationProviderProxyObservationV1::ProviderResponseObserved {
                response_sha256,
            } => (
                QualificationEvidenceEventKind::ProviderResponseObserved,
                QualificationEvidenceEventPayload::ProviderResponse {
                    response_sha256: response_sha256.clone(),
                },
            ),
            QualificationProviderProxyObservationV1::ProviderReconciliationRequested {
                request_sha256,
                credential_lease_sha256,
            } => (
                QualificationEvidenceEventKind::ProviderReconciliationRequested,
                QualificationEvidenceEventPayload::ProviderRequest {
                    request_sha256: request_sha256.clone(),
                    credential_lease_sha256: credential_lease_sha256.clone(),
                },
            ),
            QualificationProviderProxyObservationV1::ProviderReconciliationObserved {
                response_sha256,
            } => (
                QualificationEvidenceEventKind::ProviderReconciliationObserved,
                QualificationEvidenceEventPayload::ProviderResponse {
                    response_sha256: response_sha256.clone(),
                },
            ),
        };
        self.context.unsigned_event(
            QualificationEvidenceSource::ProviderProxy,
            process,
            source_context_sha256,
            source_key_id,
            kind,
            payload,
            None,
            None,
        )
    }
}

impl QualificationReceiptVerifierRecordV1 {
    /// Derives the only unsigned native-receipt-verification event.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn unsigned_event(
        &self,
        process: &QualificationSourceProcessBindingV1,
        source_context_sha256: String,
        source_key_id: String,
    ) -> QualificationEvidenceEvent {
        self.context.unsigned_event(
            QualificationEvidenceSource::ReceiptVerifier,
            process,
            source_context_sha256,
            source_key_id,
            QualificationEvidenceEventKind::NativeReceiptVerified,
            QualificationEvidenceEventPayload::ReceiptVerification {
                receipt_bytes_sha256: self.receipt_bytes_sha256.clone(),
                decoded_claims_sha256: self.decoded_claims_sha256.clone(),
                profile_inspection_sha256: self.profile_inspection_sha256.clone(),
            },
            None,
            Some(self.receipt_id.clone()),
        )
    }
}

impl QualificationProviderObserverRecordV1 {
    /// Derives the only unsigned provider-truth observation event.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn unsigned_event(
        &self,
        process: &QualificationSourceProcessBindingV1,
        source_context_sha256: String,
        source_key_id: String,
    ) -> QualificationEvidenceEvent {
        self.context.unsigned_event(
            QualificationEvidenceSource::ProviderObserver,
            process,
            source_context_sha256,
            source_key_id,
            QualificationEvidenceEventKind::ProviderTruthObserved,
            QualificationEvidenceEventPayload::ProviderTruth {
                effect: self.effect,
                provider_truth_sha256: self.provider_truth_sha256.clone(),
            },
            None,
            None,
        )
    }
}

macro_rules! impl_typed_source_record_intent {
    ($type:ty) => {
        impl $type {
            /// Commits the reader-owned observation independently of append
            /// ordering and signer-key rotation.
            pub fn intent_sha256(&self) -> Result<String, QualificationEvidenceLedgerError> {
                self.unsigned_event(
                    &QualificationSourceProcessBindingV1 {
                        source_identity: String::new(),
                        source_artifact_sha256: String::new(),
                        source_uid: 0,
                        reader_identity: String::new(),
                        reader_artifact_sha256: String::new(),
                        reader_uid: 0,
                    },
                    String::new(),
                    String::new(),
                )
                .intent_sha256()
            }
        }
    };
}

impl_typed_source_record_intent!(QualificationClientProxyRecordV1);
impl_typed_source_record_intent!(QualificationCredentialBrokerRecordV1);
impl_typed_source_record_intent!(QualificationProfileStateRecordV1);
impl_typed_source_record_intent!(QualificationProviderProxyRecordV1);
impl_typed_source_record_intent!(QualificationReceiptVerifierRecordV1);
impl_typed_source_record_intent!(QualificationProviderObserverRecordV1);

fn validate_events(
    events: &[QualificationEvidenceEvent],
) -> Result<(), QualificationEvidenceLedgerError> {
    let mut previous = ZERO_DIGEST.to_owned();
    for (index, event) in events.iter().enumerate() {
        if event.sequence != u32::try_from(index + 1).unwrap_or(u32::MAX)
            || event.previous_event_sha256 != previous
            || !event_shape_valid(event, true)
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        previous = hex::encode(Sha256::digest(canonical(event)?));
    }
    validate_event_sequences(events)?;
    validate_operation_order(events)?;
    Ok(())
}

/// Validates the exact authenticated event-chain invariants without requiring
/// the final phase commitments or ledger signature to exist yet.
///
/// The protected appender calls this only at a durable phase boundary. This
/// prevents an append-only prefix that could never later become a valid
/// qualification ledger while keeping incomplete in-flight phases possible.
pub fn qualification_evidence_event_chain_valid(
    events: &[QualificationEvidenceEvent],
) -> Result<(), QualificationEvidenceLedgerError> {
    validate_events(events)?;
    validate_agent_trust(events)
}

fn event_shape_valid(event: &QualificationEvidenceEvent, signed: bool) -> bool {
    let fixed_reader_source = matches!(
        event.source,
        QualificationEvidenceSource::ClientProxy
            | QualificationEvidenceSource::CredentialBroker
            | QualificationEvidenceSource::ProfileStateReader
            | QualificationEvidenceSource::ProviderProxy
            | QualificationEvidenceSource::ReceiptVerifier
            | QualificationEvidenceSource::ProviderObserver
    );
    registered_token(&event.scenario_id)
        && (1..=8).contains(&event.phase_index)
        && semantic_profile(&event.profile)
        && registered_token(&event.source_identity)
        && digest(&event.source_artifact_sha256)
        && event
            .source_uid
            .is_some_and(|uid| uid != 0 && uid != u32::MAX)
        && fixed_reader_source
            == event
                .reader_identity
                .as_deref()
                .is_some_and(registered_token)
        && fixed_reader_source == event.reader_artifact_sha256.as_deref().is_some_and(digest)
        && fixed_reader_source
            == event
                .reader_uid
                .is_some_and(|uid| uid != 0 && uid != u32::MAX)
        && (fixed_reader_source
            || event.reader_identity.is_none()
                && event.reader_artifact_sha256.is_none()
                && event.reader_uid.is_none())
        && (!fixed_reader_source || event.reader_uid != event.source_uid)
        && digest(&event.source_context_sha256)
        && registered_token(&event.source_key_id)
        && if signed {
            decode_fixed::<64>(&event.source_signature_base64url).is_ok()
        } else {
            event.source_signature_base64url.is_empty()
        }
        && event.supervisor_generation != 0
        && event.agent_generation != Some(0)
        && event.agent_process_id != Some(0)
        && [
            event.agent_generation.is_some(),
            event.agent_process_id.is_some(),
            event.agent_boot_sha256.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
            % 3
            == 0
        && event.agent_boot_sha256.as_deref().is_none_or(digest)
        && event.operation_id.as_deref().is_none_or(registered_token)
        && event
            .control_operation_id
            .as_deref()
            .is_none_or(registered_token)
        && event.request_id.as_deref().is_none_or(registered_token)
        && event.client_result_sha256.as_deref().is_none_or(digest)
        && event.receipt_id.as_deref().is_none_or(receipt_id)
        && event.connection_generation.as_deref().is_none_or(decimal)
        && payload_valid(&event.payload)
        && payload_matches_kind(event.kind, &event.payload)
        && digest(&event.durable_ack_sha256)
        && event.durable_ack_sha256
            == qualification_event_marker_sha256(event.sequence, event.source)
        && source_owns(event.source, event.kind)
        && event_fields_match_kind(event)
}

#[allow(clippy::too_many_lines)]
fn validate_operation_order(
    events: &[QualificationEvidenceEvent],
) -> Result<(), QualificationEvidenceLedgerError> {
    use QualificationEvidenceEventKind as Kind;
    let mut operations = BTreeMap::<&str, Vec<(usize, &QualificationEvidenceEvent)>>::new();
    for (index, event) in events.iter().enumerate() {
        if let Some(operation) = event.operation_id.as_deref() {
            if event.connection_generation.is_none() {
                return Err(QualificationEvidenceLedgerError::InvalidEvent);
            }
            operations
                .entry(operation)
                .or_default()
                .push((index, event));
        }
    }
    let singletons = [
        Kind::DecisionDurable,
        Kind::ReservationDurable,
        Kind::ReservationReleased,
        Kind::ReservationConsumed,
        Kind::ReservationRetained,
        Kind::CommandDurable,
        Kind::ConnectionReread,
        Kind::CredentialLeaseAttempted,
        Kind::CredentialLeaseSucceeded,
        Kind::CredentialLeaseClosed,
        Kind::ProviderEntryDurable,
        Kind::ProviderRequestWritten,
        Kind::ProviderResponseObserved,
        Kind::ProviderReconciliationRequested,
        Kind::ProviderReconciliationObserved,
        Kind::ProviderResultDurable,
        Kind::ObservationDurable,
        Kind::ExecutionReceiptDurable,
        Kind::TerminalDurable,
        Kind::ProviderTruthObserved,
    ];
    let order = [
        (Kind::DecisionDurable, Kind::ReservationDurable),
        (Kind::DecisionDurable, Kind::CommandDurable),
        (Kind::ReservationDurable, Kind::ReservationReleased),
        (Kind::ReservationDurable, Kind::ReservationConsumed),
        (Kind::ReservationDurable, Kind::ReservationRetained),
        (Kind::CommandDurable, Kind::ConnectionReread),
        (Kind::ConnectionReread, Kind::CredentialLeaseAttempted),
        (
            Kind::CredentialLeaseAttempted,
            Kind::CredentialLeaseSucceeded,
        ),
        (Kind::CredentialLeaseSucceeded, Kind::ProviderEntryDurable),
        (Kind::CredentialLeaseSucceeded, Kind::CredentialLeaseClosed),
        (Kind::ProviderEntryDurable, Kind::ProviderRequestWritten),
        (Kind::ProviderRequestWritten, Kind::ProviderResponseObserved),
        (
            Kind::ProviderEntryDurable,
            Kind::ProviderReconciliationRequested,
        ),
        (
            Kind::ProviderReconciliationRequested,
            Kind::ProviderReconciliationObserved,
        ),
        (Kind::ProviderReconciliationObserved, Kind::RecoveryObserved),
        (Kind::ProviderRequestWritten, Kind::ProviderResultDurable),
        (Kind::ProviderResultDurable, Kind::ObservationDurable),
        (Kind::ProviderEntryDurable, Kind::ExecutionReceiptDurable),
        (Kind::DecisionDurable, Kind::RecoveryRequiredDurable),
        (Kind::ProviderEntryDurable, Kind::RecoveryRequiredDurable),
        (Kind::RecoveryRequiredDurable, Kind::TerminalDurable),
        (Kind::ObservationDurable, Kind::TerminalDurable),
        (Kind::ExecutionReceiptDurable, Kind::TerminalDurable),
        (Kind::ReservationConsumed, Kind::TerminalDurable),
        (Kind::ReservationReleased, Kind::TerminalDurable),
        (Kind::TerminalDurable, Kind::ProviderTruthObserved),
    ];
    for rows in operations.values() {
        let position = |kind: Kind| {
            rows.iter()
                .filter(|(_, event)| event.kind == kind)
                .map(|(index, _)| *index)
                .collect::<Vec<_>>()
        };
        if position(Kind::DecisionDurable).len() != 1
            || singletons.iter().any(|kind| position(*kind).len() > 1)
            || [
                Kind::ReservationReleased,
                Kind::ReservationConsumed,
                Kind::ReservationRetained,
            ]
            .iter()
            .map(|kind| position(*kind).len())
            .sum::<usize>()
                > 1
            || order.iter().any(|(before, after)| {
                let before = position(*before);
                let after = position(*after);
                !before.is_empty() && !after.is_empty() && before[0] >= after[0]
            })
            || !position(Kind::ProviderRequestWritten).is_empty()
                && position(Kind::ProviderEntryDurable).is_empty()
            || !position(Kind::ProviderReconciliationRequested).is_empty()
                && position(Kind::ProviderEntryDurable).is_empty()
            || !position(Kind::ProviderReconciliationObserved).is_empty()
                && position(Kind::ProviderReconciliationRequested).is_empty()
            || !position(Kind::ProviderResultDurable).is_empty()
                && position(Kind::ProviderRequestWritten).is_empty()
            || !position(Kind::RecoveryRequiredDurable).is_empty()
                && position(Kind::ProviderEntryDurable).is_empty()
            || !position(Kind::CredentialLeaseSucceeded).is_empty()
                && position(Kind::CredentialLeaseAttempted).is_empty()
            || !position(Kind::CredentialLeaseClosed).is_empty()
                && position(Kind::CredentialLeaseSucceeded).is_empty()
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_event_sequences(
    events: &[QualificationEvidenceEvent],
) -> Result<(), QualificationEvidenceLedgerError> {
    let mut journal_revisions = BTreeMap::<&str, (u64, QualificationEvidenceEventKind)>::new();
    let mut connection_generations = BTreeMap::<&str, &str>::new();
    let mut agent_generation = None::<u32>;
    let mut agent_identity = None::<(u32, &str)>;
    let mut agent_killed = false;
    let mut request_ingress = BTreeMap::<&str, usize>::new();
    let mut request_egress = BTreeMap::<&str, usize>::new();
    for (index, event) in events.iter().enumerate() {
        if event.kind == QualificationEvidenceEventKind::RequestReceived
            && event
                .request_id
                .as_deref()
                .is_some_and(|request| request_ingress.insert(request, index).is_some())
            || matches!(
                event.kind,
                QualificationEvidenceEventKind::ResponseProjected
                    | QualificationEvidenceEventKind::CancellationObserved
            ) && event
                .request_id
                .as_deref()
                .is_some_and(|request| request_egress.insert(request, index).is_some())
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
    }
    for (index, event) in events.iter().enumerate() {
        if agent_killed
            && event.agent_generation.is_some()
            && event.kind != QualificationEvidenceEventKind::ProcessRestarted
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        if event.kind == QualificationEvidenceEventKind::ProcessKilled {
            if agent_killed {
                return Err(QualificationEvidenceLedgerError::InvalidEvent);
            }
            agent_killed = true;
        } else if event.kind == QualificationEvidenceEventKind::ProcessRestarted {
            if !agent_killed {
                return Err(QualificationEvidenceLedgerError::InvalidEvent);
            }
            agent_killed = false;
        }
        if event.source == QualificationEvidenceSource::JournalReader {
            let operation = event
                .operation_id
                .as_deref()
                .ok_or(QualificationEvidenceLedgerError::InvalidEvent)?;
            let revision = event
                .journal_revision
                .ok_or(QualificationEvidenceLedgerError::InvalidEvent)?;
            let mutating = !matches!(
                event.kind,
                QualificationEvidenceEventKind::ReplayObserved
                    | QualificationEvidenceEventKind::StatusObserved
                    | QualificationEvidenceEventKind::RecoveryObserved
            );
            if revision == 0
                || event.kind == QualificationEvidenceEventKind::DecisionDurable && revision != 1
                || journal_revisions
                    .get(operation)
                    .is_some_and(|(prior_revision, prior_kind)| {
                        revision < *prior_revision
                            || mutating
                                && revision == *prior_revision
                                && !(*prior_kind == QualificationEvidenceEventKind::DecisionDurable
                                    && event.kind
                                        == QualificationEvidenceEventKind::TerminalDurable)
                    })
                || event.agent_generation.is_none()
                || event.agent_process_id.is_none()
                || event.agent_boot_sha256.is_none()
            {
                return Err(QualificationEvidenceLedgerError::InvalidEvent);
            }
            journal_revisions.insert(operation, (revision, event.kind));
            if !mutating {
                let request = event
                    .request_id
                    .as_deref()
                    .ok_or(QualificationEvidenceLedgerError::InvalidEvent)?;
                if request_ingress
                    .get(request)
                    .is_none_or(|ingress| *ingress >= index)
                    || request_egress
                        .get(request)
                        .is_none_or(|egress| *egress <= index)
                {
                    return Err(QualificationEvidenceLedgerError::InvalidEvent);
                }
            }
        }
        if let (Some(operation), Some(generation)) = (
            event.operation_id.as_deref(),
            event.connection_generation.as_deref(),
        ) && connection_generations
            .insert(operation, generation)
            .is_some_and(|prior| prior != generation)
        {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        if let (Some(generation), Some(process_id), Some(boot)) = (
            event.agent_generation,
            event.agent_process_id,
            event.agent_boot_sha256.as_deref(),
        ) {
            match event.kind {
                QualificationEvidenceEventKind::ProcessRestarted => {
                    if agent_generation
                        .is_some_and(|prior| prior.checked_add(1) != Some(generation))
                        || agent_identity.is_some_and(|prior| prior == (process_id, boot))
                    {
                        return Err(QualificationEvidenceLedgerError::InvalidEvent);
                    }
                    agent_generation = Some(generation);
                    agent_identity = Some((process_id, boot));
                }
                _ => {
                    if agent_generation.is_none() {
                        agent_generation = Some(generation);
                        agent_identity = Some((process_id, boot));
                    } else if agent_generation != Some(generation)
                        || agent_identity != Some((process_id, boot))
                    {
                        return Err(QualificationEvidenceLedgerError::InvalidEvent);
                    }
                }
            }
        }
    }
    if agent_killed {
        Err(QualificationEvidenceLedgerError::InvalidEvent)
    } else {
        Ok(())
    }
}

fn validate_agent_trust(
    events: &[QualificationEvidenceEvent],
) -> Result<(), QualificationEvidenceLedgerError> {
    let mut expected = None::<(&str, &str, &str)>;
    for event in events {
        let QualificationEvidenceEventPayload::Decision {
            recovery_key_id,
            recovery_public_key_base64url,
            receipt_trust_anchor_sha256,
            ..
        } = &event.payload
        else {
            continue;
        };
        let identity = (
            recovery_key_id.as_str(),
            recovery_public_key_base64url.as_str(),
            receipt_trust_anchor_sha256.as_str(),
        );
        if expected.is_some_and(|prior| prior != identity) {
            return Err(QualificationEvidenceLedgerError::InvalidEvent);
        }
        expected = Some(identity);
    }
    Ok(())
}

fn verify_source_signatures(
    record: &QualificationEvidenceLedgerRecord,
    registry: &QualificationEvidenceSourceTrustRegistry,
    now_unix_seconds: u64,
    require_current: bool,
) -> Result<(), QualificationEvidenceLedgerError> {
    for event in &record.events {
        let key = registry.find(
            event,
            &record.domain,
            record.started_at_unix_seconds,
            record.completed_at_unix_seconds,
            now_unix_seconds,
            require_current,
        )?;
        let public_key = decode_fixed::<32>(&key.public_key_base64url)?;
        let signature = decode_fixed::<64>(&event.source_signature_base64url)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidSourceSignature)?
            .verify_strict(
                &event_signature_preimage(event)?,
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| QualificationEvidenceLedgerError::InvalidSourceSignature)?;
    }
    Ok(())
}

fn event_signature_preimage(
    event: &QualificationEvidenceEvent,
) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
    let mut unsigned = event.clone();
    unsigned.source_signature_base64url.clear();
    let canonical = canonical(&unsigned)?;
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 2 + canonical.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    preimage.push(0);
    preimage.extend_from_slice(source_token(event.source).as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&canonical);
    Ok(preimage)
}

#[allow(clippy::too_many_lines)]
fn validate_phases(
    phases: &[QualificationEvidencePhaseCommitment],
    events: &[QualificationEvidenceEvent],
) -> Result<(), QualificationEvidenceLedgerError> {
    let mut next_sequence = 1_u32;
    let mut previous_key: Option<(&str, u8)> = None;
    for phase in phases {
        let key = (phase.scenario_id.as_str(), phase.phase_index);
        if !registered_token(&phase.scenario_id)
            || phase.phase_index == 0
            || phase.phase_index > 8
            || !semantic_profile(&phase.profile)
            || !digest(&phase.operation_plan_sha256)
            || !digest(&phase.scenario_program_sha256)
            || !phase.credential_requirement.valid()
            || !digest(&phase.common_phase_evidence_sha256)
            || phase.first_event_sequence != next_sequence
            || phase.last_event_sequence < phase.first_event_sequence
            || previous_key.is_some_and(|previous| previous >= key)
        {
            return Err(QualificationEvidenceLedgerError::InvalidPhase);
        }
        let first = usize::try_from(phase.first_event_sequence - 1)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidPhase)?;
        let last = usize::try_from(phase.last_event_sequence - 1)
            .map_err(|_| QualificationEvidenceLedgerError::InvalidPhase)?;
        let slice = events
            .get(first..=last)
            .ok_or(QualificationEvidenceLedgerError::InvalidPhase)?;
        if slice.iter().any(|event| {
            event.scenario_id != phase.scenario_id
                || event.phase_index != phase.phase_index
                || event.role != phase.role
                || event.profile != phase.profile
                || event.failpoint != phase.failpoint
        }) || slice
            .first()
            .is_none_or(|event| event.kind != QualificationEvidenceEventKind::ScenarioStarted)
            || slice
                .last()
                .is_none_or(|event| event.kind != QualificationEvidenceEventKind::ScenarioCompleted)
            || slice
                .iter()
                .filter(|event| event.kind == QualificationEvidenceEventKind::ScenarioStarted)
                .count()
                != 1
            || slice
                .iter()
                .filter(|event| event.kind == QualificationEvidenceEventKind::ScenarioCompleted)
                .count()
                != 1
        {
            return Err(QualificationEvidenceLedgerError::InvalidPhase);
        }
        let acknowledged = slice
            .iter()
            .filter(|event| event.kind == QualificationEvidenceEventKind::FailpointAcknowledged)
            .count();
        let killed = slice
            .iter()
            .enumerate()
            .filter(|(_, event)| event.kind == QualificationEvidenceEventKind::ProcessKilled)
            .collect::<Vec<_>>();
        let restarted = slice
            .iter()
            .enumerate()
            .filter(|(_, event)| event.kind == QualificationEvidenceEventKind::ProcessRestarted)
            .collect::<Vec<_>>();
        let acknowledgements = slice
            .iter()
            .enumerate()
            .filter(|(_, event)| {
                event.kind == QualificationEvidenceEventKind::FailpointAcknowledged
            })
            .collect::<Vec<_>>();
        if phase.failpoint.is_some()
            && (acknowledged != 1
                || killed.len() != 1
                || restarted.len() != 1
                || acknowledgements[0].0 >= killed[0].0
                || killed[0].0 >= restarted[0].0
                || acknowledgements[0].1.control_operation_id != killed[0].1.control_operation_id
                || killed[0].1.control_operation_id != restarted[0].1.control_operation_id
                || phase.failpoint == Some(QualificationFailpoint::BeforeDecision)
                    && (acknowledgements[0].1.operation_id.is_some()
                        || killed[0].1.operation_id.is_some()
                        || restarted[0].1.operation_id.is_some()
                        || slice.iter().any(|event| {
                            matches!(
                                event.kind,
                                QualificationEvidenceEventKind::DecisionDurable
                                    | QualificationEvidenceEventKind::CommandDurable
                                    | QualificationEvidenceEventKind::ProviderEntryDurable
                            )
                        }))
                || phase.failpoint != Some(QualificationFailpoint::BeforeDecision)
                    && (acknowledgements[0].1.operation_id.is_none()
                        || acknowledgements[0].1.operation_id != killed[0].1.operation_id
                        || killed[0].1.operation_id != restarted[0].1.operation_id))
            || phase.failpoint.is_none()
                && (acknowledged != 0 || !killed.is_empty() || !restarted.is_empty())
        {
            return Err(QualificationEvidenceLedgerError::InvalidPhase);
        }
        if let Some(failpoint) = phase.failpoint {
            let acknowledgement_index = acknowledgements[0].0;
            let kill_index = killed[0].0;
            let acknowledgement = acknowledgements[0].1;
            let (after, before) = failpoint_event_boundary(failpoint);
            let after_event = acknowledgement_index
                .checked_sub(1)
                .and_then(|index| slice.get(index))
                .ok_or(QualificationEvidenceLedgerError::InvalidPhase)?;
            let same_operation = failpoint == QualificationFailpoint::BeforeDecision
                && after_event.operation_id.is_none()
                || failpoint != QualificationFailpoint::BeforeDecision
                    && after_event.operation_id == acknowledgement.operation_id;
            if after_event.kind != after
                || !same_operation
                || slice[acknowledgement_index..kill_index]
                    .iter()
                    .any(|event| {
                        event.kind == before
                            && (failpoint == QualificationFailpoint::BeforeDecision
                                || event.operation_id == acknowledgement.operation_id)
                    })
            {
                return Err(QualificationEvidenceLedgerError::InvalidPhase);
            }
        }
        next_sequence = phase
            .last_event_sequence
            .checked_add(1)
            .ok_or(QualificationEvidenceLedgerError::InvalidPhase)?;
        previous_key = Some(key);
    }
    if next_sequence != u32::try_from(events.len() + 1).unwrap_or(u32::MAX) {
        return Err(QualificationEvidenceLedgerError::InvalidPhase);
    }
    Ok(())
}

const fn failpoint_event_boundary(
    failpoint: QualificationFailpoint,
) -> (
    QualificationEvidenceEventKind,
    QualificationEvidenceEventKind,
) {
    use QualificationEvidenceEventKind as Kind;
    match failpoint {
        QualificationFailpoint::BeforeDecision => (Kind::RequestReceived, Kind::DecisionDurable),
        QualificationFailpoint::AfterDecision => (Kind::DecisionDurable, Kind::ReservationDurable),
        QualificationFailpoint::AfterReservation => {
            (Kind::ReservationDurable, Kind::CommandDurable)
        }
        QualificationFailpoint::AfterCommand => (Kind::CommandDurable, Kind::ConnectionReread),
        QualificationFailpoint::AfterReread => {
            (Kind::ConnectionReread, Kind::CredentialLeaseAttempted)
        }
        QualificationFailpoint::AfterLease => {
            (Kind::CredentialLeaseSucceeded, Kind::ProviderEntryDurable)
        }
        QualificationFailpoint::AfterEntryMarker => {
            (Kind::ProviderEntryDurable, Kind::ProviderRequestWritten)
        }
        QualificationFailpoint::AfterRequestWrite => {
            (Kind::ProviderRequestWritten, Kind::ProviderResponseObserved)
        }
        QualificationFailpoint::AfterProviderResult => {
            (Kind::ProviderResultDurable, Kind::ObservationDurable)
        }
        QualificationFailpoint::AfterObservation => {
            (Kind::ObservationDurable, Kind::ExecutionReceiptDurable)
        }
        QualificationFailpoint::AfterExecutionReceipt => {
            (Kind::ExecutionReceiptDurable, Kind::TerminalDurable)
        }
        QualificationFailpoint::AfterTerminal => (Kind::TerminalDurable, Kind::ResponseProjected),
    }
}

fn source_owns(source: QualificationEvidenceSource, kind: QualificationEvidenceEventKind) -> bool {
    use QualificationEvidenceEventKind as Kind;
    use QualificationEvidenceSource as Source;
    matches!(
        (source, kind),
        (
            Source::Supervisor,
            Kind::ScenarioStarted
                | Kind::FailpointAcknowledged
                | Kind::ProcessKilled
                | Kind::ProcessRestarted
                | Kind::ScenarioCompleted
        ) | (
            Source::ClientProxy,
            Kind::RequestReceived | Kind::ResponseProjected | Kind::CancellationObserved
        ) | (
            Source::JournalReader,
            Kind::DecisionDurable
                | Kind::CommandDurable
                | Kind::ProviderEntryDurable
                | Kind::ProviderResultDurable
                | Kind::ObservationDurable
                | Kind::ExecutionReceiptDurable
                | Kind::RecoveryRequiredDurable
                | Kind::TerminalDurable
                | Kind::ReplayObserved
                | Kind::StatusObserved
                | Kind::RecoveryObserved
        ) | (
            Source::CredentialBroker,
            Kind::ConnectionReread
                | Kind::CredentialLeaseAttempted
                | Kind::CredentialLeaseSucceeded
                | Kind::CredentialLeaseClosed
        ) | (
            Source::ProfileStateReader,
            Kind::ReservationDurable
                | Kind::ReservationReleased
                | Kind::ReservationConsumed
                | Kind::ReservationRetained
        ) | (
            Source::ProviderProxy,
            Kind::ProviderRequestWritten
                | Kind::ProviderResponseObserved
                | Kind::ProviderReconciliationRequested
                | Kind::ProviderReconciliationObserved
        ) | (Source::ReceiptVerifier, Kind::NativeReceiptVerified)
            | (Source::ProviderObserver, Kind::ProviderTruthObserved)
    )
}

#[allow(clippy::too_many_lines)]
fn payload_valid(payload: &QualificationEvidenceEventPayload) -> bool {
    use QualificationEvidenceEventPayload as Payload;
    let optional_digest = |value: &Option<String>| value.as_deref().is_none_or(digest);
    match payload {
        Payload::Control { context_sha256 }
        | Payload::Reservation {
            reservation_sha256: context_sha256,
        }
        | Payload::Command {
            sealed_command_sha256: context_sha256,
        }
        | Payload::ProviderEntry {
            sealed_command_sha256: context_sha256,
        }
        | Payload::ProviderResponse {
            response_sha256: context_sha256,
        }
        | Payload::ProviderResult {
            provider_result_sha256: context_sha256,
        } => digest(context_sha256),
        Payload::ProviderRequest {
            request_sha256,
            credential_lease_sha256,
        } => digest(request_sha256) && digest(credential_lease_sha256),
        Payload::ClientResult {
            result_sha256,
            journal_projection_kinds,
            outcome,
            completion,
            recovery_id,
            error_code,
            issue_metadata_sha256,
            receipt_ids,
        } => {
            let terminal_success = matches!(
                outcome,
                QualificationOutcomeKind::Completed
                    | QualificationOutcomeKind::Partial
                    | QualificationOutcomeKind::NotApplied
            );
            let carries_issue = *outcome != QualificationOutcomeKind::Completed;
            let carries_recovery = matches!(
                outcome,
                QualificationOutcomeKind::RecoveryRequired | QualificationOutcomeKind::Conflict
            );
            digest(result_sha256)
                && journal_projection_kinds.len() <= 64
                && journal_projection_kinds.iter().all(|kind| {
                    matches!(
                        kind,
                        QualificationEvidenceEventKind::ReplayObserved
                            | QualificationEvidenceEventKind::StatusObserved
                            | QualificationEvidenceEventKind::RecoveryObserved
                    )
                })
                && terminal_success == completion.is_some()
                && carries_recovery == recovery_id.is_some()
                && recovery_id.as_deref().is_none_or(registered_token)
                && carries_issue == error_code.is_some()
                && error_code.as_deref().is_none_or(registered_token)
                && carries_issue == issue_metadata_sha256.is_some()
                && issue_metadata_sha256.as_deref().is_none_or(digest)
                && receipt_ids.len() <= 16
                && receipt_ids.iter().all(|value| receipt_id(value))
                && receipt_ids.iter().collect::<BTreeSet<_>>().len() == receipt_ids.len()
        }
        Payload::JournalProjection {
            projection_sha256,
            state,
            effect,
            terminal,
            completion,
        } => {
            digest(projection_sha256)
                && match state {
                    QualificationJournalState::Ready => {
                        *effect == QualificationEffect::NotApplied
                            && !terminal
                            && completion.is_none()
                    }
                    QualificationJournalState::Executing => {
                        matches!(
                            effect,
                            QualificationEffect::NotApplied | QualificationEffect::Possible
                        ) && !terminal
                            && completion.is_none()
                    }
                    QualificationJournalState::RecoveryRequired => {
                        *effect == QualificationEffect::Possible
                            && !terminal
                            && completion.is_none()
                    }
                    QualificationJournalState::Denied | QualificationJournalState::Unavailable => {
                        *effect == QualificationEffect::NotApplied
                            && *terminal
                            && completion.is_none()
                    }
                    QualificationJournalState::Completed | QualificationJournalState::Partial => {
                        *effect == QualificationEffect::Applied && *terminal && completion.is_some()
                    }
                    QualificationJournalState::NotApplied => {
                        *effect == QualificationEffect::NotApplied
                            && *terminal
                            && completion.is_some()
                    }
                }
        }
        Payload::FailpointAcknowledgement {
            action_context_sha256,
            controller_nonce_sha256,
            agent_start_time_ticks,
            agent_executable_sha256,
            agent_configuration_sha256,
            agent_state_directory_sha256,
            agent_cgroup_sha256,
            boundary_event_sha256,
        } => {
            digest(action_context_sha256)
                && digest(controller_nonce_sha256)
                && *agent_start_time_ticks != 0
                && digest(agent_executable_sha256)
                && digest(agent_configuration_sha256)
                && digest(agent_state_directory_sha256)
                && digest(agent_cgroup_sha256)
                && digest(boundary_event_sha256)
        }
        Payload::ProcessKill {
            action_context_sha256,
            controller_nonce_sha256,
            agent_start_time_ticks,
            agent_executable_sha256,
            agent_configuration_sha256,
            agent_state_directory_sha256,
            agent_cgroup_sha256,
            acknowledgement_event_sha256,
            signal,
            cgroup_empty_after_kill,
        } => {
            digest(action_context_sha256)
                && digest(controller_nonce_sha256)
                && *agent_start_time_ticks != 0
                && digest(agent_executable_sha256)
                && digest(agent_configuration_sha256)
                && digest(agent_state_directory_sha256)
                && digest(agent_cgroup_sha256)
                && digest(acknowledgement_event_sha256)
                && signal == "SIGKILL"
                && *cgroup_empty_after_kill
        }
        Payload::ProcessRestart {
            action_context_sha256,
            controller_nonce_sha256,
            prior_agent_generation,
            prior_agent_process_id,
            prior_agent_start_time_ticks,
            restarted_agent_start_time_ticks,
            agent_executable_sha256,
            agent_configuration_sha256,
            agent_state_directory_sha256,
            restarted_agent_cgroup_sha256,
            kill_event_sha256,
            control_plane_ready,
        } => {
            digest(action_context_sha256)
                && digest(controller_nonce_sha256)
                && *prior_agent_generation != 0
                && *prior_agent_process_id != 0
                && *prior_agent_start_time_ticks != 0
                && *restarted_agent_start_time_ticks != 0
                && prior_agent_start_time_ticks != restarted_agent_start_time_ticks
                && digest(agent_executable_sha256)
                && digest(agent_configuration_sha256)
                && digest(agent_state_directory_sha256)
                && digest(restarted_agent_cgroup_sha256)
                && digest(kill_event_sha256)
                && *control_plane_ready
        }
        Payload::Request {
            request_input_sha256,
            principal_sha256,
            idempotency_sha256,
            preparation_input_sha256,
        } => {
            digest(request_input_sha256)
                && digest(principal_sha256)
                && optional_digest(idempotency_sha256)
                && optional_digest(preparation_input_sha256)
        }
        Payload::Decision {
            canonical_input_sha256,
            idempotency_sha256,
            canonical_action_sha256,
            receipt_action_sha256,
            receipt_context_sha256,
            authority_sha256,
            configuration_sha256,
            runtime_contract_sha256,
            preparation_sha256,
            decision_receipt_id,
            decision_receipt_bytes_sha256,
            decoded_claims_sha256,
            supervisor_context_sha256,
            recovery_key_id,
            recovery_public_key_base64url,
            receipt_trust_anchor_sha256,
            ..
        } => {
            digest(canonical_input_sha256)
                && optional_digest(idempotency_sha256)
                && digest(canonical_action_sha256)
                && digest(receipt_action_sha256)
                && digest(receipt_context_sha256)
                && digest(authority_sha256)
                && digest(configuration_sha256)
                && digest(runtime_contract_sha256)
                && digest(preparation_sha256)
                && receipt_id(decision_receipt_id)
                && digest(decision_receipt_bytes_sha256)
                && digest(decoded_claims_sha256)
                && digest(supervisor_context_sha256)
                && registered_token(recovery_key_id)
                && decode_fixed::<32>(recovery_public_key_base64url)
                    .is_ok_and(|key| key != [0; 32] && VerifyingKey::from_bytes(&key).is_ok())
                && digest(receipt_trust_anchor_sha256)
        }
        Payload::Connection {
            connection_id_sha256,
            connection_alias_sha256,
            descriptor_sha256,
            account_sha256,
        } => {
            optional_digest(connection_id_sha256)
                && optional_digest(connection_alias_sha256)
                && optional_digest(descriptor_sha256)
                && optional_digest(account_sha256)
                && [
                    connection_id_sha256.is_some(),
                    connection_alias_sha256.is_some(),
                    descriptor_sha256.is_some(),
                    account_sha256.is_some(),
                ]
                .into_iter()
                .all(|present| present == connection_id_sha256.is_some())
        }
        Payload::Credential {
            lease_sha256,
            requested_scope_sha256,
            effective_scope_sha256,
        } => {
            digest(lease_sha256) && digest(requested_scope_sha256) && digest(effective_scope_sha256)
        }
        Payload::Observation { observation_sha256 } => digest(observation_sha256),
        Payload::ExecutionReceipt {
            execution_receipt_id,
            receipt_bytes_sha256,
            decoded_claims_sha256,
            execution_result_sha256,
            ..
        } => {
            receipt_id(execution_receipt_id)
                && digest(receipt_bytes_sha256)
                && digest(decoded_claims_sha256)
                && optional_digest(execution_result_sha256)
        }
        Payload::Terminal {
            state,
            execution_result_sha256,
            ..
        } => {
            matches!(
                state,
                QualificationOutcomeKind::Denied
                    | QualificationOutcomeKind::Unavailable
                    | QualificationOutcomeKind::Completed
                    | QualificationOutcomeKind::Partial
                    | QualificationOutcomeKind::NotApplied
            ) && optional_digest(execution_result_sha256)
        }
        Payload::ReceiptVerification {
            receipt_bytes_sha256,
            decoded_claims_sha256,
            profile_inspection_sha256,
        } => {
            digest(receipt_bytes_sha256)
                && digest(decoded_claims_sha256)
                && digest(profile_inspection_sha256)
        }
        Payload::ProviderTruth {
            provider_truth_sha256,
            ..
        } => digest(provider_truth_sha256),
    }
}

fn payload_matches_kind(
    kind: QualificationEvidenceEventKind,
    payload: &QualificationEvidenceEventPayload,
) -> bool {
    use QualificationEvidenceEventKind as Kind;
    use QualificationEvidenceEventPayload as Payload;
    matches!(
        (kind, payload),
        (
            Kind::ScenarioStarted | Kind::ScenarioCompleted,
            Payload::Control { .. }
        ) | (
            Kind::FailpointAcknowledged,
            Payload::FailpointAcknowledgement { .. }
        ) | (Kind::ProcessKilled, Payload::ProcessKill { .. })
            | (Kind::ProcessRestarted, Payload::ProcessRestart { .. })
            | (Kind::RequestReceived, Payload::Request { .. })
            | (Kind::DecisionDurable, Payload::Decision { .. })
            | (
                Kind::ReservationDurable
                    | Kind::ReservationReleased
                    | Kind::ReservationConsumed
                    | Kind::ReservationRetained,
                Payload::Reservation { .. }
            )
            | (Kind::CommandDurable, Payload::Command { .. })
            | (Kind::ConnectionReread, Payload::Connection { .. })
            | (
                Kind::CredentialLeaseAttempted
                    | Kind::CredentialLeaseSucceeded
                    | Kind::CredentialLeaseClosed,
                Payload::Credential { .. }
            )
            | (Kind::ProviderEntryDurable, Payload::ProviderEntry { .. })
            | (
                Kind::ProviderRequestWritten | Kind::ProviderReconciliationRequested,
                Payload::ProviderRequest { .. }
            )
            | (
                Kind::ProviderResponseObserved | Kind::ProviderReconciliationObserved,
                Payload::ProviderResponse { .. }
            )
            | (Kind::ProviderResultDurable, Payload::ProviderResult { .. })
            | (Kind::ObservationDurable, Payload::Observation { .. })
            | (
                Kind::ExecutionReceiptDurable,
                Payload::ExecutionReceipt { .. }
            )
            | (Kind::TerminalDurable, Payload::Terminal { .. })
            | (
                Kind::NativeReceiptVerified,
                Payload::ReceiptVerification { .. }
            )
            | (
                Kind::ResponseProjected | Kind::CancellationObserved,
                Payload::ClientResult { .. }
            )
            | (
                Kind::RecoveryRequiredDurable
                    | Kind::ReplayObserved
                    | Kind::StatusObserved
                    | Kind::RecoveryObserved,
                Payload::JournalProjection { .. }
            )
            | (Kind::ProviderTruthObserved, Payload::ProviderTruth { .. })
    )
}

const fn source_token(source: QualificationEvidenceSource) -> &'static str {
    match source {
        QualificationEvidenceSource::Supervisor => "supervisor",
        QualificationEvidenceSource::ClientProxy => "client-proxy",
        QualificationEvidenceSource::JournalReader => "journal-reader",
        QualificationEvidenceSource::CredentialBroker => "credential-broker",
        QualificationEvidenceSource::ProfileStateReader => "profile-state-reader",
        QualificationEvidenceSource::ProviderProxy => "provider-proxy",
        QualificationEvidenceSource::ReceiptVerifier => "receipt-verifier",
        QualificationEvidenceSource::ProviderObserver => "provider-observer",
    }
}

fn event_fields_match_kind(event: &QualificationEvidenceEvent) -> bool {
    use QualificationEvidenceEventKind as Kind;
    let operation_required = !matches!(
        event.kind,
        Kind::ScenarioStarted
            | Kind::RequestReceived
            | Kind::ResponseProjected
            | Kind::CancellationObserved
            | Kind::FailpointAcknowledged
            | Kind::ProcessKilled
            | Kind::ProcessRestarted
            | Kind::ScenarioCompleted
    );
    let request_required = matches!(
        event.kind,
        Kind::RequestReceived
            | Kind::ResponseProjected
            | Kind::ReplayObserved
            | Kind::StatusObserved
            | Kind::RecoveryObserved
            | Kind::CancellationObserved
    );
    let journal_revision_required =
        matches!(event.source, QualificationEvidenceSource::JournalReader);
    let agent_identity_required = journal_revision_required
        || matches!(
            event.kind,
            Kind::FailpointAcknowledged | Kind::ProcessKilled | Kind::ProcessRestarted
        );
    let agent_identity_present = event.agent_generation.is_some()
        && event.agent_process_id.is_some()
        && event.agent_boot_sha256.is_some();
    let client_result_required = matches!(
        event.kind,
        Kind::ResponseProjected | Kind::CancellationObserved
    );
    let client_result_has_no_journal_identity = !client_result_required
        || (event.operation_id.is_none() && event.connection_generation.is_none());
    let receipt_id_required = event.kind == Kind::NativeReceiptVerified;
    let control_operation_required = matches!(
        event.kind,
        Kind::FailpointAcknowledged | Kind::ProcessKilled | Kind::ProcessRestarted
    );
    (!operation_required || event.operation_id.is_some())
        && (!request_required || event.request_id.is_some())
        && (journal_revision_required == event.journal_revision.is_some())
        && (agent_identity_required == agent_identity_present)
        && (event.operation_id.is_some() == event.connection_generation.is_some())
        && client_result_has_no_journal_identity
        && (client_result_required == event.client_result_sha256.is_some())
        && (!client_result_required
            || matches!(
                &event.payload,
                QualificationEvidenceEventPayload::ClientResult { result_sha256, .. }
                    if event.client_result_sha256.as_deref() == Some(result_sha256.as_str())
            ))
        && (receipt_id_required == event.receipt_id.is_some())
        && (control_operation_required == event.control_operation_id.is_some())
        && (!matches!(event.kind, Kind::ProcessKilled | Kind::ProcessRestarted)
            || agent_identity_present)
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, QualificationEvidenceLedgerError> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], QualificationEvidenceLedgerError> {
    let bytes = Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)?;
    bytes
        .try_into()
        .map_err(|_| QualificationEvidenceLedgerError::InvalidEncoding)
}

fn digest(value: &str) -> bool {
    lower_hex(value, 64)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn decimal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn lower_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn registered_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn semantic_profile(value: &str) -> bool {
    value.rsplit_once('/').is_some_and(|(id, version)| {
        registered_token(id)
            && !version.is_empty()
            && version.len() <= 5
            && version.as_bytes()[0].is_ascii_digit()
            && version.as_bytes()[0] != b'0'
            && version.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn receipt_id(value: &str) -> bool {
    value.len() == 48
        && value.starts_with("rcpt_")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn workflow_path(value: &str) -> bool {
    const PREFIX: &str = ".github/workflows/profile-qualification-";
    const SUFFIX: &str = ".yml";
    value.len() <= 256
        && value
            .strip_prefix(PREFIX)
            .and_then(|tail| tail.strip_suffix(SUFFIX))
            .is_some_and(|domain| {
                !domain.is_empty()
                    && domain.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
}

/// Protected event-ledger failures. Every failure blocks qualification.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum QualificationEvidenceLedgerError {
    #[error("qualification evidence ledger encoding is invalid")]
    InvalidEncoding,
    #[error("qualification evidence ledger record is invalid")]
    InvalidRecord,
    #[error("qualification evidence ledger event is invalid")]
    InvalidEvent,
    #[error("qualification evidence ledger phase coverage is invalid")]
    InvalidPhase,
    #[error("qualification evidence source trust registry is invalid")]
    InvalidSourceTrust,
    #[error("qualification evidence source signature is invalid")]
    InvalidSourceSignature,
    #[error("qualification evidence ledger signature is invalid")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 2_000_000_000;

    fn credential_requirement() -> QualificationCredentialRequirementV1 {
        QualificationCredentialRequirementV1 {
            workload_id_sha256: "8".repeat(64),
            provider_kind: "stripe".into(),
            contract: "auths.stripe.connection/1".into(),
            descriptor_schema: "auths.stripe.connection-descriptor/1".into(),
            credential_scope: "stripe.refunds.write/1".into(),
        }
    }

    #[test]
    fn journal_projection_payload_uses_the_lifecycle_truth_table() {
        let digest = "a".repeat(64);
        assert!(payload_valid(
            &QualificationEvidenceEventPayload::JournalProjection {
                projection_sha256: digest.clone(),
                state: QualificationJournalState::Executing,
                effect: QualificationEffect::NotApplied,
                terminal: false,
                completion: None,
            }
        ));
        assert!(payload_valid(
            &QualificationEvidenceEventPayload::JournalProjection {
                projection_sha256: digest.clone(),
                state: QualificationJournalState::Partial,
                effect: QualificationEffect::Applied,
                terminal: true,
                completion: Some(QualificationCompletion::Fresh),
            }
        ));
        assert!(!payload_valid(
            &QualificationEvidenceEventPayload::JournalProjection {
                projection_sha256: digest,
                state: QualificationJournalState::Partial,
                effect: QualificationEffect::Possible,
                terminal: true,
                completion: Some(QualificationCompletion::Fresh),
            }
        ));
    }

    #[test]
    fn state_directory_commitment_binds_one_normalized_inode() {
        let expected = qualification_state_directory_commitment(
            "/var/lib/auths/qualification-state",
            41,
            73,
            1_001,
            0o700,
        )
        .unwrap();
        assert_eq!(
            qualification_state_directory_commitment(
                "/var/lib/auths/qualification-state",
                41,
                73,
                1_001,
                0o700,
            )
            .unwrap(),
            expected
        );
        assert_ne!(
            qualification_state_directory_commitment(
                "/var/lib/auths/qualification-state",
                41,
                74,
                1_001,
                0o700,
            )
            .unwrap(),
            expected
        );
        assert_ne!(
            qualification_state_directory_commitment(
                "/var/lib/auths/other-state",
                41,
                73,
                1_001,
                0o700,
            )
            .unwrap(),
            expected
        );
        for invalid in [
            "/",
            "/var/lib/auths/qualification-state/",
            "/var//lib/auths/qualification-state",
            "/var/lib/../qualification-state",
        ] {
            assert!(
                qualification_state_directory_commitment(invalid, 41, 73, 1_001, 0o700).is_err()
            );
        }
        assert!(
            qualification_state_directory_commitment(
                "/var/lib/auths/qualification-state",
                41,
                73,
                1_001,
                0o750,
            )
            .is_err()
        );
    }

    fn source_seed(source: QualificationEvidenceSource) -> [u8; 32] {
        let byte = match source {
            QualificationEvidenceSource::Supervisor => 1,
            QualificationEvidenceSource::ClientProxy => 2,
            QualificationEvidenceSource::JournalReader => 3,
            QualificationEvidenceSource::CredentialBroker => 4,
            QualificationEvidenceSource::ProfileStateReader => 5,
            QualificationEvidenceSource::ProviderProxy => 6,
            QualificationEvidenceSource::ReceiptVerifier => 7,
            QualificationEvidenceSource::ProviderObserver => 8,
        };
        [byte; 32]
    }

    fn registry() -> QualificationEvidenceSourceTrustRegistry {
        let sources = [
            QualificationEvidenceSource::Supervisor,
            QualificationEvidenceSource::ClientProxy,
            QualificationEvidenceSource::JournalReader,
            QualificationEvidenceSource::CredentialBroker,
            QualificationEvidenceSource::ProfileStateReader,
            QualificationEvidenceSource::ProviderProxy,
            QualificationEvidenceSource::ReceiptVerifier,
            QualificationEvidenceSource::ProviderObserver,
        ];
        let mut keys = sources
            .into_iter()
            .enumerate()
            .map(|(index, source)| {
                let seed = source_seed(source);
                let fixed_reader = matches!(
                    source,
                    QualificationEvidenceSource::ClientProxy
                        | QualificationEvidenceSource::CredentialBroker
                        | QualificationEvidenceSource::ProfileStateReader
                        | QualificationEvidenceSource::ProviderProxy
                        | QualificationEvidenceSource::ReceiptVerifier
                        | QualificationEvidenceSource::ProviderObserver
                );
                let source_uid = match source {
                    QualificationEvidenceSource::Supervisor => 1_001,
                    QualificationEvidenceSource::JournalReader => 1_002,
                    _ => 1_100 + u32::try_from(index * 2).unwrap(),
                };
                QualificationEvidenceSourceTrustKey {
                    source,
                    key_id: format!("{}-test", source_token(source)),
                    algorithm: "Ed25519".into(),
                    public_key_base64url: Base64UrlUnpadded::encode_string(
                        SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
                    ),
                    source_identity: format!("{}-process", source_token(source)),
                    source_artifact_sha256: hex::encode(Sha256::digest(source_token(source))),
                    source_uid: Some(source_uid),
                    reader_identity: fixed_reader
                        .then(|| format!("{}-reader", source_token(source))),
                    reader_artifact_sha256: fixed_reader.then(|| {
                        hex::encode(Sha256::digest(format!("{}-reader", source_token(source))))
                    }),
                    reader_uid: fixed_reader.then_some(source_uid + 1),
                    allowed_domains: vec!["stripe".into()],
                    not_before_unix_seconds: NOW - 100,
                    not_after_unix_seconds: NOW + 100,
                }
            })
            .collect::<Vec<_>>();
        keys.sort_by(|left, right| {
            (source_token(left.source), left.key_id.as_str())
                .cmp(&(source_token(right.source), right.key_id.as_str()))
        });
        QualificationEvidenceSourceTrustRegistry {
            schema: "auths.profile-qualification-evidence-source-trust/1".into(),
            keys,
        }
    }

    #[test]
    fn source_key_rotation_requires_one_unique_current_key() {
        let empty = QualificationEvidenceSourceTrustRegistry {
            schema: "auths.profile-qualification-evidence-source-trust/1".into(),
            keys: Vec::new(),
        };
        assert_eq!(
            QualificationEvidenceSourceTrustRegistry::from_json(&canonical(&empty).unwrap()),
            Err(QualificationEvidenceLedgerError::InvalidSourceTrust)
        );

        let mut trust = registry();
        assert!(trust.uses_process_uid(1_001));
        assert!(trust.uses_process_uid(1_103));
        assert!(!trust.uses_process_uid(9_999));
        let client = trust
            .keys
            .iter()
            .find(|key| key.source == QualificationEvidenceSource::ClientProxy)
            .unwrap()
            .clone();
        let selected = trust
            .current_source_process_binding(
                QualificationEvidenceSource::ClientProxy,
                "stripe",
                NOW - 10,
                NOW + 10,
                NOW,
            )
            .unwrap();
        assert_eq!(selected.0, client.key_id);
        let journal = trust
            .keys
            .iter()
            .find(|key| key.source == QualificationEvidenceSource::JournalReader)
            .unwrap();
        assert_eq!(
            trust
                .source_for_append_process(
                    journal.source_uid.unwrap(),
                    &journal.source_artifact_sha256,
                    "stripe",
                    NOW - 10,
                    NOW + 10,
                    NOW,
                )
                .unwrap(),
            QualificationEvidenceSource::JournalReader
        );
        let supervisor = trust
            .keys
            .iter()
            .find(|key| key.source == QualificationEvidenceSource::Supervisor)
            .unwrap();
        assert_eq!(
            trust
                .source_for_append_process(
                    supervisor.source_uid.unwrap(),
                    &supervisor.source_artifact_sha256,
                    "stripe",
                    NOW - 10,
                    NOW + 10,
                    NOW,
                )
                .unwrap(),
            QualificationEvidenceSource::Supervisor
        );

        let mut overlapping = client.clone();
        overlapping.key_id = "client-proxy-overlap".into();
        overlapping.public_key_base64url = Base64UrlUnpadded::encode_string(
            SigningKey::from_bytes(&[42; 32]).verifying_key().as_bytes(),
        );
        trust.keys.push(overlapping);
        trust.keys.sort_by(|left, right| {
            (source_token(left.source), left.key_id.as_str())
                .cmp(&(source_token(right.source), right.key_id.as_str()))
        });
        assert!(
            trust
                .current_source_process_binding(
                    QualificationEvidenceSource::ClientProxy,
                    "stripe",
                    NOW - 10,
                    NOW + 10,
                    NOW,
                )
                .is_err()
        );

        let overlap = trust
            .keys
            .iter_mut()
            .find(|key| key.key_id == "client-proxy-overlap")
            .unwrap();
        overlap.not_before_unix_seconds = NOW + 11;
        overlap.not_after_unix_seconds = NOW + 100;
        assert_eq!(
            trust
                .current_source_process_binding(
                    QualificationEvidenceSource::ClientProxy,
                    "stripe",
                    NOW - 10,
                    NOW + 10,
                    NOW,
                )
                .unwrap()
                .0,
            client.key_id
        );
    }

    #[test]
    fn current_source_seed_is_exactly_role_and_interval_bound() {
        let trust = registry();
        let client_seed = Base64UrlUnpadded::encode_string(&source_seed(
            QualificationEvidenceSource::ClientProxy,
        ));
        assert_eq!(
            trust.verifies_current_source_seed(
                QualificationEvidenceSource::ClientProxy,
                "stripe",
                NOW - 10,
                NOW + 10,
                NOW,
                &client_seed,
            ),
            Ok(())
        );
        assert_eq!(
            trust.verifies_current_source_seed(
                QualificationEvidenceSource::CredentialBroker,
                "stripe",
                NOW - 10,
                NOW + 10,
                NOW,
                &client_seed,
            ),
            Err(QualificationEvidenceLedgerError::InvalidSignature)
        );
        assert!(
            trust
                .verifies_current_source_seed(
                    QualificationEvidenceSource::ClientProxy,
                    "stripe",
                    NOW - 10,
                    NOW + 10,
                    NOW + 101,
                    &client_seed,
                )
                .is_err()
        );
        assert!(
            trust
                .verifies_current_source_seed(
                    QualificationEvidenceSource::ClientProxy,
                    "stripe",
                    NOW - 10,
                    NOW + 10,
                    NOW,
                    "not-base64url",
                )
                .is_err()
        );
    }

    fn ledger_registry(public_key_base64url: String) -> QualificationEvidenceLedgerTrustRegistry {
        QualificationEvidenceLedgerTrustRegistry {
            schema: "auths.profile-qualification-evidence-ledger-trust/1".into(),
            keys: vec![QualificationEvidenceLedgerTrustKey {
                key_id: "ledger-test".into(),
                algorithm: "Ed25519".into(),
                public_key_base64url,
                allowed_domains: vec!["stripe".into()],
                not_before_unix_seconds: NOW - 100,
                not_after_unix_seconds: NOW + 100,
            }],
        }
    }

    fn signed_event(
        sequence: u32,
        previous: String,
        kind: QualificationEvidenceEventKind,
        source_context_sha256: &str,
    ) -> QualificationEvidenceEvent {
        let source = QualificationEvidenceSource::Supervisor;
        let mut event = QualificationEvidenceEvent {
            sequence,
            previous_event_sha256: previous,
            scenario_id: "happy-path".into(),
            phase_index: 1,
            role: QualificationOperationRole::Effect,
            profile: "auths.stripe.refund/1".into(),
            failpoint: None,
            source,
            source_identity: "supervisor-process".into(),
            source_artifact_sha256: hex::encode(Sha256::digest("supervisor")),
            source_uid: Some(1_001),
            reader_identity: None,
            reader_artifact_sha256: None,
            reader_uid: None,
            source_context_sha256: source_context_sha256.into(),
            source_key_id: "supervisor-test".into(),
            source_signature_base64url: String::new(),
            supervisor_generation: 1,
            agent_generation: None,
            agent_process_id: None,
            agent_boot_sha256: None,
            operation_id: None,
            control_operation_id: None,
            request_id: None,
            client_result_sha256: None,
            receipt_id: None,
            connection_generation: None,
            journal_revision: None,
            kind,
            payload: QualificationEvidenceEventPayload::Control {
                context_sha256: hex::encode(Sha256::digest(format!("payload-{sequence}"))),
            },
            durable_ack_sha256: qualification_event_marker_sha256(sequence, source),
        };
        sign_test_event(&mut event);
        event
    }

    fn sign_test_event(event: &mut QualificationEvidenceEvent) {
        event.durable_ack_sha256 = qualification_event_marker_sha256(event.sequence, event.source);
        event.source_signature_base64url.clear();
        let signature = SigningKey::from_bytes(&source_seed(event.source))
            .sign(&event_signature_preimage(&event).unwrap())
            .to_bytes();
        event.source_signature_base64url = Base64UrlUnpadded::encode_string(&signature);
    }

    fn record() -> QualificationEvidenceLedgerRecord {
        let mut record = QualificationEvidenceLedgerRecord {
            schema: "auths.profile-qualification-evidence-ledger-record/1".into(),
            repository_id: "123".into(),
            workflow_path: ".github/workflows/profile-qualification-stripe.yml".into(),
            workflow_revision: "1".repeat(40),
            candidate_revision: "2".repeat(40),
            attester_revision: "3".repeat(40),
            run_id: "456".into(),
            run_attempt: 1,
            domain: "stripe".into(),
            target: QualificationTarget::LinuxX86_64,
            protected_environment: "qualification-stripe".into(),
            provider_run_id: "stripe-live".into(),
            ledger_id: "ledger-test".into(),
            session_nonce_sha256: "4".repeat(64),
            supervisor_controller_uid: 1000,
            supervisor_controller_artifact_sha256: "5".repeat(64),
            ledger_appender_artifact_sha256: "7".repeat(64),
            agent_uid: 1001,
            agent_gid: 1001,
            agent_executable_sha256: "6".repeat(64),
            recovery_key_id: "recovery".into(),
            recovery_public_key_base64url: Base64UrlUnpadded::encode_string(&[9; 32]),
            phase_commitments: vec![QualificationEvidencePhaseCommitment {
                scenario_id: "happy-path".into(),
                phase_index: 1,
                role: QualificationOperationRole::Effect,
                profile: "auths.stripe.refund/1".into(),
                failpoint: None,
                operation_plan_sha256: "5".repeat(64),
                scenario_program_sha256: "7".repeat(64),
                credential_requirement: credential_requirement(),
                common_phase_evidence_sha256: "6".repeat(64),
                first_event_sequence: 1,
                last_event_sequence: 2,
            }],
            events: Vec::new(),
            started_at_unix_seconds: NOW - 10,
            deadline_at_unix_seconds: NOW + 10,
            completed_at_unix_seconds: NOW - 1,
        };
        let context = record.source_context_sha256().unwrap();
        let first = signed_event(
            1,
            ZERO_DIGEST.into(),
            QualificationEvidenceEventKind::ScenarioStarted,
            &context,
        );
        let previous = hex::encode(Sha256::digest(canonical(&first).unwrap()));
        let second = signed_event(
            2,
            previous,
            QualificationEvidenceEventKind::ScenarioCompleted,
            &context,
        );
        record.events = vec![first, second];
        record
    }

    #[test]
    fn zero_instance_negative_phase_matches_authenticated_attempts() {
        let mut ledger = record();
        ledger.phase_commitments[0].last_event_sequence = 4;
        ledger.events.clear();
        let source_context = ledger.source_context_sha256().unwrap();
        let first = signed_event(
            1,
            ZERO_DIGEST.into(),
            QualificationEvidenceEventKind::ScenarioStarted,
            &source_context,
        );
        let attempt = crate::QualificationRedactedAttempt {
            sequence: 1,
            kind: crate::QualificationAttemptKind::Execute,
            request_id: "request-1".into(),
            operation_id: None,
            recovery_id: None,
            outcome: crate::QualificationOutcomeKind::Denied,
            completion: None,
            idempotency_sha256: Some("7".repeat(64)),
            request_input_sha256: "8".repeat(64),
            preparation_input_sha256: Some("9".repeat(64)),
            principal_sha256: "a".repeat(64),
            connection_alias_sha256: None,
            connection_generation: None,
            requested_scope_sha256: None,
            configuration_sha256: None,
            sealed_command_sha256: None,
            error_code: Some("auths.test.denied".into()),
            issue_metadata_sha256: Some("c".repeat(64)),
            result_sha256: "d".repeat(64),
            receipt_ids: Vec::new(),
        };
        assert!(attempt.validate().is_ok());
        let mut request = signed_event(
            2,
            hex::encode(Sha256::digest(canonical(&first).unwrap())),
            QualificationEvidenceEventKind::ScenarioStarted,
            &source_context,
        );
        request.source = QualificationEvidenceSource::ClientProxy;
        request.source_identity = "client-proxy-process".into();
        request.source_artifact_sha256 = hex::encode(Sha256::digest("client-proxy"));
        request.source_uid = Some(1_102);
        request.reader_identity = Some("client-proxy-reader".into());
        request.reader_artifact_sha256 = Some(hex::encode(Sha256::digest("client-proxy-reader")));
        request.reader_uid = Some(1_103);
        request.source_key_id = "client-proxy-test".into();
        request.request_id = Some(attempt.request_id.clone());
        request.kind = QualificationEvidenceEventKind::RequestReceived;
        request.payload = QualificationEvidenceEventPayload::Request {
            request_input_sha256: attempt.request_input_sha256.clone(),
            principal_sha256: attempt.principal_sha256.clone(),
            idempotency_sha256: attempt.idempotency_sha256.clone(),
            preparation_input_sha256: attempt.preparation_input_sha256.clone(),
        };
        sign_test_event(&mut request);
        let mut response = request.clone();
        response.sequence = 3;
        response.previous_event_sha256 = hex::encode(Sha256::digest(canonical(&request).unwrap()));
        response.kind = QualificationEvidenceEventKind::ResponseProjected;
        response.client_result_sha256 = Some(attempt.result_sha256.clone());
        response.payload = QualificationEvidenceEventPayload::ClientResult {
            result_sha256: attempt.result_sha256.clone(),
            journal_projection_kinds: Vec::new(),
            outcome: attempt.outcome,
            completion: attempt.completion,
            recovery_id: attempt.recovery_id.clone(),
            error_code: attempt.error_code.clone(),
            issue_metadata_sha256: attempt.issue_metadata_sha256.clone(),
            receipt_ids: attempt.receipt_ids.clone(),
        };
        sign_test_event(&mut response);
        let last = signed_event(
            4,
            hex::encode(Sha256::digest(canonical(&response).unwrap())),
            QualificationEvidenceEventKind::ScenarioCompleted,
            &source_context,
        );
        ledger.events = vec![first, request, response, last];
        assert!(ledger.validate().is_ok());
        let phase = crate::QualificationCommonPhaseEvidence {
            schema: "auths.profile-qualification-common-phase-evidence/1".into(),
            repository_id: ledger.repository_id.clone(),
            workflow_run_id: ledger.run_id.clone(),
            workflow_run_attempt: ledger.run_attempt,
            candidate_revision: ledger.candidate_revision.clone(),
            domain: ledger.domain.clone(),
            target: ledger.target,
            protected_environment: ledger.protected_environment.clone(),
            provider_run_id: ledger.provider_run_id.clone(),
            scenario_id: "happy-path".into(),
            phase_index: 1,
            role: QualificationOperationRole::Effect,
            profile: "auths.stripe.refund/1".into(),
            failpoint: None,
            operation_plan_sha256: "5".repeat(64),
            scenario_program_sha256: "7".repeat(64),
            ledger_id: ledger.ledger_id.clone(),
            session_nonce_sha256: ledger.session_nonce_sha256.clone(),
            supervisor_generation: 1,
            first_event_sequence: 1,
            last_event_sequence: 4,
            instances: Vec::new(),
            attempts: vec![attempt],
        };
        assert!(
            qualification_common_phase_matches_ledger(
                &ledger,
                &ledger.phase_commitments[0],
                &phase,
            )
            .unwrap()
        );

        let mut forbidden_provider_call = ledger.clone();
        forbidden_provider_call.events[1].kind =
            QualificationEvidenceEventKind::ProviderRequestWritten;
        assert!(forbidden_provider_call.validate().is_err());
        let mut forbidden_receipt = ledger;
        forbidden_receipt.events[1].kind = QualificationEvidenceEventKind::NativeReceiptVerified;
        assert!(forbidden_receipt.validate().is_err());
    }

    #[test]
    fn signed_ledger_round_trips_and_tampering_fails() {
        let trust = registry();
        let standalone_record = record();
        let standalone = &standalone_record.events[0];
        let standalone_bytes = canonical(standalone).unwrap();
        QualificationEvidenceEvent::verify_json(
            &standalone_bytes,
            QualificationEvidenceSource::Supervisor,
            &standalone.source_context_sha256,
            &trust,
            "stripe",
            NOW - 10,
            NOW + 10,
            NOW,
        )
        .unwrap();
        let outer_seed = [99_u8; 32];
        let public = Base64UrlUnpadded::encode_string(
            SigningKey::from_bytes(&outer_seed)
                .verifying_key()
                .as_bytes(),
        );
        let ledger_trust = ledger_registry(public);
        let mut invalid_source = record();
        invalid_source.events[1].source_signature_base64url = "A".repeat(86);
        assert_eq!(
            QualificationEvidenceLedger::validate_for_signing(
                &invalid_source,
                "ledger-test",
                &trust,
                &ledger_trust,
                NOW,
            ),
            Err(QualificationEvidenceLedgerError::InvalidSourceSignature)
        );
        let mut foreign_reader = record();
        foreign_reader.events[0].reader_identity = Some("foreign-reader".into());
        foreign_reader.events[0].reader_artifact_sha256 = Some("8".repeat(64));
        foreign_reader.events[0].reader_uid = Some(9_999);
        assert_eq!(
            QualificationEvidenceLedger::validate_for_signing(
                &foreign_reader,
                "ledger-test",
                &trust,
                &ledger_trust,
                NOW,
            ),
            Err(QualificationEvidenceLedgerError::InvalidEvent)
        );
        let bytes = QualificationEvidenceLedger::sign_json(
            record(),
            "ledger-test",
            &Base64UrlUnpadded::encode_string(&outer_seed),
            &trust,
            &ledger_trust,
            NOW,
        )
        .unwrap();
        QualificationEvidenceLedger::verify_json(&bytes, &trust, &ledger_trust, NOW).unwrap();
        let mut tampered = bytes;
        let index = tampered.iter().position(|byte| *byte == b'4').unwrap();
        tampered[index] = b'5';
        assert!(
            QualificationEvidenceLedger::verify_json(&tampered, &trust, &ledger_trust, NOW)
                .is_err()
        );

        let mut transplanted = record();
        transplanted.run_id = "789".into();
        assert!(transplanted.validate().is_err());
    }

    #[test]
    fn source_keys_and_hash_chain_cannot_overlap_or_reorder() {
        let mut trust = registry();
        trust.keys[1].public_key_base64url = trust.keys[0].public_key_base64url.clone();
        assert!(
            QualificationEvidenceSourceTrustRegistry::from_json(&canonical(&trust).unwrap())
                .is_err()
        );
        let mut trust = registry();
        trust.keys[1].source_identity = trust.keys[0].source_identity.clone();
        assert!(
            QualificationEvidenceSourceTrustRegistry::from_json(&canonical(&trust).unwrap())
                .is_err()
        );
        let mut trust = registry();
        trust.keys[1].source_artifact_sha256 = trust.keys[0].source_artifact_sha256.clone();
        assert!(
            QualificationEvidenceSourceTrustRegistry::from_json(&canonical(&trust).unwrap())
                .is_err()
        );
        let mut trust = registry();
        let client_index = trust
            .keys
            .iter()
            .position(|key| key.source == QualificationEvidenceSource::ClientProxy)
            .unwrap();
        let broker_index = trust
            .keys
            .iter()
            .position(|key| key.source == QualificationEvidenceSource::CredentialBroker)
            .unwrap();
        trust.keys[broker_index].reader_identity = trust.keys[client_index].reader_identity.clone();
        assert!(
            QualificationEvidenceSourceTrustRegistry::from_json(&canonical(&trust).unwrap())
                .is_err()
        );
        let mut trust = registry();
        trust.keys[broker_index].reader_artifact_sha256 =
            trust.keys[client_index].reader_artifact_sha256.clone();
        assert!(
            QualificationEvidenceSourceTrustRegistry::from_json(&canonical(&trust).unwrap())
                .is_err()
        );
        let mut trust = registry();
        let mut rotated = trust
            .keys
            .iter()
            .find(|key| key.source == QualificationEvidenceSource::Supervisor)
            .unwrap()
            .clone();
        rotated.key_id = "supervisor-rotated".into();
        rotated.public_key_base64url = Base64UrlUnpadded::encode_string(
            SigningKey::from_bytes(&[19_u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        trust.keys.push(rotated);
        trust.keys.sort_by(|left, right| {
            (source_token(left.source), left.key_id.as_str())
                .cmp(&(source_token(right.source), right.key_id.as_str()))
        });
        QualificationEvidenceSourceTrustRegistry::from_json(&canonical(&trust).unwrap()).unwrap();
        let mut invalid = record();
        invalid.events[1].previous_event_sha256 = ZERO_DIGEST.into();
        assert_eq!(
            invalid.validate(),
            Err(QualificationEvidenceLedgerError::InvalidEvent)
        );
    }

    #[test]
    fn retained_ledgers_remain_verifiable_after_run_keys_expire() {
        let outer_seed = [99_u8; 32];
        let public = Base64UrlUnpadded::encode_string(
            SigningKey::from_bytes(&outer_seed)
                .verifying_key()
                .as_bytes(),
        );
        let mut source_trust = registry();
        for key in &mut source_trust.keys {
            key.not_after_unix_seconds = NOW + 1;
        }
        let mut ledger_trust = ledger_registry(public);
        ledger_trust.keys[0].not_after_unix_seconds = NOW + 1;
        let bytes = QualificationEvidenceLedger::sign_json(
            record(),
            "ledger-test",
            &Base64UrlUnpadded::encode_string(&outer_seed),
            &source_trust,
            &ledger_trust,
            NOW,
        )
        .unwrap();
        QualificationEvidenceLedger::verify_json(&bytes, &source_trust, &ledger_trust, NOW + 50)
            .unwrap();

        let mut expired_during_run = source_trust.clone();
        for key in &mut expired_during_run.keys {
            key.not_after_unix_seconds = NOW - 5;
        }
        assert!(
            QualificationEvidenceLedger::verify_json(
                &bytes,
                &expired_during_run,
                &ledger_trust,
                NOW + 50,
            )
            .is_err()
        );
        let mut ledger_expired_during_run = ledger_trust;
        ledger_expired_during_run.keys[0].not_after_unix_seconds = NOW - 5;
        assert!(
            QualificationEvidenceLedger::verify_json(
                &bytes,
                &source_trust,
                &ledger_expired_during_run,
                NOW + 50,
            )
            .is_err()
        );
    }

    #[test]
    fn journal_decisions_bind_one_actual_agent_trust_identity() {
        let recovery_public = Base64UrlUnpadded::encode_string(
            SigningKey::from_bytes(&[42_u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let payload = QualificationEvidenceEventPayload::Decision {
            canonical_input_sha256: "1".repeat(64),
            idempotency_sha256: Some("2".repeat(64)),
            canonical_action_sha256: "3".repeat(64),
            receipt_action_sha256: "4".repeat(64),
            receipt_context_sha256: "5".repeat(64),
            authority_sha256: "6".repeat(64),
            configuration_sha256: "7".repeat(64),
            runtime_contract_sha256: "8".repeat(64),
            preparation_sha256: "9".repeat(64),
            decision_class: QualificationReceiptDecisionClass::Authorized,
            decision_receipt_id: format!("rcpt_{}", "a".repeat(43)),
            decision_receipt_bytes_sha256: "b".repeat(64),
            decoded_claims_sha256: "c".repeat(64),
            supervisor_context_sha256: "d".repeat(64),
            recovery_key_id: "recovery-current".into(),
            recovery_public_key_base64url: recovery_public,
            receipt_trust_anchor_sha256: "e".repeat(64),
        };
        assert!(payload_valid(&payload));
        let mut first = signed_event(
            1,
            ZERO_DIGEST.into(),
            QualificationEvidenceEventKind::ScenarioStarted,
            &"e".repeat(64),
        );
        first.payload = payload.clone();
        let mut second = first.clone();
        assert_eq!(
            validate_agent_trust(&[first.clone(), second.clone()]),
            Ok(())
        );
        let QualificationEvidenceEventPayload::Decision {
            recovery_key_id, ..
        } = &mut second.payload
        else {
            unreachable!()
        };
        *recovery_key_id = "recovery-substituted".into();
        assert_eq!(
            validate_agent_trust(&[first, second]),
            Err(QualificationEvidenceLedgerError::InvalidEvent)
        );

        let mut late_decision = signed_event(
            1,
            ZERO_DIGEST.into(),
            QualificationEvidenceEventKind::DecisionDurable,
            &"e".repeat(64),
        );
        late_decision.source = QualificationEvidenceSource::JournalReader;
        late_decision.kind = QualificationEvidenceEventKind::DecisionDurable;
        late_decision.payload = payload;
        late_decision.agent_generation = Some(1);
        late_decision.agent_process_id = Some(42);
        late_decision.agent_boot_sha256 = Some("f".repeat(64));
        late_decision.operation_id = Some("op_decision-boundary".into());
        late_decision.connection_generation = Some("1".into());
        late_decision.journal_revision = Some(2);
        assert_eq!(
            validate_event_sequences(&[late_decision.clone()]),
            Err(QualificationEvidenceLedgerError::InvalidEvent)
        );
        late_decision.journal_revision = Some(1);
        assert_eq!(validate_event_sequences(&[late_decision.clone()]), Ok(()));

        let mut same_transaction_terminal = late_decision.clone();
        same_transaction_terminal.kind = QualificationEvidenceEventKind::TerminalDurable;
        assert_eq!(
            validate_event_sequences(&[late_decision.clone(), same_transaction_terminal]),
            Ok(())
        );
        let mut invented_same_revision = late_decision.clone();
        invented_same_revision.kind = QualificationEvidenceEventKind::CommandDurable;
        assert_eq!(
            validate_event_sequences(&[late_decision, invented_same_revision]),
            Err(QualificationEvidenceLedgerError::InvalidEvent)
        );
    }

    #[test]
    fn capability_free_decision_snapshot_rederives_the_complete_payload() {
        let snapshot = QualificationDecisionSnapshotV1 {
            schema: "auths.qualification-decision-snapshot/1".into(),
            operation_id: "op_decision-boundary".into(),
            profile: "auths.stripe.refund/1".into(),
            connection_generation: "1".into(),
            journal_revision: 1,
            state: QualificationDecisionSnapshotState::Ready,
            decision_class: QualificationReceiptDecisionClass::Authorized,
            canonical_input_sha256: "1".repeat(64),
            idempotency_sha256: Some("2".repeat(64)),
            canonical_action_sha256: "3".repeat(64),
            receipt_action_sha256: "4".repeat(64),
            receipt_context_sha256: "5".repeat(64),
            authority_sha256: "6".repeat(64),
            configuration_sha256: "7".repeat(64),
            runtime_contract_sha256: "8".repeat(64),
            preparation_sha256: "9".repeat(64),
            decision_receipt_id: format!("rcpt_{}", "a".repeat(43)),
            decision_receipt_bytes_sha256: "b".repeat(64),
            decoded_claims_sha256: "c".repeat(64),
            recovery_key_id: "recovery-current".into(),
            recovery_public_key_base64url: Base64UrlUnpadded::encode_string(
                SigningKey::from_bytes(&[42_u8; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
            receipt_trust_anchor_sha256: "d".repeat(64),
        };
        let bytes = snapshot.to_json().unwrap();
        let decoded = QualificationDecisionSnapshotV1::from_json(&bytes).unwrap();
        assert_eq!(decoded, snapshot);
        assert!(payload_valid(&decoded.decision_payload("e".repeat(64))));
        assert!(!String::from_utf8(bytes).unwrap().contains("recoveryHandle"));

        let mut invalid = snapshot;
        invalid.state = QualificationDecisionSnapshotState::Denied;
        assert!(invalid.to_json().is_err());
    }

    #[test]
    fn durable_decision_ack_is_canonical_and_agent_minted() {
        let ack = QualificationDurableDecisionAckV1::new(
            "op_decision-boundary".into(),
            "a".repeat(64),
            7,
            Some("ctl_0123456789abcdef0123456789abcdef".into()),
            Some("b".repeat(64)),
        )
        .unwrap();
        let bytes = ack.to_json().unwrap();
        assert_eq!(
            QualificationDurableDecisionAckV1::from_json(&bytes).unwrap(),
            ack
        );

        let mut trailing = bytes.clone();
        trailing.push(b'\n');
        assert!(QualificationDurableDecisionAckV1::from_json(&trailing).is_err());
        let mut invalid = ack;
        invalid.agent_generation = 0;
        assert!(invalid.to_json().is_err());
    }

    fn journal_decision_context_record() -> QualificationJournalDecisionContextRecord {
        QualificationJournalDecisionContextRecord {
            schema: "auths.qualification-journal-decision-context-record/1".into(),
            repository_id: "123".into(),
            workflow_path: ".github/workflows/profile-qualification-stripe.yml".into(),
            workflow_revision: "1".repeat(40),
            candidate_revision: "2".repeat(40),
            attester_revision: "3".repeat(40),
            run_id: "456".into(),
            run_attempt: 2,
            domain: "stripe".into(),
            target: QualificationTarget::LinuxX86_64,
            protected_environment: "qualification-stripe".into(),
            provider_run_id: "stripe-live".into(),
            ledger_id: "ledger-test".into(),
            session_nonce_sha256: "4".repeat(64),
            scenario_id: "crash-after-decision".into(),
            phase_index: 1,
            role: QualificationOperationRole::Effect,
            profile: "auths.stripe.refund/1".into(),
            operation_plan_sha256: "1".repeat(64),
            scenario_program_sha256: "2".repeat(64),
            failpoint: Some(QualificationFailpoint::AfterDecision),
            supervisor_controller_uid: 1000,
            supervisor_source_uid: 1001,
            journal_reader_uid: 1002,
            agent_uid: 2000,
            agent_gid: 2000,
            supervisor_source_identity: "supervisor-process".into(),
            supervisor_source_artifact_sha256: hex::encode(Sha256::digest("supervisor")),
            supervisor_controller_artifact_sha256: hex::encode(Sha256::digest("controller")),
            journal_reader_source_identity: "journal-reader-process".into(),
            journal_reader_source_artifact_sha256: hex::encode(Sha256::digest("journal-reader")),
            journal_reader_key_id: "journal-reader-test".into(),
            source_context_sha256: "6".repeat(64),
            supervisor_generation: 3,
            agent_generation: 7,
            agent_process_id: 4242,
            agent_boot_sha256: "7".repeat(64),
            agent_start_time_ticks: 123_456,
            agent_launcher_artifact_sha256: "f".repeat(64),
            agent_executable_sha256: "a".repeat(64),
            agent_configuration_sha256: "b".repeat(64),
            agent_state_directory_sha256: "c".repeat(64),
            agent_cgroup_sha256: "d".repeat(64),
            journal_path_sha256: "e".repeat(64),
            journal_device: 1,
            journal_inode: 2,
            journal_owner_uid: 2000,
            journal_mode: 0o600,
            journal_length: 4096,
            boundary_ordinal: 1,
            boundary_projection_sha256: "5".repeat(64),
            operation_id: "op_decision-boundary".into(),
            control_operation_id: Some("ctl_decision-boundary".into()),
            controller_nonce_sha256: Some("f".repeat(64)),
            journal_revision: 1,
            journal_record_sha256: "0".repeat(64),
            decision_snapshot_sha256: "8".repeat(64),
            durable_ack_sha256: "9".repeat(64),
        }
    }

    fn crash_phase_context() -> QualificationCrashPhaseContextV1 {
        let context = journal_decision_context_record();
        QualificationCrashPhaseContextV1 {
            schema: "auths.qualification-crash-phase-context/1".into(),
            source_context_sha256: context.source_context_sha256,
            domain: context.domain,
            phase: QualificationEvidencePhasePlanV1 {
                scenario_id: context.scenario_id,
                phase_index: context.phase_index,
                role: context.role,
                profile: context.profile,
                failpoint: context.failpoint,
                operation_plan_sha256: context.operation_plan_sha256,
                scenario_program_sha256: context.scenario_program_sha256,
                credential_requirement: credential_requirement(),
            },
            supervisor_source_uid: context.supervisor_source_uid,
            agent_uid: context.agent_uid,
            agent_gid: context.agent_gid,
            supervisor_source_identity: context.supervisor_source_identity,
            supervisor_generation: context.supervisor_generation,
            agent_generation: context.agent_generation,
            agent_launcher_artifact_sha256: context.agent_launcher_artifact_sha256,
            agent_executable_sha256: context.agent_executable_sha256,
            control_operation_id: context.control_operation_id.unwrap(),
            controller_nonce_sha256: context.controller_nonce_sha256.unwrap(),
        }
    }

    fn crash_process() -> QualificationCrashProcessIdentityV1 {
        let context = journal_decision_context_record();
        QualificationCrashProcessIdentityV1 {
            agent_generation: context.agent_generation,
            agent_process_id: context.agent_process_id,
            agent_boot_sha256: context.agent_boot_sha256,
            agent_start_time_ticks: context.agent_start_time_ticks,
            agent_launcher_artifact_sha256: context.agent_launcher_artifact_sha256,
            agent_executable_sha256: context.agent_executable_sha256,
            agent_configuration_sha256: context.agent_configuration_sha256,
            agent_state_directory_sha256: context.agent_state_directory_sha256,
            agent_cgroup_sha256: context.agent_cgroup_sha256,
        }
    }

    fn crash_action(facts: QualificationCrashActionFactsV1) -> QualificationCrashActionRecordV1 {
        let (sequence, previous_event_sha256) = match &facts {
            QualificationCrashActionFactsV1::FailpointAcknowledged {
                boundary_event_sha256,
                ..
            } => (4, boundary_event_sha256.clone()),
            QualificationCrashActionFactsV1::ProcessKilled {
                acknowledgement_event_sha256,
                ..
            } => (5, acknowledgement_event_sha256.clone()),
            QualificationCrashActionFactsV1::ProcessRestarted {
                kill_event_sha256, ..
            } => (6, kill_event_sha256.clone()),
        };
        QualificationCrashActionRecordV1 {
            schema: "auths.qualification-crash-action-record/1".into(),
            crash_context: crash_phase_context(),
            sequence,
            previous_event_sha256,
            profile: "auths.stripe.refund/1".into(),
            supervisor_controller_uid: 1000,
            supervisor_source_artifact_sha256: hex::encode(Sha256::digest("supervisor")),
            supervisor_controller_artifact_sha256: hex::encode(Sha256::digest("controller")),
            operation_id: Some("op_decision-boundary".into()),
            connection_generation: Some("1".into()),
            durable_ack_sha256: Some("9".repeat(64)),
            facts,
        }
    }

    fn assert_journal_context_mutation_rejected(
        signed: &[u8],
        trust: &QualificationEvidenceSourceTrustRegistry,
        mutate: impl FnOnce(&mut QualificationJournalDecisionContextRecord),
    ) {
        let mut envelope: QualificationJournalDecisionContext =
            serde_json::from_slice(signed).unwrap();
        mutate(&mut envelope.record);
        let tampered = canonical(&envelope).unwrap();
        assert_eq!(
            QualificationJournalDecisionContext::verify_json(
                &tampered,
                trust,
                NOW - 10,
                NOW + 10,
                NOW,
            ),
            Err(QualificationEvidenceLedgerError::InvalidSourceSignature)
        );
    }

    #[test]
    fn journal_decision_context_authenticates_process_ack_run_session_and_snapshot() {
        let trust = registry();
        let seed =
            Base64UrlUnpadded::encode_string(&source_seed(QualificationEvidenceSource::Supervisor));
        let context_record = journal_decision_context_record();
        let context = crash_phase_context();
        context.validate().unwrap();
        assert!(context.binds_context(&context_record));
        for mutate in [
            |context: &mut QualificationCrashPhaseContextV1| {
                context.source_context_sha256 = "a".repeat(64)
            },
            |context: &mut QualificationCrashPhaseContextV1| {
                context.phase.profile = "auths.postgresql.role/1".into()
            },
            |context: &mut QualificationCrashPhaseContextV1| {
                context.phase.operation_plan_sha256 = "c".repeat(64)
            },
            |context: &mut QualificationCrashPhaseContextV1| {
                context.agent_launcher_artifact_sha256 = "a".repeat(64)
            },
            |context: &mut QualificationCrashPhaseContextV1| {
                context.agent_executable_sha256 = "b".repeat(64)
            },
        ] {
            let mut changed = context.clone();
            mutate(&mut changed);
            assert!(!changed.binds_context(&context_record));
        }
        let mut ledger_plan = QualificationEvidenceLedgerPlanV1 {
            schema: "auths.profile-qualification-evidence-ledger-plan/1".into(),
            repository_id: context_record.repository_id.clone(),
            workflow_path: context_record.workflow_path.clone(),
            workflow_revision: context_record.workflow_revision.clone(),
            candidate_revision: context_record.candidate_revision.clone(),
            attester_revision: context_record.attester_revision.clone(),
            run_id: context_record.run_id.clone(),
            run_attempt: context_record.run_attempt,
            domain: context.domain.clone(),
            target: context_record.target,
            protected_environment: context_record.protected_environment.clone(),
            provider_run_id: context_record.provider_run_id.clone(),
            ledger_id: context_record.ledger_id.clone(),
            session_nonce_sha256: context_record.session_nonce_sha256.clone(),
            supervisor_controller_uid: 1000,
            supervisor_controller_artifact_sha256: "5".repeat(64),
            ledger_appender_artifact_sha256: "7".repeat(64),
            agent_uid: context.agent_uid,
            agent_gid: context.agent_gid,
            agent_executable_sha256: context.agent_executable_sha256.clone(),
            recovery_key_id: "recovery".into(),
            recovery_public_key_base64url: Base64UrlUnpadded::encode_string(&[9; 32]),
            phases: vec![context.phase.clone()],
            started_at_unix_seconds: NOW - 10,
            deadline_at_unix_seconds: NOW + 10,
        };
        let mut ledger_bound_context = context.clone();
        ledger_bound_context.source_context_sha256 = ledger_plan.source_context_sha256().unwrap();
        assert!(
            ledger_bound_context
                .binds_ledger_plan(&ledger_plan)
                .unwrap()
        );
        let mut repeated_profile = ledger_plan.clone();
        let mut second_phase = repeated_profile.phases[0].clone();
        second_phase.phase_index = second_phase.phase_index.checked_add(1).unwrap();
        repeated_profile.phases.push(second_phase);
        assert_eq!(
            repeated_profile.validate(),
            Err(QualificationEvidenceLedgerError::InvalidRecord)
        );
        let mut changed_appender = ledger_plan.clone();
        changed_appender.ledger_appender_artifact_sha256 = "8".repeat(64);
        assert_ne!(
            changed_appender.source_context_sha256().unwrap(),
            ledger_plan.source_context_sha256().unwrap()
        );
        ledger_plan.phases[0].profile = "auths.postgresql.role/1".into();
        assert!(
            !ledger_bound_context
                .binds_ledger_plan(&ledger_plan)
                .unwrap()
        );
        ledger_plan.phases[0].profile = ledger_bound_context.phase.profile.clone();
        ledger_plan.phases[0].operation_plan_sha256 = "d".repeat(64);
        assert!(
            !ledger_bound_context
                .binds_ledger_plan(&ledger_plan)
                .unwrap()
        );
        let signed = QualificationJournalDecisionContext::sign_json(
            context_record,
            "supervisor-test",
            &seed,
            &trust,
            NOW - 10,
            NOW + 10,
            NOW,
        )
        .unwrap();
        let verified = QualificationJournalDecisionContext::verify_json(
            &signed,
            &trust,
            NOW - 10,
            NOW + 10,
            NOW,
        )
        .unwrap();
        assert_eq!(verified.record(), &journal_decision_context_record());

        assert_journal_context_mutation_rejected(&signed, &trust, |record| {
            record.agent_process_id += 1;
        });
        assert_journal_context_mutation_rejected(&signed, &trust, |record| {
            record.agent_boot_sha256 = "a".repeat(64);
        });
        assert_journal_context_mutation_rejected(&signed, &trust, |record| {
            record.agent_launcher_artifact_sha256 = "a".repeat(64);
        });
        assert_journal_context_mutation_rejected(&signed, &trust, |record| {
            record.durable_ack_sha256 = "a".repeat(64);
        });
        assert_journal_context_mutation_rejected(&signed, &trust, |record| {
            record.run_id = "457".into();
        });
        assert_journal_context_mutation_rejected(&signed, &trust, |record| {
            record.session_nonce_sha256 = "a".repeat(64);
        });
        assert_journal_context_mutation_rejected(&signed, &trust, |record| {
            record.decision_snapshot_sha256 = "a".repeat(64);
        });
        assert_journal_context_mutation_rejected(&signed, &trust, |record| {
            record.operation_id = "op_substituted".into();
        });

        let mut shared_identity = journal_decision_context_record();
        shared_identity.journal_reader_source_identity =
            shared_identity.supervisor_source_identity.clone();
        assert_eq!(
            QualificationJournalDecisionContext::sign_json(
                shared_identity,
                "supervisor-test",
                &seed,
                &trust,
                NOW - 10,
                NOW + 10,
                NOW,
            ),
            Err(QualificationEvidenceLedgerError::InvalidEvent)
        );

        let mut shared_uid = journal_decision_context_record();
        shared_uid.journal_reader_uid = shared_uid.supervisor_source_uid;
        assert_eq!(
            QualificationJournalDecisionContext::sign_json(
                shared_uid,
                "supervisor-test",
                &seed,
                &trust,
                NOW - 10,
                NOW + 10,
                NOW,
            ),
            Err(QualificationEvidenceLedgerError::InvalidEvent)
        );

        for invalid_path in [
            ".github/workflows/profile-qualification-Stripe.yml",
            ".github/workflows/profile-qualification-stripe_extra.yml",
            ".github/workflows/profile-qualification-stripe/extra.yml",
        ] {
            let mut invalid = journal_decision_context_record();
            invalid.workflow_path = invalid_path.into();
            assert!(
                QualificationJournalDecisionContext::sign_json(
                    invalid,
                    "supervisor-test",
                    &seed,
                    &trust,
                    NOW - 10,
                    NOW + 10,
                    NOW,
                )
                .is_err()
            );
        }
        let mut boundary = journal_decision_context_record();
        boundary.boundary_ordinal = 16_384;
        assert!(
            QualificationJournalDecisionContext::sign_json(
                boundary,
                "supervisor-test",
                &seed,
                &trust,
                NOW - 10,
                NOW + 10,
                NOW,
            )
            .is_ok()
        );
        let mut overflow = journal_decision_context_record();
        overflow.boundary_ordinal = 16_385;
        assert!(
            QualificationJournalDecisionContext::sign_json(
                overflow,
                "supervisor-test",
                &seed,
                &trust,
                NOW - 10,
                NOW + 10,
                NOW,
            )
            .is_err()
        );

        for failpoint in QualificationFailpoint::ALL {
            let mut record = journal_decision_context_record();
            record.scenario_id = format!("crash-{}", failpoint.as_str());
            record.failpoint = Some(failpoint);
            assert!(record.validate().is_ok(), "{}", failpoint.as_str());

            record.control_operation_id = None;
            assert_eq!(
                record.validate(),
                Err(QualificationEvidenceLedgerError::InvalidEvent),
                "{} admitted a partial crash identity",
                failpoint.as_str()
            );
        }
    }

    #[test]
    fn crash_action_contexts_are_typed_chained_and_process_bound() {
        let trust = registry();
        let seed =
            Base64UrlUnpadded::encode_string(&source_seed(QualificationEvidenceSource::Supervisor));
        let process = crash_process();
        let acknowledged = crash_action(QualificationCrashActionFactsV1::FailpointAcknowledged {
            process: process.clone(),
            durable_ack_sha256: Some("9".repeat(64)),
            boundary_event_sha256: "1".repeat(64),
        });
        let acknowledgement_bytes = QualificationCrashActionContextV1::sign_json(
            acknowledged.clone(),
            "supervisor-test",
            &seed,
            &trust,
            NOW - 10,
            NOW + 10,
            NOW,
        )
        .unwrap();
        let verified = QualificationCrashActionContextV1::verify_json(
            &acknowledgement_bytes,
            &trust,
            NOW - 10,
            NOW + 10,
            NOW,
        )
        .unwrap();
        assert_eq!(verified.record(), &acknowledged);
        let acknowledgement_context_sha256 = hex::encode(Sha256::digest(&acknowledgement_bytes));
        assert!(matches!(
            acknowledged.event_payload(acknowledgement_context_sha256.clone()),
            QualificationEvidenceEventPayload::FailpointAcknowledgement { .. }
        ));
        let acknowledgement_event =
            acknowledged.unsigned_event("supervisor-test".into(), acknowledgement_context_sha256);
        assert_eq!(
            acknowledged.intent_sha256().unwrap(),
            acknowledgement_event.intent_sha256().unwrap()
        );
        let alternate_context_event =
            acknowledged.unsigned_event("supervisor-test".into(), "a".repeat(64));
        assert_eq!(
            acknowledgement_event.intent_sha256().unwrap(),
            alternate_context_event.intent_sha256().unwrap()
        );
        let acknowledgement_event_bytes = acknowledgement_event
            .sign_json(
                QualificationEvidenceSource::Supervisor,
                &acknowledged.crash_context.source_context_sha256,
                &seed,
                &trust,
                &acknowledged.crash_context.domain,
                NOW - 10,
                NOW + 10,
                NOW,
            )
            .unwrap();
        QualificationEvidenceEvent::verify_json(
            &acknowledgement_event_bytes,
            QualificationEvidenceSource::Supervisor,
            &acknowledged.crash_context.source_context_sha256,
            &trust,
            &acknowledged.crash_context.domain,
            NOW - 10,
            NOW + 10,
            NOW,
        )
        .unwrap();

        let acknowledgement_event_sha256 = "2".repeat(64);
        let killed = crash_action(QualificationCrashActionFactsV1::ProcessKilled {
            process: process.clone(),
            acknowledgement_event_sha256: acknowledgement_event_sha256.clone(),
            signal: "SIGKILL".into(),
            cgroup_empty_after_kill: true,
        });
        killed.validate().unwrap();
        assert!(matches!(
            killed.event_payload("3".repeat(64)),
            QualificationEvidenceEventPayload::ProcessKill { .. }
        ));

        let mut restarted_process = process.clone();
        restarted_process.agent_generation += 1;
        restarted_process.agent_process_id += 1;
        restarted_process.agent_start_time_ticks += 1;
        restarted_process.agent_cgroup_sha256 = "4".repeat(64);
        let restarted = crash_action(QualificationCrashActionFactsV1::ProcessRestarted {
            killed_process: process.clone(),
            restarted_process: restarted_process.clone(),
            kill_event_sha256: "5".repeat(64),
            control_plane_ready: true,
        });
        restarted.validate().unwrap();
        assert!(matches!(
            restarted.event_payload("6".repeat(64)),
            QualificationEvidenceEventPayload::ProcessRestart { .. }
        ));

        let mut wrong_sequence = acknowledged;
        wrong_sequence.sequence = 0;
        assert_eq!(
            wrong_sequence.validate(),
            Err(QualificationEvidenceLedgerError::InvalidEvent)
        );
        let mut wrong_signal = killed;
        let QualificationCrashActionFactsV1::ProcessKilled { signal, .. } = &mut wrong_signal.facts
        else {
            unreachable!()
        };
        *signal = "SIGTERM".into();
        assert_eq!(
            wrong_signal.validate(),
            Err(QualificationEvidenceLedgerError::InvalidEvent)
        );
        let mut reused_process = restarted;
        let QualificationCrashActionFactsV1::ProcessRestarted {
            restarted_process, ..
        } = &mut reused_process.facts
        else {
            unreachable!()
        };
        restarted_process.agent_process_id = process.agent_process_id;
        assert_eq!(
            reused_process.validate(),
            Err(QualificationEvidenceLedgerError::InvalidEvent)
        );

        for failpoint in QualificationFailpoint::ALL {
            let mut action = crash_action(QualificationCrashActionFactsV1::FailpointAcknowledged {
                process: process.clone(),
                durable_ack_sha256: Some("9".repeat(64)),
                boundary_event_sha256: "1".repeat(64),
            });
            action.crash_context.phase.failpoint = Some(failpoint);
            action.crash_context.phase.scenario_id = format!("crash-{}", failpoint.as_str());
            if failpoint == QualificationFailpoint::BeforeDecision {
                action.operation_id = None;
                action.connection_generation = None;
                action.durable_ack_sha256 = None;
                let QualificationCrashActionFactsV1::FailpointAcknowledged {
                    durable_ack_sha256,
                    ..
                } = &mut action.facts
                else {
                    unreachable!()
                };
                *durable_ack_sha256 = None;
            }
            assert!(action.validate().is_ok(), "{}", failpoint.as_str());
        }
    }

    #[test]
    fn typed_source_records_derive_only_their_fixed_source_events() {
        let context = QualificationSourceEventContextV1 {
            sequence: 1,
            previous_event_sha256: ZERO_DIGEST.into(),
            scenario_id: "scenario-1".into(),
            phase_index: 1,
            role: QualificationOperationRole::Effect,
            profile: "auths.profile.test/1".into(),
            failpoint: None,
            supervisor_generation: 1,
            operation_id: Some("operation-1".into()),
            request_id: Some("request-1".into()),
            connection_generation: Some("1".into()),
        };
        let process = QualificationSourceProcessBindingV1 {
            source_identity: "protected-signer".into(),
            source_artifact_sha256: "b".repeat(64),
            source_uid: 1_001,
            reader_identity: "protected-reader".into(),
            reader_artifact_sha256: "8".repeat(64),
            reader_uid: 1_002,
        };
        let source_context = "c".repeat(64);
        let key = "source-key".to_owned();

        let mut client_context = context.clone();
        client_context.operation_id = None;
        client_context.connection_generation = None;
        let client = QualificationClientProxyRecordV1 {
            schema: "auths.qualification-client-proxy-record/1".into(),
            context: client_context,
            observation: QualificationClientProxyObservationV1::ResponseProjected {
                result_sha256: "d".repeat(64),
                journal_projection_kinds: vec![QualificationEvidenceEventKind::StatusObserved],
                outcome: QualificationOutcomeKind::Completed,
                completion: Some(QualificationCompletion::Fresh),
                recovery_id: None,
                error_code: None,
                issue_metadata_sha256: None,
                receipt_ids: Vec::new(),
            },
        };
        let client_bytes = canonical(&client).unwrap();
        assert!(
            client_bytes
                .windows(b"resultSha256".len())
                .any(|window| window == b"resultSha256")
        );
        assert!(
            !client_bytes
                .windows(b"result_sha256".len())
                .any(|window| window == b"result_sha256")
        );
        let client = QualificationClientProxyRecordV1::from_json(&client_bytes).unwrap();
        let event = client.unsigned_event(&process, source_context.clone(), key.clone());
        assert_eq!(event.source, QualificationEvidenceSource::ClientProxy);
        assert_eq!(
            event.kind,
            QualificationEvidenceEventKind::ResponseProjected
        );
        assert_eq!(event.client_result_sha256, Some("d".repeat(64)));
        assert!(event_fields_match_kind(&event));
        let mut journal_identity = event.clone();
        journal_identity.operation_id = Some("operation-1".into());
        journal_identity.connection_generation = Some("1".into());
        assert!(!event_fields_match_kind(&journal_identity));
        let intent = event.intent_sha256().unwrap();
        let mut reordered = event.clone();
        reordered.sequence = 9;
        reordered.previous_event_sha256 = "9".repeat(64);
        reordered.source_key_id = "rotated-key".into();
        reordered.source_signature_base64url = "signature".into();
        reordered.durable_ack_sha256 = "8".repeat(64);
        assert_eq!(reordered.intent_sha256().unwrap(), intent);
        reordered.client_result_sha256 = Some("e".repeat(64));
        if let QualificationEvidenceEventPayload::ClientResult { result_sha256, .. } =
            &mut reordered.payload
        {
            *result_sha256 = "e".repeat(64);
        }
        assert_ne!(reordered.intent_sha256().unwrap(), intent);

        let broker = QualificationCredentialBrokerRecordV1 {
            schema: "auths.qualification-credential-broker-record/1".into(),
            context: context.clone(),
            observation: QualificationCredentialBrokerObservationV1::CredentialLeaseClosed {
                lease_sha256: "e".repeat(64),
                requested_scope_sha256: "f".repeat(64),
                effective_scope_sha256: "1".repeat(64),
            },
        };
        let broker_bytes = canonical(&broker).unwrap();
        assert!(
            broker_bytes
                .windows(b"leaseSha256".len())
                .any(|window| window == b"leaseSha256")
        );
        let event = broker.unsigned_event(&process, source_context.clone(), key.clone());
        assert_eq!(event.source, QualificationEvidenceSource::CredentialBroker);
        assert_eq!(
            event.kind,
            QualificationEvidenceEventKind::CredentialLeaseClosed
        );

        let state = QualificationProfileStateRecordV1 {
            schema: "auths.qualification-profile-state-record/1".into(),
            context: context.clone(),
            observation: QualificationProfileStateObservationV1::ReservationConsumed {
                reservation_sha256: "2".repeat(64),
            },
        };
        let state_bytes = canonical(&state).unwrap();
        assert!(
            state_bytes
                .windows(b"reservationSha256".len())
                .any(|window| window == b"reservationSha256")
        );
        let event = state.unsigned_event(&process, source_context.clone(), key.clone());
        assert_eq!(
            event.source,
            QualificationEvidenceSource::ProfileStateReader
        );
        assert_eq!(
            event.kind,
            QualificationEvidenceEventKind::ReservationConsumed
        );

        let proxy = QualificationProviderProxyRecordV1 {
            schema: "auths.qualification-provider-proxy-record/1".into(),
            context: context.clone(),
            observation: QualificationProviderProxyObservationV1::ProviderResponseObserved {
                response_sha256: "3".repeat(64),
            },
        };
        let proxy_bytes = canonical(&proxy).unwrap();
        assert!(
            proxy_bytes
                .windows(b"responseSha256".len())
                .any(|window| window == b"responseSha256")
        );
        let event = proxy.unsigned_event(&process, source_context.clone(), key.clone());
        assert_eq!(event.source, QualificationEvidenceSource::ProviderProxy);
        assert_eq!(
            event.kind,
            QualificationEvidenceEventKind::ProviderResponseObserved
        );

        let proxy_request = QualificationProviderProxyRecordV1 {
            schema: "auths.qualification-provider-proxy-record/1".into(),
            context: context.clone(),
            observation: QualificationProviderProxyObservationV1::ProviderRequestWritten {
                request_sha256: "7".repeat(64),
                credential_lease_sha256: "8".repeat(64),
            },
        };
        let event = proxy_request.unsigned_event(&process, source_context.clone(), key.clone());
        assert!(matches!(
            event.payload,
            QualificationEvidenceEventPayload::ProviderRequest {
                ref request_sha256,
                ref credential_lease_sha256,
            } if request_sha256 == &"7".repeat(64)
                && credential_lease_sha256 == &"8".repeat(64)
        ));

        let reconcile = QualificationProviderProxyRecordV1 {
            schema: "auths.qualification-provider-proxy-record/1".into(),
            context: context.clone(),
            observation: QualificationProviderProxyObservationV1::ProviderReconciliationRequested {
                request_sha256: "9".repeat(64),
                credential_lease_sha256: "8".repeat(64),
            },
        };
        assert_eq!(
            reconcile
                .unsigned_event(&process, source_context.clone(), key.clone())
                .kind,
            QualificationEvidenceEventKind::ProviderReconciliationRequested
        );

        let receipt = QualificationReceiptVerifierRecordV1 {
            schema: "auths.qualification-receipt-verifier-record/1".into(),
            context: context.clone(),
            receipt_id: "receipt-1".into(),
            receipt_bytes_sha256: "4".repeat(64),
            decoded_claims_sha256: "5".repeat(64),
            profile_inspection_sha256: "6".repeat(64),
        };
        let event = receipt.unsigned_event(&process, source_context.clone(), key.clone());
        assert_eq!(event.source, QualificationEvidenceSource::ReceiptVerifier);
        assert_eq!(
            event.kind,
            QualificationEvidenceEventKind::NativeReceiptVerified
        );
        assert_eq!(event.receipt_id, Some("receipt-1".into()));

        let observer = QualificationProviderObserverRecordV1 {
            schema: "auths.qualification-provider-observer-record/1".into(),
            context,
            effect: QualificationEffect::Applied,
            provider_truth_sha256: "7".repeat(64),
        };
        let event = observer.unsigned_event(&process, source_context, key);
        assert_eq!(event.source, QualificationEvidenceSource::ProviderObserver);
        assert_eq!(
            event.kind,
            QualificationEvidenceEventKind::ProviderTruthObserved
        );

        let mut noncanonical = client_bytes;
        noncanonical.push(b'\n');
        assert_eq!(
            QualificationClientProxyRecordV1::from_json(&noncanonical),
            Err(QualificationEvidenceLedgerError::InvalidEncoding)
        );
    }

    #[test]
    fn client_bridge_binding_is_canonical_and_process_bound() {
        let binding = QualificationClientBridgeBindingV1 {
            schema: "auths.qualification-client-bridge-binding/1".into(),
            source_context_sha256: "1".repeat(64),
            client_uid: 1_001,
            client_gid: 1_002,
            client_process_id: 42,
            client_start_time_ticks: 77,
            client_executable_sha256: "2".repeat(64),
            fault: None,
        };
        let bytes = binding.to_json().unwrap();
        assert_eq!(
            QualificationClientBridgeBindingV1::from_json(&bytes).unwrap(),
            binding
        );
        for fault in [
            QualificationAdmissionFaultV1::ConfigurationMismatch,
            QualificationAdmissionFaultV1::ConnectionSubstitution,
            QualificationAdmissionFaultV1::PrincipalSubstitution,
            QualificationAdmissionFaultV1::EvidenceFreshnessEdge,
            QualificationAdmissionFaultV1::StaleEvidence,
        ] {
            let mut faulted = binding.clone();
            faulted.fault = Some(fault);
            let faulted_bytes = faulted.to_json().unwrap();
            assert_eq!(
                QualificationClientBridgeBindingV1::from_json(&faulted_bytes).unwrap(),
                faulted
            );
        }
        let mut mutated = binding.clone();
        mutated.client_start_time_ticks = 0;
        assert!(mutated.to_json().is_err());
        let mut noncanonical = bytes;
        noncanonical.push(b'\n');
        assert!(QualificationClientBridgeBindingV1::from_json(&noncanonical).is_err());
    }

    #[test]
    fn supervisor_phase_request_is_canonical_and_order_bound() {
        let request = QualificationSupervisorPhaseRequestV1 {
            schema: "auths.qualification-supervisor-phase-request/1".into(),
            sequence: 7,
            previous_event_sha256: "1".repeat(64),
            scenario_id: "happy-path".into(),
            phase_index: 1,
            supervisor_generation: 2,
            kind: QualificationEvidenceEventKind::ScenarioStarted,
        };
        let bytes = request.to_json().unwrap();
        assert_eq!(
            QualificationSupervisorPhaseRequestV1::from_json(&bytes).unwrap(),
            request
        );
        let mut invalid = request.clone();
        invalid.sequence = 0;
        assert!(invalid.to_json().is_err());
        let mut invalid = request;
        invalid.kind = QualificationEvidenceEventKind::RequestReceived;
        assert!(invalid.to_json().is_err());
        let mut noncanonical = bytes;
        noncanonical.push(b'\n');
        assert!(QualificationSupervisorPhaseRequestV1::from_json(&noncanonical).is_err());
    }

    #[test]
    fn supervisor_phase_context_binds_the_reviewed_phase_and_artifact() {
        let phase = QualificationEvidencePhasePlanV1 {
            scenario_id: "happy-path".into(),
            phase_index: 1,
            role: QualificationOperationRole::Effect,
            profile: "auths.stripe.refund/1".into(),
            failpoint: None,
            operation_plan_sha256: "1".repeat(64),
            scenario_program_sha256: "3".repeat(64),
            credential_requirement: credential_requirement(),
        };
        let first = qualification_supervisor_phase_context_sha256(&phase, &"2".repeat(64)).unwrap();
        assert_eq!(
            first,
            qualification_supervisor_phase_context_sha256(&phase, &"2".repeat(64)).unwrap()
        );
        assert_ne!(
            first,
            qualification_supervisor_phase_context_sha256(&phase, &"3".repeat(64)).unwrap()
        );
        let mut invalid = phase;
        invalid.phase_index = 0;
        assert_eq!(
            qualification_supervisor_phase_context_sha256(&invalid, &"2".repeat(64)),
            Err(QualificationEvidenceLedgerError::InvalidPhase)
        );
    }
}
